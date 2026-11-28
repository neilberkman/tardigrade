/*
 * Copyright (c) 2026 Neil Berkman
 * SPDX-License-Identifier: Apache-2.0
 *
 * Raw Zephyr Flash Circular Buffer (FCB, subsys/fs/fcb) power-loss durability
 * target for nRF52840 internal NVMC flash and external JEDEC SPI NOR flash.
 *
 * On each boot:
 *   1. Mounts the 3-sector (12 KiB) FCB instance on `fcb_storage` via fcb_init()
 *      and walks all committed entries via fcb_walk() to capture the mount-time
 *      store snapshot in SRAM (0x2003F000) before issuing any recovery writes.
 *   2. Executes sequence-numbered append/update/delete operations (and, when
 *      seeded close to full so the active sector crosses into the third sector,
 *      compacts live records from f_oldest and rotates the oldest sector via
 *      fcb_rotate()), reporting each acknowledged operation to SRAM and UART.
 *   3. Re-walks the FCB from f_oldest to f_active to verify that all records
 *      acknowledged before the cut are present with their acknowledged values,
 *      no deleted key reappeared, no record value is torn, and the store still
 *      accepts new writes.
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/fs/fcb.h>
#include <zephyr/sys/printk.h>
#include <cmsis_core.h>
#include <stdint.h>
#include <string.h>

#include "fcb_oracle_common.h"

#define FCB_PARTITION_NODE     DT_NODELABEL(fcb_storage)
#define FCB_PARTITION_ID       DT_FIXED_PARTITION_ID(FCB_PARTITION_NODE)

#define FCB_RAW_MAGIC          0x46434231UL /* "FCB1" */
#define FCB_RAW_VERSION        1U
#define FCB_SECTOR_COUNT       3U

static struct flash_sector g_fcb_sectors[FCB_SECTOR_COUNT];
static struct fcb g_fcb;

static int fcb_walk_record_cb(struct fcb_entry_ctx *loc_ctx, void *arg)
{
	struct fcb_store_snapshot *snap = (struct fcb_store_snapshot *)arg;
	struct fcb_record rec;
	int rc;

	if (loc_ctx->loc.fe_data_len < sizeof(rec)) {
		snap->torn_count++;
		return 0;
	}

	rc = flash_area_read(loc_ctx->fap,
			     FCB_ENTRY_FA_DATA_OFF(loc_ctx->loc),
			     &rec, sizeof(rec));
	if (rc != 0) {
		snap->torn_count++;
		return 0;
	}

	if (loc_ctx->loc.fe_data_len != sizeof(rec)) {
		uint32_t flags = rec.magic_and_flags & FCB_REC_FLAG_MASK;

		if ((flags & FCB_REC_FLAG_FILLER) == 0U || rec.key_id != FCB_KEY_FILLER) {
			snap->torn_count++;
			return 0;
		}
	}

	fcb_snapshot_apply_record(snap, &rec);
	return 0;
}

static int fcb_append_record(struct fcb *fcbp, uint32_t key_id,
			     uint32_t seq, uint32_t flags)
{
	struct fcb_record rec;
	struct fcb_entry loc;
	int rc;

	fcb_record_build(&rec, key_id, seq, flags);

	rc = fcb_append(fcbp, (uint16_t)sizeof(rec), &loc);
	if (rc != 0) {
		return rc;
	}

	rc = fcb_flash_write(fcbp, loc.fe_sector, loc.fe_data_off,
			     &rec, sizeof(rec));
	if (rc != 0) {
		return rc;
	}

	rc = fcb_append_finish(fcbp, &loc);
	return rc;
}

static void report_ack(struct fcb_oracle_verdict *verdict, uint32_t seq,
		       uint32_t key_id, uint32_t flags)
{
	verdict->last_ack_seq = seq;
	verdict->ack_count = verdict->ack_count + 1U;
	printk("ACK seq=%u key=%u flags=0x%x\n",
	       (unsigned int)seq, (unsigned int)key_id, (unsigned int)flags);
}

int main(void)
{
	struct fcb_oracle_verdict *verdict =
		(struct fcb_oracle_verdict *)FCB_VERDICT_SRAM_BASE;
	struct fcb_store_snapshot mount_snap;
	struct fcb_store_snapshot post_snap;
	uint32_t sector_cnt = FCB_SECTOR_COUNT;
	int rc;

	memset((void *)verdict, 0, sizeof(*verdict));
	memset(&mount_snap, 0, sizeof(mount_snap));
	memset(&post_snap, 0, sizeof(post_snap));
	memset(&g_fcb, 0, sizeof(g_fcb));

	rc = flash_area_get_sectors(FCB_PARTITION_ID, &sector_cnt, g_fcb_sectors);
	if (rc != 0 || sector_cnt < FCB_SECTOR_COUNT) {
		verdict->write_err = (uint32_t)(rc < 0 ? -rc : 0xE001U);
		verdict->magic = FCB_VERDICT_MAGIC_RAW;
		goto halt;
	}

	g_fcb.f_magic = FCB_RAW_MAGIC;
	g_fcb.f_version = FCB_RAW_VERSION;
	g_fcb.f_sector_cnt = (uint8_t)FCB_SECTOR_COUNT;
	g_fcb.f_scratch_cnt = 0U;
	g_fcb.f_sectors = g_fcb_sectors;

	rc = fcb_init(FCB_PARTITION_ID, &g_fcb);
	if (rc != 0) {
		verdict->mount_ok = 0U;
		verdict->write_err = (uint32_t)(-rc);
		verdict->magic = FCB_VERDICT_MAGIC_RAW;
		goto halt;
	}
	verdict->mount_ok = 1U;

	/* Step 1: Walk FCB at mount and record recovered pre-write state. */
	rc = fcb_walk(&g_fcb, NULL, fcb_walk_record_cb, &mount_snap);
	if (rc != 0) {
		verdict->mount_ok = 0U;
		verdict->write_err = (uint32_t)(-rc);
		verdict->magic = FCB_VERDICT_MAGIC_RAW;
		goto halt;
	}

	verdict->mount_present_mask = mount_snap.present_mask;
	verdict->mount_torn_count = mount_snap.torn_count;
	for (uint32_t k = 0U; k < FCB_NUM_TRACKED_KEYS; k++) {
		verdict->mount_seq[k] = mount_snap.key_seq[k];
	}
	verdict->mount_oracle_ok = fcb_validate_mount_snapshot(&mount_snap) ? 1U : 0U;

	/* Step 2: Execute sequence-numbered append/update/delete + rotation workload. */
	rc = 0;

	/* Op 1 (seq=21): update K4 from seq=12 to seq=21. */
	if (mount_snap.key_seq[4] < 21U) {
		rc = fcb_append_record(&g_fcb, 4U, 21U, FCB_REC_FLAG_LIVE);
		if (rc == 0) {
			report_ack(verdict, 21U, 4U, FCB_REC_FLAG_LIVE);
		}
	}

	/* Op 2 (seq=22): delete K5 (tombstone record). */
	if (rc == 0 && (mount_snap.present_mask & (1UL << 5)) != 0U) {
		rc = fcb_append_record(&g_fcb, 5U, 22U, FCB_REC_FLAG_DELETED);
		if (rc == 0) {
			report_ack(verdict, 22U, 5U, FCB_REC_FLAG_DELETED);
		}
	}

	/* Op 3 (seq=23): append new record K6 (crosses into S2 when S1 is full). */
	if (rc == 0 && mount_snap.key_seq[6] < 23U) {
		rc = fcb_append_record(&g_fcb, 6U, 23U, FCB_REC_FLAG_LIVE);
		if (rc == 0) {
			report_ack(verdict, 23U, 6U, FCB_REC_FLAG_LIVE);
		}
	}

	/* When all 3 sectors are occupied and S0 is still f_oldest, compact live
	 * records from S0 (K0 @ seq=1, K3 @ seq=4) into S2 and rotate S0.
	 */
	if (rc == 0 && fcb_free_sector_cnt(&g_fcb) == 0 &&
	    g_fcb.f_oldest == &g_fcb_sectors[0] &&
	    g_fcb.f_active.fe_sector == &g_fcb_sectors[2]) {
		struct fcb_store_snapshot active_snap;

		memset(&active_snap, 0, sizeof(active_snap));
		(void)fcb_walk(&g_fcb, g_fcb.f_active.fe_sector,
			       fcb_walk_record_cb, &active_snap);
		if (active_snap.key_seq[0] == 0U) {
			rc = fcb_append_record(&g_fcb, 0U, 1U, FCB_REC_FLAG_LIVE);
		}
		if (rc == 0 && active_snap.key_seq[3] == 0U &&
		    mount_snap.key_seq[3] == 4U) {
			rc = fcb_append_record(&g_fcb, 3U, 4U, FCB_REC_FLAG_LIVE);
		}
		if (rc == 0) {
			rc = fcb_rotate(&g_fcb);
		}
	}

	/* Op 4 (seq=24): update K3 to seq=24. */
	if (rc == 0 && mount_snap.key_seq[3] < 24U) {
		rc = fcb_append_record(&g_fcb, 3U, 24U, FCB_REC_FLAG_LIVE);
		if (rc == 0) {
			report_ack(verdict, 24U, 3U, FCB_REC_FLAG_LIVE);
		}
	}

	/* Op 5 (seq>=25): if all operations 21..24 were already committed before
	 * this recovery boot, append a probe update (K6 @ seq=25+) so every recovery
	 * boot verifies that the store still accepts new writes.
	 */
	if (rc == 0 && mount_snap.key_seq[3] == 24U) {
		uint32_t probe_seq = (mount_snap.key_seq[6] >= 25U) ?
				     (mount_snap.key_seq[6] + 1U) : 25U;
		rc = fcb_append_record(&g_fcb, 6U, probe_seq, FCB_REC_FLAG_LIVE);
		if (rc == 0) {
			report_ack(verdict, probe_seq, 6U, FCB_REC_FLAG_LIVE);
		}
	}

	if (rc != 0) {
		verdict->write_ok = 0U;
		verdict->write_err = (uint32_t)(rc < 0 ? -rc : rc);
	} else {
		verdict->write_ok = 1U;
	}

	/* Step 3: Re-walk FCB from scratch and publish post-write verdict. */
	rc = fcb_walk(&g_fcb, NULL, fcb_walk_record_cb, &post_snap);
	if (rc != 0) {
		verdict->post_oracle_ok = 0U;
	} else {
		verdict->post_present_mask = post_snap.present_mask;
		verdict->post_torn_count = post_snap.torn_count;
		for (uint32_t k = 0U; k < FCB_NUM_TRACKED_KEYS; k++) {
			verdict->post_seq[k] = post_snap.key_seq[k];
		}
		verdict->post_oracle_ok = fcb_validate_post_snapshot(&post_snap) ? 1U : 0U;
	}

	if (verdict->mount_ok == 1U &&
	    verdict->mount_oracle_ok == 1U &&
	    verdict->write_ok == 1U &&
	    verdict->post_oracle_ok == 1U &&
	    verdict->mount_torn_count == 0U &&
	    verdict->post_torn_count == 0U) {
		verdict->oracle_ok = 1U;
	} else {
		verdict->oracle_ok = 0U;
	}
	verdict->magic = FCB_VERDICT_MAGIC_RAW;

halt:
	(void)irq_lock();
	while (1) {
		__NOP();
	}
	return 0;
}
