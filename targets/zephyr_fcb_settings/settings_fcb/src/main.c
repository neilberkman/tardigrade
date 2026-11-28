/*
 * Copyright (c) 2026 Neil Berkman
 * SPDX-License-Identifier: Apache-2.0
 *
 * Zephyr settings subsystem on the FCB backend (subsys/settings/src/settings_fcb.c)
 * power-loss durability target for nRF52840 internal NVMC flash and external
 * JEDEC SPI NOR flash.
 *
 * On each boot:
 *   1. Mounts the FCB settings backend via settings_subsys_init(), registers
 *      the "nvm" subtree handler, and calls settings_load() to capture the
 *      recovered mount-time key table in SRAM (0x2003F000) before issuing any
 *      new writes on the recovery boot.
 *   2. Executes sequence-numbered settings_save_one() (create & update) and
 *      settings_delete() operations (triggering settings_fcb_compress() when
 *      the active sector fills up), reporting each acknowledged operation to
 *      SRAM verdict words and UART.
 *   3. Reloads the entire settings store from flash via settings_load() to
 *      verify that every setting acknowledged before the cut is present with
 *      its acknowledged value, no deleted key reappeared, no value is torn,
 *      and the store still accepts new writes.
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/settings/settings.h>
#include <zephyr/sys/printk.h>
#include <cmsis_core.h>
#include <stdint.h>
#include <string.h>

#include "fcb_oracle_common.h"

static struct fcb_store_snapshot *g_active_load_snap;

static const char *const g_setting_keys[FCB_NUM_TRACKED_KEYS] = {
	"nvm/k00",
	"nvm/k01",
	"nvm/k02",
	"nvm/k03",
	"nvm/k04",
	"nvm/k05",
	"nvm/k06",
};

static int parse_key_suffix(const char *name, uint32_t *out_key_id)
{
	if (name == NULL || name[0] != 'k' || name[1] != '0' ||
	    name[2] < '0' || name[2] > '6' || name[3] != '\0') {
		return -1;
	}
	*out_key_id = (uint32_t)(name[2] - '0');
	return 0;
}

static int nvm_settings_set(const char *name, size_t len,
			    settings_read_cb read_cb, void *cb_arg)
{
	const char *next = NULL;
	uint32_t key_id = 0U;
	struct fcb_record rec;
	ssize_t nread;

	if (g_active_load_snap == NULL) {
		return 0;
	}
	if (settings_name_steq(name, "fil", &next) && !next) {
		return 0;
	}
	if (settings_name_steq(name, "fl2", &next) && !next) {
		return 0;
	}
	if (parse_key_suffix(name, &key_id) != 0) {
		g_active_load_snap->torn_count++;
		return 0;
	}
	if (len == 0U) {
		g_active_load_snap->present_mask &= ~(1UL << key_id);
		g_active_load_snap->key_seq[key_id] = 0U;
		return 0;
	}
	if (len != sizeof(rec)) {
		g_active_load_snap->torn_count++;
		g_active_load_snap->torn_mask |= (1UL << key_id);
		return 0;
	}
	nread = read_cb(cb_arg, &rec, sizeof(rec));
	if (nread != (ssize_t)sizeof(rec) || rec.key_id != key_id) {
		g_active_load_snap->torn_count++;
		g_active_load_snap->torn_mask |= (1UL << key_id);
		return 0;
	}
	fcb_snapshot_apply_record(g_active_load_snap, &rec);
	return 0;
}

static struct settings_handler g_nvm_handler = {
	.name = "nvm",
	.h_set = nvm_settings_set,
};

static int save_setting_record(uint32_t key_id, uint32_t seq)
{
	struct fcb_record rec;

	fcb_record_build(&rec, key_id, seq, FCB_REC_FLAG_LIVE);
	return settings_save_one(g_setting_keys[key_id], &rec, sizeof(rec));
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
	int rc;

	memset((void *)verdict, 0, sizeof(*verdict));
	memset(&mount_snap, 0, sizeof(mount_snap));
	memset(&post_snap, 0, sizeof(post_snap));

	rc = settings_subsys_init();
	if (rc != 0) {
		verdict->mount_ok = 0U;
		verdict->write_err = (uint32_t)(-rc);
		verdict->magic = FCB_VERDICT_MAGIC_SETTINGS;
		goto halt;
	}

	rc = settings_register(&g_nvm_handler);
	if (rc != 0 && rc != -EEXIST) {
		verdict->mount_ok = 0U;
		verdict->write_err = (uint32_t)(-rc);
		verdict->magic = FCB_VERDICT_MAGIC_SETTINGS;
		goto halt;
	}

	/* Step 1: Load settings at mount and record recovered pre-write state. */
	g_active_load_snap = &mount_snap;
	rc = settings_load();
	g_active_load_snap = NULL;
	if (rc != 0) {
		verdict->mount_ok = 0U;
		verdict->write_err = (uint32_t)(-rc);
		verdict->magic = FCB_VERDICT_MAGIC_SETTINGS;
		goto halt;
	}
	verdict->mount_ok = 1U;

	verdict->mount_present_mask = mount_snap.present_mask;
	verdict->mount_torn_count = mount_snap.torn_count;
	for (uint32_t k = 0U; k < FCB_NUM_TRACKED_KEYS; k++) {
		verdict->mount_seq[k] = mount_snap.key_seq[k];
	}
	verdict->mount_oracle_ok = fcb_validate_mount_snapshot(&mount_snap) ? 1U : 0U;

	/* Step 2: Execute sequence-numbered save/update/delete workload. */
	rc = 0;

	/* Op 1 (seq=21): update "nvm/k04" from seq=12 to seq=21. */
	if (mount_snap.key_seq[4] < 21U) {
		rc = save_setting_record(4U, 21U);
		if (rc == 0) {
			report_ack(verdict, 21U, 4U, FCB_REC_FLAG_LIVE);
		}
	}

	/* Op 2 (seq=22): delete "nvm/k05" via settings_delete(). */
	if (rc == 0 && (mount_snap.present_mask & (1UL << 5)) != 0U) {
		rc = settings_delete(g_setting_keys[5]);
		if (rc == 0) {
			report_ack(verdict, 22U, 5U, FCB_REC_FLAG_DELETED);
		}
	}

	/* Op 3 (seq=23): save new setting "nvm/k06" (triggers settings_fcb_compress()
	 * when the active sector S1 is full).
	 */
	if (rc == 0 && mount_snap.key_seq[6] < 23U) {
		rc = save_setting_record(6U, 23U);
		if (rc == 0) {
			report_ack(verdict, 23U, 6U, FCB_REC_FLAG_LIVE);
		}
	}

	/* Op 4 (seq=24): update "nvm/k03" from seq=4 to seq=24. */
	if (rc == 0 && mount_snap.key_seq[3] < 24U) {
		rc = save_setting_record(3U, 24U);
		if (rc == 0) {
			report_ack(verdict, 24U, 3U, FCB_REC_FLAG_LIVE);
		}
	}

	/* Op 5 (seq>=25): if all operations 21..24 were already committed before
	 * this recovery boot, save a probe update ("nvm/k06" @ seq=25+) so every
	 * recovery boot verifies that the store still accepts new writes.
	 */
	if (rc == 0 && mount_snap.key_seq[3] == 24U) {
		uint32_t probe_seq = (mount_snap.key_seq[6] >= 25U) ?
				     (mount_snap.key_seq[6] + 1U) : 25U;
		rc = save_setting_record(6U, probe_seq);
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

	/* Step 3: Reload settings from flash and publish post-write verdict. */
	g_active_load_snap = &post_snap;
	rc = settings_load();
	g_active_load_snap = NULL;
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
	verdict->magic = FCB_VERDICT_MAGIC_SETTINGS;

halt:
	(void)irq_lock();
	while (1) {
		__NOP();
	}
	return 0;
}
