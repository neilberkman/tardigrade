/*
 * Copyright (c) 2026 Neil Berkman
 * SPDX-License-Identifier: Apache-2.0
 *
 * Shared sequence-numbered record format and SRAM durability oracle layout
 * for Zephyr Flash Circular Buffer (FCB) and settings-on-FCB power-loss targets.
 */

#ifndef TARDIGRADE_FCB_ORACLE_COMMON_H_
#define TARDIGRADE_FCB_ORACLE_COMMON_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#define FCB_VERDICT_SRAM_BASE      0x2003F000UL
#define FCB_VERDICT_MAGIC_RAW      0x4643424FUL /* "FCBO" */
#define FCB_VERDICT_MAGIC_SETTINGS 0x53464342UL /* "SFCB" */

#define FCB_REC_MAGIC_BASE         0x46437000UL
#define FCB_REC_MAGIC_MASK         0xFFFFFF00UL
#define FCB_REC_FLAG_MASK          0x000000FFUL
#define FCB_REC_FLAG_LIVE          0x00U
#define FCB_REC_FLAG_DELETED       0x01U
#define FCB_REC_FLAG_FILLER        0x02U

#define FCB_NUM_TRACKED_KEYS       7U
#define FCB_KEY_FILLER             0xFEU

/* Expected post-recovery live key bitmask: K0, K1, K3, K4, K6 present; K2, K5 deleted. */
#define FCB_EXPECTED_POST_MASK     0x0000005BUL

struct fcb_record {
	uint32_t magic_and_flags;
	uint32_t key_id;
	uint32_t seq;
	uint32_t value0;
	uint32_t value1;
	uint32_t crc32;
};

struct fcb_oracle_verdict {
	volatile uint32_t magic;              /* 0x2003F000 */
	volatile uint32_t oracle_ok;          /* 0x2003F004 */
	volatile uint32_t mount_ok;           /* 0x2003F008 */
	volatile uint32_t mount_oracle_ok;    /* 0x2003F00C */
	volatile uint32_t write_ok;           /* 0x2003F010 */
	volatile uint32_t post_oracle_ok;     /* 0x2003F014 */
	volatile uint32_t mount_present_mask; /* 0x2003F018 */
	volatile uint32_t mount_torn_count;   /* 0x2003F01C */
	volatile uint32_t mount_seq[FCB_NUM_TRACKED_KEYS]; /* 0x2003F020..0x2003F038 */
	volatile uint32_t post_present_mask;  /* 0x2003F03C */
	volatile uint32_t post_torn_count;    /* 0x2003F040 */
	volatile uint32_t post_seq[FCB_NUM_TRACKED_KEYS];  /* 0x2003F044..0x2003F05C */
	volatile uint32_t last_ack_seq;       /* 0x2003F060 */
	volatile uint32_t ack_count;          /* 0x2003F064 */
	volatile uint32_t write_err;          /* 0x2003F068 */
};

struct fcb_store_snapshot {
	uint32_t present_mask;
	uint32_t torn_count;
	uint32_t torn_mask;
	uint32_t max_seq;
	uint32_t key_seq[FCB_NUM_TRACKED_KEYS];
	uint32_t key_val0[FCB_NUM_TRACKED_KEYS];
	uint32_t key_val1[FCB_NUM_TRACKED_KEYS];
};

static inline uint32_t fcb_expected_val0(uint32_t key_id, uint32_t seq)
{
	return ((0xA5000000UL | ((key_id & 0xFFUL) << 16) | (seq & 0xFFFFUL)) ^
		(seq * 0x01010101UL));
}

static inline uint32_t fcb_expected_val1(uint32_t key_id, uint32_t seq)
{
	return ((0x5A000000UL | ((key_id & 0xFFUL) << 16) | ((seq * 17UL) & 0xFFFFUL)) ^
		0xC0FFEE11UL);
}

static inline uint32_t fcb_crc32_ieee(const void *data, size_t len)
{
	const uint8_t *bytes = (const uint8_t *)data;
	uint32_t crc = 0xFFFFFFFFUL;

	for (size_t i = 0U; i < len; i++) {
		crc ^= (uint32_t)bytes[i];
		for (uint32_t bit = 0U; bit < 8U; bit++) {
			if ((crc & 1UL) != 0UL) {
				crc = (crc >> 1) ^ 0xEDB88320UL;
			} else {
				crc >>= 1;
			}
		}
	}
	return ~crc;
}

static inline void fcb_record_build(struct fcb_record *rec, uint32_t key_id,
				    uint32_t seq, uint32_t flags)
{
	rec->magic_and_flags = FCB_REC_MAGIC_BASE | (flags & FCB_REC_FLAG_MASK);
	rec->key_id = key_id;
	rec->seq = seq;
	if ((flags & FCB_REC_FLAG_DELETED) != 0U) {
		rec->value0 = 0U;
		rec->value1 = 0U;
	} else {
		rec->value0 = fcb_expected_val0(key_id, seq);
		rec->value1 = fcb_expected_val1(key_id, seq);
	}
	rec->crc32 = fcb_crc32_ieee(rec, offsetof(struct fcb_record, crc32));
}

static inline bool fcb_record_verify(const struct fcb_record *rec)
{
	uint32_t flags = rec->magic_and_flags & FCB_REC_FLAG_MASK;

	if ((rec->magic_and_flags & FCB_REC_MAGIC_MASK) != FCB_REC_MAGIC_BASE) {
		return false;
	}
	if (fcb_crc32_ieee(rec, offsetof(struct fcb_record, crc32)) != rec->crc32) {
		return false;
	}
	if ((flags & FCB_REC_FLAG_DELETED) != 0U) {
		return (rec->value0 == 0U) && (rec->value1 == 0U);
	}
	return (rec->value0 == fcb_expected_val0(rec->key_id, rec->seq)) &&
	       (rec->value1 == fcb_expected_val1(rec->key_id, rec->seq));
}

static inline void fcb_snapshot_apply_record(struct fcb_store_snapshot *snap,
					     const struct fcb_record *rec)
{
	if (!fcb_record_verify(rec)) {
		snap->torn_count++;
		if (rec->key_id < FCB_NUM_TRACKED_KEYS) {
			snap->torn_mask |= (1UL << rec->key_id);
		}
		return;
	}

	uint32_t flags = rec->magic_and_flags & FCB_REC_FLAG_MASK;

	if ((flags & FCB_REC_FLAG_FILLER) != 0U || rec->key_id == FCB_KEY_FILLER) {
		return;
	}
	if (rec->key_id >= FCB_NUM_TRACKED_KEYS) {
		snap->torn_count++;
		return;
	}
	if (rec->seq > snap->max_seq) {
		snap->max_seq = rec->seq;
	}
	if ((flags & FCB_REC_FLAG_DELETED) != 0U) {
		snap->present_mask &= ~(1UL << rec->key_id);
		snap->key_seq[rec->key_id] = 0U;
		snap->key_val0[rec->key_id] = 0U;
		snap->key_val1[rec->key_id] = 0U;
	} else {
		snap->present_mask |= (1UL << rec->key_id);
		snap->key_seq[rec->key_id] = rec->seq;
		snap->key_val0[rec->key_id] = rec->value0;
		snap->key_val1[rec->key_id] = rec->value1;
	}
}

/*
 * Validate the store snapshot captured at recovery mount (before any new
 * writes are issued on the recovery boot):
 *   1. No record value is torn (torn_count == 0).
 *   2. Every pre-cut committed key is present with its acknowledged value:
 *      - K0 must be at seq == 1.
 *      - K1 (updated from seq=2 to seq=10 before the cut) must be at seq == 10.
 *      - K2 (deleted at seq=11 before the cut) must NEVER reappear.
 *      - K3 must be at seq == 4 (or seq == 24 if Op 4 completed before the cut).
 *      - K4 must be at seq == 12 (or seq == 21 if Op 1 completed before the cut).
 *   3. Causal prefix across runtime operations Op 1..4 (seq 21..24):
 *      - K5 must be either present at seq == 13 (if cut before Op 2 completed)
 *        or absent (if Op 2 delete completed before the cut).
 *      - If K5 was deleted (Op 2, seq=22), Op 1 (K4 @ seq=21) must be present.
 *      - If K6 is present (Op 3, seq=23 or probe seq=25), both Op 1 (K4 @ seq=21)
 *        and Op 2 (K5 deleted) must have taken effect.
 *      - If K3 is at seq == 24 (Op 4), Op 3 (K6 @ seq=23/25), Op 2 (K5 deleted),
 *        and Op 1 (K4 @ seq=21) must all have taken effect.
 */
static inline bool fcb_validate_mount_snapshot(const struct fcb_store_snapshot *s)
{
	if (s->torn_count != 0U) {
		return false;
	}
	if ((s->present_mask & (1UL << 0)) == 0U || s->key_seq[0] != 1U) {
		return false;
	}
	if ((s->present_mask & (1UL << 1)) == 0U || s->key_seq[1] != 10U) {
		return false;
	}
	if ((s->present_mask & (1UL << 2)) != 0U || s->key_seq[2] != 0U) {
		return false;
	}
	if ((s->present_mask & (1UL << 3)) == 0U ||
	    (s->key_seq[3] != 4U && s->key_seq[3] != 24U)) {
		return false;
	}
	if ((s->present_mask & (1UL << 4)) == 0U ||
	    (s->key_seq[4] != 12U && s->key_seq[4] != 21U)) {
		return false;
	}

	bool k5_present = (s->present_mask & (1UL << 5)) != 0U;
	if (k5_present) {
		if (s->key_seq[5] != 13U) {
			return false;
		}
	} else {
		if (s->key_seq[5] != 0U || s->key_seq[4] != 21U) {
			return false;
		}
	}

	bool k6_present = (s->present_mask & (1UL << 6)) != 0U;
	if (k6_present) {
		if (s->key_seq[6] != 23U &&
		    (s->key_seq[6] < 25U || s->key_seq[6] > 30U)) {
			return false;
		}
		if (s->key_seq[4] != 21U || k5_present) {
			return false;
		}
	} else if (s->key_seq[6] != 0U) {
		return false;
	}

	if (s->key_seq[3] == 24U) {
		if (!k6_present || k5_present || s->key_seq[4] != 21U) {
			return false;
		}
	}
	return true;
}

static inline bool fcb_validate_post_snapshot(const struct fcb_store_snapshot *s)
{
	if (s->torn_count != 0U) {
		return false;
	}
	if (s->present_mask != FCB_EXPECTED_POST_MASK) {
		return false;
	}
	if (s->key_seq[0] != 1U ||
	    s->key_seq[1] != 10U ||
	    s->key_seq[2] != 0U ||
	    s->key_seq[3] != 24U ||
	    s->key_seq[4] != 21U ||
	    s->key_seq[5] != 0U ||
	    (s->key_seq[6] != 23U &&
	     (s->key_seq[6] < 25U || s->key_seq[6] > 30U))) {
		return false;
	}
	return true;
}

#endif /* TARDIGRADE_FCB_ORACLE_COMMON_H_ */
