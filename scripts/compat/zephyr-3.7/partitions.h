/*
 * Compatibility subset of Zephyr's partition API for building current
 * MCUboot against the repository's pinned Zephyr 3.7 asset toolchain.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TARDIGRADE_ZEPHYR_37_PARTITIONS_H_
#define TARDIGRADE_ZEPHYR_37_PARTITIONS_H_

#include <zephyr/devicetree/fixed-partitions.h>

#define DT_NODE_BY_PARTITION_LABEL(label) DT_NODE_BY_FIXED_PARTITION_LABEL(label)
#define DT_HAS_PARTITION_LABEL(label) DT_HAS_FIXED_PARTITION_LABEL(label)
#define DT_PARTITION_EXISTS(node_id) DT_FIXED_PARTITION_EXISTS(node_id)
#define DT_PARTITION_ID(node_id) DT_FIXED_PARTITION_ID(node_id)
#define DT_MEM_FROM_PARTITION(node_id) DT_MEM_FROM_FIXED_PARTITION(node_id)
#define DT_MTD_FROM_PARTITION(node_id) DT_MTD_FROM_FIXED_PARTITION(node_id)
#define DT_PARTITION_ADDR(node_id) DT_FIXED_PARTITION_ADDR(node_id)

#define PARTITION_EXISTS(label) FIXED_PARTITION_EXISTS(label)
#define PARTITION_ID(label) FIXED_PARTITION_ID(label)
#define PARTITION_OFFSET(label) FIXED_PARTITION_OFFSET(label)
#define PARTITION_ADDRESS(label) DT_FIXED_PARTITION_ADDR(DT_NODELABEL(label))
#define PARTITION_DEVICE(label) FIXED_PARTITION_DEVICE(label)
#define PARTITION_MTD(label) DT_MTD_FROM_FIXED_PARTITION(DT_NODELABEL(label))

#endif /* TARDIGRADE_ZEPHYR_37_PARTITIONS_H_ */
