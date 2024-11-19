/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the user space interface for the TLV parser.
 */

#ifndef _UAPI_LINUX_TLV_PARSER_H
#define _UAPI_LINUX_TLV_PARSER_H

#include <linux/types.h>

/*
 * TLV format:
 *
 * +--------------+--+---------+--------+---------+
 * | field1 (u16) | len1 (u32) | value1 (u8 len1) |
 * +--------------+------------+------------------+
 * |     ...      |    ...     |        ...       |
 * +--------------+------------+------------------+
 * | fieldN (u16) | lenN (u32) | valueN (u8 lenN) |
 * +--------------+------------+------------------+
 */

/**
 * struct tlv_entry - Entry of TLV format
 * @field: Field identifier
 * @length: Data length
 * @data: Data
 *
 * This structure represents an entry of the TLV format.
 */
struct tlv_entry {
	__u16 field;
	__u32 length;
	__u8 data[];
} __attribute__((packed));

#endif /* _UAPI_LINUX_TLV_PARSER_H */
