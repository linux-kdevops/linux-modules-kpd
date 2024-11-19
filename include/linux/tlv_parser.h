/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Header file of TLV parser.
 */

#ifndef _LINUX_TLV_PARSER_H
#define _LINUX_TLV_PARSER_H

#include <uapi/linux/tlv_parser.h>

/**
 * typedef callback - Callback after parsing TLV entry
 * @callback_data: Opaque data to supply to the callback function
 * @field: Field identifier
 * @field_data: Field data
 * @field_len: Length of @field_data
 *
 * This callback is invoked after a TLV entry is parsed.
 *
 * Return: Zero on success, a negative value on error.
 */
typedef int (*callback)(void *callback_data, __u16 field,
			const __u8 *field_data, __u32 field_len);

int tlv_parse(callback callback, void *callback_data, const __u8 *data,
	      size_t data_len, const char **fields, __u32 num_fields);

#endif /* _LINUX_TLV_PARSER_H */
