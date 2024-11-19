// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2017-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Parse a tlv digest list.
 */

#define pr_fmt(fmt) "digest_cache TLV PARSER: "fmt
#include <linux/module.h>
#include <linux/tlv_parser.h>
#include <linux/digest_cache.h>
#include <uapi/linux/tlv_digest_list.h>

#define kenter(FMT, ...) \
	pr_debug("==> %s(" FMT ")\n", __func__, ##__VA_ARGS__)
#define kleave(FMT, ...) \
	pr_debug("<== %s()" FMT "\n", __func__, ##__VA_ARGS__)

static const char *digest_list_fields_str[] = {
	FOR_EACH_DIGEST_LIST_FIELD(GENERATE_STRING)
};

static const char *digest_list_entry_fields_str[] = {
	FOR_EACH_DIGEST_LIST_ENTRY_FIELD(GENERATE_STRING)
};

struct tlv_callback_data {
	struct digest_cache *digest_cache;
	enum hash_algo algo;
};

/**
 * parse_digest_list_entry_digest - Parse DIGEST_LIST_ENTRY_DIGEST field
 * @tlv_data: Callback data
 * @field: Field identifier
 * @field_data: Field data
 * @field_data_len: Length of @field_data
 *
 * This function parses the DIGEST_LIST_ENTRY_DIGEST field (file digest).
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
static int parse_digest_list_entry_digest(struct tlv_callback_data *tlv_data,
					  enum digest_list_entry_fields field,
					  const __u8 *field_data,
					  __u32 field_data_len)
{
	int ret;

	kenter(",%u,%u", field, field_data_len);

	if (tlv_data->algo == HASH_ALGO__LAST) {
		pr_debug("Digest algo not set\n");
		ret = -EBADMSG;
		goto out;
	}

	if (field_data_len != hash_digest_size[tlv_data->algo]) {
		pr_debug("Unexpected data length %u, expected %d\n",
			 field_data_len, hash_digest_size[tlv_data->algo]);
		ret = -EBADMSG;
		goto out;
	}

	ret = digest_cache_htable_add(tlv_data->digest_cache,
				      (__u8 *)field_data, tlv_data->algo);
out:
	kleave(" = %d", ret);
	return ret;
}

/**
 * parse_digest_list_entry_path - Parse DIGEST_LIST_ENTRY_PATH field
 * @tlv_data: Callback data
 * @field: Field identifier
 * @field_data: Field data
 * @field_data_len: Length of @field_data
 *
 * This function handles the DIGEST_LIST_ENTRY_PATH field (file path). It
 * currently does not parse the data.
 *
 * Return: Zero.
 */
static int parse_digest_list_entry_path(struct tlv_callback_data *tlv_data,
					enum digest_list_entry_fields field,
					const __u8 *field_data,
					__u32 field_data_len)
{
	kenter(",%u,%u", field, field_data_len);

	kleave(" = 0");
	return 0;
}

/**
 * digest_list_entry_callback - DIGEST_LIST_ENTRY callback
 * @callback_data: Callback data
 * @field: Field identifier
 * @field_data: Field data
 * @field_data_len: Length of @field_data
 *
 * This callback handles the fields of DIGEST_LIST_ENTRY (nested) data, and
 * calls the appropriate parser.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
static int digest_list_entry_callback(void *callback_data, __u16 field,
				      const __u8 *field_data,
				      __u32 field_data_len)
{
	struct tlv_callback_data *tlv_data;
	int ret;

	tlv_data = (struct tlv_callback_data *)callback_data;

	switch (field) {
	case DIGEST_LIST_ENTRY_DIGEST:
		ret = parse_digest_list_entry_digest(tlv_data, field,
						     field_data,
						     field_data_len);
		break;
	case DIGEST_LIST_ENTRY_PATH:
		ret = parse_digest_list_entry_path(tlv_data, field, field_data,
						   field_data_len);
		break;
	default:
		pr_debug("Unhandled field %s\n",
			 digest_list_entry_fields_str[field]);
		/* Just ignore non-relevant fields. */
		ret = 0;
		break;
	}

	return ret;
}

/**
 * parse_digest_list_algo - Parse DIGEST_LIST_ALGO field
 * @tlv_data: Callback data
 * @field: Field identifier
 * @field_data: Field data
 * @field_data_len: Length of @field_data
 *
 * This function parses the DIGEST_LIST_ALGO field (digest algorithm).
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
static int parse_digest_list_algo(struct tlv_callback_data *tlv_data,
				  enum digest_list_fields field,
				  const __u8 *field_data, __u32 field_data_len)
{
	__u16 algo;
	int ret = 0;

	kenter(",%u,%u", field, field_data_len);

	if (field_data_len != sizeof(__u16)) {
		pr_debug("Unexpected data length %u, expected %zu\n",
			 field_data_len, sizeof(__u16));
		ret = -EBADMSG;
		goto out;
	}

	algo = __be16_to_cpu(*(__u16 *)field_data);

	if (algo >= HASH_ALGO__LAST) {
		pr_debug("Unexpected digest algo %u\n", algo);
		ret = -EBADMSG;
		goto out;
	}

	tlv_data->algo = algo;

	pr_debug("Digest algo: %s\n", hash_algo_name[algo]);
out:
	kleave(" = %d", ret);
	return ret;
}

/**
 * parse_digest_list_num_entries - Parse DIGEST_LIST_NUM_ENTRIES field
 * @tlv_data: Callback data
 * @field: Field identifier
 * @field_data: Field data
 * @field_data_len: Length of @field_data
 *
 * This function parses the DIGEST_LIST_NUM_ENTRIES field (digest list entries).
 * This field must appear after DIGEST_LIST_ALGO.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
static int parse_digest_list_num_entries(struct tlv_callback_data *tlv_data,
					 enum digest_list_fields field,
					 const __u8 *field_data,
					 __u32 field_data_len)
{
	__u32 num_entries;
	int ret;

	kenter(",%u,%u", field, field_data_len);

	if (field_data_len != sizeof(__u32)) {
		pr_debug("Unexpected data length %u, expected %zu\n",
			 field_data_len, sizeof(__u32));
		ret = -EBADMSG;
		goto out;
	}

	if (tlv_data->algo == HASH_ALGO__LAST) {
		pr_debug("Digest algo not yet initialized\n");
		ret = -EBADMSG;
		goto out;
	}

	num_entries = __be32_to_cpu(*(__u32 *)field_data);

	ret = digest_cache_htable_init(tlv_data->digest_cache, num_entries,
				       tlv_data->algo);
out:
	kleave(" = %d", ret);
	return ret;
}

/**
 * parse_digest_list_entry - Parse DIGEST_LIST_ENTRY field
 * @tlv_data: Callback data
 * @field: Field identifier
 * @field_data: Field data
 * @field_data_len: Length of @field_data
 *
 * This function parses the DIGEST_LIST_ENTRY field.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
static int parse_digest_list_entry(struct tlv_callback_data *tlv_data,
				   enum digest_list_fields field,
				   const __u8 *field_data, __u32 field_data_len)
{
	int ret;

	kenter(",%u,%u", field, field_data_len);

	ret = tlv_parse(digest_list_entry_callback, tlv_data, field_data,
			field_data_len, digest_list_entry_fields_str,
			DIGEST_LIST_ENTRY_FIELD__LAST);

	kleave(" = %d", ret);
	return ret;
}

/**
 * digest_list_callback - Digest list callback
 * @callback_data: Callback data
 * @field: Field identifier
 * @field_data: Field data
 * @field_data_len: Length of @field_data
 *
 * This callback handles the digest list fields, and calls the appropriate
 * parser.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
static int digest_list_callback(void *callback_data, __u16 field,
				const __u8 *field_data, __u32 field_data_len)
{
	struct tlv_callback_data *tlv_data;
	int ret;

	tlv_data = (struct tlv_callback_data *)callback_data;

	switch (field) {
	case DIGEST_LIST_ALGO:
		ret = parse_digest_list_algo(tlv_data, field, field_data,
					     field_data_len);
		break;
	case DIGEST_LIST_NUM_ENTRIES:
		ret = parse_digest_list_num_entries(tlv_data, field, field_data,
						    field_data_len);
		break;
	case DIGEST_LIST_ENTRY:
		ret = parse_digest_list_entry(tlv_data, field, field_data,
					      field_data_len);
		break;
	default:
		pr_debug("Unhandled field %s\n",
			 digest_list_fields_str[field]);
		/* Just ignore non-relevant fields. */
		ret = 0;
		break;
	}

	return ret;
}

/**
 * digest_list_parse_tlv - Parse a tlv digest list
 * @digest_cache: Digest cache
 * @data: Data to parse
 * @data_len: Length of @data
 *
 * This function parses a tlv digest list.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
static int digest_list_parse_tlv(struct digest_cache *digest_cache,
				 const __u8 *data, size_t data_len)
{
	struct tlv_callback_data tlv_data = {
		.digest_cache = digest_cache,
		.algo = HASH_ALGO__LAST,
	};

	return tlv_parse(digest_list_callback, &tlv_data, data, data_len,
			 digest_list_fields_str, DIGEST_LIST_FIELD__LAST);
}

static struct parser tlv_parser = {
	.name = "tlv",
	.owner = THIS_MODULE,
	.func = digest_list_parse_tlv,
};

static int __init tlv_parser_init(void)
{
	return digest_cache_register_parser(&tlv_parser);
}

static void __exit tlv_parser_exit(void)
{
	digest_cache_unregister_parser(&tlv_parser);
}

module_init(tlv_parser_init);
module_exit(tlv_parser_exit);

MODULE_AUTHOR("Roberto Sassu");
MODULE_DESCRIPTION("TLV digest list parser");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");
