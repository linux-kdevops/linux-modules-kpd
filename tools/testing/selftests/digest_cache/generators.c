// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Generate digest lists for testing.
 */

#include <stddef.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <sys/xattr.h>
#include <asm/byteorder.h>

#include "generators.h"
#include "../../../../include/uapi/linux/hash_info.h"
#include "../../../../include/uapi/linux/xattr.h"
#include "../../../../include/uapi/linux/tlv_digest_list.h"
#include "../../../../include/uapi/linux/tlv_parser.h"

int gen_tlv_list(int temp_dirfd, char *digest_list_filename,
		 enum hash_algo algo, int start_number, int num_digests,
		 enum tlv_failures failure)
{
	__u16 _algo = __cpu_to_be16(algo);
	__u32 _num_entries = __cpu_to_be32(num_digests);
	u8 digest[MAX_DIGEST_SIZE] = { 0 };
	int digest_len = hash_digest_size[algo];
	int ret, fd, i;

	struct tlv_entry algo_entry = {
		.field = __cpu_to_be16(DIGEST_LIST_ALGO),
		.length = __cpu_to_be32(sizeof(_algo)),
	};

	struct tlv_entry num_entries_entry = {
		.field = __cpu_to_be16(DIGEST_LIST_NUM_ENTRIES),
		.length = __cpu_to_be32(sizeof(_num_entries)),
	};

	struct tlv_entry entry_digest = {
		.field = __cpu_to_be16(DIGEST_LIST_ENTRY_DIGEST),
		.length = __cpu_to_be32(digest_len),
	};

	struct tlv_entry entry_entry = {
		.field = __cpu_to_be16(DIGEST_LIST_ENTRY),
		.length = __cpu_to_be32(sizeof(entry_digest) + digest_len),
	};

	switch (failure) {
	case TLV_FAILURE_ALGO_LEN:
		algo_entry.length = algo_entry.length / 2;
		break;
	case TLV_FAILURE_ALGO_MISMATCH:
		_algo = __cpu_to_be16(algo - 1);
		break;
	case TLV_FAILURE_NUM_DIGESTS:
		num_digests = 0;
		break;
	default:
		break;
	}

	fd = openat(temp_dirfd, digest_list_filename,
		    O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd == -1)
		return -errno;

	ret = write(fd, (u8 *)&algo_entry, sizeof(algo_entry));
	if (ret != sizeof(algo_entry))
		return -errno;

	ret = write(fd, (u8 *)&_algo, sizeof(_algo));
	if (ret != sizeof(_algo))
		return -errno;

	ret = write(fd, (u8 *)&num_entries_entry, sizeof(num_entries_entry));
	if (ret != sizeof(num_entries_entry))
		return -errno;

	ret = write(fd, (u8 *)&_num_entries, sizeof(_num_entries));
	if (ret != sizeof(_num_entries))
		return -errno;

	*(u32 *)digest = start_number;

	for (i = 0; i < num_digests; i++) {
		ret = write(fd, (u8 *)&entry_entry, sizeof(entry_entry));
		if (ret != sizeof(entry_entry))
			return -errno;

		ret = write(fd, (u8 *)&entry_digest, sizeof(entry_digest));
		if (ret != sizeof(entry_digest))
			return -errno;

		ret = write(fd, digest, digest_len);
		if (ret != digest_len)
			return -errno;

		(*(u32 *)digest)++;
	}

	close(fd);
	return 0;
}

int create_file(int temp_dirfd, char *filename, char *digest_list_filename)
{
	int ret = 0, fd;

	fd = openat(temp_dirfd, filename, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd == -1)
		return -errno;

	if (!digest_list_filename)
		goto out;

	ret = fsetxattr(fd, XATTR_NAME_DIGEST_LIST, digest_list_filename,
			strlen(digest_list_filename) + 1, 0);
	if (ret == -1)
		ret = -errno;
out:
	close(fd);
	return ret;
}
