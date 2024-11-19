/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Header of common.c.
 */

#ifndef _COMMON_H
#define _COMMON_H
#include <linux/types.h>

#include "../../../../include/uapi/linux/hash_info.h"

#define MD5_DIGEST_SIZE 16
#define SHA1_DIGEST_SIZE 20
#define RMD160_DIGEST_SIZE 20
#define SHA256_DIGEST_SIZE 32
#define SHA384_DIGEST_SIZE 48
#define SHA512_DIGEST_SIZE 64
#define SHA224_DIGEST_SIZE 28
#define RMD128_DIGEST_SIZE 16
#define RMD256_DIGEST_SIZE 32
#define RMD320_DIGEST_SIZE 40
#define WP256_DIGEST_SIZE 32
#define WP384_DIGEST_SIZE 48
#define WP512_DIGEST_SIZE 64
#define TGR128_DIGEST_SIZE 16
#define TGR160_DIGEST_SIZE 20
#define TGR192_DIGEST_SIZE 24
#define SM3256_DIGEST_SIZE 32
#define STREEBOG256_DIGEST_SIZE 32
#define STREEBOG512_DIGEST_SIZE 64
#define SHA3_224_DIGEST_SIZE	(224 / 8)
#define SHA3_256_DIGEST_SIZE	(256 / 8)
#define SHA3_384_DIGEST_SIZE	(384 / 8)
#define SHA3_512_DIGEST_SIZE	(512 / 8)

#define DIGEST_CACHE_DIR "/sys/kernel/security/integrity/digest_cache"
#define DIGEST_CACHE_TEST_INTERFACE "/sys/kernel/security/digest_cache_test"
#define DIGEST_CACHE_PATH_INTERFACE DIGEST_CACHE_DIR "/default_path"
#define MAX_DIGEST_SIZE 64

#define MAX_WORKS 21

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __s32 s32;
typedef __u64 u64;

enum commands {
	DIGEST_CACHE_GET,		// args: <path>
	DIGEST_CACHE_LOOKUP,		// args: <algo>|<digest>
	DIGEST_CACHE_PUT,		// args:
	DIGEST_CACHE_ENABLE_VERIF,	// args: <verif name>
	DIGEST_CACHE_DISABLE_VERIF,	// args: <verif name>
	DIGEST_CACHE_SET_VERIF,		// args: <verif name>
	DIGEST_CACHE_GET_PUT_ASYNC,	// args: <path>|<start#>|<end#>
	DIGEST_CACHE__LAST,
};

enum tlv_failures { TLV_NO_FAILURE,
		    TLV_FAILURE_ALGO_LEN,
		    TLV_FAILURE_ALGO_MISMATCH,
		    TLV_FAILURE_NUM_DIGESTS,
		    TLV_FAILURE__LAST
};

enum file_changes { FILE_WRITE,
		    FILE_TRUNCATE,
		    FILE_FTRUNCATE,
		    FILE_UNLINK,
		    FILE_RENAME,
		    FILE_SETXATTR,
		    FILE_REMOVEXATTR,
		    FILE_CHANGE__LAST
};

enum VERIFS {
	VERIF_FILENAMES,
	VERIF_NUMBER,
	VERIF_PREFETCH,
	VERIF__LAST
};

extern const char *commands_str[DIGEST_CACHE__LAST];
extern const char *const hash_algo_name[HASH_ALGO__LAST];
extern const int hash_digest_size[HASH_ALGO__LAST];
extern const char *verifs_str[VERIF__LAST];

#endif /* _COMMON_H */
