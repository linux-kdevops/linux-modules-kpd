/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Header of generators.c.
 */

#include "common.h"
#include "common_user.h"

int gen_tlv_list(int temp_dirfd, char *digest_list_filename,
		 enum hash_algo algo, int start_number, int num_digests,
		 enum tlv_failures failure);
int create_file(int temp_dirfd, char *filename, char *digest_list_filename);
