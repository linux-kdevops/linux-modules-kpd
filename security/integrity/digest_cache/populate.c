// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the code to populate a digest cache.
 */

#define pr_fmt(fmt) "digest_cache: "fmt
#include <linux/init_task.h>
#include <linux/vmalloc.h>
#include <linux/kernel_read_file.h>

#include "internal.h"

/**
 * digest_cache_read_digest_list - Read a digest list
 * @work: Work structure
 *
 * This function is invoked by schedule_work() to read a digest list.
 *
 * It does not return a value, but stores the result in the passed structure.
 */
static void digest_cache_read_digest_list(struct work_struct *work)
{
	struct read_work *w = container_of(work, struct read_work, work);

	w->ret = kernel_read_file(w->file, 0, &w->data, INT_MAX, NULL,
				  READING_DIGEST_LIST);
}

/**
 * digest_cache_populate - Populate a digest cache from a digest list
 * @dentry: Dentry of the inode for which the digest cache will be used
 * @digest_cache: Digest cache
 * @digest_list_path: Path structure of the digest list
 *
 * This function opens the digest list for reading it. Then, it schedules a
 * work to read the digest list and, once the work is done, it calls
 * digest_cache_strip_modsig() to strip a module-style appended signature and
 * digest_cache_parse_digest_list() for extracting and adding digests to the
 * digest cache.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
int digest_cache_populate(struct dentry *dentry,
			  struct digest_cache *digest_cache,
			  struct path *digest_list_path)
{
	struct file *file;
	void *data;
	size_t data_len;
	struct read_work w;
	int ret;

	file = kernel_file_open(digest_list_path, O_RDONLY, &init_cred);
	if (IS_ERR(file)) {
		pr_debug("Unable to open digest list %s, ret: %ld\n",
			 digest_cache->path_str, PTR_ERR(file));
		return PTR_ERR(file);
	}

	/* Mark the file descriptor as ours. */
	digest_cache_to_file_sec(file, digest_cache);

	w.data = NULL;
	w.file = file;
	INIT_WORK_ONSTACK(&w.work, digest_cache_read_digest_list);

	schedule_work(&w.work);
	flush_work(&w.work);
	destroy_work_on_stack(&w.work);
	fput(file);

	ret = w.ret;
	data = w.data;

	if (ret < 0) {
		pr_debug("Unable to read digest list %s, ret: %d\n",
			 digest_cache->path_str, ret);
		return ret;
	}

	data_len = digest_cache_strip_modsig(data, ret);

	/* Digest list parsers initialize the hash table and add the digests. */
	ret = digest_cache_parse_digest_list(dentry, digest_cache,
					     digest_cache->path_str, data,
					     data_len);
	if (ret < 0)
		pr_debug("Error parsing digest list %s, ret: %d\n",
			 digest_cache->path_str, ret);

	vfree(data);
	return ret;
}
