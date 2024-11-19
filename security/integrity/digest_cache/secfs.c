// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the securityfs interface of the Integrity Digest Cache.
 */

#define pr_fmt(fmt) "digest_cache: "fmt
#include <linux/security.h>

#include "internal.h"

static struct dentry *digest_cache_dir;
static struct dentry *default_path_dentry;

/**
 * write_default_path - Write default path
 * @file: File descriptor of the securityfs file
 * @buf: User space buffer
 * @datalen: Amount of data to write
 * @ppos: Current position in the file
 *
 * This function sets the new default path where digest lists can be found.
 * Can be either a regular file or a directory.
 *
 * Return: Length of path written on success, a POSIX error code otherwise.
 */
static ssize_t write_default_path(struct file *file, const char __user *buf,
				  size_t datalen, loff_t *ppos)
{
	char *new_default_path_str;

	new_default_path_str = memdup_user_nul(buf, datalen);
	if (IS_ERR(new_default_path_str))
		return PTR_ERR(new_default_path_str);

	down_write(&default_path_sem);
	kfree_const(default_path_str);
	default_path_str = new_default_path_str;
	up_write(&default_path_sem);
	return datalen;
}

/**
 * read_default_path - Read default path
 * @file: File descriptor of the securityfs file
 * @buf: User space buffer
 * @datalen: Amount of data to read
 * @ppos: Current position in the file
 *
 * This function returns the current default path where digest lists can be
 * found. Can be either a regular file or a directory.
 *
 * Return: Length of path read on success, a POSIX error code otherwise.
 */
static ssize_t read_default_path(struct file *file, char __user *buf,
				 size_t datalen, loff_t *ppos)
{
	int ret;

	down_read(&default_path_sem);
	ret = simple_read_from_buffer(buf, datalen, ppos, default_path_str,
				      strlen(default_path_str) + 1);
	up_read(&default_path_sem);
	return ret;
}

static const struct file_operations default_path_ops = {
	.open = generic_file_open,
	.write = write_default_path,
	.read = read_default_path,
	.llseek = generic_file_llseek,
};

/**
 * digest_cache_secfs_init - Initialize the securityfs interface
 * @dir: Directory entry provided by the calling LSM
 *
 * This function initializes the securityfs interfaces, for configuration
 * by user space.
 *
 * It creates 'default_path', allowing user space to change the default
 * directory where digest lists are searched.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
int __init digest_cache_secfs_init(struct dentry *dir)
{
	digest_cache_dir = securityfs_create_dir("digest_cache", dir);
	if (IS_ERR(digest_cache_dir))
		return PTR_ERR(digest_cache_dir);

	default_path_dentry = securityfs_create_file("default_path", 0660,
						     digest_cache_dir, NULL,
						     &default_path_ops);
	if (IS_ERR(default_path_dentry)) {
		securityfs_remove(digest_cache_dir);
		return PTR_ERR(default_path_dentry);
	}

	return 0;
}
