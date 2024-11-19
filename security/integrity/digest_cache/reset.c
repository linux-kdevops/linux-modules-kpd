// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Reset digest cache on digest lists/directory modifications.
 */

#define pr_fmt(fmt) "digest_cache: "fmt
#include "internal.h"

/**
 * digest_cache_reset_clear_owner - Reset and clear dig_owner
 * @inode: Inode of the digest list/directory containing the digest list
 * @reason: Reason for reset and clear
 *
 * This function sets the RESET bit of the digest cache referenced by dig_owner
 * of the passed inode, and puts and clears dig_owner.
 *
 * The next time they are called, digest_cache_get() and
 * digest_cache_dir_lookup_digest() replace respectively dig_user and the digest
 * cache of the directory entry.
 */
static void digest_cache_reset_clear_owner(struct inode *inode,
					   const char *reason)
{
	struct digest_cache_security *dig_sec;

	dig_sec = digest_cache_get_security(inode);
	if (unlikely(!dig_sec))
		return;

	mutex_lock(&dig_sec->dig_owner_mutex);
	if (dig_sec->dig_owner) {
		pr_debug("Resetting and clearing %s (dig_owner), reason: %s\n",
			 dig_sec->dig_owner->path_str, reason);
		set_bit(RESET, &dig_sec->dig_owner->flags);
		digest_cache_put(dig_sec->dig_owner);
		dig_sec->dig_owner = NULL;
	}
	mutex_unlock(&dig_sec->dig_owner_mutex);
}

/**
 * digest_cache_clear_user - Clear dig_user
 * @inode: Inode of the file using the digest cache
 * @filename: File name of the affected inode
 * @reason: Reason for clear
 *
 * This function clears dig_user in the inode security blob, so that
 * digest_cache_get() requests a new digest cache based on the updated digest
 * list location.
 */
static void digest_cache_clear_user(struct inode *inode, const char *filename,
				    const char *reason)
{
	struct digest_cache_security *dig_sec;

	dig_sec = digest_cache_get_security(inode);
	if (unlikely(!dig_sec))
		return;

	mutex_lock(&dig_sec->dig_user_mutex);
	if (dig_sec->dig_user && !test_bit(RESET, &dig_sec->dig_user->flags)) {
		pr_debug("Clearing %s (dig_user of %s), reason: %s\n",
			 dig_sec->dig_user->path_str, filename, reason);
		digest_cache_put(dig_sec->dig_user);
		dig_sec->dig_user = NULL;
	}
	mutex_unlock(&dig_sec->dig_user_mutex);
}

/**
 * digest_cache_path_truncate - A file is being truncated
 * @path: File path
 *
 * This function is called when a file is being truncated. If the inode is a
 * digest list and/or the parent is a directory containing digest lists, it
 * resets the inode and/or directory dig_owner, to force rebuilding the digest
 * cache.
 *
 * Return: Zero.
 */
int digest_cache_path_truncate(const struct path *path)
{
	struct inode *inode = d_backing_inode(path->dentry);
	struct inode *dir = d_backing_inode(path->dentry->d_parent);

	if (!S_ISREG(inode->i_mode))
		return 0;

	digest_cache_reset_clear_owner(inode, "path_truncate(file)");
	digest_cache_reset_clear_owner(dir, "path_truncate(dir)");
	return 0;
}

/**
 * digest_cache_file_release - Last reference of a file desc is being released
 * @file: File descriptor
 *
 * This function is called when the last reference of a file descriptor is
 * being released. If the inode is a regular file and was opened for write or
 * was created, it resets the inode and the parent directory dig_owner, to
 * force rebuilding the digest caches.
 */
void digest_cache_file_release(struct file *file)
{
	struct inode *dir = d_backing_inode(file_dentry(file)->d_parent);

	if (!S_ISREG(file_inode(file)->i_mode) ||
	    ((!(file->f_mode & FMODE_WRITE)) &&
	      !(file->f_mode & FMODE_CREATED)))
		return;

	digest_cache_reset_clear_owner(file_inode(file), "file_release(file)");
	digest_cache_reset_clear_owner(dir, "file_release(dir)");
}

/**
 * digest_cache_inode_unlink - An inode is being removed
 * @dir: Inode of the affected directory
 * @dentry: Dentry of the inode being removed
 *
 * This function is called when an existing inode is being removed. If the
 * inode is a digest list/digest list directory, or the parent inode is the
 * digest list directory and the inode is a regular file, it resets the
 * affected inode dig_owner, to force rebuilding the digest cache.
 *
 * Return: Zero.
 */
int digest_cache_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = d_backing_inode(dentry);

	if (!S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode))
		return 0;

	digest_cache_reset_clear_owner(inode, S_ISREG(inode->i_mode) ?
				       "inode_unlink(file)" :
				       "inode_unlink(dir)");

	if (S_ISREG(inode->i_mode))
		digest_cache_reset_clear_owner(dir, "inode_unlink(dir)");

	return 0;
}

/**
 * digest_cache_inode_rename - An inode is being renamed
 * @old_dir: Inode of the directory containing the inode being renamed
 * @old_dentry: Dentry of the inode being renamed
 * @new_dir: Directory where the inode will be placed into
 * @new_dentry: Dentry of the inode after being renamed
 *
 * This function is called when an existing inode is being moved from a
 * directory to another (rename). If the inode is a digest list or the digest
 * list directory, or that inode is a digest list moved from/to the digest list
 * directory, it resets the affected inode dig_owner, to force rebuilding the
 * digest cache.
 *
 * Return: Zero.
 */
int digest_cache_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
			      struct inode *new_dir, struct dentry *new_dentry)
{
	struct inode *old_inode = d_backing_inode(old_dentry);

	if (!S_ISREG(old_inode->i_mode) && !S_ISDIR(old_inode->i_mode))
		return 0;

	digest_cache_reset_clear_owner(old_inode, S_ISREG(old_inode->i_mode) ?
				       "inode_rename(file)" :
				       "inode_rename(dir)");

	if (S_ISREG(old_inode->i_mode)) {
		digest_cache_reset_clear_owner(old_dir,
					       "inode_rename(from_dir)");
		digest_cache_reset_clear_owner(new_dir,
					       "inode_rename(to_dir)");
	}

	return 0;
}

/**
 * digest_cache_inode_post_setxattr - An xattr was set
 * @dentry: File
 * @name: Xattr name
 * @value: Xattr value
 * @size: Size of xattr value
 * @flags: Flags
 *
 * This function is called after an xattr was set on an existing inode. If the
 * inode points to a digest cache and the xattr set is security.digest_list, it
 * puts and clears dig_user in the inode security blob, to force retrieving a
 * fresh digest cache.
 */
void digest_cache_inode_post_setxattr(struct dentry *dentry, const char *name,
				      const void *value, size_t size, int flags)
{
	if (strcmp(name, XATTR_NAME_DIGEST_LIST))
		return;

	digest_cache_clear_user(d_backing_inode(dentry), dentry->d_name.name,
				"inode_post_setxattr");
}

/**
 * digest_cache_inode_post_removexattr - An xattr was removed
 * @dentry: File
 * @name: Xattr name
 *
 * This function is called after an xattr was removed from an existing inode.
 * If the inode points to a digest cache and the xattr removed is
 * security.digest_list, it puts and clears dig_user in the inode security
 * blob, to force retrieving a fresh digest cache.
 */
void digest_cache_inode_post_removexattr(struct dentry *dentry,
					 const char *name)
{
	if (strcmp(name, XATTR_NAME_DIGEST_LIST))
		return;

	digest_cache_clear_user(d_backing_inode(dentry), dentry->d_name.name,
				"inode_post_removexattr");
}
