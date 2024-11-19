// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the main code of the Integrity Digest Cache.
 */

#define pr_fmt(fmt) "digest_cache: "fmt
#include <linux/namei.h>
#include <linux/xattr.h>

#include "internal.h"

static int digest_cache_enabled __ro_after_init;
static struct kmem_cache *digest_cache_cache __read_mostly;

loff_t inode_sec_offset;
loff_t file_sec_offset;

char *default_path_str = CONFIG_DIGEST_LIST_DEFAULT_PATH;

/* Protects default_path_str. */
struct rw_semaphore default_path_sem;

/**
 * digest_cache_alloc_init - Allocate and initialize a new digest cache
 * @path_str: Path string of the digest list
 * @filename: Digest list file name (can be an empty string)
 *
 * This function allocates and initializes a new digest cache.
 *
 * Return: A new digest cache on success, NULL on error.
 */
static struct digest_cache *digest_cache_alloc_init(char *path_str,
						    char *filename)
{
	struct digest_cache *digest_cache;

	digest_cache = kmem_cache_zalloc(digest_cache_cache, GFP_KERNEL);
	if (!digest_cache)
		return digest_cache;

	digest_cache->path_str = kasprintf(GFP_KERNEL, "%s%s%s", path_str,
					   filename[0] ? "/" : "", filename);
	if (!digest_cache->path_str) {
		kmem_cache_free(digest_cache_cache, digest_cache);
		return NULL;
	}

	atomic_set(&digest_cache->ref_count, 1);
	digest_cache->flags = 0UL;

	pr_debug("New digest cache %s (ref count: %d)\n",
		 digest_cache->path_str, atomic_read(&digest_cache->ref_count));

	return digest_cache;
}

/**
 * digest_cache_free - Free all memory occupied by the digest cache
 * @digest_cache: Digest cache
 *
 * This function frees the memory occupied by the digest cache.
 */
static void digest_cache_free(struct digest_cache *digest_cache)
{
	pr_debug("Freed digest cache %s\n", digest_cache->path_str);
	kfree(digest_cache->path_str);
	kmem_cache_free(digest_cache_cache, digest_cache);
}

/**
 * digest_cache_create - Create a digest cache
 * @dentry: Dentry of the inode for which the digest cache will be used
 * @default_path: Path structure of the default path
 * @digest_list_path: Path structure of the digest list
 * @path_str: Path string of the digest list
 * @filename: Digest list file name (can be an empty string)
 *
 * This function first locates, from the passed path and filename, the digest
 * list inode from which the digest cache will be created or retrieved (if it
 * already exists).
 *
 * If dig_owner is NULL in the inode security blob, this function creates a
 * new digest cache with reference count set to 1 (reference returned), sets
 * it to dig_owner and consequently increments again the digest cache reference
 * count.
 *
 * Otherwise, it simply increments the reference count of the existing
 * dig_owner, since that reference is returned to the caller.
 *
 * This function locks dig_owner_mutex to protect against concurrent requests
 * to obtain a digest cache from the same inode.
 *
 * Return: A digest cache on success, NULL on error.
 */
struct digest_cache *digest_cache_create(struct dentry *dentry,
					 struct path *default_path,
					 struct path *digest_list_path,
					 char *path_str, char *filename)
{
	struct digest_cache *digest_cache = NULL;
	struct digest_cache_security *dig_sec;
	struct inode *inode = d_backing_inode(default_path->dentry);
	int ret;

	if (S_ISDIR(inode->i_mode) && filename[0]) {
		ret = vfs_path_lookup(default_path->dentry, default_path->mnt,
				      filename, LOOKUP_FOLLOW,
				      digest_list_path);
		if (ret < 0) {
			pr_debug("Cannot find digest list %s/%s\n", path_str,
				 filename);
			return NULL;
		}

		inode = d_backing_inode(digest_list_path->dentry);

		/* No support for nested directories. */
		if (!S_ISREG(inode->i_mode)) {
			pr_debug("%s is not a regular file (no support for nested directories)\n",
				 digest_list_path->dentry->d_name.name);
			return NULL;
		}
	} else {
		digest_list_path->dentry = default_path->dentry;
		digest_list_path->mnt = default_path->mnt;
		path_get(digest_list_path);
	}

	/*
	 * Cannot request a digest cache for the same inode the digest cache
	 * is populated from.
	 */
	if (d_backing_inode(dentry) == inode) {
		pr_debug("Cannot request a digest cache for %s and create the digest cache from it\n",
			 dentry->d_name.name);
		return NULL;
	}

	dig_sec = digest_cache_get_security(inode);
	if (unlikely(!dig_sec))
		goto out;

	/* Serialize check and assignment of dig_owner. */
	mutex_lock(&dig_sec->dig_owner_mutex);
	if (dig_sec->dig_owner) {
		/* Increment ref. count for reference returned to the caller. */
		digest_cache = digest_cache_ref(dig_sec->dig_owner);
		goto out;
	}

	/* Ref. count is already 1 for this reference. */
	dig_sec->dig_owner = digest_cache_alloc_init(path_str, filename);
	if (!dig_sec->dig_owner)
		goto out;

	/* Increment ref. count for reference returned to the caller. */
	digest_cache = digest_cache_ref(dig_sec->dig_owner);

	/* Make other digest cache requestors wait until creation complete. */
	set_bit(INIT_IN_PROGRESS, &digest_cache->flags);
out:
	mutex_unlock(&dig_sec->dig_owner_mutex);
	return digest_cache;
}

/**
 * digest_cache_new - Retrieve digest list file name and request digest cache
 * @dentry: Dentry of the inode for which the digest cache will be used
 * @digest_list_path: Path structure of the digest list (updated)
 *
 * This function locates the default path. If it is a file, it directly creates
 * a digest cache from it. Otherwise, it reads the digest list file name from
 * the security.digest_list xattr and requests the creation of a digest cache
 * with that file name. If security.digest_list is empty or not found, this
 * function requests the creation of a digest cache on the parent directory.
 *
 * This function passes to the caller the path of the digest list from which
 * the digest cache was created (file or parent directory), so that
 * digest_cache_init() can reuse the same path, and to prevent the inode from
 * being evicted between creation and initialization.
 *
 * Return: A digest cache on success, NULL on error.
 */
static struct digest_cache *digest_cache_new(struct dentry *dentry,
					     struct path *digest_list_path)
{
	char filename[NAME_MAX + 1] = { 0 };
	struct digest_cache *digest_cache = NULL;
	struct path default_path;
	int ret;

	ret = kern_path(default_path_str, 0, &default_path);
	if (ret < 0) {
		pr_debug("Cannot find path %s\n", default_path_str);
		return NULL;
	}

	/* The default path is a file, no need to get xattr. */
	if (S_ISREG(d_backing_inode(default_path.dentry)->i_mode)) {
		pr_debug("Default path %s is a file, not reading %s xattr\n",
			 default_path_str, XATTR_NAME_DIGEST_LIST);
		goto create;
	} else if (!S_ISDIR(d_backing_inode(default_path.dentry)->i_mode)) {
		pr_debug("Default path %s must be either a file or a directory\n",
			 default_path_str);
		goto out;
	}

	ret = vfs_getxattr(&nop_mnt_idmap, dentry, XATTR_NAME_DIGEST_LIST,
			   filename, sizeof(filename) - 1);
	if (ret <= 0) {
		if (ret && ret != -ENODATA && ret != -EOPNOTSUPP) {
			pr_debug("Cannot get %s xattr from file %s, ret: %d\n",
				 XATTR_NAME_DIGEST_LIST, dentry->d_name.name,
				 ret);
			goto out;
		}

		pr_debug("Digest list file name not found for file %s, using %s\n",
			 dentry->d_name.name, default_path_str);

		goto create;
	}

	if (strchr(filename, '/')) {
		pr_debug("%s xattr should contain only a file name, got: %s\n",
			 XATTR_NAME_DIGEST_LIST, filename);
		goto out;
	}

	pr_debug("Found %s xattr in %s, default path: %s, digest list: %s\n",
		 XATTR_NAME_DIGEST_LIST, dentry->d_name.name, default_path_str,
		 filename);
create:
	digest_cache = digest_cache_create(dentry, &default_path,
					   digest_list_path, default_path_str,
					   filename);
out:
	path_put(&default_path);
	return digest_cache;
}

/**
 * digest_cache_init - Initialize a digest cache
 * @dentry: Dentry of the inode for which the digest cache will be used
 * @digest_list_path: Path structure of the digest list
 * @digest_cache: Digest cache to initialize
 *
 * This function checks if the INIT_STARTED digest cache flag is set. If it is,
 * or the caller didn't provide the digest list path, it waits until the caller
 * that saw INIT_STARTED unset and had the path completes the initialization.
 *
 * The latter sets INIT_STARTED (atomically), performs the initialization,
 * clears the INIT_IN_PROGRESS digest cache flag, and wakes up the other
 * callers.
 *
 * Return: A valid and initialized digest cache on success, NULL otherwise.
 */
struct digest_cache *digest_cache_init(struct dentry *dentry,
				       struct path *digest_list_path,
				       struct digest_cache *digest_cache)
{
	/* Wait for digest cache initialization. */
	if (!digest_list_path->dentry ||
	    test_and_set_bit(INIT_STARTED, &digest_cache->flags)) {
		wait_on_bit(&digest_cache->flags, INIT_IN_PROGRESS,
			    TASK_UNINTERRUPTIBLE);
		goto out;
	}

	/* Notify initialization complete. */
	clear_and_wake_up_bit(INIT_IN_PROGRESS, &digest_cache->flags);
out:
	if (test_bit(INVALID, &digest_cache->flags)) {
		pr_debug("Digest cache %s is invalid, don't return it\n",
			 digest_cache->path_str);
		digest_cache_put(digest_cache);
		digest_cache = NULL;
	}

	return digest_cache;
}

/**
 * digest_cache_get - Get a digest cache for a given inode
 * @file: File descriptor of the inode for which the digest cache will be used
 *
 * This function tries to find a digest cache from the inode security blob from
 * the passed file descriptor (dig_user field). If a digest cache was not found,
 * it calls digest_cache_new() to create a new one. In both cases, it increments
 * the digest cache reference count before returning the reference to the
 * caller.
 *
 * The caller is responsible to call digest_cache_put() to release the digest
 * cache reference returned.
 *
 * This function locks dig_user_mutex to protect against concurrent requests
 * to obtain a digest cache for the same inode.
 *
 * Return: A digest cache on success, NULL otherwise.
 */
struct digest_cache *digest_cache_get(struct file *file)
{
	struct digest_cache_security *dig_sec;
	struct digest_cache *digest_cache = NULL;
	struct inode *inode = file_inode(file);
	struct dentry *dentry = file_dentry(file);
	struct path digest_list_path = { .dentry = NULL, .mnt = NULL };

	if (!digest_cache_enabled)
		return NULL;

	/* Do not allow recursion for now. */
	if (digest_cache_opened_fd(file))
		return NULL;

	dig_sec = digest_cache_get_security(inode);
	if (unlikely(!dig_sec))
		return NULL;

	/* Serialize accesses to inode for which the digest cache is used. */
	mutex_lock(&dig_sec->dig_user_mutex);
	if (!dig_sec->dig_user) {
		down_read(&default_path_sem);
		/* Consume extra reference from digest_cache_create(). */
		dig_sec->dig_user = digest_cache_new(dentry, &digest_list_path);
		up_read(&default_path_sem);
	}

	if (dig_sec->dig_user)
		/* Increment ref. count for reference returned to the caller. */
		digest_cache = digest_cache_ref(dig_sec->dig_user);

	mutex_unlock(&dig_sec->dig_user_mutex);

	if (digest_cache)
		digest_cache = digest_cache_init(dentry, &digest_list_path,
						 digest_cache);

	if (digest_list_path.dentry)
		path_put(&digest_list_path);

	return digest_cache;
}
EXPORT_SYMBOL_GPL(digest_cache_get);

/**
 * digest_cache_put - Release a digest cache reference
 * @digest_cache: Digest cache
 *
 * This function decrements the reference count of the digest cache passed as
 * argument. If the reference count reaches zero, it calls digest_cache_free()
 * to free the digest cache.
 */
void digest_cache_put(struct digest_cache *digest_cache)
{
	struct digest_cache *to_free;

	to_free = digest_cache_unref(digest_cache);
	if (!to_free)
		return;

	digest_cache_free(to_free);
}
EXPORT_SYMBOL_GPL(digest_cache_put);

/**
 * digest_cache_opened_fd - Determine if fd is opened by Digest Cache
 * @file: File descriptor
 *
 * Determine whether or not the file descriptor was internally opened by the
 * Integrity Digest Cache.
 *
 * Return: True if it is opened by us, false otherwise.
 */
bool digest_cache_opened_fd(struct file *file)
{
	struct digest_cache *digest_cache = digest_cache_from_file_sec(file);

	return !!digest_cache;
}
EXPORT_SYMBOL_GPL(digest_cache_opened_fd);

/**
 * digest_cache_inode_alloc_security - Initialize inode security blob
 * @inode: Inode for which the security blob is initialized
 *
 * This function initializes the digest_cache_security structure, directly
 * stored in the inode security blob.
 *
 * Return: Zero.
 */
static int digest_cache_inode_alloc_security(struct inode *inode)
{
	struct digest_cache_security *dig_sec;

	/* The inode security blob is always allocated here. */
	dig_sec = digest_cache_get_security(inode);
	mutex_init(&dig_sec->dig_owner_mutex);
	mutex_init(&dig_sec->dig_user_mutex);
	return 0;
}

/**
 * digest_cache_inode_free_security_rcu - Release the digest cache references
 * @inode_security: Inode security blob
 *
 * Since the inode is being evicted, this function releases the non-needed
 * references to the digest caches stored in the digest_cache_security
 * structure.
 */
static void digest_cache_inode_free_security_rcu(void *inode_security)
{
	struct digest_cache_security *dig_sec;

	dig_sec = digest_cache_get_security_from_blob(inode_security);
	mutex_destroy(&dig_sec->dig_owner_mutex);
	mutex_destroy(&dig_sec->dig_user_mutex);
	if (dig_sec->dig_owner)
		digest_cache_put(dig_sec->dig_owner);
	if (dig_sec->dig_user)
		digest_cache_put(dig_sec->dig_user);
}

static struct security_hook_list digest_cache_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(inode_alloc_security, digest_cache_inode_alloc_security),
	LSM_HOOK_INIT(inode_free_security_rcu,
		      digest_cache_inode_free_security_rcu),
};

/**
 * digest_cache_do_init - Initialize the Integrity Digest Cache
 * @lsm_id: ID of LSM registering the LSM hooks
 * @inode_offset: Offset in the inode security blob
 * @file_offset: Offset in the file security blob
 *
 * Initialize the Integrity Digest Cache, by instantiating a cache for the
 * digest_cache structure and by registering the LSM hooks as part of the
 * calling LSM.
 */
int __init digest_cache_do_init(const struct lsm_id *lsm_id,
				loff_t inode_offset, loff_t file_offset)
{
	init_rwsem(&default_path_sem);

	inode_sec_offset = inode_offset;
	file_sec_offset = file_offset;

	digest_cache_cache = kmem_cache_create("digest_cache_cache",
					       sizeof(struct digest_cache),
					       0, SLAB_PANIC, NULL);

	security_add_hooks(digest_cache_hooks, ARRAY_SIZE(digest_cache_hooks),
			   lsm_id);

	digest_cache_enabled = 1;
	return 0;
}
