// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Manage digest caches from directories.
 */

#define pr_fmt(fmt) "digest_cache: "fmt
#include <linux/init_task.h>
#include <linux/namei.h>

#include "internal.h"

/**
 * digest_cache_dir_iter - Digest cache directory iterator
 * @__ctx: iterate_dir() context
 * @name: Name of file in the accessed directory
 * @namelen: String length of @name
 * @offset: Current position in the directory stream (see man readdir)
 * @ino: Inode number
 * @d_type: File type
 *
 * This function stores the names of the files in the containing directory in
 * a linked list. If they are in the format
 * <seq num>-<digest list format>-<digest list name>, this function orders them
 * by seq num, so that digest lists are processed in the desired order.
 * Otherwise, if <seq num>- is not included, it adds the name at the end of
 * the list.
 *
 * Return: True to continue processing, false to stop.
 */
static bool digest_cache_dir_iter(struct dir_context *__ctx, const char *name,
				  int namelen, loff_t offset, u64 ino,
				  unsigned int d_type)
{
	struct readdir_callback *ctx = container_of(__ctx, typeof(*ctx), ctx);
	struct dir_entry *new_entry, *p;
	unsigned int seq_num;
	char *separator;
	int ret;

	if (!strcmp(name, ".") || !strcmp(name, ".."))
		return true;

	if (d_type != DT_REG)
		return true;

	new_entry = kmalloc(sizeof(*new_entry) + namelen + 1, GFP_KERNEL);
	if (!new_entry)
		return false;

	memcpy(new_entry->name, name, namelen);
	new_entry->name[namelen] = '\0';
	new_entry->seq_num = UINT_MAX;
	new_entry->digest_cache = NULL;
	mutex_init(&new_entry->digest_cache_mutex);
	new_entry->prefetched = false;

	if (new_entry->name[0] < '0' || new_entry->name[0] > '9')
		goto out;

	separator = strchr(new_entry->name, '-');
	if (!separator)
		goto out;

	*separator = '\0';
	ret = kstrtouint(new_entry->name, 10, &seq_num);
	*separator = '-';
	if (ret < 0)
		goto out;

	new_entry->seq_num = seq_num;

	list_for_each_entry(p, ctx->head, list) {
		if (seq_num <= p->seq_num) {
			list_add(&new_entry->list, p->list.prev);
			pr_debug("Added %s before %s in dir list\n",
				 new_entry->name, p->name);
			return true;
		}
	}
out:
	list_add_tail(&new_entry->list, ctx->head);
	pr_debug("Added %s to tail of dir list\n", new_entry->name);
	return true;
}

/**
 * digest_cache_dir_add_entries - Add dir entries to a dir digest cache
 * @digest_cache: Dir digest cache
 * @digest_list_path: Path structure of the digest list directory
 *
 * This function iterates over the entries of a directory, and creates a linked
 * list of file names from that directory.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
int digest_cache_dir_add_entries(struct digest_cache *digest_cache,
				 struct path *digest_list_path)
{
	struct file *dir_file;
	struct readdir_callback buf = {
		.ctx.actor = digest_cache_dir_iter,
		.ctx.pos = 0,
		.head = &digest_cache->dir_entries,
	};
	int ret;

	dir_file = kernel_file_open(digest_list_path, O_RDONLY, &init_cred);
	if (IS_ERR(dir_file)) {
		pr_debug("Cannot access %s, ret: %ld\n", digest_cache->path_str,
			 PTR_ERR(dir_file));
		return PTR_ERR(dir_file);
	}

	ret = iterate_dir(dir_file, &buf.ctx);
	if (ret < 0)
		pr_debug("Failed to iterate directory %s\n",
			 digest_cache->path_str);

	fput(dir_file);
	return ret;
}

/**
 * digest_cache_dir_create - Create and initialize a directory digest cache
 * @dentry: Dentry of the file whose digest is looked up
 * @dir_path: Path structure of the digest list directory (updated)
 * @path_str: Path string of the digest list directory
 *
 * This function creates and initializes (or obtains if it already exists) a
 * directory digest cache. It updates the path that digest cache was
 * created/obtained from, so that the caller can use it to perform lookup
 * operations.
 *
 * Before creating the digest cache, this function first calls
 * digest_cache_prefetch_requested() to check if prefetching has been requested
 * on the directory, and passes the result to digest_cache_create(), so that the
 * latter sets the DIR_PREFETCH bit in the directory digest cache.
 *
 * Return: A directory digest cache on success, NULL otherwise.
 */
static struct digest_cache *digest_cache_dir_create(struct dentry *dentry,
						    struct path *dir_path,
						    char *path_str)
{
	struct digest_cache *digest_cache;
	struct path _dir_path;
	bool prefetch_req;
	int ret;

	ret = kern_path(path_str, 0, &_dir_path);
	if (ret < 0) {
		pr_debug("Cannot find path %s\n", path_str);
		return NULL;
	}

	prefetch_req = digest_cache_prefetch_requested(&_dir_path, path_str);

	digest_cache = digest_cache_create(dentry, &_dir_path, dir_path,
					   path_str, "", prefetch_req, false);
	if (digest_cache)
		digest_cache = digest_cache_init(dentry, dir_path,
						 digest_cache);

	path_put(&_dir_path);
	return digest_cache;
}

/**
 * digest_cache_dir_lookup_digest - Lookup a digest
 * @dentry: Dentry of the file whose digest is looked up
 * @digest_cache: Dir digest cache
 * @digest: Digest to search
 * @algo: Algorithm of the digest to search
 *
 * This function iterates over the linked list created by
 * digest_cache_dir_add_entries() and looks up the digest in the digest cache
 * of each entry.
 *
 * Return: A digest cache reference if the digest is found, NULL if not, an
 *         error pointer if dir digest cache changed since last get.
 */
struct digest_cache *
digest_cache_dir_lookup_digest(struct dentry *dentry,
			       struct digest_cache *digest_cache, u8 *digest,
			       enum hash_algo algo)
{
	struct dir_entry *dir_entry;
	struct digest_cache *dir_cache, *cache, *found = NULL;
	struct path dir_path = { .dentry = NULL, .mnt = NULL };
	struct path digest_list_path;
	int ret;

	/* Try to reacquire the dir digest cache, and check if changed. */
	dir_cache = digest_cache_dir_create(dentry, &dir_path,
					    digest_cache->path_str);
	if (dir_cache != digest_cache) {
		if (dir_cache)
			found = ERR_PTR(-EAGAIN);

		goto out;
	}

	list_for_each_entry(dir_entry, &dir_cache->dir_entries, list) {
		mutex_lock(&dir_entry->digest_cache_mutex);
		if (dir_entry->digest_cache &&
		    test_bit(RESET, &dir_entry->digest_cache->flags)) {
			digest_cache_put(dir_entry->digest_cache);
			dir_entry->digest_cache = NULL;
		}

		if (!dir_entry->digest_cache) {
			digest_list_path.dentry = NULL;
			digest_list_path.mnt = NULL;

			cache = digest_cache_create(dentry, &dir_path,
						    &digest_list_path,
						    dir_cache->path_str,
						    dir_entry->name, false,
						    false);
			if (cache)
				cache = digest_cache_init(dentry,
							  &digest_list_path,
							  cache);

			if (digest_list_path.dentry)
				path_put(&digest_list_path);

			/* Ignore digest caches that cannot be instantiated. */
			if (!cache) {
				mutex_unlock(&dir_entry->digest_cache_mutex);
				continue;
			}

			/* Consume extra ref. from digest_cache_create(). */
			dir_entry->digest_cache = cache;
			/* Digest list was read, mark entry as prefetched. */
			dir_entry->prefetched = true;
		}
		mutex_unlock(&dir_entry->digest_cache_mutex);

		ret = digest_cache_htable_lookup(dentry,
						 dir_entry->digest_cache,
						 digest, algo);
		if (!ret) {
			found = digest_cache_ref(dir_entry->digest_cache);
			break;
		}
	}
out:
	if (dir_cache)
		digest_cache_put(dir_cache);
	if (dir_path.dentry)
		path_put(&dir_path);

	return found;
}

/**
 * digest_cache_dir_lookup_filename - Lookup a digest list
 * @dentry: Dentry of the file whose digest list is looked up
 * @dir_path: Path structure of the digest list directory
 * @digest_cache: Dir digest cache
 * @filename: File name of the digest list to search
 *
 * This function iterates over the linked list created by
 * digest_cache_dir_add_entries() and looks up a digest list with a matching
 * file name among the entries. If there is no match, it prefetches (reads) the
 * current digest list. Otherwise, it creates and initializes a new digest
 * cache.
 *
 * The new digest cache is not returned, since it might have been created from
 * a different inode than the one originally found during digest_cache_create().
 *
 * If it is the right one, digest_cache_init() called from digest_cache_get()
 * will go ahead and simply use the initialized digest cache. If for any reason
 * the inode was different, digest_cache_init() will use the one previously
 * returned by digest_cache_create().
 */
static void digest_cache_dir_lookup_filename(struct dentry *dentry,
					     struct path *dir_path,
					     struct digest_cache *digest_cache,
					     char *filename)
{
	struct digest_cache *cache;
	struct dir_entry *dir_entry;
	struct path digest_list_path;
	bool filename_found;

	list_for_each_entry(dir_entry, &digest_cache->dir_entries, list) {
		mutex_lock(&dir_entry->digest_cache_mutex);
		filename_found = !strcmp(dir_entry->name, filename);
		if (!filename_found && dir_entry->prefetched) {
			mutex_unlock(&dir_entry->digest_cache_mutex);
			continue;
		}

		digest_list_path.dentry = NULL;
		digest_list_path.mnt = NULL;

		cache = digest_cache_create(dentry, dir_path, &digest_list_path,
					    digest_cache->path_str,
					    dir_entry->name, false,
					    filename_found ? false : true);
		if (cache)
			cache = digest_cache_init(dentry, &digest_list_path,
						  cache);

		if (digest_list_path.dentry)
			path_put(&digest_list_path);

		if (!filename_found)
			pr_debug("Digest list %s/%s %s prefetched\n",
				 digest_cache->path_str, dir_entry->name,
				 cache ? "has been" : "cannot be");

		if (cache)
			digest_cache_put(cache);

		dir_entry->prefetched = true;
		mutex_unlock(&dir_entry->digest_cache_mutex);

		if (filename_found)
			break;
	}

	/* Prefetching done, no need to repeat. */
	clear_bit(FILE_PREFETCH, &digest_cache->flags);
}

/**
 * digest_cache_dir_prefetch - Prefetch digest lists in parent directory
 * @dentry: Dentry of the file whose digest list is looked up
 * @digest_cache: Digest cache
 *
 * This function prefetches the digest lists in the parent directory of the
 * passed digest cache.
 *
 * Return: Zero on success, a POSIX error code otherwise.
 */
int digest_cache_dir_prefetch(struct dentry *dentry,
			      struct digest_cache *digest_cache)
{
	struct digest_cache *dir_cache;
	char *path_str, *last;
	struct path dir_path = { .dentry = NULL, .mnt = NULL };
	int ret = 0;

	last = strrchr(digest_cache->path_str, '/');
	if (!last)
		return -EINVAL;

	path_str = kstrndup(digest_cache->path_str,
			    last - digest_cache->path_str, GFP_KERNEL);
	if (!path_str)
		return -ENOMEM;

	dir_cache = digest_cache_dir_create(dentry, &dir_path, path_str);

	kfree(path_str);

	if (!dir_cache) {
		ret = -ENOENT;
		goto out;
	}

	digest_cache_dir_lookup_filename(dentry, &dir_path, dir_cache,
					 last + 1);

	digest_cache_put(dir_cache);
out:
	if (dir_path.dentry)
		path_put(&dir_path);

	return ret;
}

/**
 * digest_cache_dir_free - Free the stored file list and put digest caches
 * @digest_cache: Dir digest cache
 *
 * This function frees the file list created by digest_cache_dir_add_entries(),
 * and puts the digest cache of each directory entry, if a reference exists.
 */
void digest_cache_dir_free(struct digest_cache *digest_cache)
{
	struct dir_entry *p, *q;

	list_for_each_entry_safe(p, q, &digest_cache->dir_entries, list) {
		if (p->digest_cache)
			digest_cache_put(p->digest_cache);

		list_del(&p->list);
		mutex_destroy(&p->digest_cache_mutex);
		kfree(p);
	}
}
