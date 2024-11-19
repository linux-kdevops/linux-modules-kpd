/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Internal header of the Integrity Digest Cache.
 */

#ifndef _DIGEST_CACHE_INTERNAL_H
#define _DIGEST_CACHE_INTERNAL_H

#include <linux/lsm_hooks.h>
#include <linux/digest_cache.h>

/* Digest cache bits in flags. */
#define INIT_IN_PROGRESS	0	/* Digest cache being initialized. */
#define INIT_STARTED		1	/* Digest cache init started. */
#define INVALID			2	/* Digest cache marked as invalid. */

/**
 * struct read_work - Structure to schedule reading a digest list
 * @work: Work structure
 * @file: File descriptor of the digest list to read
 * @data: Digest list data (updated)
 * @ret: Return value from kernel_read_file() (updated)
 *
 * This structure contains the necessary information to schedule reading a
 * digest list.
 */
struct read_work {
	struct work_struct work;
	struct file *file;
	void *data;
	int ret;
};

/**
 * struct digest_cache_entry - Entry of a digest cache hash table
 * @hnext: Pointer to the next element in the collision list
 * @digest: Stored digest
 *
 * This structure represents an entry of a digest cache hash table, storing a
 * digest.
 */
struct digest_cache_entry {
	struct hlist_node hnext;
	u8 digest[];
};

/**
 * struct htable - Hash table
 * @next: Next hash table in the linked list
 * @slots: Hash table slots
 * @num_slots: Number of slots
 * @num_digests: Number of digests stored in the hash table
 * @algo: Algorithm of the digests
 *
 * This structure is a hash table storing digests of file data or metadata.
 */
struct htable {
	struct list_head next;
	struct hlist_head *slots;
	unsigned int num_slots;
	u64 num_digests;
	enum hash_algo algo;
};

/**
 * struct digest_cache - Digest cache
 * @htables: Hash tables (one per algorithm)
 * @ref_count: Number of references to the digest cache
 * @path_str: Path of the digest list the digest cache was created from
 * @flags: Control flags
 *
 * This structure represents a cache of digests extracted from a digest list.
 */
struct digest_cache {
	struct list_head htables;
	atomic_t ref_count;
	char *path_str;
	unsigned long flags;
};

/**
 * struct digest_cache_security - Digest cache pointers in inode security blob
 * @dig_owner: Digest cache created from this inode
 * @dig_owner_mutex: Protects @dig_owner
 * @dig_user: Digest cache requested for this inode
 * @dig_user_mutex: Protects @dig_user
 *
 * This structure contains references to digest caches, protected by their
 * respective mutex.
 */
struct digest_cache_security {
	struct digest_cache *dig_owner;
	struct mutex dig_owner_mutex;
	struct digest_cache *dig_user;
	struct mutex dig_user_mutex;
};

extern loff_t inode_sec_offset;
extern loff_t file_sec_offset;
extern char *default_path_str;
extern struct rw_semaphore default_path_sem;

static inline struct digest_cache_security *
digest_cache_get_security_from_blob(void *inode_security)
{
	return inode_security + inode_sec_offset;
}

static inline struct digest_cache_security *
digest_cache_get_security(const struct inode *inode)
{
	if (unlikely(!inode->i_security))
		return NULL;

	return digest_cache_get_security_from_blob(inode->i_security);
}

static inline struct digest_cache *
digest_cache_ref(struct digest_cache *digest_cache)
{
	int ref_count = atomic_inc_return(&digest_cache->ref_count);

	pr_debug("Ref (+) digest cache %s (ref count: %d)\n",
		 digest_cache->path_str, ref_count);
	return digest_cache;
}

static inline struct digest_cache *
digest_cache_unref(struct digest_cache *digest_cache)
{
	bool ref_is_zero;

	/* Unreliable ref. count, but cannot decrement before print (UAF). */
	pr_debug("Ref (-) digest cache %s (ref count: %d)\n",
		 digest_cache->path_str,
		 atomic_read(&digest_cache->ref_count) - 1);

	ref_is_zero = atomic_dec_and_test(&digest_cache->ref_count);
	return (ref_is_zero) ? digest_cache : NULL;
}

static inline void digest_cache_to_file_sec(const struct file *file,
					    struct digest_cache *digest_cache)
{
	struct digest_cache **digest_cache_sec;

	digest_cache_sec = file->f_security + file_sec_offset;
	*digest_cache_sec = digest_cache;
}

static inline struct digest_cache *
digest_cache_from_file_sec(const struct file *file)
{
	struct digest_cache **digest_cache_sec;

	digest_cache_sec = file->f_security + file_sec_offset;
	return *digest_cache_sec;
}

/* main.c */
struct digest_cache *digest_cache_create(struct dentry *dentry,
					 struct path *default_path,
					 struct path *digest_list_path,
					 char *path_str, char *filename);
struct digest_cache *digest_cache_init(struct dentry *dentry,
				       struct path *digest_list_path,
				       struct digest_cache *digest_cache);
int __init digest_cache_do_init(const struct lsm_id *lsm_id,
				loff_t inode_offset, loff_t file_offset);

/* secfs.c */
int __init digest_cache_secfs_init(struct dentry *dir);

/* htable.c */
void digest_cache_htable_free(struct digest_cache *digest_cache);

/* parsers.c */
int digest_cache_parse_digest_list(struct dentry *dentry,
				   struct digest_cache *digest_cache,
				   char *path_str, void *data, size_t data_len);

/* populate.c */
int digest_cache_populate(struct dentry *dentry,
			  struct digest_cache *digest_cache,
			  struct path *digest_list_path);

/* modsig.c */
size_t digest_cache_strip_modsig(__u8 *data, size_t data_len);

#endif /* _DIGEST_CACHE_INTERNAL_H */
