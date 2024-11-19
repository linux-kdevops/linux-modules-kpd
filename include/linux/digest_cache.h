/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2024 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Public API of the Integrity Digest Cache.
 */

#ifndef _LINUX_DIGEST_CACHE_H
#define _LINUX_DIGEST_CACHE_H

#include <linux/fs.h>
#include <crypto/hash_info.h>

#ifdef CONFIG_INTEGRITY_DIGEST_CACHE
/* Client API */
struct digest_cache *digest_cache_get(struct file *file);
void digest_cache_put(struct digest_cache *digest_cache);
bool digest_cache_opened_fd(struct file *file);
struct digest_cache *digest_cache_lookup(struct dentry *dentry,
					 struct digest_cache *digest_cache,
					 u8 *digest, enum hash_algo algo);

/* Parser API */
int digest_cache_htable_init(struct digest_cache *digest_cache, u64 num_digests,
			     enum hash_algo algo);
int digest_cache_htable_add(struct digest_cache *digest_cache, u8 *digest,
			    enum hash_algo algo);
int digest_cache_htable_lookup(struct dentry *dentry,
			       struct digest_cache *digest_cache, u8 *digest,
			       enum hash_algo algo);

#else
static inline struct digest_cache *digest_cache_get(struct file *file)
{
	return NULL;
}

static inline void digest_cache_put(struct digest_cache *digest_cache)
{
}

static inline bool digest_cache_opened_fd(struct file *file)
{
	return false;
}

static inline struct digest_cache *
digest_cache_lookup(struct dentry *dentry, struct digest_cache *digest_cache,
		    u8 *digest, enum hash_algo algo)
{
	return NULL;
}

static inline int digest_cache_htable_init(struct digest_cache *digest_cache,
					   u64 num_digests, enum hash_algo algo)
{
	return -EOPNOTSUPP;
}

static inline int digest_cache_htable_add(struct digest_cache *digest_cache,
					  u8 *digest, enum hash_algo algo)
{
	return -EOPNOTSUPP;
}

static inline int digest_cache_htable_lookup(struct dentry *dentry,
					     struct digest_cache *digest_cache,
					     u8 *digest, enum hash_algo algo)
{
	return -EOPNOTSUPP;
}

#endif /* CONFIG_INTEGRITY_DIGEST_CACHE */
#endif /* _LINUX_DIGEST_CACHE_H */
