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

struct digest_cache;

/**
 * typedef parser_func - Function to parse digest lists
 *
 * Define a function type to parse digest lists.
 */
typedef int (*parser_func)(struct digest_cache *digest_cache, const u8 *data,
			   size_t data_len);

/**
 * struct parser - Structure to store a function pointer to parse digest list
 * @list: Linked list
 * @owner: Kernel module owning the parser
 * @name: Parser name (must match the format in the digest list file name)
 * @func: Function pointer for parsing
 *
 * This structure stores a function pointer to parse a digest list.
 */
struct parser {
	struct list_head list;
	struct module *owner;
	const char name[NAME_MAX + 1];
	parser_func func;
};

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
int digest_cache_register_parser(struct parser *parser);
void digest_cache_unregister_parser(struct parser *parser);

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

static inline int digest_cache_register_parser(const char *name,
					       parser_func func)
{
	return -EOPNOTSUPP;
}

static inline void digest_cache_unregister_parser(const char *name)
{
}

#endif /* CONFIG_INTEGRITY_DIGEST_CACHE */
#endif /* _LINUX_DIGEST_CACHE_H */
