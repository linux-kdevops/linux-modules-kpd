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

#ifdef CONFIG_INTEGRITY_DIGEST_CACHE
/* Client API */
struct digest_cache *digest_cache_get(struct file *file);
void digest_cache_put(struct digest_cache *digest_cache);
bool digest_cache_opened_fd(struct file *file);

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

#endif /* CONFIG_INTEGRITY_DIGEST_CACHE */
#endif /* _LINUX_DIGEST_CACHE_H */
