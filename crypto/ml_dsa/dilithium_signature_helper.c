// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include <linux/export.h>
#include <linux/math.h>
#include <linux/slab.h>
#include "dilithium_type.h"

#define cround(x) round_up((x), umax(DILITHIUM_AHAT_ALIGNMENT, CRYPTO_MINALIGN))

struct dilithium_ctx *dilithium_ctx_alloc(void)
{
	struct dilithium_ctx *ctx;
	struct crypto_shash *shash;
	void *p;

	shash = crypto_alloc_shash("shake256", 0, 0);
	if (IS_ERR(shash)) {
		pr_warn("no shake256: %ld\n", PTR_ERR(shash));
		return ERR_CAST(shash);
	}

	p = kzalloc(cround(sizeof(struct dilithium_ctx)) +
		    cround(crypto_shash_descsize(shash)),
		    GFP_KERNEL);
	if (!p) {
		crypto_free_shash(shash);
		return ERR_PTR(-ENOMEM);
	}

	ctx = p;
	//ctx->dilithium_hash_ctx = p + cround(sizeof(struct dilithium_ctx));
	ctx->dilithium_prehash_type = shash;
	return ctx;
}
EXPORT_SYMBOL(dilithium_ctx_alloc);

struct dilithium_ctx *dilithium_ctx_alloc_ahat(enum dilithium_type type)
{
	struct dilithium_ctx *ctx;
	struct crypto_shash *shash;
	size_t ahat_size;
	void *p;

	shash = crypto_alloc_shash("shake256", 0, 0);
	if (IS_ERR(shash))
		return ERR_CAST(shash);

	switch (type) {
#ifdef CONFIG_CRYPTO_DILITHIUM_44
	case DILITHIUM_44:
		ahat_size = DILITHIUM_44_AHAT_SIZE;
		break;
#endif
#ifdef CONFIG_CRYPTO_DILITHIUM_65
	case DILITHIUM_65:
		ahat_size = DILITHIUM_65_AHAT_SIZE;
		break;
#endif
#ifdef CONFIG_CRYPTO_DILITHIUM_87
	case DILITHIUM_87:
		ahat_size = DILITHIUM_87_AHAT_SIZE;
		break;
#endif
	default:
		WARN_ON(1);
		return ERR_PTR(-EINVAL);
	}

	p = kzalloc(cround(sizeof(struct dilithium_ctx)) +
		    cround(ahat_size) +
		    cround(crypto_shash_descsize(shash)),
		    GFP_KERNEL);
	if (!p) {
		crypto_free_shash(shash);
		return ERR_PTR(-ENOMEM);
	}

	ctx = p;
	p += cround(sizeof(struct dilithium_ctx));
	ctx->ahat = p;
	ctx->ahat_size = ahat_size;
	p += cround(ahat_size);
	//ctx->dilithium_hash_ctx = p;
	ctx->dilithium_prehash_type = shash;
	return ctx;
}
EXPORT_SYMBOL(dilithium_ctx_alloc_ahat);

void dilithium_ctx_zero_free(struct dilithium_ctx *ctx)
{
	crypto_free_shash(ctx->dilithium_prehash_type);
	kfree_sensitive(ctx);
}
EXPORT_SYMBOL(dilithium_ctx_zero_free);
