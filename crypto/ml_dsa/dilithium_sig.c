// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
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

#include <linux/init.h>
#include <linux/module.h>
#include <crypto/internal/sig.h>
#include "dilithium.h"

enum dilithium_kernel_key_type {
	dilithium_kernel_key_unset = 0,
	dilithium_kernel_key_sk = 1,
	dilithium_kernel_key_pk = 2,
};

struct dilithium_kernel_ctx {
	union {
		struct dilithium_sk sk;
		struct dilithium_pk pk;
	};
	enum dilithium_kernel_key_type key_type;
};

/* src -> message */
/* dst -> signature */
static int dilithium_kernel_sign(struct crypto_sig *tfm, const void *src,
				 unsigned int slen, void *dst,
				 unsigned int dlen)
{
	struct dilithium_kernel_ctx *ctx = crypto_sig_ctx(tfm);
	struct dilithium_sig *sig;
	enum dilithium_type type;
	uint8_t *sig_ptr;
	size_t sig_len;
	int ret;

	if (unlikely(ctx->key_type != dilithium_kernel_key_sk))
		return -EINVAL;

	type = dilithium_sk_type(&ctx->sk);
	if (dlen != dilithium_sig_size(type))
		return -EINVAL;

	sig = kmalloc(sizeof(struct dilithium_sig), GFP_KERNEL);
	if (!sig)
		return -ENOMEM;

	ret = dilithium_sign(sig, src, slen, &ctx->sk, lc_seeded_rng);
	if (ret)
		goto out;

	ret = dilithium_sig_ptr(&sig_ptr, &sig_len, sig);
	if (ret)
		goto out;

	memcpy(dst, sig_ptr, sig_len);
	ret = sig_len;

out:
	kfree_sensitive(sig);
	return ret;
}

/* src -> signature */
/* msg -> message */
static int dilithium_kernel_verify(struct crypto_sig *tfm, const void *src,
				   unsigned int slen, const void *msg,
				   unsigned int msg_len)
{
	struct dilithium_kernel_ctx *ctx = crypto_sig_ctx(tfm);
	struct dilithium_sig *sig;
	size_t sig_len;
	enum dilithium_type type;
	int ret;

	if (unlikely(ctx->key_type != dilithium_kernel_key_pk))
		return -EINVAL;

	type = dilithium_pk_type(&ctx->pk);
	sig_len = dilithium_sig_size(type);
	if (slen < sig_len)
		return -EINVAL;

	sig = kmalloc(sizeof(struct dilithium_sig), GFP_KERNEL);
	if (!sig)
		return -ENOMEM;

	ret = dilithium_sig_load(sig, src, sig_len);
	if (ret)
		goto out;

	ret = dilithium_verify(sig, msg, msg_len, &ctx->pk);

out:
	kfree_sensitive(sig);
	return ret;
}

#ifdef CONFIG_CRYPTO_DILITHIUM_87
static unsigned int dilithium_kernel_87_key_size(struct crypto_sig *tfm)
{
	struct dilithium_kernel_ctx *ctx = crypto_sig_ctx(tfm);

	switch (ctx->key_type) {
	case dilithium_kernel_key_sk:
		return sizeof(struct dilithium_87_sk);

	case dilithium_kernel_key_unset:
	case dilithium_kernel_key_pk:
	default:
		return sizeof(struct dilithium_87_pk);
	}
}
#endif

#ifdef CONFIG_CRYPTO_DILITHIUM_65
static unsigned int dilithium_kernel_65_key_size(struct crypto_sig *tfm)
{
	struct dilithium_kernel_ctx *ctx = crypto_sig_ctx(tfm);

	switch (ctx->key_type) {
	case dilithium_kernel_key_sk:
		return sizeof(struct dilithium_65_sk);

	case dilithium_kernel_key_unset:
	case dilithium_kernel_key_pk:
	default:
		return sizeof(struct dilithium_65_pk);
	}
}
#endif

#ifdef CONFIG_CRYPTO_DILITHIUM_44
static unsigned int dilithium_kernel_44_key_size(struct crypto_sig *tfm)
{
	struct dilithium_kernel_ctx *ctx = crypto_sig_ctx(tfm);

	switch (ctx->key_type) {
	case dilithium_kernel_key_sk:
		return sizeof(struct dilithium_44_sk);

	case dilithium_kernel_key_unset:
	case dilithium_kernel_key_pk:
	default:
		return sizeof(struct dilithium_44_pk);
	}
}
#endif

static int dilithium_kernel_set_pub_key_int(struct crypto_sig *tfm,
					    const void *key,
					    unsigned int keylen,
					    enum dilithium_type type)
{
	struct dilithium_kernel_ctx *ctx = crypto_sig_ctx(tfm);
	int ret;

	ctx->key_type = dilithium_kernel_key_unset;

	ret = dilithium_pk_load(&ctx->pk, key, keylen);
	if (!ret) {
		if (dilithium_pk_type(&ctx->pk) != type)
			ret = -EOPNOTSUPP;
		else
			ctx->key_type = dilithium_kernel_key_pk;
	}

	return ret;
}

#ifdef CONFIG_CRYPTO_DILITHIUM_44
static int dilithium_kernel_44_set_pub_key(struct crypto_sig *tfm,
					   const void *key,
					   unsigned int keylen)
{
	return dilithium_kernel_set_pub_key_int(tfm, key, keylen, DILITHIUM_44);
}
#endif

#ifdef CONFIG_CRYPTO_DILITHIUM_65
static int dilithium_kernel_65_set_pub_key(struct crypto_sig *tfm,
					   const void *key,
					   unsigned int keylen)
{
	return dilithium_kernel_set_pub_key_int(tfm, key, keylen, DILITHIUM_65);
}
#endif

#ifdef CONFIG_CRYPTO_DILITHIUM_87
static int dilithium_kernel_87_set_pub_key(struct crypto_sig *tfm,
					   const void *key,
					   unsigned int keylen)
{
	return dilithium_kernel_set_pub_key_int(tfm, key, keylen, DILITHIUM_87);
}
#endif

static int dilithium_kernel_set_priv_key_int(struct crypto_sig *tfm,
					     const void *key,
					     unsigned int keylen,
					     enum dilithium_type type)
{
	struct dilithium_kernel_ctx *ctx = crypto_sig_ctx(tfm);
	int ret;

	ctx->key_type = dilithium_kernel_key_unset;

	ret = dilithium_sk_load(&ctx->sk, key, keylen);

	if (!ret) {
		if (dilithium_sk_type(&ctx->sk) != type)
			ret = -EOPNOTSUPP;
		else
			ctx->key_type = dilithium_kernel_key_sk;
	}

	return ret;
}

#ifdef CONFIG_CRYPTO_DILITHIUM_44
static int dilithium_kernel_44_set_priv_key(struct crypto_sig *tfm,
					    const void *key,
					    unsigned int keylen)
{
	return dilithium_kernel_set_priv_key_int(tfm, key, keylen,
						    DILITHIUM_44);
}
#endif

#ifdef CONFIG_CRYPTO_DILITHIUM_65
static int dilithium_kernel_65_set_priv_key(struct crypto_sig *tfm,
					    const void *key,
					    unsigned int keylen)
{
	return dilithium_kernel_set_priv_key_int(tfm, key, keylen,
						    DILITHIUM_65);
}
#endif

#ifdef CONFIG_CRYPTO_DILITHIUM_87
static int dilithium_kernel_87_set_priv_key(struct crypto_sig *tfm,
					    const void *key,
					    unsigned int keylen)
{
	return dilithium_kernel_set_priv_key_int(tfm, key, keylen,
						    DILITHIUM_87);
}
#endif

static unsigned int dilithium_kernel_max_size(struct crypto_sig *tfm)
{
	struct dilithium_kernel_ctx *ctx = crypto_sig_ctx(tfm);
	enum dilithium_type type;

	switch (ctx->key_type) {
	case dilithium_kernel_key_sk:
		type = dilithium_sk_type(&ctx->sk);
		/* When SK is set -> generate a signature */
		return dilithium_sig_size(type);
	case dilithium_kernel_key_pk:
		type = dilithium_pk_type(&ctx->pk);
		/* When PK is set, this is a safety valve, result is boolean */
		return dilithium_sig_size(type);
	default:
		return 0;
	}
}

static int dilithium_kernel_alg_init(struct crypto_sig *tfm)
{
	return 0;
}

static void dilithium_kernel_alg_exit(struct crypto_sig *tfm)
{
	struct dilithium_kernel_ctx *ctx = crypto_sig_ctx(tfm);

	ctx->key_type = dilithium_kernel_key_unset;
}

#ifdef CONFIG_CRYPTO_DILITHIUM_87
static struct sig_alg dilithium_kernel_87 = {
	.sign			= dilithium_kernel_sign,
	.verify			= dilithium_kernel_verify,
	.set_pub_key		= dilithium_kernel_87_set_pub_key,
	.set_priv_key		= dilithium_kernel_87_set_priv_key,
	.key_size		= dilithium_kernel_87_key_size,
	.max_size		= dilithium_kernel_max_size,
	.init			= dilithium_kernel_alg_init,
	.exit			= dilithium_kernel_alg_exit,
	.base.cra_name		= "ml-dsa87",
	.base.cra_driver_name	= "ml-dsa87-leancrypto",
	.base.cra_ctxsize	= sizeof(struct dilithium_kernel_ctx),
	.base.cra_module	= THIS_MODULE,
	.base.cra_priority	= 5000,
};
#endif

#ifdef CONFIG_CRYPTO_DILITHIUM_65
static struct sig_alg dilithium_kernel_65 = {
	.sign			= dilithium_kernel_sign,
	.verify			= dilithium_kernel_verify,
	.set_pub_key		= dilithium_kernel_65_set_pub_key,
	.set_priv_key		= dilithium_kernel_65_set_priv_key,
	.key_size		= dilithium_kernel_65_key_size,
	.max_size		= dilithium_kernel_max_size,
	.init			= dilithium_kernel_alg_init,
	.exit			= dilithium_kernel_alg_exit,
	.base.cra_name		= "ml-dsa65",
	.base.cra_driver_name	= "ml-dsa65-leancrypto",
	.base.cra_ctxsize	= sizeof(struct dilithium_kernel_ctx),
	.base.cra_module	= THIS_MODULE,
	.base.cra_priority	= 5000,
};
#endif

#ifdef CONFIG_CRYPTO_DILITHIUM_44
static struct sig_alg dilithium_kernel_44 = {
	.sign			= dilithium_kernel_sign,
	.verify			= dilithium_kernel_verify,
	.set_pub_key		= dilithium_kernel_44_set_pub_key,
	.set_priv_key		= dilithium_kernel_44_set_priv_key,
	.key_size		= dilithium_kernel_44_key_size,
	.max_size		= dilithium_kernel_max_size,
	.init			= dilithium_kernel_alg_init,
	.exit			= dilithium_kernel_alg_exit,
	.base.cra_name		= "ml-dsa44",
	.base.cra_driver_name	= "ml-dsa44-leancrypto",
	.base.cra_ctxsize	= sizeof(struct dilithium_kernel_ctx),
	.base.cra_module	= THIS_MODULE,
	.base.cra_priority	= 5000,
};
#endif

static int __init dilithium_init(void)
{
	int ret;

#ifdef CONFIG_CRYPTO_DILITHIUM_44
	ret = crypto_register_sig(&dilithium_kernel_44);
	if (ret < 0)
		goto error_44;
#endif
#ifdef CONFIG_CRYPTO_DILITHIUM_65
	ret = crypto_register_sig(&dilithium_kernel_65);
	if (ret < 0)
		goto error_65;
#endif
#ifdef CONFIG_CRYPTO_DILITHIUM_87
	ret = crypto_register_sig(&dilithium_kernel_87);
	if (ret < 0)
		goto error_87;
#endif
	return 0;
#ifdef CONFIG_CRYPTO_DILITHIUM_87
error_87:
#endif
#ifdef CONFIG_CRYPTO_DILITHIUM_65
	crypto_unregister_sig(&dilithium_kernel_65);
error_65:
#endif
#ifdef CONFIG_CRYPTO_DILITHIUM_44
	crypto_unregister_sig(&dilithium_kernel_44);
error_44:
#endif
	pr_err("Failed to register (%d)\n", ret);
	return ret;
}
module_init(dilithium_init);

static void dilithium_exit(void)
{
#ifdef CONFIG_CRYPTO_DILITHIUM_87
	crypto_unregister_sig(&dilithium_kernel_87);
#endif
#ifdef CONFIG_CRYPTO_DILITHIUM_65
	crypto_unregister_sig(&dilithium_kernel_65);
#endif
#ifdef CONFIG_CRYPTO_DILITHIUM_44
	crypto_unregister_sig(&dilithium_kernel_44);
#endif
}
module_exit(dilithium_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("Leancrypto ML-DSA/Dilithium");
MODULE_AUTHOR("Stephan Mueller <smueller@chronox.de>");
MODULE_ALIAS_CRYPTO("ml-dsa44");
MODULE_ALIAS_CRYPTO("ml-dsa65");
MODULE_ALIAS_CRYPTO("ml-dsa87");
