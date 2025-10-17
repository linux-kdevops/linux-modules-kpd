// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Cryptographic API.
 *
 * SHA-3, as specified in
 * https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
 *
 * SHA-3 code by Jeff Garzik <jeff@garzik.org>
 *               Ard Biesheuvel <ard.biesheuvel@linaro.org>
 */
#include <crypto/internal/hash.h>
#include <crypto/sha3.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>

static struct sha3_ctx *crypto_sha3_desc(struct shash_desc *desc)
{
	return shash_desc_ctx(desc);
}

int crypto_sha3_init(struct shash_desc *desc)
{
	struct sha3_ctx *ctx = crypto_sha3_desc(desc);

	memset(ctx, 0, sizeof(*ctx));
	ctx->block_size = crypto_shash_blocksize(desc->tfm);
	ctx->padding = 0x06;
	return 0;
}
EXPORT_SYMBOL(crypto_sha3_init);

static int crypto_sha3_update(struct shash_desc *desc, const u8 *data,
			      unsigned int len)
{
	struct sha3_ctx *ctx = crypto_sha3_desc(desc);

	sha3_update(ctx, data, len);
	return len;
}

static int crypto_sha3_finup(struct shash_desc *desc, const u8 *src,
			     unsigned int len, u8 *out)
{
	struct sha3_ctx *ctx = crypto_sha3_desc(desc);

	if (len && src)
		sha3_update(ctx, src, len);
	sha3_squeeze(ctx, out, crypto_shash_digestsize(desc->tfm));
	sha3_clear(ctx);
	return 0;
}

static struct shash_alg algs[] = { {
	.digestsize		= SHA3_224_DIGEST_SIZE,
	.init			= crypto_sha3_init,
	.update			= crypto_sha3_update,
	.finup			= crypto_sha3_finup,
	.descsize		= sizeof(struct sha3_ctx),
	.base.cra_name		= "sha3-224",
	.base.cra_driver_name	= "sha3-224-generic",
	.base.cra_flags		= 0,
	.base.cra_blocksize	= SHA3_224_BLOCK_SIZE,
	.base.cra_module	= THIS_MODULE,
}, {
	.digestsize		= SHA3_256_DIGEST_SIZE,
	.init			= crypto_sha3_init,
	.update			= crypto_sha3_update,
	.finup			= crypto_sha3_finup,
	.descsize		= sizeof(struct sha3_ctx),
	.base.cra_name		= "sha3-256",
	.base.cra_driver_name	= "sha3-256-generic",
	.base.cra_flags		= 0,
	.base.cra_blocksize	= SHA3_256_BLOCK_SIZE,
	.base.cra_module	= THIS_MODULE,
}, {
	.digestsize		= SHA3_384_DIGEST_SIZE,
	.init			= crypto_sha3_init,
	.update			= crypto_sha3_update,
	.finup			= crypto_sha3_finup,
	.descsize		= sizeof(struct sha3_ctx),
	.base.cra_name		= "sha3-384",
	.base.cra_driver_name	= "sha3-384-generic",
	.base.cra_flags		= 0,
	.base.cra_blocksize	= SHA3_384_BLOCK_SIZE,
	.base.cra_module	= THIS_MODULE,
}, {
	.digestsize		= SHA3_512_DIGEST_SIZE,
	.init			= crypto_sha3_init,
	.update			= crypto_sha3_update,
	.finup			= crypto_sha3_finup,
	.descsize		= sizeof(struct sha3_ctx),
	.base.cra_name		= "sha3-512",
	.base.cra_driver_name	= "sha3-512-generic",
	.base.cra_flags		= 0,
	.base.cra_blocksize	= SHA3_512_BLOCK_SIZE,
	.base.cra_module	= THIS_MODULE,
} };

static int __init sha3_generic_mod_init(void)
{
	return crypto_register_shashes(algs, ARRAY_SIZE(algs));
}

static void __exit sha3_generic_mod_fini(void)
{
	crypto_unregister_shashes(algs, ARRAY_SIZE(algs));
}

module_init(sha3_generic_mod_init);
module_exit(sha3_generic_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SHA-3 Secure Hash Algorithm");

MODULE_ALIAS_CRYPTO("sha3-224");
MODULE_ALIAS_CRYPTO("sha3-224-generic");
MODULE_ALIAS_CRYPTO("sha3-256");
MODULE_ALIAS_CRYPTO("sha3-256-generic");
MODULE_ALIAS_CRYPTO("sha3-384");
MODULE_ALIAS_CRYPTO("sha3-384-generic");
MODULE_ALIAS_CRYPTO("sha3-512");
MODULE_ALIAS_CRYPTO("sha3-512-generic");
