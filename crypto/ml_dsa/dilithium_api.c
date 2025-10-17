// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/pq-crystals/dilithium
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/);
 * or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).
 */

#ifndef DILITHIUM_API_H
#define DILITHIUM_API_H

#include <linux/export.h>
#include "dilithium.h"
#include "dilithium_pct.h"

void dilithium_ctx_zero(struct dilithium_ctx *ctx)
{
	if (!ctx)
		return;

#ifdef CONFIG_CRYPTO_DILITHIUM_87
	dilithium_87_ctx_zero(ctx);
#elif defined(CONFIG_CRYPTO_DILITHIUM_65)
	dilithium_65_ctx_zero(ctx);
#elif defined(CONFIG_CRYPTO_DILITHIUM_44)
	dilithium_44_ctx_zero(ctx);
#endif
}
EXPORT_SYMBOL(dilithium_ctx_zero);

void dilithium_ctx_internal(struct dilithium_ctx *ctx)
{
	if (ctx)
		ctx->ml_dsa_internal = 1;
}
EXPORT_SYMBOL(dilithium_ctx_internal);

void dilithium_ctx_hash(struct dilithium_ctx *ctx,
			struct crypto_shash *hash)
{
	if (ctx)
		ctx->dilithium_prehash_type = hash;
}
EXPORT_SYMBOL(dilithium_ctx_hash);

void dilithium_ctx_userctx(struct dilithium_ctx *ctx, const uint8_t *userctx,
			   size_t userctxlen)
{
	if (ctx) {
		ctx->userctx = userctx;
		ctx->userctxlen = userctxlen;
	}
}
EXPORT_SYMBOL(dilithium_ctx_userctx);

void dilithium_ctx_external_mu(struct dilithium_ctx *ctx, const uint8_t *external_mu,
			       size_t external_mu_len)
{
	if (ctx) {
		ctx->external_mu = external_mu;
		ctx->external_mu_len = external_mu_len;
	}
}
EXPORT_SYMBOL(dilithium_ctx_external_mu);

void dilithium_ctx_drop_ahat(struct dilithium_ctx *ctx)
{
	if (ctx)
		ctx->ahat_expanded = 0;
}
EXPORT_SYMBOL(dilithium_ctx_drop_ahat);

enum dilithium_type dilithium_sk_type(const struct dilithium_sk *sk)
{
	if (!sk)
		return DILITHIUM_UNKNOWN;
	return sk->dilithium_type;
}
EXPORT_SYMBOL(dilithium_sk_type);

enum dilithium_type dilithium_pk_type(const struct dilithium_pk *pk)
{
	if (!pk)
		return DILITHIUM_UNKNOWN;
	return pk->dilithium_type;
}
EXPORT_SYMBOL(dilithium_pk_type);

enum dilithium_type dilithium_sig_type(const struct dilithium_sig *sig)
{
	if (!sig)
		return DILITHIUM_UNKNOWN;
	return sig->dilithium_type;
}
EXPORT_SYMBOL(dilithium_sig_type);

__pure unsigned int dilithium_sk_size(enum dilithium_type dilithium_type)
{
	switch (dilithium_type) {
	case DILITHIUM_87:
#ifdef CONFIG_CRYPTO_DILITHIUM_87
		return sizeof_field(struct dilithium_sk, key.sk_87);
#else
		return 0;
#endif
	case DILITHIUM_65:
#ifdef CONFIG_CRYPTO_DILITHIUM_65
		return sizeof_field(struct dilithium_sk, key.sk_65);
#else
		return 0;
#endif
	case DILITHIUM_44:
#ifdef CONFIG_CRYPTO_DILITHIUM_44
		return sizeof_field(struct dilithium_sk, key.sk_44);
#else
		return 0;
#endif
	case DILITHIUM_UNKNOWN:
	default:
		return 0;
	}
}
EXPORT_SYMBOL(dilithium_sk_size);

__pure unsigned int dilithium_pk_size(enum dilithium_type dilithium_type)
{
	switch (dilithium_type) {
	case DILITHIUM_87:
#ifdef CONFIG_CRYPTO_DILITHIUM_87
		return sizeof_field(struct dilithium_pk, key.pk_87);
#else
		return 0;
#endif
	case DILITHIUM_65:
#ifdef CONFIG_CRYPTO_DILITHIUM_65
		return sizeof_field(struct dilithium_pk, key.pk_65);
#else
		return 0;
#endif
	case DILITHIUM_44:
#ifdef CONFIG_CRYPTO_DILITHIUM_44
		return sizeof_field(struct dilithium_pk, key.pk_44);
#else
		return 0;
#endif
	case DILITHIUM_UNKNOWN:
	default:
		return 0;
	}
}
EXPORT_SYMBOL(dilithium_pk_size);

__pure unsigned int dilithium_sig_size(enum dilithium_type dilithium_type)
{
	switch (dilithium_type) {
	case DILITHIUM_87:
#ifdef CONFIG_CRYPTO_DILITHIUM_87
		return sizeof_field(struct dilithium_sig, sig.sig_87);
#else
		return 0;
#endif
	case DILITHIUM_65:
#ifdef CONFIG_CRYPTO_DILITHIUM_65
		return sizeof_field(struct dilithium_sig, sig.sig_65);
#else
		return 0;
#endif
	case DILITHIUM_44:
#ifdef CONFIG_CRYPTO_DILITHIUM_44
		return sizeof_field(struct dilithium_sig, sig.sig_44);
#else
		return 0;
#endif
	case DILITHIUM_UNKNOWN:
	default:
		return 0;
	}
}
EXPORT_SYMBOL(dilithium_sig_size);

int dilithium_sk_load(struct dilithium_sk *sk,
		      const uint8_t *src_key, size_t src_key_len)
{
	if (!sk || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef CONFIG_CRYPTO_DILITHIUM_87
	} else if (src_key_len == dilithium_sk_size(DILITHIUM_87)) {
		struct dilithium_87_sk *_sk = &sk->key.sk_87;

		memcpy(_sk->sk, src_key, src_key_len);
		sk->dilithium_type = DILITHIUM_87;
		return 0;
#endif
#ifdef CONFIG_CRYPTO_DILITHIUM_65
	} else if (src_key_len == dilithium_sk_size(DILITHIUM_65)) {
		struct dilithium_65_sk *_sk = &sk->key.sk_65;

		memcpy(_sk->sk, src_key, src_key_len);
		sk->dilithium_type = DILITHIUM_65;
		return 0;
#endif
#ifdef CONFIG_CRYPTO_DILITHIUM_44
	} else if (src_key_len == dilithium_sk_size(DILITHIUM_44)) {
		struct dilithium_44_sk *_sk = &sk->key.sk_44;

		memcpy(_sk->sk, src_key, src_key_len);
		sk->dilithium_type = DILITHIUM_44;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}
EXPORT_SYMBOL(dilithium_sk_load);

int dilithium_pk_load(struct dilithium_pk *pk,
		      const uint8_t *src_key, size_t src_key_len)
{
	if (!pk || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef CONFIG_CRYPTO_DILITHIUM_87
	} else if (src_key_len == dilithium_pk_size(DILITHIUM_87)) {
		struct dilithium_87_pk *_pk = &pk->key.pk_87;

		memcpy(_pk->pk, src_key, src_key_len);
		pk->dilithium_type = DILITHIUM_87;
		return 0;
#endif
#ifdef CONFIG_CRYPTO_DILITHIUM_65
	} else if (src_key_len == dilithium_pk_size(DILITHIUM_65)) {
		struct dilithium_65_pk *_pk = &pk->key.pk_65;

		memcpy(_pk->pk, src_key, src_key_len);
		pk->dilithium_type = DILITHIUM_65;
		return 0;
#endif
#ifdef CONFIG_CRYPTO_DILITHIUM_44
	} else if (src_key_len == dilithium_pk_size(DILITHIUM_44)) {
		struct dilithium_44_pk *_pk = &pk->key.pk_44;

		memcpy(_pk->pk, src_key, src_key_len);
		pk->dilithium_type = DILITHIUM_44;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}
EXPORT_SYMBOL(dilithium_pk_load);

int dilithium_sig_load(struct dilithium_sig *sig,
		       const uint8_t *src_sig, size_t src_sig_len)
{
	if (!sig || !src_sig || src_sig_len == 0) {
		return -EINVAL;
#ifdef CONFIG_CRYPTO_DILITHIUM_87
	} else if (src_sig_len == dilithium_sig_size(DILITHIUM_87)) {
		struct dilithium_87_sig *_sig = &sig->sig.sig_87;

		memcpy(_sig->sig, src_sig, src_sig_len);
		sig->dilithium_type = DILITHIUM_87;
		return 0;
#endif
#ifdef CONFIG_CRYPTO_DILITHIUM_65
	} else if (src_sig_len == dilithium_sig_size(DILITHIUM_65)) {
		struct dilithium_65_sig *_sig = &sig->sig.sig_65;

		memcpy(_sig->sig, src_sig, src_sig_len);
		sig->dilithium_type = DILITHIUM_65;
		return 0;
#endif
#ifdef CONFIG_CRYPTO_DILITHIUM_44
	} else if (src_sig_len == dilithium_sig_size(DILITHIUM_44)) {
		struct dilithium_44_sig *_sig = &sig->sig.sig_44;

		memcpy(_sig->sig, src_sig, src_sig_len);
		sig->dilithium_type = DILITHIUM_44;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}
EXPORT_SYMBOL(dilithium_sig_load);

int dilithium_sk_ptr(uint8_t **dilithium_key,
		     size_t *dilithium_key_len, struct dilithium_sk *sk)
{
	if (!sk || !dilithium_key || !dilithium_key_len) {
		return -EINVAL;
#ifdef CONFIG_CRYPTO_DILITHIUM_87
	} else if (sk->dilithium_type == DILITHIUM_87) {
		struct dilithium_87_sk *_sk = &sk->key.sk_87;

		*dilithium_key = _sk->sk;
		*dilithium_key_len = dilithium_sk_size(sk->dilithium_type);
		return 0;
#endif
#ifdef CONFIG_CRYPTO_DILITHIUM_65
	} else if (sk->dilithium_type == DILITHIUM_65) {
		struct dilithium_65_sk *_sk = &sk->key.sk_65;

		*dilithium_key = _sk->sk;
		*dilithium_key_len = dilithium_sk_size(sk->dilithium_type);
		return 0;
#endif
#ifdef CONFIG_CRYPTO_DILITHIUM_44
	} else if (sk->dilithium_type == DILITHIUM_44) {
		struct dilithium_44_sk *_sk = &sk->key.sk_44;

		*dilithium_key = _sk->sk;
		*dilithium_key_len = dilithium_sk_size(sk->dilithium_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}
EXPORT_SYMBOL(dilithium_sk_ptr);

int dilithium_pk_ptr(uint8_t **dilithium_key,
		     size_t *dilithium_key_len, struct dilithium_pk *pk)
{
	if (!pk || !dilithium_key || !dilithium_key_len) {
		return -EINVAL;
#ifdef CONFIG_CRYPTO_DILITHIUM_87
	} else if (pk->dilithium_type == DILITHIUM_87) {
		struct dilithium_87_pk *_pk = &pk->key.pk_87;

		*dilithium_key = _pk->pk;
		*dilithium_key_len = dilithium_pk_size(pk->dilithium_type);
		return 0;
#endif
#ifdef CONFIG_CRYPTO_DILITHIUM_65
	} else if (pk->dilithium_type == DILITHIUM_65) {
		struct dilithium_65_pk *_pk = &pk->key.pk_65;

		*dilithium_key = _pk->pk;
		*dilithium_key_len = dilithium_pk_size(pk->dilithium_type);
		return 0;
#endif
#ifdef CONFIG_CRYPTO_DILITHIUM_44
	} else if (pk->dilithium_type == DILITHIUM_44) {
		struct dilithium_44_pk *_pk = &pk->key.pk_44;

		*dilithium_key = _pk->pk;
		*dilithium_key_len = dilithium_pk_size(pk->dilithium_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}
EXPORT_SYMBOL(dilithium_pk_ptr);

int dilithium_sig_ptr(uint8_t **dilithium_sig,
		      size_t *dilithium_sig_len, struct dilithium_sig *sig)
{
	if (!sig || !dilithium_sig || !dilithium_sig_len) {
		return -EINVAL;
#ifdef CONFIG_CRYPTO_DILITHIUM_87
	} else if (sig->dilithium_type == DILITHIUM_87) {
		struct dilithium_87_sig *_sig = &sig->sig.sig_87;

		*dilithium_sig = _sig->sig;
		*dilithium_sig_len = dilithium_sig_size(sig->dilithium_type);
		return 0;
#endif
#ifdef CONFIG_CRYPTO_DILITHIUM_65
	} else if (sig->dilithium_type == DILITHIUM_65) {
		struct dilithium_65_sig *_sig = &sig->sig.sig_65;

		*dilithium_sig = _sig->sig;
		*dilithium_sig_len = dilithium_sig_size(sig->dilithium_type);
		return 0;
#endif
#ifdef CONFIG_CRYPTO_DILITHIUM_44
	} else if (sig->dilithium_type == DILITHIUM_44) {
		struct dilithium_44_sig *_sig = &sig->sig.sig_44;

		*dilithium_sig = _sig->sig;
		*dilithium_sig_len = dilithium_sig_size(sig->dilithium_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}
EXPORT_SYMBOL(dilithium_sig_ptr);

int dilithium_keypair(struct dilithium_pk *pk,
		      struct dilithium_sk *sk, struct crypto_rng *rng_ctx,
		      enum dilithium_type dilithium_type)
{
	if (!pk || !sk)
		return -EINVAL;

	switch (dilithium_type) {
	case DILITHIUM_87:
#ifdef CONFIG_CRYPTO_DILITHIUM_87
		pk->dilithium_type = dilithium_type;
		sk->dilithium_type = dilithium_type;
		return dilithium_87_keypair(&pk->key.pk_87, &sk->key.sk_87,
					    rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_65:
#ifdef CONFIG_CRYPTO_DILITHIUM_65
		pk->dilithium_type = dilithium_type;
		sk->dilithium_type = dilithium_type;
		return dilithium_65_keypair(&pk->key.pk_65, &sk->key.sk_65,
					    rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_44:
#ifdef CONFIG_CRYPTO_DILITHIUM_44
		pk->dilithium_type = dilithium_type;
		sk->dilithium_type = dilithium_type;
		return dilithium_44_keypair(&pk->key.pk_44, &sk->key.sk_44,
					    rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}
EXPORT_SYMBOL(dilithium_keypair);

int dilithium_keypair_from_seed(struct dilithium_pk *pk, struct dilithium_sk *sk,
				const uint8_t *seed, size_t seedlen,
				enum dilithium_type dilithium_type)
{
	if (!pk || !sk)
		return -EINVAL;

	switch (dilithium_type) {
	case DILITHIUM_87:
#ifdef CONFIG_CRYPTO_DILITHIUM_87
		pk->dilithium_type = dilithium_type;
		sk->dilithium_type = dilithium_type;
		return dilithium_87_keypair_from_seed(
			&pk->key.pk_87, &sk->key.sk_87, seed, seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_65:
#ifdef CONFIG_CRYPTO_DILITHIUM_65
		pk->dilithium_type = dilithium_type;
		sk->dilithium_type = dilithium_type;
		return dilithium_65_keypair_from_seed(
			&pk->key.pk_65, &sk->key.sk_65, seed, seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_44:
#ifdef CONFIG_CRYPTO_DILITHIUM_44
		pk->dilithium_type = dilithium_type;
		sk->dilithium_type = dilithium_type;
		return dilithium_44_keypair_from_seed(
			&pk->key.pk_44, &sk->key.sk_44, seed, seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}
EXPORT_SYMBOL(dilithium_keypair_from_seed);

int dilithium_pct(const struct dilithium_pk *pk,
		  const struct dilithium_sk *sk)
{
	return _dilithium_pct_fips(pk, sk);
}
EXPORT_SYMBOL(dilithium_pct);

int dilithium_sign(struct dilithium_sig *sig,
		   const uint8_t *m, size_t mlen,
		   const struct dilithium_sk *sk,
		   struct crypto_rng *rng_ctx)
{
	if (!sk || !sig)
		return -EINVAL;

	switch (sk->dilithium_type) {
	case DILITHIUM_87:
#ifdef CONFIG_CRYPTO_DILITHIUM_87
		sig->dilithium_type = DILITHIUM_87;
		return dilithium_87_sign(&sig->sig.sig_87, m, mlen,
					 &sk->key.sk_87, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_65:
#ifdef CONFIG_CRYPTO_DILITHIUM_65
		sig->dilithium_type = DILITHIUM_65;
		return dilithium_65_sign(&sig->sig.sig_65, m, mlen,
					 &sk->key.sk_65, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_44:
#ifdef CONFIG_CRYPTO_DILITHIUM_44
		sig->dilithium_type = DILITHIUM_44;
		return dilithium_44_sign(&sig->sig.sig_44, m, mlen,
					 &sk->key.sk_44, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}
EXPORT_SYMBOL(dilithium_sign);

int dilithium_sign_ctx(struct dilithium_sig *sig,
		       struct dilithium_ctx *ctx, const uint8_t *m,
		       size_t mlen, const struct dilithium_sk *sk,
		       struct crypto_rng *rng_ctx)
{
	if (!sk || !sig)
		return -EINVAL;

	switch (sk->dilithium_type) {
	case DILITHIUM_87:
#ifdef CONFIG_CRYPTO_DILITHIUM_87
		sig->dilithium_type = DILITHIUM_87;
		return dilithium_87_sign_ctx(&sig->sig.sig_87, ctx, m, mlen,
					     &sk->key.sk_87, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_65:
#ifdef CONFIG_CRYPTO_DILITHIUM_65
		sig->dilithium_type = DILITHIUM_65;
		return dilithium_65_sign_ctx(&sig->sig.sig_65, ctx, m, mlen,
					     &sk->key.sk_65, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_44:
#ifdef CONFIG_CRYPTO_DILITHIUM_44
		sig->dilithium_type = DILITHIUM_44;
		return dilithium_44_sign_ctx(&sig->sig.sig_44, ctx, m, mlen,
					     &sk->key.sk_44, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}
EXPORT_SYMBOL(dilithium_sign_ctx);

int dilithium_sign_init(struct dilithium_ctx *ctx,
			const struct dilithium_sk *sk)
{
	if (!sk)
		return -EINVAL;

	switch (sk->dilithium_type) {
	case DILITHIUM_87:
#ifdef CONFIG_CRYPTO_DILITHIUM_87
		return dilithium_87_sign_init(ctx, &sk->key.sk_87);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_65:
#ifdef CONFIG_CRYPTO_DILITHIUM_65
		return dilithium_65_sign_init(ctx, &sk->key.sk_65);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_44:
#ifdef CONFIG_CRYPTO_DILITHIUM_44
		return dilithium_44_sign_init(ctx, &sk->key.sk_44);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}
EXPORT_SYMBOL(dilithium_sign_init);

int dilithium_sign_update(struct dilithium_ctx *ctx, const uint8_t *m,
			  size_t mlen)
{
#ifdef CONFIG_CRYPTO_DILITHIUM_87
	return dilithium_87_sign_update(ctx, m, mlen);
#elif defined(CONFIG_CRYPTO_DILITHIUM_65)
	return dilithium_65_sign_update(ctx, m, mlen);
#elif defined(CONFIG_CRYPTO_DILITHIUM_44)
	return dilithium_44_sign_update(ctx, m, mlen);
#else
	return -EOPNOTSUPP;
#endif
}
EXPORT_SYMBOL(dilithium_sign_update);

int dilithium_sign_final(struct dilithium_sig *sig,
			 struct dilithium_ctx *ctx,
			 const struct dilithium_sk *sk,
			 struct crypto_rng *rng_ctx)
{
	if (!sk || !sig)
		return -EINVAL;

	switch (sk->dilithium_type) {
	case DILITHIUM_87:
#ifdef CONFIG_CRYPTO_DILITHIUM_87
		sig->dilithium_type = DILITHIUM_87;
		return dilithium_87_sign_final(&sig->sig.sig_87, ctx,
					       &sk->key.sk_87, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_65:
#ifdef CONFIG_CRYPTO_DILITHIUM_65
		sig->dilithium_type = DILITHIUM_65;
		return dilithium_65_sign_final(&sig->sig.sig_65, ctx,
					       &sk->key.sk_65, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_44:
#ifdef CONFIG_CRYPTO_DILITHIUM_44
		sig->dilithium_type = DILITHIUM_44;
		return dilithium_44_sign_final(&sig->sig.sig_44, ctx,
					       &sk->key.sk_44, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}
EXPORT_SYMBOL(dilithium_sign_final);

int dilithium_verify(const struct dilithium_sig *sig, const uint8_t *m,
		     size_t mlen, const struct dilithium_pk *pk)
{
	if (!pk || !sig || sig->dilithium_type != pk->dilithium_type)
		return -EINVAL;

	switch (pk->dilithium_type) {
	case DILITHIUM_87:
#ifdef CONFIG_CRYPTO_DILITHIUM_87
		return dilithium_87_verify(&sig->sig.sig_87, m, mlen,
					   &pk->key.pk_87);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_65:
#ifdef CONFIG_CRYPTO_DILITHIUM_65
		return dilithium_65_verify(&sig->sig.sig_65, m, mlen,
					   &pk->key.pk_65);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_44:
#ifdef CONFIG_CRYPTO_DILITHIUM_44
		return dilithium_44_verify(&sig->sig.sig_44, m, mlen,
					   &pk->key.pk_44);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}
EXPORT_SYMBOL(dilithium_verify);

int dilithium_verify_ctx(const struct dilithium_sig *sig,
			 struct dilithium_ctx *ctx, const uint8_t *m,
			 size_t mlen, const struct dilithium_pk *pk)
{
	if (!pk || !sig || sig->dilithium_type != pk->dilithium_type)
		return -EINVAL;

	switch (pk->dilithium_type) {
	case DILITHIUM_87:
#ifdef CONFIG_CRYPTO_DILITHIUM_87
		return dilithium_87_verify_ctx(&sig->sig.sig_87, ctx, m,
					       mlen, &pk->key.pk_87);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_65:
#ifdef CONFIG_CRYPTO_DILITHIUM_65
		return dilithium_65_verify_ctx(&sig->sig.sig_65, ctx, m,
					       mlen, &pk->key.pk_65);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_44:
#ifdef CONFIG_CRYPTO_DILITHIUM_44
		return dilithium_44_verify_ctx(&sig->sig.sig_44, ctx, m,
					       mlen, &pk->key.pk_44);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}
EXPORT_SYMBOL(dilithium_verify_ctx);

int dilithium_verify_init(struct dilithium_ctx *ctx,
			  const struct dilithium_pk *pk)
{
	if (!pk)
		return -EINVAL;

	switch (pk->dilithium_type) {
	case DILITHIUM_87:
#ifdef CONFIG_CRYPTO_DILITHIUM_87
		return dilithium_87_verify_init(ctx, &pk->key.pk_87);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_65:
#ifdef CONFIG_CRYPTO_DILITHIUM_65
		return dilithium_65_verify_init(ctx, &pk->key.pk_65);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_44:
#ifdef CONFIG_CRYPTO_DILITHIUM_44
		return dilithium_44_verify_init(ctx, &pk->key.pk_44);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}
EXPORT_SYMBOL(dilithium_verify_init);

int dilithium_verify_update(struct dilithium_ctx *ctx, const uint8_t *m,
			    size_t mlen)
{
#ifdef CONFIG_CRYPTO_DILITHIUM_87
	return dilithium_87_verify_update(ctx, m, mlen);
#elif defined(CONFIG_CRYPTO_DILITHIUM_65)
	return dilithium_65_verify_update(ctx, m, mlen);
#elif defined(CONFIG_CRYPTO_DILITHIUM_44)
	return dilithium_44_verify_update(ctx, m, mlen);
#else
	return -EOPNOTSUPP;
#endif
}
EXPORT_SYMBOL(dilithium_verify_update);

int dilithium_verify_final(const struct dilithium_sig *sig,
			   struct dilithium_ctx *ctx,
			   const struct dilithium_pk *pk)
{
	if (!pk || !sig || sig->dilithium_type != pk->dilithium_type)
		return -EINVAL;

	switch (pk->dilithium_type) {
	case DILITHIUM_87:
#ifdef CONFIG_CRYPTO_DILITHIUM_87
		return dilithium_87_verify_final(&sig->sig.sig_87, ctx,
						 &pk->key.pk_87);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_65:
#ifdef CONFIG_CRYPTO_DILITHIUM_65
		return dilithium_65_verify_final(&sig->sig.sig_65, ctx,
						 &pk->key.pk_65);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_44:
#ifdef CONFIG_CRYPTO_DILITHIUM_44
		return dilithium_44_verify_final(&sig->sig.sig_44, ctx,
						 &pk->key.pk_44);
#else
		return -EOPNOTSUPP;
#endif
	case DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}
EXPORT_SYMBOL(dilithium_verify_final);

#endif /* DILITHIUM_API_H */
