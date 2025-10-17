/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
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

#ifndef DILITHIUM_SIGNATURE_IMPL_H
#define DILITHIUM_SIGNATURE_IMPL_H

#include "dilithium.h"
#include "dilithium_type.h"
#include "dilithium_debug.h"
#include "dilithium_pack.h"
#include "dilithium_pct.h"
#include "dilithium_signature_impl.h"
#include "signature_domain_separation.h"
#include "small_stack_support.h"

/*
 * Enable this macro to report the rejection code paths taken with the
 * signature generation operation. When disabled, the compiler should
 * eliminate this code which means that the counting code is folded away.
 */
#undef REJECTION_TEST_SAMPLING

#define _WS_POLY_UNIFORM_BUF_SIZE                                              \
	(POLY_UNIFORM_NBLOCKS * SHAKE128_BLOCK_SIZE + 2)

#ifndef LC_POLY_UNIFOR_BUF_SIZE_MULTIPLIER
#error "LC_POLY_UNIFOR_BUF_SIZE_MULTIPLIER is not defined"
#endif

#define WS_POLY_UNIFORM_BUF_SIZE                                               \
	(_WS_POLY_UNIFORM_BUF_SIZE * LC_POLY_UNIFOR_BUF_SIZE_MULTIPLIER)

static int dilithium_keypair_from_seed_impl(struct dilithium_pk *pk,
					    struct dilithium_sk *sk,
					    const uint8_t *seed,
					    size_t seedlen);

static int dilithium_keypair_impl(struct dilithium_pk *pk,
				  struct dilithium_sk *sk,
				  struct crypto_rng *rng_ctx)
{
	struct workspace {
		union {
			polyvecl s1, s1hat;
		} s1;
		union {
			polyvecl mat[DILITHIUM_K];
			polyveck t0;
		} matrix;
		polyveck s2, t1;
		uint8_t seedbuf[2 * DILITHIUM_SEEDBYTES +
				DILITHIUM_CRHBYTES];
		union {
			poly polyvecl_pointwise_acc_montgomery_buf;
			uint8_t poly_uniform_buf[WS_POLY_UNIFORM_BUF_SIZE];
			uint8_t poly_uniform_eta_buf[POLY_UNIFORM_ETA_BYTES];
			uint8_t tr[DILITHIUM_TRBYTES];
		} tmp;
	};
	static const uint8_t dimension[2] = { DILITHIUM_K, DILITHIUM_L };
	const uint8_t *rho, *rhoprime, *key;
	int ret;
	struct shake256_ctx shake256_ctx;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	if (WARN_ON_ONCE(!pk) ||
	    WARN_ON_ONCE(!sk)) {
		ret = -EINVAL;
		goto out;
	}

	/* Get randomness for rho, rhoprime and key */
	ret = crypto_rng_generate(rng_ctx, NULL, 0, ws->seedbuf,
				  DILITHIUM_SEEDBYTES);
	if (ret < 0)
		goto out;
	dilithium_print_buffer(ws->seedbuf, DILITHIUM_SEEDBYTES,
			       "Keygen - Seed");

	shake256_init(&shake256_ctx);
	shake256_update(&shake256_ctx, ws->seedbuf, DILITHIUM_SEEDBYTES);
	shake256_update(&shake256_ctx, dimension, sizeof(dimension));
	shake256_squeeze(&shake256_ctx, ws->seedbuf, sizeof(ws->seedbuf));
	shake256_clear(&shake256_ctx);

	rho = ws->seedbuf;
	dilithium_print_buffer(ws->seedbuf, DILITHIUM_SEEDBYTES,
			       "Keygen - RHO");
	pack_pk_rho(pk, rho);
	pack_sk_rho(sk, rho);

	/*
	 * Timecop: RHO' is a random number which is enlarged to sample the
	 * vectors S1 and S2 from. The sampling operation is not considered
	 * relevant for the side channel operation as (a) an attacker does not
	 * have access to the random number and (b) only the result after the
	 * sampling operation of S1 and S2 is released.
	 */
	rhoprime = rho + DILITHIUM_SEEDBYTES;
	dilithium_print_buffer(rhoprime, DILITHIUM_CRHBYTES,
			       "Keygen - RHOPrime");

	key = rhoprime + DILITHIUM_CRHBYTES;
	dilithium_print_buffer(key, DILITHIUM_SEEDBYTES, "Keygen - Key");

	/* Timecop: key goes into the secret key */
	poison(key, DILITHIUM_SEEDBYTES);

	pack_sk_key(sk, key);

	/* Sample short vectors s1 and s2 */

	polyvecl_uniform_eta(&ws->s1.s1, rhoprime, 0,
			     ws->tmp.poly_uniform_eta_buf);
	polyveck_uniform_eta(&ws->s2, rhoprime, DILITHIUM_L,
			     ws->tmp.poly_uniform_eta_buf);

	/* Timecop: s1 and s2 are secret */
	poison(&ws->s1.s1, sizeof(polyvecl));
	poison(&ws->s2, sizeof(polyveck));

	dilithium_print_polyvecl(&ws->s1.s1,
				 "Keygen - S1 L x N matrix after ExpandS:");
	dilithium_print_polyveck(&ws->s2,
				 "Keygen - S2 K x N matrix after ExpandS:");

	pack_sk_s1(sk, &ws->s1.s1);
	pack_sk_s2(sk, &ws->s2);

	polyvecl_ntt(&ws->s1.s1hat);
	dilithium_print_polyvecl(&ws->s1.s1hat,
				 "Keygen - S1 L x N matrix after NTT:");

	/* Expand matrix */
	polyvec_matrix_expand(ws->matrix.mat, rho, ws->tmp.poly_uniform_buf);
	dilithium_print_polyvecl_k(
		ws->matrix.mat, "Keygen - MAT K x L x N matrix after ExpandA:");

	polyvec_matrix_pointwise_montgomery(
		&ws->t1, ws->matrix.mat, &ws->s1.s1hat,
		&ws->tmp.polyvecl_pointwise_acc_montgomery_buf);
	dilithium_print_polyveck(&ws->t1,
				 "Keygen - T K x N matrix after A*NTT(s1):");

	polyveck_reduce(&ws->t1);
	dilithium_print_polyveck(
		&ws->t1, "Keygen - T K x N matrix reduce after A*NTT(s1):");

	polyveck_invntt_tomont(&ws->t1);
	dilithium_print_polyveck(&ws->t1,
				 "Keygen - T K x N matrix after NTT-1:");

	/* Add error vector s2 */
	polyveck_add(&ws->t1, &ws->t1, &ws->s2);
	dilithium_print_polyveck(&ws->t1,
				 "Keygen - T K x N matrix after add S2:");

	/* Extract t1 and write public key */
	polyveck_caddq(&ws->t1);
	dilithium_print_polyveck(&ws->t1, "Keygen - T K x N matrix caddq:");

	polyveck_power2round(&ws->t1, &ws->matrix.t0, &ws->t1);
	dilithium_print_polyveck(&ws->matrix.t0,
				 "Keygen - T0 K x N matrix after power2round:");
	dilithium_print_polyveck(&ws->t1,
				 "Keygen - T1 K x N matrix after power2round:");

	pack_sk_t0(sk, &ws->matrix.t0);
	pack_pk_t1(pk, &ws->t1);
	dilithium_print_buffer(pk->pk, DILITHIUM_PUBLICKEYBYTES,
			       "Keygen - PK after pkEncode:");

	/* Compute H(rho, t1) and write secret key */
	shake256(pk->pk, sizeof(pk->pk), ws->tmp.tr, sizeof(ws->tmp.tr));
	dilithium_print_buffer(ws->tmp.tr, sizeof(ws->tmp.tr), "Keygen - TR:");
	pack_sk_tr(sk, ws->tmp.tr);

	dilithium_print_buffer(sk->sk, DILITHIUM_SECRETKEYBYTES,
			       "Keygen - SK:");

	/* Timecop: pk and sk are not relevant for side-channels any more. */
	unpoison(pk->pk, sizeof(pk->pk));
	unpoison(sk->sk, sizeof(sk->sk));

	ret = dilithium_pct_fips(pk, sk);

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

static int dilithium_keypair_from_seed_impl(struct dilithium_pk *pk,
					    struct dilithium_sk *sk,
					    const uint8_t *seed,
					    size_t seedlen)
{
	struct crypto_rng *rng;
	int ret;

	if (seedlen != DILITHIUM_SEEDBYTES)
		return -EINVAL;

	rng = crypto_alloc_rng("stdrng", 0, 0);
	if (IS_ERR(rng))
		return PTR_ERR(rng);

	ret = crypto_rng_seedsize(rng);
	if (ret < 0)
		goto out;
	if (seedlen != ret) {
		ret = -EINVAL;
		goto out;
	}

	/* Set the seed that the key generation can pull via the RNG. */
	ret = crypto_rng_reset(rng, seed, seedlen);
	if (ret < 0)
		goto out;

	/* Generate the key pair from the seed. */
	ret = dilithium_keypair_impl(pk, sk, rng);

out:
	return ret;
}

static int dilithium_sign_internal_ahat(struct dilithium_sig *sig,
					const struct dilithium_sk *sk,
					struct dilithium_ctx *ctx,
					struct crypto_rng *rng_ctx)
{
	struct workspace_sign {
		polyvecl s1, y, z;
		polyveck t0, s2, w1, w0, h;
		poly cp;
		uint8_t seedbuf[DILITHIUM_SEEDBYTES + DILITHIUM_RNDBYTES +
				DILITHIUM_CRHBYTES];
		union {
			uint8_t poly_uniform_gamma1_buf[WS_POLY_UNIFORM_BUF_SIZE];
			uint8_t poly_challenge_buf[POLY_CHALLENGE_BYTES];
		} tmp;
	};
	unsigned int n;
	uint8_t *key, *mu, *rhoprime, *rnd;
	const polyvecl *mat = ctx->ahat;
	uint16_t nonce = 0;
	int ret = 0;
	uint8_t __maybe_unused rej_total = 0;
	LC_DECLARE_MEM(ws, struct workspace_sign, sizeof(uint64_t));

	/* AHat must be present at this time */
	if (WARN_ON_ONCE(!mat)) {
		ret = -EINVAL;
		goto out;
	}

	key = ws->seedbuf;
	rnd = key + DILITHIUM_SEEDBYTES;
	mu = rnd + DILITHIUM_RNDBYTES;

	/*
	 * If the external mu is provided, use this verbatim, otherwise
	 * calculate the mu value.
	 */
	if (ctx->external_mu) {
		if (ctx->external_mu_len != DILITHIUM_CRHBYTES)
			return -EINVAL;
		memcpy(mu, ctx->external_mu, DILITHIUM_CRHBYTES);
	} else {
		/*
		 * Set the digestsize - for SHA512 this is a noop, for SHAKE256,
		 * it sets the value. The BUILD_BUG_ON is to check that the
		 * SHA-512 output size is identical to the expected length.
		 */
		BUILD_BUG_ON(DILITHIUM_CRHBYTES != SHA3_512_DIGEST_SIZE);
		if (!dilithium_hash_check_digestsize(ctx, DILITHIUM_CRHBYTES)) {
			ret = -EINVAL;
			goto out;
		}
		dilithium_hash_final(ctx, mu, DILITHIUM_CRHBYTES);
	}
	dilithium_print_buffer(mu, DILITHIUM_CRHBYTES, "Siggen - MU:");

	if (rng_ctx) {
		ret = crypto_rng_generate(rng_ctx, NULL, 0, rnd,
					  DILITHIUM_RNDBYTES);
		if (ret < 0)
			goto out;
	} else {
		memset(rnd, 0, DILITHIUM_RNDBYTES);
	}
	dilithium_print_buffer(rnd, DILITHIUM_RNDBYTES, "Siggen - RND:");

	unpack_sk_key(key, sk);

	/* Timecop: key is secret */
	poison(key, DILITHIUM_SEEDBYTES);

	/* Re-use the ws->seedbuf, but making sure that mu is unchanged */
	BUILD_BUG_ON(DILITHIUM_CRHBYTES >
		     DILITHIUM_SEEDBYTES + DILITHIUM_RNDBYTES);
	rhoprime = key;

	shake256(key,
		 DILITHIUM_SEEDBYTES + DILITHIUM_RNDBYTES +
		 DILITHIUM_CRHBYTES,
		 rhoprime, DILITHIUM_CRHBYTES);
	dilithium_print_buffer(rhoprime, DILITHIUM_CRHBYTES,
			       "Siggen - RHOPrime:");

	/*
	 * Timecop: RHO' is the hash of the secret value of key which is
	 * enlarged to sample the intermediate vector y from. Due to the hashing
	 * any side channel on RHO' cannot allow the deduction of the original
	 * key.
	 */
	unpoison(rhoprime, DILITHIUM_CRHBYTES);

	unpack_sk_s1(&ws->s1, sk);

	/* Timecop: s1 is secret */
	poison(&ws->s1, sizeof(polyvecl));

	polyvecl_ntt(&ws->s1);
	dilithium_print_polyvecl(&ws->s1,
				 "Siggen - S1 L x N matrix after NTT:");

	unpack_sk_s2(&ws->s2, sk);

	/* Timecop: s2 is secret */
	poison(&ws->s2, sizeof(polyveck));

	polyveck_ntt(&ws->s2);
	dilithium_print_polyveck(&ws->s2,
				 "Siggen - S2 K x N matrix after NTT:");

	unpack_sk_t0(&ws->t0, sk);
	polyveck_ntt(&ws->t0);
	dilithium_print_polyveck(&ws->t0,
				 "Siggen - T0 K x N matrix after NTT:");

rej:
	/* Sample intermediate vector y */
	polyvecl_uniform_gamma1(&ws->y, rhoprime, nonce++,
				ws->tmp.poly_uniform_gamma1_buf);
	dilithium_print_polyvecl(
		&ws->y,
		"Siggen - Y L x N matrix after ExpandMask - start of loop");

	/* Timecop: s2 is secret */
	poison(&ws->y, sizeof(polyvecl));

	/* Matrix-vector multiplication */
	ws->z = ws->y;
	polyvecl_ntt(&ws->z);

	/* Use the cp for this operation as it is not used here so far. */
	polyvec_matrix_pointwise_montgomery(&ws->w1, mat, &ws->z, &ws->cp);
	polyveck_reduce(&ws->w1);
	polyveck_invntt_tomont(&ws->w1);
	dilithium_print_polyveck(&ws->w1,
				 "Siggen - W K x N matrix after NTT-1");

	/* Decompose w and call the random oracle */
	polyveck_caddq(&ws->w1);
	polyveck_decompose(&ws->w1, &ws->w0, &ws->w1);

	/* Timecop: the signature component w1 is not sensitive any more. */
	unpoison(&ws->w1, sizeof(polyveck));
	polyveck_pack_w1(sig->sig, &ws->w1);
	dilithium_print_buffer(sig->sig,
			       DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES,
			       "Siggen - w1Encode of W1");

	dilithium_hash_init(ctx);
	dilithium_hash_update(ctx, mu, DILITHIUM_CRHBYTES);
	dilithium_hash_finup(ctx, sig->sig,
			     DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES,
			     sig->sig, DILITHIUM_CTILDE_BYTES);

	dilithium_print_buffer(sig->sig, DILITHIUM_CTILDE_BYTES,
			       "Siggen - ctilde");

	poly_challenge(&ws->cp, sig->sig, ws->tmp.poly_challenge_buf);
	dilithium_print_poly(&ws->cp, "Siggen - c after SampleInBall");
	poly_ntt(&ws->cp);
	dilithium_print_poly(&ws->cp, "Siggen - c after NTT");

	/* Compute z, reject if it reveals secret */
	polyvecl_pointwise_poly_montgomery(&ws->z, &ws->cp, &ws->s1);
	polyvecl_invntt_tomont(&ws->z);
	polyvecl_add(&ws->z, &ws->z, &ws->y);
	dilithium_print_polyvecl(&ws->z, "Siggen - z <- y + cs1");

	polyvecl_reduce(&ws->z);
	dilithium_print_polyvecl(&ws->z, "Siggen - z reduction");

	/* Timecop: the signature component z is not sensitive any more. */
	unpoison(&ws->z, sizeof(polyvecl));

	if (polyvecl_chknorm(&ws->z, DILITHIUM_GAMMA1 - DILITHIUM_BETA)) {
		dilithium_print_polyvecl(&ws->z, "Siggen - z rejection");
		rej_total |= 1 << 0;
		goto rej;
	}

	/*
	 * Check that subtracting cs2 does not change high bits of w and low
	 * bits do not reveal secret information.
	 */
	polyveck_pointwise_poly_montgomery(&ws->h, &ws->cp, &ws->s2);
	polyveck_invntt_tomont(&ws->h);
	polyveck_sub(&ws->w0, &ws->w0, &ws->h);
	polyveck_reduce(&ws->w0);

	/* Timecop: verification data w0 is not sensitive any more. */
	unpoison(&ws->w0, sizeof(polyveck));

	if (polyveck_chknorm(&ws->w0,
			     DILITHIUM_GAMMA2 - DILITHIUM_BETA)) {
		dilithium_print_polyveck(&ws->w0, "Siggen - r0 rejection");
		rej_total |= 1 << 1;
		goto rej;
	}

	/* Compute hints for w1 */
	polyveck_pointwise_poly_montgomery(&ws->h, &ws->cp, &ws->t0);
	polyveck_invntt_tomont(&ws->h);
	polyveck_reduce(&ws->h);

	/* Timecop: the signature component h is not sensitive any more. */
	unpoison(&ws->h, sizeof(polyveck));

	if (polyveck_chknorm(&ws->h, DILITHIUM_GAMMA2)) {
		dilithium_print_polyveck(&ws->h, "Siggen - ct0 rejection");
		rej_total |= 1 << 2;
		goto rej;
	}

	polyveck_add(&ws->w0, &ws->w0, &ws->h);

	n = polyveck_make_hint(&ws->h, &ws->w0, &ws->w1);
	if (n > DILITHIUM_OMEGA) {
		dilithium_print_polyveck(&ws->w0, "Siggen - h rejection");
		rej_total |= 1 << 3;
		goto rej;
	}

	/* Write signature */
	dilithium_print_buffer(sig->sig, DILITHIUM_CTILDE_BYTES,
			       "Siggen - Ctilde:");
	dilithium_print_polyvecl(&ws->z, "Siggen - Z L x N matrix:");
	dilithium_print_polyveck(&ws->h, "Siggen - H K x N matrix:");

	pack_sig(sig, &ws->z, &ws->h);

	dilithium_print_buffer(sig->sig, DILITHIUM_CRYPTO_BYTES,
			       "Siggen - Signature:");

out:
	LC_RELEASE_MEM(ws);
#ifdef REJECTION_TEST_SAMPLING
	return ret ? ret : rej_total;
#else
	return ret;
#endif
}

static int dilithium_sign_internal_noahat(struct dilithium_sig *sig,
					  const struct dilithium_sk *sk,
					  struct dilithium_ctx *ctx,
					  struct crypto_rng *rng_ctx)
{
	struct workspace_sign {
		polyvecl mat[DILITHIUM_K];
		uint8_t poly_uniform_buf[WS_POLY_UNIFORM_BUF_SIZE];
	};
	/* The first bytes of the key is rho. */
	const uint8_t *rho = sk->sk;
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace_sign, DILITHIUM_AHAT_ALIGNMENT);

	polyvec_matrix_expand(ws->mat, rho, ws->poly_uniform_buf);

	/* Temporarily set the pointer */
	ctx->ahat = ws->mat;

	ret = dilithium_sign_internal_ahat(sig, sk, ctx, rng_ctx);

	ctx->ahat = NULL;
	LC_RELEASE_MEM(ws);
	return ret;
}

static int dilithium_sk_expand_impl(const struct dilithium_sk *sk,
				    struct dilithium_ctx *ctx)
{
	struct workspace_sign {
		uint8_t poly_uniform_buf[WS_POLY_UNIFORM_BUF_SIZE];
	};
	/* The first bytes of the key is rho. */
	const uint8_t *rho = sk->sk;
	polyvecl *mat = ctx->ahat;
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace_sign, sizeof(uint64_t));

	/*
	 * The compile time sanity check links API header file with
	 * Dilithium-internal definitions.
	 *
	 * Runtime sanity check ensures that the allocated context has
	 * sufficient size (e.g. not that caller used, say,
	 * DILITHIUM_44_CTX_ON_STACK_AHAT with a ML-DSA 65 or 87 key)
	 */
#if DILITHIUM_MODE == 2
	BUILD_BUG_ON(DILITHIUM_44_AHAT_SIZE !=
		     sizeof(polyvecl) * DILITHIUM44_K);
	if (ctx->ahat_size < DILITHIUM_44_AHAT_SIZE) {
		ret = -EOVERFLOW;
		goto out;
	}
#elif DILITHIUM_MODE == 3
	BUILD_BUG_ON(DILITHIUM_65_AHAT_SIZE !=
		     sizeof(polyvecl) * DILITHIUM65_K);
	if (ctx->ahat_size < DILITHIUM_65_AHAT_SIZE) {
		ret = -EOVERFLOW;
		goto out;
	}
#elif DILITHIUM_MODE == 5
	BUILD_BUG_ON(DILITHIUM_87_AHAT_SIZE !=
		     sizeof(polyvecl) * DILITHIUM87_K);
	if (ctx->ahat_size < DILITHIUM_87_AHAT_SIZE) {
		ret = -EOVERFLOW;
		goto out;
	}
#else
#error "Undefined DILITHIUM_MODE"
#endif

	polyvec_matrix_expand(mat, rho, ws->poly_uniform_buf);
	dilithium_print_polyvecl_k(mat,
				   "AHAT - A K x L x N matrix after ExpandA:");

	ctx->ahat_expanded = 1;

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

static int dilithium_sign_internal(struct dilithium_sig *sig,
				   const struct dilithium_sk *sk,
				   struct dilithium_ctx *ctx,
				   struct crypto_rng *rng_ctx)
{
	int ret;

	if (!ctx->ahat)
		return dilithium_sign_internal_noahat(sig, sk, ctx, rng_ctx);

	if (!ctx->ahat_expanded) {
		ret = dilithium_sk_expand_impl(sk, ctx);
		if (ret < 0)
			goto out;
	}

	ret = dilithium_sign_internal_ahat(sig, sk, ctx, rng_ctx);

out:
	return ret;
}

static int dilithium_sign_ctx_impl(struct dilithium_sig *sig,
				   struct dilithium_ctx *ctx,
				   const uint8_t *m, size_t mlen,
				   const struct dilithium_sk *sk,
				   struct crypto_rng *rng_ctx)
{
	uint8_t tr[DILITHIUM_TRBYTES];
	int ret = 0;

	/* rng_ctx is allowed to be NULL as handled below */
	if (!sig || !sk || !ctx)
		return -EINVAL;
	/* Either the message or the external mu must be provided */
	if (!m && !ctx->external_mu)
		return -EINVAL;

	dilithium_print_buffer(m, mlen, "Siggen - Message");

	unpack_sk_tr(tr, sk);

	if (m) {
		/* Compute mu = CRH(tr, msg) */
		dilithium_hash_init(ctx);
		dilithium_hash_update(ctx, tr, DILITHIUM_TRBYTES);

		ret = signature_domain_separation(
			&ctx->dilithium_hash_ctx, ctx->ml_dsa_internal,
			ctx->userctx, ctx->userctxlen,
			m, mlen,
			ctx->randomizer, ctx->randomizerlen,
			DILITHIUM_NIST_CATEGORY);
		if (ret < 0)
			goto out;
	}

	ret = dilithium_sign_internal(sig, sk, ctx, rng_ctx);

out:
	memzero_explicit(tr, sizeof(tr));
	return ret;
}

static int dilithium_sign_impl(struct dilithium_sig *sig,
			       const uint8_t *m, size_t mlen,
			       const struct dilithium_sk *sk,
			       struct crypto_rng *rng_ctx)
{
	struct dilithium_ctx *ctx;
	int ret;

	ctx = dilithium_ctx_alloc();
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);

	ret = dilithium_sign_ctx_impl(sig, ctx, m, mlen, sk, rng_ctx);

	dilithium_ctx_zero_free(ctx);
	return ret;
}

static int dilithium_sign_init_impl(struct dilithium_ctx *ctx,
				    const struct dilithium_sk *sk)
{
	uint8_t tr[DILITHIUM_TRBYTES];

	/* rng_ctx is allowed to be NULL as handled below */
	if (!ctx || !sk)
		return -EINVAL;

	/* Require the use of SHAKE256 */
	if (!dilithium_hash_check_blocksize(ctx, SHAKE256_BLOCK_SIZE))
		return -EOPNOTSUPP;

	unpack_sk_tr(tr, sk);

	/* Compute mu = CRH(tr, msg) */
	dilithium_hash_init(ctx);
	dilithium_hash_update(ctx, tr, DILITHIUM_TRBYTES);
	memzero_explicit(tr, sizeof(tr));

	return signature_domain_separation(
		&ctx->dilithium_hash_ctx, ctx->ml_dsa_internal,
		ctx->userctx, ctx->userctxlen,
		NULL, 0,
		ctx->randomizer, ctx->randomizerlen,
		DILITHIUM_NIST_CATEGORY);
}

static int dilithium_sign_update_impl(struct dilithium_ctx *ctx,
				      const uint8_t *m, size_t mlen)
{
	if (!ctx || !m)
		return -EINVAL;

	/* Compute CRH(tr, msg) */
	dilithium_hash_update(ctx, m, mlen);

	return 0;
}

static int dilithium_sign_final_impl(struct dilithium_sig *sig,
				     struct dilithium_ctx *ctx,
				     const struct dilithium_sk *sk,
				     struct crypto_rng *rng_ctx)
{
	int ret = 0;

	/* rng_ctx is allowed to be NULL as handled below */
	if (!sig || !ctx || !sk) {
		ret = -EINVAL;
		goto out;
	}

	ret = dilithium_sign_internal(sig, sk, ctx, rng_ctx);

out:
	dilithium_ctx_zero(ctx);
	return ret;
}

static int dilithium_verify_internal_ahat(const struct dilithium_sig *sig,
					  const struct dilithium_pk *pk,
					  struct dilithium_ctx *ctx)
{
	struct workspace_verify {
		union {
			poly cp;
		} matrix;
		polyveck w1;
		union {
			polyveck t1, h;
			polyvecl z;
			uint8_t mu[DILITHIUM_CRHBYTES];
			union {
				uint8_t coeffs[round_up(DILITHIUM_CTILDE_BYTES, 8)];
			} __aligned(8) c2;
		} buf;

		union {
			poly polyvecl_pointwise_acc_montgomery_buf;
			uint8_t buf[DILITHIUM_K *
				    DILITHIUM_POLYW1_PACKEDBYTES];
			uint8_t poly_challenge_buf[POLY_CHALLENGE_BYTES];
		} tmp;
	};
	/* The first bytes of the signature is c~ and thus contains c1. */
	const uint8_t *c1 = sig->sig;
	const polyvecl *mat = ctx->ahat;
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace_verify, sizeof(uint64_t));

	/* AHat must be present at this time */
	if (!mat) {
		ret = -EINVAL;
		goto out;
	}

	unpack_sig_z(&ws->buf.z, sig);
	if (polyvecl_chknorm(&ws->buf.z,
			     DILITHIUM_GAMMA1 - DILITHIUM_BETA)) {
		ret = -EINVAL;
		goto out;
	}

	polyvecl_ntt(&ws->buf.z);
	polyvec_matrix_pointwise_montgomery(
		&ws->w1, mat, &ws->buf.z,
		&ws->tmp.polyvecl_pointwise_acc_montgomery_buf);

	/* Matrix-vector multiplication; compute Az - c2^dt1 */
	poly_challenge(&ws->matrix.cp, c1, ws->tmp.poly_challenge_buf);
	poly_ntt(&ws->matrix.cp);

	unpack_pk_t1(&ws->buf.t1, pk);
	polyveck_shiftl(&ws->buf.t1);
	polyveck_ntt(&ws->buf.t1);
	polyveck_pointwise_poly_montgomery(&ws->buf.t1, &ws->matrix.cp,
					   &ws->buf.t1);

	polyveck_sub(&ws->w1, &ws->w1, &ws->buf.t1);
	polyveck_reduce(&ws->w1);
	polyveck_invntt_tomont(&ws->w1);

	/* Reconstruct w1 */
	polyveck_caddq(&ws->w1);
	dilithium_print_polyveck(&ws->w1,
				 "Sigver - W K x N matrix before hint:");

	if (unpack_sig_h(&ws->buf.h, sig))
		return -EINVAL;
	dilithium_print_polyveck(&ws->buf.h, "Siggen - H K x N matrix:");

	polyveck_use_hint(&ws->w1, &ws->w1, &ws->buf.h);
	dilithium_print_polyveck(&ws->w1,
				 "Sigver - W K x N matrix after hint:");
	polyveck_pack_w1(ws->tmp.buf, &ws->w1);
	dilithium_print_buffer(ws->tmp.buf,
			       DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES,
			       "Sigver - W after w1Encode");

	if (ctx->external_mu) {
		if (ctx->external_mu_len != DILITHIUM_CRHBYTES)
			return -EINVAL;

		/* Call random oracle and verify challenge */
		dilithium_hash_init(ctx);
		dilithium_hash_update(ctx, ctx->external_mu, DILITHIUM_CRHBYTES);
	} else {
		dilithium_hash_final(ctx, ws->buf.mu, DILITHIUM_CRHBYTES);

		/* Call random oracle and verify challenge */
		dilithium_hash_init(ctx);
		dilithium_hash_update(ctx, ws->buf.mu, DILITHIUM_CRHBYTES);
	}

	dilithium_hash_finup(ctx,
			     ws->tmp.buf, DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES,
			     ws->buf.c2.coeffs, DILITHIUM_CTILDE_BYTES);

	/* Signature verification operation */
	if (memcmp(c1, ws->buf.c2.coeffs, DILITHIUM_CTILDE_BYTES) != 0)
		ret = -EBADMSG;

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

static int
dilithium_verify_internal_noahat(const struct dilithium_sig *sig,
				 const struct dilithium_pk *pk,
				 struct dilithium_ctx *ctx)
{
	struct workspace_verify {
		polyvecl mat[DILITHIUM_K];
		uint8_t poly_uniform_buf[WS_POLY_UNIFORM_BUF_SIZE];
	};
	/* The first bytes of the key is rho. */
	const uint8_t *rho = pk->pk;
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace_verify, sizeof(uint64_t));

	polyvec_matrix_expand(ws->mat, rho, ws->poly_uniform_buf);

	/* Temporarily set the pointer */
	ctx->ahat = ws->mat;

	ret = dilithium_verify_internal_ahat(sig, pk, ctx);

	ctx->ahat = NULL;
	LC_RELEASE_MEM(ws);
	return ret;
}

static int dilithium_pk_expand_impl(const struct dilithium_pk *pk,
				    struct dilithium_ctx *ctx)
{
	struct workspace_verify {
		uint8_t poly_uniform_buf[WS_POLY_UNIFORM_BUF_SIZE];
	};
	/* The first bytes of the key is rho. */
	const uint8_t *rho = pk->pk;
	polyvecl *mat = ctx->ahat;
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace_verify, sizeof(uint64_t));

	/*
	 * Runtime sanity check ensures that the allocated context has
	 * sufficient size (e.g. not that caller used, say,
	 * DILITHIUM_44_CTX_ON_STACK_AHAT with a ML-DSA 65 or 87 key)
	 */
#if DILITHIUM_MODE == 2
	if (ctx->ahat_size < DILITHIUM_44_AHAT_SIZE) {
		ret = -EOVERFLOW;
		goto out;
	}
#elif DILITHIUM_MODE == 3
	if (ctx->ahat_size < DILITHIUM_65_AHAT_SIZE) {
		ret = -EOVERFLOW;
		goto out;
	}
#elif DILITHIUM_MODE == 5
	if (ctx->ahat_size < DILITHIUM_87_AHAT_SIZE) {
		ret = -EOVERFLOW;
		goto out;
	}
#else
#error "Undefined DILITHIUM_MODE"
#endif

	polyvec_matrix_expand(mat, rho, ws->poly_uniform_buf);
	ctx->ahat_expanded = 1;

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

static int dilithium_verify_internal(const struct dilithium_sig *sig,
				     const struct dilithium_pk *pk,
				     struct dilithium_ctx *ctx)
{
	int ret;

	if (!ctx->ahat)
		return dilithium_verify_internal_noahat(sig, pk, ctx);

	if (!ctx->ahat_expanded) {
		ret = dilithium_pk_expand_impl(pk, ctx);
		if (ret < 0)
			goto out;
	}

	ret = dilithium_verify_internal_ahat(sig, pk, ctx);

out:
	return ret;
}

static int dilithium_verify_ctx_impl(const struct dilithium_sig *sig,
				     struct dilithium_ctx *ctx,
				     const uint8_t *m, size_t mlen,
				     const struct dilithium_pk *pk)
{
	uint8_t tr[DILITHIUM_TRBYTES];
	int ret = 0;

	if (!sig || !pk || !ctx)
		return -EINVAL;

	/* Either the message or the external mu must be provided */
	if (!m && !ctx->external_mu)
		return -EINVAL;

	/* Make sure that ->mu is large enough for ->tr */
	BUILD_BUG_ON(DILITHIUM_TRBYTES > DILITHIUM_CRHBYTES);

	/* Compute CRH(H(rho, t1), msg) */
	shake256(pk->pk, DILITHIUM_PUBLICKEYBYTES, tr,
		 DILITHIUM_TRBYTES);

	if (m) {
		dilithium_hash_init(ctx);
		dilithium_hash_update(ctx, tr, DILITHIUM_TRBYTES);
		ret = signature_domain_separation(
			&ctx->dilithium_hash_ctx, ctx->ml_dsa_internal,
			ctx->userctx, ctx->userctxlen,
			m, mlen,
			ctx->randomizer, ctx->randomizerlen,
			DILITHIUM_NIST_CATEGORY);
		if (ret < 0)
			goto out;
	}

	ret = dilithium_verify_internal(sig, pk, ctx);

out:
	memzero_explicit(tr, sizeof(tr));
	return ret;
}

static int dilithium_verify_impl(const struct dilithium_sig *sig,
				 const uint8_t *m, size_t mlen,
				 const struct dilithium_pk *pk)
{
	struct dilithium_ctx *ctx;
	int ret;

	ctx = dilithium_ctx_alloc();
	if (IS_ERR(ctx))
		return PTR_ERR(ctx);

	ret = dilithium_verify_ctx_impl(sig, ctx, m, mlen, pk);

	dilithium_ctx_zero_free(ctx);
	return ret;
}

static int dilithium_verify_init_impl(struct dilithium_ctx *ctx,
				      const struct dilithium_pk *pk)
{
	uint8_t mu[DILITHIUM_TRBYTES];

	/* rng_ctx is allowed to be NULL as handled below */
	if (!ctx || !pk)
		return -EINVAL;

	/* Require the use of SHAKE256 */
	if (!dilithium_hash_check_blocksize(ctx, SHAKE256_BLOCK_SIZE))
		return -EOPNOTSUPP;

	/* Compute CRH(H(rho, t1), msg) */
	shake256(pk->pk, DILITHIUM_PUBLICKEYBYTES, mu,
		 DILITHIUM_TRBYTES);

	dilithium_hash_init(ctx);
	dilithium_hash_update(ctx, mu, DILITHIUM_TRBYTES);
	memzero_explicit(mu, sizeof(mu));

	return signature_domain_separation(
		&ctx->dilithium_hash_ctx, ctx->ml_dsa_internal,
		ctx->userctx, ctx->userctxlen,
		NULL, 0,
		ctx->randomizer, ctx->randomizerlen,
		DILITHIUM_NIST_CATEGORY);
}

static int dilithium_verify_update_impl(struct dilithium_ctx *ctx,
					const uint8_t *m, size_t mlen)
{
	if (!ctx || !m)
		return -EINVAL;

	/* Compute CRH(H(rho, t1), msg) */
	dilithium_hash_update(ctx, m, mlen);

	return 0;
}

static int dilithium_verify_final_impl(const struct dilithium_sig *sig,
				       struct dilithium_ctx *ctx,
				       const struct dilithium_pk *pk)
{
	int ret = 0;

	if (!sig || !ctx || !pk) {
		ret = -EINVAL;
		goto out;
	}

	ret = dilithium_verify_internal(sig, pk, ctx);

out:
	dilithium_ctx_zero(ctx);
	return ret;
}

#endif /* DILITHIUM_SIGNATURE_IMPL_H */
