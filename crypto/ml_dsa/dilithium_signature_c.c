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

#include "dilithium_signature_c.h"

/* We need once the buffer size to handle the hashing */
#define LC_POLY_UNIFOR_BUF_SIZE_MULTIPLIER 1

#include "dilithium_poly.h"
#include "dilithium_poly_common.h"
#include "dilithium_poly_c.h"
#include "dilithium_polyvec.h"
#include "dilithium_polyvec_c.h"
#include "dilithium_pack.h"
#include "dilithium_signature_impl.h"

int dilithium_keypair_from_seed_c(struct dilithium_pk *pk, struct dilithium_sk *sk,
				  const uint8_t *seed, size_t seedlen)
{
	return dilithium_keypair_from_seed_impl(pk, sk, seed, seedlen);
}

int dilithium_keypair_c(struct dilithium_pk *pk,
			struct dilithium_sk *sk, struct crypto_rng *rng_ctx)
{
	return dilithium_keypair_impl(pk, sk, rng_ctx);
}

int dilithium_sign_c(struct dilithium_sig *sig,
		     const uint8_t *m, size_t mlen,
		     const struct dilithium_sk *sk,
		     struct crypto_rng *rng_ctx)
{
	return dilithium_sign_impl(sig, m, mlen, sk, rng_ctx);
}

int dilithium_sign_ctx_c(struct dilithium_sig *sig,
			 struct dilithium_ctx *ctx, const uint8_t *m,
			 size_t mlen, const struct dilithium_sk *sk,
			 struct crypto_rng *rng_ctx)
{
	return dilithium_sign_ctx_impl(sig, ctx, m, mlen, sk, rng_ctx);
}

int dilithium_sign_init_c(struct dilithium_ctx *ctx,
			  const struct dilithium_sk *sk)
{
	return dilithium_sign_init_impl(ctx, sk);
}

int dilithium_sign_update_c(struct dilithium_ctx *ctx, const uint8_t *m,
			    size_t mlen)
{
	return dilithium_sign_update_impl(ctx, m, mlen);
}

int dilithium_sign_final_c(struct dilithium_sig *sig,
			   struct dilithium_ctx *ctx,
			   const struct dilithium_sk *sk,
			   struct crypto_rng *rng_ctx)
{
	return dilithium_sign_final_impl(sig, ctx, sk, rng_ctx);
}

int dilithium_verify_c(const struct dilithium_sig *sig, const uint8_t *m,
		       size_t mlen, const struct dilithium_pk *pk)
{
	return dilithium_verify_impl(sig, m, mlen, pk);
}

int dilithium_verify_ctx_c(const struct dilithium_sig *sig,
			   struct dilithium_ctx *ctx, const uint8_t *m,
			   size_t mlen, const struct dilithium_pk *pk)
{
	return dilithium_verify_ctx_impl(sig, ctx, m, mlen, pk);
}

int dilithium_verify_init_c(struct dilithium_ctx *ctx,
			    const struct dilithium_pk *pk)
{
	return dilithium_verify_init_impl(ctx, pk);
}

int dilithium_verify_update_c(struct dilithium_ctx *ctx, const uint8_t *m,
			      size_t mlen)
{
	return dilithium_verify_update_impl(ctx, m, mlen);
}

int dilithium_verify_final_c(const struct dilithium_sig *sig,
			     struct dilithium_ctx *ctx,
			     const struct dilithium_pk *pk)
{
	return dilithium_verify_final_impl(sig, ctx, pk);
}

int dilithium_keypair_from_seed(struct dilithium_pk *pk, struct dilithium_sk *sk,
				  const uint8_t *seed, size_t seedlen)
{
	return dilithium_keypair_from_seed_c(pk, sk, seed, seedlen);
}

int dilithium_keypair(struct dilithium_pk *pk,
			struct dilithium_sk *sk, struct crypto_rng *rng_ctx)
{
	return dilithium_keypair_c(pk, sk, rng_ctx);
}

int dilithium_sign(struct dilithium_sig *sig,
		     const uint8_t *m, size_t mlen,
		     const struct dilithium_sk *sk,
		     struct crypto_rng *rng_ctx)
{
	return dilithium_sign_c(sig, m, mlen, sk, rng_ctx);
}

int dilithium_sign_ctx(struct dilithium_sig *sig,
			 struct dilithium_ctx *ctx, const uint8_t *m,
			 size_t mlen, const struct dilithium_sk *sk,
			 struct crypto_rng *rng_ctx)
{
	return dilithium_sign_ctx_c(sig, ctx, m, mlen, sk, rng_ctx);
}

int dilithium_sign_init(struct dilithium_ctx *ctx,
			  const struct dilithium_sk *sk)
{
	return dilithium_sign_init_c(ctx, sk);
}

int dilithium_sign_update(struct dilithium_ctx *ctx, const uint8_t *m,
			    size_t mlen)
{
	return dilithium_sign_update_c(ctx, m, mlen);
}

int dilithium_sign_final(struct dilithium_sig *sig,
			   struct dilithium_ctx *ctx,
			   const struct dilithium_sk *sk,
			   struct crypto_rng *rng_ctx)
{
	return dilithium_sign_final_c(sig, ctx, sk, rng_ctx);
}

int dilithium_verify(const struct dilithium_sig *sig, const uint8_t *m,
		       size_t mlen, const struct dilithium_pk *pk)
{
	return dilithium_verify_c(sig, m, mlen, pk);
}

int dilithium_verify_ctx(const struct dilithium_sig *sig,
			   struct dilithium_ctx *ctx, const uint8_t *m,
			   size_t mlen, const struct dilithium_pk *pk)
{
	return dilithium_verify_ctx_c(sig, ctx, m, mlen, pk);
}

int dilithium_verify_init(struct dilithium_ctx *ctx,
			    const struct dilithium_pk *pk)
{
	return dilithium_verify_init_c(ctx, pk);
}

int dilithium_verify_update(struct dilithium_ctx *ctx, const uint8_t *m,
			      size_t mlen)
{
	return dilithium_verify_update_c(ctx, m, mlen);
}

int dilithium_verify_final(const struct dilithium_sig *sig,
			     struct dilithium_ctx *ctx,
			     const struct dilithium_pk *pk)
{
	return dilithium_verify_final_c(sig, ctx, pk);
}
