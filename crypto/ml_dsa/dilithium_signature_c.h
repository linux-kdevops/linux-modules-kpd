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

#ifndef DILITHIUM_SIGNATURE_C_H
#define DILITHIUM_SIGNATURE_C_H

#include "dilithium_type.h"

int dilithium_keypair_c(struct dilithium_pk *pk,
			struct dilithium_sk *sk,
			struct crypto_rng *rng_ctx);
int dilithium_keypair_from_seed_c(struct dilithium_pk *pk,
				  struct dilithium_sk *sk,
				  const uint8_t *seed, size_t seedlen);

int dilithium_sign_c(struct dilithium_sig *sig, const uint8_t *m,
		     size_t mlen, const struct dilithium_sk *sk,
		     struct crypto_rng *rng_ctx);
int dilithium_sign_ctx_c(struct dilithium_sig *sig,
			 struct dilithium_ctx *ctx, const uint8_t *m,
			 size_t mlen, const struct dilithium_sk *sk,
			 struct crypto_rng *rng_ctx);
int dilithium_sign_init_c(struct dilithium_ctx *ctx,
			  const struct dilithium_sk *sk);
int dilithium_sign_update_c(struct dilithium_ctx *ctx, const uint8_t *m,
			    size_t mlen);
int dilithium_sign_final_c(struct dilithium_sig *sig,
			   struct dilithium_ctx *ctx,
			   const struct dilithium_sk *sk,
			   struct crypto_rng *rng_ctx);

int dilithium_verify_c(const struct dilithium_sig *sig, const uint8_t *m,
		       size_t mlen, const struct dilithium_pk *pk);
int dilithium_verify_ctx_c(const struct dilithium_sig *sig,
			   struct dilithium_ctx *ctx, const uint8_t *m,
			   size_t mlen, const struct dilithium_pk *pk);
int dilithium_verify_init_c(struct dilithium_ctx *ctx,
			    const struct dilithium_pk *pk);
int dilithium_verify_update_c(struct dilithium_ctx *ctx, const uint8_t *m,
			      size_t mlen);
int dilithium_verify_final_c(const struct dilithium_sig *sig,
			     struct dilithium_ctx *ctx,
			     const struct dilithium_pk *pk);

#endif /* DILITHIUM_SIGNATURE_C_H */
