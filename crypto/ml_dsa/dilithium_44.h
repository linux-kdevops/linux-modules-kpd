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

#ifndef DILITHIUM_44_H
#define DILITHIUM_44_H

/*
 * Dilithium Security Levels
 * 2 -> 192 bits of security strength
 * 3 -> 225 bits of security strength
 * 5 -> 257 bits of security strength
 */

/* DILITHIUM_MODE 2 */
#define DILITHIUM44_NIST_CATEGORY 1
#define DILITHIUM44_LAMBDA 128
#define DILITHIUM44_K 4
#define DILITHIUM44_L 4
#define DILITHIUM44_ETA 2
#define DILITHIUM44_TAU 39
#define DILITHIUM44_BETA 78
#define DILITHIUM44_GAMMA1 (1 << 17)
#define DILITHIUM44_GAMMA2 ((DILITHIUM_Q - 1) / 88)
#define DILITHIUM44_OMEGA 80

#define DILITHIUM44_CTILDE_BYTES (DILITHIUM44_LAMBDA * 2 / 8)
#define DILITHIUM44_POLYT1_PACKEDBYTES 320
#define DILITHIUM44_POLYT0_PACKEDBYTES 416
#define DILITHIUM44_POLYVECH_PACKEDBYTES (DILITHIUM44_OMEGA + DILITHIUM44_K)

#if DILITHIUM44_GAMMA1 == (1 << 17)
#define DILITHIUM44_POLYZ_PACKEDBYTES 576
#elif DILITHIUM44_GAMMA1 == (1 << 19)
#define DILITHIUM44_POLYZ_PACKEDBYTES 640
#endif

#if DILITHIUM44_GAMMA2 == (DILITHIUM_Q - 1) / 88
#define DILITHIUM44_POLYW1_PACKEDBYTES 192
#elif DILITHIUM44_GAMMA2 == (DILITHIUM_Q - 1) / 32
#define DILITHIUM44_POLYW1_PACKEDBYTES 128
#endif

#if DILITHIUM44_ETA == 2
#define DILITHIUM44_POLYETA_PACKEDBYTES 96
#elif DILITHIUM44_ETA == 4
#define DILITHIUM44_POLYETA_PACKEDBYTES 128
#endif

/*
 * Sizes of the different Dilithium buffer types.
 *
 * WARNING: Do not use these defines in your code. If you need the sizes of
 * the different variable sizes, use sizeof of the different variable structs or
 * use the different *_size functions documented below to retrieve the data size
 * of a particular Dilithium component.
 */
#define DILITHIUM44_PUBLICKEYBYTES					\
	(DILITHIUM_SEEDBYTES +						\
	 DILITHIUM44_K * DILITHIUM44_POLYT1_PACKEDBYTES)
#define DILITHIUM44_SECRETKEYBYTES					\
	(2 * DILITHIUM_SEEDBYTES + DILITHIUM_TRBYTES +			\
	 DILITHIUM44_L * DILITHIUM44_POLYETA_PACKEDBYTES +		\
	 DILITHIUM44_K * DILITHIUM44_POLYETA_PACKEDBYTES +		\
	 DILITHIUM44_K * DILITHIUM44_POLYT0_PACKEDBYTES)

#define DILITHIUM44_CRYPTO_BYTES					\
	(DILITHIUM44_CTILDE_BYTES +					\
	 DILITHIUM44_L * DILITHIUM44_POLYZ_PACKEDBYTES +		\
	 DILITHIUM44_POLYVECH_PACKEDBYTES)

#ifndef __ASSEMBLER__
/**
 * @brief Dilithium secret key
 */
struct dilithium_44_sk {
	uint8_t sk[DILITHIUM44_SECRETKEYBYTES];
};

/**
 * @brief Dilithium public key
 */
struct dilithium_44_pk {
	uint8_t pk[DILITHIUM44_PUBLICKEYBYTES];
};

/**
 * @brief Dilithium signature
 */
struct dilithium_44_sig {
	uint8_t sig[DILITHIUM44_CRYPTO_BYTES];
};

/*
 * The alignment is based on largest alignment of a polyvecl typedef - this is
 * the AVX2 definition.
 */
#define DILITHIUM_AHAT_ALIGNMENT (32)

/* Size of the AHat matrix for ML-DSA 87 */
#define DILITHIUM_44_AHAT_SIZE                                              \
	(256 * sizeof(int32_t) * DILITHIUM44_K * DILITHIUM44_L)

/**
 * @brief Zeroize Dilithium context allocated with
 *	  DILITHIUM_CTX_ON_STACK dilithium_ed25519_alloc
 *
 * @param [in] ctx Dilithium context to be zeroized
 */
static inline void dilithium_44_ctx_zero(struct dilithium_ctx *ctx)
{
	if (!ctx)
		return;
	dilithium_hash_clear(ctx);
	if (ctx->ahat) {
		memzero_explicit(ctx->ahat, ctx->ahat_size);
		ctx->ahat_expanded = 0;
	}
}

/**
 * @brief Allocate Dilithium stream context on heap
 *
 * @param [out] ctx Allocated Dilithium stream context
 *
 * @return: 0 on success, < 0 on error
 */
struct dilithium_ctx *dilithium_44_ctx_alloc(void);

/**
 * @brief Allocate Dilithium stream context on heap including additional
 * parameter relevant for the signature operation.
 *
 * \note See \p DILITHIUM_44_CTX_ON_STACK_AHAT for details.
 *
 * @param [out] ctx Allocated Dilithium stream context
 *
 * @return: 0 on success, < 0 on error
 */
struct dilithium_ctx *dilithium_44_ctx_alloc_ahat(void);

/**
 * @brief Zeroize and free Dilithium stream context
 *
 * @param [in] ctx Dilithium stream context to be zeroized and freed
 */
void dilithium_44_ctx_zero_free(struct dilithium_ctx *ctx);

/**
 * @brief Return the size of the Dilithium secret key.
 */
__pure
static inline unsigned int dilithium_44_sk_size(void)
{
	return sizeof_field(struct dilithium_44_sk, sk);
}

/**
 * @brief Return the size of the Dilithium public key.
 */
__pure
static inline unsigned int dilithium_44_pk_size(void)
{
	return sizeof_field(struct dilithium_44_pk, pk);
}

/**
 * @brief Return the size of the Dilithium signature.
 */
__pure
static inline unsigned int dilithium_44_sig_size(void)
{
	return sizeof_field(struct dilithium_44_sig, sig);
}

/**
 * @brief Generates Dilithium public and private key.
 *
 * @param [out] pk pointer to allocated output public key
 * @param [out] sk pointer to allocated output private key
 * @param [in] rng_ctx pointer to seeded random number generator context
 *
 * @return 0 (success) or < 0 on error
 */
int dilithium_44_keypair(struct dilithium_44_pk *pk, struct dilithium_44_sk *sk,
			 struct crypto_rng *rng_ctx);

/**
 * @brief Generates Dilithium public and private key from a given seed.
 *
 * The idea of the function is the allowance of FIPS 204 to maintain the seed
 * used to generate a key pair in lieu of maintaining a private key or the
 * key pair (which used much more memory). The seed must be treated equally
 * sensitive as a private key.
 *
 * The seed is generated by simply obtaining 32 bytes from a properly seeded
 * DRNG, i.e. the same way as a symmetric key would be generated.
 *
 * @param [out] pk pointer to allocated output public key
 * @param [out] sk pointer to allocated output private key
 * @param [in] seed buffer with the seed data which must be exactly 32 bytes
 *		    in size
 * @param [in] seedlen length of the seed buffer
 *
 * @return 0 (success) or < 0 on error
 */
int dilithium_44_keypair_from_seed(struct dilithium_44_pk *pk,
				       struct dilithium_44_sk *sk,
				       const uint8_t *seed, size_t seedlen);

/**
 * @brief Computes ML-DSA signature in one shot
 *
 * @param [out] sig pointer to output signature
 * @param [in] m pointer to message to be signed
 * @param [in] mlen length of message
 * @param [in] sk pointer to bit-packed secret key
 * @param [in] rng_ctx pointer to seeded random number generator context - when
 *		       pointer is non-NULL, perform a randomized signing.
 *		       Otherwise use deterministic signing.
 *
 * @return 0 (success) or < 0 on error
 */
int dilithium_44_sign(struct dilithium_44_sig *sig, const uint8_t *m,
		      size_t mlen, const struct dilithium_44_sk *sk,
		      struct crypto_rng *rng_ctx);

/**
 * @brief Computes signature with Dilithium context in one shot
 *
 * This API allows the caller to provide an arbitrary context buffer which
 * is hashed together with the message to form the message digest to be signed.
 *
 * @param [out] sig pointer to output signature
 * @param [in] ctx reference to the allocated Dilithium context handle
 * @param [in] m pointer to message to be signed
 * @param [in] mlen length of message
 * @param [in] sk pointer to bit-packed secret key
 * @param [in] rng_ctx pointer to seeded random number generator context - when
 *		       pointer is non-NULL, perform a randomized signing.
 *		       Otherwise use deterministic signing.
 *
 * @return 0 (success) or < 0 on error
 */
int dilithium_44_sign_ctx(struct dilithium_44_sig *sig,
			      struct dilithium_ctx *ctx,
			      const uint8_t *m, size_t mlen,
			      const struct dilithium_44_sk *sk,
			      struct crypto_rng *rng_ctx);

/**
 * @brief Initializes a signature operation
 *
 * This call is intended to support messages that are located in non-contiguous
 * places and even becomes available at different times. This call is to be
 * used together with the dilithium_sign_update and dilithium_sign_final.
 *
 * @param [in,out] ctx pointer to an allocated Dilithium context
 * @param [in] sk pointer to bit-packed secret key
 *
 * @return 0 (success) or < 0 on error; -EOPNOTSUPP is returned if a different
 *	   hash than lc_shake256 is used.
 */
int dilithium_44_sign_init(struct dilithium_ctx *ctx,
			   const struct dilithium_44_sk *sk);

/**
 * @brief Add more data to an already initialized signature state
 *
 * This call is intended to support messages that are located in non-contiguous
 * places and even becomes available at different times. This call is to be
 * used together with the dilithium_sign_init and dilithium_sign_final.
 *
 * @param [in] ctx pointer to Dilithium context that was initialized with
 *			    dilithium_sign_init
 * @param [in] m pointer to message to be signed
 * @param [in] mlen length of message
 *
 * @return 0 (success) or < 0 on error
 */
int dilithium_44_sign_update(struct dilithium_ctx *ctx, const uint8_t *m,
			     size_t mlen);

/**
 * @brief Computes signature
 *
 * @param [out] sig pointer to output signature
 * @param [in] ctx pointer to Dilithium context that was initialized with
 *			dilithium_sign_init and filled with
 *			dilithium_sign_update
 * @param [in] sk pointer to bit-packed secret key
 * @param [in] rng_ctx pointer to seeded random number generator context - when
 *		       pointer is non-NULL, perform a randomized signing.
 *		       Otherwise use deterministic signing.
 *
 * @return 0 (success) or < 0 on error
 */
int dilithium_44_sign_final(struct dilithium_44_sig *sig,
			    struct dilithium_ctx *ctx,
			    const struct dilithium_44_sk *sk,
			    struct crypto_rng *rng_ctx);

/**
 * @brief Verifies ML-DSA signature in one shot
 *
 * @param [in] sig pointer to input signature
 * @param [in] m pointer to message
 * @param [in] mlen length of message
 * @param [in] pk pointer to bit-packed public key
 *
 * @return 0 if signature could be verified correctly and -EBADMSG when
 * signature cannot be verified, < 0 on other errors
 */
int dilithium_44_verify(const struct dilithium_44_sig *sig, const uint8_t *m,
			size_t mlen, const struct dilithium_44_pk *pk);

/**
 * @brief Verifies signature with Dilithium context in one shot
 *
 * This API allows the caller to provide an arbitrary context buffer which
 * is hashed together with the message to form the message digest to be signed.
 *
 * @param [in] sig pointer to input signature
 * @param [in] ctx reference to the allocated Dilithium context handle
 * @param [in] m pointer to message
 * @param [in] mlen length of message
 * @param [in] pk pointer to bit-packed public key
 *
 * @return 0 if signature could be verified correctly and -EBADMSG when
 * signature cannot be verified, < 0 on other errors
 */
int dilithium_44_verify_ctx(const struct dilithium_44_sig *sig,
				struct dilithium_ctx *ctx,
				const uint8_t *m, size_t mlen,
				const struct dilithium_44_pk *pk);

/**
 * @brief Initializes a signature verification operation
 *
 * This call is intended to support messages that are located in non-contiguous
 * places and even becomes available at different times. This call is to be
 * used together with the dilithium_verify_update and
 * dilithium_verify_final.
 *
 * @param [in,out] ctx pointer to an allocated Dilithium context
 * @param [in] pk pointer to bit-packed public key
 *
 * @return 0 (success) or < 0 on error; -EOPNOTSUPP is returned if a different
 *	   hash than lc_shake256 is used.
 */
int dilithium_44_verify_init(struct dilithium_ctx *ctx,
			     const struct dilithium_44_pk *pk);

/**
 * @brief Add more data to an already initialized signature state
 *
 * This call is intended to support messages that are located in non-contiguous
 * places and even becomes available at different times. This call is to be
 * used together with the dilithium_verify_init and
 * dilithium_verify_final.
 *
 * @param [in,out] ctx pointer to Dilithium context that was initialized with
 *			    dilithium_sign_init
 * @param [in] m pointer to message to be signed
 * @param [in] mlen length of message
 *
 * @return 0 (success) or < 0 on error
 */
int dilithium_44_verify_update(struct dilithium_ctx *ctx, const uint8_t *m,
			       size_t mlen);

/**
 * @brief Verifies signature
 *
 * @param [in] sig pointer to output signature
 * @param [in] ctx pointer to Dilithium context that was initialized with
 *			dilithium_sign_init and filled with
 *			dilithium_sign_update
 * @param [in] pk pointer to bit-packed public key
 *
 * @return 0 if signature could be verified correctly and -EBADMSG when
 * signature cannot be verified, < 0 on other errors
 */
int dilithium_44_verify_final(const struct dilithium_44_sig *sig,
			      struct dilithium_ctx *ctx,
			      const struct dilithium_44_pk *pk);

#endif /* __ASSEMBLER__ */

#endif /* DILITHIUM_44_H */
