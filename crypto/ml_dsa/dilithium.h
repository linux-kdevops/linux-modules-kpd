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

#ifndef DILITHIUM_H
#define DILITHIUM_H

#undef pr_fmt
#define pr_fmt(fmt) "ML-DSA: " fmt
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <crypto/sha2.h>
#include <crypto/sha3.h>
#include <crypto/hash.h>
#include <crypto/rng.h>

#define DILITHIUM_SEEDBYTES 32
#define DILITHIUM_CRHBYTES 64
#define DILITHIUM_TRBYTES 64
#define DILITHIUM_RNDBYTES 32
#define DILITHIUM_N 256
#define DILITHIUM_Q 8380417
#define DILITHIUM_D 13
#define DILITHIUM_ROOT_OF_UNITY 1753

extern const int32_t dilithium_zetas[DILITHIUM_N];
#define lc_seeded_rng crypto_default_rng

struct dilithium_ctx {
	/**
	 * @brief Hash context used internally to the library - it should not
	 * be touched by the user
	 */
	struct shake256_ctx dilithium_hash_ctx;

	/**
	 * @brief When using HashML-DSA, set the hash reference used for the
	 * hash operation. Allowed values are lc_sha256, lc_sha512, lc_sha3_256,
	 * lc_sha3_384, lc_sha3_512, lc_shake128 and lc_shake256. Note, the
	 * actual message digest operation can be performed external to
	 * leancrypto. This parameter only shall indicate the used hash
	 * operation.
	 *
	 * \note Use \p dilithium_ctx_hash or
	 * \p dilithium_ed25519_ctx_hash to set this value.
	 */
	struct crypto_shash *dilithium_prehash_type;

	/**
	 * @brief length of the user context (allowed range between 0 and 255
	 * bytes)
	 *
	 * \note Use \p dilithium_ctx_userctx or
	 * \p dilithium_ed25519_ctx_userctx to set this value.
	 */
	size_t userctxlen;

	/**
	 * @brief buffer with a caller-specified context string
	 *
	 * \note Use \p dilithium_ctx_userctx or
	 * \p dilithium_ed25519_ctx_userctx to set this value.
	 */
	const uint8_t *userctx;

	/**
	 * @brief Pointer to the AHat buffer. This can be provided by the caller
	 * or it must be NULL otherwise.
	 *
	 * \note Use \p DILITHIUM_CTX_ON_STACK_AHAT to provide memory for
	 * storing AHat in the caller context and thus make the signature
	 * operation much faster starting with the 2nd use of the key (pair).
	 */
	void *ahat;
	unsigned short ahat_size;

	/**
	 * @brief Pointer to the external mu.
	 *
	 * If set, the signature operation will use the provided mu instead of
	 * the message. In this case, the message pointer to the signature
	 * generation or verification can be NULL.
	 */
	const uint8_t *external_mu;
	size_t external_mu_len;

	/**
	 * @brief Pointer to the randomizer
	 *
	 * This is used for the Composite signature: For the discussion of the
	 * randomizer, see https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html
	 */
	const uint8_t *randomizer;
	size_t randomizerlen;

	/**
	 * @brief NIST category required for composite signatures
	 *
	 * The domain separation logic depends on the selection of the right
	 * OID for the "Domain" data.
	 */
	unsigned int nist_category;

	/**
	 * @brief When set to true, only the ML-DSA.Sign_internal or
	 * ML-DSA.Verify_internal are performed (see FIPS 204 chapter 6).
	 * Otherwise the ML-DSA.Sign / ML-DSA.Verify (see FIPS chapter 5) is
	 * applied.
	 *
	 * \note Use \p dilithium_ctx_internal or
	 * \p dilithium_ed25519_ctx_internal to set this value.
	 *
	 * \warning Only set this value to true if you exactly know what you are
	 * doing!.
	 */
	bool ml_dsa_internal:1;

	/**
	 * @brief Was aHat already filled? This is used and set internally.
	 */
	bool ahat_expanded:1;
} __aligned(CRYPTO_MINALIGN);

static inline void dilithium_hash_init(struct dilithium_ctx *ctx)
{
	shake256_init(&ctx->dilithium_hash_ctx);
}

static inline bool dilithium_hash_check_blocksize(const struct dilithium_ctx *ctx, size_t bsize)
{
	return bsize == SHAKE256_BLOCK_SIZE;
	//return crypto_shash_blocksize(hash_ctx->tfm) == bsize;
}

static inline bool dilithium_hash_check_digestsize(const struct dilithium_ctx *ctx, size_t dsize)
{
	return true;
	//return crypto_shash_digestsize(hash_ctx->tfm) == dsize;
}

static inline void dilithium_hash_clear(struct dilithium_ctx *ctx)
{
	shake256_clear(&ctx->dilithium_hash_ctx);
}

static inline void dilithium_hash_update(struct dilithium_ctx *ctx,
					 const u8 *in, size_t in_size)
{
	shake256_update(&ctx->dilithium_hash_ctx, in, in_size);
}

static inline void dilithium_hash_finup(struct dilithium_ctx *ctx,
					const u8 *in, size_t in_size,
					u8 *out, size_t out_size)
{
	shake256_update(&ctx->dilithium_hash_ctx, in, in_size);
	shake256_squeeze(&ctx->dilithium_hash_ctx, out, out_size);
	shake256_clear(&ctx->dilithium_hash_ctx);
}

static inline void dilithium_hash_final(struct dilithium_ctx *ctx, u8 *out, size_t out_size)
{
	shake256_squeeze(&ctx->dilithium_hash_ctx, out, out_size);
	shake256_clear(&ctx->dilithium_hash_ctx);
}

#include "dilithium_87.h"
#include "dilithium_65.h"
#include "dilithium_44.h"

enum dilithium_type {
	DILITHIUM_UNKNOWN,	/** Unknown key type */
	DILITHIUM_87,		/** Dilithium 87 */
	DILITHIUM_65,		/** Dilithium 65 */
	DILITHIUM_44,		/** Dilithium 44 */
};

/** @defgroup Dilithium ML-DSA / CRYSTALS-Dilithium Signature Mechanism
 *
 * \note Although the API uses the term "dilithium", the implementation complies
 * with FIPS 204. Thus the terms Dilithium and ML-DSA are used interchangeably.
 *
 * Dilithium API concept
 *
 * The Dilithium API is accessible via the following header files with the
 * mentioned purpose.
 *
 * * dilithium.h: This API is the generic API allowing the caller to select
 *   which Dilithium type (Dilithium 87, 65 or 44) are to be used. The selection
 *   is made either with the flag specified during key generation or by matching
 *   the size of the imported data with the different dilithium_*_load API
 *   calls. All remaining APIs take the information about the Dilithium type
 *   from the provided input data.
 *
 *   This header file only provides inline functions which selectively call
 *   the API provided with the header files below.
 *
 * * dilithium_87.h: Direct access to Dilithium 87.
 *
 * * dilithium_65.h: Direct access to Dilithium 65.
 *
 * * dilithium_44.h: Direct access to Dilithium 44.
 *
 * To support the stream mode of the Dilithium signature operation, a
 * context structure is required. This context structure can be allocated either
 * on the stack or heap with \p DILITHIUM_CTX_ON_STACK or
 * \p dilithium_ctx_alloc. The context should be zeroized
 * and freed (only for heap) with \p dilithium_ctx_zero or
 * \p dilithium_ctx_zero_free.
 */

/**
 * @brief Dilithium secret key
 */
struct dilithium_sk {
	enum dilithium_type dilithium_type;
	union {
#ifdef CONFIG_CRYPTO_DILITHIUM_87
		struct dilithium_87_sk sk_87;
#endif
#ifdef CONFIG_CRYPTO_DILITHIUM_65
		struct dilithium_65_sk sk_65;
#endif
#ifdef CONFIG_CRYPTO_DILITHIUM_44
		struct dilithium_44_sk sk_44;
#endif
	} key;
};

/**
 * @brief Dilithium public key
 */
struct dilithium_pk {
	enum dilithium_type dilithium_type;
	union {
#ifdef CONFIG_CRYPTO_DILITHIUM_87
		struct dilithium_87_pk pk_87;
#endif
#ifdef CONFIG_CRYPTO_DILITHIUM_65
		struct dilithium_65_pk pk_65;
#endif
#ifdef CONFIG_CRYPTO_DILITHIUM_44
		struct dilithium_44_pk pk_44;
#endif
	} key;
};

/**
 * @brief Dilithium signature
 */
struct dilithium_sig {
	enum dilithium_type dilithium_type;
	union {
#ifdef CONFIG_CRYPTO_DILITHIUM_87
		struct dilithium_87_sig sig_87;
#endif
#ifdef CONFIG_CRYPTO_DILITHIUM_65
		struct dilithium_65_sig sig_65;
#endif
#ifdef CONFIG_CRYPTO_DILITHIUM_44
		struct dilithium_44_sig sig_44;
#endif
	} sig;
};

/**
 * @ingroup Dilithium
 * @brief Allocates Dilithium context on heap
 *
 * @param [out] ctx Dilithium context pointer
 *
 * @return 0 (success) or < 0 on error
 */
struct dilithium_ctx *dilithium_ctx_alloc(void);

/**
 * @ingroup Dilithium
 * @brief Allocates Dilithium context on heap with support to keep the internal
 *	  representation of the key.
 *
 * \note See \p DILITHIUM_CTX_ON_STACK_AHAT for details.
 *
 * @param [out] ctx Dilithium context pointer
 *
 * @return 0 (success) or < 0 on error
 */
struct dilithium_ctx *dilithium_ctx_alloc_ahat(enum dilithium_type type);

/**
 * @ingroup Dilithium
 * @brief Zeroizes and frees Dilithium context on heap
 *
 * @param [out] ctx Dilithium context pointer
 */
void dilithium_ctx_zero_free(struct dilithium_ctx *ctx);

/**
 * @ingroup Dilithium
 * @brief Zeroizes Dilithium context either on heap or on stack
 *
 * @param [out] ctx Dilithium context pointer
 */
void dilithium_ctx_zero(struct dilithium_ctx *ctx);

/**
 * @ingroup Dilithium
 * @brief Mark the Dilithium context to execute ML-DSA.Sign_internal /
 *	  ML-DSA.Verify_internal.
 *
 * @param [in] ctx Dilithium context
 */
void dilithium_ctx_internal(struct dilithium_ctx *ctx);

/**
 * @ingroup Dilithium
 * @brief Set the hash type that was used for pre-hashing the message. The
 *	  message digest is used with the HashML-DSA. The message digest
 *	  is to be provided via the message pointer in the sign/verify APIs.
 *
 * @param [in] ctx Dilithium context
 * @param [in] hash Hash context referencing the used hash for pre-hashing the
 *		    message
 */
void dilithium_ctx_hash(struct dilithium_ctx *ctx,
			struct crypto_shash *hash);

/**
 * @ingroup Dilithium
 * @brief Specify the optional user context string to be applied with the
 *	  Dilithium signature operation.
 *
 * @param [in] ctx Dilithium context
 * @param [in] userctx User context string
 * @param [in] userctxlen Size of the user context string
 */
void dilithium_ctx_userctx(struct dilithium_ctx *ctx,
			   const uint8_t *userctx, size_t userctxlen);

/**
 * @ingroup Dilithium
 * @brief Specify the optional external mu value.
 *
 * \note If the external mu is specified, the signature generation /
 * verification APIs do not require a message. In this case, the message buffer
 * can be set to NULL.
 *
 * \note If both a message and an external mu are provided, the external mu
 * takes precedence.
 *
 * @param [in] ctx Dilithium context
 * @param [in] external_mu User context string
 * @param [in] external_mu_len Size of the user context string
 */
void dilithium_ctx_external_mu(struct dilithium_ctx *ctx,
			       const uint8_t *external_mu,
			       size_t external_mu_len);

/**
 * @ingroup Dilithium
 * @brief Invalidate the expanded key that potentially is stored in the context.
 *
 * This call can be executed on a context irrespective it was allocated with
 * space for the expanded representation or not. Thus, the caller does not need
 * to track whether the context supports the expanded key.
 *
 * @param [in] ctx Dilithium context
 */
void dilithium_ctx_drop_ahat(struct dilithium_ctx *ctx);

/**
 * @ingroup Dilithium
 * @brief Obtain Dilithium type from secret key
 *
 * @param [in] sk Secret key from which the type is to be obtained
 *
 * @return key type
 */
enum dilithium_type dilithium_sk_type(const struct dilithium_sk *sk);

/**
 * @ingroup Dilithium
 * @brief Obtain Dilithium type from public key
 *
 * @param [in] pk Public key from which the type is to be obtained
 *
 * @return key type
 */
enum dilithium_type dilithium_pk_type(const struct dilithium_pk *pk);

/**
 * @ingroup Dilithium
 * @brief Obtain Dilithium type from signature
 *
 * @param [in] sig Signature from which the type is to be obtained
 *
 * @return key type
 */
enum dilithium_type
dilithium_sig_type(const struct dilithium_sig *sig);

/**
 * @ingroup Dilithium
 * @brief Return the size of the Dilithium secret key.
 *
 * @param [in] dilithium_type Dilithium type for which the size is requested
 *
 * @return requested size
 */
__pure unsigned int
dilithium_sk_size(enum dilithium_type dilithium_type);

/**
 * @ingroup Dilithium
 * @brief Return the size of the Dilithium public key.
 *
 * @param [in] dilithium_type Dilithium type for which the size is requested
 *
 * @return requested size
 */
__pure unsigned int
dilithium_pk_size(enum dilithium_type dilithium_type);

/**
 * @ingroup Dilithium
 * @brief Return the size of the Dilithium signature.
 *
 * @param [in] dilithium_type Dilithium type for which the size is requested
 *
 * @return requested size
 */
unsigned int __pure
dilithium_sig_size(enum dilithium_type dilithium_type);

/**
 * @ingroup Dilithium
 * @brief Load a Dilithium secret key provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] sk Secret key to be filled (the caller must have it allocated)
 * @param [in] src_key Buffer that holds the key to be imported
 * @param [in] src_key_len Buffer length that holds the key to be imported
 *
 * @return 0 on success or < 0 on error
 */
int dilithium_sk_load(struct dilithium_sk *sk, const uint8_t *src_key,
		      size_t src_key_len);

/**
 * @ingroup Dilithium
 * @brief Load a Dilithium public key provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] pk Secret key to be filled (the caller must have it allocated)
 * @param [in] src_key Buffer that holds the key to be imported
 * @param [in] src_key_len Buffer length that holds the key to be imported
 *
 * @return 0 on success or < 0 on error
 */
int dilithium_pk_load(struct dilithium_pk *pk, const uint8_t *src_key,
		      size_t src_key_len);

/**
 * @ingroup Dilithium
 * @brief Load a Dilithium signature provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] sig Secret key to be filled (the caller must have it allocated)
 * @param [in] src_sig Buffer that holds the signature to be imported
 * @param [in] src_sig_len Buffer length that holds the signature to be imported
 *
 * @return 0 on success or < 0 on error
 */
int dilithium_sig_load(struct dilithium_sig *sig, const uint8_t *src_sig,
		       size_t src_sig_len);

/**
 * @ingroup Dilithium
 * @brief Obtain the reference to the Dilithium key and its length
 *
 * \note Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto key, too.
 *
 * @param [out] dilithium_key Dilithium key pointer
 * @param [out] dilithium_key_len Length of the key buffer
 * @param [in] sk Dilithium secret key from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
int dilithium_sk_ptr(uint8_t **dilithium_key, size_t *dilithium_key_len,
		     struct dilithium_sk *sk);

/**
 * @ingroup Dilithium
 * @brief Obtain the reference to the Dilithium key and its length
 *
 * \note Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto key, too.
 *
 * @param [out] dilithium_key Dilithium key pointer
 * @param [out] dilithium_key_len Length of the key buffer
 * @param [in] pk Dilithium publi key from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
int dilithium_pk_ptr(uint8_t **dilithium_key, size_t *dilithium_key_len,
		     struct dilithium_pk *pk);

/**
 * @ingroup Dilithium
 * @brief Obtain the reference to the Dilithium signature and its length
 *
 * \note Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto signature,
 * too.
 *
 * @param [out] dilithium_sig Dilithium signature pointer
 * @param [out] dilithium_sig_len Length of the signature buffer
 * @param [in] sig Dilithium signature from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
int dilithium_sig_ptr(uint8_t **dilithium_sig, size_t *dilithium_sig_len,
		      struct dilithium_sig *sig);

/**
 * @ingroup Dilithium
 * @brief Generates Dilithium public and private key.
 *
 * @param [out] pk pointer to allocated output public key
 * @param [out] sk pointer to allocated output private key
 * @param [in] rng_ctx pointer to seeded random number generator context
 * @param [in] dilithium_type type of the Dilithium key to generate
 *
 * @return 0 (success) or < 0 on error
 */
int dilithium_keypair(struct dilithium_pk *pk, struct dilithium_sk *sk,
		      struct crypto_rng *rng_ctx,
		      enum dilithium_type dilithium_type);

/**
 * @ingroup Dilithium
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
 * @param [in] dilithium_type type of the Dilithium key to generate
 *
 * @return 0 (success) or < 0 on error
 */
int dilithium_keypair_from_seed(struct dilithium_pk *pk,
				struct dilithium_sk *sk,
				const uint8_t *seed, size_t seedlen,
				enum dilithium_type dilithium_type);

/**
 * @brief Pairwise consistency check as per FIPS 140 IG
 *
 * This call should be invoked after generating a key pair in FIPS mode
 *
 * @param [in] pk Public key
 * @param [in] sk Secret key
 *
 * @return 0 on success, < 0 on error
 */
int dilithium_pct(const struct dilithium_pk *pk,
		  const struct dilithium_sk *sk);

/**
 * @ingroup Dilithium
 * @brief Computes signature in one shot
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
int dilithium_sign(struct dilithium_sig *sig, const uint8_t *m,
		   size_t mlen, const struct dilithium_sk *sk,
		   struct crypto_rng *rng_ctx);

/**
 * @ingroup Dilithium
 * @brief Computes signature woth user context in one shot
 *
 * This API allows the caller to provide an arbitrary context buffer which
 * is hashed together with the message to form the message digest to be signed.
 *
 * Using the ctx structure, the caller can select 3 different types of ML-DSA:
 *
 * * ctx->dilithium_prehash_type set to a hash type, HashML-DSA is assumed which
 *   implies that the message m must be exactly digest size (FIPS 204 section
 *   5.4)
 *
 * * ctx->ml_dsa_internal set to 1, the ML-DSA.Sign_internal and
 *   .Verify_internal are executed (FIPS 204 chapter 6)
 *
 * * both aforementioned parameter set to NULL / 0, ML-DSA.Sign and
 *   ML-DSA.Verify are executed (FIPS 204 sections 5.2 and 5.3)
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
int dilithium_sign_ctx(struct dilithium_sig *sig,
		       struct dilithium_ctx *ctx, const uint8_t *m,
		       size_t mlen, const struct dilithium_sk *sk,
		       struct crypto_rng *rng_ctx);

/**
 * @ingroup Dilithium
 * @brief Initializes a signature operation
 *
 * This call is intended to support messages that are located in non-contiguous
 * places and even becomes available at different times. This call is to be
 * used together with the dilithium_sign_update and dilithium_sign_final.
 *
 * @param [in,out] ctx pointer Dilithium context
 * @param [in] sk pointer to bit-packed secret key
 *
 * @return 0 (success) or < 0 on error; -EOPNOTSUPP is returned if a different
 *	   hash than lc_shake256 is used.
 */
int dilithium_sign_init(struct dilithium_ctx *ctx,
			const struct dilithium_sk *sk);

/**
 * @ingroup Dilithium
 * @brief Add more data to an already initialized signature state
 *
 * This call is intended to support messages that are located in non-contiguous
 * places and even becomes available at different times. This call is to be
 * used together with the dilithium_sign_init and dilithium_sign_final.
 *
 * @param [in] ctx pointer to Dilithium context that was initialized with
 *	      	   dilithium_sign_init
 * @param [in] m pointer to message to be signed
 * @param [in] mlen length of message
 *
 * @return 0 (success) or < 0 on error
 */
int dilithium_sign_update(struct dilithium_ctx *ctx, const uint8_t *m,
			  size_t mlen);

/**
 * @ingroup Dilithium
 * @brief Computes signature
 *
 * @param [out] sig pointer to output signature
 * @param [in] ctx pointer to Dilithium context that was initialized with
 *	      	   dilithium_sign_init and filled with
 * 		   dilithium_sign_update
 * @param [in] sk pointer to bit-packed secret key
 * @param [in] rng_ctx pointer to seeded random number generator context - when
 *		       pointer is non-NULL, perform a randomized signing.
 *		       Otherwise use deterministic signing.
 *
 * @return 0 (success) or < 0 on error
 */
int dilithium_sign_final(struct dilithium_sig *sig,
			 struct dilithium_ctx *ctx,
			 const struct dilithium_sk *sk,
			 struct crypto_rng *rng_ctx);

/**
 * @ingroup Dilithium
 * @brief Verifies signature in one shot
 *
 * @param [in] sig pointer to input signature
 * @param [in] m pointer to message
 * @param [in] mlen length of message
 * @param [in] pk pointer to bit-packed public key
 *
 * @return 0 if signature could be verified correctly and -EBADMSG when
 * signature cannot be verified, < 0 on other errors
 */
int dilithium_verify(const struct dilithium_sig *sig, const uint8_t *m,
		     size_t mlen, const struct dilithium_pk *pk);

/**
 * @ingroup Dilithium
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
int dilithium_verify_ctx(const struct dilithium_sig *sig,
			 struct dilithium_ctx *ctx, const uint8_t *m,
			 size_t mlen, const struct dilithium_pk *pk);

/**
 * @ingroup Dilithium
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
int dilithium_verify_init(struct dilithium_ctx *ctx,
			  const struct dilithium_pk *pk);

/**
 * @ingroup Dilithium
 * @brief Add more data to an already initialized signature state
 *
 * This call is intended to support messages that are located in non-contiguous
 * places and even becomes available at different times. This call is to be
 * used together with the dilithium_verify_init and
 * dilithium_verify_final.
 *
 * @param [in] ctx pointer to Dilithium context that was initialized with
 *		   dilithium_sign_init
 * @param [in] m pointer to message to be signed
 * @param [in] mlen length of message
 *
 * @return 0 (success) or < 0 on error
 */
int dilithium_verify_update(struct dilithium_ctx *ctx, const uint8_t *m,
			    size_t mlen);

/**
 * @ingroup Dilithium
 * @brief Verifies signature
 *
 * @param [in] sig pointer to output signature
 * @param [in] ctx pointer to Dilithium context that was initialized with
 *		   dilithium_sign_init and filled with
 *		   dilithium_sign_update
 * @param [in] pk pointer to bit-packed public key
 *
 * @return 0 if signature could be verified correctly and -EBADMSG when
 * signature cannot be verified, < 0 on other errors
 */
int dilithium_verify_final(const struct dilithium_sig *sig,
			   struct dilithium_ctx *ctx,
			   const struct dilithium_pk *pk);

/* No valgrind */
#define poison(addr, len)
#define unpoison(addr, len)
#define is_poisoned(addr, len)

#endif /* DILITHIUM_H */
