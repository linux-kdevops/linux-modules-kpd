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

#include <crypto/sha3.h>
#include <crypto/hash.h>
#include "signature_domain_separation.h"

static const char *signature_prehash_type;

/* RFC4055 2.16.840.1.101.3.4.2.1 */
static const uint8_t sha256_oid_der[] __maybe_unused = { 0x06, 0x09, 0x60, 0x86,
							 0x48, 0x01, 0x65, 0x03,
							 0x04, 0x02, 0x01 };
/* RFC4055 2.16.840.1.101.3.4.2.2 */
static const uint8_t sha384_oid_der[] __maybe_unused = { 0x06, 0x09, 0x60, 0x86,
							 0x48, 0x01, 0x65, 0x03,
							 0x04, 0x02, 0x02 };
/* RFC4055 2.16.840.1.101.3.4.2.3 */
static const uint8_t sha512_oid_der[] __maybe_unused = { 0x06, 0x09, 0x60, 0x86,
							 0x48, 0x01, 0x65, 0x03,
							 0x04, 0x02, 0x03 };

/*
 * https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html
 */
static const uint8_t sha3_256_oid_der[] __maybe_unused = {
	0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08
};
static const uint8_t sha3_384_oid_der[] __maybe_unused = {
	0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09
};
static const uint8_t sha3_512_oid_der[] __maybe_unused = {
	0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a
};

/* RFC8692 2.16.840.1.101.3.4.2.11 */
static const uint8_t shake128_oid_der[] __maybe_unused = {
	0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B
};

/* RFC8692 2.16.840.1.101.3.4.2.11 */
static const uint8_t shake256_oid_der[] __maybe_unused = {
	0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C
};

int signature_ph_oids(struct shake256_ctx *hash_ctx, size_t mlen,
		      unsigned int nist_category)
{
	/* If no hash is supplied, we have no HashML-DSA */
	if (!signature_prehash_type)
		return 0;

	/*
	 * The signature init/update/final operation will not work with the
	 * check of mlen, as only when _final is invoked, the message length
	 * is known.
	 *
	 * As defined in FIPS 204, section 5.4 requires
	 * "... the digest that is signed needs to be generated using an
	 * approved hash function or XOF (e.g., from FIPS 180 or FIPS 202) that
	 * provides at least λ bits of classical security strength against both
	 * collision and second preimage attacks ... Obtaining at least λ bits
	 * of classical security strength against collision attacks requires
	 * that the digest to be signed be at least 2λ bits in length."
	 * This requirement implies in the following definitions.
	 */
	(void)mlen;

	switch (nist_category) {
	case 1:
		if (strcmp(signature_prehash_type, "sha256") == 0) {
			// if (mlen != LC_SHA256_SIZE_DIGEST)
			// 	return -EOPNOTSUPP;
			shake256_update(hash_ctx, sha256_oid_der,
					sizeof(sha256_oid_der));
			return 0;
		}
		if (strcmp(signature_prehash_type, "sha3-256") == 0) {
			// if (mlen != LC_SHA3_256_SIZE_DIGEST)
			// 	return -EOPNOTSUPP;
			shake256_update(hash_ctx, sha3_256_oid_der,
					sizeof(sha3_256_oid_der));
			return 0;
		}
		if (strcmp(signature_prehash_type, "shake128") == 0) {
			/* FIPS 204 section 5.4.1 */
			// if (mlen != 32)
			// 	return -EOPNOTSUPP;
			shake256_update(hash_ctx, shake128_oid_der,
					sizeof(shake128_oid_der));
			return 0;
		}
		/* FALLTHROUGH - Dilithium44 allows the following, too */
		fallthrough;
	case 3:
		if (strcmp(signature_prehash_type, "sha3-384") == 0) {
			// if (mlen != LC_SHA3_384_SIZE_DIGEST)
			// 	return -EOPNOTSUPP;
			shake256_update(hash_ctx, sha3_384_oid_der,
					sizeof(sha3_384_oid_der));
			return 0;
		}
		if (strcmp(signature_prehash_type, "sha384") == 0) {
			// if (mlen != LC_SHA384_SIZE_DIGEST)
			// 	return -EOPNOTSUPP;
			shake256_update(hash_ctx, sha384_oid_der,
					sizeof(sha384_oid_der));
			return 0;
		}
		/* FALLTHROUGH - Dilithium[44|65] allows the following, too  */
		fallthrough;
	case 5:
		if (strcmp(signature_prehash_type, "sha512") == 0) {
			// if (mlen != LC_SHA512_SIZE_DIGEST)
			// 	return -EOPNOTSUPP;
			shake256_update(hash_ctx, sha512_oid_der,
					sizeof(sha512_oid_der));
			return 0;
		}
		if (strcmp(signature_prehash_type, "sha3-512") == 0) {
			// if (mlen != LC_SHA3_512_SIZE_DIGEST)
			// 	return -EOPNOTSUPP;
			shake256_update(hash_ctx, sha3_512_oid_der,
					sizeof(sha3_512_oid_der));
			return 0;
		} else if (strcmp(signature_prehash_type, "shake256") == 0) {
			/* FIPS 204 section 5.4.1 */
			/*
			 * TODO: mlen must be >= 64 to comply with the
			 * aforementioned requirement - unfortunately we can
			 * only check mlen at the end of the signature
			 * operation - shall this be implemented?
			 */
			// if (mlen != 64)
			// 	return -EOPNOTSUPP;
			shake256_update(hash_ctx, shake256_oid_der,
					sizeof(shake256_oid_der));
			return 0;
		}
		break;
	default:
		break;
	}

	return -EOPNOTSUPP;
}

/* FIPS 204 pre-hash ML-DSA domain separation, but without original message */
static int standalone_signature_domain_separation(
	struct shake256_ctx *hash_ctx, const uint8_t *userctx,
	size_t userctxlen, size_t mlen, unsigned int nist_category)
{
	uint8_t domainseparation[2];

	domainseparation[0] = signature_prehash_type ? 1 : 0;
	domainseparation[1] = (uint8_t)userctxlen;

	shake256_update(hash_ctx, domainseparation, sizeof(domainseparation));
	shake256_update(hash_ctx, userctx, userctxlen);

	return signature_ph_oids(hash_ctx, mlen, nist_category);
}

/*
 * Domain separation as required by:
 *
 * FIPS 204 pre-hash ML-DSA: randomizer is NULL
 * Composite ML-DSA draft 5: randomizer is set
 */
int signature_domain_separation(struct shake256_ctx *hash_ctx,
				unsigned int ml_dsa_internal,
				const uint8_t *userctx, size_t userctxlen,
				const uint8_t *m, size_t mlen,
				const uint8_t *randomizer, size_t randomizerlen,
				unsigned int nist_category)
{
	int ret = 0;

	/* The internal operation skips the domain separation code */
	if (ml_dsa_internal)
		goto out;

	if (userctxlen > 255)
		return -EINVAL;

	/* If Composite ML-DSA is requested, use domain as userctx */
	if (randomizer) {
		return -EOPNOTSUPP;
	} else {
		ret = standalone_signature_domain_separation(
			hash_ctx, userctx, userctxlen,
			mlen, nist_category);
	}

out:
	shake256_update(hash_ctx, m, mlen);
	return ret;
}
