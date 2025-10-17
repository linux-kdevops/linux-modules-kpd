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

#ifndef DILITHIUM_PACK_H
#define DILITHIUM_PACK_H

/*******************************************************************************
 * Pack / Unpack public key
 ******************************************************************************/

static inline void unpack_pk_rho(uint8_t rho[DILITHIUM_SEEDBYTES],
				 const struct dilithium_pk *pk)
{
	memcpy(rho, pk->pk, DILITHIUM_SEEDBYTES);
}

static inline void unpack_pk_t1(polyveck *t1, const struct dilithium_pk *pk)
{
	unsigned int i;
	const uint8_t *pubkey = pk->pk + DILITHIUM_SEEDBYTES;

	for (i = 0; i < DILITHIUM_K; ++i)
		polyt1_unpack(&t1->vec[i],
			      pubkey + i * DILITHIUM_POLYT1_PACKEDBYTES);
}

/*******************************************************************************
 * Pack / Unpack secret key
 ******************************************************************************/
static inline void unpack_sk_key(uint8_t key[DILITHIUM_SEEDBYTES],
				 const struct dilithium_sk *sk)
{
	memcpy(key, sk->sk + DILITHIUM_SEEDBYTES, DILITHIUM_SEEDBYTES);
}

static inline void unpack_sk_tr(uint8_t tr[DILITHIUM_TRBYTES],
				const struct dilithium_sk *sk)
{
	memcpy(tr, sk->sk + 2 * DILITHIUM_SEEDBYTES, DILITHIUM_TRBYTES);
}

static inline void unpack_sk_s1(polyvecl *s1, const struct dilithium_sk *sk)
{
	unsigned int i;
	const uint8_t *seckey =
		sk->sk + 2 * DILITHIUM_SEEDBYTES + DILITHIUM_TRBYTES;

	for (i = 0; i < DILITHIUM_L; ++i)
		polyeta_unpack(&s1->vec[i],
			       seckey + i * DILITHIUM_POLYETA_PACKEDBYTES);
}

static inline void unpack_sk_s2(polyveck *s2, const struct dilithium_sk *sk)
{
	unsigned int i;
	const uint8_t *seckey =
		sk->sk + 2 * DILITHIUM_SEEDBYTES + DILITHIUM_TRBYTES +
		DILITHIUM_L * DILITHIUM_POLYETA_PACKEDBYTES;

	for (i = 0; i < DILITHIUM_K; ++i)
		polyeta_unpack(&s2->vec[i],
			       seckey + i * DILITHIUM_POLYETA_PACKEDBYTES);
}

static inline void unpack_sk_t0(polyveck *t0, const struct dilithium_sk *sk)
{
	unsigned int i;
	const uint8_t *seckey =
		sk->sk + 2 * DILITHIUM_SEEDBYTES + DILITHIUM_TRBYTES +
		DILITHIUM_L * DILITHIUM_POLYETA_PACKEDBYTES +
		DILITHIUM_K * DILITHIUM_POLYETA_PACKEDBYTES;

	for (i = 0; i < DILITHIUM_K; ++i)
		polyt0_unpack(&t0->vec[i],
			      seckey + i * DILITHIUM_POLYT0_PACKEDBYTES);
}

/**
 * @brief pack_sig - Bit-pack signature sig = (c, z, h).
 *
 * NOTE: A signature is the concatenation of sig = (c || packed z || packed h).
 *	 As c is already present in the first bytes of sig, this function does
 *	 not need to copy it yet again to the right location. This implies that
 *	 this function does not process c.
 *
 * @param [out] sig signature
 * @param [in] z pointer to vector z
 * @param [in] h pointer to hint vector h
 */
static inline void pack_sig(struct dilithium_sig *sig, const polyvecl *z,
			    const polyveck *h)
{
	unsigned int i, j, k;
	/* Skip c */
	uint8_t *signature = sig->sig + DILITHIUM_CTILDE_BYTES;

	BUILD_BUG_ON((1ULL << (sizeof(j) << 3)) < DILITHIUM_N);
	BUILD_BUG_ON((1ULL << (sizeof(k) << 3)) < DILITHIUM_N);

	for (i = 0; i < DILITHIUM_L; ++i)
		polyz_pack(signature + i * DILITHIUM_POLYZ_PACKEDBYTES,
			   &z->vec[i]);
	signature += DILITHIUM_L * DILITHIUM_POLYZ_PACKEDBYTES;

	/* Encode h */
	memset(signature, 0, DILITHIUM_OMEGA + DILITHIUM_K);

	k = 0;
	for (i = 0; i < DILITHIUM_K; ++i) {
		for (j = 0; j < DILITHIUM_N; ++j)
			if (h->vec[i].coeffs[j] != 0)
				signature[k++] = (uint8_t)j;

		signature[DILITHIUM_OMEGA + i] = (uint8_t)k;
	}
}

/**
 * @brief unpack_sig_z - Unpack z part of signature sig = (c, z, h).
 *
 * NOTE: The c value is not unpacked as it can be used right from the signature.
 *	 To access it, a caller simply needs to use the first
 *	 DILITHIUM_CTILDE_BYTES of the signature.
 *
 * @param [out] z pointer to output vector z
 * @param [in] sig signature
 */
static inline void unpack_sig_z(polyvecl *z, const struct dilithium_sig *sig)
{
	unsigned int i;
	/* Skip c */
	const uint8_t *signature = sig->sig + DILITHIUM_CTILDE_BYTES;

	for (i = 0; i < DILITHIUM_L; ++i)
		polyz_unpack(&z->vec[i],
			     signature + i * DILITHIUM_POLYZ_PACKEDBYTES);
}

/**
 * @brief unpack_sig - Unpack h value of signature sig = (c, z, h).
 *
 * NOTE: The c value is not unpacked as it can be used right from the signature.
 *	 To access it, a caller simply needs to use the first
 *	 DILITHIUM_CTILDE_BYTES of the signature.
 *
 * @param [out] h pointer to output hint vector h
 * @param [in] sig signature
 *
 * @return 1 in case of malformed signature; otherwise 0.
 */
static inline int unpack_sig_h(polyveck *h, const struct dilithium_sig *sig)
{
	unsigned int i, j, k;
	/* Skip c */
	const uint8_t *signature =
		sig->sig + DILITHIUM_CTILDE_BYTES +
		DILITHIUM_L * DILITHIUM_POLYZ_PACKEDBYTES;

	/* Decode h */
	k = 0;
	for (i = 0; i < DILITHIUM_K; ++i) {
		for (j = 0; j < DILITHIUM_N; ++j)
			h->vec[i].coeffs[j] = 0;

		if (signature[DILITHIUM_OMEGA + i] < k ||
		    signature[DILITHIUM_OMEGA + i] > DILITHIUM_OMEGA)
			return 1;

		for (j = k; j < signature[DILITHIUM_OMEGA + i]; ++j) {
			/* Coefficients are ordered for strong unforgeability */
			if (j > k && signature[j] <= signature[j - 1])
				return 1;
			h->vec[i].coeffs[signature[j]] = 1;
		}

		k = signature[DILITHIUM_OMEGA + i];
	}

	/* Extra indices are zero for strong unforgeability */
	for (j = k; j < DILITHIUM_OMEGA; ++j)
		if (signature[j])
			return 1;

	return 0;
}

#endif /* DILITHIUM_PACK_H */
