// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * Copyright (C) 2025 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <crypto/sig.h>
#include <kunit/test.h>
#include "dilithium.h"

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("Leancrypto ML-DSA/Dilithium tests");
MODULE_AUTHOR("David Howells <dhowells@redhat.com>");

struct dilithium_testvector {
	u16		pk_len;
	u16		sk_len;
	u16		msg_len;
	u16		sig_len;
	const char	*what;
	const char	*algo;
	const u8	*pk;
	const u8	*sk;
	const u8	*sig;
	const u8	*msg;
};

/*
 * Use rejection test vector which will cover all rejection code paths
 * as generated with the dilithium_edge_case_tester.
 *
 * For FIPS 140: The test vectors cover the requirements of IG 10.3.A.
 */
static const struct dilithium_testvector dilithium44_testvectors[] = {
#include "dilithium_pure_rejection_vectors_44.h"
};
static const struct dilithium_testvector dilithium65_testvectors[] = {
#include "dilithium_pure_rejection_vectors_65.h"
};
static const struct dilithium_testvector dilithium87_testvectors[] = {
#include "dilithium_pure_rejection_vectors_87.h"
};

/*
 * Allow kunit to free a crypto signature processing object.
 */
static void __kunit_crypto_free_sig(void *sig)
{
	crypto_free_sig(sig);
}

/*
 * Allow kunit to allocate a crypto signature processing object.
 */
static struct crypto_sig *kunit_crypto_alloc_sig(struct kunit *test,
						 const char *alg_name,
						 u32 type, u32 mask)
{
	struct crypto_sig *sig;

	sig = crypto_alloc_sig(alg_name, 0, 0);
        KUNIT_ASSERT_NOT_ERR_OR_NULL(test, sig);

	kunit_add_action_or_reset(test, __kunit_crypto_free_sig, sig);
	return sig;
}

/*
 * Force the freeing of a signature.
 */
static void kunit_crypto_free_sig(struct kunit *test, void *sig)
{
	kunit_release_action(test, __kunit_crypto_free_sig, sig);
}

/*
 * Do a single signing test.
 */
static void dilithium_siggen_test_one(struct kunit *test, int index,
				      const struct dilithium_testvector *tc)
{
	struct crypto_sig *sig;
	size_t bsize;
	void *buf;
	int ret;

	sig = kunit_crypto_alloc_sig(test, tc->algo, 0, 0);
	if (IS_ERR(sig))
		return;

	ret = crypto_sig_set_privkey(sig, tc->sk, tc->sk_len);
	KUNIT_ASSERT_EQ_MSG(test, ret, 0, "Can't set private key");

	bsize = crypto_sig_maxsize(sig);
	buf = kunit_kmalloc(test, bsize, GFP_KERNEL);
	if (!buf)
		goto out;

	ret = crypto_sig_sign(sig, tc->msg, tc->msg_len, buf, bsize);
	KUNIT_ASSERT_GT_MSG(test, ret, 0, "Signing failed");
	KUNIT_ASSERT_EQ_MSG(test, ret, bsize, "Incorrect sig size");
	KUNIT_ASSERT_MEMEQ_MSG(test, buf, tc->sig, ret,
			       "Different sig generated\n");

	kunit_kfree(test, buf);
out:
	kunit_crypto_free_sig(test, sig);
}

static void dilithium_sigver_test_one(struct kunit *test, int index,
				      const struct dilithium_testvector *tc)
{
	struct crypto_sig *sig;
	int ret;

	sig = kunit_crypto_alloc_sig(test, tc->algo, 0, 0);
	if (IS_ERR(sig))
		return;

	ret = crypto_sig_set_pubkey(sig, tc->pk, tc->pk_len);
	KUNIT_ASSERT_EQ_MSG(test, ret, 0, "Can't set public key");

	ret = crypto_sig_verify(sig, tc->sig, tc->sig_len, tc->msg, tc->msg_len);
	KUNIT_ASSERT_EQ_MSG(test, ret, 0, "Verify failed");

	kunit_crypto_free_sig(test, sig);
}

static void dilithium44_kunit_test(struct kunit *test)
{
	const struct dilithium_testvector *tc = dilithium44_testvectors;
	int count = ARRAY_SIZE(dilithium44_testvectors);

	for (int index = 0; index < count; index++) {
		dilithium_siggen_test_one(test, index, &tc[index]);
		dilithium_sigver_test_one(test, index, &tc[index]);
	}

	KUNIT_SUCCEED(test);
}

static void dilithium65_kunit_test(struct kunit *test)
{
	const struct dilithium_testvector *tc = dilithium65_testvectors;
	int count = ARRAY_SIZE(dilithium65_testvectors);

	for (int index = 0; index < count; index++) {
		dilithium_siggen_test_one(test, index, &tc[index]);
		dilithium_sigver_test_one(test, index, &tc[index]);
	}

	KUNIT_SUCCEED(test);
}

static void dilithium87_kunit_test(struct kunit *test)
{
	const struct dilithium_testvector *tc = dilithium87_testvectors;
	int count = ARRAY_SIZE(dilithium87_testvectors);

	for (int index = 0; index < count; index++) {
		dilithium_siggen_test_one(test, index, &tc[index]);
		dilithium_sigver_test_one(test, index, &tc[index]);
	}

	KUNIT_SUCCEED(test);
}

static struct kunit_case __refdata dilithium_kunit_cases[] = {
	KUNIT_CASE(dilithium44_kunit_test),
	KUNIT_CASE(dilithium65_kunit_test),
	KUNIT_CASE(dilithium87_kunit_test),
	{}
};

static struct kunit_suite dilithium_kunit_suite = {
	.name		= "ml-dsa",
	.test_cases	= dilithium_kunit_cases,
};

kunit_test_suites(&dilithium_kunit_suite);
