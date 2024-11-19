# SPDX-License-Identifier: GPL-2.0
#
# Makefile for building the Integrity Digest Cache.

obj-$(CONFIG_INTEGRITY_DIGEST_CACHE) += digest_cache.o

digest_cache-y := main.o secfs.o htable.o parsers.o

CFLAGS_parsers.o += -DPARSERS_DIR=\"$(MODLIB)/kernel/security/integrity/digest_cache/parsers\"
