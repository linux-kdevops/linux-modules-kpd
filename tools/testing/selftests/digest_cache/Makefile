# SPDX-License-Identifier: GPL-2.0
TEST_GEN_PROGS_EXTENDED = digest_cache_kern.ko
TEST_GEN_PROGS := all_test

$(OUTPUT)/%.ko: $(wildcard common.[ch]) testmod/Makefile testmod/kern.c
	$(call msg,MOD,,$@)
	$(Q)$(MAKE) -C testmod
	$(Q)cp testmod/digest_cache_kern.ko $@

LOCAL_HDRS += common.h common_user.h generators.h
CFLAGS += -ggdb -Wall -Wextra $(KHDR_INCLUDES)

OVERRIDE_TARGETS := 1
override define CLEAN
	$(call msg,CLEAN)
	$(Q)$(MAKE) -C testmod clean
	rm -Rf $(TEST_GEN_PROGS) $(TEST_GEN_PROGS_EXTENDED)
	rm -Rf $(OUTPUT)/common.o $(OUTPUT)/common_user.o $(OUTPUT)/generators.o
	rm -Rf $(OUTPUT)/common.mod
endef

include ../lib.mk

$(OUTPUT)/all_test: common.c common.h common_user.c common_user.h generators.c
