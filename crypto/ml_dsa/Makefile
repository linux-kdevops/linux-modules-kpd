################################################################################
# Signature implementation: Dilithium

################################################################################
# C Implementation
################################################################################
ml_dsa-y += \
	signature_domain_separation.o \
	dilithium_api.o \
	dilithium_zetas.o \
	dilithium_sig.o \
	dilithium_signature_helper.o

ml_dsa-$(CONFIG_CRYPTO_DILITHIUM_87) += dilithium_87.o
ml_dsa-$(CONFIG_CRYPTO_DILITHIUM_65) += dilithium_65.o
ml_dsa-$(CONFIG_CRYPTO_DILITHIUM_44) += dilithium_44.o

obj-$(CONFIG_CRYPTO_ML_DSA) += ml_dsa.o

obj-$(CONFIG_CRYPTO_ML_DSA_TEST) += dilithium_selftest.o
