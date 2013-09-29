
CC := $(ATH_CROSS_COMPILE_TYPE)gcc
TARGET_TYPE ?= AR9888
TARGET_VERS ?= v2

all:
	$(CC) -g3 -Wall  \
		-I ../../include/ \
		-I ../../CORE/SERVICES/COMMON/ \
		-I ../../CORE/SERVICES/HIF/ \
		-I ../../../../include/ \
		-I ../../../../../include/ \
		-I ../../../../../../../drivers/wlan_modules/lmac/ath_dev/ \
		-I ../../../../../include/$(TARGET_TYPE)/$(TARGET_VERS)/ \
		athdiag.c -o athdiag

clean:
	rm -f athdiag
