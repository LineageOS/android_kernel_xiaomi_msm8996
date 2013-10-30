# Android makefile for the WLAN Module

# Assume no targets will be supported
WLAN_CHIPSET :=

# Build/Package options for 8084 target
ifeq ($(call is-board-platform,apq8084),true)
WLAN_CHIPSET := qca_cld
WLAN_SELECT := CONFIG_QCA_CLD_WLAN=m
WLAN_ISOC_SELECT := WLAN_ISOC=n
endif

# Build/Package only in case of supported target
ifneq ($(WLAN_CHIPSET),)

LOCAL_PATH := $(call my-dir)

# This makefile is only for DLKM
ifneq ($(findstring vendor,$(LOCAL_PATH)),)

# Determine if we are Proprietary or Open Source
ifneq ($(findstring opensource,$(LOCAL_PATH)),)
    WLAN_PROPRIETARY := 0
else
    WLAN_PROPRIETARY := 1
endif

ifeq ($(WLAN_PROPRIETARY),1)
    WLAN_BLD_DIR := vendor/qcom/proprietary/wlan-noship
else
    WLAN_BLD_DIR := vendor/qcom/opensource/wlan
endif

ifeq ($(call is-android-codename,JELLY_BEAN),true)
       DLKM_DIR := $(TOP)/device/qcom/common/dlkm
else
       DLKM_DIR := build/dlkm
endif

# This is set once per LOCAL_PATH, not per (kernel) module
KBUILD_OPTIONS := WLAN_ROOT=../$(WLAN_BLD_DIR)/qcacld-2.0
# We are actually building wlan.ko here, as per the
# requirement we are specifying <chipset>_wlan.ko as LOCAL_MODULE.
# This means we need to rename the module to <chipset>_wlan.ko
# after wlan.ko is built.
KBUILD_OPTIONS += MODNAME=wlan
KBUILD_OPTIONS += BOARD_PLATFORM=$(TARGET_BOARD_PLATFORM)
KBUILD_OPTIONS += $(WLAN_SELECT)
KBUILD_OPTIONS += $(WLAN_ISOC_SELECT)

include $(CLEAR_VARS)
#LOCAL_MODULE              := proprietary_$(WLAN_CHIPSET)_wlan.ko
#LOCAL_MODULE_KBUILD_NAME  := wlan.ko
#LOCAL_MODULE_TAGS         := debug
#LOCAL_MODULE_DEBUG_ENABLE := true
#LOCAL_MODULE_PATH         := $(TARGET_OUT)/lib/modules/$(WLAN_CHIPSET)
#include $(DLKM_DIR)/AndroidKernelModule.mk
###########################################################

# Create Symbolic link
$(shell mkdir -p $(TARGET_OUT)/lib/modules; \
	ln -sf /system/lib/modules/$(WLAN_CHIPSET)/$(WLAN_CHIPSET)_wlan.ko \
	       $(TARGET_OUT)/lib/modules/wlan.ko)

# Copy config ini files to target
ifeq ($(WLAN_PROPRIETARY),1)
$(shell mkdir -p $(TARGET_OUT)/etc/firmware/wlan/$(WLAN_CHIPSET))
$(shell rm -f $(TARGET_OUT)/etc/firmware/wlan/$(WLAN_SHIPSET)/WCNSS_qcom_cfg.ini)
$(shell rm -f $(TARGET_OUT)/etc/firmware/wlan/$(WLAN_SHIPSET)/WCNSS_cfg.dat)
$(shell rm -f $(TARGET_OUT)/etc/firmware/wlan/$(WLAN_SHIPSET)/WCNSS_qcom_wlan_nv.bin)
$(shell cp $(LOCAL_PATH)/firmware_bin/WCNSS_qcom_cfg.ini $(TARGET_OUT)/etc/firmware/wlan/$(WLAN_CHIPSET))
$(shell cp $(LOCAL_PATH)/firmware_bin/WCNSS_cfg.dat $(TARGET_OUT)/etc/firmware/wlan/$(WLAN_CHIPSET))
$(shell cp $(LOCAL_PATH)/firmware_bin/WCNSS_qcom_wlan_nv.bin $(TARGET_OUT)/etc/firmware/wlan/$(WLAN_CHIPSET))
endif

endif # DLKM check

endif # supported target check
