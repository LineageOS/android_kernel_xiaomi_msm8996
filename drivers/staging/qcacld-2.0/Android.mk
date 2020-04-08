# Android makefile for the WLAN Module

# Assume no targets will be supported
WLAN_CHIPSET :=

ifeq ($(BOARD_HAS_QCOM_WLAN), true)
# Build/Package options for 8084/8092/8960/8992/8994/msm8996 targets
ifeq ($(call is-board-platform-in-list, apq8084 mpq8092 msm8952 msm8960 msm8992 msm8994 msm8996),true)
WLAN_CHIPSET := qca_cld
WLAN_SELECT := CONFIG_QCA_CLD_WLAN=m
endif

# Build/Package options for 8953_som/8909_som target
ifeq ($(call is-board-platform-in-list, msm8953 msm8909),true)
ifeq ($(SD624_SOM_SUPPORT), true)
WLAN_CHIPSET := qca_cld
WLAN_SELECT := CONFIG_QCA_CLD_WLAN=m
endif
ifeq ($(SD212_SOM_SUPPORT), true)
WLAN_CHIPSET := qca_cld
WLAN_SELECT := CONFIG_QCA_CLD_WLAN=m
endif
endif

# Build/Package only in case of supported target
ifneq ($(WLAN_CHIPSET),)

# Check for kernel version
ifeq ($(TARGET_KERNEL_VERSION),)
$(info "WLAN: TARGET_KERNEL_VERSION not defined, assuming default")
TARGET_KERNEL_VERSION := 3.18
TARGET_KERNEL_SOURCE := kernel
KERNEL_TO_BUILD_ROOT_OFFSET := ../
endif

# Check for supported kernel
ifeq ($(TARGET_KERNEL_VERSION),$(filter $(TARGET_KERNEL_VERSION),4.4 3.18))
$(info "WLAN: supported kernel detected, building qcacld-2.0")

# If kernel path offset is not defined, assume old kernel structure
ifeq ($(KERNEL_TO_BUILD_ROOT_OFFSET),)
$(info "WLAN: KERNEL_TO_BUILD_ROOT_OFFSET not defined, assuming default")
KERNEL_TO_BUILD_ROOT_OFFSET := ../
endif

LOCAL_PATH := $(call my-dir)

# This makefile is only for DLKM
ifneq ($(findstring vendor,$(LOCAL_PATH)),)

# Determine if we are Proprietary or Open Source
ifneq ($(findstring opensource,$(LOCAL_PATH)),)
    WLAN_PROPRIETARY := 0
    WLAN_OPEN_SOURCE := 1
else
    WLAN_PROPRIETARY := 1
    WLAN_OPEN_SOURCE := 0
endif

ifeq ($(WLAN_PROPRIETARY),1)
    WLAN_BLD_DIR := vendor/qcom/proprietary/wlan-noship
else
    WLAN_BLD_DIR := vendor/qcom/opensource/wlan
endif

# DLKM_DIR was moved for JELLY_BEAN (PLATFORM_SDK 16)
ifeq ($(call is-platform-sdk-version-at-least,16),true)
       DLKM_DIR := $(TOP)/device/qcom/common/dlkm
else
       DLKM_DIR := build/dlkm
endif

# Copy WCNSS_cfg.dat and WCNSS_qcom_cfg.ini file from firmware_bin/ folder to target out directory.
ifeq ($(call is-board-platform-in-list, msm8960),true)
$(shell rm -f $(TARGET_OUT_ETC)/firmware/wlan/qca_cld/WCNSS_cfg.dat)
$(shell rm -f $(TARGET_OUT_ETC)/firmware/wlan/qca_cld/WCNSS_qcom_cfg.ini)
$(shell cp $(LOCAL_PATH)/firmware_bin/WCNSS_cfg.dat $(TARGET_OUT_ETC)/firmware/wlan/qca_cld)
$(shell cp $(LOCAL_PATH)/firmware_bin/WCNSS_qcom_cfg.ini $(TARGET_OUT_ETC)/firmware/wlan/qca_cld)
endif

###########################################################
# This is set once per LOCAL_PATH, not per (kernel) module
KBUILD_OPTIONS := WLAN_ROOT=$(KERNEL_TO_BUILD_ROOT_OFFSET)$(WLAN_BLD_DIR)/qcacld-2.0
# We are actually building wlan.ko here, as per the
# requirement we are specifying <chipset>_wlan.ko as LOCAL_MODULE.
# This means we need to rename the module to <chipset>_wlan.ko
# after wlan.ko is built.
KBUILD_OPTIONS += MODNAME=wlan
KBUILD_OPTIONS += BOARD_PLATFORM=$(TARGET_BOARD_PLATFORM)
KBUILD_OPTIONS += $(WLAN_SELECT)
KBUILD_OPTIONS += WLAN_OPEN_SOURCE=$(WLAN_OPEN_SOURCE)

#module to be built for all user,userdebug and eng tags
include $(CLEAR_VARS)
LOCAL_MODULE              := $(WLAN_CHIPSET)_wlan.ko
LOCAL_MODULE_KBUILD_NAME  := wlan.ko
LOCAL_MODULE_TAGS         := optional
LOCAL_MODULE_DEBUG_ENABLE := true
ifeq ($(PRODUCT_VENDOR_MOVE_ENABLED), true)
LOCAL_MODULE_PATH         := $(TARGET_OUT_VENDOR)/lib/modules/$(WLAN_CHIPSET)
else
LOCAL_MODULE_PATH         := $(TARGET_OUT)/lib/modules/$(WLAN_CHIPSET)
endif # PRODUCT_VENDOR_MOVE_ENABLED
include $(DLKM_DIR)/AndroidKernelModule.mk
###########################################################

# Create Symbolic link for built <WLAN_CHIPSET>_wlan.ko driver from
# standard module location.
# TO-DO: This step needs to be moved to a post-build make target instead
# TO-DO: as this may run multiple times
ifneq ($(call is-board-platform-in-list, msm8952),true)
ifeq ($(PRODUCT_VENDOR_MOVE_ENABLED), true)
$(shell mkdir -p $(TARGET_OUT_VENDOR)/lib/modules; \
    ln -sf /$(TARGET_COPY_OUT_VENDOR)/lib/modules/$(WLAN_CHIPSET)/$(WLAN_CHIPSET)_wlan.ko \
           $(TARGET_OUT_VENDOR)/lib/modules/wlan.ko)
else
$(shell mkdir -p $(TARGET_OUT)/lib/modules; \
    ln -sf /system/lib/modules/$(WLAN_CHIPSET)/$(WLAN_CHIPSET)_wlan.ko \
           $(TARGET_OUT)/lib/modules/wlan.ko)
endif # PRODUCT_VENDOR_MOVE_ENABLED
endif
$(shell ln -sf /persist/wlan_mac.bin $(TARGET_OUT_ETC)/firmware/wlan/qca_cld/wlan_mac.bin)

ifeq ($(call is-board-platform-in-list, msm8960),true)
$(shell ln -sf /firmware/image/bdwlan20.bin $(TARGET_OUT_ETC)/firmware/fakeboar.bin)
$(shell ln -sf /firmware/image/otp20.bin $(TARGET_OUT_ETC)/firmware/otp.bin)
$(shell ln -sf /firmware/image/utf20.bin $(TARGET_OUT_ETC)/firmware/utf.bin)
$(shell ln -sf /firmware/image/qwlan20.bin $(TARGET_OUT_ETC)/firmware/athwlan.bin)

$(shell ln -sf /firmware/image/bdwlan20.bin $(TARGET_OUT_ETC)/firmware/bdwlan20.bin)
$(shell ln -sf /firmware/image/otp20.bin $(TARGET_OUT_ETC)/firmware/otp20.bin)
$(shell ln -sf /firmware/image/utf20.bin $(TARGET_OUT_ETC)/firmware/utf20.bin)
$(shell ln -sf /firmware/image/qwlan20.bin $(TARGET_OUT_ETC)/firmware/qwlan20.bin)

$(shell ln -sf /firmware/image/bdwlan30.bin $(TARGET_OUT_ETC)/firmware/bdwlan30.bin)
$(shell ln -sf /firmware/image/otp30.bin $(TARGET_OUT_ETC)/firmware/otp30.bin)
$(shell ln -sf /firmware/image/utf30.bin $(TARGET_OUT_ETC)/firmware/utf30.bin)
$(shell ln -sf /firmware/image/qwlan30.bin $(TARGET_OUT_ETC)/firmware/qwlan30.bin)
endif

# Copy config ini files to target
ifeq ($(call is-board-platform-in-list, msm8994),false)
ifeq ($(WLAN_PROPRIETARY),1)
$(shell mkdir -p $(TARGET_OUT)/etc/firmware/wlan/$(WLAN_CHIPSET))
$(shell mkdir -p $(TARGET_OUT)/etc/wifi)
$(shell rm -f $(TARGET_OUT)/etc/wifi/WCNSS_qcom_cfg.ini)
$(shell rm -f $(TARGET_OUT)/etc/firmware/wlan/$(WLAN_SHIPSET)/WCNSS_cfg.dat)
$(shell cp $(LOCAL_PATH)/firmware_bin/WCNSS_qcom_cfg.ini $(TARGET_OUT)/etc/wifi)
$(shell cp $(LOCAL_PATH)/firmware_bin/WCNSS_cfg.dat $(TARGET_OUT)/etc/firmware/wlan/$(WLAN_CHIPSET))
endif
endif

endif # DLKM check
endif # Supported kernel check
endif # supported target check
endif # WLAN enabled check
