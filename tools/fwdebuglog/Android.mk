LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := cld-fwlog-record
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../../CORE/SERVICES/COMMON
LOCAL_SHARED_LIBRARIES := libc libcutils
LOCAL_SRC_FILES := cld-fwlog-record.c
LOCAL_CFLAGS := $(CFLAGS)
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := cld-fwlog-parser
LOCAL_MODULE_TAGS := optional
LOCAL_C_INCLUDES := $(LOCAL_PATH)/../../CORE/SERVICES/COMMON
LOCAL_SHARED_LIBRARIES := libc libcutils
LOCAL_SRC_FILES := cld-fwlog-parser.c
LOCAL_CFLAGS := $(CFLAGS)
include $(BUILD_EXECUTABLE)
