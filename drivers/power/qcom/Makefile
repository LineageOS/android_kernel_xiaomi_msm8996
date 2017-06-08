obj-$(CONFIG_MSM_PM)		+= msm-pm.o pm-data.o
obj-$(CONFIG_MSM_IDLE_STATS)	+= lpm-stats.o
obj-$(CONFIG_MSM_NOPM)		+= no-pm.o
obj-$(CONFIG_PM)                += pm-boot.o
obj-$(CONFIG_APSS_CORE_EA)	+= msm-core.o
obj-$(CONFIG_MSM_APM)		+= apm.o

ifeq ($(CONFIG_APSS_CORE_EA),y)
obj-$(CONFIG_DEBUG_FS)	+= debug_core.o
endif
