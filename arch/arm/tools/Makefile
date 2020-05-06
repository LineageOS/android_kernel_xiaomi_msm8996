#
# linux/arch/arm/tools/Makefile
#
# Copyright (C) 2001 Russell King
#

gen := arch/$(ARCH)/include/generated
kapi := $(gen)/asm

kapi-hdrs-y := $(kapi)/mach-types.h

targets += $(addprefix ../../../,$(kapi-hdrs-y))

PHONY += kapi

kapi:	$(kapi-hdrs-y)

# Create output directory if not already present
_dummy := $(shell [ -d '$(kapi)' ] || mkdir -p '$(kapi)')

$(kapi)/mach-types.h: $(src)/gen-mach-types $(src)/mach-types
	@$(kecho) '  Generating $@'
	@mkdir -p $(dir $@)
	$(Q)$(AWK) -f $^ > $@ || { rm -f $@; /bin/false; }
