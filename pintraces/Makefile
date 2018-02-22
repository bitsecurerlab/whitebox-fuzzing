.PHONY: default tags
default: all

%:
ifeq ("true","true")
	(make -f Makefile.pin PIN_ROOT=/root/whitebox_fuzzer/pin TARGET=intel64 ARCH_X64="true" $@)
endif
	(make -f Makefile.pin PIN_ROOT=/root/whitebox_fuzzer/pin TARGET=ia32 ARCH_X64="true" $@)

tags:
