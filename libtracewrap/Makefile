# Wrapper to configure and build libtrace

.PHONY: default
default: all

%:
ifeq (true, true)
	test -d libtrace32 || cp -R libtrace ./libtrace32
endif
	$(MAKE) CONFIGURED
	$(MAKE) -C libtrace $@
ifeq (true, true)
	$(MAKE) -C libtrace32 $@
endif

CONFIGURED: libtrace/Makefile.am libtrace/configure.ac
	(cd libtrace && INCDIRS="" CPPFLAGS="" ./configure --with-batteries=/root/whitebox_fuzzer/batteries/_build/src)
ifeq (true, true)
	(cd libtrace32 && INCDIRS="" CPPFLAGS=" -m32" CXXFLAGS="-m32" LDFLAGS=" -m32" ./configure --with-batteries=/root/whitebox_fuzzer/batteries/_build/src)
endif
	touch CONFIGURED
