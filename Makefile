# Hiredis Makefile
# Copyright (C) 2010-2011 Salvatore Sanfilippo <antirez at gmail dot com>
# Copyright (C) 2010-2011 Pieter Noordhuis <pcnoordhuis at gmail dot com>
# This file is released under the BSD license, see the COPYING file

OBJ=net.o hiredis.o sds.o async.o read.o
OBJ_SSL=hiredis_ssl.o
EXAMPLES=hiredis-example hiredis-example-libevent hiredis-example-libev hiredis-example-glib
ifneq ($(USE_SSL),)
EXAMPLES+=hiredis-example-ssl
endif
TESTS=hiredis-test
LIBNAME=libhiredis
LIBNAME_SSL=libhiredis_ssl
PKGCONFNAME=hiredis.pc
PKGCONFNAME_SSL=hiredis_ssl.pc

HIREDIS_MAJOR=$(shell grep HIREDIS_MAJOR hiredis.h | awk '{print $$3}')
HIREDIS_MINOR=$(shell grep HIREDIS_MINOR hiredis.h | awk '{print $$3}')
HIREDIS_PATCH=$(shell grep HIREDIS_PATCH hiredis.h | awk '{print $$3}')
HIREDIS_SONAME=$(shell grep HIREDIS_SONAME hiredis.h | awk '{print $$3}')

# Installation related variables and target
PREFIX?=/usr/local
INCLUDE_PATH?=include/hiredis
LIBRARY_PATH?=lib
PKGCONF_PATH?=pkgconfig
INSTALL_INCLUDE_PATH= $(DESTDIR)$(PREFIX)/$(INCLUDE_PATH)
INSTALL_LIBRARY_PATH= $(DESTDIR)$(PREFIX)/$(LIBRARY_PATH)
INSTALL_PKGCONF_PATH= $(INSTALL_LIBRARY_PATH)/$(PKGCONF_PATH)

# redis-server configuration used for testing
REDIS_PORT=56379
REDIS_SERVER=redis-server
define REDIS_TEST_CONFIG
	daemonize yes
	pidfile /tmp/hiredis-test-redis.pid
	port $(REDIS_PORT)
	bind 127.0.0.1
	unixsocket /tmp/hiredis-test-redis.sock
endef
export REDIS_TEST_CONFIG

# Fallback to gcc when $CC is not in $PATH.
CC:=$(shell sh -c 'type $(CC) >/dev/null 2>/dev/null && echo $(CC) || echo gcc')
CXX:=$(shell sh -c 'type $(CXX) >/dev/null 2>/dev/null && echo $(CXX) || echo g++')
OPTIMIZATION?=-O3
WARNINGS=-Wall -W -Wstrict-prototypes -Wwrite-strings
DEBUG?= -g -ggdb
REAL_CFLAGS=$(OPTIMIZATION) -fPIC $(CFLAGS) $(WARNINGS) $(DEBUG) $(ARCH)
REAL_LDFLAGS=$(LDFLAGS) $(ARCH)

DYLIBSUFFIX=so
STLIBSUFFIX=a
DYLIB_MINOR_NAME=$(LIBNAME).$(DYLIBSUFFIX).$(HIREDIS_SONAME)
DYLIB_MAJOR_NAME=$(LIBNAME).$(DYLIBSUFFIX).$(HIREDIS_MAJOR)
DYLIBNAME=$(LIBNAME).$(DYLIBSUFFIX)
DYLIB_MAKE_CMD_PREFIX=$(CC) -shared -Wl,-soname,$(DYLIB_MINOR_NAME)
DYLIB_MAKE_CMD_SUFFIX=$(LDFLAGS)
STLIBNAME=$(LIBNAME).$(STLIBSUFFIX)
STLIB_MAKE_CMD=ar rcs

DYLIB_MINOR_SSL_NAME=$(LIBNAME_SSL).$(DYLIBSUFFIX).$(HIREDIS_SONAME)
DYLIB_MAJOR_SSL_NAME=$(LIBNAME_SSL).$(DYLIBSUFFIX).$(HIREDIS_MAJOR)
DYLIBNAME_SSL=$(LIBNAME_SSL).$(DYLIBSUFFIX)
STLIBNAME_SSL=$(LIBNAME_SSL).$(STLIBSUFFIX)

ifneq ($(USE_SSL),)
SSL_TARGETS=$(DYLIBNAME_SSL) $(STLIBNAME_SSL) $(PKGCONFNAME_SSL)
HIREDIS_SSL_HEADER=hiredis_ssl.h
endif

# Platform-specific overrides
uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')
ifeq ($(uname_S),SunOS)
  REAL_LDFLAGS+= -ldl -lnsl -lsocket
  DYLIB_MAKE_CMD_PREFIX=$(CC) -G
  DYLIB_MAKE_CMD_SUFFIX=-h $(DYLIB_MINOR_NAME) $(LDFLAGS)
  INSTALL= cp -r
endif
ifeq ($(uname_S),Darwin)
  DYLIBSUFFIX=dylib
  DYLIB_MINOR_NAME=$(LIBNAME).$(HIREDIS_SONAME).$(DYLIBSUFFIX)
  DYLIB_MAKE_CMD_PREFIX=$(CC) -shared -Wl,-install_name,$(DYLIB_MINOR_NAME)
  DYLIB_MAKE_CMD_SUFFIX=$(LDFLAGS)
endif

all: $(DYLIBNAME) $(STLIBNAME) hiredis-test $(PKGCONFNAME) $(SSL_TARGETS)

# Deps (use make dep to generate this)
async.o: async.c fmacros.h async.h hiredis.h read.h sds.h net.h dict.c dict.h
dict.o: dict.c fmacros.h dict.h
hiredis.o: hiredis.c fmacros.h hiredis.h read.h sds.h net.h
net.o: net.c fmacros.h net.h hiredis.h read.h sds.h
read.o: read.c fmacros.h read.h sds.h
sds.o: sds.c sds.h
test.o: test.c fmacros.h hiredis.h read.h sds.h
hiredis_ssl.o: hiredis_ssl.c

$(DYLIBNAME): $(OBJ)
	$(DYLIB_MAKE_CMD_PREFIX) -o $(DYLIBNAME) $(DYLIB_MAKE_CMD_SUFFIX) $(OBJ)

$(STLIBNAME): $(OBJ)
	$(STLIB_MAKE_CMD) $(STLIBNAME) $(OBJ)

dynamic: $(DYLIBNAME)
static: $(STLIBNAME)

$(DYLIBNAME_SSL): $(OBJ_SSL)
	$(DYLIB_MAKE_CMD_PREFIX) -o $(DYLIBNAME_SSL) $(DYLIB_MAKE_CMD_SUFFIX) $(OBJ_SSL)

$(STLIBNAME_SSL): $(OBJ_SSL)
	$(STLIB_MAKE_CMD) $(STLIBNAME_SSL) $(OBJ_SSL)

dynamic_ssl: $(DYLIBNAME_SSL)
static_ssl: $(STLIBNAME_SSL)

# Binaries:
hiredis-example-libevent: examples/example-libevent.c adapters/libevent.h $(STLIBNAME)
	$(CC) -o examples/$@ $(REAL_CFLAGS) $(REAL_LDFLAGS) -I. $< -levent $(STLIBNAME)

hiredis-example-libev: examples/example-libev.c adapters/libev.h $(STLIBNAME)
	$(CC) -o examples/$@ $(REAL_CFLAGS) $(REAL_LDFLAGS) -I. $< -lev $(STLIBNAME)

hiredis-example-glib: examples/example-glib.c adapters/glib.h $(STLIBNAME)
	$(CC) -o examples/$@ $(REAL_CFLAGS) $(REAL_LDFLAGS) $(shell pkg-config --cflags --libs glib-2.0) -I. $< $(STLIBNAME)

hiredis-example-ivykis: examples/example-ivykis.c adapters/ivykis.h $(STLIBNAME)
	$(CC) -o examples/$@ $(REAL_CFLAGS) $(REAL_LDFLAGS) -I. $< -livykis $(STLIBNAME)

hiredis-example-macosx: examples/example-macosx.c adapters/macosx.h $(STLIBNAME)
	$(CC) -o examples/$@ $(REAL_CFLAGS) $(REAL_LDFLAGS) -I. $< -framework CoreFoundation $(STLIBNAME)

ifndef AE_DIR
hiredis-example-ae:
	@echo "Please specify AE_DIR (e.g. <redis repository>/src)"
	@false
else
hiredis-example-ae: examples/example-ae.c adapters/ae.h $(STLIBNAME)
	$(CC) -o examples/$@ $(REAL_CFLAGS) $(REAL_LDFLAGS) -I. -I$(AE_DIR) $< $(AE_DIR)/ae.o $(AE_DIR)/zmalloc.o $(AE_DIR)/../deps/jemalloc/lib/libjemalloc.a -pthread $(STLIBNAME)
endif

ifndef LIBUV_DIR
hiredis-example-libuv:
	@echo "Please specify LIBUV_DIR (e.g. ../libuv/)"
	@false
else
hiredis-example-libuv: examples/example-libuv.c adapters/libuv.h $(STLIBNAME)
	$(CC) -o examples/$@ $(REAL_CFLAGS) $(REAL_LDFLAGS) -I. -I$(LIBUV_DIR)/include $< $(LIBUV_DIR)/.libs/libuv.a -lpthread -lrt $(STLIBNAME)
endif

ifeq ($(and $(QT_MOC),$(QT_INCLUDE_DIR),$(QT_LIBRARY_DIR)),)
hiredis-example-qt:
	@echo "Please specify QT_MOC, QT_INCLUDE_DIR AND QT_LIBRARY_DIR"
	@false
else
hiredis-example-qt: examples/example-qt.cpp adapters/qt.h $(STLIBNAME)
	$(QT_MOC) adapters/qt.h -I. -I$(QT_INCLUDE_DIR) -I$(QT_INCLUDE_DIR)/QtCore | \
	    $(CXX) -x c++ -o qt-adapter-moc.o -c - $(REAL_CFLAGS) -I. -I$(QT_INCLUDE_DIR) -I$(QT_INCLUDE_DIR)/QtCore
	$(QT_MOC) examples/example-qt.h -I. -I$(QT_INCLUDE_DIR) -I$(QT_INCLUDE_DIR)/QtCore | \
	    $(CXX) -x c++ -o qt-example-moc.o -c - $(REAL_CFLAGS) -I. -I$(QT_INCLUDE_DIR) -I$(QT_INCLUDE_DIR)/QtCore
	$(CXX) -o examples/$@ $(REAL_CFLAGS) $(REAL_LDFLAGS) -I. -I$(QT_INCLUDE_DIR) -I$(QT_INCLUDE_DIR)/QtCore -L$(QT_LIBRARY_DIR) qt-adapter-moc.o qt-example-moc.o $< -pthread $(STLIBNAME) -lQtCore
endif

hiredis-example: examples/example.c $(STLIBNAME)
	$(CC) -o examples/$@ $(REAL_CFLAGS) $(REAL_LDFLAGS) -I. $< $(STLIBNAME)

hiredis-example-ssl: examples/example-ssl.c $(STLIBNAME) $(STLIBNAME_SSL)
	$(CC) -o examples/$@ $(REAL_CFLAGS) $(REAL_LDFLAGS) -I. $< $(STLIBNAME) $(STLIBNAME_SSL) -lssl -lcrypto

examples: $(EXAMPLES)

hiredis-test: test.o $(STLIBNAME)

hiredis-%: %.o $(STLIBNAME)
	$(CC) $(REAL_CFLAGS) -o $@ $(REAL_LDFLAGS) $< $(STLIBNAME)

test: hiredis-test
	./hiredis-test

check: hiredis-test
	@echo "$$REDIS_TEST_CONFIG" | $(REDIS_SERVER) -
	$(PRE) ./hiredis-test -h 127.0.0.1 -p $(REDIS_PORT) -s /tmp/hiredis-test-redis.sock || \
			( kill `cat /tmp/hiredis-test-redis.pid` && false )
	kill `cat /tmp/hiredis-test-redis.pid`

.c.o:
	$(CC) -std=c99 -pedantic -c $(REAL_CFLAGS) $<

clean:
	rm -rf $(DYLIBNAME) $(STLIBNAME) $(TESTS) $(PKGCONFNAME) examples/hiredis-example* *.o *.gcda *.gcno *.gcov $(SSL_TARGETS)

dep:
	$(CC) -MM *.c

ifeq ($(uname_S),SunOS)
  INSTALL?= cp -r
endif

INSTALL?= cp -a

$(PKGCONFNAME): hiredis.h
	@echo "Generating $@ for pkgconfig..."
	@echo prefix=$(PREFIX) > $@
	@echo exec_prefix=\$${prefix} >> $@
	@echo libdir=$(PREFIX)/$(LIBRARY_PATH) >> $@
	@echo includedir=$(PREFIX)/$(INCLUDE_PATH) >> $@
	@echo >> $@
	@echo Name: hiredis >> $@
	@echo Description: Minimalistic C client library for Redis. >> $@
	@echo Version: $(HIREDIS_MAJOR).$(HIREDIS_MINOR).$(HIREDIS_PATCH) >> $@
	@echo Libs: -L\$${libdir} -lhiredis >> $@
	@echo Cflags: -I\$${includedir} -D_FILE_OFFSET_BITS=64 >> $@

$(PKGCONFNAME_SSL): hiredis_ssl.h
	@echo "Generating $@ for pkgconfig..."
	@echo prefix=$(PREFIX) > $@
	@echo exec_prefix=\$${prefix} >> $@
	@echo libdir=$(PREFIX)/$(LIBRARY_PATH) >> $@
	@echo includedir=$(PREFIX)/$(INCLUDE_PATH) >> $@
	@echo >> $@
	@echo Name: hiredis_ssl >> $@
	@echo Description: SSL support for hiredis C client library. >> $@
	@echo Requires: hiredis >> $@
	@echo Version: $(HIREDIS_MAJOR).$(HIREDIS_MINOR).$(HIREDIS_PATCH) >> $@
	@echo Libs: -L\$${libdir} -lhiredis_ssl >> $@
	@echo Libs.private: lssl -lcrypto >> $@
	@echo Cflags: -I\$${includedir} -D_FILE_OFFSET_BITS=64 >> $@


install: $(DYLIBNAME) $(STLIBNAME) $(PKGCONFNAME) $(SSL_TARGETS)
	mkdir -p $(INSTALL_INCLUDE_PATH) $(INSTALL_LIBRARY_PATH)
	$(INSTALL) hiredis.h $(HIREDIS_SSL_HEADER) async.h read.h sds.h adapters $(INSTALL_INCLUDE_PATH)
	$(INSTALL) $(DYLIBNAME) $(INSTALL_LIBRARY_PATH)/$(DYLIB_MINOR_NAME)
	cd $(INSTALL_LIBRARY_PATH) && ln -sf $(DYLIB_MINOR_NAME) $(DYLIBNAME)
	$(INSTALL) $(STLIBNAME) $(INSTALL_LIBRARY_PATH)
	mkdir -p $(INSTALL_PKGCONF_PATH)
	$(INSTALL) $(PKGCONFNAME) $(INSTALL_PKGCONF_PATH)
ifneq ($(USE_SSL),)
	$(INSTALL) $(DYLIBNAME_SSL) $(INSTALL_LIBRARY_PATH)/$(DYLIB_MINOR_SSL_NAME)
	cd $(INSTALL_LIBRARY_PATH) && ln -sf $(DYLIB_MINOR_SSL_NAME) $(DYLIBNAME_SSL)
	$(INSTALL) $(STLIBNAME_SSL) $(INSTALL_LIBRARY_PATH)
	$(INSTALL) $(PKGCONFNAME_SSL) $(INSTALL_PKGCONF_PATH)
endif

32bit:
	@echo ""
	@echo "WARNING: if this fails under Linux you probably need to install libc6-dev-i386"
	@echo ""
	$(MAKE) CFLAGS="-m32" LDFLAGS="-m32"

32bit-vars:
	$(eval CFLAGS=-m32)
	$(eval LDFLAGS=-m32)

gprof:
	$(MAKE) CFLAGS="-pg" LDFLAGS="-pg"

gcov:
	$(MAKE) CFLAGS="-fprofile-arcs -ftest-coverage" LDFLAGS="-fprofile-arcs"

coverage: gcov
	make check
	mkdir -p tmp/lcov
	lcov -d . -c -o tmp/lcov/hiredis.info
	genhtml --legend -o tmp/lcov/report tmp/lcov/hiredis.info

noopt:
	$(MAKE) OPTIMIZATION=""

.PHONY: all test check clean dep install 32bit 32bit-vars gprof gcov noopt
