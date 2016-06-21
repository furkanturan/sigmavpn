
Zybo =

ifeq ($(ZYBO),1)

# This part is for the modified Makefile of SigmaVPN code
# It does make for the Linux running on Zybo,
# It uses libsodium and libpcap from the cross complilation directories
# Those directories are ../libsodium_installdir and ../libpcap-1.7.4
# Commands reach this part: make ZYBO=1, make ZYBO=1 clean, make ZYBO=1 install

PWD		= $(shell pwd)

INSTALLDIR ?= $(PWD)/../BootFiles/sigmavpn/sigmavpn_installdir
BINDIR ?= $(INSTALLDIR)/bin
SYSCONFDIR ?= $(INSTALLDIR)/etc
LIBEXECDIR ?= $(INSTALLDIR)/lib/sigmavpn

SODIUM_INSTALLDIR ?= $(PWD)/../sigmavpn_deps/libsodium_installdir
SODIUM_CPPFLAGS ?= -I$(SODIUM_INSTALLDIR)/include
SODIUM_LDFLAGS ?= -Wl,-static -L$(SODIUM_INSTALLDIR)/lib -lsodium -Wl,-Bdynamic

LIBPCAP_PATH ?= $(PWD)/../sigmavpn_deps/libpcap-1.7.4
LIBPCAP_CPPFLAGS ?= -I$(LIBPCAP_PATH)
LIBPCAP_LDFLAGS ?= -L$(LIBPCAP_PATH) -lpcap

CC = arm-xilinx-linux-gnueabi-gcc
CFLAGS ?= -g3 -O2 -fPIC -Wall -Wextra -lc
CPPFLAGS += -g3 -O2 $(SODIUM_CPPFLAGS)
LDFLAGS += $(SODIUM_LDFLAGS) -ldl -pthread
DYLIB_CFLAGS ?= $(CFLAGS) -shared

TARGETS_OBJS = dep/ini.o main.o modules.o naclkeypair.o pack.o tai.o 
TARGETS_BIN = naclkeypair sigmavpn
TARGETS_MODULES = proto/proto_hwtai.o \
    proto/proto_raw.o proto/proto_nacl0.o proto/proto_nacltai.o \
    intf/intf_tuntap.o intf/intf_private.o intf/intf_udp.o

TARGETS = $(TARGETS_OBJS) $(TARGETS_BIN) $(TARGETS_MODULES)

all: $(TARGETS)

clean:
	rm -f $(TARGETS)

distclean: clean

install: all
	mkdir -p $(BINDIR) $(SYSCONFDIR) $(LIBEXECDIR)
	cp $(TARGETS_BIN) $(BINDIR)
	cp $(TARGETS_MODULES) $(LIBEXECDIR)

proto/proto_hwtai.o: proto/proto_hwnacltai.c pack.o tai.o
	$(CC) $(CPPFLAGS) $(SODIUM_CPPFLAGS) proto/proto_hwnacltai.c pack.o tai.o \
    -o proto/proto_hwtai.o $(DYLIB_CFLAGS) $(SODIUM_LDFLAGS)

proto/proto_raw.o: proto/proto_raw.c
	$(CC) $(CPPFLAGS) $(SODIUM_CPPFLAGS) proto/proto_raw.c -o \
		proto/proto_raw.o $(DYLIB_CFLAGS) $(SODIUM_LDFLAGS)

proto/proto_nacl0.o: proto/proto_nacl0.c pack.o
	$(CC) $(CPPFLAGS) $(SODIUM_CPPFLAGS) proto/proto_nacl0.c pack.o -o \
		proto/proto_nacl0.o $(DYLIB_CFLAGS) $(SODIUM_LDFLAGS)

proto/proto_nacltai.o: proto/proto_nacltai.c pack.o tai.o
	$(CC) $(CPPFLAGS) $(SODIUM_CPPFLAGS) proto/proto_nacltai.c pack.o tai.o -o \
	 	proto/proto_nacltai.o $(DYLIB_CFLAGS) $(SODIUM_LDFLAGS)

intf/intf_tuntap.o: intf/intf_tuntap.c
	$(CC) $(CPPFLAGS) intf/intf_tuntap.c -o intf/intf_tuntap.o $(DYLIB_CFLAGS)

intf/intf_private.o: intf/intf_private.c
	$(CC) $(CPPFLAGS) $(LIBPCAP_CPPFLAGS) intf/intf_private.c -o \
		intf/intf_private.o $(LIBPCAP_LDFLAGS) $(DYLIB_CFLAGS)

intf/intf_udp.o: intf/intf_udp.c
	$(CC) $(CPPFLAGS) intf/intf_udp.c -o intf/intf_udp.o $(DYLIB_CFLAGS)

naclkeypair: naclkeypair.o
	$(CC) -static -o naclkeypair naclkeypair.o $(LDFLAGS)

sigmavpn: main.o modules.o dep/ini.o
	$(CC) -o sigmavpn main.o modules.o dep/ini.o $(LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

else

# This part is for the original Makefile of SigmaVPN code
# It does make for the PC, with installed PCAP and libsodium libraries
# Regular commands reach to this part: make, make clean, make install

INSTALLDIR ?= /usr/local
BINDIR ?= $(INSTALLDIR)/bin
SYSCONFDIR ?= $(INSTALLDIR)/etc
LIBEXECDIR ?= $(INSTALLDIR)/lib/sigmavpn

SODIUM_CPPFLAGS ?= -I/usr/local/include
SODIUM_LDFLAGS ?= -L/usr/local/lib -lsodium
CFLAGS ?= -g3 -O2 -fPIC -Wall -Wextra
CPPFLAGS += -g3 -O2 $(SODIUM_CPPFLAGS)
LDFLAGS += $(SODIUM_LDFLAGS) -ldl -pthread
DYLIB_CFLAGS ?= $(CFLAGS) -shared

TARGETS_OBJS = dep/ini.o main.o modules.o naclkeypair.o pack.o tai.o
TARGETS_BIN = naclkeypair sigmavpn
TARGETS_MODULES = proto/proto_raw.o proto/proto_nacl0.o proto/proto_nacltai.o \
	intf/intf_tuntap.o intf/intf_udp.o 
    #intf/intf_private.o

CC = gcc

TARGETS = $(TARGETS_OBJS) $(TARGETS_BIN) $(TARGETS_MODULES)

all: $(TARGETS)

clean:
	rm -f $(TARGETS)

distclean: clean

install: all
	mkdir -p $(BINDIR) $(SYSCONFDIR) $(LIBEXECDIR)
	cp $(TARGETS_BIN) $(BINDIR)
	cp $(TARGETS_MODULES) $(LIBEXECDIR)

proto/proto_raw.o: proto/proto_raw.c
	$(CC) $(CPPFLAGS) $(SODIUM_CPPFLAGS) proto/proto_raw.c -o \
		proto/proto_raw.o $(DYLIB_CFLAGS) $(SODIUM_LDFLAGS)

proto/proto_nacl0.o: proto/proto_nacl0.c pack.o
	$(CC) $(CPPFLAGS) $(SODIUM_CPPFLAGS) proto/proto_nacl0.c pack.o -o \
		proto/proto_nacl0.o $(DYLIB_CFLAGS) $(SODIUM_LDFLAGS)

proto/proto_nacltai.o: proto/proto_nacltai.c pack.o tai.o
	$(CC) $(CPPFLAGS) $(SODIUM_CPPFLAGS) proto/proto_nacltai.c pack.o tai.o -o \
		proto/proto_nacltai.o $(DYLIB_CFLAGS) $(SODIUM_LDFLAGS)

intf/intf_tuntap.o: intf/intf_tuntap.c
	$(CC) $(CPPFLAGS) intf/intf_tuntap.c -o \
		intf/intf_tuntap.o $(DYLIB_CFLAGS)

# intf/intf_private.o: intf/intf_private.c
# 	$(CC) $(CPPFLAGS) intf/intf_private.c -o \
# 		intf/intf_private.o -lpcap $(DYLIB_CFLAGS)

intf/intf_udp.o: intf/intf_udp.c
	$(CC) $(CPPFLAGS) intf/intf_udp.c -o intf/intf_udp.o $(DYLIB_CFLAGS)

naclkeypair: naclkeypair.o
	$(CC) -o naclkeypair naclkeypair.o $(LDFLAGS)

sigmavpn: main.o modules.o dep/ini.o
	$(CC) -o sigmavpn main.o modules.o dep/ini.o $(LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

endif
