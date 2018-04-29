#
# use gmake in FreeBSD

UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S), FreeBSD)
	CC=cc
	CPP=c++
else
	CC=gcc
	CPP=g++
endif

CFLAGS= -Wall -std=gnu99 -Wdeprecated-declarations
RELEASE= -O2

LIBS= -lc

SRCS := $(shell find src -name "*.c")
SRCS += $(shell find vendor/m_net/src -name "*.c")
SRCS += $(shell find vendor/m_foundation/src -name "*.c")

R_SRCS := $(SRCS)
R_SRCS += $(shell find vendor/m_dnscnt/src -name "*.c")

DIRS := $(shell find src -type d)
DIRS += $(shell find vendor/m_net/src -type d)
DIRS += $(shell find vendor/m_foundation/src -type d)

R_DIRS := $(DIRS)
R_DIRS += $(shell find vendor/m_dnscnt/src -type d)

INCS := $(foreach n, $(DIRS), -I$(n))
R_INCS := $(foreach n, $(R_DIRS), -I$(n))

all: debug

debug: $(SRCS) $(R_SRCS)
	$(CC) $(DEBUG) $(CFLAGS) $(INCS) -o tun_local.out $(SRCS) $(LIBS) -DTEST_TUNNEL_LOCAL
	$(CC) $(DEBUG) $(CFLAGS) $(R_INCS) -o tun_remote.out $(R_SRCS) $(LIBS) -DTEST_TUNNEL_REMOTE -DTEST_TUNNEL_DNS

release: $(SRCS) $(R_SRCS)
	$(CC) $(RELEASE) $(CFLAGS) $(INCS) -o tun_local.out $(SRCS) $(LIBS) -DTEST_TUNNEL_LOCAL
	$(CC) $(RELEASE) $(CFLAGS) $(R_INCS) -o tun_remote.out $(R_SRCS) $(LIBS) -DTEST_TUNNEL_REMOTE -DTEST_TUNNEL_DNS

clean:
	rm -rf *.out *.dSYM
