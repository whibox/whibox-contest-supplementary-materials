CFLAGS=-g
LDFLAGS=$(CFLAGS) -L/usr/local/lib
LDLIBS=-lgmp

ifeq ($(NO_SECCOMP),1)
CFLAGS += -DNO_SECCOMP
else
CFLAGS += -Wno-prio-ctor-dtor
LDLIBS += -lseccomp
endif

all: dECDSA

dECDSA.o: dECDSA.c

dECDSA: main.c dECDSA.o

clean:
	rm -f dECDSA.o dECDSA
