# src/causal_guardian/Makefile
CFLAGS  = -Wall -O2 -I../ebpf
LDLIBS  = -lbpf -lssl -lcrypto

.PHONY: all clean

all: causal-guardian

causal-guardian: main.c ../ebpf/causal_chain.h
	gcc $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f causal-guardian
