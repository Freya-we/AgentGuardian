# src/ebpf/Makefile
CC      = clang
CFLAGS  = -g -O2 -target bpf -D__TARGET_ARCH_x86
INCLUDES = -I. -I/usr/include/x86_64-linux-gnu

.PHONY: all clean

all: loader

# Step 1: 编译 BPF 目标文件
execve_monitor.bpf.o: execve_monitor.bpf.c causal_chain.h
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Step 2: 生成 skeleton 头文件
execve_monitor.skel.h: execve_monitor.bpf.o
	bpftool gen skeleton $< > $@

# Step 3: 编译用户态加载器
loader: loader.c execve_monitor.skel.h
	gcc -Wall -O2 -o loader loader.c -lbpf -lelf -lz -lssl -lcrypto

clean:
	rm -f *.o *.skel.h loader
