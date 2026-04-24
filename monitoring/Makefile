.DELETE_ON_ERROR:

CLANG ?= clang
BPFTOOL ?= bpftool

ifeq ($(shell command -v $(CLANG) 2>/dev/null),)
$(error clang not found in PATH)
endif

ifeq ($(shell command -v $(BPFTOOL) 2>/dev/null),)
$(error bpftool not found in PATH)
endif

load: monitor
	./monitor load

unload: monitor
	./monitor unload

monitor: monitor.c syscall_monitor.h syscall_monitor.skel.h
	$(CLANG) monitor.c -g -Wall -Werror -fsanitize=undefined,address -lbpf -lelf -o $@

syscall_monitor.bpf.o: syscall_monitor.bpf.c utils.h vmlinux.h
	$(CLANG) -O2 -Wall -Werror -g -target bpf -D__TARGET_ARCH_x86 -c $< -o $@

syscall_monitor.skel.h: syscall_monitor.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

vmlinux.h: /sys/kernel/btf/vmlinux
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	rm -rf *.o syscall_monitor.skel.h vmlinux.h monitor

.PHONY: clean load unload
