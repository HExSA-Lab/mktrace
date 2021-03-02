CC:=gcc
MCFLAGS:= -Wall -O2

obj-m+=mktraced.o

mktraced-objs := src/device.o src/syscall_tbl.o src/worker.o src/new_syscalls.o src/mktrace_main.o

all: mktraced.ko mktrace

mktrace: src/mktrace.c
	$(CC) $(MCFLAGS) -o $@ $<

mktraced.ko: 
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

ins: mktraced.ko
	@sudo insmod mktraced.ko

rm:
	@sudo rmmod mktraced

install:
	@sudo cp mktrace /usr/bin/

clean:
	@rm -f src/*.o *.ko mktrace
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

.PHONY: clean ins rm install
