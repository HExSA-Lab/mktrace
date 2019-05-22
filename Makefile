CC:=gcc
MCFLAGS:= -Wall -O2

obj-m+=mktraced.o

all: mktraced.ko mktrace

mktrace: mktrace.c
	$(CC) $(MCFLAGS) -o $@ $<

mktraced.ko: mktraced.c
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

ins: mktraced.ko
	@sudo insmod mktraced.ko

rm:
	@sudo rmmod mktraced

install:
	@sudo cp mktrace /usr/bin/

clean:
	@rm -f *.o *.ko mktrace
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

.PHONY: clean ins rm install
