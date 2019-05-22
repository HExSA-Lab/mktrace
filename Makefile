obj-m += sf_sim.o

all: tracer
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

tracer:
	gcc -o tracer.o tracer.c

ins:
	sudo insmod sf_sim.ko

rm:
	sudo rmmod sf_sim
