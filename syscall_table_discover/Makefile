obj-m += the_usctm.o
the_usctm-objs += usctm.o ./lib/vtpmo.o

all_install:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) EXTRA_CFLAGS+=-DSYS_CALL_INSTALL modules

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) EXTRA_CFLAGS+=-DFLAG modules 

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

mount:
	insmod the_usctm.ko

unmount:
	rmmod the_usctm
