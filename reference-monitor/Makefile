
obj-m += the_reference_monitor.o
the_reference_monitor-objs += reference_monitor.o lib/scth.o ../utils/utils.o

sys_call_table_address = $(shell cat /sys/module/the_usctm/parameters/sys_call_table_address)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

mount:
	insmod the_reference_monitor.ko syscall_table_addr=$(sys_call_table_address) passwd=$(passwd)

unmount:
	rmmod the_reference_monitor
