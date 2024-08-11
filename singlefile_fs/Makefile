obj-m += singlefilefs.o
singlefilefs-objs += singlefilefs_src.o file.o dir.o

all:
	gcc singlefilemakefs.c -o singlefilemakefs
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules 

load-FS-driver:
	sudo insmod singlefilefs.ko	

create-fs:
	dd bs=4096 count=100 if=/dev/zero of=image
	./singlefilemakefs image
	sudo mkdir -p /opt/mount
        
mount-fs:
	sudo mount -o loop -t singlefilefs image /opt/mount/

umount-fs:
	sudo umount /opt/mount/

delete-fs:
	sudo rmdir /opt/mount
	rm image

unload-FS-driver:
	sudo rmmod singlefilefs

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
	rm singlefilemakefs
