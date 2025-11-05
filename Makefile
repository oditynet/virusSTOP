KERNEL_PATH ?= /lib/modules/$(shell uname -r)/build

# Имя модуля - bitx
obj-m += bitx.o

all:
	make -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean

install:
	sudo insmod bitx.ko

uninstall:
	sudo rmmod bitx

