KERNEL_PATH ?= /lib/modules/$(shell uname -r)/build

obj-m += bitx.o

# Отключаем построение зависимостей ядра
CONFIG_MODULE_SIG=n
CONFIG_SYSTEM_TRUSTED_KEYS=""

all:
	$(MAKE) -C $(KERNEL_PATH) M=$(PWD) modules -j$(shell nproc)
	sudo cp bitx.ko /lib/modules/$(shell uname -r)/kernel/drivers/misc/bitx.ko
    sudo depmod -a
	sudo insmod bitx.ko trusted_processes="pacman,yay,make"

clean:
	$(MAKE) -C $(KERNEL_PATH) M=$(PWD) clean

# Только сборка модуля без лишнего
quick:
	$(MAKE) -C $(KERNEL_PATH) M=$(PWD) modules-prepare
	$(MAKE) -C $(KERNEL_PATH) M=$(PWD) modules
