KERNEL_PATH ?= /lib/modules/$(shell uname -r)/build

obj-m += bitx.o

# Отключаем построение зависимостей ядра
CONFIG_MODULE_SIG=n
CONFIG_SYSTEM_TRUSTED_KEYS=""

all:
	$(MAKE) -C $(KERNEL_PATH) M=$(PWD) modules -j$(shell nproc)

clean:
	$(MAKE) -C $(KERNEL_PATH) M=$(PWD) clean

# Только сборка модуля без лишнего
quick:
	$(MAKE) -C $(KERNEL_PATH) M=$(PWD) modules-prepare
	$(MAKE) -C $(KERNEL_PATH) M=$(PWD) modules
