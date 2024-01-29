obj-m += loxilb-csum-kprobe.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

mod-install:
	@cp -f loxilb-csum-kprobe.ko /usr/lib/modules/`uname -r`/kernel/net/core/
	@cp -f loxilb-csum-kprobe.conf /etc/modules-load.d/
	@depmod
	@modprobe loxilb-csum-kprobe

mod-uninstall:
	@rm -f /etc/modules-load.d/loxilb-csum-kprobe.conf
	@rm -f /usr/lib/modules/`uname -r`/kernel/net/core/loxilb-csum-kprobe.ko
	@rmmod loxilb-csum-kprobe
