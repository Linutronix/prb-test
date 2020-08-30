BDIR ?= /lib/modules/`uname -r`/build

ifeq ($(KERNELRELEASE),)
# called from shell

.PHONY: default clean

default:
	make -C $(BDIR) M=$(shell pwd) modules

clean:
	rm -rf prb.* *.o *.mod.* .*cmd* Module.symvers modules.order .tmp_versions

else
# called from kernel Makefile

prb-y := test_prb.o printk_ringbuffer.o
obj-m := prb.o
endif
