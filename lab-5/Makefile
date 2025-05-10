obj-m := int_stack_usb.o

KDIR := /usr/lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

ccflags-y := -DDEFAULT_USB_VID=0x31B2 -DDEFAULT_USB_PID=0x5075

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
