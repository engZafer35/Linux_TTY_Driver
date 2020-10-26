obj-m := ztty_basic.o
KVERSION := $(shell uname -r)
CFLAGS_ztty_basic.o := -DDEBUG

all: ztty_basic.c
	$(MAKE) -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
clean:
	$(MAKE) -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
