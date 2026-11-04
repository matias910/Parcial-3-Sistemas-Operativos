# mmapguard - Makefile (out-of-tree module). Uso: make | make load | make test ...
KDIR  ?= /lib/modules/$(shell uname -r)/build
SRC   := $(CURDIR)/src
PROT  ?= /tmp/mg_test/secret.txt

.PHONY: all clean load unload reload test bench status

all:
	$(MAKE) -C $(KDIR) M=$(SRC) modules

clean:
	$(MAKE) -C $(KDIR) M=$(SRC) clean
	rm -f tests/bench_mmap

load: all
	sudo insmod $(SRC)/mmapguard.ko protected=$(PROT)

unload:
	-sudo rmmod mmapguard

reload: unload load

status:
	@cat /proc/mmapguard

test: all
	sudo ./tests/run_tests.sh

bench: all
	sudo ./tests/bench.sh
