# Build the Izenpe Tarjeta Virtual PKCS#11 module.
#
# Needs a C compiler. On the host:  sudo apt install build-essential
# The vendored pkcs11.h (from p11-kit, g10 Code) means no -dev headers are required.

CC      ?= cc
CFLAGS  ?= -O2 -g -Wall -Wextra -fPIC -std=c11 -Iinclude
LDFLAGS ?= -shared -pthread
TARGET  ?= libizenpe-pkcs11.so

$(TARGET): izenpe_pkcs11.c include/pkcs11.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ izenpe_pkcs11.c
	# minimize exported symbols would be nicer; keep simple for now

.PHONY: clean
clean:
	rm -f $(TARGET)
