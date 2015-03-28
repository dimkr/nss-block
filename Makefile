CC ?= cc
CFLAGS ?= -O2 -fPIC
LDFLAGS ?=
DESTDIR ?= /
LIB_DIR ?= lib
DOC_DIR ?= usr/share/doc/nss-block

CFLAGS += -Wall -pedantic -pthread
LDFLAGS += -shared -pthread

SRCS = $(wildcard *.c)
OBJECTS = $(SRCS:.c=.o)
HEADERS = $(wildcard *.h)

%.o: %.c $(HEADERS)
	$(CC) -c -o $@ $< $(CFLAGS)

libnss_block.so.2: $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f libnss_block.so.2 $(OBJECTS)

install: libnss_block.so.2
	install -D -m 644 libnss_block.so.2 $(DESTDIR)/$(LIB_DIR)/libnss_block.so.2
	install -D -m 644 README $(DESTDIR)/$(DOC_DIR)/README
	install -m 644 AUTHORS $(DESTDIR)/$(DOC_DIR)/AUTHORS
	install -m 644 COPYING $(DESTDIR)/$(DOC_DIR)/COPYING
