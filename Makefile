CFLAGS += -g -Wall
LDFLAGS += -ljson-c -lcrypto

.PHONY: all
all: sslocal sserver test

sslocal : client.c common.o crypto.o log.o
	$(CC) -o $@ $(CFLAGS) $^ $(LDFLAGS) -ljson-c -lcrypto

sserver : server.c common.o crypto.o log.o
	$(CC) -o $@ $(CFLAGS) $^ $(LDFLAGS) -ljson-c -lcrypto

test: test.c common.o crypto.o log.o
	$(CC) -o $@ $(CFLAGS) $^ $(LDFLAGS) -ljson-c -lcrypto

common.o: common.h

crypto.o: crypto.h

log.o: log.h

.PHONY: clean
clean:
	rm -rf *.o sserver sslocal test
