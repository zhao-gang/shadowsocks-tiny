CFLAGS += -g -Wall

.PHONY: all
all: sslocal sserver test

sslocal : client.c common.o crypto.o log.o
	$(CC) -o $@ $(CFLAGS) $^ -lcrypto

sserver : server.c common.o crypto.o log.o
	$(CC) -o $@ $(CFLAGS) $^ -lcrypto

test: test.c common.o crypto.o log.o
	$(CC) -o $@ $(CFLAGS) $^ -lcrypto

common.o: common.h

crypto.o: crypto.h

log.o: log.h

.PHONY: clean
clean:
	rm -rf *.o sserver sslocal test
