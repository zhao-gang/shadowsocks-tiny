CFLAGS += -g -Wall

.PHONY: all
all: sslocal sserver test

sslocal : client.c common.c crypto.c log.c
	$(CC) -o $@ $(CFLAGS) $^ -lcrypto

sserver : server.c common.c crypto.c log.c
	$(CC) -o $@ $(CFLAGS) $^ -lcrypto

test: test.c common.c crypto.c log.c
	$(CC) -o $@ $(CFLAGS) $^ -lcrypto

client.c: common.c crypto.c

common.c: common.h log.c

crypto.c: crypto.h common.c

log.c: log.h

server.c: common.c crypto.c

.PHONY: clean
clean:
	rm -rf *.o sserver sslocal test
