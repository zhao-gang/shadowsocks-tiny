CFLAGS += -g -Wall

.PHONY: all
all: sslocal sserver test ssredirect

sslocal : client.c common.o crypto.o log.o
	$(CC) -o $@ $(CFLAGS) $^ $(LDFLAGS) -lcrypto

sserver : server.c common.o crypto.o log.o
	$(CC) -o $@ $(CFLAGS) $^ $(LDFLAGS) -lcrypto

test: test.c common.o crypto.o log.o
	$(CC) -o $@ $(CFLAGS) $^ $(LDFLAGS) -lcrypto

ssredirect: client-redirect.c common.o crypto.o log.o
	$(CC) -o $@ $(CFLAGS) $^ $(LDFLAGS) -lcrypto

common.o: common.h

crypto.o: crypto.h

log.o: log.h

.PHONY: clean
clean:
	rm -rf *.o sserver sslocal test ssredirect
