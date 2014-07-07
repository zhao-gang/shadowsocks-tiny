CFLAGS += -g -Wall

.PHONY: all
all: sslocal sserver

sslocal : client.c common.o crypto.o log.o
	$(CC) -o $@ $(CFLAGS) $^ $(LDFLAGS) -lcrypto

sserver : server.c common.o crypto.o log.o
	$(CC) -o $@ $(CFLAGS) $^ $(LDFLAGS) -lcrypto

common.o: common.h

crypto.o: crypto.h

log.o: log.h

.PHONY: clean
clean:
	rm -rf *.o sserver sslocal
