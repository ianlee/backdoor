CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lpthread -lpcap

MKDIR_P = mkdir -p
OUT_DIR = ../exe

# all: directories main
all: directories server client

server: backdoor-server.o utils.o pktcap.o isaac_encryption.o
	${CC} ${LDFLAGS} backdoor-server.o utils.o pktcap.o isaac_encryption.o -o ${OUT_DIR}/server

client: backdoor-client.o utils.o pktcap.o isaac_encryption.o
	${CC} ${LDFLAGS} backdoor-client.o utils.o pktcap.o isaac_encryption.o -o ${OUT_DIR}/client

backdoor-server.o: backdoor-server.c backdoor-server.h pktcap.h utils.h 
	${CC} ${CFLAGS} -c backdoor-server.c

backdoor-client.o: backdoor-client.c backdoor-client.h pktcap.h utils.h
	${CC} ${CFLAGS} -c backdoor-client.c

utils.o:  utils.c utils.h
	${CC} ${CFLAGS} -c utils.c

pktcap.o: pktcap.h pktcap.c
	${CC} ${CFLAGS} -c pktcap.c

isaac_encryption.o: lib/isaac_encryption.c lib/isaac_encryption.h
	${CC} ${CFLAGS} -c lib/isaac_encryption.c

clean:
	rm -rf *.o *.c~ *.cpp~ *.h~ ${OUT_DIR}/server ${OUT_DIR}/client

directories: 
	${MKDIR_P} ${OUT_DIR}/