CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lpthread

MKDIR_P = mkdir -p
OUT_DIR = ../exe





all: directories main 


main: main.c main.h backdoor-client.o backdoor-server.o utils.o pktcap.o
	${CC} ${CFLAGS} main.c main.h backdoor-client.o backdoor-server.o utils.o pktcap.o ${LDFLAGS} -o ${OUT_DIR}/backdoor

backdoor-server.o : backdoor-server.c backdoor-server.h
	${CC} ${CFLAGS} -c backdoor-server.c
backdoor-client.o : backdoor-client.c backdoor-client.h
	${CC} ${CFLAGS} -c backdoor-client.c
utils.o :  utils.c utils.h
	${CC} ${CFLAGS} -c utils.c
pktcap.o: pktcap.h pktcap.c
	${CC} ${CFLAGS} -c pktcap.c
clean:
	rm -rf *.o *.c~ *.cpp~ *.h~ ${OUT_DIR}/backdoor
directories: ${OUT_DIR}
	${MKDIR_P} ${OUT_DIR}/

