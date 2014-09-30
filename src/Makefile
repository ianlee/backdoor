CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lpthread

MKDIR_P = mkdir -p
OUT_DIR = ../exe





all: directories main 


main: main.c main.h communication.o cleanup.o doorman.o exec.o
	${CC} ${CFLAGS} main.c main.h communication.o cleanup.o doorman.o exec.o ${LDFLAGS} -o ${OUT_DIR}/backdoor
communication.o : communication.c communication.h
	${CC} ${CFLAGS} -c communication.c
cleanup.o : cleanup.c cleanup.h
	${CC} ${CFLAGS} -c cleanup.c
doorman.o : doorman.c doorman.h
	${CC} ${CFLAGS} -c doorman.c
exec.o :  exec.c exec.h
	${CC} ${CFLAGS} -c exec.c
clean:
	rm -rf *.o *.c~ *.cpp~ *.h~ ${OUT_DIR}/backdoor
directories: ${OUT_DIR}
	${MKDIR_P} ${OUT_DIR}/

