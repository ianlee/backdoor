CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lpthread
all: main
client: main_client
main: main.c main.h communication.o cleanup.o doorman.o exec.o
	${CC} ${CFLAGS} main.c main.h communication.o cleanup.o doorman.o exec.o ${LDFLAGS} -o ../exe/backdoor
communication.o : communication.c communication.h
	${CC} ${CFLAGS} -c communication.c
cleanup.o : cleanup.c cleanup.h
	${CC} ${CFLAGS} -c cleanup.c
doorman.o : doorman.c doorman.h
	${CC} ${CFLAGS} -c doorman.c
exec.o :  exec.c exec.h
	${CC} ${CFLAGS} -c exec.c
clean:
	rm -rf *.o *.c~ *.cpp~ *.h~ ../exe/backdoor
