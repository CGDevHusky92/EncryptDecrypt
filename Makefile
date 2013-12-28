.SUFFIXES: .c .o
ASSIGNMENT=fge.d
CC=gcc
EXEC=fge
CFLAGS= -Wall -g -lcrypto
OBJS=$(SRC:.c=.o)
SRC=fge.c
VAL=valgrind
VALFLAGS=-v --track-origins=yes --leak-check=full
ARGS=/home/campus24/crgorect/ 1

all: $(SRC) $(EXEC)
	
$(EXEC): $(OBJS) 
	$(CC) $(CFLAGS) $(OBJS) -o $@

test:
	clear
	make
	$(VAL) $(VALFLAGS) ./$(EXEC) $(ARGS)

clean:
	rm -f ./*~
	rm -f ./$(EXEC) 

prepare:
	rm -f ./$(ASSIGNMENT).tgz
	gtar -zcvf $(ASSIGNMENT).tgz Makefile README $(SRC)

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@