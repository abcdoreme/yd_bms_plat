
EXEC = bms
SOURCES = $(wildcard *.c)
EXEC_SOURCES = $(filter-out $(LOGSRV_SRC), $(SOURCES))
OBJS = $(EXEC_SOURCES:.c=.o)

#CFLAGS += -Wall
CFLAGS += -Ilibevent -Ilibevent/include -Ilibevent/build/include -I/usr/include
LDFLAGS+= -lm -lmysqlclient

CC = gcc

all: $(EXEC)


$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) libevent/build/lib/libevent.a $(LDFLAGS)

clean:
	-rm -rf $(EXEC) *.o
