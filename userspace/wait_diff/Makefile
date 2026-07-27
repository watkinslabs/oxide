CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror -pthread
LDLIBS += -pthread -lrt

TARGET := wait_diff
OBJS := main.o common.o sleep.o locks.o fdwait.o jobctl.o cputime.o mqueue.o syslog.o

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c probe.h
	$(CC) $(CFLAGS) -c -o $@ $<

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(TARGET) $(OBJS)
