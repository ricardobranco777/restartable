BIN	= restartable
CFLAGS	= -Wall -Wextra -O2
LDFLAGS	= -lkvm -lutil
OBJS	=

CC	= gcc

$(BIN): restartable.c $(OBJS)
	$(CC) $(CFLAGS) -o $@ -c $< $(OBJS) $(LDFLAGS)

clean:
	rm -f $(PROC) $(OBJS)
