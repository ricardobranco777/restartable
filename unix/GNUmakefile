BIN	= restartable
CFLAGS	= -Wall -Wextra -O2
LDFLAGS	= -lkvm -lutil
OBJS	=

$(BIN): restartable.c $(OBJS)
	$(CC) $(CFLAGS) -o $@ $< $(OBJS) $(LDFLAGS)

clean:
	rm -f $(PROC) $(OBJS)
