CC = gcc
BIN = restartable
CFLAGS = -Wall -O2
LDFLAGS = -lproc

$(BIN): restartable.c
	$(CC) -o $@ $(CFLAGS) restartable.c $(LDFLAGS)

clean:
	@rm -f $(BIN)
