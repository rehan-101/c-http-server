CC      = gcc
CFLAGS  = -Wall -Wextra -g -fsanitize=address
LDFLAGS = -lcjson -lsqlite3 -lcrypto -ljwt -pthread

SRC_DIR = src
INC_DIR = include
BIN     = myServer

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(SRCS:.c=.o)

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -I$(INC_DIR) -c $< -o $@

clean:
	rm -f $(OBJS) $(BIN)

run:
	./$(BIN)

.PHONY: all clean run
