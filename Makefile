CC = cc
CFLAGS = -Wall -Wextra -std=c11 -Os
LDFLAGS =

SOURCES = sha256.c validation.c
OBJECTS = $(SOURCES:.c=.o)
TARGET = validate

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c sha256.h
	$(CC) $(CFLAGS) -c -o $@ $<

test: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(OBJECTS) $(TARGET)

rebuild: clean all

.PHONY: all test clean rebuild
