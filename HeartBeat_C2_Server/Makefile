# Makefile for compiling HeartBeat_Server

CC = gcc
CFLAGS = -Wall -g  # Optional flags for warnings and debugging
TARGET = HeartBeat_Server
SRC = HeartBeat_Server.c
CUSTOM_HEADER = c2_modules.c

# Default target to build the program
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) $(CUSTOM_HEADER) -o $(TARGET)

# Clean target to remove compiled files
clean:
	rm -f $(TARGET)

.PHONY: all clean
