# Makefile for compiling HeartBeat_Server
# add -Wall to cflags to view all warnings
CC = gcc
CFLAGS =  -g # Optional flags for warnings and debugging
TARGET = HeartBeat_Server
SRC = HeartBeat_Server.c
CUSTOM_HEADER = c2_modules.c

# Default target to build the program
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) $(CUSTOM_HEADER) -o $(TARGET)

#Rebuild target
rebuild: clean all 

# Clean target to remove compiled files
clean:
	rm -f $(TARGET)

.PHONY: all rebuild clean
