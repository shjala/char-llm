CC = gcc
CFLAGS = -Wall -D_FILE_OFFSET_BITS=64 -Iinclude -std=c99
LIBS = $(shell pkg-config fuse3 --cflags --libs) -lcurl -pthread
TARGET = bin/llm
SOURCE = llm.c
BINDIR = bin

all: $(BINDIR) $(TARGET)

$(BINDIR):
	mkdir -p $(BINDIR)

# Build
$(TARGET): $(SOURCE) include/ioctl.h | $(BINDIR)
	$(CC) $(CFLAGS) $(SOURCE) $(LIBS) -o $(TARGET)

# Clean
clean:
	rm -f $(TARGET)
	rmdir $(BINDIR) 2>/dev/null || true

# Phony
.PHONY: all clean
