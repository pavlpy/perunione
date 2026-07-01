LDFLAGS = -shared

VERSION_MAJOR=1
VERSION_MINOR=0
ARCH ?= $(shell uname -m)

DT_CFLAGS =
CC = gcc

ifeq ($(ARCH),x86_64)
    CC = gcc
    DT_CFLAGS = -m64 -march=x86-64
endif

ifeq ($(ARCH),i686)
    CC = gcc
    DT_CFLAGS = -m32 -march=i686
endif

ifeq ($(ARCH),arm64)
    CC = aarch64-linux-gnu-gcc
    DT_CFLAGS = -march=armv8-a
endif

CFLAGS = -Wall -Wextra -O2 -Isrc -MMD -MP -mrdrnd -fPIC -fvisibility=hidden $(DT_CFLAGS)

TARGET = libperunione_$(ARCH)_$(VERSION_MAJOR).$(VERSION_MINOR).so
OBJ_DIR = obj
SRC_DIR = src

SRCS = $(SRC_DIR)/decoencoder.c \
       $(SRC_DIR)/ellyptic.c \
       $(SRC_DIR)/ext_intr.c \
       $(SRC_DIR)/proto_logic.c

OBJS = $(OBJ_DIR)/decoencoder.o \
       $(OBJ_DIR)/ellyptic.o \
       $(OBJ_DIR)/ext_intr.o \
       $(OBJ_DIR)/proto_logic.o

DEPS = $(OBJS:.o=.d)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^
	@echo "$(TARGET) compiled"


$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

-include $(DEPS)

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

.PHONY: all clean
