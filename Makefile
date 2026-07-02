LDFLAGS = -shared

VERSION_MAJOR=1
VERSION_MINOR=0
ARCH ?= $(shell uname -m)
OS  ?= $(shell uname -s | tr A-Z a-z)

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

TARGET = libperunione_$(OS)_$(ARCH)_$(VERSION_MAJOR).$(VERSION_MINOR).so
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

MESSENGER_DIR = libperunione_messenger_src_fortest
MESSENGER_SRCS = $(MESSENGER_DIR)/main.c $(MESSENGER_DIR)/net_transport.c
MESSENGER_BIN  = messenger

TEST_SRC  = test_libperunione.c
TEST_BIN  = test_libperunione

.PHONY: all clean messenger test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^
	@echo "$(TARGET) compiled"

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

-include $(DEPS)

messenger: $(TARGET)
	$(CC) -Wall -Wextra -O2 -Isrc -o $(MESSENGER_BIN) $(MESSENGER_SRCS) \
		-L. -l:$(TARGET) -Wl,-rpath,'$$ORIGIN'
	@echo "messenger compiled"

test: $(TARGET)
	$(CC) -Wall -Wextra -g -O0 -Isrc -mrdrnd -o $(TEST_BIN) $(TEST_SRC) $(SRCS)
	@echo "$(TEST_BIN) compiled"

test_run: test
	./$(TEST_BIN)

clean:
	rm -rf $(OBJ_DIR) $(TARGET) $(MESSENGER_BIN) $(TEST_BIN)
