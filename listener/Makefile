# Makefile — marvell-proto-fuzzer mock listener
#
# Targets:
#   make safe      → SAFE_MODE=1, AddressSanitizer enabled
#   make unsafe    → SAFE_MODE=0, no sanitizer (simulates vulnerable device)
#   make all       → both safe and unsafe
#   make clean     → remove build artifacts

CC       := gcc
CFLAGS   := -Wall -Wextra -std=c11 -g
ASAN     := -fsanitize=address -fno-omit-frame-pointer
SRCS     := mock_listener.c packet_parser.c
HEADERS  := packet_parser.h

SAFE_BIN   := listener_safe
UNSAFE_BIN := listener_unsafe

.PHONY: all safe unsafe clean

all: safe unsafe

safe: $(SRCS) $(HEADERS)
	$(CC) $(CFLAGS) $(ASAN) -DSAFE_MODE=1 -o $(SAFE_BIN) $(SRCS)
	@echo "[✓] Built $(SAFE_BIN) with SAFE_MODE=1 and AddressSanitizer"

unsafe: $(SRCS) $(HEADERS)
	$(CC) $(CFLAGS) -DSAFE_MODE=0 -o $(UNSAFE_BIN) $(SRCS)
	@echo "[✓] Built $(UNSAFE_BIN) with SAFE_MODE=0 (no sanitizer — may crash!)"

clean:
	rm -f $(SAFE_BIN) $(UNSAFE_BIN) *.o listener.log listener_crashes.log
	@echo "[✓] Cleaned build artifacts"
