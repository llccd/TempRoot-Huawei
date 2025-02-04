CFLAGS := -O2 -Wall -Wextra

.PHONY: all clean

all: patch_system poc

clean:
	$(RM) patch_system poc

poc: poc.c
	$(CC) -o $@ $^ $(CFLAGS) $(EXTRA_CFLAGS)

patch_system: patch_system.c
	$(CC) -o $@ $^ $(CFLAGS) $(EXTRA_CFLAGS)
