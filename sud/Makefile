CFLAGS := -O2 -Wall -Wextra
LDFLAGS := -llog

OBJS =
OBJS += $(sort $(patsubst %.c,%.o,$(wildcard *.c)))

.PHONY: all clean

all: su

clean:
	$(RM) $(OBJS) su

su: $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(EXTRA_LDFLAGS)

%.o: %.c
	$(CC) -o $@ $^ -c $(CFLAGS) $(EXTRA_CFLAGS)
