CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -Wpedantic -Werror -O2 -D_GNU_SOURCE
LDFLAGS =
LIBS    =

SRCDIR  = src
INCDIR  = include
BUILDDIR = build
BINDIR  = bin

SRCS    = $(wildcard $(SRCDIR)/*.c)
OBJS    = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SRCS))
MAIN    = $(SRCDIR)/main.c
TARGET  = $(BINDIR)/syscage

TESTDIR = tests
TESTS   = $(wildcard $(TESTDIR)/*.c)
TEST_OBJS = $(patsubst $(TESTDIR)/%.c,$(BUILDDIR)/%.o,$(filter-out $(MAIN),$(SRCS)))
TEST_BINS = $(patsubst $(TESTDIR)/%.c,$(BUILDDIR)/%,$(TESTS))

.PHONY: all clean test install uninstall

all: $(TARGET)

$(TARGET): $(OBJS) | $(BINDIR)
	$(CC) $(CFLAGS) -I$(INCDIR) -o $@ $^ $(LDFLAGS) $(LIBS)

$(BUILDDIR)/%.o: $(SRCDIR)/%.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -I$(INCDIR) -c -o $@ $<

$(BINDIR):
	mkdir -p $(BINDIR)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

test: $(TEST_BINS)
	@for t in $(TEST_BINS); do \
		echo "Running $$t..."; \
		$$t && echo "PASS" || echo "FAIL"; \
	done

$(BUILDDIR)/test_%: $(TESTDIR)/test_%.c $(TEST_OBJS) | $(BUILDDIR)
	$(CC) $(CFLAGS) -I$(INCDIR) -o $@ $< $(TEST_OBJS) $(LDFLAGS) $(LIBS)

clean:
	rm -rf $(BUILDDIR) $(BINDIR) *.trace *.syscage

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/syscage

uninstall:
	rm -f /usr/local/bin/syscage
