CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -Wpedantic -Werror -O2 -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
LDFLAGS = -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack
LIBS    =

SRCDIR  = src
INCDIR  = include
BUILDDIR = build
BINDIR  = bin
PREFIX  ?= /usr/local
MANDIR  ?= $(PREFIX)/share/man/man1

SRCS    = $(wildcard $(SRCDIR)/*.c)
OBJS    = $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SRCS))
MAIN    = $(SRCDIR)/main.c
TARGET  = $(BINDIR)/syscage

TESTDIR = tests
TESTS   = $(wildcard $(TESTDIR)/*.c)
TEST_OBJS = $(patsubst $(TESTDIR)/%.c,$(BUILDDIR)/%.o,$(filter-out $(MAIN),$(SRCS)))
TEST_BINS = $(patsubst $(TESTDIR)/%.c,$(BUILDDIR)/%,$(TESTS))

.PHONY: all clean test install install-man uninstall

all: $(TARGET)

$(TARGET): $(OBJS) | $(BINDIR)
	@$(CC) $(CFLAGS) -I$(INCDIR) -o $@ $^ $(LDFLAGS) $(LIBS)
	@strip $@
	@echo "✅ Build successful."

$(BUILDDIR)/%.o: $(SRCDIR)/%.c | $(BUILDDIR)
	@$(CC) $(CFLAGS) -I$(INCDIR) -c -o $@ $<

$(BINDIR):
	@mkdir -p $(BINDIR)

$(BUILDDIR):
	@mkdir -p $(BUILDDIR)

test: $(TEST_BINS)
	@for t in $(TEST_BINS); do \
		echo "🧪 Running $$t..."; \
		$$t && echo "  PASS" || echo "  FAIL"; \
	done

$(BUILDDIR)/test_%: $(TESTDIR)/test_%.c $(TEST_OBJS) | $(BUILDDIR)
	@$(CC) $(CFLAGS) -I$(INCDIR) -o $@ $< $(TEST_OBJS) $(LDFLAGS) $(LIBS)

clean:
	@echo "🧹 Clean."
	@rm -rf $(BUILDDIR) $(BINDIR)

install: $(TARGET) install-man
	@install -m 755 -d $(DESTDIR)$(PREFIX)/bin
	@install -m 755 $(TARGET) $(DESTDIR)$(PREFIX)/bin/syscage

install-man:
	@install -m 755 -d $(DESTDIR)$(MANDIR)
	@install -m 644 man/syscage.1 $(DESTDIR)$(MANDIR)/syscage.1

uninstall:
	@rm -f $(DESTDIR)$(PREFIX)/bin/syscage
	@rm -f $(DESTDIR)$(MANDIR)/syscage.1
	@-rmdir $(DESTDIR)$(MANDIR) 2>/dev/null; true
