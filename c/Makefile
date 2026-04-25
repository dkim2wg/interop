CC      = cc
CFLAGS  = -std=c11 -Wall -Wextra -g \
          $(shell pkg-config --cflags openssl) \
          $(shell PKG_CONFIG_PATH=/opt/homebrew/lib/pkgconfig pkg-config --cflags libcjson)
LDFLAGS = $(shell pkg-config --libs openssl) \
          $(shell PKG_CONFIG_PATH=/opt/homebrew/lib/pkgconfig pkg-config --libs libcjson) \
          -lresolv

CORE_SRCS = base64.c tagparse.c dkim2_hash.c dkim2_header.c \
            dkim2_recipe.c dkim2_dns.c dkim2_crypto.c \
            dkim2_sign.c dkim2_verify.c
CORE_OBJS = $(CORE_SRCS:.c=.o)

# Milter binary deferred to Task 11 (requires libmilter)
# all: dkim2-milter
all: $(CORE_OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

TESTS = tests/test_base64 tests/test_tagparse tests/test_hash \
        tests/test_header tests/test_recipe tests/test_crypto \
        tests/test_verify

test: $(TESTS)
	@for t in $(TESTS); do echo "Running $$t..."; $$t || exit 1; done

tests/test_base64: tests/test_base64.c base64.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

tests/test_tagparse: tests/test_tagparse.c tagparse.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

tests/test_hash: tests/test_hash.c dkim2_hash.o base64.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

tests/test_header: tests/test_header.c dkim2_header.o tagparse.o base64.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

tests/test_recipe: tests/test_recipe.c dkim2_recipe.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

tests/test_crypto: tests/test_crypto.c dkim2_crypto.o base64.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

tests/test_verify: tests/test_verify.c $(CORE_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o $(TESTS)
