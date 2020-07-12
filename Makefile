TESTWHITE=test-whitebox
TESTBLACK=test-blackbox
TESTDATA=test-data.h
TESTLIB=p256-native.o
SRC=p256-m.c
HDR=p256-m.h

CC=clang
CFLAGS=-Werror -Weverything --std=c99 -Os
CFLAGS_SAN=-fsanitize=address -fsanitize=undefined

runtest: $(TESTBLACK) $(TESTWHITE)
	./$(TESTBLACK)
	./$(TESTWHITE)

$(TESTLIB): $(SRC) $(HDR)
	$(CC) $(CFLAGS) $(CFLAGS_SAN) $< -c -o $@

$(TESTBLACK): test-blackbox.c $(TESTLIB) $(TESTDATA) $(HDR)
	$(CC) $(CFLAGS) $(CFLAGS_SAN) $< $(TESTLIB) -o $@

$(TESTWHITE): test-whitebox.c $(TESTDATA) $(SRC)
	$(CC) $(CFLAGS) $(CFLAGS_SAN) $< -o $@

$(TESTDATA): gen-test-data.py p256.py
	python3 $< > $@

all: runtest
	./sizes.sh
	./stack.sh | sed -n 's/^..p256-m.c *p256_/p256_/p'

clean:
	rm -f $(TESTBLACK) $(TESTWHITE) $(TESTDATA)
	rm -f *.s *.o *.dump *.sizes *.su *.dfinish
	rm -f *.gcda *.gcno *.info *.html
	rm -rf cov-black cov-white

.PHONY: runtest clean all
