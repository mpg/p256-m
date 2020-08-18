TESTOPEN=test-openbox
TESTCLOSED=test-closedbox
TESTDATA=test-data.h
TESTLIB=p256-native.o
SRC=p256-m.c
HDR=p256-m.h

CC=clang
CFLAGS=-Werror -Weverything --std=c99 -Os
CFLAGS_SAN=-fsanitize=address -fsanitize=undefined

runtest: $(TESTCLOSED) $(TESTOPEN)
	./$(TESTCLOSED)
	./$(TESTOPEN)

$(TESTLIB): $(SRC) $(HDR)
	$(CC) $(CFLAGS) $(CFLAGS_SAN) $< -c -o $@

$(TESTCLOSED): test-closedbox.c $(TESTLIB) $(TESTDATA) $(HDR)
	$(CC) $(CFLAGS) $(CFLAGS_SAN) $< $(TESTLIB) -o $@

$(TESTOPEN): test-openbox.c $(TESTDATA) $(SRC)
	$(CC) $(CFLAGS) $(CFLAGS_SAN) $< -o $@

$(TESTDATA): gen-test-data.py p256.py
	python3 $< > $@

all: runtest
	./sizes.sh
	./stack.sh

clean:
	rm -f $(TESTCLOSED) $(TESTOPEN) $(TESTDATA)
	rm -f *.s *.o *.dump *.sizes *.su *.dfinish
	rm -f *.gcda *.gcno *.info *.html
	rm -rf cov-closed cov-open

.PHONY: runtest clean all
