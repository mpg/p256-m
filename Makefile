TESTWHITE=test-whitebox
TESTBLACK=test-blackbox
TESTDATA=test-data.h
TESTLIB=p256-native.o
SRC=p256-m.c
HDR=p256-m.h

CC=clang
CFLAGS=-Werror -Weverything --std=c99 -O1

runtest: $(TESTBLACK) $(TESTWHITE)
	./$(TESTBLACK)
	./$(TESTWHITE)

$(TESTLIB): $(SRC) $(HDR)
	$(CC) $(CFLAGS) $< -c -o $@

$(TESTBLACK): test-blackbox.c $(TESTLIB) $(TESTDATA) $(HDR)
	$(CC) $(CFLAGS) $< $(TESTLIB) -o $@

$(TESTWHITE): test-whitebox.c $(TESTDATA) $(SRC)
	$(CC) $(CFLAGS) $< -o $@

$(TESTDATA): gen-test-data.py p256.py
	python $< > $@

all: runtest
	./sizes.sh
	./stack.sh | sed -n 's/^..p256-m.c *//p' | head

clean:
	rm -f $(TESTBLACK) $(TESTWHITE) $(TESTDATA)
	rm -f *.s *.o *.dump *.sizes *.su *.dfinish

.PHONY: runtest clean all
