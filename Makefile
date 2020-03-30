TESTBIN=test-whitebox
TESTDATA=test-data.h
SRC=p256-m.c

runtest: $(TESTBIN)
	./$(TESTBIN)

$(TESTBIN): test-whitebox.c $(TESTDATA) $(SRC)
	clang -Weverything --std=c99 -O1 $< -o $@

$(TESTDATA): gen-test-data.py
	python $< > $@

all: runtest
	./sizes.sh
	./stack.sh | sed -n 's/^..p256-m.c *//p' | head

clean:
	rm -f $(TESTBIN) $(TESTDATA) *.s *.o *.dump *.sizes *.su *.dfinish

.PHONY: runtest clean all
