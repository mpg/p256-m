TESTBIN=test
SRC=p256-m.c

runtest: $(TESTBIN)
	./$(TESTBIN)

$(TESTBIN): $(SRC)
	clang -Weverything -O1 $< -o $@

all: runtest
	./sizes.sh

clean:
	rm -f $(TESTBIN) *.s *.o *.dump *.sizes

.PHONY: runtest clean all
