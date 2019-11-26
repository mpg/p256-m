TESTBIN=test
SRC=p256-m.c

runtest: $(TESTBIN)
	./$(TESTBIN)

$(TESTBIN): $(SRC)
	clang -Weverything -O1 $< -o $@

clean:
	rm -f $(TESTBIN)

.PHONY: runtest clean
