mntr: mntr.c thpool.c
	gcc -static -o $@ $^ -lprocps -lpthread -lm -lcairo

clean:
	rm -f mntr
