mntr: mntr.c thpool.c
	gcc -static -o $@ $^ -lprocps -lpthread -lm

install:
	scp mntr geneplus@192.168.10.200:/home/geneplus/.local/bin

clean:
	rm -f mntr
