.PHONY: keygen sign
.DEFAULT_GOAL := all

keygen:
	gcc -std=c99 -o keygen keygen.c posixrand.c tweetnacl.c

sign:
	gcc -std=c99 -o sign sign.c posixrand.c tweetnacl.c

all: keygen sign
