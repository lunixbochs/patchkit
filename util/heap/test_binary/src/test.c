#define USE_DL_PREFIX
#include "malloc.h"
#include <libcgc.h>
#include "libc.h"
/*
void *malloc(size_t size);
void free(void *buf);
void *realloc(void *buf, size_t size);
void *calloc(size_t n_elements, size_t elem_size);

#define MAGIC 0xdeadbeef

//typedef struct MAGIC 
void *malloc(size_t size) {
	return dlmalloc(size);
}

void free(void *buf) {
	dlfree(buf);
}

void *realloc(void *buf, size_t size) {
	return dlrealloc(buf, size);
}
void *calloc(size_t n_elements, size_t elem_size) {
  size_t req = 0;
  if (n_elements != 0) {
    req = n_elements * elem_size;
    if (((n_elements | elem_size) & ~(size_t)0xffff) &&
        (req / n_elements != elem_size))
		//Just fail
		return NULL;
  }
  return dlcalloc(req, 1);
}

*/
int count = 25;

void check(char *b, int s, int v) {
	int i;
	for (i = 0; i < s; i++) {
		if (b[i] != v) {
			printf("FAILED exp %d != actual %d, s=%d\n", v, b[i], s);
			break;
		}
	}
}
int main() {
	char *buf[50];
	int i;
	for (i = 2; i < count; i++) {
		buf[i] = malloc(1<<i);
		memset(buf[i], i, 1<<i);
		printf("Alloced %p\n", buf[i]);
	}
	printf("***FREEING\n");
	for (i = 2; i < count; i++) {
		free(buf[i]);
	}
	printf("***ANOTHER MALLOC\n");
	for (i = 2; i < count; i++) {
		buf[i] = malloc(1<<i);
		memset(buf[i], i, 1<<i);
		buf[i][0] = i;
		printf("Alloced %p\n", buf[i]);
	}
	printf("***realloc - double\n");
	for (i = 2; i < count; i++) {
		buf[i] = realloc(buf[i],2<<i);
		check(buf[i], 1<<i, i);
		printf("Alloced %p - %d\n", buf[i], buf[i][0]);
	}

	printf("***realloc - half\n");
	for (i = 2; i < count; i++) {
		buf[i] = realloc(buf[i],1<<(i-1));
		check(buf[i], 1<<(i-1), i);
		printf("Alloced %p - %d\n", buf[i], buf[i][0]);
	}
	printf("***FREEING\n");
	for (i = 2; i < count; i++) {
		free(buf[i]);
	}

	for (i = 2; i < count; i++) {
		buf[i] = calloc(2, 1<<i);
		printf("Alloced %p\n", buf[i]);
		check(buf[i], 2<<i, 0);
	}

}
