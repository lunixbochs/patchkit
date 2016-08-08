#ifndef LIBC_H
#define LIBC_H

#include <libcgc.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int cmp_t(const void *, const void *);
void qsort(void *a, size_t n, size_t es, cmp_t *cmp);

#define HUGE_VAL (__builtin_huge_val())

#ifndef LONG_MAX
#define LONG_MAX SSIZE_MAX
#endif
#ifndef LONG_MIN
#define LONG_MIN (-SSIZE_MAX - 1)
#endif

#define EMAX EPIPE
#define ERANGE (EMAX+1)

typedef __builtin_va_list va_list;

#define va_arg(a, type) __builtin_va_arg(a,type)

#define va_end(args) __builtin_va_end(args)

#define va_start(ap, last) \
        __builtin_va_start((ap), (last))

extern int errno;

unsigned int htonl(unsigned int hostlong);

size_t strlen(const char *str);
char *strcpy(char *dst, const char *src);
int strcmp(const char *s1, const char *s2);
char *strchr(const char *s, int c);
long strtol(const char *str, char **endptr, int base);
char *strsep(char **stringp, const char *delim);
char *strdup(const char *str);

double atof(const char *nptr);

void *memset(void *dst, int c, unsigned int n);
int memcmp(const void *b1, const void *b2, size_t n);
void *memcpy(void *b1, const void *b2, size_t n);
void *memmove(void *b1, const void *b2, size_t n);

int toupper(int c);
int tolower(int c);

int transmit_all(int fd, const void *buf, const size_t size);
unsigned int recieve_all(int fd, char *buf, unsigned int size);
int read_until_delim(int fd, char *buf, unsigned int size, char endchar);

#define EOF                  -1

#ifndef NULL
#define NULL ((void*)0)
#endif

#define _FILE_STATE_OPEN  1
#define _FILE_STATE_ERROR 2
#define _FILE_STATE_EOF   4
#define _FILE_HAVE_LAST   8

struct _FILE;
typedef struct _FILE FILE;

extern FILE *stdin;
extern FILE *stdout;
extern FILE *stderr;
extern FILE *stdneg;

int  fgetc(FILE *);
int  getc(FILE *);
int  getchar(void);
int  putchar(int c);
int  fputc(int c, FILE *stream);

char *fgets(char *, int, FILE *);
int fdread(void *, size_t, size_t, int);
int fread(void *, size_t, size_t, FILE *);
int fwrite(const void *buf, size_t size, size_t nmemb, FILE *f);

int ferror(FILE *stream);
int feof(FILE *stream);

int printf(const char *format, ...);
int dprintf(int fd, const char *format, ...);
int fprintf(FILE * stream, const char *format, ...);
int snprintf(char *str, size_t size, const char *format, ...);
int sprintf(char *str, const char *format, ...);
int vsprintf(char *str, const char *format, va_list ap);
int vprintf(const char *format, va_list ap);
int vfprintf(FILE *stream, const char *format, va_list ap);
int vdprintf(int fd, const char *format, va_list ap);
int vsnprintf(char *str, size_t size, const char *format, va_list ap);

int fflush(FILE *stream);

ssize_t getline(char **lineptr, size_t *n, FILE *stream);
ssize_t getdelim(char **lineptr, size_t *n, int delim, FILE *stream);

ssize_t fd_getline(char **lineptr, size_t *n, int fd);
ssize_t fd_getdelim(char **lineptr, size_t *n, int delim, int fd);

void *malloc(size_t size);
void *calloc(size_t number, size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);

#ifdef __cplusplus
}
#endif

#endif
