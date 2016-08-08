#include <libcgc.h>
#include "libc.h"

#ifdef __cplusplus
extern "C" {
#endif

static void printf_core(unsigned int (*func)(char, void *, int), void *user, const char *format, va_list ap);

struct _FILE {
   int fd;
   int state;
   size_t max;
   size_t curr;
   unsigned char buf[4096];
};

static FILE std_files[4] = { {0, _FILE_STATE_OPEN}, {1, _FILE_STATE_OPEN}, {2, _FILE_STATE_OPEN}, {3, _FILE_STATE_OPEN} };

int errno;

FILE *stdin = &std_files[0];
FILE *stdout = &std_files[1];
FILE *stderr = &std_files[2];
FILE *stdneg = &std_files[3];

#define IS_DIGIT     1
#define IS_UPPER     2
#define IS_LOWER     4
#define IS_SPACE     8
#define IS_XDIGIT    16
#define IS_CTRL      32
#define IS_BLANK     64

#define IS_ALPHA     (IS_LOWER | IS_UPPER)
#define IS_ALNUM     (IS_ALPHA | IS_DIGIT)

static unsigned char type_flags[256] = {
     0, IS_CTRL, IS_CTRL, IS_CTRL, IS_CTRL, IS_CTRL, IS_CTRL, IS_CTRL,
     IS_CTRL, IS_SPACE | IS_BLANK, IS_SPACE, IS_SPACE, IS_SPACE, IS_SPACE, IS_CTRL, IS_CTRL,

     IS_CTRL, IS_CTRL, IS_CTRL, IS_CTRL, IS_CTRL, IS_CTRL, IS_CTRL, IS_CTRL,
     IS_CTRL, IS_CTRL, IS_CTRL, IS_CTRL, IS_CTRL, IS_CTRL, IS_CTRL, IS_CTRL,

     IS_SPACE | IS_BLANK, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

     IS_DIGIT | IS_XDIGIT, IS_DIGIT | IS_XDIGIT, IS_DIGIT | IS_XDIGIT, IS_DIGIT | IS_XDIGIT, IS_DIGIT | IS_XDIGIT, IS_DIGIT | IS_XDIGIT, IS_DIGIT | IS_XDIGIT, IS_DIGIT | IS_XDIGIT,
     IS_DIGIT | IS_XDIGIT, IS_DIGIT | IS_XDIGIT, 0, 0, 0, 0, 0, 0,

     0, IS_UPPER | IS_XDIGIT, IS_UPPER | IS_XDIGIT, IS_UPPER | IS_XDIGIT, IS_UPPER | IS_XDIGIT, IS_UPPER | IS_XDIGIT, IS_UPPER | IS_XDIGIT, IS_UPPER,
     IS_UPPER, IS_UPPER, IS_UPPER, IS_UPPER, IS_UPPER, IS_UPPER, IS_UPPER, IS_UPPER,

     IS_UPPER, IS_UPPER, IS_UPPER, IS_UPPER, IS_UPPER, IS_UPPER, IS_UPPER, IS_UPPER,
     IS_UPPER, IS_UPPER, IS_UPPER, 0, 0, 0, 0, 0,

     0, IS_LOWER | IS_XDIGIT, IS_LOWER | IS_XDIGIT, IS_LOWER | IS_XDIGIT, IS_LOWER | IS_XDIGIT, IS_LOWER | IS_XDIGIT, IS_LOWER | IS_XDIGIT, IS_LOWER,
     IS_LOWER, IS_LOWER, IS_LOWER, IS_LOWER, IS_LOWER, IS_LOWER, IS_LOWER, IS_LOWER,

     IS_LOWER, IS_LOWER, IS_LOWER, IS_LOWER, IS_LOWER, IS_LOWER, IS_LOWER, IS_LOWER,
     IS_LOWER, IS_LOWER, IS_LOWER, 0, 0, 0, 0, 0,
};

int isalnum(int c) {
   return (type_flags[c & 0xff] & IS_ALNUM) != 0;
}

int isalpha(int c) {
   return (type_flags[c & 0xff] & IS_ALPHA) != 0;
}

int isascii(int c) {
   return c >= 0 && c < 128;
}

int isblank(int c) {
   return (type_flags[c & 0xff] & IS_BLANK) != 0;
}

int iscntrl(int c) {
   return (type_flags[c & 0xff] & IS_CTRL) != 0;
}

int isdigit(int c) {
   return (type_flags[c & 0xff] & IS_DIGIT) != 0;
}

int isgraph(int c) {
   return c > ' ' && c <= '~';
}

int islower(int c) {
   return (type_flags[c & 0xff] & IS_LOWER) != 0;
}

int isprint(int c) {
   return c >= ' ' && c <= '~';
}

int ispunct(int c) {
   return isprint(c) && (type_flags[c & 0xff] & (IS_SPACE | IS_ALNUM)) == 0;
}

int isspace(int c) {
   return (type_flags[c & 0xff] & IS_SPACE) != 0;
}

int isupper(int c) {
   return (type_flags[c & 0xff] & IS_UPPER) != 0;
}

int isxdigit(int c) {
   return (type_flags[c & 0xff] & IS_XDIGIT) != 0;
}

int toupper(int c) {
   if (isalpha(c)) {
      return c & ~0x20;
   }
   return c;
}

int tolower(int c) {
   if (isalpha(c)) {
      return c | 0x20;
   }
   return c;
}

char *strsep(char **stringp, const char *delim) {
   char *tok = *stringp;
   char *endp = NULL;
   if (*stringp == NULL) {
      return NULL;
   }
   while (*delim) {
      char *d;
      for (d = tok; *d && (endp == NULL || d < endp); d++) {
         if (*d == *delim) {
            endp = d;
            break;
         }
      }
      delim++;
   }
   if (endp != NULL) {
      *endp++ = '\0';
   }
   *stringp = endp;
   return tok;
}

char *strdup(const char *str) {
   size_t len = strlen(str) + 1;
   char *res = (char*)malloc(len);
   if (res) memcpy(res, str, len);
   return res;
}

static int valueOf(char ch, int base) {
   if (isdigit(ch)) {
      int x = ch - '0';
      return x < base ? x : -1;
   }
   else if (isalpha(ch)) {
      int x = toupper(ch) - 'A' + 10;
      return x < base ? x : -1;
   }
   return -1;
}

long strtol(const char *str, char **endptr, int base) {
   const char *n = str;
   int neg = 0;
   int digit;
   long result = 0;
   if (base != 0 && (base < 2 || base > 36)) {
      errno = EINVAL;
      return 0;
   }
   
   /*init *endptr to beginning of string*/
   if (endptr) {
      *endptr = (char*)str;
   }
   
   /*skip white space*/
   while (isspace(*n)) n++;
   
   /*deal with possible sign*/
   if (*n == '+') {
      n++;
   }
   else if (*n == '-') {
      n++;
      neg = 1;
   }
   
   /*handle base == 0*/
   if (base == 0) {
      base = 10;
      if (*n == '0') {
         base = 8;
         n++;
         if (*n == 'X' || *n == 'x') {
            base = 16;
            n++;
         }
      }
   }
   
   while ((digit = valueOf(*n, base)) != -1) {
      long next = result * base + digit;
      if (next < result) {
         /*overflow*/
         errno = ERANGE;
         return neg ? LONG_MIN : LONG_MAX;
      }
      result = next;
      n++;
      if (endptr) {
         /* *endptr points to character after last converted digit*/
         *endptr = (char*)n;
      }  
   }
   
   return neg ? -result : result;
}

double atof(const char *nptr) {
   const char *n = nptr;
   int neg = 0;
   int digit;
   double result = 0;
   double base = 10.0;
   int _base = 10;
   
   /*skip white space*/
   while (isspace(*n)) n++;
   
   /*deal with possible sign*/
   if (*n == '+') {
      n++;
   }
   else if (*n == '-') {
      n++;
      neg = 1;
   }
   
   /*handle base == 0*/
   if (*n == '0' && (n[1] == 'X' || n[1] == 'x')) {
      base = 16.0;
      _base = 16;
      n += 2;
   }
   
   while ((digit = valueOf(*n, _base)) != -1) {
      double next = result * base + digit;
      if (next < result) {
         /*overflow*/
         errno = ERANGE;
         return neg ? -HUGE_VAL : HUGE_VAL;
      }
      result = next;
      n++;
   }
   if (*n == '.') {
      n++;
      while ((digit = valueOf(*n, _base)) != -1) {
         double next = result + digit / base;
         if (next < result) {
            /*overflow*/
            errno = ERANGE;
            return neg ? -HUGE_VAL : HUGE_VAL;
         }
         result = next;
         base /= _base;
         if (base == 0.0) {
            break;
         }
         n++;
      }
   }
      
   return neg ? -result : result;
}

unsigned int htonl(unsigned int hostlong) {
 __asm__ ("bswapl %%eax"
          : "=a" (hostlong)
          : "a" (hostlong)
          );
   return hostlong;
}

int transmit_all(int fd, const void *buf, const size_t size) {
    size_t sent = 0;
    size_t sent_now = 0;
    int ret;

    if (!buf) 
        return 1;

    if (!size)
        return 2;

    while (sent < size) {
        ret = transmit(fd, sent + (const char*)buf, size - sent, &sent_now);
        if (ret != 0) {
            return 3;
        }
        sent += sent_now;
    }

    return 0;
}

unsigned int recieve_all(int fd, char *buf, unsigned int size) {
   char ch;
   unsigned int total = 0;
   size_t nbytes;
   while (size) {
      if (receive(fd, &ch, 1, &nbytes) != 0 || nbytes == 0) {
         break;
      }
      buf[total++] = ch;
      size--;
   }
   return total;
}

/*
 * Read characters into buf until endchar is found. Stop reading when
 * endchar is read.  Returns the total number of chars read EXCLUDING
 * endchar.  endchar is NEVER copied into the buffer.  Note that it
 * is possible to perform size+1 reads as long as the last char read
 * is endchar.
 */
int read_until_delim(int fd, char *buf, unsigned int size, char endchar) {
   char ch;
   unsigned int total = 0;
   size_t nbytes;
   while (1) {
      if (receive(fd, &ch, 1, &nbytes) != 0 || nbytes == 0) {
         return -1;
      }
      if (ch == endchar) break;
      if (total >= size) return -1;
      buf[total++] = ch;
   }
   return (int)total;
}

void *memset(void *dst, int c, unsigned int n) {
   char *d = (char*)dst;
   while (n--) {*d++ = (char)c;}
   return dst;
}

int memcmp(const void *b1, const void *b2, size_t n) {
   unsigned char *p1 = (unsigned char*)b1;
   unsigned char *p2 = (unsigned char*)b2;
   while (n > 0 && *p1 == *p2) {
      p1++;
      p2++;
      n--;
   }
   return n == 0 ? 0 : (*p1 - *p2);
}

void *memcpy(void *b1, const void *b2, size_t n) {
   unsigned int *i1 = (unsigned int *)b1;
   unsigned int *i2 = (unsigned int *)b2;
   while (n >= sizeof(unsigned int)) {
      *i1++ = *i2++;
      n -= sizeof(unsigned int);
   }
   unsigned char *p1 = (unsigned char*)i1;
   unsigned char *p2 = (unsigned char*)i2;
   while (n > 0) {
      *p1++ = *p2++;
      n--;
   }
   return b1;
}

void *memmove(void *b1, const void *b2, size_t n) {
   if (n == 0 || b1 == b2) return b1;
   if (b1 < b2) {
      return memcpy(b1, b2, n);
   }
   unsigned int *e1 = (unsigned int*)(n + (unsigned char *)b1);
   unsigned int *e2 = (unsigned int*)(n + (unsigned char *)b2);
   while (n >= sizeof(unsigned int)) {
      *--e1 = *--e2;
      n -= sizeof(unsigned int);
   }
   unsigned char *p1 = (unsigned char*)e1;
   unsigned char *p2 = (unsigned char*)e2;
   while (n > 0) {
      *--p1 = *--p2;
      n--;
   }
   return b1;
}

int strcmp(const char *s1, const char *s2) {
   while (*s1 != '\0' && *s2 != '\0'  && *s1 == *s2) {
      s1++;
      s2++;
   }
   return *s1 - *s2;
}

char *strcpy(char *dst, const char *src) {
   char *d = dst;
   while ((*d++ = *src++) != 0) {}
   return dst;
}

size_t strlen(const char *str) {
   size_t res = 0;
   while (*str++) {res++;}
   return res;
}

char *strchr(const char *s, int c) {
   while (*s && *s != c) {s++;}
   return (char*)(*s ? s : (c ? NULL : s));
}

int snprintf(char *str, size_t size, const char *format, ...) {
   va_list va;
   va_start(va, format);
   return vsnprintf(str, size, format, va);
}

int vsprintf(char *str, const char *format, va_list ap) {
   return vsnprintf(str, 0xffffffff, format, ap);
}

int sprintf(char *str, const char *format, ...) {
   va_list va;
   va_start(va, format);
   return vsprintf(str, format, va);
}

struct _str_printer {
   char *outbuf;
   unsigned int max;
   unsigned int count;
};

/*if flag != 0 return number of chars output so far*/
static unsigned int strn_printer(char ch, void *_sp, int flag) {
   struct _str_printer *sp = (struct _str_printer *)_sp;
   if (flag) {
      return sp->count;
   }
   else if (sp->count < sp->max) {
      *(sp->outbuf) = ch;
      (sp->outbuf)++;
   }
   sp->count++;
   return 0;
}

struct _file_printer {
   FILE *file;
   int err;
   unsigned int count;
};

/*if flag != 0 return number of chars output so far*/
static unsigned int file_printer(char ch, void *_fp, int flag) {
   struct _file_printer *fp = (struct _file_printer *)_fp;
   if (flag == 0) {
      fputc(ch, fp->file);
      fp->count++;
   }
   else if (flag == 1) {
      return fp->count;
   }
   else if (flag == 2) {
      fflush(fp->file);
   }
   return 0;
}

int printf(const char *format, ...) {
   va_list va;
   va_start(va, format);
   return vprintf(format, va);
}

int vprintf(const char *format, va_list ap) {
   return vfprintf(stdout, format, ap);
}

int vfprintf(FILE * stream, const char *format, va_list ap) {
   struct _file_printer fp;
   fp.file = stream;
   fp.err = 0;
   fp.count = 0;
   printf_core(file_printer, &fp, format, ap);
   return fp.count;
}

int fprintf(FILE * stream, const char *format, ...) {
   va_list va;
   va_start(va, format);
   return vfprintf(stream, format, va);
}

struct _fd_printer {
   int fd;
   int err;
   unsigned int count;
   unsigned char buf[4096];
};

/*if flag != 0 return number of chars output so far*/
static unsigned int fd_printer(char ch, void *_fp, int flag) {
   struct _fd_printer *fp = (struct _fd_printer *)_fp;
   if (flag == 0) {
      fp->buf[fp->count++ % sizeof(fp->buf)] = ch;
      if ((fp->count % sizeof(fp->buf)) == 0) {
         if (transmit_all(fp->fd, &ch, sizeof(fp->buf)) != 0) {
            _terminate(1);
         }         
      }
   }
   else if (flag == 1) {
      return fp->count;
   }
   else if (flag == 2) {
      unsigned int rem = fp->count % sizeof(fp->buf);
      if (rem != 0) {
         if (transmit_all(fp->fd, fp->buf, rem) != 0) {
            _terminate(1);
         }
      }
   }
   return 0;
}

#define STATE_NORMAL 0
#define STATE_ESCAPE 1
#define STATE_PERCENT 2
#define STATE_OCTAL 3
#define STATE_HEX 4
#define STATE_FLAGS 5
#define STATE_WIDTH 6
#define STATE_PRECISION 7
#define STATE_LENGTH 8
#define STATE_CONVERSION 9
#define STATE_WIDTH_ARG 10
#define STATE_WIDTH_VAL 11
#define STATE_PRECISION_ARG 12
#define STATE_PRECISION_VAL 13
#define STATE_NARG 15

#define FLAGS_TICK 1
#define FLAGS_LEFT 2
#define FLAGS_SIGN 4
#define FLAGS_SPACE 8
#define FLAGS_HASH 16
#define FLAGS_ZERO 32

#define LENGTH_H 1
#define LENGTH_HH 2
#define LENGTH_L 3
#define LENGTH_J 5
#define LENGTH_Z 6
#define LENGTH_T 7
#define LENGTH_CAPL 8

static char *r_utoa(unsigned int val, char *outbuf) {
   char *p = outbuf;
   *p = '0';
   while (val) {
      *p++ = (val % 10) + '0';
      val /= 10;
   }
   return p != outbuf ? (p - 1) : p;
}

/*outbuf needs to be at least 22 chars*/
static char *r_llotoa(unsigned long long val, char *outbuf) {
   char *p = outbuf;
   *p = '0';
   while (val) {
      *p++ = (val & 7) + '0';
      val >>= 3;
   }
   return p != outbuf ? (p - 1) : p;
}

static char *r_otoa(unsigned int val, char *outbuf) {
   return r_llotoa(val, outbuf);
}

/*outbuf needs to be at least 22 chars*/
static char *r_llxtoa(unsigned long long val, char *outbuf, int caps) {
   char *p = outbuf;
   *p = '0';
   while (val) {
      char digit = (char)(val & 0xf);
      if (digit < 10) {
         digit += '0';
      }
      else {
         digit = caps ? (digit + 'A' - 10) : (digit + 'a' - 10);
      }
      *p++ = digit;
      val >>= 4;
   }
   return p != outbuf ? (p - 1) : p;
}

static char *r_xtoa(unsigned int val, char *outbuf, int caps) {
   return r_llxtoa(val, outbuf, caps);
}

static int hex_value_of(char ch) {
   if (isdigit(ch)) {
      return ch - '0';
   }
   else if (isalpha(ch)) {
      return toupper(ch) - 'A' + 10;
   }
   return -1;
}

/*
func is responsible for outputing the given character
user is a pointer to data required by func
*/
static void printf_core(unsigned int (*func)(char, void *, int), void *user, const char *format, va_list ap) {
   int state = STATE_NORMAL;
   int flags = 0;
   int digit_count = 0;
   int value = 0;
   char ch;
   int arg_count = 0;
   int width_value = -1;
   int prec_value = -1;
   int field_arg = -1;
   int length = 0;
   char **args = (char**)ap;
   for (ch = *format++; ch; ch = *format++) {
      switch (state) {
         case STATE_NORMAL:
            if (ch == '%') {
               state = STATE_PERCENT;
            }
            else if (ch == '\\') {
               state = STATE_ESCAPE;
            }
            else {
               func(ch, user, 0);
            }
            break;
         case STATE_ESCAPE:
            switch (ch) {
               case 'n':
                  func('\n', user, 0);
                  break;
               case 't':
                  func('\t', user, 0);
                  break;
               case 'r':
                  func('\r', user, 0);
                  break;
               case 'b':
                  func('\b', user, 0);
                  break;
               case 'f':
                  func('\f', user, 0);
                  break;
               case 'v':
                  func('\v', user, 0);
                  break;
               case '\\': case '\'': case '"':
                  func(ch, user, 0);
                  break;
               case 'x':
                  state = STATE_HEX;
                  digit_count = 0;
                  value = 0;
                  break;
               default:
                  if (ch > '0' && ch < '8') {
                     state = STATE_OCTAL;
                     digit_count = 1;
                     value = ch - '0';
                  }
                  else {
                     func(*format, user, 0);
                  }
                  break;
            }
            if (state == STATE_ESCAPE) {
               state = STATE_NORMAL;
            }
            break;
         case STATE_PERCENT:
            if (ch == '%') {
               func(ch, user, 0);
               state = STATE_NORMAL;
            }
            else {
               state = STATE_NARG;
               flags = 0;
               format--;
            }
            break;
         case STATE_OCTAL:
            if (ch > '0' && ch < '8' && digit_count < 3) {
               digit_count++;
               value = value * 8 + (ch - '0');
               if (digit_count == 3) {
                  func(value, user, 0);
                  state = STATE_NORMAL;
               }
            }
            else {
               func(value, user, 0);
               state = STATE_NORMAL;
               format--;
            }
            break;
         case STATE_HEX:
            if (isxdigit(ch) && digit_count < 2) {
               digit_count++;
               value = value * 16 + hex_value_of(ch);
               if (digit_count == 2) {
                  func(value, user, 0);
                  state = STATE_NORMAL;
               }
            }
            else {
               func(value, user, 0);
               state = STATE_NORMAL;
               format--;
            }
            break;
         case STATE_NARG:
            width_value = -1;
            prec_value = -1;
            flags = 0;
            length = 0;
            field_arg = -1;
            if (ch == '0') {
               format--;
               state = STATE_FLAGS;
               break;
            }
            if (isdigit(ch)) {
               /*
               could be width or could be arg specifier or a 0 flag
               width and arg values don't start with 0
               */
               width_value = 0;
               while (isdigit(ch)) {
                  width_value = width_value * 10 + (ch - '0');
                  ch = *format++;
               }
               if (ch == '$') {
                  field_arg = width_value - 1;
                  width_value = 0;
                  state = STATE_FLAGS;
               }
               else {
                  /*this was a width*/
                  format--;
                  state = STATE_PRECISION;
               }
            }
            else {
               format--;
               state = STATE_FLAGS;
            }
            break;
         case STATE_FLAGS:
            switch (ch) {
               case '\'':
                  flags |= FLAGS_TICK;
                  break;
               case '-':
                  flags |= FLAGS_LEFT;
                  break;
               case '+':
                  flags |= FLAGS_SIGN;
                  break;
               case ' ':
                  flags |= FLAGS_SPACE;
                  break;
               case '#':
                  flags |= FLAGS_HASH;
                  break;
               case '0':
                  flags |= FLAGS_ZERO;
                  break;
               default:
                  format--;
                  if ((flags & (FLAGS_ZERO | FLAGS_LEFT)) == (FLAGS_ZERO | FLAGS_LEFT)) {
                     /*if both '-' and '0' appear, '0' is ignored*/
                     flags &= ~FLAGS_ZERO;
                  }
                  state = STATE_WIDTH;
                  break;
            }
            break;
         case STATE_WIDTH:
            if (ch == '*') {
               ch = *format++;
               int width_arg = 0;
               if (isdigit(ch)) {
                  while (isdigit(ch)) {
                     width_arg = width_arg * 10 + (ch - '0');
                     ch = *format++;
                  }
                  width_arg--;
                  if (ch != '$') {
                     /*error*/
                  }
               }
               else {
                  width_arg = arg_count++;
                  format--;
               }
               width_value = (int)args[width_arg];
            }
            else if (isdigit(ch)) {
               width_value = 0;
               while (isdigit(ch)) {
                  width_value = width_value * 10 + (ch - '0');
                  ch = *format++;
               }
               format--;
            }
            else {
               /*no width specified*/
               format--;
            }
            state = STATE_PRECISION;
            break;
         case STATE_PRECISION:
            if (ch == '.') {
               /*have a precision*/
               ch = *format++;
               if (ch == '*') {
                  ch = *format++;
                  int prec_arg = 0;
                  if (isdigit(ch)) {
                     while (isdigit(ch)) {
                        prec_arg = prec_arg * 10 + (ch - '0');
                        ch = *format++;
                     }
                     prec_arg--;
                     if (ch != '$') {
                        /*error*/
                     }
                  }
                  else {
                     prec_arg = arg_count++;
                     format--;
                  }
                  prec_value = (int)args[prec_arg];
               }
               else if (isdigit(ch)) {
                  prec_value = 0;
                  while (isdigit(ch)) {
                     prec_value = prec_value * 10 + (ch - '0');
                     ch = *format++;
                  }
                  format--;
               }
               else {
                  /*no precision specified*/
                  format--;
               }
            }
            else {
               /*no precision specified*/
               format--;
            }
            state = STATE_LENGTH;
            break;
         case STATE_LENGTH:
            switch (ch) {
               case 'h':
                  length = LENGTH_H;
                  if (*format == 'h') {
                     length++;
                     format++;
                  }
                  break;
               case 'l':
                  length = LENGTH_L;
                  if (*format == 'l') {
                     format++;
                  }
                  break;
               case 'j':
                  length = LENGTH_J;
                  break;
               case 'z':
                  length = LENGTH_Z;
                  break;
               case 't':
                  length = LENGTH_T;
                  break;
               case 'L':
                  length = LENGTH_CAPL;
                  break;
               default:
                  format--;
                  break;
            }
            state = STATE_CONVERSION;
            break;
         case STATE_CONVERSION: {
            char num_buf[32];
            char *num_ptr;
            int use_caps = 1;
            int sign;
            int val;
            /* long long llval; */
            if (field_arg == -1) {
               field_arg = arg_count++;
            }
            switch (ch) {
               case 'd': case 'i': {
                  int len;
                  switch (length) {
                     case LENGTH_H:
                        val = (short)(int)args[field_arg];
                        sign = val < 0;
                        if (sign) {
                           val = -val;
                        }
                        num_ptr = r_utoa(val, num_buf);
                        break;
                     case LENGTH_HH:
                        val = (char)(int)args[field_arg];
                        sign = val < 0;
                        if (sign) {
                           val = -val;
                        }
                        num_ptr = r_utoa(val, num_buf);
                        break;
                     case LENGTH_L:
                     default:
                        val = (long)args[field_arg];
                        sign = val < 0;
                        if (sign) {
                           val = -val;
                        }
                        num_ptr = r_utoa(val, num_buf);
                        break;
                  }
                  len = num_ptr - num_buf + 1;
                  if (width_value == -1) {
                     /* by default min length is the entire value */
                     width_value = len;
                     if (sign || (flags & FLAGS_SIGN)) {
                        width_value++;
                     }
                  }
                  if (prec_value == -1) {
                     /* by default max is entire value */
                     prec_value = len;
                     if ((flags & FLAGS_ZERO) != 0 && prec_value < width_value) {
                        /* widen precision if necessary to pad to width with '0' */
                        if (sign || (flags & FLAGS_SIGN)) {
                           prec_value = width_value - 1;
                        }
                        else {
                           prec_value = width_value;
                        }
                     }
                  }
                  else {
                     if (prec_value < len) {
                        prec_value = len;
                     }
                     /* number won't need leading zeros */
                     flags &= ~FLAGS_ZERO;
                  }
                  if (flags & FLAGS_LEFT) {
                     if (sign) {
                        func('-', user, 0);
                        if (width_value > 0) {
                           width_value--;
                        }
                     }
                     else if ((flags & FLAGS_SIGN) != 0) {
                        func('+', user, 0);
                        if (width_value > 0) {
                           width_value--;
                        }
                     }
                     while (prec_value > len) {
                        func('0', user, 0);
                        prec_value--;
                        if (width_value > 0) {
                           width_value--;
                        }
                     }
                     while (prec_value != 0) {
                        func(*num_ptr--, user, 0);
                        prec_value--;
                        if (width_value > 0) {
                           width_value--;
                        }
                     }
                     while (width_value != 0) {
                        func(' ', user, 0);
                        width_value--;
                     }
                  }
                  else {
                     while (width_value > (prec_value + 1)) {
                        func(' ', user, 0);
                        width_value--;
                     }
                     if (sign) {
                        func('-', user, 0);
                        if (width_value > 0) {
                           width_value--;
                        }
                     }
                     else if ((flags & FLAGS_SIGN) != 0) {
                        func('+', user, 0);
                        if (width_value > 0) {
                           width_value--;
                        }
                     }
                     if (width_value > prec_value) {
                        func(' ', user, 0);
                        width_value--;
                     }                        
                     while (prec_value > len) {
                        func('0', user, 0);
                        prec_value--;
                     }
                     while (prec_value != 0) {
                        func(*num_ptr--, user, 0);
                        prec_value--;
                     }
                  }
                  break;
               }
               case 'o': {
                  int len;
                  switch (length) {
                     case LENGTH_H:
                        num_ptr = r_otoa((unsigned short)(unsigned int)args[field_arg], num_buf);
                        break;
                     case LENGTH_HH:
                        num_ptr = r_otoa((unsigned char)(unsigned int)args[field_arg], num_buf);
                        break;
                     case LENGTH_L:
                     default:
                        num_ptr = r_otoa((unsigned long)args[field_arg], num_buf);
                        break;
                  }
                  if (flags & FLAGS_HASH) {
                     if (*num_ptr != '0') {
                        num_ptr++;
                        *num_ptr = '0';
                     }
                  }
                  len = num_ptr - num_buf + 1;
                  if (width_value == -1) {
                     /* by default min length is the entire value */
                     width_value = len;
                  }
                  if (prec_value == -1) {
                     /* by default max is entire value */
                     prec_value = len;
                     if ((flags & FLAGS_ZERO) != 0 && prec_value < width_value) {
                        /* widen precision if necessary to pad to width with '0' */
                        prec_value = width_value;
                     }
                  }
                  else {
                     if (prec_value < len) {
                        prec_value = len;
                     }
                     flags &= ~FLAGS_ZERO;
                  }
                  if (flags & FLAGS_LEFT) {
                     while (prec_value > len) {
                        func('0', user, 0);
                        prec_value--;
                        if (width_value > 0) {
                           width_value--;
                        }
                     }
                     while (prec_value != 0) {
                        func(*num_ptr--, user, 0);
                        prec_value--;
                        if (width_value > 0) {
                           width_value--;
                        }
                     }
                     while (width_value != 0) {
                        func(' ', user, 0);
                        width_value--;
                     }
                  }
                  else {
                     while (width_value > prec_value) {
                        func(' ', user, 0);
                        width_value--;
                     }
                     while (prec_value > len) {
                        func('0', user, 0);
                        prec_value--;
                     }
                     while (prec_value != 0) {
                        func(*num_ptr--, user, 0);
                        prec_value--;
                     }
                  }
                  break;
               }
               case 'u': {
                  int len;
                  switch (length) {
                     case LENGTH_H:
                        num_ptr = r_utoa((unsigned short)(unsigned int)args[field_arg], num_buf);
                        break;
                     case LENGTH_HH:
                        num_ptr = r_utoa((unsigned char)(unsigned int)args[field_arg], num_buf);
                        break;
                     case LENGTH_L:
                     default:
                        num_ptr = r_utoa((unsigned long)args[field_arg], num_buf);
                        break;
                  }
                  len = num_ptr - num_buf + 1;
                  if (width_value == -1) {
                     /* by default min length is the entire value */
                     width_value = len;
                  }
                  if (prec_value == -1) {
                     /* by default max is entire value */
                     prec_value = len;
                     if ((flags & FLAGS_ZERO) != 0 && prec_value < width_value) {
                        /* widen precision if necessary to pad to width with '0' */
                        prec_value = width_value;
                     }
                  }
                  else {
                     if (prec_value < len) {
                        prec_value = len;
                     }
                     flags &= ~FLAGS_ZERO;
                  }
                  if (flags & FLAGS_LEFT) {
                     while (prec_value > len) {
                        func('0', user, 0);
                        prec_value--;
                        if (width_value > 0) {
                           width_value--;
                        }
                     }
                     while (prec_value != 0) {
                        func(*num_ptr--, user, 0);
                        prec_value--;
                        if (width_value > 0) {
                           width_value--;
                        }
                     }
                     while (width_value != 0) {
                        func(' ', user, 0);
                        width_value--;
                     }
                  }
                  else {
                     while (width_value > prec_value) {
                        func(' ', user, 0);
                        width_value--;
                     }
                     while (prec_value > len) {
                        func('0', user, 0);
                        prec_value--;
                     }
                     while (prec_value != 0) {
                        func(*num_ptr--, user, 0);
                        prec_value--;
                     }
                  }
                  break;
               }
               case 'x':
                  use_caps = 0;  /* now fall into X case */
               case 'X': {
                  int len;
                  switch (length) {
                     case LENGTH_H:
                        num_ptr = r_xtoa((unsigned short)(unsigned int)args[field_arg], num_buf, use_caps);
                        break;
                     case LENGTH_HH:
                        num_ptr = r_xtoa((unsigned char)(unsigned int)args[field_arg], num_buf, use_caps);
                        break;
                     case LENGTH_L:
                     default:
                        num_ptr = r_xtoa((unsigned long)args[field_arg], num_buf, use_caps);
                        break;
                  }
                  len = num_ptr - num_buf + 1;
                  if (width_value == -1) {
                     /* by default min length is the entire value */
                     width_value = len;
                  }
                  if (prec_value == -1) {
                     /* by default max is entire value */
                     prec_value = len;
                     if ((flags & FLAGS_ZERO) != 0 && prec_value < width_value) {
                        /* widen precision if necessary to pad to width with '0' */
                        prec_value = width_value;
                     }
                  }
                  else {
                     if (prec_value < len) {
                        prec_value = len;
                     }
                     flags &= ~FLAGS_ZERO;
                  }
                  if (flags & FLAGS_LEFT) {
                     if (flags & FLAGS_HASH && (len != 1 || *num_ptr != '0')) {
                        func('0', user, 0);
                        if (width_value > 0) {
                           width_value--;
                        }
                        func(use_caps ? 'X' : 'x', user, 0);
                        if (width_value > 0) {
                           width_value--;
                        }
                     }
                     while (prec_value > len) {
                        func('0', user, 0);
                        prec_value--;
                        if (width_value > 0) {
                           width_value--;
                        }
                     }
                     while (prec_value != 0) {
                        func(*num_ptr--, user, 0);
                        prec_value--;
                        if (width_value > 0) {
                           width_value--;
                        }
                     }
                     while (width_value != 0) {
                        func(' ', user, 0);
                        width_value--;
                     }
                  }
                  else {
                     while (width_value > (prec_value + 2)) {
                        func(' ', user, 0);
                        width_value--;
                     }
                     if (flags & FLAGS_HASH && (len != 1 || *num_ptr != '0')) {
                        func('0', user, 0);
                        if (width_value > 0) {
                           width_value--;
                        }
                        func(use_caps ? 'X' : 'x', user, 0);
                        if (width_value > 0) {
                           width_value--;
                        }
                     }
                     else {
                        while (width_value > prec_value) {
                           func(' ', user, 0);
                           width_value--;
                        }
                     }
                     while (prec_value > len) {
                        func('0', user, 0);
                        prec_value--;
                     }
                     while (prec_value != 0) {
                        func(*num_ptr--, user, 0);
                        prec_value--;
                     }
                  }
                  break;
               }
               case 'f': case 'F':
                  break;
               case 'e': case 'E':
                  break;
               case 'g': case 'G':
                  break;
               case 'a': case 'A':
                  break;
               case 'c': {
                  unsigned char ch = (unsigned char)(unsigned int)args[field_arg];
                  if (width_value == -1) {
                     width_value = 1;
                  }
                  if (flags & FLAGS_LEFT) {
                     func((char)ch, user, 0);
                     if (width_value > 0) {
                        width_value--;
                     }
                     while (width_value != 0) {
                        func(' ', user, 0);
                        width_value--;
                     }
                  }
                  else {
                     while (width_value > 1) {
                        func(' ', user, 0);
                        width_value--;
                     }
                     func(ch, user, 0);
                  }
                  break;
               }
               case 's': {
                  const char *s_arg = (const char *)args[field_arg];
                  int len = strlen(s_arg);
                  if (width_value == -1) {
                     /* by default min length is the entire string */
                     width_value = len;
                  }
                  if (prec_value == -1 || prec_value > len) {
                     /* by default max is entire string but no less than width */
                     prec_value = len;
                  }
                  if (flags & FLAGS_LEFT) {
                     while (prec_value != 0) {
                        func(*s_arg++, user, 0);
                        prec_value--;
                        if (width_value > 0) {
                           width_value--;
                        }
                     }
                     while (width_value != 0) {
                        func(' ', user, 0);
                        width_value--;
                     }
                  }
                  else {
                     while (width_value > prec_value) {
                        func(' ', user, 0);
                        width_value--;
                     }
                     while (prec_value != 0) {
                        func(*s_arg++, user, 0);
                        prec_value--;
                     }
                  }
                  break;
               }
               case 'p': {
                  int len;
                  flags |= FLAGS_HASH;
                  num_ptr = r_xtoa((unsigned int)args[field_arg], num_buf, 0);
                  len = num_ptr - num_buf + 1;
                  if (prec_value == -1) {
                     /* by default max is entire value */
                     prec_value = len;
                  }
                  else {
                     if (prec_value < len) {
                        prec_value = len;
                     }
                     flags &= ~FLAGS_ZERO;
                  }
                  if (width_value == -1) {
                     /* by default min length is the entire value */
                     width_value = prec_value + 2;
                  }
                  if (flags & FLAGS_LEFT) {
                     func('0', user, 0);
                     if (width_value > 0) {
                        width_value--;
                     }
                     func('x', user, 0);
                     if (width_value > 0) {
                        width_value--;
                     }
                     while (prec_value > len) {
                        func('0', user, 0);
                        prec_value--;
                        if (width_value > 0) {
                           width_value--;
                        }
                     }
                     while (prec_value != 0) {
                        func(*num_ptr--, user, 0);
                        prec_value--;
                        if (width_value > 0) {
                           width_value--;
                        }
                     }
                     while (width_value != 0) {
                        func(' ', user, 0);
                        width_value--;
                     }
                  }
                  else {
                     while (width_value > (prec_value + 2)) {
                        func(' ', user, 0);
                        width_value--;
                     }
                     func('0', user, 0);
                     if (width_value > 0) {
                        width_value--;
                     }
                     func('x', user, 0);
                     if (width_value > 0) {
                        width_value--;
                     }
                     while (prec_value > len) {
                        func('0', user, 0);
                        prec_value--;
                     }
                     while (prec_value != 0) {
                        func(*num_ptr--, user, 0);
                        prec_value--;
                     }
                  }
                  break;
               }
               case 'n': {
                  void *np = (void*)args[field_arg];
                  unsigned int len = func(0, user, 1);
                  switch (length) {
                     case LENGTH_HH:
                        *(unsigned char*)np = (unsigned char)len;
                        break;
                     case LENGTH_H:
                        *(unsigned short*)np = (unsigned short)len;
                        break;
                     case LENGTH_L:
                     default:
                        *(unsigned int*)np = len;
                        break;
                  }
                  break;
               }
               case 'C':
                  break;
               case 'S':
                  break;
               default:
                  break;
            }
            state = STATE_NORMAL;
            break;
         }
      }
   }
   func(0, user, 2);
}

int vdprintf(int fd, const char *format, va_list ap) {
   struct _fd_printer fp;
   fp.fd = fd;
   fp.err = 0;
   fp.count = 0;
   printf_core(fd_printer, &fp, format, ap);
   return fp.count;
}

int dprintf(int fd, const char *format, ...) {
   va_list va;
   va_start(va, format);
   return vdprintf(fd, format, va);
}

int vsnprintf(char *str, size_t size, const char *format, va_list ap) {
   struct _str_printer sp;
   sp.outbuf = str;
   sp.max = size;
   sp.count = 0;
   printf_core(strn_printer, &sp, format, ap);
   if (sp.count < sp.max) {
      *sp.outbuf = 0;
   }
   else if (sp.max > 0) {
      str[size - 1] = 0;
   }
   return sp.count;
}

int fgetc(FILE *stream) {
   if (stream->curr < stream->max) {
      return stream->buf[stream->curr++];
   }
   stream->curr = stream->max = 0;
   
   if (receive(stream->fd, stream->buf, sizeof(stream->buf), &stream->max) != 0) {
      stream->state |= _FILE_STATE_ERROR;
      return EOF;
   }
   else if (stream->max == 0) {
      stream->state |= _FILE_STATE_EOF;
      return EOF;
   }
   else {
      return stream->buf[stream->curr++];
   }
}

int getc(FILE *stream) {
   return fgetc(stream);
}

int getchar(void) {
   return getc(stdin);
}

char *fgets(char *s, int size, FILE *stream) {
   int idx = 0;
   while (idx < (size - 1)) {
      int ch = fgetc(stream);
      if (ch == EOF) {  /* error or eof */
         if ((stream->state & _FILE_STATE_EOF) != 0) {
            if (idx > 0) {
               break;
            }
         }
         return NULL;
      }
      else {
         s[idx++] = ch;
         if (ch == '\n') {
            break;
         }
      }
   }
   s[idx] = '\0';
   return s;
}

int fdread(void *buf, size_t size, size_t nmemb, int fd) {
   if (fd < 0 || fd > 3) {
      return -1;
   }
   return fread(buf, size, nmemb, &std_files[fd]);
}

int fread(void *buf, size_t size, size_t nmemb, FILE *f) {
   char *buf_ = (char*)buf;
   size_t nitems;
   size_t n;
   for (nitems = 0; nitems < nmemb; nitems++) {
      for (n = 0; n < size; n++) {
         int ch = fgetc(f);
         if (ch == EOF) {
            return nitems;
         }
         *buf_++ = ch;
      }
   }
   return nitems;
}

int fputc(int c, FILE *stream) {
   if (stream->fd == 0) {
      errno = EBADF;
      return -1;
   }
   if (stream->max < sizeof(stream->buf)) {
      stream->buf[stream->max++] = c;
   }
   if (stream->max == sizeof(stream->buf)) {
      return fflush(stream);
   }
   return c & 0xff;
}

int putchar(int c) {
   return fputc(c, stdout);
}

int fwrite(const void *buf, size_t size, size_t nmemb, FILE *f) {
   const char *buf_ = (const char*)buf;
   size_t nitems;
   size_t n;
   for (nitems = 0; nitems < nmemb; nitems++) {
      for (n = 0; n < size; n++) {
         if (fputc(*buf_++, f) == EOF) {
            return nitems;
         }
      }
   }
   return nitems;
}

int fflush(FILE *stream) {
   if (stream->fd == 0) {
      errno = EBADF;
      return -1;
   }
   if (stream->curr == stream->max) {
      /* nothing to flush */
      return 0;
   }
   
   size_t to_send = stream->max - stream->curr;
   if (transmit_all(stream->fd, stream->buf + stream->curr, to_send) != 0) {
      stream->state |= _FILE_STATE_ERROR;
      return EOF;
   }
   else {
      stream->curr = stream->max = 0;
   }
   return 0;
}

ssize_t fd_getline(char **lineptr, size_t *n, int fd) {
   return fd_getdelim(lineptr, n, '\n', fd);
}

ssize_t fd_getdelim(char **lineptr, size_t *n, int delim, int fd) {
   if (fd < 0 || fd > 3) {
      return -1;
   }
   return getdelim(lineptr, n, delim, &std_files[fd]);
}

ssize_t getline(char **lineptr, size_t *n, FILE *stream) {
   return getdelim(lineptr, n, '\n', stream);
}

ssize_t getdelim(char **lineptr, size_t *n, int delim, FILE *stream) {
   char buf[256];
   int idx = 0;
   int numchars = 0;
   while (1) {
      int ch = fgetc(stream);
      if (ch == EOF) {  /* error or eof */
         if ((stream->state & _FILE_STATE_EOF) != 0) {
            if (numchars > 0 || idx > 0) {
               ssize_t need = numchars + idx + 1;
               if (need > *n) {
                  *lineptr = (char*)realloc(*lineptr, need);
               }
               memcpy(*lineptr + numchars, buf, idx);
               numchars += idx;
               break;
            }
         }
         return -1;
      }
      else {
         buf[idx++] = ch;
         if (ch == delim) {
            ssize_t need = numchars + idx + 1;
            if (need > *n) {
               *lineptr = (char*)realloc(*lineptr, need);
            }
            memcpy(*lineptr + numchars, buf, idx);
            numchars += idx;
            break;
         }
         else if (idx == 256) {
            ssize_t need = numchars + idx + 1;
            if (need > *n) {
               *lineptr = (char*)realloc(*lineptr, need);
            }
            memcpy(*lineptr + numchars, buf, idx);
            numchars += idx;
            idx = 0;
         }
      }
   }
   (*lineptr)[numchars] = '\0';
   *n = numchars;
   return numchars;
}

#ifdef __cplusplus
}
#endif
