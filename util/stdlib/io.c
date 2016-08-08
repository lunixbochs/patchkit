int gets(char *buf, size_t size) {
    for (int i = 0; i < size - 1; i++) {
        int err = receive(0, buf, 1, 0);
        if (err) return err;
        if (*buf == '\n') break;
        buf++;
    }
    *buf = '\0';
    return 0;
}

void puts(char *s) {
    transmit(1, s, strlen(s), 0);
}

void putc(int c) {
    transmit(1, &c, 1, 0);
}

int printf(const char *fmt, ...) {
#define arg(type) va_arg(params, type)
    const char *pos = fmt, *flush = fmt;
    char c;
    int control = false;

    va_list params;
    va_start(params, fmt);
    while ((c = *pos++) != 0) {
        if (control) {
            if (flush < pos - 2) {
                transmit(1, flush, pos - flush - 2, 0);
                flush = pos;
            }
            control = false;
            // TODO: implement padding controls
            if (c >= '0' && c <= '9') {
                control = true;
                continue;
            }
            switch (c) {
                case '%':
                    putc(c);
                    break;
                case 'c':
                    putc(arg(int));
                    break;
                case 's': {
                    char *s = arg(char *);
                    if (s == NULL) {
                        puts("(null)");
                    } else {
                        puts(s);
                    }
                    break;
                }
                case 'd':
                case 'i': {
                    int i = arg(int);
                    if (i < 0) {
                        i = (i ^ -1) + 1;
                        puts("-");
                    }
                    puts(itoa(i, 10));
                    break;
                }
                case 'u':
                    puts(itoa(arg(int), 10));
                    break;
                case 'p':
                case 'x':
                    puts(itoa(arg(int), 16));
                    break;
                case 'X':
                    puts(strupr(itoa(arg(int), 16)));
                    break;
            }
        } else if (c == '%') {
            control = true;
        }
    }
    if (flush < pos - 1) {
        transmit(1, flush, pos - flush - 1, 0);
        flush = pos;
    }
    va_end(params);
#undef arg
    return 0;
}
