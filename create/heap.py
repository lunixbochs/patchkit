def patch(pt):
    pt.entry = pt.inject(c=r'''
    void main() {
        void *test = dlmalloc(5);
        memcpy(test, "hi\n", 3);
        transmit(1, test, 3, 0);
        _terminate(0);
    }
    ''')
