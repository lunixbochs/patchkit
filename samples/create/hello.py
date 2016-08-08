def create(pt):
    pt.entry = pt.inject(c=r'''
    void _start() {
        transmit(1, "hello\n", 6, 0);
        _terminate(0);
    }
    ''')
