import os

def read(name):
    path = os.path.join(os.path.dirname(__file__), name)
    return open(path, 'rb').read()
