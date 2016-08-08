import random
import subprocess
from pwn import *
p = process(sys.argv[1:])

key = list('ECAF')
for i in xrange(random.randint(1, 4)):
    c = os.urandom(1)
    key.append(c)
    for j in xrange(4):
        key[j] = chr(ord(key[j]) ^ ord(c))
key = ''.join(key)
print 'sending key', repr(key)
p.send(key)

# wait for key response
ref = ''.join([chr(ord(c) ^ 0xff) for c in key])
buf = ''
while True:
    buf += p.recv(1)
    if buf[-len(ref):] == ref:
        print 'got key response'
        break

nonce = p.recv(8).encode('hex')
sign = subprocess.Popen(['util/backdoor/sign', nonce], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
sig = sign.communicate()[0].strip().decode('hex')

p.send(p32(len(sig)))
p.send(sig)
flag = p.recv(4)
print 'flag', repr(flag)
