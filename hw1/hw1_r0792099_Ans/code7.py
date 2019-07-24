# coding=utf-8
# https://www.cnblogs.com/pcat/p/5478509.html
# https://github.com/bwall/HashPump
# https://www.youtube.com/watch?v=sMla6_4Z-CQ
# https://www.youtube.com/watch?v=nqXhZAj0yr4
import hashpumpy
import os
import random
import hashlib
import base64
from pwn import *

def sha256(data):
    m = hashlib.sha256()
    m.update(data)
    return m.hexdigest()

sys.dont_write_bytecode = True
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
sys.stdin = os.fdopen(sys.stdin.fileno(), 'r', 0)
r = remote("140.112.31.96" , 10154)
# get Token of Balsn coin = 1
print r.recv()
print r.recv()
r.sendline('2')
print r.recv()
print r.recv()
# 選擇拿 1 個 coin 的 Token
r.sendline('1')
print r.recv()
token = r.recv()
# original = 1 個 coin 的 digest
original_digest = (token.split("Token")[1].split('='))[0].strip(': \n')

print original_digest
r.sendline('3')
msg = r.recv()
print 'here',msg
msg = r.recv()
print 'here',msg


# original_digest = 'dcc71d18341f4bffc9895622a9abe57774f6c64c32849f0b9506e895fd618bd3'
# print "original_digest =",original_digest

# # 利用 "key={}&BALSN_Coin=1" 的 digest 製造 "key={}&BALSN_Coin=1000"的 digest。
# # key 的長度會變動，但 key 的內容對 append data 不重要。
for random_part_length in range(40,51):
    key = "key={}".format(os.urandom(random_part_length))
    key = key + "&BALSN_Coin="

    original_data = "1"
    data_to_add   = "&BALSN_Coin=1000"

    # create Hash(key | original_data | data_to_add)
    new_digest, new_data = hashpumpy.hashpump( original_digest , original_data , data_to_add , len(key) )
    print "b64 encode =",base64.b64encode(new_data)
    # print "b64 decode =",base64.b64decode(base64.b64encode(new_data))

    print "new_digest =",new_digest
    print "key length =",len(key)
    print "new_data   =",new_data,"\n"
    r.sendline(base64.b64encode(new_data))
    msg = r.recv()
    print "here",msg
    msg = r.recv()
    r.sendline(new_digest)
    msg = r.recv()
    if msg != "Invalid Token":
        print "Get Correct Digest."
        print "======================>",msg
        msg = r.recv()
        print "after==>",msg
        break
    msg = r.recv() # main page
    print "here",msg
    r.sendline('3')
    msg = r.recv()
    print 'here',msg
    msg = r.recv()
    print 'here',msg
    # print "correct =",sha256(key + original_data + data_to_add)
    # print "hash(key + new_data) =",sha256(key + new_data),"\n\n"


