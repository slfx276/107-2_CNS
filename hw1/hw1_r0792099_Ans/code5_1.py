# -*- coding: UTF-8 -*-
# Decrypt
from pwn import *
import time
import random

# time seed = 1554356401
# ylYG69TVAzBSgNvhNC/ZqKe7EEZB68oisw==

print "\nstart time = ",int(time.time())
# nc server
r = remote("140.112.31.96" , 10152)
# record server's time seed
t = int(time.time()) 
# msg = (bytes.decode(r.recv())).strip('\n')
msg = r.recv().strip('\n')
print msg.strip('\n')
end_time = int(time.time())
print "end time = ",end_time

# reset random.seed
random.seed(t)
msg = base64.b64decode(msg)
decrypted = [ord(i)^ random.randint(0,255) for i in msg]
char_decrypted = [chr(i) for i in decrypted]
print "".join(char_decrypted)

#     flag = "BALSN{7ime_Se3d_Cr4ck!n9}"