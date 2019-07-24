from pwn import *
import os
import re


print("hello world")
r = remote("140.112.31.97", 10160)

f1 = "BALSN{This_!5_7h3_34sy_onE}"
f2 = "BALSN{FuzZZZzzzZZzzZzZZZZZzz!nGGG}"
f3 = "BALSN{FUzziNG_i5_S0_Fun!}"
f4 = "BALSN{G0od_LucK_K33P_Try!nG}"
f5 = "BALSN{N0w_Y0u_UnD3RS7aND_H0w_Fuzz3r_W0rK_^^}"
pattern = re.compile(r"BALSN(.)+}")

i = 0
flag = []
while True:
    guess = os.urandom(20)
    r.sendline(guess)
    response = str(r.recv())
    if i % 5000 == 0:
        print ("i = ",i)
    if 'B' in response :
        # print("Send: {}\n   Response:\n{} ".format(guess, response))
        result = pattern.search(response).group()
        if not (result in flag):
            print(result)
            flag.append(result)
        
    i += 1
    
print("Flag set = ", response)
