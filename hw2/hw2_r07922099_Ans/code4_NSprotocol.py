# -*- coding: utf-8 -*-
#!/usr/bin/env python3
from pwn import *
import os
import time
from base64 import b64encode, b64decode
import logging
# from Cryptodome.Util.Padding import pad, unpad

# https://github.com/dlitz/pycrypto/blob/master/lib/Crypto/Util/Padding.py
#
#  Util/Padding.py :  Functions to manage padding
#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================

""" Functions to manage padding
This module provides minimal support for adding and removing standard padding
from data.
"""

__all__ = [ 'ValueError', 'pad', 'unpad' ]

from Crypto.Util.py3compat import *

def pad(data_to_pad, block_size, style='pkcs7'):
    """Apply standard padding.
    :Parameters:
      data_to_pad : byte string
        The data that needs to be padded.
      block_size : integer
        The block boundary to use for padding. The output length is guaranteed
        to be a multiple of ``block_size``.
      style : string
        Padding algorithm. It can be *'pkcs7'* (default), *'iso7816'* or *'x923'*.
    :Return:
      The original data with the appropriate padding added at the end.
    """

    padding_len = block_size-len(data_to_pad)%block_size
    if style == 'pkcs7':
        padding = bchr(padding_len)*padding_len
    elif style == 'x923':
        padding = bchr(0)*(padding_len-1) + bchr(padding_len)
    elif style == 'iso7816':
        padding = bchr(128) + bchr(0)*(padding_len-1)
    else:
        raise ValueError("Unknown padding style")
    return data_to_pad + padding

def unpad(padded_data, block_size, style='pkcs7'):
    """Remove standard padding.
    :Parameters:
      padded_data : byte string
        A piece of data with padding that needs to be stripped.
      block_size : integer
        The block boundary to use for padding. The input length
        must be a multiple of ``block_size``.
      style : string
        Padding algorithm. It can be *'pkcs7'* (default), *'iso7816'* or *'x923'*.
    :Return:
        Data without padding.
    :Raises ValueError:
        if the padding is incorrect.
    """

    pdata_len = len(padded_data)
    if pdata_len % block_size:
        raise ValueError("Input data is not padded")
    if style in ('pkcs7', 'x923'):
        padding_len = bord(padded_data[-1])
        if padding_len<1 or padding_len>min(block_size, pdata_len):
            raise ValueError("Padding is incorrect.")
        if style == 'pkcs7':
            if padded_data[-padding_len:]!=bchr(padding_len)*padding_len:
                raise ValueError("PKCS#7 padding is incorrect.")
        else:
            if padded_data[-padding_len:-1]!=bchr(0)*(padding_len-1):
                raise ValueError("ANSI X.923 padding is incorrect.")
    elif style == 'iso7816':
        padding_len = pdata_len - padded_data.rfind(bchr(128))
        if padding_len<1 or padding_len>min(block_size, pdata_len):
            raise ValueError("Padding is incorrect.")
        if padding_len>1 and padded_data[1-padding_len:]!=bchr(0)*(padding_len-1):
            raise ValueError("ISO 7816-4 padding is incorrect.")
    else:
        raise ValueError("Unknown padding style")
    return padded_data[:-padding_len]

from Crypto.Cipher import AES

BLOCK_SIZE = 16
KEY_SIZE = 32
NONCE_SIZE = 32

def getRandom(n):
    val = os.urandom(n)
    return val

def encrypt(msg, iv, key):
    '''
    丟 bytes(msg)進來 encrypt
    '''
    msg = pad(msg, BLOCK_SIZE)
    aes = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    ciphertext = aes.encrypt(msg)
    return b64encode(ciphertext)

def decrypt(msg, iv, key):
    aes = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
    msg = b64decode(msg)
    plaintext = aes.decrypt(msg)
    plaintext = unpad(plaintext, BLOCK_SIZE)
    return bytes(plaintext)

# %% Q5-1
# ==============================================================
r = remote("140.112.31.97" , 10158)
print("\n")

# create {A,Na,Tb || IV_B}K_BS which B sened to server

# record IV_AB
IV_AB_information = str(r.recv(),'utf-8')
print("1. ",IV_AB_information)
IV_AB = IV_AB_information.split(":")[1].strip(' \n')
IV_AB = b64decode(bytes(IV_AB , encoding = 'utf-8'))
# print("1. " , str(r.recv(),'utf-8'))
r.recv() # main page
r.sendline("1")
print("2. " , str(r.recv() ,'utf-8')) # Initiating communication with B

##
## 注意幾乎所有資料型態都是 type, 只有輸入input才是string
## string 要能直接丟到 
## encrypte、decrypte fcuntion 的型態必須是 "b'123'"這種 string?

# ----------- first send --------------

Na = bytes('a'*32 , 'utf-8')
# Na = getRandom(NONCE_SIZE) # (bytes)

Na_b64 = str(b64encode(Na),'utf-8') # input type must be string
print("3.  Na_b64=" , Na_b64 , ", length = " , len(Na_b64) , ", type=" ,type(Na_b64))

r.sendline("A||" + Na_b64)

print("4.  first send =>" , "A||" + Na_b64)
print("5. " , str(r.recv(),'utf-8'))

text = str(r.recv(),'utf-8') # get B->S, msg1, msg2
print("6.  text = \n\n" , text , "\n" , sep="")
text = text.split(":")
BtoS = text[1].split("||")[2][:-3]

# get msg = {A,Na,Tb || IV_B}K_BS : (bytes)
BtoS_msg = bytes(BtoS,'utf-8')

print("7. " ,"Encrypted_BtoS_msg = ",BtoS_msg,", type=" ,type(BtoS_msg))

# get str(b64encode(Nb), 'utf-8')
Nb_b64 = text[2][1:-5]
print("\n8.  Nb_b64 = " , Nb_b64 , ", type=" , type(Nb_b64), sep="")
Nb = b64decode(Nb_b64) # (32 bytes)

print("9.  Nb = ", Nb,", type=" , type(Nb) , len(Nb))

encrypted_Nb = encrypt(Nb , IV_AB , Na)
print("10.  Encrypted_Nb = ", encrypted_Nb, ", type =" ,type(encrypted_Nb))

# ----------- second send --------------
print("11.  second send =>" ,  str(encrypted_Nb,'utf-8') + "||" + str(BtoS_msg,'utf-8') )
r.sendline(str(encrypted_Nb,'utf-8') + "||" + str(BtoS_msg,'utf-8') )


f = str(r.recv(),'utf-8').split(":")
print("f = " , f)


f = f[1][3:-2]
# print(bytes(f,'utf-8'))

# print(f)
flag = decrypt(bytes(f,'utf-8') , IV_AB , Na)
print("\nFLAG =>" ,flag)

print("\n")

# ## encryption test
# msg1 = bytes('{}||{}||{}'.format("B", Na_b64 , time.time()), 'utf-8')
# print("msg1= ",msg1)
# iv = getRandom(16)
# key = getRandom(32)
# msg1 = encrypt(msg1, iv , key)
# print(type(msg1) , msg1)
# print(str(msg1, 'utf-8'))
# # 用這樣的 string 可以被當 bytes 解碼
# msg1 = str(msg1,'utf-8')
# msg2 = decrypt(msg1,iv,key)
# print(msg2)

# %% Q5-2
print("---------------------- subsequent authentication -----------------------\n")

print("\n")

# get {A,K_AB,Tb || IV_B}K_BS
msg1 = text[3][1:-5]
print("1.  msg1 = ", msg1 )
print(str(r.recv(),'utf-8')) # main page
r.sendline('2')

print(str(r.recv(),'utf-8'),end="") # Continue communicating with B
print(str(r.recv(),'utf-8'))

# ------ old communication first send -------
r.sendline(Na_b64 + "||" + msg1)

Nb_b64 = str(r.recv(),'utf-8')
print(Nb_b64)
Nb_b64 = Nb_b64.split(":")[1][1:-1]
print(str(r.recv(),'utf-8')) # get {Na || IV_AB}K_AB

# # ------ new communication fist send --------

r = remote("140.112.31.97" , 10158)
print("\n" , str(r.recv(),'utf-8') , "\n" , str(r.recv(),'utf-8') , end="")
r.sendline('2')
print(str(r.recv(),'utf-8') , str(r.recv(),'utf-8'))
r.sendline(Nb_b64 + "||" + msg1)
print("!!!!!!!!! copy as input of code4_subProgram.py  \n=> " , str(r.recv(),'utf-8')) # get Nb
print(str(r.recv(),'utf-8')) # get {Na || IV_AB}K_AB
r.interactive()