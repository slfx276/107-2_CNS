
Q4-1.

$ python3 code4_NSprotocol.py

Q4-2.

$ python3 code4_NSprotocol.py

(根據顯示訊息指示複製 Nb，並使用另一個terminal執行code4_subProgram.py)

$ python3 code4_subProgram.py

(貼上剛才複製的 Nb 作為 input)
(根據code4_subProgram.py 顯示的訊息複製 msg2)
(貼上 msg2 到 code4_NSprotocol.py 的 terminal 視窗)


Q5 (使用python2) 使用套件：gmpy,libnum,RsaCtfTool


1. (Export Packet Bytes of Server's certificate as "certificate.der" from wireshark)
2. $ cd ~/Desktop
3. $ openssl x509 -inform DER -in certificate.der -pubkey -noout > key.pub
4. $ python ./RSACtf/RsaCtfTool.py --publickey ~/Desktop/key.pub --verbose --private
5. copy private key message into file "private.key"
6. use private.key decrypt packet with wireshark


Q6. (使用python2)

$ python code6_dos.py

