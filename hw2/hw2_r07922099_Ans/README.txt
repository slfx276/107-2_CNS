
Q4-1.

$ python3 code4_NSprotocol.py

Q4-2.

$ python3 code4_NSprotocol.py

(�ھ���ܰT�����ܽƻs Nb�A�èϥΥt�@��terminal����code4_subProgram.py)

$ python3 code4_subProgram.py

(�K�W��~�ƻs�� Nb �@�� input)
(�ھ�code4_subProgram.py ��ܪ��T���ƻs msg2)
(�K�W msg2 �� code4_NSprotocol.py �� terminal ����)


Q5 (�ϥ�python2) �ϥήM��Ggmpy,libnum,RsaCtfTool


1. (Export Packet Bytes of Server's certificate as "certificate.der" from wireshark)
2. $ cd ~/Desktop
3. $ openssl x509 -inform DER -in certificate.der -pubkey -noout > key.pub
4. $ python ./RSACtf/RsaCtfTool.py --publickey ~/Desktop/key.pub --verbose --private
5. copy private key message into file "private.key"
6. use private.key decrypt packet with wireshark


Q6. (�ϥ�python2)

$ python code6_dos.py

