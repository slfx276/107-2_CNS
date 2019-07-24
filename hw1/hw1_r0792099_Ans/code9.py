# -*- coding: UTF-8 -*-
# http://math.ntnu.edu.tw/~li/Crypt/Note4.pdf
# https://github.com/mcerovic/PohligHellman/blob/master/pohlig_hellman.py
# http://factordb.com/index.php?query=28661294800114069007768236017771012251607018576093986823286814149509513675452275635042638987354048629725185006983949952108837417118101024196427874059746112373146674688108102191658628381225899560628677933856157056627887468689106995559937935463599189450455206845179774222254667824788120465189001600194073757297794949787319524466635098273575710447185401574795742616708210395524755264624260682423348748123914632427585203446721466593339015399125761744284777424125509546314701569108898934480431326685681803242146702497611445457941195705272186806178159360836165609438994389786824034040397877095231384671425898312053134662668


from random import randint

# with open('./flag') as f:
#     flag = f.read()

# 21415417452862385822209271012817793150895390435770476978046862065625337202884791511920664986408841095900654738070236727797129762672224612357265828740478833337740444073740756067502998861070838401401680603766287937704416650587657439702450162322209198221779685030352473193878589584731120025567610438855058432121554123472417518418523366569057525298543223124010040598652144578966584834782274187095435034339994426555536056645750433383503505768388846624008773128977330539145239402105552071835989196181032937384073405971339677972093187563528876255816400751585513195407386698978227320390696973150369705374547095189643212682512
p = 28661294800114069007768236017771012251607018576093986823286814149509513675452275635042638987354048629725185006983949952108837417118101024196427874059746112373146674688108102191658628381225899560628677933856157056627887468689106995559937935463599189450455206845179774222254667824788120465189001600194073757297794949787319524466635098273575710447185401574795742616708210395524755264624260682423348748123914632427585203446721466593339015399125761744284777424125509546314701569108898934480431326685681803242146702497611445457941195705272186806178159360836165609438994389786824034040397877095231384671425898312053134662669
# p-1 =  2^2 · 691829 · 1035707335...23

g = 16078909570239876795055844516958246040709670677352681543313753053742973386508316274779434207505711677850871497649465535051866957457021948204451138330623660110191150301811323442658421231468580615274747861693791813916691182214785963319378314164808593693096050898468910883788576053845247354173273067934871765729622501051769175928793373665854926345829773055861683607699372255679226577615328998611278891869859367786539895393361508257631990706373751978989473197793935179727162255300656316829056421905796513359716410495375718068635872275352455310154328769091838733283528171239199077479704783804081954231420368626696801127642

A = 9340452235281687649179730131347600098035863140428398900981411533633371264718145252165753061065519626540250139067066846166158109482861629930934553097060819398166910839016649649389400890564461994003517904562426085846135074299789413165048217091262887032553237951780946374567140045468137848997309879390015437159256440742904227487263694000680455249547753807999100362666118355759928723607488280501640696133337414383498319589705206603309621303727416574866970950071925883156805160340145795061042509620095769270530810442957140774320438686238478056698045187991043722493407959150698880688428379196792889590689932219828874647750
# B = input('Enter the public key you recieved: ') # Received g^b
B = 26923678295279019615441397805045962794004606567356312544405381922111654086218407546817914506984351145096161124431937703671408667110573346077797775065061005655125448280034263489750362311512284835239408247678109055129780522865641310684720459200881605571205689031364461558771208172858717637782802878739859330877034107783974891564334345018138580903618219381613763392446297669870167803434140046176854035263846037467714326529961765466554973348241899513352858975305014553164351658927866277335110203514745977353702879859614780742308712391605520182472687426382896587151667314003989030444701542438790937903449260688071080288807
cipher = 21415417452862385822209271012817793150895390435770476978046862065625337202884791511920664986408841095900654738070236727797129762672224612357265828740478833337740444073740756067502998861070838401401680603766287937704416650587657439702450162322209198221779685030352473193878589584731120025567610438855058432121554123472417518418523366569057525298543223124010040598652144578966584834782274187095435034339994426555536056645750433383503505768388846624008773128977330539145239402105552071835989196181032937384073405971339677972093187563528876255816400751585513195407386698978227320390696973150369705374547095189643212682512

a = 0 # Alice's random private key
# Brute force search Alice's secret key a
a = 352497 # by loop below
# for i in range(691829):
#     if pow(g , i , p) == A:
#         a = i
#         print "Alice's secret key = ",i
#         break

s = pow(B, a, p) # s = g^(ab) (mod p)
s_inverse = pow(B , 691829-a , p)  # s * s_inverse = 1 (mod p)
message = cipher * s_inverse % p

message = hex(message)[2:].rstrip("L")
if len(message) % 2 != 0: # if odd string
    message = "0" + message
print(message.decode('hex'))

