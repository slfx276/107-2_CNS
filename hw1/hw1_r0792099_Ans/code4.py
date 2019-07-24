# %%
# round 1
# 可用 python3 執行 
from pwn import *
import base64
r = remote("140.112.31.96" , 10151)
msg = r.recv()
print(msg)
r.sendline('2')
msg = (str(r.recv()).split('=')[1]).strip('\n []>:')[:-8]
r.sendline(msg)
msg = str(r.recv()) # round 1
print(msg) 
s = msg.split('=')[1].split('[')[0][1:-2]
print(s)
lower = [chr(97+i) for i in range(26)]
upper = [chr(65+i) for i in range(26)]

for shift in range(26):
    # print("shift =",shift , end = "  => ")  
    print(shift,"=", end="")
    for i in range(len(s)):
        if ord('a') <= ord(s[i]) <= ord('z')  :
            after = ord(s[i]) + shift
            if after > ord('z'):
                after -= 26
            print(chr(after) , end="")
        elif ord('A') <= ord(s[i]) <= ord('Z'):
            after = ord(s[i]) + shift
            if after > ord('Z'):
                after -= 26
            print(chr(after) , end="")
        else:
            print(s[i] , end = "")
    print("")

# select shift value of Ciesar
shift = int(input("Select shift value: "))

round1_result = ""
for i in range(len(s)):
        if ord('a') <= ord(s[i]) <= ord('z')  :
            after = ord(s[i]) + shift
            if after > ord('z'):
                after -= 26
            round1_result += chr(after)
        elif ord('A') <= ord(s[i]) <= ord('Z'):
            after = ord(s[i]) + shift
            if after > ord('Z'):
                after -= 26
            round1_result += chr(after)
        else:
            round1_result += s[i]
print(round1_result)
r.sendline(round1_result)



# %%
# round 2 - observe shift value

msg = str(r.recv()) # round 2 message

c1 = msg.split('=')[1][1:-9].strip(' \n')
m1 = msg.split('=')[2][1:-9].strip(' \n')
c2 = msg.split('=')[3][1:-8].strip(' \n\\')
# print("c1=",c1)
# print("m1=",m1)
# print("c2=",c2)


alphabet = [chr(i + ord('a')) for i in range(26)]

# new record shift value - find key
shift_list = [-1,-1,-1,-1,-1,-1,-1]

for i in range(len(m1)):
    if ord('a') <= ord(m1[i]) <= ord('z') or ord('A') <= ord(m1[i]) <= ord('Z'):
        value = ( ord(m1[i]) - ord(c1[i]) ) % 26
        if shift_list[i % 7] != value:
            shift_list[i % 7] = value

print("round2 key list = ",shift_list)

# 印出 shift value of m1-c1
# list_index = 0
# for i in range(len(c1)):
#     if ord('a') <= ord(c1[i]) <= ord('z') or ord('A') <= ord(c1[i]) <= ord('Z'):
#         print(alphabet[ shift_list[list_index] % 26 ] , end="")
#         list_index = (list_index + 1) % len(shift_list)
#     else:
#         print(c1[i],end = "")
# print("")

# Round 2 - calculate plaintext 2
list_index = 0
print(c2)
round2_result = ""
for i in range(len(c2)):
    # lower alphabet ciphertext
    if ord('a') <= ord(c2[i]) <= ord('z'):
        after = ord(c2[i]) + shift_list[list_index]

        if after > ord('z'):
            after -= 26
        elif after < ord('a'):
            after += 26
        print(chr(after) , end="")
        round2_result += chr(after)
    # upper alphabet ciphertext
    elif ord('A') <= ord(c2[i]) <= ord('Z'):
        after = ord(c2[i]) + shift_list[list_index]

        if after > ord('Z'):
            after -= 26
        elif after < ord('A'):
            after += 26
        print(chr(after) , end="")
        round2_result += chr(after)
    else:
        print(c2[i] , end="")
        round2_result += c2[i]

    list_index = (list_index + 1) % len(shift_list)
print("")
print("round2_result = ",round2_result)
r.sendline(round2_result.strip('\n '))
    
# %%
# Round 3
msg = str(r.recv())
print("\n\nhere",msg)


c1 = msg.split('=')[1][1:-9].strip(' \n')
m1 = msg.split('=')[2][1:-9].strip(' \n')
c2 = msg.split('=')[3][1:-9].strip(' \n\\')

print("c1=",c1)
print("m1=",m1)
print("c2=",c2)

# # c1 = 'iinretenepcrxeee s wttiintnehrgc i eterh'
# # m1 = 'interesting recent experience with their'

# # 4-row
# # c1 = "ts rnnmh olnokaded oercaews  pigriit,sne"
# # m1 = "their social networks, and spending more"
# # c2 = "psoe g a,rsi rmt.Tuheircnoeo, oonho hnetofnhwrtti"

# # 3-row
# # c1 = "gk sowhslir,os,e nwo oen h a iia neet rfsintofmeosmrtspeo"
# # m1 = "get know of someone who has similar interest, profession,"
# # c2 = "axlNo pcseeirirnneape o nypol a hr hi neetn eet m.tleenatrtsgc"

# # c1 = "seoraccsineai l t yhmleel dasieiarz  ecna"
# # m1 = "social media can really increase the size"
# # c2 = "meol.rp eoT eacpkmo erng inntfeoh cmegta ni liosedna"


# # Preprocessing
# text = """c1 = "nfpa  rocalis laetysunseotd,h us"tfm"  i"btn ud
# [+] m1 = "posts," but they can also find "mutual friends"
# [+] c2 = o inscca eaolsins ug  ncobeehlrht ootwtna oehdnrscek"""

# text = text.split('[+]')
# c1 = text[0].replace("c1 = " , "").strip('\n')
# m1 = text[1].replace(" m1 = " , "").strip('\n')
# c2 = text[2].replace(" c2 = " , "").strip('\n')
# # print(c1,m1,c2,sep="\n")


answer_row_num = 0
for num_row in range(2,27):
    row = [[] for i in range(num_row)]
    direction = 1
    row_index = 0
    for i in range(len(m1)):
        row[row_index].append(m1[i])
        row_index += direction
        if row_index == num_row:
            row_index -= 2
            direction = -1
        elif row_index == -1:
            row_index += 2
            direction = 1
    # find the corret row number
    flag = True
    count = 0
    for i in range(len(row)):
        for j in range(len(row[i])):
            # print(row[i][j] , end="")
            if row[i][j] != c1[count]:
                flag = False
                count = 0
                break
            count += 1
    #     print("")
    # print("\n")
    if flag == True:
        answer_row_num = num_row
        print("\nRow Num = " , answer_row_num)
        break

for i in range(len(row)):
    for j in range(len(row[i])):
        print(row[i][j] , end="")
print("")

# Decrept Rail Fence Cipher from source code
def decipher(cipherText, key):

	result = ""

	matrix = [["" for x in range(len(cipherText))] for y in range(key)]

	idx = 0
	increment = 1

	for selectedRow in range(0, len(matrix)):
		row = 0

		for col in range(0, len(matrix[ row ])):
			if row + increment < 0 or row + increment >= len(matrix):
				increment = increment * -1

			if row == selectedRow:
				matrix[row][col] += cipherText[idx]
				idx += 1
			
			row += increment
	
	matrix = transpose( matrix )
	for list in matrix:
		result += "".join(list)

	return result

def transpose( m ):
	
	result = [ [ 0 for y in range( len(m) ) ] for x in range( len(m[0]) ) ]
	
	for i in range( len(m) ):
		for j in range( len(m[0]) ):
			result[ j ][ i ] = m[ i ][ j ]
	
	return result
def rail_pattern(n):
    from itertools import cycle
    r = [i for i in range(n)]
    return cycle(r + r[-2:0:-1])
def decode(ciphertext, rails):
    p = rail_pattern(rails)
    indexes = sorted(range(len(ciphertext)), key=lambda i: next(p))
    result = [''] * len(ciphertext)
    for i, c in zip(indexes, ciphertext):
        result[i] = c
    return ''.join(result)

# print("round3==",decode(c2 , answer_row_num))
round3_result = str(decode(c2 , answer_row_num))
print("round3====",round3_result)
r.sendline(round3_result)


# #%%
# # Round 4
# # http://www.convertstring.com/zh_TW/EncodeDecode/Base64Decode?fbclid=IwAR0YQAigXjCpgSybY5UZWcbTnfbFcwhi6egcRMhbs2HWx4USGB9sTthdYwI


msg = str(r.recv())
print("round4 ===here\n" , msg)
c1 = msg.split('[+]')[1][6:-2]
print("round4 c1=" , c1)
print(c1,type(c1))
round4_result = base64.b64decode(c1)
print("round4_result = ",round4_result)
r.sendline(round4_result)
msg = r.recv()
print(msg) # Get flag



