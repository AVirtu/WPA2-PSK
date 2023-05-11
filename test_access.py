import hashlib
import binascii, hmac
import math
from binascii import a2b_hex



ssid = 'MyHomeWIFI' # Name of network
passPhrase = "mypass123" # Password


pmk_hex = hashlib.pbkdf2_hmac('sha256', passPhrase.encode(), ssid.encode(), 4096, 256)[:64]
pmk = binascii.b2a_base64(pmk_hex).decode()



def PRF512(pmk, A, B):
    B = B.encode()
    byte_pmk = pmk.encode()
    file = open('PTKAP.txt', 'w')
    ptk1 = hmac.new(byte_pmk, A.encode() + B, hashlib.sha256).hexdigest()
    ptk2 = hmac.new(byte_pmk, A.encode() + B, hashlib.sha256).hexdigest()
    ptk3 = hmac.new(byte_pmk, A.encode() + B, hashlib.sha256).hexdigest()
    ptk4 = hmac.new(byte_pmk, A.encode() + B, hashlib.sha256).hexdigest()
    ptk = ptk1 + ptk2 + ptk3 + ptk4[0:4]
    ptk = binascii.b2a_base64(a2b_hex(ptk)).decode()
    file.write(ptk)
    return file.close()




A = "Pairwise key expansion\0"

f_1 = open('APMAC.txt', 'w')
APmac = a2b_hex("20dce64f6c90") # MAC-address of router
f_1.write('20dce64f6c90')
f_1.close()


f_2 = open('ANOUNCE.txt', 'w')
ANonce = a2b_hex("3320ced2535ed697d52c272aeea799d4d188a4603142f37a240f8064d7cdf588")
f_2.write('3320ced2535ed697d52c272aeea799d4d188a4603142f37a240f8064d7cdf588')
f_2.close()

f1 = open('CLIENTMAC.txt', 'r')
Clientmac = f1.read()
Clientmac = a2b_hex(Clientmac) # MAC-address of client
f1.close()

f2 = open('SNOUNCE.txt', 'r')
SNonce = f2.read()
SNonce = a2b_hex(SNonce)
f2.close()


B = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce, SNonce)
B = binascii.b2a_base64(B).decode()




ptk = PRF512(pmk, A, B)

f3 = open('PTKAP.txt', 'r')
ptk_ap = f3.read()
print("PTKAP: ", ptk_ap)
f3.close()

print("PMKAP: ", pmk)
