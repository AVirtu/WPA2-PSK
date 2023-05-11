import hashlib
import binascii, hmac
from binascii import a2b_hex
from tkinter import *
from tkinter import messagebox


root = Tk()
root.title('Authentication ')
root.geometry('300x150')
root.resizable(False, False)


message1_lbl = Label(root, text = 'MyHomeWIFI', font=("Arial", 14))
message1_lbl.grid(row=0, column=0, columnspan=2, ipadx=80, ipady=5, padx=5, pady=5)

message2_lbl = Label(root, text = 'Enter password', font=("Arial", 10))
message2_lbl.grid(row=5, column=0, sticky='w')

password1_entry = Entry(root)
password1_entry.grid(row=5, column=1, sticky='w')




ssid = 'MyHomeWIFI' # Name of network


def authentication():
    ssid = 'MyHomeWIFI'
    password = password1_entry.get()


    def get_pmk():
        pmk_hex = hashlib.pbkdf2_hmac('sha256', password.encode(), ssid.encode(), 4096, 256)[:64]
        pmk = binascii.b2a_base64(pmk_hex).decode()

        return pmk

    pmk = get_pmk()


    f2 = open('SNOUNCE.txt', 'w')
    SNonce = a2b_hex('b4455d0bc446645c5957434f653ad0bfa59f6be1a265fbf33b7d547b1b484534')
    f2.write('b4455d0bc446645c5957434f653ad0bfa59f6be1a265fbf33b7d547b1b484534')
    f2.close()

    f1 = open('CLIENTMAC.txt', 'w')
    Clientmac = a2b_hex('e0b9a51fe794') # MAC-address of client
    f1.write('e0b9a51fe794')
    f1.close()

    import test_access

    def PRF512(pmk, A, B):
        B = B.encode()
        byte_pmk = pmk.encode()
        file = open('PTKCLNT.txt', 'w')
        ptk1 = hmac.new(byte_pmk, A.encode() + B, hashlib.sha256).hexdigest()
        ptk2 = hmac.new(byte_pmk, A.encode() + B, hashlib.sha256).hexdigest()
        ptk3 = hmac.new(byte_pmk, A.encode() + B, hashlib.sha256).hexdigest()
        ptk4 = hmac.new(byte_pmk, A.encode() + B, hashlib.sha256).hexdigest()
        ptk = ptk1 + ptk2 + ptk3 + ptk4[0:4]
        ptk = binascii.b2a_base64(a2b_hex(ptk)).decode()
        file.write(ptk)
        return file.close()



    A = 'Pairwise key expansion\0'

    f_2 = open('APMAC.txt', 'r')
    APmac = f_2.read() # MAC-address of router
    APmac = a2b_hex(APmac)
    f_2.close()



    f_1 = open('ANOUNCE.txt', 'r')
    ANonce = f_1.read()
    ANonce = a2b_hex(ANonce)
    f_1.close()


    B = min(APmac, Clientmac) + max(APmac, Clientmac) + min(ANonce, SNonce) + max(ANonce, SNonce)
    B = binascii.b2a_base64(B).decode()


    ptk_client = PRF512(pmk, A, B)

    f3 = open('PTKAP.txt', 'r')
    ptk_ap = f3.read()
    f3.close()

    f_3 = open('PTKCLNT.txt', 'r')
    ptk_client = f_3.read()
    print('PTKCLNT:', ptk_client)
    f_3.close()

    print("PMKCLNT: ", pmk)


    if ptk_client == ptk_ap:
        messagebox.showinfo("Успех", "Аутентификация прошла успешно!")
        root.destroy()
    else:
        messagebox.showerror("Ошибка!", "Неверный пароль!")
        root.destroy()

btn1 = Button(root, text='Enter', command=authentication)
btn1.grid(row=6, columnspan=3, padx=5, pady=5)

root.mainloop()

