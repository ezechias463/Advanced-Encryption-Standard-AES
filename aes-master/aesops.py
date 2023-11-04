
import string
from tkinter import Widget
from turtle import width
from aes import AES
import os
from hashlib import pbkdf2_hmac
from hmac import new as new_hmac, compare_digest

AES_KEY_SIZE = 16
HMAC_KEY_SIZE = 16
IV_SIZE = 16

SALT_SIZE = 16
HMAC_SIZE = 32

def get_key_iv(password, salt, workload=100000):
    """
    Stretches the password and extracts an AES key, an HMAC key and an AES
    initialization vector.
    """
    stretched = pbkdf2_hmac('sha256', password, salt, workload, AES_KEY_SIZE + IV_SIZE + HMAC_KEY_SIZE)
    aes_key, stretched = stretched[:AES_KEY_SIZE], stretched[AES_KEY_SIZE:]
    hmac_key, stretched = stretched[:HMAC_KEY_SIZE], stretched[HMAC_KEY_SIZE:]
    iv = stretched[:IV_SIZE]
    return aes_key, hmac_key, iv


def encrypt(mode, key, plaintext, workload=100000):
    """
    Encrypts `plaintext` with `key` using AES-128, an HMAC to verify integrity,
    and PBKDF2 to stretch the given key.

    The exact algorithm is specified in the module docstring.
    """
    if isinstance(key, str):
        key = key.encode('latin-1')
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('latin-1')

    ciphertext = b'0'
    salt = os.urandom(SALT_SIZE)
    key, hmac_key, iv = get_key_iv(key, salt, workload)

    if(mode == "cbc"):
        ciphertext = AES(key).encrypt_cbc(plaintext, iv)
    elif (mode == "pcbc"):
        ciphertext = AES(key).encrypt_pcbc(plaintext, iv)
    elif (mode == "cfb"):
        ciphertext = AES(key).encrypt_cfb(plaintext, iv)
    elif (mode == "ofb"):   
        ciphertext = AES(key).encrypt_ofb(plaintext, iv)
    elif (mode == "ctr"):   
        ciphertext = AES(key).encrypt_ctr(plaintext, iv)

    hmac = new_hmac(hmac_key, salt + ciphertext, 'sha256').digest()
    assert len(hmac) == HMAC_SIZE
    return hmac + salt + ciphertext


def decrypt(mode, key, ciphertext, workload=100000):
    """
    Decrypts `ciphertext` with `key` using AES-128, an HMAC to verify integrity,
    and PBKDF2 to stretch the given key.

    The exact algorithm is specified in the module docstring.
    """

    assert len(ciphertext) % 16 == 0, "Ciphertext must be made of full 16-byte blocks."

    assert len(ciphertext) >= 32, """
    Ciphertext must be at least 32 bytes long (16 byte salt + 16 byte block). To
    encrypt or decrypt single blocks use `AES(key).decrypt_block(ciphertext)`.
    """

    if isinstance(key, str):
        key = key.encode('latin-1')
    
    plaintext = b'0'

    hmac, ciphertext = ciphertext[:HMAC_SIZE], ciphertext[HMAC_SIZE:]
    salt, ciphertext = ciphertext[:SALT_SIZE], ciphertext[SALT_SIZE:]
    key, hmac_key, iv = get_key_iv(key, salt, workload)

    expected_hmac = new_hmac(hmac_key, salt + ciphertext, 'sha256').digest()
    assert compare_digest(hmac, expected_hmac), 'Ciphertext corrupted or tampered.'

    if(mode == "cbc"):
        plaintext = AES(key).decrypt_cbc(ciphertext, iv)
    elif (mode == "pcbc"):
        plaintext = AES(key).decrypt_pcbc(ciphertext, iv)
    elif (mode == "cfb"):
        plaintext = AES(key).decrypt_cfb(ciphertext, iv)
    elif (mode == "ofb"):   
        plaintext = AES(key).decrypt_ofb(ciphertext, iv)
    elif (mode == "ctr"):   
        plaintext = AES(key).decrypt_ctr(ciphertext, iv)

    return plaintext

__all__ = ["encrypt", "decrypt", "AES"]


if __name__ == '__main__':

    """Graphic User Interface"""
    import tkinter 
    from tkinter import ttk
    from tkinter import messagebox

    def press_encrypt():
        keyS = key_entry.get()
        messageS = ptext_entry.get("1.0",'end-1c')
        modeS = mode_entry.get().lower()

        if((keyS != "") and (modeS!= "") and (messageS != "")):
                key = keyS.encode('latin-1')
                message = messageS.encode('latin-1')
                mode = modeS    
                cipher = encrypt(mode, key, message)
                print(cipher)
                ctext_entry.delete("1.0",'end-1c')
                ctext_entry.insert(tkinter.END, cipher.decode('latin-1'))
        else:
            messagebox.showwarning(title="Error", message=":Mode, Key and Plain Text are required!")
    
    def press_decrypt():
        keyS = key_entry.get()
        messageS = ptext_entry.get("1.0",'end-1c')
        modeS = mode_entry.get().lower()

        if((keyS != "") and (modeS!= "") and (messageS != "")):
                key = keyS.encode('latin-1')
                message = messageS.encode('latin-1')
                mode = modeS    
                plain = decrypt(mode, key, message)
                ctext_entry.delete("1.0",'end-1c')
                ctext_entry.insert(tkinter.END, plain.decode('latin-1'))
        else:
            messagebox.showwarning(title="Error", message=":Mode, Key and Plain Text are required!")
        
    window = tkinter.Tk()
    window.title("Advanced Encryption Standard")

    frame = tkinter.Frame(window)
    frame.pack()

    mode_key_frame = tkinter.LabelFrame(frame, text="Encryption Mode & Key")
    mode_key_frame.grid(row=0, column=0, padx=20, pady=10)

    mode_label = tkinter.Label(mode_key_frame, text="Encryption mode :")
    mode_label.grid(row=0, column=0)
    key_label = tkinter.Label(mode_key_frame, text="Encryption key :")
    key_label.grid(row=1, column=0)

    mode_entry = ttk.Combobox(mode_key_frame, width=39, values=["CBC","PCBC","CFB","OFB","CTR"])
    key_entry = tkinter.Entry(mode_key_frame, width=42)
    mode_entry.grid(row=0, column=1)
    key_entry.grid(row=1, column=1)

    for Widget in mode_key_frame.winfo_children():
        Widget.grid_configure(padx=10, pady=5)

    plaintext_frame = tkinter.LabelFrame(frame, text="Plain Text")
    plaintext_frame.grid(row=1, column=0, sticky="news", padx=20, pady=10)

    ptext_entry = tkinter.Text(plaintext_frame, bg="cyan", height=5, width=45)
    ptext_entry.grid(row=0, column=0, padx=20, pady=10)

    button_frame = tkinter.LabelFrame(frame)
    button_frame.grid(row=2, column=0, sticky="news", padx=20, pady=10)

    button_encrypt = tkinter.Button(button_frame, bg="red", fg="white", width=20, text="Encrypt", command= press_encrypt)
    button_encrypt.grid(row=0, column=0,  padx=20, pady=10)

    button_decrypt = tkinter.Button(button_frame, bg="red", fg="white",width=20, text="Decrypt", command= press_decrypt)
    button_decrypt.grid(row=0, column=1,  padx=20, pady=10)

    ciphertext_frame = tkinter.LabelFrame(frame, text="Cipher Text")
    ciphertext_frame.grid(row=3, column=0, sticky="news", padx=20, pady=10)

    ctext_entry = tkinter.Text(ciphertext_frame, bg="cyan", height=10, width=45)
        
    ctext_entry.grid(row=0, column=0, padx=20, pady=10 )

    window.mainloop()
    