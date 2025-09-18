import tkinter as tk
from tkinter import ttk, messagebox
import os

def xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def ecb_encrypt(plaintext: bytes, key: bytes, block_size: int = 16) -> bytes:
    plaintext = pad(plaintext, block_size)
    ciphertext = b''
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i+block_size]
        ciphertext += xor_bytes(block, key)
    return ciphertext

def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes, block_size: int = 16) -> bytes:
    plaintext = pad(plaintext, block_size)
    ciphertext = b''
    prev = iv
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i+block_size]
        xored = xor_bytes(block, prev)
        encrypted = xor_bytes(xored, key)
        ciphertext += encrypted
        prev = encrypted
    return ciphertext

def bytes_to_bin(data: bytes) -> str:
    return ''.join(f'{byte:08b}' for byte in data)

def bin_to_ascii(bin_str: str) -> str:
    chars = []
    for i in range(0, len(bin_str), 8):
        byte = bin_str[i:i+8]
        if len(byte) == 8:
            chars.append(chr(int(byte, 2)))
    return ''.join(chars)

def encrypt():
    message = entry_message.get().encode()
    key_input = entry_key.get()
    block_size = 16
    mode = mode_var.get()
    if key_input:
        key = key_input.encode()
        if len(key) < block_size:
            key = key.ljust(block_size, b'0')
        elif len(key) > block_size:
            key = key[:block_size]
    else:
        key = os.urandom(block_size)
        entry_key.delete(0, tk.END)
        entry_key.insert(0, key.decode(errors='replace'))
        messagebox.showinfo('Random Key', f'Random key used: {key}')
    if mode == 'ECB':
        enc = ecb_encrypt(message, key, block_size)
        bin_enc = bytes_to_bin(enc)
        ascii_enc = bin_to_ascii(bin_enc)
        result_var.set(ascii_enc)
    elif mode == 'CBC':
        iv_input = entry_iv.get()
        if iv_input:
            iv = iv_input.encode()
            if len(iv) < block_size:
                iv = iv.ljust(block_size, b'0')
            elif len(iv) > block_size:
                iv = iv[:block_size]
        else:
            iv = os.urandom(block_size)
            entry_iv.delete(0, tk.END)
            entry_iv.insert(0, iv.decode(errors='replace'))
            messagebox.showinfo('Random IV', f'Random IV used: {iv}')
        enc = cbc_encrypt(message, key, iv, block_size)
        bin_enc = bytes_to_bin(enc)
        ascii_enc = bin_to_ascii(bin_enc)
        result_var.set(ascii_enc)
    else:
        result_var.set('Invalid mode selected.')


root = tk.Tk()
root.title('XOR ECB/CBC Encryption')
root.resizable(False, False)  # Disable maximize/fullscreen

frame = ttk.Frame(root, padding=20)
frame.grid(row=0, column=0)

# Message
label_message = ttk.Label(frame, text='Message:')
label_message.grid(row=0, column=0, sticky='e')
entry_message = ttk.Entry(frame, width=40)
entry_message.grid(row=0, column=1)

# Key
label_key = ttk.Label(frame, text='Key (16 bytes, blank=random):')
label_key.grid(row=1, column=0, sticky='e')
entry_key = ttk.Entry(frame, width=40)
entry_key.grid(row=1, column=1)

label_iv = ttk.Label(frame, text='IV (CBC only, blank=random):')
entry_iv = ttk.Entry(frame, width=40)

def update_iv_visibility(*args):
    if mode_var.get() == 'CBC':
        label_iv.grid(row=2, column=0, sticky='e')
        entry_iv.grid(row=2, column=1)
    else:
        label_iv.grid_remove()
        entry_iv.grid_remove()

mode_var = tk.StringVar(value='ECB')
mode_var.trace_add('write', update_iv_visibility)

# Mode
label_mode = ttk.Label(frame, text='Mode:')
label_mode.grid(row=3, column=0, sticky='e')
mode_menu = ttk.Combobox(frame, textvariable=mode_var, values=['ECB', 'CBC'], state='readonly')
mode_menu.grid(row=3, column=1)
update_iv_visibility()

# Encrypt button
button_encrypt = ttk.Button(frame, text='Encrypt', command=encrypt)
button_encrypt.grid(row=4, column=0, columnspan=2, pady=10)

# Result
label_result = ttk.Label(frame, text='Encrypted (ASCII from binary):')
label_result.grid(row=5, column=0, sticky='e')
result_var = tk.StringVar()
entry_result = ttk.Entry(frame, textvariable=result_var, width=40, state='readonly')
entry_result.grid(row=5, column=1)

root.mainloop()

# To run this script, execute this command in your terminal: python xor_cipher_gui.py