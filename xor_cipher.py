import os
from typing import List

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

def main():
    message = input('Enter the message to encrypt: ').encode()
    key_input = input('Enter the key (16 bytes recommended, leave blank for random): ')
    block_size = 16
    if key_input:
        key = key_input.encode()
        if len(key) < block_size:
            key = key.ljust(block_size, b'0')
        elif len(key) > block_size:
            key = key[:block_size]
    else:
        key = os.urandom(block_size)
    mode = input('Select mode (ECB/CBC): ').strip().upper()

    def bytes_to_bin(data: bytes) -> str:
        return ''.join(f'{byte:08b}' for byte in data)

    def bin_to_ascii(bin_str: str) -> str:
        chars = []
        for i in range(0, len(bin_str), 8):
            byte = bin_str[i:i+8]
            if len(byte) == 8:
                chars.append(chr(int(byte, 2)))
        return ''.join(chars)

    if mode == 'ECB':
        enc = ecb_encrypt(message, key, block_size)
        bin_enc = bytes_to_bin(enc)
        ascii_enc = bin_to_ascii(bin_enc)
        print('Encrypted (ASCII):', ascii_enc)
    elif mode == 'CBC':
        iv_input = input('Enter IV (16 bytes recommended, leave blank for random): ')
        if iv_input:
            iv = iv_input.encode()
            if len(iv) < block_size:
                iv = iv.ljust(block_size, b'0')
            elif len(iv) > block_size:
                iv = iv[:block_size]
        else:
            iv = os.urandom(block_size)
        enc = cbc_encrypt(message, key, iv, block_size)
        bin_enc = bytes_to_bin(enc)
        ascii_enc = bin_to_ascii(bin_enc)
        print('Encrypted (ASCII):', ascii_enc)
    else:
        print('Invalid mode selected.')

if __name__ == '__main__':
    main()

# To run this script, execute this command in your terminal: python xor_cipher.py