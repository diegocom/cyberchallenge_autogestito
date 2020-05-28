from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA256, SHA512


key_digest = '31af112461ca634ea7468e685a6edec4b63a1b1a324a2d77e2172d0d14a84ac455c7448836ec9ab98a614e14487e010ed88ef80f081a7bf911b8e20e04e1c9d7'
iv = b64decode('750dddjhwyJSJ2YhRFZAjw==')
flag = b64decode('L1i39WIWpALQBHZiZWzXdU/mCzwD6pbVZowcJiGUz237mfOBEuYK3/dpJMHq+DP4')

pswd = input('Insert password: ').encode()
pswd_digest = SHA256.new(pswd).digest()
pswd_digest2 =SHA512.new(pswd_digest).hexdigest()


if(pswd_digest2 == key_digest):
    cipher = AES.new(pswd_digest, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(flag), AES.block_size)
    print('You did it: ', pt.decode('utf-8'))
else:
    print("lol nope")


