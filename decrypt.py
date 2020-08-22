from argparse import ArgumentParser

from base64 import b64decode

from Crypto.Hash import SHA1
from Crypto.Cipher import AES

xorList = ['。', '〃', '〄', '々', '〆', '〇', '〈', '〉', '《', '》', '「', '」', '『', '』', '【', '】', '〒', '〓', '〔', '〕']

# parse arguments
parser = ArgumentParser('hcdecryptor')
parser.add_argument('file', help='file to decrypt')
parser.add_argument('key', help='key to decrypt the file with')
args = parser.parse_args()

# open file
xor_b64_encrypted_file = open(args.file, mode='r')
xor_b64_encrypted_contents = xor_b64_encrypted_file.read()

print(f'Opened file "{args.file}"')

# unxor the file
print('UnXORing the file')
b64_encrypted_contents = b''

for index in range(len(xor_b64_encrypted_contents)):
    b64_encrypted_contents += bytes([ord(xor_b64_encrypted_contents[index]) ^ ord(xorList[index % len(xorList)])])

# base64 decode the file
print('Decoding the file from Base64')
encrypted_contents = b64decode(b64_encrypted_contents)

# decrypt the file
decryption_key = SHA1.new(data=bytes(args.key, 'utf-8')).digest()[:16]

print(f'Decrypting the file with key "{args.key}"')
original_contents = AES.new(decryption_key, AES.MODE_ECB).decrypt(encrypted_contents)

print(original_contents)
