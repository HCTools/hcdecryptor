from argparse import ArgumentParser

from typing import Callable, List, ByteString, NamedTuple, Dict, NewType

from base64 import b64decode

from Crypto.Hash import SHA1
from Crypto.Cipher import AES

valueMap: List[str] = [
    'payload', 
    'payloadProxyURL', 
    'shouldNotWorkWithRoot', 
    'lockPayloadAndServers', 
    'expiryDate', 
    'hasNotes', 
    'noteField2', 
    'sshAddress', 
    'onlyAllowOnMobileData', 
    'unlockRemoteProxy',
    'unknown',
    'vpnAddress',
    'sslSni',
    'shouldConnectUsingSSH',
    'lockPayload',
    'udpgwPort',
    'hasHWID',
    'hwid',
    'noteField1',
    'unlockUserAndPassword',
    'sslAndPayloadMode',
    'enablePassword',
    'password'
]

xorList: List[str] = ['。', '〃', '〄', '々', '〆', '〇', '〈', '〉', '《', '》', '「', '」', '『', '』', '【', '】', '〒', '〓', '〔', '〕']

DecryptFunction = NewType('DecryptFunction', Callable[[ByteString, str], ByteString])
encryption_schemes: List[DecryptFunction] = []

def encryption_scheme(func: DecryptFunction):
    global encryption_schemes
    encryption_schemes.append(func)

    return func

@encryption_scheme
def decrypt_plain(contents: ByteString, key: str) -> ByteString:
    decryption_key = SHA1.new(data=bytes(key, 'utf-8')).digest()[:16]

    return AES.new(decryption_key, AES.MODE_ECB).decrypt(contents)

@encryption_scheme
def decrypt_obfuscated(contents: ByteString, key: str) -> ByteString:
    # unxor the file
    b64_encrypted_contents = b''

    for index in range(len(contents)):
        b64_encrypted_contents += bytes([ord(contents[index]) ^ ord(xorList[index % len(xorList)])])

    # base64 decode the file
    encrypted_contents = b64decode(b64_encrypted_contents)

    # then use the plain decryptor
    return decrypt_plain(encrypted_contents, key)

# parse arguments
parser = ArgumentParser('hcdecryptor')
parser.add_argument('file', help='file to decrypt')
parser.add_argument('key', help='key to decrypt the file with')
args: NamedTuple = parser.parse_args()

# open file
xor_b64_encrypted_file = open(args.file, mode='r')
xor_b64_encrypted_contents: ByteString = xor_b64_encrypted_file.read()

print(f'Opened file "{args.file}"')

original_contents: ByteString = encryption_schemes[1](xor_b64_encrypted_contents, args.key)

config: List[str] = original_contents.split(b'[splitConfig]')
values: Dict[str, str] = dict(zip(valueMap, config))

print(values)
