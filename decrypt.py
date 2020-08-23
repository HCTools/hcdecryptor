from argparse import ArgumentParser

from typing import Callable, List, ByteString, Tuple, NamedTuple, Dict, NewType

from base64 import b64decode

from Crypto.Hash import SHA1
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

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
    'udpgwPort',
    'lockPayload',
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
    b64_encrypted_contents = b""

    for index in range(len(contents)):
        b64_encrypted_contents += bytes([ord(contents[index]) ^ ord(xorList[index % len(xorList)])])

    # base64 decode the file
    encrypted_contents = b64decode(b64_encrypted_contents)

    # then use the plain decryptor
    return decrypt_plain(encrypted_contents, key)

embeddedKeyList: str = """1:hc_reborn___7
1:hc_reborn_tester_5
1:hc_reborn_7
1:hc_reborn_4
"""

# parse arguments
parser = ArgumentParser('hcdecryptor')
parser.add_argument('file', help='file to decrypt')

key_args = parser.add_mutually_exclusive_group()
key_args.add_argument('--key', '-k', help='key to use to decrypt the file')
key_args.add_argument('--keyfile', '-K', help='keyfile to additionally look for keys in')

parser.add_argument('--raw', '-r', action='store_true', help='output raw, decrypted file')
args: NamedTuple = parser.parse_args()

# parse keyfile
def parse_key_entry(entry: str):
    key_list = entry.split(':', 1)

    return (int(key_list[0]), key_list[1].strip())

if not args.key:
    keylist = set(embeddedKeyList.splitlines())

    if args.keyfile:
        keyfile = open(args.keyfile, 'r')
        keyfile_contents = set(keyfile.readlines())

        keylist = keylist | keyfile_contents

    keylist = list(map(parse_key_entry, keylist))

# open file
xor_b64_encrypted_file = open(args.file, mode='r')
xor_b64_encrypted_contents: ByteString = xor_b64_encrypted_file.read()

print(f'Opened {args.file}')

original_contents: str = ''

for index in range(len(keylist)):
    key = keylist[index]

    print(f'Trying key {key[1]}')

    decrypted_contents: ByteString = encryption_schemes[key[0]](xor_b64_encrypted_contents, key[1])

    try:
        original_contents = decrypted_contents.decode('utf-8')
    except UnicodeDecodeError:
        if index >= len(keylist):
            print('Ran out of keys!')
            exit(1)

        print('Wrong key, trying next one...')

    if 'splitConfig' in original_contents:
        print(f'Successfully decrypted {args.file} with key {key[1]}')
        break

if not args.raw:
    config: List[str] = original_contents.split('[splitConfig]')
    values: Dict[str, str] = dict(zip(valueMap, config))

    print(values)
else:
    print(original_contents)
