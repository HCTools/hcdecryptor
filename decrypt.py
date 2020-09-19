#!/usr/bin/env python3
'''
Copyright (C) 2020  HCTools

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
'''

# print a GPL notice
copyrightNotice = '''HCDecryptor, Copyright (C) 2020  HCTools\n
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it under certain conditions.
'''
print(copyrightNotice)

from argparse import ArgumentParser

from typing import Callable, List, ByteString, Tuple, Dict, NewType

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

xorList = ['。', '〃', '〄', '々', '〆', '〇', '〈', '〉', '《', '》', '「', '」', '『', '』', '【', '】', '〒', '〓', '〔', '〕']

def decrypt(contents, key):
    decryption_key = SHA1.new(data=bytes(key, 'utf-8')).digest()[:16]

    return AES.new(decryption_key, AES.MODE_ECB).decrypt(contents)

def deobfuscate(contents):
    encrypted_string = contents.decode('utf-8')
    deobfuscated_contents = b''

    for index in range(len(encrypted_string)):
        deobfuscated_contents += bytes([ord(encrypted_string[index]) ^ ord(xorList[index % len(xorList)])])

    return b64decode(deobfuscated_contents)

embeddedKeyList = '''1:hc_reborn___7
1:hc_reborn_tester
1:hc_reborn_tester_5
1:hc_reborn_7
1:hc_reborn_6
1:hc_reborn_5
1:hc_reborn_4
1:hc_reborn_3
1:hc_reborn_2
1:hc_reborn_1
0:hc_reborn10
0:hc_reborn9
0:hc_reborn8
0:hc_reborn7
0:keY_secReaT_hc
0:keY_secReaT_hc1
0:keY_secReaT_hc2
0:keY_secReaT_hc_reborn
0:keY_secReaT_hc_reborn1
0:keY_secReaT_hc_2
0:keY_secReaT_hc_reborn3
0:keY_secReaT_hc_reborn4
0:keY_secReaT_hc_reborn5
0:keY_secReaT_hc_reborn6
0:keY_secReaT_te4Z9
0:keY_secReaT_te4Z10
0:keY_secReaT_te4Z11
0:keY_secReaT_e
'''

# parse arguments
parser = ArgumentParser('hcdecryptor')

parser.add_argument('file', help='file to decrypt')

key_args = parser.add_mutually_exclusive_group()
key_args.add_argument('--key', '-k', help='key to use to decrypt the file')
key_args.add_argument('--keyfile', '-K', help='keyfile to additionally look for keys in')

parser.add_argument('--raw', '-r', action='store_true', help='output raw, decrypted file')
args = parser.parse_args()

# parse keyfile
def parse_key_entry(entry):
    key_list = entry.split(':', 1)

    return (bool(int(key_list[0])), key_list[1].strip())

if not args.key:
    keylist = set(embeddedKeyList.splitlines())

    if args.keyfile:
        keyfile = open(args.keyfile, 'r')
        keyfile_contents = set(keyfile.readlines())

        keylist = keylist | keyfile_contents

    keylist = list(map(parse_key_entry, keylist))

# open file
encrypted_file = open(args.file, mode='rb')
encrypted_contents = encrypted_file.read()

print(f'Opened {args.file}')

try:
    contents = deobfuscate(encrypted_contents)
except:
    contents = encrypted_contents

original_contents = ''

if not args.key:
    for index in range(len(keylist)):
        key = keylist[index]

        print(f'Trying key {key[1]}')

        try:
            original_contents = decrypt(contents, key[1]).decode('utf-8')
        except:
            if index >= len(keylist):
                print('Ran out of keys!')
                exit(1)

            print('Wrong key, trying next one...')

        if 'splitConfig' in original_contents:
            print(f'Successfully decrypted {args.file} with key {key[1]}')
            break
else:
    try:
        original_contents = decrypt(deobfuscated_contents, args.key).decode('utf-8')
    except:
        print('Wrong key!')
        exit(1)

if not args.raw:
    config = original_contents.split('[splitConfig]')
    values = dict(zip(valueMap, config))

    print(values)
else:
    print(original_contents)
