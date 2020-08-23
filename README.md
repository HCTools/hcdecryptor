# hcdecryptor
Decryptor for HTTP Custom configuration files 

Decrypts files with `.hc` extension, for the app [HTTP Custom](https://play.google.com/store/apps/details?id=xyz.easypro.httpcustom)

## Requirements

    python3
    pycryptodome

## Usage

Simply place your `encrypted.hc` file in the same folder as the main script, then run:

    python3 decrypt.py encrypted.hc <key>

## Keys

The keys change between some versions. The most recent key that should work with recent files is `hc_reborn_4`

The most recent public beta key is `hc_reborn_7`
