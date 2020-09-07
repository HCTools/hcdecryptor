

# hcdecryptor

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Made by D4rkh3xx0r69420 and @LDLGD0

Decryptor for HTTP Custom configuration files

Decrypts files with `.hc` extension, for the app [HTTP Custom](https://play.google.com/store/apps/details?id=xyz.easypro.httpcustom)

## Requirements

    python3
    pycryptodome

## Installation

    git clone https://github.com/HCTools/hcdecryptor.git
    cd hcdecryptor
    pip3 install -r requirements.txt

Install dependencies using `pip install -r requirements.txt`.

## Usage

Simply place your `encrypted.hc` file in the same folder as the main script, then run:

    python3 decrypt.py encrypted.hc

## Keys

The keys change between some versions. The most recent key that should work with recent files is `hc_reborn_4` (latest version from Play Store)

The most recent public beta key is `hc_reborn___7` (2.6, 232)

Another key which may work is `hc_reborn_7` (2.4, 210)

And finally the last most used one is `hc_reborn_tester_5` (2.5, unknown build)

More keys will be added to the default keylist if changed by the app.

