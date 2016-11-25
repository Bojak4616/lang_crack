#!/usr/bin/python

import argparse
import hashlib
import itertools
from sys import exit

__author__ = "Jesse Buonanno"


def hash_text(hash_type, plaintext):
    if hash_type.lower() == 'md5':
        return hashlib.md5(plaintext).hexdigest()

    if hash_type.lower() == 'sh1':
        return hashlib.sha1(plaintext).hexdigest()

    if hash_type.lower() == 'sha256':
        return hashlib.sha256(plaintext).hexdigest()


def bruteforcer(charset, maxlength):
    return (''.join(candidate) for candidate in itertools.chain.from_iterable(itertools.product(charset, repeat=i)
                                                                              for i in range(1, maxlength + 1)))


def bruteforce_handling(language, hash_type, hash_file):
    charset = ""

    if language == "eng":
        # 94 total possible characters
        for ascii_char in range(32, 126):
            charset += chr(ascii_char)

    elif language == "kor":
        # 11272 total possible characters
        for ascii_char in range(32, 64):
            charset += chr(ascii_char)

        for ascii_char in range(91, 96):
            charset += chr(ascii_char)

        for ascii_char in range(123, 126):
            charset += chr(ascii_char)

        for kor_charset_1 in range(12593, 12642):
            charset += unichr(kor_charset_1)

        for kor_charset_2 in range(44032, 55215):
            charset += unichr(kor_charset_2)

        charset = charset.encode(encoding='UTF-8')

    elif language == "rus":
        # 103 total possible charcters
        for ascii_char in range(32, 64):
            charset += chr(ascii_char)

        for ascii_char in range(91, 96):
            charset += chr(ascii_char)

        for ascii_char in range(123, 126):
            charset += chr(ascii_char)

        for rus_charset in range(1040, 1103):
            charset += unichr(rus_charset)

        charset = charset.encode(encoding='UTF-8')

    elif language == "CJ":
        # 1078 total characters
        for ascii_char in range(32, 64):
            charset += chr(ascii_char)

        for ascii_char in range(91, 96):
            charset += chr(ascii_char)

        for ascii_char in range(123, 126):
            charset += chr(ascii_char)

        for uni_charset in range(19968, 21006):
            charset += unichr(uni_charset)

        charset = charset.encode(encoding='UTF-8')


    cracked = {}

    print "[*] Press CTRL+C to stop cracking"

    try:
        for guess in bruteforcer(charset, 100):
            for hash in hash_file:
                hash = hash.rstrip('\n')
                if hash_text(hash_type, guess) == hash:
                    if guess in cracked:
                        continue
                    print "[+] Hash '" + hash + "' cracked with plaintext of '" + guess + "'"
                    cracked[guess] = hash

            hash_file.seek(0, 0)

    except KeyboardInterrupt:
        print "[*] Cleaning up"
        return cracked

    return cracked


def wordlist_handling(hash_type, hash_file, wordlist_file):
    cracked = {}

    print "[*] Press CTRL+C to stop cracking"
    try:
        for guess in wordlist_file:
            guess = guess.rstrip('\n')
            for hash in hash_file:
                hash = hash.rstrip('\n')
                if hash_text(hash_type, guess) == hash:
                    if guess in cracked:
                        continue
                    print "[+] Hash: '" + hash + "' cracked with plaintext of '" + guess + "'"
                    cracked[guess] = hash

            hash_file.seek(0, 0)

    except KeyboardInterrupt:
        print "[*] Cleaning up"
        return cracked

    return cracked


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", help="Specify Verbose", action="store_true")
    parser.add_argument("language", help="Supported languages are English, Korean, Russian, Chinese/Japanese",
                        choices=["eng", "kor", "rus", "cj"], type=str)
    parser.add_argument("hash_type", help="Supported hash types are md5, sha1, sha256", choices=["md5", "sh1", "sha256"],
                        type=str)
    parser.add_argument("attack_type", help="Supported hash types are bruteforce(bf) or wordlist(wl). If wl, then specify file.",
                        choices=["bf", "wl"], type=str)
    parser.add_argument('--output', type=argparse.FileType('wb', 0), default="output.txt", help="Default output goes to output.txt")
    parser.add_argument("hash_file", type=argparse.FileType('rb', 0), help="File containing hashed passwords")
    args = parser.parse_known_args()

    # TODO: This line needs to be higher. When specified the location of the hashfile switched with the wordlist.
    if args[0].attack_type == 'wl':
        parser.add_argument("wordlist", type=argparse.FileType('rb', 0),
                            help="File containing password wordlist to be checked against hashed passwords.")

    return parser.parse_args()

if __name__ == '__main__':

    args = parse_args()
    output_file = args.output

    try:
        wordlist_file = args.wordlist
    except AttributeError:
        wordlist_file = ""
        pass

    if args.attack_type == 'wl':
            for key, value in wordlist_handling(args.hash_type, args.hash_file, wordlist_file).iteritems():
                output_file.write(key + ':' + value + '\n')

    elif args.attack_type == 'bf':
            for key, value in bruteforce_handling(args.language, args.hash_type, args.hash_file).iteritems():
                output_file.write(key + ':' + value + '\n')

    print "[*]Check " + output_file.name + " for list of cracked passwords!"

    exit(0)
