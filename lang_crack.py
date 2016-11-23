#!/usr/bin/python

import argparse
import hashlib

__author__ = "Jesse Buonanno"


def hash_text(hash_type, plaintext):
    if hash_type.lower() == 'md5':
        return hashlib.md5(plaintext).hexdigest()

    if hash_type.lower() == 'sh1':
        return hashlib.sha1(plaintext).hexdigest()

    if hash_type.lower() == 'sha256':
        return hashlib.sha256(plaintext).hexdigest()
    else:
        # Shouldn't have to get here
        return None


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", help="Specify Verbose", action="store_true")
    parser.add_argument("hash_type", help="Supported hash types are MD5, SHA1, SHA256", type=str)
    parser.add_argument("attack_type", help="Supported hash types are bruteforce(bf) or wordlist(wl). If wl, then specify file.",
                        choices=["bf", "wl"], type=str)
    parser.add_argument("hash_file", type=argparse.FileType('rb', 0), help="File containing hashed passwords")
    parser.add_argument('--output', type=argparse.FileType('wb', 0), default="output.txt", help="Default output goes to output.txt")
    args = parser.parse_known_args()

    if args[0].attack_type == 'wl':
        parser.add_argument("wordlist", type=argparse.FileType('rb', 0),
                            help="File containing password wordlist to be checked against hashed passwords")

    return parser.parse_args()

if __name__ == '__main__':

    args = parse_args()

    hash_file = args.hash_file
    output_file = args.output
    attack_type = args.attack_type
    hash_type = args.hash_type
    wordlist_file = ""
    try:
        wordlist_file = args.wordlist
    except AttributeError:
        pass

    print args





