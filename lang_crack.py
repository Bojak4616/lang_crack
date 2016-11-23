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


def bruteforce_handling(hash_type, hash_file):
    cracked = {}

    return cracked


def wordlist_handling(hash_type, hash_file, wordlist_file):
    cracked = {}

    try:
        for password in wordlist_file:
            for hash in hash_file:
                if hash_text(hash_type, password) == hash.rstrip('\n'):
                    cracked[password.rstrip('\n')] = hash.rstrip('\n')

    except KeyboardInterrupt:
        print "[*] Cleaning up"
        return cracked

    return cracked


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", help="Specify Verbose", action="store_true")
    parser.add_argument("hash_type", help="Supported hash types are md5, sha1, sha256", choices=["md5", "sh1", "sha256"],
                        type=str)
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
    output_file = args.output

    try:
        wordlist_file = args.wordlist
    except AttributeError:
        wordlist_file = ""
        pass

    if args.attack_type == 'wl':
            for key, value in wordlist_handling(args.hash_type, args.hash_file, wordlist_file).iteritems():
                print key + ' : ' + value

    elif args.attack_type == 'bf':
            print bruteforce_handling(args.hash_type, args.hash_file)







