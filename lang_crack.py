#!/usr/bin/python

import argparse
import hashlib

__author__ = "Jesse Buonanno"

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", help="Specify Verbose", action="store_true")
    parser.add_argument("hash_type", help="Supported hash types are MD5, SHA1, SHA256", type=str)
    parser.add_argument("attack_type", help="Supported hash types are bruteforce(bf) or wordlist(wl)",
                        choices=["bf", "wl"], type=str)
    args = parser.parse_known_args()

    if args[0].attack_type == 'wl':
        parser.add_argument("wordlist", help="File containing password wordlist to be checked against hashed passwords",
                            type=str)

    parser.add_argument("hash_file", help="File containing hashed passwords", type=str)
    parser.add_argument('--output', type=argparse.FileType('wb', 0), default="output.txt")
    #TODO: Add threading and threading argument. Depends how large the password files will be
    args = parser.parse_args()


