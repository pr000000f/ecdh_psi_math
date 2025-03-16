#!/usr/bin/sage
# vim: syntax=python

# run in /draft-irtf-cfrg-hash-to-curve/poc/
# install package with sage -pip install ecdsa library
# run with sage ecdh_psi.sage

import sys
import os
import ecdsa
import hashlib
import csv
from ecdsa import NIST256p
from ecdsa import ellipticcurve

print("ECDH-PSI from rfc draft implementation.")

try:
    from sagelib.suite_p256 import test_suite_p256
    from sagelib.suite_p256 import p256_sswu_ro
    from sagelib.suite_p256 import p256_order
    from printer import Printer
except ImportError:
    sys.exit("Error loading preprocessed sage files.")

def sage_point_to_ecdsa_point(curve, sage_point):
    x_coord_hex = Printer.tv.x_hex(sage_point)
    y_coord_hex = Printer.tv.y_hex(sage_point)
    python_point = ellipticcurve.Point(curve, int(x_coord_hex, 16), int(y_coord_hex, 16))
    return python_point

def str_set_to_sage_point_set(str_set):
    return [p256_sswu_ro(str) for str in str_set]

def sage_point_set_to_ecdsa_point_set(curve, sage_point_set):
    return [sage_point_to_ecdsa_point(curve, sage_point) for sage_point in sage_point_set]

def mask_set(point_set, sk):
    return [point * sk for point in point_set]

def ecdsa_point_set_to_hash_str(curve, point_set):
    ret_list = []
    #byte_length = curve.baselen 
    for point in point_set:
        #point_bytes = point.x().to_bytes() + point.y().to_bytes()
        hash_str = hashlib.sha256(point.to_bytes()).hexdigest()
        ret_list.append(hash_str)
    return ret_list

def csv_reader(filename):
    str_set = []
    with open(filename, "r", encoding="utf-8") as file:
        csv_reader = csv.reader(file)
        for row in csv_reader:
            str_set.append([str(cell) for cell in row])
    return str_set[0]


if __name__ == "__main__":

    # Step 0: read .csv file
    str_set_a = csv_reader("set_a.csv")
    str_set_b = csv_reader("set_b.csv")

    # Step 1: hash_to_curve
    #str_set_a = ['abc', 'def']
    sage_point_set_a = str_set_to_sage_point_set(str_set_a)
    #str_set_b = ['abc', 'efg']
    sage_point_set_b = str_set_to_sage_point_set(str_set_b)

    # Step 2: from sage's point to ecdsa's point
    point_set_a = sage_point_set_to_ecdsa_point_set(NIST256p.curve, sage_point_set_a)
    point_set_b = sage_point_set_to_ecdsa_point_set(NIST256p.curve, sage_point_set_b)

    # Step 3: generate secret keys
    ecdsa_key_a = ecdsa.SigningKey.generate(curve = NIST256p)
    ecdsa_key_b = ecdsa.SigningKey.generate(curve = NIST256p)
    sk_a = ecdsa_key_a.privkey.secret_multiplier
    sk_b = ecdsa_key_b.privkey.secret_multiplier

    # Step 4: local mask
    point_set_a_a = mask_set(point_set_a, sk_a)
    point_set_b_b = mask_set(point_set_b, sk_b)

    # Step 5: remote mask
    point_set_a_ab = mask_set(point_set_a_a, sk_b)
    point_set_b_ba = mask_set(point_set_b_b, sk_a)

    # Step 6: to sha_256 hash string
    hash_a_ab = ecdsa_point_set_to_hash_str(NIST256p.curve, point_set_a_ab)
    hash_b_ba = ecdsa_point_set_to_hash_str(NIST256p.curve, point_set_b_ba)

    # Step 7: presentation
    print("set_AB:")
    for index, hash_str in enumerate(hash_a_ab):
        print(index, ":", hash_str)

    print("set_BA:")
    for index, hash_str in enumerate(hash_b_ba):
        print(index, ":", hash_str)

    print("Intersection: ")
    for index, hash_str in enumerate(hash_a_ab):
        for hash_str_cmp in hash_b_ba:
            if hash_str == hash_str_cmp:
                print(str_set_a[index])

    
