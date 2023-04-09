import hashlib
import random
from string import ascii_uppercase, digits

"""
Date: 2023-04-09

This is a Python implementation of the ORE.

The ORE is a one-way encryption scheme that allows comparison of encrypted data.

The ORE function is defined as follows:
    ORE(m, k) = SHA224(m + k) mod 3
    
The ORE comparison function is defined as follows:
    ORE(m, n, k) = 0 if m = n
                = -1 if m < n
                = 1 if m > n
                              
"""

LEN = 16  # Length of the ORE string


def rnd_word(n):
    """Generate a random string of length n"""
    return ''.join(random.choice(ascii_uppercase + digits) for _ in range(n))


def prf(msg, k):
    """Compute the ORE function"""
    pad = "0" * (LEN - len(msg))
    return int(hashlib.sha224((msg + pad + k).encode('utf-8')).hexdigest(), 16)


def encrypt(m, k):
    """Encrypt an integer using ORE"""
    m = bin(m)[2:]
    tmp_m = ""
    tmpres = ""
    for i in m:
        tmp_m += i
        tmpres += str((prf(tmp_m[:-1], k) + int(tmp_m[-1])) % 3)
    return tmpres


def decrypt(m, k):
    """Decrypt an ORE string"""
    dec_m = ""
    for i in range(len(m)):
        dec_m += str((int(m[i]) - prf(dec_m, k)) % 3)
    return int(dec_m, 2)


def comp_ore(u, v):
    """Compare two ORE strings"""
    if u == v:
        return 0
    L = len(u)
    cnt = 0
    while u[cnt] == v[cnt]:
        cnt += 1
    if (int(u[cnt]) + 1) % 3 == int(v[cnt]):
        return -1
    else:
        return 1


def comp_int(u, v):
    """Compare two integers"""
    if u == v:
        return 0
    elif u > v:
        return 1
    else:
        return -1


def test(cnt, tests):
    """Test the ORE comparison function"""
    for i in range(tests):
        passwd = rnd_word(10)
        num1 = random.randrange(2**63, 2**64)
        num2 = random.randrange(2**63, 2**64)

        a = encrypt(num1, passwd)
        b = encrypt(num2, passwd)
        if comp_ore(a, b) == comp_int(num1, num2):
            cnt += 1
        print("Succeded in: %d out of %d tests." % (cnt, tests))

# test(0, 100)
