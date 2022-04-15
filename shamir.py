from ec import n
from random import sample

import secrets

def poly_eval(coeffs, x):
    y = 0
    for i, c_i in enumerate(coeffs):
        y = (y + c_i * pow(x, i, n)) % n
    return y

def lagrange(T, i):
    lamb_i = 1
    for j in T:
        if j != i:
            lamb_i = lamb_i * j % n
            lamb_i = lamb_i * pow(j - i, n - 2, n) % n
    return lamb_i

def split_secret(secret, t, k):
    # Generate random polynomial of degree t - 1
    coeffs = [secret]
    for i in range(t - 1):
        coeffs.append(1 + secrets.randbelow(n - 1))

    # Evaluate polynomial at points 1, ..., k to generate shares
    shares = {}
    for i in range(1, k + 1):
        shares[i] = poly_eval(coeffs, i)

    return shares

def recover_secret(shares):
    T = list(shares.keys())
    z = 0
    for i, y in shares.items():
        z = (z + lagrange(T, i) * y) % n
    return z

def test_shamir():
    for k in range(3, 10):
        for t in range(2, k):
            secret = 1 + secrets.randbelow(n - 1)
            all_shares = split_secret(secret, t, k)
            threshold_shares = dict(sample(all_shares.items(), t))
            assert recover_secret(threshold_shares) == secret

if __name__ == '__main__':
    test_shamir()
