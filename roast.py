from collections import namedtuple

import hashlib
import secrets

from fastec import (
    G, n, infinity,
    Point, point_add, point_mul,
    bytes_from_point, int_from_bytes,
)

from shamir import lagrange

# This implementation can be sped up by storing the midstate after hashing
# tag_hash instead of rehashing it all the time.
def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()

def H(tag, *items):
    buf = bytearray()
    for item in items:
        if type(item) is Point:
            buf.extend(bytes_from_point(item))
        else:
            buf.extend(item)
    return int_from_bytes(tagged_hash(tag, bytes(buf))) % n

def pre_round():
    d_i = 1 + secrets.randbelow(n - 1)
    e_i = 1 + secrets.randbelow(n - 1)
    D_i = point_mul(G, d_i)
    E_i = point_mul(G, e_i)
    spre_i = (d_i, e_i)
    pre_i = (D_i, E_i)
    return spre_i, pre_i

def pre_agg(i_to_pre, T):
    D = infinity
    E = infinity
    for i in T:
        D_i, E_i = i_to_pre[i]
        D = point_add(D, D_i)
        E = point_add(E, E_i)
    pre = (D, E)
    return pre

SessionContext = namedtuple('SessionContext', ['X', 'i_to_X', 'msg', 'T', 'pre', 'pre_i'])

def share_val(ctx, i, s_i):
    X = ctx.X
    X_i = ctx.i_to_X[i]
    msg = ctx.msg
    T = ctx.T
    D, E = ctx.pre
    D_i, E_i = ctx.pre_i

    b = H('non', X, msg, D, E)
    R = point_add(D, point_mul(E, b))
    c = H('sig', X, msg, R)
    lambda_i = lagrange(T, i)
    lhs = point_mul(G, s_i)
    rhs = point_add(point_add(D_i, point_mul(E_i, b)), point_mul(X_i, c * lambda_i % n))
    return lhs == rhs

def sign_round(ctx, i, sk_i, spre_i):
    X = ctx.X
    msg = ctx.msg
    T = ctx.T
    D, E = ctx.pre

    d_i, e_i = spre_i
    b = H('non', X, msg, D, E)
    R = point_add(D, point_mul(E, b))
    c = H('sig', X, msg, R)
    lambda_i = lagrange(T, i)
    s_i = (d_i + b * e_i + c * lambda_i * sk_i) % n
    return s_i

def sign_agg(ctx, i_to_s):
    X = ctx.X
    msg = ctx.msg
    T = ctx.T
    D, E = ctx.pre

    b = H('non', X, msg, D, E)
    R = point_add(D, point_mul(E, b))
    s = 0
    for i in T:
        s_i = i_to_s[i]
        s = (s + s_i) % n
    return R, s

def verify(ctx, sig):
    X = ctx.X
    msg = ctx.msg

    R, s = sig
    c = H('sig', X, msg, R)
    lhs = point_mul(G, s)
    rhs = point_add(R, point_mul(X, c))
    return lhs == rhs
