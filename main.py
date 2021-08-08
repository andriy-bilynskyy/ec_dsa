#!/usr/bin/env python3
# -*- coding: utf-8 -*-


#constant definition
SK  = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
MSG = ""


import hashlib


def modp_inv(x, p):
    return pow(x, p-2, p)


def recover_x(p, d, y, sign):
    if y >= p:
        return None
    x2 = (y*y-1) * modp_inv(d*y*y+1, p)
    if x2 == 0:
        if sign:
            return None
        else:
            return 0
        # Compute square root of x2
    modp_sqrt_m1 = pow(2, (p-1) // 4, p)
    x = pow(x2, (p+3) // 8, p)
    if (x*x - x2) % p != 0:
        x = x * modp_sqrt_m1 % p
    if (x*x - x2) % p != 0:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


def sha512(s):
    return hashlib.sha512(s).digest()


def sha512_modq(s, q):
    return int.from_bytes(sha512(s), "little") % q


def secret_expand(secret):
    if len(secret) != 32:
        raise Exception("Bad size of private key")
    h = sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    return (a, h[32:])


def point_compress(p, P):
    zinv = modp_inv(P[2], p)
    x = P[0] * zinv % p
    y = P[1] * zinv % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def point_decompress(p, d, s):
    if len(s) != 32:
        raise Exception("Invalid input length for decompression")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = recover_x(p, d, y, sign)
    if x is None:
        return None
    else:
        return (x, y, 1, x*y % p)


def point_equal(p, P, Q):
    if (P[0] * Q[2] - Q[0] * P[2]) % p != 0:
        return False
    if (P[1] * Q[2] - Q[1] * P[2]) % p != 0:
        return False
    return True


def point_add(p, d, P, Q):
    A, B = (P[1]-P[0]) * (Q[1]-Q[0]) % p, (P[1]+P[0]) * (Q[1]+Q[0]) % p;
    C, D = 2 * P[3] * Q[3] * d % p, 2 * P[2] * Q[2] % p;
    E, F, G, H = B-A, D-C, D+C, B+A;
    return (E*F, G*H, F*G, E*H);


def point_mul(p, d, s, P):
    Q = (0, 1, 1, 0) # Neutral element
    while s > 0:
        if s & 1:
            Q = point_add(p, d, Q, P)
        P = point_add(p, d, P, P)
        s >>= 1
    return Q


def secret_to_public(p, d, G, secret):
    (a, dummy) = secret_expand(secret)
    return point_compress(p, point_mul(p, d, a, G))


def sign(p, d, q, G, secret, msg):
    a, prefix = secret_expand(secret)
    A = point_compress(p, point_mul(p, d, a, G))
    r = sha512_modq(prefix + msg, q)
    R = point_mul(p, d, r, G)
    Rs = point_compress(p, R)
    h = sha512_modq(Rs + A + msg, q)
    s = (r + h * a) % q
    return Rs + int.to_bytes(s, 32, "little")


def verify(p, d, q, G, public, msg, signature):
    if len(public) != 32:
        raise Exception("Bad public key length")
    if len(signature) != 64:
        Exception("Bad signature length")
    A = point_decompress(p, d, public)
    if not A:
        return False
    Rs = signature[:32]
    R = point_decompress(p, d, Rs)
    if not R:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= q:
        return False
    h = sha512_modq(Rs + public + msg, q)
    sB = point_mul(p, d, s, G)
    hA = point_mul(p, d, h, A)
    return point_equal(p, sB, point_add(p, d, R, hA))


def main():

    print("Curve constants:")
    #base field
    p = 2**255 - 19
    print("p=%uL" % p)
    print("p=0x%XL" % p)
    #curve constant
    d = -121665 * modp_inv(121666, p) % p
    print("d=%uL" % d)
    print("d=0x%XL" % d)
    #group order
    q = 2**252 + 27742317777372353535851937790883648493
    print("q=%uL" % q)
    print("q=0x%XL" % q)
    #base point Y
    g_y = 4 * modp_inv(5, p) % p
    print("Gy=%uL" % g_y)
    print("Gy=0x%XL" % g_y)
    #base point X
    g_x = recover_x(p, d, g_y, 0)
    print("Gx=%uL" % g_x)
    print("Gx=0x%XL" % g_x)
    #define base piont
    G = (g_x, g_y, 1, g_x * g_y % p)

    print("Keys:")
    #secret key
    sk = bytes.fromhex(SK)
    print("SK: 0x" + "".join("{:02X}".format(x) for x in sk))
    #calculate public key
    pk = secret_to_public(p, d, G, sk)
    print("PK: 0x" + "".join("{:02X}".format(x) for x in pk))

    print("Signature:")
    #read message
    message = bytes.fromhex(MSG)
    print("MSG: 0x" + "".join("{:02X}".format(x) for x in message))
    #make signature
    signature = sign(p, d, q, G, sk, message)
    print("MSG: 0x" + "".join("{:02X}".format(x) for x in signature))

    print("Verify:")
    #verify signature
    if verify(p, d, q, G, pk, message, signature) == True:
        print("Signature OK!")
    else:
        print("Signature failed!")


# call main function
if __name__ == "__main__":
    main()