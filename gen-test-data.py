#!/usr/bin/python3
# coding: utf-8

"""Generate test data for P-256 and related functions."""

from p256 import (ModInt, p256,
                  ecdsa_modint_from_hash, EcdsaSigner,
                  tv_ecdsa_rfc6979_key, tv_ecdsa_rfc6979,
                  tv_ecdh_nist)

base = 2**32
n_limbs = 8
top = base ** n_limbs


def montmul(x, y, m):
    """Montgomery multiplication of x, y mod m."""
    x = ModInt(x, m)
    y = ModInt(y, m)
    R = ModInt(top, m)
    return int(x * y / R)


Rp = ModInt(top, p256.p)
Rn = ModInt(top, p256.n)


def get(x, i):
    """Return i-th limb of x."""
    return (x // base**i) % base


def c_print(name, val):
    """Print 256-bit value as little-endian array of 32-bit values."""
    print('static const uint32_t', name + '[8] = {', end='')
    for i in range(8):
        sep = '\n    ' if i % 4 == 0 else ' '
        print(sep + '0x' + format(get(val, i), '08x') + ',', end='')
    print('\n};')


def c_bytes(name, val, n):
    """Print int value as big-endian array of n bytes."""
    array = name + '[' + str(n) + ']'
    print('static const uint8_t', array, '= {', end='')
    for i in range(n):
        sep = '\n    ' if i % 8 == 0 else ' '
        limb = (val // 256**(n-1-i)) % 256
        print(sep + '0x' + format(limb, '02x') + ',', end='')
    print('\n};')


def c_point(name, p):
    """Print curve point as array of bytes."""
    val = top * int(p.x()) + int(p.y())
    c_bytes(name, val, 64)


def c_bytestr(name, val):
    """Print byte string as an array of bytes."""
    array = name + '[' + str(len(val)) + ']'
    print('static const uint8_t', array, '= {', end='')
    for i, b in enumerate(val):
        sep = '\n    ' if i % 8 == 0 else ' '
        print(sep + '0x' + format(b, '02x') + ',', end='')
    print('\n};')


def c_pair(name, r, s):
    """Print a pair of 256-bit values as an array of 64 bytes."""
    val = top * r + s
    c_bytes(name, val, 64)


def print_e(name, h):
    """Print the e value (Montgomery domain) derive from hash h."""
    e = ecdsa_modint_from_hash(h, p256.n, 256)
    e_mont = int(e) * top % p256.n
    c_print(name, e_mont)


def print_val(name, x, y, m):
    """Print result of Montgomery multiplication."""
    v = montmul(x, y, m)
    c_print(name, v)


def com(msg):
    """Skip a line and print a comment."""
    print("\n/*", msg, "*/")


# These constants are not in test data but in the code itself
# This is how they were generated for reference.
#
# c_print("p256_b", int(p256.b * Rp))
# c_print("p256_Gx", int(p256.gx * Rp))
# c_print("p256_Gy", int(p256.gy * Rp))

print("""
/*
 * Test data for ECDH, ECDSA, and internal functions.
 * This file was generated by gen-test-data.py
 */
""")


# generated by random.randrange(2**256)
r = 0x760cd745ec0db49cf76db5ed0a14613ed937cbcb9c4ecc3c7d3d0eb8dcd1d063
s = 0x17380bcf120eb6d7dde65249accbcfffb3b1c6ed5444fc98c5e403b2514595c2

com("General-purpose random values")
c_print('r', r)
c_print('s', s)

com("r+s, r-s, s-r")
c_print('rps', r + s)
c_print('rms', r - s)
c_print('smr', s - r)

com("Useful values for arithmetic tests""")
c_print('zero', 0)
c_print('one', 1)
c_print('word', 2**32 - 1)
c_print('b128', 2**128)

com("n + 2**32 - 1 mod p")
c_print('npwmp', (p256.n + 2**32 - 1) % p256.p)
com("n + 2**128 mod p")
c_print('npbmp', (p256.n + 2**128) % p256.p)
com("n + n mod p")
c_print('npnmp', (p256.n * 2) % p256.p)
com("p - 1")
c_print('pm1', p256.p - 1)
com("n - 1")
c_print('nm1', p256.n - 1)
com("p - n")
c_print('pmn', p256.p - p256.n)

com("r * 2^256 mod p and mod n")
c_print('rmontp', int(r * Rp))
c_print('rmontn', int(r * Rn))

com("r * s / 2^256 mod p")
print_val("rsRip", r, s, p256.p)
com("r * s / 2^256 mod n")
print_val("rsRin", r, s, p256.n)

com("r * s mod p")
c_print("rtsmp", r * s % p256.p)
com("r * s mod n")
c_print("rtsmn", r * s % p256.n)

com("r^-1 mod p")
c_print("rip", int(ModInt(r, p256.p).inv()))
com("r^-1 mod n")
c_print("rin", int(ModInt(r, p256.n).inv()))

com("actual curve parameters (not in Montgomery domain)")
c_print("b_raw", int(p256.b))
c_print("gx_raw", int(p256.gx))
c_print("gy_raw", int(p256.gy))

com("some jacobian coordinates for the base point, in Montgomery domain")
z = ModInt(r*s, p256.p)
c_print("jac_gx", int(p256.gx * z**2 * Rp))
c_print("jac_gy", int(p256.gy * z**3 * Rp))
c_print("jac_gz", int(z * Rp))

com("affine coordinates (not Montgomery) for 2 * G")
g2 = 2 * p256.base_point()
c_print("g2x", int(g2.x()))
c_print("g2y", int(g2.y()))

com("affine coordinates (not Montgomery) for 3 * G")
g3 = 3 * p256.base_point()
c_print("g3x", int(g3.x()))
c_print("g3y", int(g3.y()))

com("affine (non-Montgomery) y coordinates for -G, -2G, -3G")
c_print("g1yn", int(-p256.base_point().y()))
c_print("g2yn", int(-g2.y()))
c_print("g3yn", int(-g3.y()))

com("affine (non-Montgomery) coordinates for rG, sG, and rsG")
rg = r * p256.base_point()
sg = s * p256.base_point()
rsg = r * s * p256.base_point()
c_print("rgx", int(rg.x()))
c_print("rgy", int(rg.y()))
c_print("sgx", int(sg.x()))
c_print("sgy", int(sg.y()))
c_print("rsgx", int(rsg.x()))
c_print("rsgy", int(rsg.y()))

com("r and s as bytes, big-endian")
c_bytes("rbytes", r, 32)
c_bytes("sbytes", s, 32)

com("the curve's base point as bytes")
c_point('gbytes', p256.base_point())

com("rG, sG and rsG as bytes")
c_point("rgb", rg)
c_point("sgb", sg)
c_bytes("rsgxb", int(rsg.x()), 32)

com("ECDSA test vectors from RFC 6979 A.2.5 + integers derived from hashes")
for i, tv in enumerate(tv_ecdsa_rfc6979):
    h = tv['h']
    bits = len(h) * 8
    case = str(bits) + "ab"[i // 5]

    c_bytestr("h" + case, h)
    print_e("h" + case + "_e", h)

    c_bytes("k" + case, tv['k'], 32)
    c_pair("sig" + case, tv['r'], tv['s'])

com("key material from RFC A.2.5")
key = tv_ecdsa_rfc6979_key
c_bytes("ecdsa_priv", key['x'], 32)
c_pair("ecdsa_pub", key['Ux'], key['Uy'])

com("bad key matetial")
c_bytes("priv_bad_0", 0, 32)
c_bytes("priv_bad_n", p256.n, 32)
c_bytes("priv_bad_m", top - 1, 32)

Ux, Uy = key['Ux'], key['Uy']
c_pair("pub_bad_xp", p256.p, Uy)
c_pair("pub_bad_xm", top - 1, Uy)
c_pair("pub_bad_yp", Ux, p256.p)
c_pair("pub_bad_ym", Ux, top - 1)

com("bad ECDSA signature (out-of-range)")
tv = tv_ecdsa_rfc6979[2]
sigr, sigs = tv['r'], tv['s']
c_pair("sig_bad_r0", 0, sigs)
c_pair("sig_bad_rn", p256.n, sigs)
c_pair("sig_bad_rm", top - 1, sigs)
c_pair("sig_bad_s0", sigr, 0)
c_pair("sig_bad_sn", sigr, p256.n)
c_pair("sig_bad_sm", sigr, top - 1)

com("ECDSA: crafted hash values to hit sign/verify special cases")
# h256a_s0:
#   when signing: gives s == 0
#   when verifying: with dummy non-zero s, gives R == 0 (u1 G = - u2 Q)
# h256a_double:
#   when verifying: with dummy non-zero s, gives u1 G == u2 Q
sigr = ModInt(sigr, p256.n)
d = ModInt(tv_ecdsa_rfc6979_key['x'], p256.n)
# 0 == s == e + rd / k  <=>  e = -rd
e = - sigr * d
c_bytes("h256a_s0", int(e), 32)
# u1 G == u2 Q <=> e = rd
e = sigr * d
c_bytes("h256a_double", int(e), 32)

com("ECDSA: signature on all-0 hash")
key = tv_ecdsa_rfc6979_key
signer = EcdsaSigner(p256, key['x'])
sig = signer.sign(b"\0" * 32)
c_pair("sig_h0", sig[0], sig[1])
c_bytes("h0", 0, 32)

com("ECDH test vectors from NIST")
for i, tv in enumerate(tv_ecdh_nist):
    base = "ecdh" + str(i) + "_"
    c_pair(base + "o", tv['ox'], tv['oy'])
    c_bytes(base + "d", tv['d'], 32)
    c_pair(base + "q", tv['Qx'], tv['Qy'])
    c_bytes(base + "z", tv['Z'], 32)
