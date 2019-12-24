#!/usr/bin/python3
# coding: utf-8

from p256 import ModInt, p256, ecdsa_modint_from_hash
from rnd import c_print

b = 2**32

def get(x, i):
    return (x // b**i) % b

def montmul(x, y, m):
    m_prime = int(-ModInt(m, b).inv())
    #print(hex(m_prime))

    a = 0
    for i in range(8):
        #print("\ni =", i)
        u = (get(a, 0) + get(x, i) * get(y, 0)) * m_prime % b
        #print("u:", hex(u))
        a = (a + get(x, i) * y + u * m) // b
        #print("a:", hex(a))

    if a > m:
        a -= m

    return a

def ref(x, y, m):
    x = ModInt(x, m)
    y = ModInt(y, m)
    R = ModInt(b**8, m)
    return int(x * y / R)

def print_val(name, x, y, m):
    v = montmul(x, y, m)
    assert(v == ref(x, y, m))
    c_print(name, v)

p = p256.p
n = p256.n
r = 0x760cd745ec0db49cf76db5ed0a14613ed937cbcb9c4ecc3c7d3d0eb8dcd1d063
s = 0x17380bcf120eb6d7dde65249accbcfffb3b1c6ed5444fc98c5e403b2514595c2

#print_val("rsRip", r, s, p)
#print_val("rsRin", r, s, n)

#c_print("rip", int(ModInt(r, p).inv()))
#c_print("rin", int(ModInt(r, n).inv()))

# c_print("p256_b", int(p256.b * ModInt(b**8, p256.p)))
# c_print("p256_Gx", int(p256.gx * ModInt(b**8, p256.p)))
# c_print("p256_Gy", int(p256.gy * ModInt(b**8, p256.p)))

# c_print("b_raw", int(p256.b))
# c_print("gx_raw", int(p256.gx))
# c_print("gy_raw", int(p256.gy))

# Rp = ModInt(b**8, p)
# z = ModInt(r*s, p)
# c_print("jac_gx", int(p256.gx * z**2 * Rp))
# c_print("jac_gy", int(p256.gy * z**3 * Rp))
# c_print("jac_gz", int(z * Rp))

# c_print("g1yn", int(-p256.base_point().y()))

# g2 = 2 * p256.base_point()
# c_print("g2x", int(g2.x()))
# c_print("g2y", int(g2.y()))
# c_print("g2yn", int(-g2.y()))

# g3 = 3 * p256.base_point()
# c_print("g3x", int(g3.x()))
# c_print("g3y", int(g3.y()))
# c_print("g3yn", int(-g3.y()))

def c_bytes(name, val, n):
    array = name + '[' + str(n) + ']'
    print('static const uint8_t', array, '= {', end='')
    for i in range(n):
        sep = '\n    ' if i % 8 == 0 else ' '
        limb = (val // 256**(n-1-i)) % 256
        print(sep + '0x' + format(limb, '02x') + ',', end='')
    print('\n};')


def c_point(name, p):
    val = 2**256 * int(p.x()) + int(p.y())
    c_bytes(name, val, 64)

# c_bytes("rbytes", r, 32);
# c_bytes("sbytes", s, 32);

#c_print("rmontp", r * 2**256 % p256.p)
#c_print("rmontn", r * 2**256 % p256.n)

# c_point('gbytes', p256.base_point())

# rg = r * p256.base_point()
# c_print("rgx", int(rg.x()))
# c_print("rgy", int(rg.y()))
# c_point("rgb", rg)

# sg = s * p256.base_point()
# c_print("sgx", int(sg.x()))
# c_print("sgy", int(sg.y()))
# c_point("sgb", sg)

# rsg = r * s * p256.base_point()
# c_print("rsgx", int(rsg.x()))
# c_print("rsgy", int(rsg.y()))
# c_bytes("rsgxb", int(rsg.x()), 32)

# excerpt from RFC 6979 A.2.5, message = "sample" (6 bytes)
h1 = "8151325dcdbae9e0ff95f9f9658432dbedfdb209"
h256 = "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf"
h512 = ("39a5e04aaff7455d9850c605364f514c11324ce64016960d23d5dc57d3ffd8f4"
    + "9a739468ab8049bf18eef820cdb1ad6c9015f838556bc7fad4138b23fdf986c7")

k1 = 0x882905F1227FD620FBF2ABF21244F0BA83D0DC3A9103DBBEE43A1FB858109DB4
r1 = 0x61340C88C3AAEBEB4F6D667F672CA9759A6CCAA9FA8811313039EE4A35471D32
s1 = 0x6D7F147DAC089441BB2E2FE8F7A3FA264B9C475098FDCF6E00D7C996E1B8B7EB

k256 = 0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
r256 = 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
s256 = 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8

k512 = 0x5FA81C63109BADB88C1F367B47DA606DA28CAD69AA22C4FE6AD7DF73A7173AA5
r512 = 0x8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00
s512 = 0x2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE

def c_hex(name, hex_str):
    n = len(hex_str) // 2
    v = int(hex_str, 16)
    c_bytes(name, v, n)

c_hex("h1", h1)
c_hex("h256", h256)
c_hex("h512", h512)

def print_e(name, h):
    e = ecdsa_modint_from_hash(bytes.fromhex(h), p256.n, 256)
    e_mont = int(e) * 2**256 % p256.n
    c_print(name, e_mont)

print_e("h1_e", h1)
print_e("h256_e", h256)
print_e("h512_e", h512)

#c_bytes("k1", k1, 32)
#c_bytes("r1", r1, 32)
#c_bytes("s1", s1, 32)
#
#c_bytes("k256", k256, 32)
#c_bytes("r256", r256, 32)
#c_bytes("s256", s256, 32)
#
#c_bytes("k512", k512, 32)
#c_bytes("r512", r512, 32)
#c_bytes("s512", s512, 32)
