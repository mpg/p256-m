#!/usr/bin/python3
# coding: utf-8

from p256 import ModInt, p256
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

# rg = r * p256.base_point()
# c_print("rgx", int(rg.x()))
# c_print("rgy", int(rg.y()))

# sg = s * p256.base_point()
# c_print("sgx", int(sg.x()))
# c_print("sgy", int(sg.y()))

# rsg = r * s * p256.base_point()
# c_print("rsgx", int(rsg.x()))
# c_print("rsgy", int(rsg.y()))


def c_bytes(name, val):
    array = name + '[32]'
    print('static const uint8_t', array, '= {', end='')
    for i in range(32):
        sep = '\n    ' if i % 8 == 0 else ' '
        limb = (val // 256**(31-i)) % 256
        print(sep + '0x' + format(limb, '02x') + ',', end='')
    print('\n};')


c_bytes("rbytes", r);
