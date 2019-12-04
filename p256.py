#!/usr/bin/python3
# coding: utf-8

import secrets

class ModInt:
    """Modular integer"""

    def __init__(self, x, n):
        """x mod n"""
        self.x = x % n
        self.n = n

    def __repr__(self):
        return "ModInt({}, {})".format(self.x, self.n)

    def __int__(self):
        return self.x

    def __eq__(self, other):
        return self.x == other.x and self.n == other.n

    def __add__(self, other):
        return ModInt(self.x + other.x, self.n)

    def __sub__(self, other):
        return ModInt(self.x - other.x, self.n)

    def __neg__(self):
        return ModInt(-self.x, self.n)

    def __mul__(self, other):
        return ModInt(self.x * other.x, self.n)

    def __rmul__(self, other):
        """Multiply self by an integer"""
        return ModInt(self.x * other, self.n)

    def __pow__(self, other):
        return ModInt(pow(self.x, other, self.n), self.n)

    def inv(self):
        """Return modular inverse as a ModInt or raise ZeroDIvisionError"""
        a, b, u, s = self.x, self.n, 1, 0
        # invariants: a < b and a == u*x mod n and b == s*x mod n
        while a > 1:
            q, r = divmod(b, a)  # r = b - q*a
            a, b, u, s = r, a, s - q*u, u
        if a != 1:
            raise ZeroDivisionError
        return ModInt(u, self.n)

    def __truediv__(self, other):
        return self * other.inv()

    def is_zero(self):
        return self.x == 0


class Curve:
    """Curve parameters - Short Weierstrass curves over GF(p), p > 3"""
    # assuming cofactor of 1 (true for NIST and Brainpool curves),
    # so n is the order of the curve and of the base point G

    def __init__(self, name, *, p, a, b, gx, gy, n):
        self.name = name
        self.p = p
        self.a = ModInt(a, p)
        self.b = ModInt(b, p)
        self.gx = ModInt(gx, p)
        self.gy = ModInt(gy, p)
        self.n = n

        self.p_bits = p.bit_length()
        self.p_bytes = (self.p_bits + 7) // 8

        self.n_bits = n.bit_length()
        self.n_bytes = (self.n_bits + 7) // 8

    def __str__(self):
        return self.name

    def zero(self):
        return CurvePoint(None, self)

    def base_point(self):
        return CurvePoint((self.gx, self.gy), self)


# rfc 6090 app. D, or rfc 5903 3.1, or sec2-v2 2.4.2, or FIPS 186-4 D.1.2.3
p256 = Curve(
    "P-256",
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    a=-3,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
)


class CurvePoint:
    """Point on a Curve"""

    def __init__(self, coordinates, curve):
        """Coordinates is either a pair of ModInt or None for 0"""
        self.coord = coordinates
        self.curve = curve

    def is_zero(self):
        return self.coord is None

    def x(self):
        return self.coord[0]

    def y(self):
        return self.coord[1]

    def __eq__(self, other):
        if self.is_zero() and other.is_zero():
            return True

        if self.is_zero() or other.is_zero():
            return False

        return self.x() == other.x() and self.y() == other.y()

    def __add__(self, other):
        """Add two points - RFC 6090 Appendix F.1"""

        if self.is_zero():
            return other

        if other.is_zero():
            return self

        x1, y1, x2, y2 = self.x(), self.y(), other.x(), other.y()

        if self != other and x1 == y1:
            return CurvePoint(None, self.curve)

        if self != other:
            x3 = ((y2-y1) / (x2-x1))**2 - x1 - x2
            y3 = (x1-x3) * (y2-y1) / (x2-x1) - y1
            return CurvePoint((x3, y3), self.curve)

        # this can't happen with curves of large prime order,
        # but let's just follow the formulas in the RFC
        if y1.is_zero():
            return CurvePoint(None, self.curve)

        a = self.curve.a
        x3 = ((3*x1**2 + a) / (2*y1))**2 - 2*x1
        y3 = (x1-x3)*(3*x1**2 + a) / (2*y1) - y1
        return CurvePoint((x3, y3), self.curve)

    def __rmul__(self, other):
        """Multiply self by a positive integer"""

        # invariant: result + scale * scalar = self * other
        result = self.curve.zero()
        scale = self
        scalar = other
        while scalar != 0:
            if scalar % 2 != 0:
                result += scale
            scale += scale
            scalar //= 2

        return result


def ecdsa_modint_from_hash(msg_hash, n, nbits):
    """Derive an integer mod n from a message hash for ECDSA."""
    # This is Sec1 4.1.3 step 5 or 4.1.4 step 3
    # Subteps 1-3: simplify when nbits is a multiple of 8
    assert(nbits % 8 == 0)
    l = min(32, len(msg_hash))
    msg_hash = msg_hash[:l]
    # Substep 4: 2.3.8 says big endian
    e = int.from_bytes(msg_hash, 'big')
    # Extra: mod n
    return ModInt(e, n)


class EcdsaSigner:
    def __init__(self, curve, d=None):
        """Create an ECDSA private key for curve or load it from an int"""
        self.curve = curve
        self.d = d if d is not None else self._gen_scalar()

    def _gen_scalar(self):
        # sec1 3.2.1: d in [1, n-1]
        return secrets.randbelow(self.curve.n - 2) + 1

    def _gen_public(self, d):
        return d * self.curve.base_point()

    def public_key(self):
        return self._gen_public(self.d)

    def sign(self, msg_hash, k=None):
        """Generate a signature (int pair) for that message hash (bytes)"""
        # sec1 4.1.3, but instead of retrying just abort
        n = self.curve.n
        nbits = self.curve.n_bits
        # 1. Set ephemeral keypair
        if k is None:
            k = self._gen_scalar()
        R = self._gen_public(k)
        k = ModInt(k, n)
        # 2, 3. Convert to integer mod n
        r = ModInt(int(R.x()), n)
        assert(not r.is_zero())
        # 4. Skipped - we take the hash as input
        # 5. Derive integer from hash
        e = ecdsa_modint_from_hash(msg_hash, n, nbits)
        # 6. Compute s
        d = ModInt(self.d, n)
        s = (e + r * d) / k
        assert(not s.is_zero())
        # 7. Output two integers
        return (int(r), int(s))


class EcdsaVerifier:
    def __init__(self, curve, public_key):
        """Create an ECDSA verifier from a public key (CurvePoint)"""
        self.curve = curve
        self.Q = public_key

    def is_valid(self, sig, msg_hash):
        """Tell if signature (int pair) is valid for that hash (bytes)"""
        # sec1 4.1.4
        n = self.curve.n
        nbits = self.curve.n_bits
        r, s = sig
        # 1. Verify range
        if not (0 < r < n and 0 < s < n):
            return False
        # 2. Skip hashing - we take the hash as input
        # 3. Derive integer from hash
        e = ecdsa_modint_from_hash(msg_hash, n, nbits)
        # 4. Compute u1, u2
        r = ModInt(r, n)
        s = ModInt(s, n)
        u1 = e / s
        u2 = r / s
        # 5. Compute R
        R = int(u1) * self.curve.base_point() + int(u2) * self.Q
        if R.is_zero():
            return False
        # 6, 7. Convert to v
        v = ModInt(int(R.x()), n)
        # 8. Compare
        return v == r


if __name__ == '__main__':
    print("P-256 ECDH test vectors from RFC 5903 Sec. 8.1...", end=' ')

    i = 0xC88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433
    gix = 0xDAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180
    giy = 0x5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3
    r = 0xC6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53
    grx = 0xD12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63
    gry = 0x56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB
    girx = 0xD6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE
    giry = 0x522BDE0AF0D8585B8DEF9C183B5AE38F50235206A8674ECB5D98EDB20EB153A2

    gi = i * p256.base_point()
    assert(gix == int(gi.x()) and giy == int(gi.y()))

    gr = r * p256.base_point()
    assert(grx == int(gr.x()) and gry == int(gr.y()))

    si = i * gr
    assert(girx == int(si.x()) and giry == int(si.y()))

    sr = r * gi
    assert(girx == int(sr.x()) and giry == int(sr.y()))

    print("OK")

    print("P-256 ECDSA test vectors from RFC 4754 Sec. 8.1...", end=' ')

    w = 0xDC51D3866A15BACDE33D96F992FCA99DA7E6EF0934E7097559C27F1614C88A7F
    k = 0x9E56F509196784D963D1C0A401510EE7ADA3DCC5DEE04B154BF61AF1D5A6DECE
    r = 0xCB28E0999B9C7715FD0A80D8E47A77079716CBBF917DD72E97566EA1C066957C
    s = 0x86FA3BB4E26CAD5BF90B7F81899256CE7594BB1EA0C89212748BFF3B3D5B0315
    h = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
    h = bytes.fromhex(h)

    signer = EcdsaSigner(p256, w)
    sig = signer.sign(h, k)
    assert(sig == (r, s))

    verif = EcdsaVerifier(p256, signer.public_key())
    assert(verif.is_valid((r, s), h) is True)

    bad_r = r + 1
    bad_s = s + 1
    bad_h = h[::-1]
    assert(verif.is_valid((bad_r, s), h) is False)
    assert(verif.is_valid((r, bad_s), h) is False)
    assert(verif.is_valid((r, s), bad_h) is False)

    print("OK")

    print("P-256 ECDSA test vectors from RFC 6979 A.2.5...", end=' ')

    x = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721

    signer = EcdsaSigner(p256, x)
    verif = EcdsaVerifier(p256, signer.public_key())

    # hashes of "sample" (6 bytes) with SHA-1, SHA-256, SHA-512
    h1 = "8151325dcdbae9e0ff95f9f9658432dbedfdb209"
    h256 = "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf"
    h512 = ("39a5e04aaff7455d9850c605364f514c11324ce64016960d23d5dc57d3ffd8f4"
        + "9a739468ab8049bf18eef820cdb1ad6c9015f838556bc7fad4138b23fdf986c7")
    hashes = tuple(bytes.fromhex(h) for h in (h1, h256, h512))

    k1 = 0x882905F1227FD620FBF2ABF21244F0BA83D0DC3A9103DBBEE43A1FB858109DB4
    r1 = 0x61340C88C3AAEBEB4F6D667F672CA9759A6CCAA9FA8811313039EE4A35471D32
    s1 = 0x6D7F147DAC089441BB2E2FE8F7A3FA264B9C475098FDCF6E00D7C996E1B8B7EB

    k256 = 0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
    r256 = 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
    s256 = 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8

    k512 = 0x5FA81C63109BADB88C1F367B47DA606DA28CAD69AA22C4FE6AD7DF73A7173AA5
    r512 = 0x8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00
    s512 = 0x2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE

    ks = (k1, k256, k512)
    rs = (r1, r256, r512)
    ss = (s1, s256, s512)

    for h, k, r, s in zip(hashes, ks, rs, ss):
        sig = signer.sign(h, k)
        assert(sig == (r, s))
        assert(verif.is_valid((r,s), h) is True)
        assert(verif.is_valid((r+1,s), h) is False)
        assert(verif.is_valid((r,s+1), h) is False)
        assert(verif.is_valid((r,s), h[::-1]) is False)

    print("OK")
