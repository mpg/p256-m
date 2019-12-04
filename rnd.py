#!/usr/bin/python3
# coding: utf-8

import random

n_limbs = 8

def c_print(name, val):
    array = name + '[' + str(n_limbs) + ']'
    print('static const uint32_t', array, '= {', end='')
    for i in range(n_limbs):
        sep = '\n    ' if i % 4 == 0 else ' '
        print(sep + '0x' + format(val % 2**32, '08x') + ',', end='')
        val >>=32
    print('\n};')


if __name__ == '__main__':
    r = random.randrange(2**256)
    s = random.randrange(2**256)

    c_print('r', r)
    c_print('s', s)
    c_print('rps', r + s)
    c_print('rms', r - s)
    c_print('smr', s - r)
