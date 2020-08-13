#!/bin/sh

for CPU in m0 m4 a5; do
    echo "*** $CPU ***"
    arm-none-eabi-gcc -c -fdump-rtl-dfinish -fstack-usage \
        -Os -fomit-frame-pointer -mthumb -mcpu=cortex-$CPU \
        p256-m.c

    # fix stack usage of naked function (asm)
    if [ $CPU = m0 ]; then
        sed -i '/u32_muladd64/ s/\b0\b/8/' p256-m.su
    fi

    python3 wcs.py | sed -n 's/^..p256-m.c *p256_/p256_/p'
done
