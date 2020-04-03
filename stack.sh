#!/bin/sh

arm-none-eabi-gcc -c -fdump-rtl-dfinish -fstack-usage \
    -Os -fomit-frame-pointer -mthumb -mcpu=cortex-m0 \
    p256-m.c
python wcs.py
