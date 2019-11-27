#!/bin/sh

set -eu

SRC=p256-m.c
CFLAGS_COMMON="-Werror -fomit-frame-pointer -D NO_MAIN $SRC"

gcc() {
    arm-none-eabi-gcc -Wall -Wextra -mthumb \
        -Os $CFLAGS_COMMON "$@"
}

clang() {
    env clang -Weverything -Wno-missing-prototypes --target=arm-none-eabi \
        -Oz $CFLAGS_COMMON "$@"
}

for CC in gcc clang; do
    for CPU in m0; do
        NAME="${CC}-${CPU}"
        $CC -mcpu=cortex-$CPU -S -fverbose-asm -o ${NAME}.s
        $CC -mcpu=cortex-$CPU -c -o ${NAME}.o
        arm-none-eabi-objdump -d ${NAME}.o > ${NAME}.dump
        nm --radix=d --size-sort ${NAME}.o > ${NAME}.sizes
    done
done

arm-none-eabi-size *.o
