#!/bin/sh

set -eu

SRC=p256-m.c
CFLAGS_COMMON="-Werror --std=c99 -fomit-frame-pointer -mthumb $SRC"

gcc() {
    arm-none-eabi-gcc -Wall -Wextra -pedantic \
        -Os $CFLAGS_COMMON "$@"
}

clang() {
    env clang --target=arm-none-eabi -Weverything \
        -Oz $CFLAGS_COMMON "$@"
}

OBJECTS=''

for CC in gcc clang; do
    for CPU in m0 m4 a5; do
        case $CPU in
            m4|a5)  DMUL='-DMUL64_IS_CONSTANT_TIME';;
            *)      DMUL='';;
        esac
        NAME="${CC}-${CPU}"
        $CC -mcpu=cortex-$CPU $DMUL -S -fverbose-asm -o ${NAME}.s
        $CC -mcpu=cortex-$CPU $DMUL -c -o ${NAME}.o
        arm-none-eabi-objdump -d ${NAME}.o > ${NAME}.dump
        nm --radix=d --size-sort ${NAME}.o > ${NAME}.sizes
        OBJECTS="$OBJECTS ${NAME}.o"
    done
done

arm-none-eabi-size $OBJECTS
