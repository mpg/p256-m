#!/bin/sh

set -eu

CPU_LIST='m0 m0plus m3 m4 m7 m23 m33'

for CPU in $CPU_LIST; do
    arm-none-eabi-gcc -mcpu=cortex-$CPU -mthumb -dM -E - </dev/null |
        sort > macros-gcc-$CPU.txt
    clang --target=arm-none-eabi -mcpu=cortex-$CPU -dM -E - </dev/null |
        sort > macros-clang-$CPU.txt
done

get_macro() {
    RE=$1
    CC=$2
    CPU=$3

    sed -n "s/^#define $RE \(.*\)/\1/p" macros-$CC-$CPU.txt
}

for MACRO_RE in __GNUC__ __ARM_ARCH __ARM_ARCH_PROFILE __ARM_FEATURE_DSP; do
    printf "\n%s\n      " "$MACRO_RE"
    for CPU in $CPU_LIST; do
        printf "%7s " $CPU
    done
    printf "\n"
    for CC in gcc clang; do
        printf "%5s " $CC
        for CPU in $CPU_LIST; do
            printf "%7s " $(get_macro "$MACRO_RE" $CC $CPU)
        done
        printf "\n"
    done
done

# comment out for manual exploration
rm macros-*.txt
