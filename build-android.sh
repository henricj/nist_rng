#!/bin/bash

ANDROID_NDK_ROOT=$1

if [ ! -d "${ANDROID_NDK_ROOT}" ] ; then
    echo "please specify the android NDK root as first parameter";
    exit 1;
fi

set -e

CMAKEPARAMS="-DCMAKE_BUILD_TYPE=Release -DANDROID_NDK=${ANDROID_NDK_ROOT} \
    -DANDROID_NATIVE_API_LEVEL=android-17 -DANDROID_STL_FORCE_FEATURES=ON \
    -DCMAKE_TOOLCHAIN_FILE=../../cmake//android.toolchain.cmake \
    -DCMAKE_INSTALL_PREFIX=out"

mkdir buildandroid
cd buildandroid

mkdir armeabi-v7a
cd armeabi-v7a
cmake ${CMAKEPARAMS} -DANDROID_TOOLCHAIN_NAME=arm-linux-androideabi-4.9 -DANDROID_ABI=armeabi-v7a ../../ || exit 1
make install
cd ..

mkdir arm64-v8a
cd arm64-v8a
cmake ${CMAKEPARAMS} -DANDROID_TOOLCHAIN_NAME=aarch64-linux-android-4.9 -DANDROID_ABI=arm64-v8a ../../ || exit 1
make install
cd ..

mkdir mips
cd mips
cmake ${CMAKEPARAMS} -DANDROID_TOOLCHAIN_NAME=mipsel-linux-android-4.9 -DANDROID_ABI=mips ../../ || exit 1
make install
cd ..

mkdir mips64
cd mips64
cmake ${CMAKEPARAMS} -DANDROID_TOOLCHAIN_NAME=mips64el-linux-android-4.9 -DANDROID_ABI=mips64 ../../ || exit 1
make install
cd ..

mkdir x86
cd x86
cmake ${CMAKEPARAMS} -DANDROID_TOOLCHAIN_NAME=x86-4.9 -DANDROID_ABI=x86 ../../ || exit 1
make install
cd ..

mkdir x86_64
cd x86_64
cmake ${CMAKEPARAMS} -DANDROID_TOOLCHAIN_NAME=x86_64-4.9 -DANDROID_ABI=x86_64 ../../ || exit 1
make install
cd ..
