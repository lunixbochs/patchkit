#!/usr/bin/env bash

echo
echo "Take a look here if Unicorn fails to build:"
echo " https://github.com/unicorn-engine/unicorn/blob/master/docs/COMPILE-NIX.md"
echo
echo "If you're on Ubuntu, you want to do this first:"
echo " sudo apt-get update"
echo " sudo apt-get install python-pip build-essential git cmake python-dev libglib2.0-dev"
echo
echo "If you're on a Mac, do this first:"
echo " brew install pkg-config glib cmake"
echo
echo "Using ./build as a tmp dir. ^C if that's a bad idea."
echo
if [ ! "${HEADLESS}" ]; then
	echo -n "[press enter to continue]"
	read
fi
echo

cwd=$(pwd)
export build="${cwd}/build"

mkdir build &>/dev/null
set -e

echo "[*] Building Keystone"
cd "${build}"
git clone https://github.com/keystone-engine/keystone.git
cd keystone && mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DLLVM_TARGETS_TO_BUILD="all" -G "Unix Makefiles" .. && make -j2
echo

echo "[*] Building Capstone"
cd "${build}"
git clone https://github.com/aquynh/capstone.git
cd capstone && make -j2
echo

echo "[*] Building Unicorn"
cd "${build}"
git clone https://github.com/unicorn-engine/unicorn.git
cd unicorn && ./make.sh

if [ ! "${HEADLESS}" ]; then
	sudo ./install.sh
fi
