#!/bin/bash -u



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
echo -n "[press enter to continue]"
read
echo

cwd=$(pwd)
build="$cwd/build"
set -e

echo
echo "[*] Installing projects and Python bindings (using sudo)"

echo "[*] Installing keystone"
cd "$build/keystone/build" && sudo make install
echo "[*] Bindings keystone python"
cd "$build/keystone/bindings/python" && sudo make install

echo "[*] Installing capstone"
cd "$build/capstone" && sudo make install
echo "[*] Bindings capstone python"
cd "$build/capstone/bindings/python" && sudo make install

echo "[*] Installing unicorn"
cd "$build/unicorn/build/build" && sudo make installwwwwwwdww
echo "[*] Bindings unicorn python"
cd "$build/unicorn/bindings/python" && sudo make install

which ldconfig &>/dev/null && sudo ldconfig

echo
echo "All done!"
echo
echo -n "Testing Python import: "
python -c "import capstone, keystone, unicorn; capstone.CS_ARCH_X86, unicorn.UC_ARCH_X86, keystone.KS_ARCH_X86; print 'works.'"
