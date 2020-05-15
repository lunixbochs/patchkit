#!/usr/bin/env bash

echo
echo "[*] Installing projects and Python bindings (as root)"
cd "$build/keystone/build" && make install
cd "$build/keystone/bindings/python" && make install

cd "$build/capstone" && make install
cd "$build/capstone/bindings/python" && make install

cd "$build/unicorn" && ./make.sh install
cd "$build/unicorn/bindings/python" && make install

which ldconfig &>/dev/null && ldconfig

echo
echo "All done!"
echo
echo -n "Testing Python import: "
python -c "import capstone, keystone, unicorn; capstone.CS_ARCH_X86, unicorn.UC_ARCH_X86, keystone.KS_ARCH_X86; print 'works.'"
