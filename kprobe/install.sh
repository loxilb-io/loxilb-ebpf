#!/bin/bash
sudo apt-get install build-essential linux-headers-`uname -r`
git clone -n --depth=1 --filter=tree:0 https://github.com/loxilb-io/loxilb-ebpf
cd loxilb-ebpf
git sparse-checkout set --no-cone kprobe
git checkout
cd kprobe
make
sudo make install
