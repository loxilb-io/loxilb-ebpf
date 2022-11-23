[![eBPF Emerging Project](https://img.shields.io/badge/ebpf.io-Emerging--Project-success)](https://ebpf.io/projects#loxilb) ![gpl](https://img.shields.io/badge/license-GPL-blue.svg)  ![bsd](https://img.shields.io/badge/license-BSD-blue.svg)

## This README is here for anyone who wants to build loxilb ebpf only modules

## Install Dependencies

sudo apt install clang llvm libelf-dev gcc-multilib libpcap-dev  
sudo apt install linux-tools-$(uname -r)  
sudo apt install elfutils dwarves  

## Build libbpf

cd libbpf/src  
sudo make install  
sudo ldconfig  

## Build loxilb ebpf

cd -   
make  
