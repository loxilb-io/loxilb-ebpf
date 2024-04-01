#!/bin/bash
if [ -d /opt/loxilb/dp/ ]; then
  sudo umount /opt/loxilb/dp/ >> /dev/null 2>&1
  sudo rm -fr /opt/loxilb/dp/bpf >> /dev/null 2>&1
fi
sudo mkdir -p /opt/loxilb/dp/ >> /dev/null 2>&1
sudo mount -t bpf bpf /opt/loxilb/dp/ >> /dev/null 2>&1
