#!/bin/bash
if [ ! -d /opt/loxilb/cgroup/ ]; then
  mkdir -p /opt/loxilb/cgroup/ && mount -t cgroup2 -o rw,relatime,nsdelegate,memory_recursiveprot cgroup2 /opt/loxilb/cgroup/;
else
  umount /opt/loxilb/cgroup/;
  mount -t cgroup2 -o rw,relatime,nsdelegate,memory_recursiveprot cgroup2 /opt/loxilb/cgroup/;
fi
