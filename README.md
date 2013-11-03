kfdns4linux
===========

Kernel dns requests filter for Linux


 Experimental initial implementation of filter which can help to protect servers
from DNS amplification attacks. The idea is quite simple. We count DNS requests
and if we exceeded specified threshold we send empty reply with tc flag and drop
original request. In this case DNS resolver should send request again using TCP.
Attacker will not use TCP and his requests will be ignored.

Tested with:

CentOS 6 (2.6.32 kernel)
Gentoo (3.10 kernel)
   

Building from source:

    1. Install packages required to build kernel modules
    2. make 
    
Installing on CentOS 6:
* Install git: ```yum install -y git```
* Get sources: ```
cd /usr/src;
git clone https://github.com/dcherednik/kfdns4linux.git;
cd kfdns4linux;```
* Install kernel headers for CentOS 6: ```yum install -y kernel-devel```
* Install kernel headers for CentOS 6 + OpenVZ:  ```yum install -y vzkernel-devel```
* Make it: ```make```

Using:

    #insmod kfdns.ko threshold=100 period=100

You may use noop=1 parameter for prevent any actions on traffic, it's non dis.

You see list of "bad" IP
    
    #cat /proc/net/kfdns

Limitation:
    1. Only IPv4
    2. Can work only on the servers with DNS server software
