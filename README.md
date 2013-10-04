kfdns4linux
===========

Kernel dns requests filter for Linux


 Experimental initial implementation of filter which can help to protect
from DNS amplification attacks. The idea is quite simple. We count DNS requests
and if we exceeded specified threshold we send empty reply with tc flag and drop
original request. In this case DNS resolver should send request again using TCP.
Attacker will not use TCP and his requests will be ignored.


Building from source:

    1. Install packages required to build kernel modules
    2. make 

Using:

    #insmod kfdns.ko threshold=100 period=100

Limitation:

    0. Not tested
    1. Only IPv4
    2. Not optimized (no NUMA, locking and disabling bh)
    
