# Readme

This is the SigmaVPN's fork fot the "Hardware Acceleration of a Software-based VPN" project. The project aims creating a VPN Device design using SigmaVPN application as the base VPN solution. The SigmaVPN is altered to construct a VPN Device which utilize a cryptogprahic hardware acceleration to execute expensive cryptographic operations in a short time, and maximize the communication bandwidth. Moreover, the device, works with two Ethernet ports: One is public and the other is private communication ports.

The parent repository of the project and details of it can be found [here](https://github.com/furkanturan/Hardware-Accelerated-SigmaVPN).

# How to Cross-Compiles SigmaVPN for ZYBO Board 

First the libraries should be cross compiled

The linux version running on my ZYBO board is:

```
Linux (none) 3.18.0-xilinx-46110-gd627f5d #1 SMP PREEMPT Tue Aug 25 17:21:47 CEST 2015 armv7l GNU/Linux
```

Run these commands on Terminal to reach the cross compiler. They will change according to the Vivado version you are running

```
export CROSS_COMPILE=arm-xilinx-linux-gnueabi-
source /opt/Xilinx/Vivado/2014.3.1/settings64.sh
```

## Cross compile libdsodium 

I crosscompiled them into: `.../SigmaVPN/Zybo/libsodium_installdir`

I used the instructions are [here](https://download.libsodium.org/libsodium/content/installation/), but I changed them for `arm-xilinx-linux-gnueabi`

```
export PATH=/opt/Xilinx/SDK/2014.3.1/gnu/arm/lin/bin:$PATH
export CFLAGS='-g'
./configure --host=arm-xilinx-linux-gnueabi --prefix=.../SigmaVPN/Zybo/libsodium_installdir
make install
```

## Cross compile libpcap 

I got hep from [here](https://emreboy.wordpress.com/2013/03/02/cross-compile-libpcap-source-code/). To cross compile libpcap install these dependencies of making libpcap first:

```
apt-get install flex
apt-cache search yacc
```

Then cross compile libpcap

```
CC=arm-xilinx-linux-gnueabi-gcc ac_cv_linux_vers=2 CFLAGS=-g ./configure --host=arm-xilinx-linux --with-pcap=linux
make
```

## Cross compile the SigmaVPN  

Just use the new Makefile file provided in SigmaVPN's folder with following parameter. The last line will create the output files in the folder `BootFiles/sigmavpn/sigmavpn_installdir`.

```
make ZYBO=1 clean
make ZYBO=1
make ZYBO=1 install
``` 



