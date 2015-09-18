# Readme

This is my project to convert SigmaVPN into a device which has two interfaces
namely private and public interfaces. The end result expected is to transmit
what is received on private interface to public interface under encryption.

## Cross Compile for ZYBO:

Note that I followed [Embedded Linux Tutorial - Zybo](http://www.instructables.com/id/Embedded-Linux-Tutorial-Zybo/?ALLSTEPS)
tutorial for installing Linux to ZYBO. I used the RAMdisk image provided [here](http://www.wiki.xilinx.com/Build+and+Modify+a+Rootfs).

The Linux version running on the Zybo Board is:

    Linux (none) 3.18.0-xilinx-46110-gd627f5d #1 SMP PREEMPT Tue Aug 25 17:21:47 CEST 2015 armv7l GNU/Linux

### Start by taking the dependencies

Basically use these two commands as it is always the issue when using
`arm-xilinx-linux-gnueabi-`

```
export CROSS_COMPILE=arm-xilinx-linux-gnueabi-
source /opt/Xilinx/Vivado/2014.3.1/settings64.sh
```

### Cross compile libdsodium

Instructions are [here](http://doc.libsodium.org/installation/index.html#cross-compiling),
but I changed them for `arm-xilinx-linux-gnueabi`

Locate the libpcap folder as ../libsodium_installdir

```
export PATH=/opt/Xilinx/SDK/2014.3.1/gnu/arm/lin/bin:$PATH
export CFLAGS='-g'
./configure --host=arm-xilinx-linux-gnueabi --prefix=path/to/libsodium_installdir
make install
```

### Cross compile libpcap

Got help from [here](https://emreboy.wordpress.com/2013/03/02/cross-compile-libpcap-source-code/).
To follow the instructions there, if they are not installed yet,
install these dependencies of making libpcap first:

```
apt-get install flex
apt-cache search yacc
```

Locate the libpcap folder as ../libpcap-1.7.4

Then cross compile libpcap

```
CC=arm-xilinx-linux-gnueabi-gcc ac_cv_linux_vers=2 CFLAGS=-g ./configure --host=arm-xilinx-linux --with-pcap=linux
make
```

### Cross Compile SigmaVPN

Just use Makefile with `ZYBO=1`

```
make ZYBO=1 clean
make ZYBO=1
make ZYBO=1 install
```
