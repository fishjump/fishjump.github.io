---
title: 从内核出发手撕Linux网络协议栈(二)
---

## 孔乙己: 系统调用的调用有四种写法

既然这个系列是从源码开始手撕Linux网络协议栈，那么不妨先了解一下Linux的系统调用是如何发生的，然后尝试自己给Linux添加一个系统调用，以便之后更容易了解和学习网络模块的内核实现。

以一个简单的例子开始，以下是一个常规的Hello World。尝试编译这个程序并运行会毫不意外的看到控制台输出了`Hello, World!`。这当然不是我们今天关心的内容。

```c
#include <stdio.h>

int main() {
  printf("Hello, World!\n");
  return 0;
}
```

如果我们尝试使用`strace`命令来查看这个程序，我们会得到大概如下结果。这表明我们的程序使用到了`write`系统调用。此外，好奇的朋友可以通过`man strace`命令来查看`strace`的功能，不必怀疑，这个命令正如说明中表述的那样，可以追踪系统调用和信号。

```bash
strace ./01-regualr-print

# 得到输出：
# execve("./01-regualr-print", ["./01-regualr-print"], 0x7ffd3b369be0 /* 39 vars */) = 0
# .......
# write(1, "Hello, World!\n", 14Hello, World!
# )         = 14
# exit_group(0)                           = ?
# +++ exited with 0 +++
```

那么有没有办法可以直接使用`write`系统调用呢？答案是肯定的。通过输入命令`man syscalls`可以了解到，被封装好的系统调用都已经定义在`unistd.h`这个头文件中。我们仅需要包含这个头文件并且编译就好了。另外，细心的朋友也许注意到了，这个`write`函数其实和我们平时使用C语言读写文件所用的`write`函数是同一个函数。这是因为类Unix系统的设计理念是“一切皆文件”，而且`write`是一个符合POSIX标准的标准C函数。其中，0代表标准输入，1代表标准输出，而2代表标准错误输出。

下面的例子展示了如何通过`write`来输出Hello World。

```c
#include <unistd.h>

int main() {
  const char str[] = "Hello,World!\n";
  write(1, str, sizeof(str));
  return 0;
}
```

但是现在，孔乙己并不满足于这两种系统调用的写法，他还想要学习更多更贴近底层的写法。让我们来使用`man syscall`了解一下C标准库所提供的直接使用系统调用号来进行系统调用的方法。这份说明中除了讲述了函数的原型、功能和样例，也介绍了不同体系结构下系统调用实现方法的差异。总之先让我们来体验下`syscall`函数吧。下面的例子中`__NR_write`是`sys_write`系统调用的调用号的宏定义，在绝大多数情况下，我想你也可以直接使用数字1来代替。其中NR代表Number，这和我们一般使用的No有所差别。除了这是从Unix传承下来的习惯之外，我想也有避免歧义的考量在里面。

```c
#include <sys/syscall.h>
#include <unistd.h>

int main() {
  const char str[] = "Hello,World!\n";
  syscall(__NR_write, 1, str, sizeof(str));
  return 0; 
}
```

到了这里，其实我们已经了解了大部分系统调用的知识。但是，本着怀疑一切的精神，孔乙己想要挑战下`syscall`说明的正确性。文档中说到了x86_64架构下`syscall`是使用哪些寄存器来传递参数的，那么就让我们来验证一下。

```asm
section .data
    msg db 'Hello,World!', 0xa  ; 0xa 是换行符
    len equ $ - msg             ; 计算消息的长度

section .text
    global _start

_start:
    ; sys_write 的系统调用号为 1
    mov rax, 1                  ; 将系统调用号 1 (sys_write) 存入 rax 寄存器
    mov rdi, 1                  ; 文件描述符为 1 (stdout)
    mov rsi, msg                ; 将消息的地址存入 rsi 寄存器
    mov rdx, len                ; 将消息的长度存入 rdx 寄存器
    syscall                     ; 调用系统调用
    mov rax, 0

    ; 退出系统调用的编号为 60，等效于c语言中exit(0)
    mov rax, 60                 ; 将系统调用号 60 (sys_exit) 存入 rax 寄存器
    xor rdi, rdi                ; 将退出码 0 存入 rdi 寄存器
    syscall                     ; 调用系统调用
```

特别说明，这里我使用了nasm的语法规则，可以使用以下命令来编译。由于我们使用汇编来开发，没有走正常的`main`作为入口，而是使用elf标准中规定的`_start`作为程序入口（c语言中的`main`函数事实上会被编译器生成的`_start`函数调用）。因此，为了程序可以正常退出，我们还需要额外执行`sys_exit`系统调用来告诉系统我们的程序正常结束了。

```bash
nasm -f elf64 -o 04-x86syscall.o 04-x86syscall.S
ld -o 04-x86syscall 04-x86syscall.o
```

## Hacking in the kernel

现在我们已经了解了Linux的系统调用了，让我们尝试给Linux加入自己设计的系统调用吧！

首先，我们需要打开源代码根目录下`./arch/x86/entry/syscalls/syscall_64.tbl`这个文件，在最后一行追加我们自己的系统调用，我把它取名为`hacing`，如下。

```bash
# <调用号>  <ABI>   <名字>           <对应函数名>
335       common  hacking         __x64_sys_hacking

```

然后我们需要在`./include/linux/syscalls.h`中添加我们的函数声明，如下。这时候为了防止错误，最好紧跟你的上一个系统调用添加声明。有时候没有添加对地方可以被放进一个错误的`#if`预处理宏中间从而导致声明没有被正确添加。

```c
asmlinkage long sys_hacking(char *str, size_t len);
```

最后，我们需要在`./kernel/sys.c`文件中实现我们的系统调用了。这一步其实是相对很自由的，你可以在几乎任何地方实现这个函数，只要最后能被正确链接理论上都是可行的。一部分平台相关的系统调用其实放在了`./arch/x86`目录下，而一些放在了上面说的文件中。你甚至可以自己新建一个文件来实现。但是为了避免一些问题，就让我们随大流编辑`./kernel/sys.c`吧。

```c
SYSCALL_DEFINE2(hacking, char __user *, str, size_t, len) {
	int ret;
	char buffer[256];
	if (len > 256) {
		return -1;
	}

	ret = copy_from_user(buffer, str, len);
	printk("Well done, %d. You hacked into the kernel.\n", buffer);
	return ret;
}
```

其中`SYSCALL_DEFINE2`宏帮助我们定义一个带有两个参数的系统调用，名字叫`hacking`。当然我们完全可以不使用`SYSCALL_DEFINE2`而是使用我们之前声明的函数原型，这是完全没有错的，不过为了风格统一，这里使用了`SYSCALL_DEFINE2`宏。`__user`是一个宏定义，没有任何作用，仅仅作为提示，表示这个地址来自于用户空间，因此需要内核函数`copy_from_user`将其复制到内核空间再使用。

让我们再次使用`make`命令来编译内核。与此同时，我们可以开始制作一个用户态的应用程序并且放入根文件系统中，来调用我们自定义的系统调用。请注意，由于busybox不带libc等动态链接库，因此这里需要使用`gcc hacking_syscall.c -o hacking_syscall --static`来进行静态链接。

```c
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  if (argc != 2) {
    const char str[] = "default man";
    syscall(335, str, sizeof(str));
    return 0;
  }

  syscall(335, argv[1], strlen(argv[1]) + 1);
  return 0;
}
```

让我们将这个程序复制进`busybox/__install/bin`目录中，再次打包根文件系统并且进入qemu，敲下命令`hacking_syscall`。我们成功实现了自己的系统调用。

![](/images/linux-kernel-net-02-01.png)

## 参考文档

strace文档：https://man7.org/linux/man-pages/man1/strace.1.html

syscalls文档：https://man7.org/linux/man-pages/man2/syscalls.2.html

syscall文档：https://man7.org/linux/man-pages/man2/syscall.2.html
