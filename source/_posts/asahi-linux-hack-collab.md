---
title: '"I Hacked macOS" Stream Followup'
---

Asahi Lina在17号直播了如何使用一个普通用户一键拿到root权限(事实上,这还是她拿到权限的降权)。

[直播回放链接](https://www.youtube.com/watch?v=hDek2cp0dmI)

整个直播内容很有启发性，由浅入深的解释了整个过程以及其背后的原理，我相信每个人看完都会有所收获。

### 内容大纲

1. GPU Basics
2. Virtual Memory
3. GPU command buffer
4. Apple's secret uPPL
5. Return-oriented programming

要了解整个hack的过程，我们首先需要对GPU这个物理硬件有一定的基础知识，这也会在第一部分讲述。然后，我们需要了解到一些关于虚拟内存的相关内容，绝大多数计算机专业的人应该都清楚这个概念，因此只会提到和hack相关的一些概念而不会全部讲解。接着是GPU command buffer，它用于缓存将要发送给GPU执行的指令的队列。随后我们需要知道uPPL这个Feature的存在，它是一个Apple Silicon私有的CPU特性。传统CPU拥有Ring0-3四个特权级别，0最高而3最低，但是在Apple Silicon中，uPPL是类似于Ring -1级别的存在。最后是一个面向返回值的编程，通过破坏栈结构来构造我们想要的返回值，以及实现任意地址跳转，有相关经验的朋友肯定知道是什么原理，具体内容会在之后解释。

这个Hack最终可以得到全地址空间的任意读写（chmod 777 /dev/mem），因此，可以说取得root权限反而是一种“降权”，因为root也讲究尊重页表映射。

## GPU Basics

![cpuvsgpu](/images/asahi-linux-hack-collab-cpuvsgpu.png)

GPU和CPU没有本质上的区别，他们都是一种计算单元，接收输入，然后得到输出。区别在于，GPU可以一次性接收大量的输入，然后并行地进行计算，最后得到大量的输出。此外，GPU内部计算单元更多，但是频率更低，因此，GPU更适合于大量的简单并行计算，而CPU更适合于复杂计算（往往是串行的）。

在这次的hack当中，读者不需要掌握更多关于GPU并行计算的只是，只要把它当作一个独立于CPU的CPU就好了。

### Apple GPU Archtechture

![applegpuarch](/images/asahi-linux-hack-collab-applegpuarch.png)

Apple的GPU如图，内核向coprocessor发送指令，然后coprocessor再将指令发送给GPU硬件。这里的coprocessor是另一个独立于CPU的CPU，但是它也是一个”标准“的CPU（这里是指标准的armv8 cpu），不过性能相对于CPU较低。这样做可以加速CPU和GPU之间的通信，因为这样GPU Firmware不必跑在主CPU上占用资源，而是可以直接在coprocessor上运行。

对于了解GPU传统使用方法的朋友肯定可以理解VDM和PDM的用处，他们分别负责场景中顶点位置和像素色彩的计算，通常在Shader程序中叫做vertex shader和fragment shader。这里不会详细讲解这两个概念，重点是CDM。因为机器学习的原因流行，General-purpose computing on graphics processing units（GPGPU）的概念越来越普及，CDM就是用于这个目的的，它可以用于通用并行计算，而非仅仅是图形学相关的计算（尽管在其出现之前就有不少人教你如何使用shader来进行科学计算，不过这算一种野路子）。

此外需要注意的是，这些Data Master仅仅是用于任务调度，指令发送，其真实的计算是由背后的USC来完成的。

## Virtual Memory

```c++
#include <iostream>

using namespace std;

int main() {
    int a = 0;
    void *p = &a;

    // output is "&a is 0x7fffc6ba5ddc"
    cout << "&a is " << p << endl;

    return 0;
}
```

在现代操作系统中，任何程序都是跑在虚拟内存之上的，例如你打印一个变量的内存地址，你会得到一个地址，例如这里是`0x7fffc6ba5ddc`。地址中每个“1”代表了1 Byte的内存，前面的地址则代表这个变量处于第一百多TB的内存位置，这显然是不可能的，因为通常我们的内存只有几十GB。这就是虚拟内存的作用，它将物理内存映射到虚拟内存。在这里这个物理地址的值是`0x814745ddc`，大概是内存32GB的空间左右。如果你对如何实现虚拟地址到物理地址感兴趣，你可以研究一下Linux中如何获取页表，通常是和硬件相关的，例如x86的CPU会有一个CR3寄存器，而ARMv8则是TTBR0和TTBR1寄存器，你通常需要在内核态才能访问到这些寄存器。

### 虚拟地址到物理地址的映射是如何实现的？

![addrmapping](/images/asahi-linux-hack-collab-addrmapping.png)

大家可以注意到以上两个地址，`0x7fffc6ba5ddc`和`0x814745ddc`，其末尾的`0x5ddc`是相同的，也就是说，这是一个页内偏移，页大小最大为`2^(4*4)=64kb`,事实上，Apple使用了16KB的页表，也就是一个64位的地址中，最后14位是页内偏移。`0x5ddc`的5之所以相同只是因为这两个虚拟地址的页号和物理地址的前缀的最后两位恰好为0而已。

![addrmapping-1](/images/asahi-linux-hack-collab-addrmapping-1.png)

值得注意的是，每个进程可都有自己的页表，因此不同程序可以拥有相同的虚拟地址而不会导致地址冲突。例如，Cyan和Lina都用有地址`0x12345`，而他们分别在各自的进程内指向不同的物理地址，这样就不会冲突。同样的原理，Linux内核页拥有自己的页表。事实上，在Linux上有这样一个规则，高地址永远代表内核空间，低地址代表用户空间，如下图所示。

![highlowaddr](/images/asahi-linux-hack-collab-highlowaddr.png)

将64位地址等分为两部分，高地址部分为内核空间，低地址部分为用户空间。高地址空间的内容由所有进程共享，而低地址空间的内容则由每个进程独立拥有。也就是说，如果你在进程Cyan中修改了某个内核空间的地址，那么进程Lina也会看到这个修改，但是如果你在进程Cyan中修改了某个用户空间的地址，那么进程Lina是看不到这个修改的。

让我们短暂回到hack这个主题，由于coprocessor也是一个标准的CPU，其也有自己的页表，结构大概如下图所示，其页表结构与主CPU完全相同，因为它们都是标准的CPU。但是权限配置略有不同，因为主CPU需要频繁切换到用户/内核态，而协处理器的firmware几乎只工作在内核态，除非渲染的上下文被显式的更换。

![coprocaddr](/images/asahi-linux-hack-collab-coprocaddr.png)

### 统一物理内存 （Unified Memory）


这一部分是比较tricky的部分，由于Apple使用了统一物理内存，我们不必通过PCIe来进行CPU/GPU数据交换，这可以显著提高性能。但是这也意味着，**我们可以在GPU上直接访问CPU的内存**，这就是这次hack的关键所在。

让我们先来看一下，在用户态下，这个流程是怎么样的。对于CPU而言，我们需要将一张材质（texture），通常是一张图片，放入内存中。然后创建一个Shader Program，以及我们的用户程序，理所应当的，也是在内存当中。

然后是对于GPU而言，它并不关心具体的用户程序内容，它只知道获取shader program以及所需的材质。然后，GPU会渲染并输出一张图片，放入内存当中。最后，Screen Controller（屏幕控制器）会将这张图片显示在屏幕上，也就是我们平时在显示器看到的内容。注意最后一步并没有涉及到CPU，屏幕控制器会直接从固定物理地址处读取像素数据，然后显示在屏幕上。

在整个过程中，shader program和用户空间的程序都是跑在各自对应的页表中的。我们无法直接控制shader program去读取任何物理地址的内容。

![cpugpuuser](/images/asahi-linux-hack-collab-cpugpuuser.png)

在内核态下，CPU和GPU的交互则是这样的。如下图，CPU在启动阶段会配置其自身的页表以及coprocessor的页表（写入内存中），然后协处理器会将firmware也加载到内存中，不过CPU并不关心firmware的具体内容。当然，Linux内核也会在启动时写入内存，但是GPU同样不关心其具体内容。在GPU工作时，本质上是CPU向内存写入指令，然后协处理器从内存中读取指令，调用GPU功能。在这里，其实是用到了MMIO的概念，也就是Memory Mapped IO，这是一种特殊的IO方式，将IO设备的寄存器映射到内存中，然后通过读写内存来控制IO设备。这里的GPU就是一个IO设备，其寄存器被映射到内存中，然后CPU通过写入内存来控制GPU。除此之外，其上还有其他方式可以控制GPU，例如PCIe，但是苹果并没有使用这种方式。

![cpugpukernel](/images/asahi-linux-hack-collab-cpugpukernel.png)

### 页表（Page Table）

现在可以来回顾以下页表的结构，以便我们更好的理解后续的内容。如下图所示，如果使用一个大页表，对于64位的CPU，假设每个表项（一页，16KB）占用8Byte，那么配置1TB大小的虚拟地址（40bit有效位）就需要512MB的页表，这个开销有点大。还记得之前提到过，为了实现进程间的隔离，每个应用都有其单独的页表，因此，如果有100个进程，那么就需要100个页表，也就是50GB的内存，只为了存储页表，这显然是不现实的。

![onebigtable](/images/asahi-linux-hack-collab-onebigtable.png)

所以，现代CPU普遍使用可配置的多级页表，例如x86的CPU通常配置为三级页表（512B页大小）。Apple Scilicon属于ARMv8架构，Apple配置为三级页表，页大小为16KB。如下图，我们并不需要为所有分支配置真实存在的页表，直到其真正被使用。大多数现代CPU并不完全支持64位地址，如下图，第一级页表使用3位，第二级和第三级均分别占用11位，页大小为16KB，即14位（2^14=16KB），总计39位。这是一个已经足够大的空间(512GB)，至少短时间内不会存在不够用的情况。此外，ARMv8在硬件上区分了用户空间和内核空间的地址，如果我们想要访问用户空间的地址，那么我们需要访问TTBR0，如果我们想要访问内核空间的地址，那么我们需要访问TTBR1。

![treetable](/images/asahi-linux-hack-collab-treetable.png)

以下是一个具体的例子：

![vmemcvt](/images/asahi-linux-hack-collab-vmemcvt.png)

由于最高位是0，因此访问TTB0寄存器，TTB0寄存器存储了用户态L1 Table的**物理内存地址**，然后接下来3bit为`0b001=1`，因此访问L1 Table的第1个表项（从0开始计数）。同理类推，直到最后L3 Table记录了前面这写地址所对应的物理地址，然后再拼接上最后14位页内偏移，得到最终的物理地址。注意，这里的地址是40位（1位TTB，39位虚拟地址），而不是64位。在真正的程序中，前面的地址需要和TTB位相同，也就是全0或者全1，否则会引起CPU异常。

### 页表权限

![pageperm](/images/asahi-linux-hack-collab-pageperm.png)

这是一个简化后的例子，每个表项除了有下一级表的物理地址外，还有一些附带的信息来辅助完成一些功能，例如权限控制，页面置换算法等，这里只考虑协处理器和GPU的权限。举个例子，比如对于存有内核信息的页，firmware和GPU都没有访问其的权限，GPU没有访问firmware内容的权限等。

下面是GPU固件和GPU的内容以及权限的对应关系：

![gpuperm](/images/asahi-linux-hack-collab-gpuperm.png)

记住GPU Firmware的协处理器和GPU并不是同一个东西，协处理器是一个标准的CPU，而GPU是一个专用的硬件。在协处理器上，固件会改写其页表以将不同的内容写入到不同的GPU Context中。Apple Silicon的GPU支持最多同时加载64个Shader Program，称为Context0到Context63。此外需要注意的是，Context 0是CPU内核独享的，用于GUI渲染等系统高优先级任务，通常我们从Context1开始使用。此外，在GPU上，我们是没有访问GPU固件页表，固件，和Firmware Command的权限的（这一点由GPU上的MMU，也就是内存管理单元来实现）。Firmware Command是一个程序，类似于JVM的存在，是Apple私有的内容。你可以从Kernel Driver发送字节指令给Firmware Command，然后其会执行这些指令。Buffer Control用于控制GPU的缓冲区，例如你可以将一个Shader Program的输出放入缓冲区，称为FBO（Frame Buffer Object），然后当作另一个Shader Program的输入（而不是读取CPU放置的内容），高级的图形驱动也通过Buffer Control来支持局部渲染，提高渲染性能，不过这些信息和今天的主题无关，不再更详细的解释。

### TTBAT（Translation Table Base Address Table）

![ttbat](/images/asahi-linux-hack-collab-ttbat.png)

GPU并没有一个标准的MMU，但是无论如何，它需要一种方式来实现Context切换的功能，也就说，它至少需要知道Context的地址在哪里。这就是TTBAT的作用，它是一个固定的页表，用于存储Context的地址。如上图，各个Context所对应的TTB0地址均不一样，而TTB1均一样。

## 开始Hack！！！

现在你已经掌握了全部的基础知识了，来看看Apple在什么地方犯了错，让我们有机会可以Hack它。

![memmap](/images/asahi-linux-hack-collab-memmap.png)

Lina在逆向Apple GPU驱动的适合发现了这些页表配置。我们虽然不知道具体哪些比特位代表什么样的权限，但是我们可以知道哪些表项的权限相同，然后我们可以知道哪些功能的权限是如何的。如图，三个红色的权限是相同的，其中一个可能是Read only，一个一定是R/w，那么红色的权限就是R/W。那么，问题来了，Lina发现了一个不认识的表项，其权限也是R/W，经过进一步的分析，这个表项是Firmware Command Buffer所在的地址空间，理论上它不应该可以被GPU访问。

### Firmware Command Buffer

![cmdbuffer](/images/asahi-linux-hack-collab-cmdbuffer.png)

我们可以通过运行在CPU上的GPU驱动向协处理器发送上面这样一个格式的调用，其中microsequence就是上面提到的，Firmware Command可以像JVM一样解释执行的字节码。按理来说，这样的字节码功能是有限的，但是Apple可能是为了方便调试的原因，把所有的功能都放在了这里，导致这个字节码是图灵完备的，也就是说，我们可以在这里实现任何功能。比如我们可以通过load/store指令来读写内存，通过test指令来比较大小（if控制流），通过add来实现计算（例如逻辑运算，比如异或和加法来实现减法，通过加法和循环来实现乘法），通过jump指令来执行有条件/无条件跳转。这样，我们就可以实现任何功能了。

![isa](/images/asahi-linux-hack-collab-isa.png)

总结一下，这个破解思路是，首先CPU向协处理器发送字节码，然后协处理器将字节码写入到Firmware Command Buffer，然后Firmware Command解释执行这些字节码。到此为止，我们还没有任何权限，但是，由于Firmware Command会调用GPU去执行我们的shader program，此时，我们是控制GPU的，而恰好GPU上的页表配置错误，导致我们可以访问Firmware Command Buffer。在Shader程序执行结束后，协处理器会从协处理器的栈上读取返回地址从而返回到上一层Firmware Command中的函数，但是此时这个栈上的内容已经被我们修改了，因此，我们可以实现任意地址跳转。整个过程的修改是在GPU上完成的，但是最终我们取得的是协处理器的虚拟机权限。具体如何操作，我们会在之后的内容中讲解。

是到此为止，我们还只拥有Firmware Command的读写权限，而不是全部内存的读写权限。我们需要进一步的提升权限。

### Self-Modifying Code

![smc](/images/asahi-linux-hack-collab-smc.png)

现在思考一下，由于microsequence的执行内容是固定的，唯一的变数就是microsequence会调用我们写的shader程序，那么我们能不能在shader程序中实现任意功能呢？答案是肯定的。由于冯诺以曼结构，程序的数据和程序本身都是在内存中。例如，一段shader程序将一个地址写入到xxx地址，而xxx的地址就是下一条指令的地址，这样就等于我修改了这个程序自身，从而可以实现任意地址跳转，最后将程序跳转到我们想要执行的firmware command中的指令序列。通常来说，程序所在的内存是只读的，但是这里由于Apple的失误，我们可以自由的在运行时修改程序的内容。

### uPPL

到此为止，我们只能修改Firmware Command Buffer的内容，其实这本身没有太大意义，我们只能很有限的修改协处理器的行为，但是我们无法修改CPU的行为。

但是，我们可以利用uPPL的一个漏洞！

![uPPL](/images/asahi-linux-hack-collab-uPPL.png)

也许有细心的人可以意识到，uPPL是CPU的一个部分，适用于主CPU和协处理器。如果你打算在协处理器上访问uPPL的配置，uPPL本身，或者其他页表或内核数据的数据，那么这些请求都会被uPPL拒绝。注意，这是虽然说uPPL有全部页表的访问权限，但是只是它自己有权限，如果外部请求访问这些敏感内容，它有权利拒绝（如果配置正确的话）。

但是访问TTBAT（也就是GPU的页表）呢？它不阻止你在协处理器上读写TTBAT，似乎苹果写协处理器部分的程序员没有意识到GPU上的问题，因此只配置了CPU部分的权限！

也许还有人要问，那么是否可以在GPU上直接修改TTBAT呢？答案是不可以，因为GPU上的MMU会阻止你这么做。

### Hack流程

现在已经可以得到一个大致的流程了：
1. 通过我们的shader程序，修改Firmware Command Buffer中的内容，获取Firmware Command的控制权限
2. 通过coprocessor，修改GPU的页表，获取GPU的控制权限
3. 将任意地址映射写入GPU的页表，假装其是一个Context
4. 再次调用shader程序，修改假Context的内容，实现任意地址读写
5. 修改firmware command这个虚拟机本身的内容，实现执行任意汇编指令（之前只能执行虚拟机中的字节码）
6. 自然而然的，我们可以拿到root shell了

### Return-Oriented Programming

![rop](/images/asahi-linux-hack-collab-rop.png)

要拿到虚拟机和协处理器的控制权限，我们需要知道一个函数是如何返回的。尽管两者在细节上略有不同，但是本质是一样的。

如上图，x86架构下函数的返回地址会在栈上。而ARMv8架构下，对于单层函数调用，会有一个Link Register（LR）来存储返回地址。而对于多层函数调用，会先将现有的LR压入栈中，然后将新的LR写入到LR寄存器中。总之，我们只需要修改当前的栈内容，就可以控制函数的返回地址了。


### Root Shell获取

Lina没有在直播中在这里多做讲解，大概原理就是，扫描macOS内核中的特定内容（因为内核代码中一定存在magic number），找到这个特定内容之后，由于我们可以很容易的在内核态执行代码来获取内核函数以及内核头的虚拟地址等信息，我们可以通过这个特定内容计算出内核头的物理地址，然后我们再找到获取root权限的函数，通过ROP的方式调用这个函数，就可以拿到root权限了。
