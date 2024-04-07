---
title: 从内核出发手撕Linux网络协议栈(一)
---

## 随笔

接触Linux也几年时间了，翻过不少相关博客和书籍，尝试过啃一些Linux内核源代码，但总觉得少了点什么。琢磨来琢磨去，渐渐有了个想法：或许是缺少了理论与实践的结合。书上的知识虽珍贵，实践却是另一回事。曾经写过不少代码，读过不少书，但书归书，实践归实践。于是，我决定要开始真正动手，去改动Linux内核源代码，试着用自己的思路替换或改进其中的网络协议栈。这个计划，我暂且命名为“忒修斯的船”。

## 目标

现在这个计划的第一步就是从源码开始编译出一个可以运行的Linux系统。为此，这里需要知道一些基本的知识。Linux内核本身仅提供了对硬件的抽象和管理，它包含了操作系统的核心功能，比如进程管理、内存管理、文件系统等。Linux内核提供了系统调用接口，使用户空间程序可以与硬件进行交互，并且提供了一系列的API供用户空间程序调用，以便进行系统操作。而Linux发行版通常还包含了其他用户空间的程序和工具，例如系统库、Shell、命令行工具、图形界面环境等。

这篇文章将采用Linux 4.19内核，这是[Kernel.org](http://kernel.org)上最古老且长期受支持的版本。选择这个老版本的内核是因为新版本引入了许多复杂的新功能和优化，这些对新手来说可能有些难以理解，并且可能会让读者分心，不利于形成自己的内核源码阅读方法论，尤其是对于内核的大体框架和设计思路。获取内核后，我们将使用busybox构建我们的根文件系统，即Linux系统中的Shell和命令行工具等。最后，我们将使用qemu启动我们自己的“Linux发行版”。

## 编译Linux源码

读者可以在[Kernel.org](http://kernel.org)上自行下载并解压，或者使用下面的命令下载。

```bash
wget https://mirrors.edge.kernel.org/pub/linux/kernel/v4.x/linux-4.19.311.tar.gz
tar -xvf linux-4.19.311.tar.gz
```

本例中使用的是x86环境，如果想要编译到其他环境，按需要可能需要交叉编译器。如果是Apple Silicon Mac用户，那么就需要指定目标架构是arm。

```bash
export ARCH=x86
```

然后我们需要配置我们的内核，为了避免一个一个设置带来的繁琐操作，可以先生成一个默认的配置然后再进行微调。

```bash
# 直接保存退出
make x86_64_defconfig

# 开启Gneral setup --> Initial RAM filesystem and RAM disk (initramfs/initrd) support
# 开启Device Drivers --> Block Devices --> RAM block device support
make menuconfig

# 编译Linux内核，可能需要安装一些软件，读者根据提示和自己的发行版来安装。
# 编译输出为arch/x86_64/boot/bzImage
make
```

我们之所以启用这些设置，主要是因为我希望能够在内存中展开我们的rootfs，而不是实际挂载一个硬盘。当然，我们可以创建一个虚拟硬盘文件，将rootfs写入其中，并将其指定给qemu，但这样做太过繁琐。目前，我们的关注重点并不在这些事情上，而是从源代码中构建一个可以启动的Linux系统。

## 编译Busybox

在我们着手编译Busybox之前，首先需要获取其源代码并进行编译。尽管我们并不深入研究Busybox的源码，但值得注意的是，Busybox并不直接影响内核的运行。因此，在理论上，我们可以选择任何版本的Busybox进行编译。在这次的操作中，我选择了最新版本的Busybox源码。

```bash
wget https://www.busybox.net/downloads/busybox-1.36.1.tar.bz2
tar -xvf busybox-1.36.1.tar.bz2
```

由于Busybox的主要目的是提供一个精简的Unix工具集，因此它并不编译任何动态链接库。在完成下载和解压后，我们需要配置Busybox的编译选项，将其设置为静态链接，这样它就不会依赖于任何动态库。否则，如果将Busybox放入我们的根文件系统并启动我们自己的Linux，可能会因缺少依赖而导致运行失败。

```bash
# 开启Busybox Settings --> Build Options --> Build BusyBox as a static binary (no shared libs)
make menuconfig

# 编译输出为busybox源码目录下的_install目录
make && make install
```

除了编译Busybox，我们还需要额外创建一些文件和目录，具体如下所示。其中，部分命令需要以sudo或者root权限执行：

```bash
mkdir etc dev mnt proc sys tmp
mkdir etc/init.d

# 内容设置为:
# proc        /proc           proc         defaults        0        0
# tmpfs       /tmp            tmpfs    　　defaults        0        0
# sysfs       /sys            sysfs        defaults        0        0
vim etc/fstab

# 内容设置为:
# echo -e "Welcome to tinyLinux"
# /bin/mount -a
# echo -e "Remounting the root filesystem"
# mount  -o  remount,rw  /
# mkdir -p /dev/pts
# mount -t devpts devpts /dev/pts
# echo /sbin/mdev > /proc/sys/kernel/hotplug
# mdev -s
vim etc/init.d/rcS
chmod 755 etc/init.d/rcS

# 内容设置为:
# ::sysinit:/etc/init.d/rcS
# ::respawn:-/bin/sh
# ::askfirst:-/bin/sh
vim etc/inittab
chmod 755 etc/inittab
```

在Linux系统中，fstab是一个至关重要的配置文件，它承担着文件系统挂载的责任。当内核将rootfs原封不动地复制到内存中，并将执行权限交给init进程后，大多数的init进程会依据fstab来挂载其他文件系统。正如我们在上面创建的`etc/init.d/rcS`脚本中所使用的那样，通过执行`mount -a`命令来根据fstab挂载文件系统。然而，如今的许多发行版已经开始采用systemd来管理这些API文件系统，如proc、tmp、sys等。因此，在我们正在使用的Linux系统中可能无法在fstab中找到这些条目。

`rcS`是我们在inittab中配置的启动脚本，它定义了系统在启动后所执行的任务。而inittab则是init进程的一些设置，在每个发行版中可能略有不同。对于Busybox的配置，你可以参考[busybox官方示例](https://git.busybox.net/busybox/tree/examples/inittab)。此外，我们需要确保这两个文件具有可执行权限，使用`chmod 755`命令来赋予它们权限。

## 启动操作系统

接下来，我们只需将我们的根文件目录打包起来，并使用qemu来启动它即可。在这里，我们选择了ext3分区格式，但读者也可以选择其他支持的格式，比如fat32。

``` bash
dd if=/dev/zero of=./rootfs.ext3 bs=1M count=32
mkfs.ext3 rootfs.ext3
mkdir fs
mount -o loop rootfs.ext3 ./fs
cp -rf ./busybox-1.36.1/_install/* ./fs
umount ./fs
gzip --best -c rootfs.ext3 > rootfs.img.gz
```

在格式化一个块文件将其变成ext3格式,挂载并将`_install`目录的内容复制进去,取消挂载,并将其压缩之后.我们可以用qemu启动我们的Linux了. 注意启动参数, 我们将`root=/dev/ram init=/linuxrc`作为参数传递给内核, 其意味着我们将使用内存来作为我们的根文件系统, 即所有"文件操作"都是在内存中而不是真正的在修改我们的硬盘. 此外init进程的程序为`/linuxrc`,我们可以在`_install`目录找到它.

首先，我们需要对一个块文件进行格式化，使其成为ext3格式。然后，我们将挂载这个格式化后的块文件，并将`_install`目录中的内容复制到其中。接着，我们取消对挂载文件系统的挂载。接下来，我们将对块文件进行压缩，以便后续使用qemu启动。在启动时，我们需要特别注意启动参数。通过传递`root=/dev/ram init=/linuxrc`给内核，我们告诉系统将内存作为根文件系统，使得所有的文件操作都将在内存中进行，而不会对硬盘进行实质性的修改。同时，我们指定了init进程的程序为`/linuxrc`，这个程序可以在`_install`目录中找到。

``` bash
qemu-system-x86_64 \
  -kernel ./linux-4.19.311/arch/x86_64/boot/bzImage  \
  -initrd ./rootfs.img.gz   \
  -append "root=/dev/ram init=/linuxrc"  \
  -serial file:output.txt
```

![](/images/linux-kernel-net-01-01.png)

当系统成功启动后，我们将在qemu中验证我之前的一些说法。首先，我们执行`df -a`命令，通过观察文件系统的挂载情况来验证。结果显示，文件系统确实如fstab中所示被正确地挂载了。此外，我们还注意到`/dev/root`被挂载在了根目录`/`上，这也与我们的预期相符。

![](/images/linux-kernel-net-01-02.png)

现在让我们使用`ls -al /dev | less`来看看`/dev/root`和`/dev/ram`的关系。如下图，可以看见`/dev/root`是指向`/dev/ram9`的一个软链接。

![](/images/linux-kernel-net-01-03.png)


最后,让我们确认下我们的init进程，使用`ps -a | less`命令，可以看见1号进程确实是linuxrc这个程序。

![](/images/linux-kernel-net-01-04.png)

到此，我们已成功启动了我们自己的Linux系统。在接下来的文章中，我将尝试修改系统中的代码，以定制一个属于我们自己的特别版Linux。通过这个过程，我们将深入学习Linux系统的网络协议栈。

## 参考文档

fstab配置格式: https://wiki.archlinux.org/title/Fstab

API文件系统: https://www.freedesktop.org/wiki/Software/systemd/APIFileSystems/

inittab配置格式: https://git.busybox.net/busybox/tree/examples/inittab
