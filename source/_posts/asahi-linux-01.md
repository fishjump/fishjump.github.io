---
title: Asahi Linux 逆向实践日记（一）
---

我是从m1 macbook air开始关注苹果的macbook系列，因为其兼顾了性能于续航，但是缺点是macOS并不是真正的Linux，尽管大多数时候使用起来并无差别，但是有时候我还是希望可以在macbook上用到真正的Linux。在Asahi Linux发布的早期我就关注到了这个distribution，早期其安装难度和可用度并不高，但是现在看来其已经达到了一个可以勉强日常使用的水平。

我过去的经验一直是自低向上的去bringup一些硬件，从来没有想过如何逆向一个硬件（确实有逆向一些软件的经验）。看到Asahi Linux，我觉得这是一个很好的案例来学习如何逆向一个硬件，因此就有了这篇日记（希望后面还有）。

截至今天为止（15 Sep, 2023），我成功通过marcan的m1n1 bootloader启动了proxy和hypervisor模式。

这些内容几乎都来自于marcan的[Youtube频道](https://www.youtube.com/watch?v=aMTfPSzrjXs&t=3001s&ab_channel=marcan)。由于Asahi Wiki几乎是落后于更新的，所以会加上一些个人的理解/修正。

## Asahi Linux的启动流程

可以访问这两个文档来获得最详细的信息:
 1. [m1n1:User Guide](https://github.com/AsahiLinux/docs/wiki/m1n1%3AUser-Guide)
 2. [Tethered Boot Setup (For Developers)](https://github.com/AsahiLinux/docs/wiki/Tethered-Boot-Setup-%28For-Developers%29)

如果你已经使用了Asahi Linux安装脚本安装了完整的Linux，你需要阅读第二篇wiki来启用m1n1的后门模式，给了你5秒的窗口期在启动Linux之前进入Proxy模式，m1n1的具体使用可以参考第一篇wiki。

m1n1的功能如下：

它是一个最小化的，继承了一个proxy mode和hypervisor mode的bootloader，你可以使用它直接来启动一个linux/macOS，也可以用它来加载另一个bootloader，例如uboot，甚至是另一个版本的m1n1。

![m1n1](images/asahi-linux-01-graph-1.png)

### Proxy mode

我认为Proxy mode是一个很棒的概念，你可以通过串口/USB虚拟串口来连接m1 mac和另一台开发机（任何架构，操作系统），然后通过serial RPC来直接操作你的mac，避免了反复重启，上传kernel。m1n1提供了python的封装和一些python脚本，我们可以直接在python上先硬编码测试好功能，然后再使用别的语言来正式开发。

以下是一个例子：
 1. 使用安装脚本安装好Asahi Linux
 2. 关机后长按开机键进入mac的recovery模式
 3. 选择Option，你可能会被要求输入密码
 4. 在最上面的Appmenu中打开终端，执行`csrutil disable && nvram boot-args=-v`， 然后关机（参考[这里](https://github.com/AsahiLinux/docs/wiki/Tethered-Boot-Setup-%28For-Developers%29#enabling-the-backdoor-proxy-mode)）。
 5. 用一条USB-A2C或者C2C的线连接你的mac和另一台开发机，开机。
 6. 这时候你自己观察，会发现在Asahi Logo出来的适合会有5秒倒计时，你需要在这5秒内执行proxy python脚本，否则m1n1会进入Linux，而不是停留在这里。

```bash
# 如果没有别的外部存储设备，这里应该是/dev/ttyACM0
export M1N1DEVICE=/dev/ttyACM0
./proxyclient/tools/shell.py
```

然后你可以使用python来和你的mac交互了，具体可以使用的函数可以阅读代码`./proxyclient/m1n1/proxy.py`。可以查看[这个视频](https://www.youtube.com/watch?v=aMTfPSzrjXs&t=3001s&ab_channel=marcan)获得一些可以马上观测到结果的例子。当然，在我使用看这个视频的时候，marcan给具体内存的值应该已经不可用，你可以先读出内存，再在你读出的基础上修改。

### Hypervisor

marcan发现Apple并没有特别阻止macOS在虚拟机上执行（尽管也没有特别支持），所以我们就有一个特别好的方法来观测macOS。我们可以开发一个最小化的虚拟机，将macOS跑在这个虚拟机上面，观测我们感兴趣的内容以便更好地逆向macOS。

这部分的内容可以在[这里](https://github.com/AsahiLinux/docs/wiki/SW%3AHypervisor)找到。但是因为Apple的更新策略，设置虚拟机还是比较痛苦的，我没有成功使用`kmutils`生成kernelcache，而是使用了系统内自带的kernelcache来加载macOS（[这一节内容](https://github.com/AsahiLinux/docs/wiki/SW%3AHypervisor#running-the-stock-macos-kernel-from-a-macos-install)）。我不是一个macOS专家，我感觉macOS的kernelcache应该是类似于boot.efi之类的东西。

然后是一些有用的信息，
1. 推荐另外安装一个系统，以防你日常使用的系统挂掉了。
2. Apple会强制更新你的macOS，所以最好是下载好一个完整镜像然后离线安装。
3. 苹果不会发布每一个版本内核对应的KDK（kernel debug kit），因此一定要提前确定好你下载的macOS版本有对应的KDK可以在苹果开发者网站下载到。
4. 以防万一你错误设置了启动对象（`kmutils configure-boot -c <custom-boot-object>`）无法启动macos，你只需要把其重设为stock kernel cache就可以了，例如`kmutils configure-boot -v /Volumes/Macintosh\ HD -c /System/Volumes/Preboot/<UUID>/boot/<long hash>/System/Library/Caches/com.apple.kernelcaches/kernelcache`。
5. 如果你有多个macOS，你可以使用diskutils info来查看每个分区对应的UUID，从而你可以找到你想要启动的kernelcache，大概长这样`/System/Volumes/Preboot/(UUID)/boot/(long hash)/System/Library/Caches/com.apple.kernelcaches/kernelcache`。
