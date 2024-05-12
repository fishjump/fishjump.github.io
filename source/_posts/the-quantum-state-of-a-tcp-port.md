---
title: 处于量子叠加态的TCP端口
---

注：本文翻译自Cloudflare博客The quantum state of a TCP port，同时融合了一些我个人的理解。

有时候我们可以有这样的感觉，一个看似简单的问题却可以引申出很复杂的答案，今天就让我们来看一个Linux网络协议栈中的例子。

## 什么时候两个TCP Socket可以共享一个地址？

如果我在浏览器上输入blog.cloudflare.com，浏览器会尝试使用TCP连接到一个远程的IP地址，就比方它是104.16.132.229:443吧。同时，我们本地的Linux操作系统也会随机分配一个端口给我们的本地IP地址，比如说是192.0.2.42:54321吧。如果这时候我想要访问另外一个网站会发生什么？我们可以利用这同一个端口号和本地IP建立一个新的TCP连接吗？

这里博主（原作者）准备了八个小问题，让我们通过启发式学习的方法来学习Linux TCP Socket的地址和端口复用规则。最后的我们的到的结论可能有些反常识。

我们的问题主要分为以下两种场景：

![](images/the-quantum-state-of-a-tcp-port-01.png)

第一种情况，两个绑定到不同本地IP（例如我们有双网卡，或者有虚拟网卡）但是相同端口的socket去访问同一个远程地址，并且远程地址的端口号也相同。第二种情况，我们使用一个本地的IP去访问两个不同IP不同端口的远程地址。

在我们的小问题中，我们会：

1. 让OS自动分配socket的IP地址和（或）端口号，又或者
2. 我们会显式地在connect之前，使用bind指定本地地址和端口。这样的作法有个术语叫做bind-before-connect

因为我们在测试bind()的一些边界情况，所以我们需要限定系统可以用的本地地址资源，也就是（IP，port）这样的二元组。我们当然可以先起很多个socket去把资源耗尽，但是有一种更简便的方法，可以参考参考资料中的【Linux网络相关系统配置】。这样做的话，我们可以保证系统只有一个可用的临时本地端口，端口号是60000。

```bash
sysctl -w net.ipv4.ip_local_port_range='60000 60000'
```

现在开始尝试看Python代码回答下面的小问题，预测代码的结果，它的输出是什么，结果是成功还是失败，如果是失败为什么？不要去尝试问ChatGPT，不然问题就没有意义了。问题的答案可以在文章最后查看。

当然，一份代码总是有一些初始化步骤，这里我直接放出来这个初始化步骤，在接下来的小问题中我们会省略这些初始化步骤，让我们关心问题的核心。

```python
from os import system
from socket import *

# Missing constants
IP_BIND_ADDRESS_NO_PORT = 24

# Our network namespace has just *one* ephemeral port
system("sysctl -w net.ipv4.ip_local_port_range='60000 60000'")

# Open a listening socket at *:1234. We will connect to it.
ln = socket(AF_INET, SOCK_STREAM)
ln.bind(("", 1234))
ln.listen(SOMAXCONN)
```

## 场景一：如果IP不同，但是端口相同的情况

在场景一中，我们连接到相同的远端地址，127.9.9.9:1234。Sockets会使用不同的本地IP，我们是否能够共享端口，或者端口是否足够？

| local IP | local port | remote IP | remote port |
| -------- | ---------- | --------- | ------------|
| unique   | same       | same      | same        |
| 127.0.0.1 <br/> 127.1.1.1 <br/> 127.2.2.2 | 60000 | 127.9.9.9 | 1234 |

### 问题一

在本地，我们将两个socket明确绑定到两个IP，而端口由系统指定。请记住此时我们本地可用的临时端口只有60000号。

```python
s1 = socket(AF_INET, SOCK_STREAM)
s1.bind(('127.1.1.1', 0))
s1.connect(('127.9.9.9', 1234))
s1.getsockname(), s1.getpeername()

s2 = socket(AF_INET, SOCK_STREAM)
s2.bind(('127.2.2.2', 0))
s2.connect(('127.9.9.9', 1234))
s2.getsockname(), s2.getpeername()
```

### 问题二

这次设置几乎与之前相同。但是我们让操作系统来决定第一个socket的IP地址和端口号。你认为这次的结果会与上一个问题有所不同吗？

```python
s1 = socket(AF_INET, SOCK_STREAM)
s1.connect(('127.9.9.9', 1234))
s1.getsockname(), s1.getpeername()

s2 = socket(AF_INET, SOCK_STREAM)
s2.bind(('127.2.2.2', 0))
s2.connect(('127.9.9.9', 1234))
s2.getsockname(), s2.getpeername()
```

### 问题三

这个问题与上面的问题很相似，我们只是改变了顺序。首先，我们明确指定第一个socket的IP地址和端口。然后我们让操作系统来决定第二个socket的IP地址和端口号。显然，这样的顺序变化不应该有任何区别，对吗？

```python
s1 = socket(AF_INET, SOCK_STREAM)
s1.bind(('127.1.1.1', 0))
s1.connect(('127.9.9.9', 1234))
s1.getsockname(), s1.getpeername()

s2 = socket(AF_INET, SOCK_STREAM)
s2.connect(('127.9.9.9', 1234))
s2.getsockname(), s2.getpeername()
```

## 场景二：当本地IP和端口相同，但是远端IP不同的时候

在场景二中，我们调转一下情况。不再是多个本地IP和一个远程地址，而是一个本地地址127.0.0.1:60000和两个不同的远程地址。问题不变，两个socket能共享本地端口吗？提醒：临时端口范围仍然只有一个，60000号端口。

| local IP | local port | remote IP | remote port |
| -------- | ---------- | --------- | ------------|
| unique   | same       | same      | same        |
| 127.0.0.1 | 60000 | 127.8.8.8 <br/> 127.9.9.9 | 1234 |

### 问题四

让我们从一个基础的热身问题开始吧。我们使用connect()去连接两个不同的远端地址。

```python
s1 = socket(AF_INET, SOCK_STREAM)
s1.connect(('127.8.8.8', 1234))
s1.getsockname(), s1.getpeername()

s2 = socket(AF_INET, SOCK_STREAM)
s2.connect(('127.9.9.9', 1234))
s2.getsockname(), s2.getpeername()
```

### 问题五

如果我们使用bind()去显式绑定本地IP地址，但是让操作系统去选择端口。这样的话结果有什么变化吗？

```python
s1 = socket(AF_INET, SOCK_STREAM)
s1.bind(('127.0.0.1', 0))
s1.connect(('127.8.8.8', 1234))
s1.getsockname(), s1.getpeername()

s2 = socket(AF_INET, SOCK_STREAM)
s2.bind(('127.0.0.1', 0))
s2.connect(('127.9.9.9', 1234))
s2.getsockname(), s2.getpeername()
```

### 问题六

这次我们显式的指定本地IP地址和端口，在现实开发过程中，有时候我们确实需要这样去指定本地端口。

```python
s1 = socket(AF_INET, SOCK_STREAM)
s1.bind(('127.0.0.1', 60_000))
s1.connect(('127.8.8.8', 1234))
s1.getsockname(), s1.getpeername()

s2 = socket(AF_INET, SOCK_STREAM)
s2.bind(('127.0.0.1', 60_000))
s2.connect(('127.9.9.9', 1234))
s2.getsockname(), s2.getpeername()
```

### 问题七

让我们来让问题变得更复杂一点，我们加入了SO_REUSEADDR flag。

首先，我们告诉操作系统帮我们选择一个本地IP地址和端口，然后我们显式bind到相同的IP地址和端口（我们知道OS一定会分配给我们60000端口）。第二个socket同样使用了本地地址重用，这种情况是被允许的吗？

```python
s1 = socket(AF_INET, SOCK_STREAM)
s1.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
s1.connect(('127.8.8.8', 1234))
s1.getsockname(), s1.getpeername()

s2 = socket(AF_INET, SOCK_STREAM)
s2.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
s2.bind(('127.0.0.1', 60_000))
s2.connect(('127.9.9.9', 1234))
s2.getsockname(), s2.getpeername()
```

### 问题八

最后一个问题，让我们来调转一下问题七中的顺序。按照常理来说结果应该是一样的，这对吗？

```python
s1 = socket(AF_INET, SOCK_STREAM)
s1.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
s1.bind(('127.0.0.1', 60_000))
s1.connect(('127.9.9.9', 1234))
s1.getsockname(), s1.getpeername()

s2 = socket(AF_INET, SOCK_STREAM)
s2.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
s2.connect(('127.8.8.8', 1234))
s2.getsockname(), s2.getpeername()
```

## 问题答案

### 场景一 - 问题一

```python
>>> s1 = socket(AF_INET, SOCK_STREAM)
>>> s1.bind(('127.1.1.1', 0))
>>> s1.connect(('127.9.9.9', 1234))
>>> s1.getsockname(), s1.getpeername()
(('127.1.1.1', 60000), ('127.9.9.9', 1234))
>>>
>>> s2 = socket(AF_INET, SOCK_STREAM)
>>> s2.bind(('127.2.2.2', 0))
>>> s2.connect(('127.9.9.9', 1234))
>>> s2.getsockname(), s2.getpeername()
(('127.2.2.2', 60000), ('127.9.9.9', 1234))
```

代码成功运行，共享本地端口。

### 场景一 - 问题二

```python
>>> s1 = socket(AF_INET, SOCK_STREAM)
>>> s1.connect(('127.9.9.9', 1234))
>>> s1.getsockname(), s1.getpeername()
(('127.0.0.1', 60000), ('127.9.9.9', 1234))
>>>
>>> s2 = socket(AF_INET, SOCK_STREAM)
>>> s2.bind(('127.2.2.2', 0))
>>> s2.connect(('127.9.9.9', 1234))
>>> s2.getsockname(), s2.getpeername()
(('127.2.2.2', 60000), ('127.9.9.9', 1234))
```

代码成功运行，共享本地端口。

### 场景一 - 问题三

```python
>>> s1 = socket(AF_INET, SOCK_STREAM)
>>> s1.bind(('127.1.1.1', 0))
>>> s1.connect(('127.9.9.9', 1234))
>>> s1.getsockname(), s1.getpeername()
(('127.1.1.1', 60000), ('127.9.9.9', 1234))

>>> s2 = socket(AF_INET, SOCK_STREAM)
>>> s2.connect(('127.9.9.9', 1234))
Traceback (most recent call last):
  ...
OSError: [Errno 99] Cannot assign requested address
```

代码运行失败，无法共享端口。

#### 解决方案

使用`IP_BIND_ADDRESS_NO_PORT`选项。

```python
>>> s1 = socket(AF_INET, SOCK_STREAM)
>>> s1.setsockopt(SOL_IP, IP_BIND_ADDRESS_NO_PORT, 1)
>>> s1.bind(('127.1.1.1', 0))
>>> s1.connect(('127.9.9.9', 1234))
>>> s1.getsockname(), s1.getpeername()
(('127.1.1.1', 60000), ('127.9.9.9', 1234))
>>>
>>> s2 = socket(AF_INET, SOCK_STREAM)
>>> s2.connect(('127.9.9.9', 1234))
>>> s2.getsockname(), s2.getpeername()
(('127.0.0.1', 60000), ('127.9.9.9', 1234))
```

### 场景二 - 问题四

```python
>>> s1 = socket(AF_INET, SOCK_STREAM)
>>> s1.connect(('127.8.8.8', 1234))
>>> s1.getsockname(), s1.getpeername()
(('127.0.0.1', 60000), ('127.8.8.8', 1234))
>>>
>>> s2 = socket(AF_INET, SOCK_STREAM)
>>> s2.connect(('127.9.9.9', 1234))
>>> s2.getsockname(), s2.getpeername()
(('127.0.0.1', 60000), ('127.9.9.9', 1234))
```

代码成功运行，共享本地端口。

### 场景二 - 问题五

```python
>>> s1 = socket(AF_INET, SOCK_STREAM)
>>> s1.bind(('127.0.0.1', 0))
>>> s1.connect(('127.8.8.8', 1234))
>>> s1.getsockname(), s1.getpeername()
(('127.0.0.1', 60000), ('127.8.8.8', 1234))
>>>
>>> s2 = socket(AF_INET, SOCK_STREAM)
>>> s2.bind(('127.0.0.1', 0))
Traceback (most recent call last):
  ...
OSError: [Errno 98] Address already in use
```

代码运行失败，无法共享端口。

#### 解决方案

使用`IP_BIND_ADDRESS_NO_PORT`选项。

```python
>>> s1 = socket(AF_INET, SOCK_STREAM)
>>> s1.setsockopt(SOL_IP, IP_BIND_ADDRESS_NO_PORT, 1)
>>> s1.bind(('127.0.0.1', 0))
>>> s1.connect(('127.8.8.8', 1234))
>>> s1.getsockname(), s1.getpeername()
(('127.0.0.1', 60000), ('127.8.8.8', 1234))
>>>
>>> s2 = socket(AF_INET, SOCK_STREAM)
>>> s2.setsockopt(SOL_IP, IP_BIND_ADDRESS_NO_PORT, 1)
>>> s2.bind(('127.0.0.1', 0))
>>> s2.connect(('127.9.9.9', 1234))
>>> s2.getsockname(), s2.getpeername()
(('127.0.0.1', 60000), ('127.9.9.9', 1234))
```

### 场景二 - 问题六

```python
>>> s1 = socket(AF_INET, SOCK_STREAM)
>>> s1.bind(('127.0.0.1', 60_000))
>>> s1.connect(('127.8.8.8', 1234))
>>> s1.getsockname(), s1.getpeername()
(('127.0.0.1', 60000), ('127.8.8.8', 1234))
>>>
>>> s2 = socket(AF_INET, SOCK_STREAM)
>>> s2.bind(('127.0.0.1', 60_000))
Traceback (most recent call last):
  ...
OSError: [Errno 98] Address already in use
```

代码运行失败，无法共享端口。

#### 解决方案

使用`SO_REUSEADDR`选项。

```python
>>> s1 = socket(AF_INET, SOCK_STREAM)
>>> s1.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
>>> s1.bind(('127.0.0.1', 60_000))
>>> s1.connect(('127.8.8.8', 1234))
>>> s1.getsockname(), s1.getpeername()
(('127.0.0.1', 60000), ('127.8.8.8', 1234))
>>>
>>> s2 = socket(AF_INET, SOCK_STREAM)
>>> s2.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
>>> s2.bind(('127.0.0.1', 60_000))
>>> s2.connect(('127.9.9.9', 1234))
>>> s2.getsockname(), s2.getpeername()
(('127.0.0.1', 60000), ('127.9.9.9', 1234))
```

### 场景二 - 问题七

```python
>>> s1 = socket(AF_INET, SOCK_STREAM)
>>> s1.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
>>> s1.connect(('127.8.8.8', 1234))
>>> s1.getsockname(), s1.getpeername()
(('127.0.0.1', 60000), ('127.8.8.8', 1234))
>>>
>>> s2 = socket(AF_INET, SOCK_STREAM)
>>> s2.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
>>> s2.bind(('127.0.0.1', 60_000))
>>> s2.connect(('127.9.9.9', 1234))
>>> s2.getsockname(), s2.getpeername()
(('127.0.0.1', 60000), ('127.9.9.9', 1234))
```

代码成功运行，共享本地端口。

### 场景二 - 问题八

```python
>>> s1 = socket(AF_INET, SOCK_STREAM)
>>> s1.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
>>> s1.bind(('127.0.0.1', 60_000))
>>> s1.connect(('127.9.9.9', 1234))
>>> s1.getsockname(), s1.getpeername()
(('127.0.0.1', 60000), ('127.9.9.9', 1234))
>>>
>>> s2 = socket(AF_INET, SOCK_STREAM)
>>> s2.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
>>> s2.connect(('127.8.8.8', 1234))
Traceback (most recent call last):
  ...
OSError: [Errno 99] Cannot assign requested address
```

代码运行失败，无法共享端口，没有解决方案。

## 本地TCP端口的三重秘密

现在我们真的弄明白了Linux端口分配的机制吗？也许并没有。我们只是在做类似于对一个黑箱做逆向工程。在这个黑箱背后藏着什么呢？我们来看看。

Linux会在一个叫做bhash的哈希表中记录跟踪所有被使用的TCP**端口**。这里不要和ehah哈希表搞混了，ehash表用于记录已经建立连接的(local socket，remote socket)对。

![](images/the-quantum-state-of-a-tcp-port-02.png)

每个哈希表的入口指向一个叫做bind bucket的链表。bind bucket将所有共享端口的socket放在一起。具体来说，做哈希的内容是：

1. socket的network namespace
2. socket的VRF设备（Virtual Routing and Forwarding）
3. socket绑定的本地端口

现在让我们来考虑最简单的情况，只有一个网络命名空间，没有VRF。这样的情况下，我们可以说socket所在的bind bucket只和本地端口有关。也就是说，在每个bind bucket中的socket通过一个链表来共享一个本地端口。

当我们让内核去给一个socket分配一个本地地址时，它会去检查现有的socket，因为只有满足特定条件我们才可以进行本地端口共享。下面这段注释从include/net/inet_hashtables.h中复制。

1. 绑定到不同interface（网络接口，对于PC可以简单当作网卡）可以共享本地端口。否则，检测情况2
2. 如果所有的socket都有sk->sk_reuse标志，而且其中没有socket在TCP_LISTEN状态，那么可以共享本地端口.否则，检测情况3
3. 如果所有socket都绑定到了不同的地址，那么端口可以共享。如果也不满足这个条件，那么端口不能共享。

```c
/* There are a few simple rules, which allow for local port reuse by
 * an application.  In essence:
 *
 *   1) Sockets bound to different interfaces may share a local port.
 *      Failing that, goto test 2.
 *   2) If all sockets have sk->sk_reuse set, and none of them are in
 *      TCP_LISTEN state, the port may be shared.
 *      Failing that, goto test 3.
 *   3) If all sockets are bound to a specific inet_sk(sk)->rcv_saddr local
 *      address, and none of them are the same, the port may be
 *      shared.
 *      Failing this, the port cannot be shared.
 *
 * The interesting point, is test #2.  This is what an FTP server does
 * all day.  To optimize this case we use a specific flag bit defined
 * below.  As we add sockets to a bind bucket list, we perform a
 * check of: (newsk->sk_reuse && (newsk->sk_state != TCP_LISTEN))
 * As long as all sockets added to a bind bucket pass this test,
 * the flag bit will be set.
 * ...
 */
```

上面的注释表明内核试图去尽可能保证端口没有冲突。为此，bind bucket内有一些额外的属性来汇总它所持有的sockets的属性。

```c
struct inet_bind_bucket {
        /* ... */
        signed char          fastreuse;
        signed char          fastreuseport;
        kuid_t               fastuid;
#if IS_ENABLED(CONFIG_IPV6)
        struct in6_addr      fast_v6_rcv_saddr;
#endif
        __be32               fast_rcv_saddr;
        unsigned short       fast_sk_family;
        bool                 fast_ipv6_only;
        /* ... */
};
```

让我们重点关注第一个flag，fastreuse。它从Linux 2.1.90版本开始存在。最开始它是以一个bit flag的形式存在，随着时间的发展，它变成了一个字节大小的字段。而其他的六个字段和SO_REUSEPORT这个flag有关，从Linux 3.9加入内核，在今天不会涉及到。

当内核需要将一个socket绑定到一个端口的时候，它首先会去在bind bucket中寻找这个端口。而让问题更复杂的是，在内核中寻找TCP bind bucket的逻辑被分散在两处。它有可能发生在bind()系统调用中，也可能发生在connect()系统调用中。具体使用哪一块的逻辑取决于socket的初始化方式。

![](images/the-quantum-state-of-a-tcp-port-03.png)

但是不论怎样，当我们在执行inet_csk_get_port()或__inet_hash_connect()的时候，我们总是去遍历bhash中对应位置的bind bucket链表去寻找一个匹配的端口号。端口号或许已经在bucket中存在；又或许不存在，我们需要创建一个新的bucket元素。当它存在时，fastreuse可能有三种状态，-1，0，或者1。也许内核开发者收到了量子力学的启发？

三种状态其实反映了bind bucket的两个方面：

1. 哪些socket在bind bucket中
2. 什么时候可以共享端口

让我们尝试解密三种fastreuse的状态以及在每种情况下的含义。首先，fastreuse字段对bind bucket的拥有者（即哪些使用这个端口的socket）传递了什么信息？

| fastreuse | 使用这个端口的多个（或者只有一个）socket中有          |
| --------- | ---------------------------------------        |
| -1        | 一个或者多个socket是通过connect()获得得一个临时端口号 |
| 0         | 一个或则多个socket调用bind()时没有设置SO_REUSEADDR  |
| +1        | 一个或则多个socket调用bind()时设置了SO_REUSEADDR    |

尽管上面的说明不是全部的真相，但是目前来说它足够“正确”了。我们马上会接触到更详细的内容。

当我们需要端口共享时，事实可能远比我们想象中更不直观，符合直觉。

| 我能否 … 当 … 时 | fastreuse = -1 | fastreuse = 0 | fastreuse = +1 |
| - | - | - | - |
| 调用bind()去绑定（使用临时端口或者显式指定的端口）一个相同的已经有的端口 | 当且仅当IP不同时，可以 ① | ← 同上 | ← 同上 |
| 调用bind()去绑定一个端口，并且设置SO_REUSEADDR | 当且仅当IP不同时，**或者**发生冲突的其他所有socket也设置了SO_REUSEADDR ① | ← 同上 | 可以 ② |
| 调用connect()，使用相同的临时端口，访问相同的远端（IP，port）地址 | 当且仅当本地IP不同时，可以③ | 不可以 ③ | 不可以 ③ |
| 调用connect()，使用相同的临时端口，访问不同的远端（IP，port）地址 | 可以 ③ | 不可以 ③ | 不可以 ③ |

① 当显式绑定时取决于由inet_csk_get_port()调用的inet_csk_bind_conflict()，**或者**使用connect隐式绑定时，取决于由inet_csk_get_port()调用的inet_csk_find_open_port()。

② 对于fastreuse == 1的bind bucket，inet_csk_get_port()跳过端口冲突检查。

③ 这个调用链inet_hash_connect() → __inet_hash_connect()会直接不去fastreuse != -1的bind bucket中找端口。

虽然乍一看这些规则十分复杂，但是我们可以提前出几个简单的规则：

- 如果本地IP地址与任何现有socket没有冲突，bind()总是成功的；
- 如果bind bucket不是fastreuse = -1，那么使用connect来分配地址总是失败的（是fastreuse = -1也不一定成功）
- 如果没有本地和远端地址冲突，那么connect分配地址总是成功的
- 如果所有冲突的socket都设置了SO_REUSEADDR，并且没有socket在listening状态（即没有当作服务器），那么设置了SO_REUSEADDR的socket可以进行本地地址共享。

## 我听你扯这么多，但是我不信怎么办？

我们生在一个好时代，你不必相信我，可以使用drgn，一个内核调试工具（链接在参考资料中），去自己看看bind bucket的状态。

需要注意的是，虽然在wsl中可以安装drgn，但是由于缺少内核符号文件，无法进行调试。推荐使用一个正经的虚拟机或者直接在物理机上调试。你可能需要根据第一次跑drgn失败的提示，根据发行版不同，以不同的方法安装内核符号文件（但是wsl装不了，因为软件源中没有wsl的专属符号文件）。

```python
#!/usr/bin/env drgn

"""
dump_bhash.py - List all TCP bind buckets in the current netns.

Script is not aware of VRF.
"""

import os

from drgn.helpers.linux.list import hlist_for_each, hlist_for_each_entry
from drgn.helpers.linux.net import get_net_ns_by_fd
from drgn.helpers.linux.pid import find_task


def dump_bind_bucket(head, net):
    for tb in hlist_for_each_entry("struct inet_bind_bucket", head, "node"):
        # Skip buckets not from this netns
        if tb.ib_net.net != net:
            continue

        port = tb.port.value_()
        fastreuse = tb.fastreuse.value_()
        owners_len = len(list(hlist_for_each(tb.owners)))

        print(
            "{:8d}  {:{sign}9d}  {:7d}".format(
                port,
                fastreuse,
                owners_len,
                sign="+" if fastreuse != 0 else " ",
            )
        )


def get_netns():
    pid = os.getpid()
    task = find_task(prog, pid)
    with open(f"/proc/{pid}/ns/net") as f:
        return get_net_ns_by_fd(task, f.fileno())


def main():
    print("{:8}  {:9}  {:7}".format("TCP-PORT", "FASTREUSE", "#OWNERS"))

    tcp_hashinfo = prog.object("tcp_hashinfo")
    net = get_netns()

    # Iterate over all bhash slots
    for i in range(0, tcp_hashinfo.bhash_size):
        head = tcp_hashinfo.bhash[i].chain
        # Iterate over bind buckets in the slot
        dump_bind_bucket(head, net)


main()
```

读者可以自行验证我上面说的结论是否正确。请注意为了正确复现结果，下面的代码片段使用了和开头小问题中相同的设置。

两个socket共享临时端口60000：

```python
>>> s1 = socket(AF_INET, SOCK_STREAM)
>>> s1.connect(('127.1.1.1', 1234))
>>> s2 = socket(AF_INET, SOCK_STREAM)
>>> s2.connect(('127.2.2.2', 1234))
>>> !./dump_bhash.py
TCP-PORT  FASTREUSE  #OWNERS
    1234          0        3
   60000         -1        2
```

两个使用了bind()的socket共享60000端口：

```python
>>> s1 = socket(AF_INET, SOCK_STREAM)
>>> s1.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
>>> s1.bind(('127.1.1.1', 60_000))
>>> s2 = socket(AF_INET, SOCK_STREAM)
>>> s2.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
>>> s2.bind(('127.1.1.1', 60_000))
>>> !./dump_bhash.py
TCP-PORT  FASTREUSE  #OWNERS
    1234          0        1
   60000         +1        2
```

一个socket使用SO_REUSEADDR，一个socket不使用：

```python
>>> s1 = socket(AF_INET, SOCK_STREAM)
>>> s1.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
>>> s1.bind(('127.1.1.1', 60_000))
>>> !./dump_bhash.py
TCP-PORT  FASTREUSE  #OWNERS
    1234          0        1
   60000         +1        1
>>> s2 = socket(AF_INET, SOCK_STREAM)
>>> s2.bind(('127.2.2.2', 60_000))
>>> !./dump_bhash.py
TCP-PORT  FASTREUSE  #OWNERS
    1234          0        1
   60000          0        2
```

通过这个drgn，我们就可以写很多测试来证明我的结论是正确的。但是最后一个代码片段中发生了什么导致fastreuse从+1变成了0。这代表我们还没有完全理解fastreuse的机制。让我们来画一个状态机图吧。

## fastreuse的状态机

正如我们刚刚看到的结果，bind bucket不必在整个生命周期中始终为fastreuse == 1的状态。当我们向bind bucket中添加socket的时候就可以改变其状态。例如刚刚，它从1变成了0，当：

1. 没有任何冲突
2. 没有设置SO_REUSEADDR

![](images/the-quantum-state-of-a-tcp-port-04.png)

我们可以通过仔细阅读inet_csk_get_port → inet_csk_update_fastreuse的源码来确定全部细节。现在，我们已经了解了内核端口复用的全部机制，但是引出了另外一个问题。

## 为什么我们需要思考端口复用的细节

首先，当你遇到bind()系统调用返回EADDRINUSE错误时，或者connect()返回EADDRNOTAVAIL错误时，你可以知道发生了什么，或者至少有工具可以找出答案。

其次，因为我们（Cloudflare）之前已经宣传过一种从特定范围的端口打开连接的技术（放在参考资料里面），其中涉及使用SO_REUSEADDR选项对socket进行bind()。 当时我们没有意识到，存在一种特殊情况，即其无法与常规的，使用connect()分配地址的socket共享同一端口。虽然这不会影响这项技术的价值，但是知道更多的细节总是好的。

为了让事情更简单，Cloudflare和Linux社区合作，添加了信了socket选项来扩展内核API。IP_LOCAL_PORT_RANGE让用户可以指定本地端口范围，在Linux 6.3中加入内核。有了这个选项，我们可以不必依赖bind的技巧，让上面的技术可以和常规的，通过connect()获取地址的socket共享本地端口。

## 总结

今天我们提出了一个相对简单的问题，两个TCP socket在什么情况下可以共享一个本地地址？并努力寻找答案。答案很复杂，无法一言以蔽之。 并且这甚至不是完整的答案。 毕竟我们忽略了SO_REUSEPORT，并且没有考虑与在TCP_LISTEN状态的socket的冲突。

不过，如果一定要有一个简单的结论的话，那就是对socket进行bind()操作可能会产生很复杂的后果。当使用bind()选择出口IP地址时，最好同时带上IP_BIND_ADDRESS_NO_PORT，并将使用内核默认分配的端口。否则我们可能会无意中阻止本地TCP端口复用。

遗憾的是，这个经验不适用于UDP，因为IP_BIND_ADDRESS_NO_PORT对UDP没有用。不过这就是另一回事了，今天不展开讲了（也许之后会写写）。

## 参考资料

Linux网络相关系统配置：https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html?#ip-variables
内核调试工具drgn：https://drgn.readthedocs.io/en/latest/index.html
如何防止临时端口耗尽并且爱上TCP长连接： https://blog.cloudflare.com/how-to-stop-running-out-of-ephemeral-ports-and-start-to-love-long-lived-connections/