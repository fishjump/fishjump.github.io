---
title: 从内核出发手撕Linux网络协议栈(四)
---

## Bind系统调用的定义

在上一集，我们讨论了`socket`系统调用的实现，并且介绍了一些关于阅读Linux内核代码的思路。这一集，我们将会拆解网络协议栈中的`bind`系统调用。我们首先可以通过`man bind`命令来查看一下它的函数原型。

```c
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>

int bind(int sockfd, const struct sockaddr *addr,
        	socklen_t addrlen);
```

首先它需要一个`sockfd`，即我们在`socket`系统调用中得到的结果。而第二和第三个参数则是传入了我们要绑定的地址。如果仔细阅读`man bind`中的信息，你可以找到`struct sockaddr`具体长什么样。下面展示了一个UNIX socket的地址格式，具体类型是`struct sockaddr_un`。当然我们现在常用的的socket格式还是网络协议相关的，例如TCP和UDP。那么我现在提出一个问题，操作系统是如何完成这么多不同种类的地址格式的兼容的呢？

```c
struct sockaddr_un my_addr;

#define MY_SOCK_PATH "/somepath"
my_addr.sun_family = AF_UNIX;
strncpy(my_addr.sun_path, MY_SOCK_PATH,
		sizeof(my_addr.sun_path) - 1);
bind(sfd, (struct sockaddr *) &my_addr,
            sizeof(struct sockaddr_un))
```

我们可以使用正则表达式`struct sockaddr.* \{`找到所有的地址结构体定义，记得使用工具的时候仅搜索头文件，这样可以大幅缩小查找范围。下面以`struct sockaddr`，`struct sockaddr_un`和`struct sockaddr_in`为例。

```c
// 通用address定义
struct sockaddr {
	sa_family_t	sa_family;	/* address family, AF_xxx	*/
	char		sa_data[14];	/* 14 bytes of protocol address	*/
};

// UNIX address定义
#define UNIX_PATH_MAX	108
struct sockaddr_un {
	__kernel_sa_family_t sun_family; /* AF_UNIX */
	char sun_path[UNIX_PATH_MAX];	/* pathname */
};

// IPv4协议族地址定义
struct in_addr {
	__be32	s_addr;
};

struct sockaddr_in {
  __kernel_sa_family_t	sin_family;	/* Address family		*/
  __be16		sin_port;	/* Port number			*/
  struct in_addr	sin_addr;	/* Internet address		*/

  /* Pad to size of `struct sockaddr'. */
  unsigned char		__pad[__SOCK_SIZE__ - sizeof(short int) -
			sizeof(unsigned short int) - sizeof(struct in_addr)];
};
```

可以看见他们的共同点就是第一个元素都存储了自身的协议族。这样，无论这个结构体如何被强转类型，程序都可以获取到协议族信息，并以此来判断传入参数是否正确。此外，可以看见尽管`struct sockaddr`已经是一个长度明确的结构体，但是`bind`函数仍然要求传入`socklen_t addrlen`，可见这组API在设计之时也考虑到了后续的扩展，它允许协议开发者超过通用addr定义的14字节地址长度，就如UNIX address最长可以有108字节。

回到IPv4协议族，它包括了两个要素，IP地址和端口号。其中IP地址是一个`uint32`的整数，而端口号则是一个`uint16`的整数。剩余部分的pad，正如注释所述，用于补齐剩余字节，使得`struct sockaddr_in`和`struct sockaddr`大小一致。

## __sys_bind：bind系统调用的入口

使用上一集讲到的方法，我们可以搜索正则表达式`'SYSCALL_DEINE.\(bind'`来找到bind的实现，如下所示。

```c
int __sys_bind(int fd, struct sockaddr __user *umyaddr, int addrlen)
{
	struct socket *sock;
	struct sockaddr_storage address;
	int err, fput_needed;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (sock) {
		err = move_addr_to_kernel(umyaddr, addrlen, &address);
		if (err >= 0) {
			err = security_socket_bind(sock,
						   (struct sockaddr *)&address,
						   addrlen);
			if (!err)
				err = sock->ops->bind(sock,
						      (struct sockaddr *)
						      &address, addrlen);
		}
		fput_light(sock->file, fput_needed);
	}
	return err;
}
```

整个函数的逻辑还是很好理解的，首先通过`sockfd_lookup_light`函数，使用`fd`来查找到绑定的`sock`。其原理已经在上一集讲过了，简单来说，整个网络协议栈的上层IO都工作在一个VFS（虚拟文件系统）上，当我们试图在socket的VFS上创建一个inode的同时，我们就会创建出一个一一对应的socket。然后，我们再创建一个`struct file`，与这个inode绑定，并且为其分配一个fd（文件描述符）。

```c
static struct socket *sockfd_lookup_light(int fd, int *err, int *fput_needed)
{
	struct fd f = fdget(fd);
	struct socket *sock;

	*err = -EBADF;
	if (f.file) {
		sock = sock_from_file(f.file, err);
		if (likely(sock)) {
			*fput_needed = f.flags;
			return sock;
		}
		fdput(f);
	}
	return NULL;
}

struct socket *sock_from_file(struct file *file, int *err)
{
	if (file->f_op == &socket_file_ops)
		return file->private_data;	/* set in sock_map_fd */

	*err = -ENOTSOCK;
	return NULL;
}
```

尝试进入函数`sockfd_lookup_light`来验证我们的猜想。可以看见正如我们猜测的那样，首先可以通过`fdget`来获取到fd所对应的结构体，并且使用`sock_from_file`来从file中获取到我们的`struct socket`。倘若我们更进一步进入`sock_from_file`中，我们会发现其本质就是读取`f.file`中的`private_data`，即`struct socket`的指针，这就是上一集中我们看见`sock_alloc_file`函数放进去的内容。



## inet_bind：IPv4协议族的bind实现

整个IPv4协议族的`bind`实现也是极为简单的，除去一些错误处理逻辑外，可以看见逻辑大致可以分为两个分支。

1. 如果具体的协议有自己的`bind`实现，那么使用协议的`bind`实现；
2. 否则，使用默认的IPv4协议族`bind`实现。

那么假设我们使用了TCP协议，那么会走到哪一条分支呢？在上一集中我们已经知道TCP协议的所有实现可以在`tcp_prot`这个全局变量中找到，它定义在`net/ipv4/tcp_ipv4.c`中，由于它太长了直接在文章中贴出来影响观感，这里就不再贴出了。观察这个变量，发现它并没有对`bind`字段进行赋值，也就是说我们将使用默认的inet_bind实现，`__inet_bind`。

```c
int inet_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sock *sk = sock->sk;
	int err;

	/* If the socket has its own bind function then use it. (RAW) */
	if (sk->sk_prot->bind) {
		return sk->sk_prot->bind(sk, uaddr, addr_len);
	}
	if (addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;

	/* BPF prog is run before any checks are done so that if the prog
	 * changes context in a wrong way it will be caught.
	 */
	err = BPF_CGROUP_RUN_PROG_INET4_BIND(sk, uaddr);
	if (err)
		return err;

	return __inet_bind(sk, uaddr, addr_len, false, true);
}
```

## __inet_bind：TCP连接真正实现bind的地方

这部分的代码大约有100行，并且没有明显的业务逻辑相关的函数调用，也就是说这个函数本身已经是相当底层了。那么，如果想要真的明白这个函数的含义，我们需要有一点思路并且仔细观察。

我的思路如下：
1. 因为`bind`函数本质上是告诉系统一个socket对应的地址，那么我们可以观察`uaddr`的去向。
2. 尽管这个函数中有许多赋值和if判断干扰我们的思路，但是如果我们足够敏感的话，可以发现一组加锁和解锁的操作。在操作系统中，这意味着我们真正开始读写有意义的数据了。

```c
int __inet_bind(struct sock *sk, struct sockaddr *uaddr, int addr_len,
		bool force_bind_address_no_port, bool with_lock)
{
	struct sockaddr_in *addr = (struct sockaddr_in *)uaddr;

	snum = ntohs(addr->sin_port);

	// 一些赋值和判断操作。。。。

	if (with_lock)
		lock_sock(sk);

	inet->inet_rcv_saddr = inet->inet_saddr = addr->sin_addr.s_addr;

	if (snum || /* 一些其他的条件判断 */) {
		if (sk->sk_prot->get_port(sk, snum)) {
			// 错误处理
		}
	}

	inet->inet_sport = htons(inet->inet_num);

	// 一些重要的赋值和判断操作。。。。


out_release_sock:
	if (with_lock)
		release_sock(sk);
out:
	return err;
}
```

根据上面的思路，我们可以得到这样的一个思路框架，追踪`addr`的读写情况，我们大概率可以找到想要的内容。仔细阅读代码，可以发现使用`addr->sin_addr`的地方相当多，但是使用`addr->sin_port`的地方却只有两个，因此我决定从这里入手。通过谷歌可以知道`ntohs`函数的作用是将网络表达（network）的数据转换为本机表达（host），后缀s表示输出为`unsigned short`（uint16）类型。之所以需要这个函数是因为，本机的数据大小端是平台有关的，例如x86平台为大端，如`0x1234`在内存中表达，由低地址向高地址为`0x12 0x34`。而网络字节序规定传输内容为小端排列，即0x1234应当，由低向高地址表示为`0x34 0x12`。因此我们需要这样的一个函数来完成数据转换。额外的，arm平台规定用户可以在CPU上配置大小端，例如选择为小端系统，那么这个函数就是应当是一个空函数。类似的函数还有`htons`，`htonl`，`ntohl`，其中l后缀代表`unsigned long`，即uint32。

在获得了`snum`之后，我们可以很敏感的发现`sk->sk_prot->get_port(sk, snum)`其实又调用了一个TCP协议的内容，其功能应该是获取端口相关的逻辑。随后，可以发现似乎没有别地方使用端口号了。但是仔细思考，可以做出这样一个猜测，s代表source，而d代表destination。假设如此，那么`inet->inet_sport = htons(inet->inet_num)`很可能就是对端口号的赋值。

这样一来，我们引申出来两个问题：

1. `snum`是如何与`inet->inet_num`建立起关联的
2. 为什么给`inet`赋值就可以完成bind的配置（它似乎只是一个局部变量，我们如何完成数据的持久化？）

这两个问题在这个函数中似乎没有很好的回答，那么我们可以先去查看get_port函数。

## inet_csk_get_port的实现

通过查阅`tcp_prot`结构体，可以发现`get_port`在TCP协议中的实现为`inet_csk_get_port`。暂且不讨论其中端口重用的逻辑的话，大体结构如下。整个函数不算短，但是逻辑很清晰。首先可以通过名字知道`struct inet_hashinfo *hinfo`是一个哈希表，其元数据定义在`sk->sk_prot->h.hashinfo`，即，在这里对应了`tcp_prot`的`h.hashinfo`字段。通过跳转，可以发现其就是一个定义在`net/ipv4/tcp_ipv4.c`的全局变量`struct inet_hashinfo tcp_hashinfo`。这也就一定程度上解释了操作系统是如何持久化bind的记录。

接下来的逻辑上，假设我们的`port`为0，那么我们会通过sk来尝试查找返回已经绑定的端口，如果没有则返回错误。这一段显然不是我们正在绑定端口时调用`get_port`需要的逻辑，而是绑定后查找端口所需的逻辑。

下一段逻辑，通过对`port`求哈希，加自旋锁（spinlock），然后查找对应和哈希链表上有没有我们想要的端口，如果没有，则创建之，并且返回，这是就是我们正常的主流程。如果有，那么我们则需要进行端口复用，这取决于协议的实现。如果读者愿意回头看看给`sk->sk_reuse`赋值的地方，可以发现在`inet_create`中有一行`	if (INET_PROTOSW_REUSE & answer_flags) sk->sk_reuse = SK_CAN_REUSE;`，而`answer_flags`来自于`inetsw_arrary`。其中TCP协议对应的flags为`INET_PROTOSW_PERMANENT | INET_PROTOSW_ICSK`，即TCP协议并不原生支持端口复用。这部分逻辑可以忽略。

此处进行一点补充，为了防止有人不知道哈希链表。其本质就是一个哈希表，表中每个元素为一个链表。这样做是因为哈希表有可能会撞哈希，即不同数据有极低概率拥有相同的哈希值，在这种情况下，我们将其用链表串起来。这样的数据结构拥有近似哈希表的速度，因为理想情况下哈希碰撞不会发生或极少发生。但是极端情况下，它会退化成一个链表，即进去的所有元素都发生了哈希碰撞。

接下来，有一个语句很可疑，`if (!inet_csk(sk)->icsk_bind_hash) inet_bind_hash(sk, tb, port);`。它与port，port生成的哈希表元素tb，以及sk都有关系，并且函数中提到了inet。那么它很可能和我们之前的疑问有关系。

```c
int inet_csk_get_port(struct sock *sk, unsigned short snum)
{
	bool reuse = sk->sk_reuse && sk->sk_state != TCP_LISTEN;
	struct inet_hashinfo *hinfo = sk->sk_prot->h.hashinfo;
	int ret = 1, port = snum;
	struct inet_bind_hashbucket *head;
	struct net *net = sock_net(sk);
	struct inet_bind_bucket *tb = NULL;
	kuid_t uid = sock_i_uid(sk);

	if (!port) {
		head = inet_csk_find_open_port(sk, &tb, &port);
		if (!head)
			return ret;
		if (!tb)
			goto tb_not_found;
		goto success;
	}
	head = &hinfo->bhash[inet_bhashfn(net, port,
					  hinfo->bhash_size)];
	spin_lock_bh(&head->lock);
	inet_bind_bucket_for_each(tb, &head->chain)
		if (net_eq(ib_net(tb), net) && tb->port == port)
			goto tb_found;
tb_not_found:
	tb = inet_bind_bucket_create(hinfo->bind_bucket_cachep,
				     net, head, port);
	if (!tb)
		goto fail_unlock;
tb_found:
	// 检查是否可以端口复用
	if (!hlist_empty(&tb->owners)) {
		if (sk->sk_reuse == SK_FORCE_REUSE)
			goto success;

		if ((tb->fastreuse > 0 && reuse) ||
		    sk_reuseport_match(tb, sk))
			goto success;
		if (inet_csk_bind_conflict(sk, tb, true, true))
			goto fail_unlock;
	}
success:
	// 省略端口复用相关的逻辑...
	if (!inet_csk(sk)->icsk_bind_hash)
		inet_bind_hash(sk, tb, port);
	WARN_ON(inet_csk(sk)->icsk_bind_hash != tb);
	ret = 0;

fail_unlock:
	spin_unlock_bh(&head->lock);
	return ret;
}
```

进入这个函数，我们可以看见`snum`，即端口号确实赋值给了`inet->inet_num`。并且记录了它所对应的哈希表位置。此时，我们应当有意识地意识到`inet_sk`和`inet_csk`这两个函数并不简单。进入这两个函数可以发现他们是一个简单的强转，即类似于`return (struct inet_sock *)sk`这样的形式。

``` c
void inet_bind_hash(struct sock *sk, struct inet_bind_bucket *tb,
		    const unsigned short snum)
{
	inet_sk(sk)->inet_num = snum;
	sk_add_bind_node(sk, &tb->owners);
	inet_csk(sk)->icsk_bind_hash = tb;
}
```

进一步地，我们查看`struct sock`，`struct inet_sock`和`struct inet_connection_sock`和定义，可以发现这样的包含关系。并且额外的，作为剧透，我可以告诉读者还有一个`tcp_sock`套在`inet_connection_sock`外层。也就是说，我们一直使用的`struct sock`其实是一个“基类”，而它真正的类型其实是`struct tcp_sock`（因为我们在``socket`系统调用，`sock_create`函数中调用`pf->create`，调用到了`inet_create`，其中使用了`sk_alloc`创建`struct sock`，并且这个函数知道我们使用的协议。整个逻辑链很清晰，感兴趣的读者可以自行阅读，最终可以看见底层是函数根据`tcp_prot`中的`obj_size`来进行`kmalloc`，而`obj_size = sizeof(struct tcp_sock)`。使用这样的技巧，C语言可以实现一些面向对象中继承的特性。


```c
struct inet_sock {
	struct sock		sk;
};

struct inet_connection_sock {
	struct inet_sock	  icsk_inet;
};

struct tcp_sock {
	struct inet_connection_sock	  inet_conn;
};

```

## 小结：让我们回到__inet_bind

至此，我们应该已经可以回答之前提出的两个问题。`bind`函数本质上只是将地址和端口存入全局变量中。地址会被放入内存堆上的`struct sock *sk`中，而端口除了会被放在sk中，还会放在一个全局的哈希表中，用于快速查找是否有重复的端口占用。这些数据通过`struct sock *sk`串联起来。而其也不是一个简单的`struct sock`，本质上是一个`struct tcp_sock`对象，我们针对不同函数，有限度地将其强转为不同层次所需要的结构。总的来说，`bind`的实现是相当简单的，仅仅涉及到一些全局变量的读写操作。
