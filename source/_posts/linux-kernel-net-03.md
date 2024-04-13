---
title: 从内核出发手撕Linux网络协议栈(三)
---

## 事前准备

上一回说到一个系统调用是如何实现的，这次就从系统调用的定义开始拆解`socket`系统调用的源码。正所谓工欲善其事，必先利其器，由于C语言本身的特性，导致IDE跳转的功能并不总是好用。这里有两种解决方案，一种是使用`ctags`命令来生成符号文件供IDE使用，IDE大概率也内置了这样的功能。这个功能的缺点是，由于Linux源码中为了兼容多种体系，有很多重复的函数定义在不同的体系目录下。而第二种方法更为现代，即利用`compile_commands.json`这个文件来帮助我们查看真实编译时使用的编译指令。

对于高版本内核，其内部已经集成了对`compile_commands.json`的支持。我们只需要使用`make compile_commands.json`即可生成对应的文件，然后在vscode或者其他你喜欢的编辑器或者ide中配置对应的选项即可。现代的工具大概率已经集成了对这项特性的支持。但是，我们使用的4.19版本内核源码还没有提供这样的支持。此时我们可以使用到`bear`命令来hook make的过程，这个命令可以在Github找到下载地址，并且大概率大多数Linux发行版已经提供对其的支持，直接使用自己的包管理工具下载即可。

```bash
make menuconfig
# 会在工作目录生成compile_commands.json
bear make
```
## socket系统调用

想要研究清楚`socket`系统调用，那么首先肯定还是要知道`socket`函数是如何被使用的。我们将如下例子的参数带入到后面的讲解中。我们通常使用如下的方法来创建一个TCP连接的socket。对于不熟悉C语言网络API的朋友来说，可能好奇为什么这当中为什么没有指定端口号。这是因为我们需要在之后使用`bind`函数来指定端口，当然这是后面的话题了。

```c
sockfd = socket(AF_INET, SOCK_STREAM, 0)
```

上面例子中的三个分别是`family`（或者有些地方称之为`domain`），`type`和`protocol`。其中`family`指的是协议族，常见的有`AF_INET`和`AF_INET6`，即IPv4和IPv6。第二个参数叫做`type`，即`socket`连接的类型，Linux中定义的且常用的有`SOCK_STREAM`和`SOCK_DGRAM`，通常来说对应了TCP和UDP协议。但是它们本质上是指选择一套有连接或者无连接的协议（数据报协议）。第三个参数`protocol`则代表了通信协议。这里是一个特殊情况，当你决定了`type`参数之后将`protocol`设置为`0`，那么即默认选择TCP或者UDP。你当然也可以显式指明`IPPROTO_TCP`或`IPPROTO_UDP`。这里需要注意一点，`type`和`protocol`是不能自由排列组合的，例如指定`type`为`SOCKET_STREAM`且指定`protocol`为`IPPROTO_UDP`是非法的。

## 从系统调用入口开始

按照上一集的介绍，我们知道了`socket`是拥有三个参数的系统调用，那么我们可以搜索`"SYSCALL_DEFINE3(socket"`来找到`socket`定义的位置，它在`net/socket.c`中，内容如下：

```bash
grep "SYSCALL_DEFINE3\(socket"
```

```c
SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)
{
	return __sys_socket(family, type, protocol);
}
```
 
可以看到它原样传递给了一个内部实现，这个内部实现的源码可以通过IDE内的跳转功能轻易找到（如果你正确配置了`compile_commands.json`）。

```c
int __sys_socket(int family, int type, int protocol)
{
	int retval;
	struct socket *sock;
	int flags;

	/* Check the SOCK_* constants for consistency.  */
	BUILD_BUG_ON(SOCK_CLOEXEC != O_CLOEXEC);
	BUILD_BUG_ON((SOCK_MAX | SOCK_TYPE_MASK) != SOCK_TYPE_MASK);
	BUILD_BUG_ON(SOCK_CLOEXEC & SOCK_TYPE_MASK);
	BUILD_BUG_ON(SOCK_NONBLOCK & SOCK_TYPE_MASK);

	flags = type & ~SOCK_TYPE_MASK;
	if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
		return -EINVAL;
	type &= SOCK_TYPE_MASK;

	if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
		flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;

	retval = sock_create(family, type, protocol, &sock);
	if (retval < 0)
		return retval;

	return sock_map_fd(sock, flags & (O_CLOEXEC | O_NONBLOCK));
}
```

除开一些配置，我们可以看见`socket`主要做了两件事。第一，通过`sock_create`函数来创建一个socket；第二，将这个sock使用`sock_map_fd`映射到文件系统中，因为UNIX的设计思路是一切皆文件。

## sock_create函数解析

跳转到`sock_create`函数，它同样经过了一层包装。这层包装主要是在系统层面实现网络代理功能，并且区分用户态和内核态建立起的连接（即通过socket函数只能创建用户态socket连接）

```c
int sock_create(int family, int type, int protocol, struct socket **res)
{
	return __sock_create(current->nsproxy->net_ns, family, type, protocol, res, 0);
}
```

进入真正的内部实现，值得关注的点主要有两个函数调用。其一，`sock_alloc`创建了一个`struct socket`对象；其二，函数内调用了`pf->create`来创建（或者说真正初始化`struct socket`对象）。在讲解上面两点之前可以大致梳理一下其他函数。整个函数的前半段主要是一些防呆错误判断。中间有出现security开头的函数，主要是实现安全方面的内容。读者可以通过全局搜索，找到两处这个函数的定义，一处在`include/linux/security.h`，以内联空函数的形式出现，而另一处在`security/security.c`，具有真正的功能。并且我们可以在头文件中观察到函数实现的选择是通过定义`CONFIG_SECURITY_NETWORK`来实现的。它可以在`make menuconfig`或者`.config`文件中配置。这里我们可以暂时跳过它。另一处则是rcu系列的函数，可以通过它们的名字和询问Google，ChatGPT得知。这些函数主要是实现锁的功能，我们这里也暂时不关心它们。

```c
int __sock_create(struct net *net, int family, int type, int protocol,
			 struct socket **res, int kern)
{
	int err;
	struct socket *sock;
	const struct net_proto_family *pf;

	/*
	 *      Check protocol is in range
	 */
	if (family < 0 || family >= NPROTO)
		return -EAFNOSUPPORT;
	if (type < 0 || type >= SOCK_MAX)
		return -EINVAL;

	/* Compatibility.

	   This uglymoron is moved from INET layer to here to avoid
	   deadlock in module load.
	 */
	if (family == PF_INET && type == SOCK_PACKET) {
		pr_info_once("%s uses obsolete (PF_INET,SOCK_PACKET)\n",
			     current->comm);
		family = PF_PACKET;
	}

	err = security_socket_create(family, type, protocol, kern);
	if (err)
		return err;

	/*
	 *	Allocate the socket and allow the family to set things up. if
	 *	the protocol is 0, the family is instructed to select an appropriate
	 *	default.
	 */
	sock = sock_alloc();
	if (!sock) {
		net_warn_ratelimited("socket: no more sockets\n");
		return -ENFILE;	/* Not exactly a match, but its the
				   closest posix thing */
	}

	sock->type = type;

#ifdef CONFIG_MODULES
	/* Attempt to load a protocol module if the find failed.
	 *
	 * 12/09/1996 Marcin: But! this makes REALLY only sense, if the user
	 * requested real, full-featured networking support upon configuration.
	 * Otherwise module support will break!
	 */
	if (rcu_access_pointer(net_families[family]) == NULL)
		request_module("net-pf-%d", family);
#endif

	rcu_read_lock();
	pf = rcu_dereference(net_families[family]);
	err = -EAFNOSUPPORT;
	if (!pf)
		goto out_release;

	/*
	 * We will call the ->create function, that possibly is in a loadable
	 * module, so we have to bump that loadable module refcnt first.
	 */
	if (!try_module_get(pf->owner))
		goto out_release;

	/* Now protected by module ref count */
	rcu_read_unlock();

	err = pf->create(net, sock, protocol, kern);
	if (err < 0)
		goto out_module_put;

	/*
	 * Now to bump the refcnt of the [loadable] module that owns this
	 * socket at sock_release time we decrement its refcnt.
	 */
	if (!try_module_get(sock->ops->owner))
		goto out_module_busy;

	/*
	 * Now that we're done with the ->create function, the [loadable]
	 * module can have its refcnt decremented
	 */
	module_put(pf->owner);
	err = security_socket_post_create(sock, family, type, protocol, kern);
	if (err)
		goto out_sock_release;
	*res = sock;

	return 0;

out_module_busy:
	err = -EAFNOSUPPORT;
out_module_put:
	sock->ops = NULL;
	module_put(pf->owner);
out_sock_release:
	sock_release(sock);
	return err;

out_release:
	rcu_read_unlock();
	goto out_sock_release;
}
```

### sock_alloc函数解析

显然让我们进入`sock_alloc`函数来看看。这个函数很简单，如下所示。值得关注的点主要在`new_inode_pseudo`和`SOCKET_I`上。其中`new_inode_pseudo`创建了一个inode，然后`SOCKET_I`将这个inode和一个socket指针联系在了一起。

```c
struct socket *sock_alloc(void)
{
	struct inode *inode;
	struct socket *sock;

	inode = new_inode_pseudo(sock_mnt->mnt_sb);
	if (!inode)
		return NULL;

	sock = SOCKET_I(inode);

	inode->i_ino = get_next_ino();
	inode->i_mode = S_IFSOCK | S_IRWXUGO;
	inode->i_uid = current_fsuid();
	inode->i_gid = current_fsgid();
	inode->i_op = &sockfs_inode_ops;

	return sock;
}
```

对于`new_inode_pseudo`，通过观察函数的名字，参数名字以及按F12跳转，我们可以知道：

1. 这是文件系统相关的操作，`sock_mnt`大概率是代表一个文件系统上的挂载点
2. 这个函数大概率是在`sock_mnt`这个挂载点上创建一个pseudo inode，即伪inode。也就是并不真实存在于硬盘上，但是存在于文件系统中的inode。这也表现出了UNIX一切皆文件的特点。

口说无凭，虽然这里我们不关心文件系统的部分，但是我们可以查看`sock_mnt`的定义。很明显它是一个全局变量，因为它没有在这个函数内定义。通过跳转和全局搜索，我么可以查看到`sock_mnt`的使用情况。可以看见它就是一个vfsmount，即virtual filesystem mount，虚拟文件系统挂载点。并且在`sock_init`函数中很明确调用了文件系统和挂载相关的函数，并且赋值给它。到此，我们不打算进一步深究，否则就有点脱离今天的主题，网络协议栈了。

```c
// sock_mnt的定义
static struct vfsmount *sock_mnt __read_mostly;

static int __init sock_init(void) {
  // .... 其他函数调用
	err = register_filesystem(&sock_fs_type);
	if (err)
		goto out_fs;
	sock_mnt = kern_mount(&sock_fs_type);
	if (IS_ERR(sock_mnt)) {
		err = PTR_ERR(sock_mnt);
		goto out_mount;
	}
  // .... 其他函数调用
}
```

下一个我们感兴趣的东西是`SOCKET_I`，它的定义同样可以通过跳转来找到。

```c
struct socket_alloc {
	struct socket socket;
	struct inode vfs_inode;
};

static inline struct socket *SOCKET_I(struct inode *inode)
{
	return &container_of(inode, struct socket_alloc, vfs_inode)->socket;
}
```

这里用到了`container_of`，它是一个Linux内核代码中常用的宏定义，具体的实现代码有点复杂，但是原理还是比较简单的。首先，Linux使用了C语言编写，而C语言并不支持C++中的模板特性。因此，当我们使用一个数据结构时（例如链表，二叉树等结构），我们没有办法如STL那样将我们的对象“装入”到数据结构中。相反，如下所示，我们需要在对象中添加一个数据结构的字段。其中的`list`指向下一个Duck的`list`字段。但是这时我们是无法直接访问Duck的其他元素的，因为我们持有的仅仅是一个`struct list_head`对象。

```c
struct Duck {
  struct list_head list;
  char duck_name[10];
};
```

为了解决这个问题，我们有两种办法。第一，我们可以约定`struct list_head`必须是结构体的第一个元素，如下面的例子，那么list的地址也一定是Duck的地址。但是这样的方法缺少一定的灵活性。第二个方法更为泛用，首先我们有一个list的，并且我明确知道它是被套在一个Duck对象里面，那么list到Duck对象的首地址的偏移一定是确定的（即C语言中结构体中的元素在编译期一定是确定的）。这时候，我们可以通过这样的一个技巧来计算出这个偏移量：将一个`NULL`指针强转成Duck类型，然后使其指向list，即`&((Duck*)NULL)->list`。这样我们就得到一个list的偏移值，因为`NULL`被定义为0。当然，为了保险起见，我们可以再减去`NULL`来确保我们的结果正确。

这里就可以再插入一个知识点。可能会有人认为这样的操作可能会引起异常，因为我们在访问一个非法的地址。但是事实上这样的操作是安全的，因为我们并没有去尝试读取list的内容，而只是对其使用`&`取地址操作。

回到`SOCKET_I`函数，这里其实的作用就是：我现在持有一个`inode`，并且我明确知道这个`inode`存在于`struct socket_alloc`结构体中，并且`inode`的字段是`vfs_inode`。那么`container_of`宏会告诉我这个`struct socket_alloc`对象的地址是多少。

到了这里，我们明白了`sock_alloc`整个函数的功能。但是还有一点也许读者并没有注意到，那就是在`sock_alloc`函数中，`inode`和`sock`都是在函数内创建的变量，似乎并没有涉及到`struct socket_alloc`这个结构体。为了解决这个疑点，我们可以同样全局搜索`struct socket_alloc`，发现还有`sock_alloc_inode`，`sock_destroy_inode`等函数用到了它。这样似乎就可以解决我们的疑问了，即在创建inode的过程中，即`new_inode_pseudo`中，我们确保了`inode`和`sock`存在一一对应的关系。

我们可以继续搜索`sock_alloc_inode`，发现它被放置于`sockfs_ops`中，为一组函数指针。而`sockfs_ops`则在`sockfs_mount`被传递给文件系统。按照同样的方法向上搜索，可以追溯到上面讨论过的`sock_init`函数中。即这些操作都是网络模块向文件系统注册过的。

```c
static const struct super_operations sockfs_ops = {
	.alloc_inode	= sock_alloc_inode,
	.destroy_inode	= sock_destroy_inode,
	.statfs		= simple_statfs,
};

static struct dentry *sockfs_mount(struct file_system_type *fs_type,
			 int flags, const char *dev_name, void *data)
{
	return mount_pseudo_xattr(fs_type, "socket:", &sockfs_ops,
				  sockfs_xattr_handlers,
				  &sockfs_dentry_operations, SOCKFS_MAGIC);
}
```

### pf->create到底是个啥

到此我们可以进入到`sock_create`的下一个函数，`pf->create`函数。通过上面的例子，我们也可以知道在Linux内核源码中，函数指针是很常用的。这里同样是一个函数指针的调用，为了查清楚这个指针究竟来自哪里，我们有两种思路。这里两种方法都可以达到我们的目的。但是有时候一种方法不行，或者可能选项太多的时候，可以尝试换另一种方法。

1. 查看pf的类型和定义，并搜索这个类型的使用情况。
2. 查看pf的赋值情况，并且查看数据源或者函数。

#### 思路一

通过搜索pf的类型`struct net_proto_family`，我们可以找到一系列文件。这里推荐使用`rg`命令（ripgreg，一个更快的`grep`命令）或者vscode内建的搜索来完成。

```bash
rg "struct net_proto_family"

# 其中有一项结果为
# net/ipv4/af_inet.c
# 1075:static const struct net_proto_family inet_family_ops = {
```

在众多结果中，有一项看起来很可能是我们感兴趣的内容。因为它的文件名是`net/ipv4/af_inet.c`。

#### 思路二

我们可以在`__sock_create`函数内找到这一行语句`pf = rcu_dereference(net_families[family]);`。并且我们已经知道rcu本身是锁相关的代码，因此我们可以直接查看`net_families`的定义和赋值情况。

再次通过搜索，我们看到一个可能感兴趣的点，`rcu_assign_pointer(net_families[ops->family], ops)`，这条语句出现在`sock_register`函数中，更加能说明这很可能能追溯到`pf->create`从哪里来。尝试全局搜索`sock_register`，我们能得到和思路一一样的结果。

```bash
rg sock_register

# 其中有一项结果为
# net/ipv4/af_inet.c
# 1915:   (void)sock_register(&inet_family_ops);
```
#### 探索af_inet和socket的联系

无论是通过上面哪种方法，我们都能知道我们可以在`inet_family_ops`这个对象中找到`create`的定义。

```c
static const struct net_proto_family inet_family_ops = {
	.family = PF_INET,
	.create = inet_create,
	.owner	= THIS_MODULE,
};

static int __init inet_init(void)
{
    // 其他代码。。。
    (void)sock_register(&inet_family_ops);
    // 其他代码。。。
}
```

现在让我们阅读`inet_create`函数。

```c
static int inet_create(struct net *net, struct socket *sock, int protocol,
		       int kern)
{
	struct sock *sk;
	struct inet_protosw *answer;
	struct inet_sock *inet;
	struct proto *answer_prot;
	unsigned char answer_flags;
	int try_loading_module = 0;
	int err;

	if (protocol < 0 || protocol >= IPPROTO_MAX)
		return -EINVAL;

	sock->state = SS_UNCONNECTED;

	/* Look for the requested type/protocol pair. */
lookup_protocol:
	err = -ESOCKTNOSUPPORT;
	rcu_read_lock();
	list_for_each_entry_rcu(answer, &inetsw[sock->type], list) {

		err = 0;
		/* Check the non-wild match. */
		if (protocol == answer->protocol) {
			if (protocol != IPPROTO_IP)
				break;
		} else {
			/* Check for the two wild cases. */
			if (IPPROTO_IP == protocol) {
				protocol = answer->protocol;
				break;
			}
			if (IPPROTO_IP == answer->protocol)
				break;
		}
		err = -EPROTONOSUPPORT;
	}

	if (unlikely(err)) {
		if (try_loading_module < 2) {
			rcu_read_unlock();
			/*
			 * Be more specific, e.g. net-pf-2-proto-132-type-1
			 * (net-pf-PF_INET-proto-IPPROTO_SCTP-type-SOCK_STREAM)
			 */
			if (++try_loading_module == 1)
				request_module("net-pf-%d-proto-%d-type-%d",
					       PF_INET, protocol, sock->type);
			/*
			 * Fall back to generic, e.g. net-pf-2-proto-132
			 * (net-pf-PF_INET-proto-IPPROTO_SCTP)
			 */
			else
				request_module("net-pf-%d-proto-%d",
					       PF_INET, protocol);
			goto lookup_protocol;
		} else
			goto out_rcu_unlock;
	}

	err = -EPERM;
	if (sock->type == SOCK_RAW && !kern &&
	    !ns_capable(net->user_ns, CAP_NET_RAW))
		goto out_rcu_unlock;

	sock->ops = answer->ops;
	answer_prot = answer->prot;
	answer_flags = answer->flags;
	rcu_read_unlock();

	WARN_ON(!answer_prot->slab);

	err = -ENOBUFS;
	sk = sk_alloc(net, PF_INET, GFP_KERNEL, answer_prot, kern);
	if (!sk)
		goto out;

	err = 0;
	if (INET_PROTOSW_REUSE & answer_flags)
		sk->sk_reuse = SK_CAN_REUSE;

	inet = inet_sk(sk);
	inet->is_icsk = (INET_PROTOSW_ICSK & answer_flags) != 0;

	inet->nodefrag = 0;

	if (SOCK_RAW == sock->type) {
		inet->inet_num = protocol;
		if (IPPROTO_RAW == protocol)
			inet->hdrincl = 1;
	}

	if (net->ipv4.sysctl_ip_no_pmtu_disc)
		inet->pmtudisc = IP_PMTUDISC_DONT;
	else
		inet->pmtudisc = IP_PMTUDISC_WANT;

	inet->inet_id = 0;

	sock_init_data(sock, sk);

	sk->sk_destruct	   = inet_sock_destruct;
	sk->sk_protocol	   = protocol;
	sk->sk_backlog_rcv = sk->sk_prot->backlog_rcv;

	inet->uc_ttl	= -1;
	inet->mc_loop	= 1;
	inet->mc_ttl	= 1;
	inet->mc_all	= 1;
	inet->mc_index	= 0;
	inet->mc_list	= NULL;
	inet->rcv_tos	= 0;

	sk_refcnt_debug_inc(sk);

	if (inet->inet_num) {
		/* It assumes that any protocol which allows
		 * the user to assign a number at socket
		 * creation time automatically
		 * shares.
		 */
		inet->inet_sport = htons(inet->inet_num);
		/* Add to protocol hash chains. */
		err = sk->sk_prot->hash(sk);
		if (err) {
			sk_common_release(sk);
			goto out;
		}
	}

	if (sk->sk_prot->init) {
		err = sk->sk_prot->init(sk);
		if (err) {
			sk_common_release(sk);
			goto out;
		}
	}

	if (!kern) {
		err = BPF_CGROUP_RUN_PROG_INET_SOCK(sk);
		if (err) {
			sk_common_release(sk);
			goto out;
		}
	}
out:
	return err;
out_rcu_unlock:
	rcu_read_unlock();
	goto out;
}
```

在这一段函数中，除去一些锁操作，错误校验和单纯枯燥的赋值之外。值得关注的点就是。

1. `list_for_each_entry_rcu`这个循环
2. `sock->ops = answer->ops`赋值，我们想知道有哪些操作被传递给了`sock`
3. `sock_init_data(sock, sk)`函数调用，`socket`和`sock`结构体的差别是什么

首先，让我们看看`list_for_each_entry_rcu`这个循环。尝试搜索就可以发现它是一个宏定义，并且本质上就是`for`循环和`container_of`的组合。我们之前已经聊过`container_of`了。

```c
#define list_entry_rcu(ptr, type, member) \
	container_of(READ_ONCE(ptr), type, member)

#define list_for_each_entry_rcu(pos, head, member) \
	for (pos = list_entry_rcu((head)->next, typeof(*pos), member); \
		&pos->member != (head); \
		pos = list_entry_rcu(pos->member.next, typeof(*pos), member))
```

通过搜索可以知道，inetsw是一个链表数组`static struct list_head inetsw[SOCK_MAX]`，并且我们可以合理地猜测每个链表是按照`sock`的`type`分开的，即有连接（`SOCK_STREAM`），无连接（`SOCK_DGRAM`）以及其他类型。例如，在`inetsw[SOCK_STREAM]`上应当会有TCP协议的实现所对应的对象，而`inetsw[SOCK_DGRAM]`链表上可以找到UDP的实现。

```c
list_for_each_entry_rcu(answer, &inetsw[sock->type], list) {

	err = 0;
	/* Check the non-wild match. */
	if (protocol == answer->protocol) {
		if (protocol != IPPROTO_IP)
			break;
	} else {
		/* Check for the two wild cases. */
		if (IPPROTO_IP == protocol) {
			protocol = answer->protocol;
			break;
		}
		if (IPPROTO_IP == answer->protocol)
			break;
	}
	err = -EPROTONOSUPPORT;
}
```

我们暂且不去寻找这些实现，且关注这个循环本身。第一个if很好理解，当`if (protocol == answer->protocol) { if (protocol != IPPROTO_IP) break; }`，找到对应的协议时，且它不是一个通用协议的时候（`IPPROTO_IP`在约定中是一个wild protocol，即通配协议）。我们退出循环，并且带着`answer`（因为它在函数一开始就创建了，不会因为离开作用域而销毁）进入到下面的步骤。

而后面的else个人认为不太直观。当第一次循环开始且链表上第一个元素不等于我们要找的元素时，如果`protocol`等于`IPPROTO_IP`，即0（可以通过查找宏定义得知），那么就让`protocol`等于当前的`answer`并退出循环（因为判断中`if (IPPROTO_IP == protocol)`的`protocol`和`IPPROTO_IP`均不会随循环改变，如果第一次匹配不上那么就永远匹配不上了）。其实这也就是说，`SOCK_STREAM`链表上第一个元素一定是TCP协议的实现，这也就是为什么最开始的例子里面，我们可以使用`sockfd = socket(AF_INET, SOCK_STREAM, 0)`来创建TCP连接，而不必指定`IPPROTO_TCP`，UDP也是同理。

第二个判断，当`if (IPPROTO_IP == answer->protocol)`，我们也跳出循环。说明这个类型的链表上有一个协议注册为了通用协议，不论我们要找的是什么协议都会返回它（正常情况它会被注册为链表最后一个元素）。默认情况下，只用使用`type=SOCK_RAW`才会用到它，即我们想基于裸IP协议进行一些操作时才会用到它，而不使用任何协议，如TCP，UDP等。

如果所有条件均不满足，那么就会得到`err = -EPROTONOSUPPORT`，返回错误。

现在来看第二个点，`sock->ops = answer->ops`。那么我们可以通过之前的方案，已知`answer`来自于`inetsw`。那么追溯`inetsw`可以看到它是一个`list_head`数组，并且在`inet_register_protosw`中被赋值。继续追溯，可以查到`inet_init`中调用了`inet_register_protosw`函数，且所有数据来自于`inetsw_array`。

```c
static struct list_head inetsw[SOCK_MAX];

void inet_register_protosw(struct inet_protosw *p)
{
  // 其他代码。。。
	last_perm = &inetsw[p->type];
	list_for_each(lh, &inetsw[p->type]) {
		answer = list_entry(lh, struct inet_protosw, list);
		/* Check only the non-wild match. */
		if ((INET_PROTOSW_PERMANENT & answer->flags) == 0)
			break;
		if (protocol == answer->protocol)
			goto out_permanent;
		last_perm = lh;
	}
  // 其他代码。。。
}

static int __init inet_init(void)
{
  // 其他代码。。。

	/* Register the socket-side information for inet_create. */
	for (r = &inetsw[0]; r < &inetsw[SOCK_MAX]; ++r)
		INIT_LIST_HEAD(r);

	for (q = inetsw_array; q < &inetsw_array[INETSW_ARRAY_LEN]; ++q)
		inet_register_protosw(q);

  // 其他代码。。。
}
```

当我们尝试搜索`inetsw_array`时，所有东西都有了答案。我们可以看见Linux内核默认支持的所有IP族协议了。并且通过跳转`tcp_prot`等变量，可以看见各个协议的具体实现。

```c
static struct inet_protosw inetsw_array[] =
{
	{
		.type =       SOCK_STREAM,
		.protocol =   IPPROTO_TCP,
		.prot =       &tcp_prot,
		.ops =        &inet_stream_ops,
		.flags =      INET_PROTOSW_PERMANENT |
			      INET_PROTOSW_ICSK,
	},

	{
		.type =       SOCK_DGRAM,
		.protocol =   IPPROTO_UDP,
		.prot =       &udp_prot,
		.ops =        &inet_dgram_ops,
		.flags =      INET_PROTOSW_PERMANENT,
       },

       {
		.type =       SOCK_DGRAM,
		.protocol =   IPPROTO_ICMP,
		.prot =       &ping_prot,
		.ops =        &inet_sockraw_ops,
		.flags =      INET_PROTOSW_REUSE,
       },

       {
	       .type =       SOCK_RAW,
	       .protocol =   IPPROTO_IP,	/* wild card */
	       .prot =       &raw_prot,
	       .ops =        &inet_sockraw_ops,
	       .flags =      INET_PROTOSW_REUSE,
       }
};
```

让我们之后再来深挖tcp协议的具体实现。先回到刚刚的主题，还有第三个问题没有解决，那就是`struct socket`结构体和`struct sock`结构体的关系。通过跳转到`struct socket`结构体的定义，我们可以看见`struct sock sk`是`struct socket`结构体内部的一个元素，并且进入`struct sock`结构体的定义（太长此处不展开），可以看见许多内部底层的内容，通过搜索引擎可以知道，`struct sock`中的内容主要是供内核使用，而`struct socket`是暴露给用户态的接口。此处详细内容就不再深究，因为我们现在主要关心的是`struct socket`创建的整个主流程。

```c
struct socket {
	socket_state		state;

	short			type;

	unsigned long		flags;

	struct socket_wq	*wq;

	struct file		*file;
	struct sock		*sk;
	const struct proto_ops	*ops;
};
```

### sock_create函数总结

到此，我们已经挖完了`sock_create`函数的主流程。它会先创建一个`inode`给`sock`，并且根据对应入参的协议族选择对应的`create`函数来初始化这个`sock`。接下来我们会研究`sock_map_fd`。顾名思义，它会将我们的`socket`映射到一个具体的文件上，并且返回文件描述符`fd`（file descriptor）。

## sock_map_fd函数解析

由于我们在`sock_create`函数中已经拥有了一个`inode`，这一块的主要任务，可以合理地猜想，就是将我们的`inode`映射到一个具体的文件上面，并且获得一个文件描述符。

进入函数，我们可以看到主流程很简单。首先是`get_unused_fd_flags`获取一个未使用的`fd`号。这里其实可以衍生出一个很有趣的，关于文件系统的面试题。那就是当服务器`fd`耗尽有什么办法解决。解决办法很多，我们可以提高`fd`的上限（是的，这是可以配置的）；或者是优化资源使用，少创建`fd`；对`fd`复用，而不是一个客户端一个`fd`，例如`epoll`等。

```c
static int sock_map_fd(struct socket *sock, int flags)
{
	struct file *newfile;
	int fd = get_unused_fd_flags(flags);
	if (unlikely(fd < 0)) {
		sock_release(sock);
		return fd;
	}

	newfile = sock_alloc_file(sock, flags, NULL);
	if (likely(!IS_ERR(newfile))) {
		fd_install(fd, newfile);
		return fd;
	}

	put_unused_fd(fd);
	return PTR_ERR(newfile);
}
```

下一步，我们可以进入`sock_alloc_file`查看`sock`是如何和一个文件联系起来的。类似于`socket_create`，这里我们创建了一个pseudo file，并且将一些`socket`操作抽象成了文件操作，放在了`socket_file_ops`中传递给文件系统，例如`open`，`close`，`write`等操作，这使得我们的文件系统知道如何操作这些文件。

可以看到这里使用了`SOCK_INODE`函数来获取`sock`对应的`inode`。如果跳转过去，可以发现它就在之前的`SOCKET_I`函数旁边，使用同样的原理完成了`socket`和`inode`的双向互查。如果创建成功，那么我们在`sock`和`file`中加入互相的指针以实现互查，然后返回`file`指针。

最后是`fd_install`函数，可以进入这个函数发现它是一个文件系统内的函数，因此今天也不做深究。它的大概功能可以通过名字和搜索引擎知道，就是绑定文件描述符和文件。

```c
struct file *sock_alloc_file(struct socket *sock, int flags, const char *dname)
{
	struct file *file;

	if (!dname)
		dname = sock->sk ? sock->sk->sk_prot_creator->name : "";

	file = alloc_file_pseudo(SOCK_INODE(sock), sock_mnt, dname,
				O_RDWR | (flags & O_NONBLOCK),
				&socket_file_ops);
	if (IS_ERR(file)) {
		sock_release(sock);
		return file;
	}

	sock->file = file;
	file->private_data = sock;
	return file;
}
```

### sock_map_fd总结

这个函数相比`sock_create`要简单不少。当然以上都是纯粹的代码分析。这里做一个实验。大家可以尝试随便启动一个tcp或者http服务器（毕竟基于TCP，不讨论HTTP3的特例的话），然后找到它的进程编号。那么大概率你可以在文件系统中看见类似于下面的内容，这也证明socket确实是被当作一个文件在操作，和我们阅读代码中的内容一致。

```bash
# 找到你的进程编号
ps -aux | grep main

# 搜索这个进程下的文件描述符 
ll /proc/<pid>/fd

# 得到类似的输出
# total 0
# dr-x------ 2 <uid> <uid>  0 Apr 13 21:38 .
# dr-xr-xr-x 9 <uid> <uid>  0 Apr 13 21:38 ..
# lrwx------ 1 <uid> <uid> 64 Apr 13 21:38 0 -> /dev/pts/15
# lrwx------ 1 <uid> <uid> 64 Apr 13 21:38 1 -> /dev/pts/15
# lr-x------ 1 <uid> <uid> 64 Apr 13 21:38 19 -> /dev/urandom
# lrwx------ 1 <uid> <uid> 64 Apr 13 21:38 2 -> /dev/pts/15
# l-wx------ 1 <uid> <uid> 64 Apr 13 21:38 20 -> /home/<uid>/.vscode-server/data/logs/20240413T101955/ptyhost.log
# l-wx------ 1 <uid> <uid> 64 Apr 13 21:38 21 -> /home/<uid>/.vscode-server/data/logs/20240413T101955/remoteagent.log
# lrwx------ 1 <uid> <uid> 64 Apr 13 21:38 22 -> /dev/ptmx
# lrwx------ 1 <uid> <uid> 64 Apr 13 21:38 23 -> /dev/ptmx
# l-wx------ 1 <uid> <uid> 64 Apr 13 21:38 25 -> /home/<uid>/.vscode-server/data/logs/20240413T101955/network.log
# lrwx------ 1 <uid> <uid> 64 Apr 13 21:38 3 -> 'socket:[21472904]'
```

## 参考资料

inet_create分支解析：https://github.com/xgfone/snippet/blob/master/snippet/docs/linux/program/raw-socket-demystified.txt