---
title: 从内核出发手撕Linux网络协议栈(七)
---

大家五一假期快乐 ：-）

今天来讲讲connect系统调用的实现，这个系统调用流程比较长，用于客户端向服务器端发起建立连接请求。同样的，可以先使用man connect指令来看看connect调用的用法。我们一定是先使用socket()系统调用创建了一个客户端socket，然后再将它的fd传递给connect，并且给到服务器的地址端口信息来建立连接。返回值则是服务器socket所对应的fd。

```c
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```

## connect系统调用的实现

有了前面六集的经验，我们可以先在这里预测一下我们想要看见的代码的样子，这样有助于我们接下来理解代码。应该是可以分成三层的，由浅入深分别如下：

1. 系统调用定义层：这一层主要是包装一下，做一下协议族的判断，然后简单地将参数传递给下一层。
2. inet层：这一层我们主要会创建一个socket对象，包括其对应的inode和fd等必要的内容。然后具体网络通信相关的内容会给tcp层来完成。
3. tcp层：这一层我们主要是就是创建一个sock对象，并且在这里真正意义上完成连接的建立，当然也包括tcp三次握手的蛛丝马迹。

现在让我们用同样的方法来验证一下我的猜想是不是正确的。

## __sys_connect的实现

首先还是我们熟悉的sockfd_lookup_light函数，这个函数通过传入fd找到对应的socket对象。

```c
int __sys_connect(int fd, struct sockaddr __user *uservaddr, int addrlen)
{
	struct socket *sock;
	struct sockaddr_storage address;
	int err, fput_needed;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (!sock)
		goto out;
```

然后接着就是另外一个我们很熟悉的函数，这个函数将用户空间地址的内容拷贝到内核空间。因为内核空间无法直接访问用户空间的内容，反之亦然。

```c
err = move_addr_to_kernel(uservaddr, addrlen, &address);
if (err < 0)
	goto out_put;
```

接着，我们同样的会调用security_socket_connect，在介绍socket系统调用的时候已经介绍过。在开启了CONFIG_SECURITY_NETWORK时，函数会进行额外的安全验证/操作。否则，这些函数会被定义为inline的空函数（直接return 0），然后被编译器优化掉，没有额外的性能开销。

这里我们最关心的就是sock->ops->connect了，通过查找之前几集都用到的inetsw_array可以找到这个函数是指向inet_stream_connect的。

```c
	err =
	    security_socket_connect(sock, (struct sockaddr *)&address, addrlen);
	if (err)
		goto out_put;

	err = sock->ops->connect(sock, (struct sockaddr *)&address, addrlen,
				 sock->file->f_flags);
out_put:
	fput_light(sock->file, fput_needed);
out:
	return err;
}
```

## inet_stream_connect的实现

inet_stream_connect给socket对象中的sock对象（即sk）加了锁，确保同时只有这个线程可以访问它。然后__inet_stream_connect负责具体的建立连接的实现。

```c
int inet_stream_connect(struct socket *sock, struct sockaddr *uaddr,
			int addr_len, int flags)
{
	int err;

	lock_sock(sock->sk);
	err = __inet_stream_connect(sock, uaddr, addr_len, flags, 0);
	release_sock(sock->sk);
	return err;
}
```

现在让我们来看看__inet_stream_connect的具体实现。首先是判断用户传入的目标地址并且进行判断。如果传入的地址不为NULL，并且addr_len小于我们正常所需的大小，那么我们会返回一个错误。这样的判断听起来有点奇怪，因为我们判断addr_len并且返回错误，但是并没说当uaddr等于NULL时有什么错误。

这样做其实是有原因的，在使用tcp fast open的情况下，socket可以在建立连接前发送数据，这时候会用到tcp_sendmsg_fastopen()函数，而这个函数会调用__inet_stream_connect()，并且**uaddr和addr_len同时为0**。

除开这个例外，别的判断逻辑是显而易见的。当我们uaddr没有指定协议族时，函数同样做出异常处理，即尝试断开连接。

```c
if (uaddr) {
	if (addr_len < sizeof(uaddr->sa_family))
		return -EINVAL;

	if (uaddr->sa_family == AF_UNSPEC) {
		err = sk->sk_prot->disconnect(sk, flags);
		sock->state = err ? SS_DISCONNECTING : SS_UNCONNECTED;
		goto out;
	}
}
```

接下来我们会尝试根据socket对象的状态来决定不同的分支。如果目前的状态是SS_CONNECTED或者SS_CONNECTING，那么就设置对应的状态为EISCONN（error is connecting），EINPROGRESS（error in progress）。这里比较反直觉的是default写在了最开始，但是因为每个分支都有break或者goto来确保分支不会fallthrough，所以这样的写法是没问题的，行为如同正常的switch语句一样。这样做的原因大概率是因为作者希望强调主逻辑SS_UNCONNECTED，不希望在主逻辑之后再放一个分支逻辑来干扰读者阅读代码。

```c
switch (sock->state) {
default:
	err = -EINVAL;
	goto out;
case SS_CONNECTED:
	err = -EISCONN;
	goto out;
case SS_CONNECTING:
	if (inet_sk(sk)->defer_connect)
		err = is_sendmsg ? -EINPROGRESS : -EISCONN;
	else
		err = -EALREADY;
	/* Fall out of switch with err, set for this state */
	break;
case SS_UNCONNECTED:
	// 如果没有连接，则尝试连接。。。
}
```

现在让我们来细看一下连接的代码。其中最主要的还是sk->sk_prot->connect()来调用更底层的连接逻辑。如果返回结果正常，那么则将状态设置为SS_CONNECTING。另外的一个我们可能感兴趣的操作就是sk->sk_prot->pre_connect()，主要是取决于我们是否启用BPF和CGROUP相关的功能。它们都是功能强大的内核资源监控手段。

```c
err = -EISCONN;
if (sk->sk_state != TCP_CLOSE)
	goto out;

if (BPF_CGROUP_PRE_CONNECT_ENABLED(sk)) {
	err = sk->sk_prot->pre_connect(sk, uaddr, addr_len);
	if (err)
		goto out;
}

err = sk->sk_prot->connect(sk, uaddr, addr_len);
if (err < 0)
	goto out;

sock->state = SS_CONNECTING;

if (!err && inet_sk(sk)->defer_connect)
	goto out;

/* Just entered SS_CONNECTING state; the only
 * difference is that return value in non-blocking
 * case is EINPROGRESS, rather than EALREADY.
 */
err = -EINPROGRESS;
break;
```

虽然我们不会在这里深度了解ebpf或者cgroup，但是可以粗略看一下pre_connect的实现。可以很合理地做出推测，它应该是一个hook点来告诉bpf和cgroup我们调用了connect()。尝试在全局范围搜索BPF_CGROUP_RUN_PROG_INET4_CONNECT宏定义，可以看见有两种定义，其中一种是没有任何实现，单纯返回0的宏。

```c
static int tcp_v4_pre_connect(struct sock *sk, struct sockaddr *uaddr,
			      int addr_len)
{
	/* This check is replicated from tcp_v4_connect() and intended to
	 * prevent BPF program called below from accessing bytes that are out
	 * of the bound specified by user in addr_len.
	 */
	if (addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;

	sock_owned_by_me(sk);

	return BPF_CGROUP_RUN_PROG_INET4_CONNECT(sk, uaddr);
}
```

![](images/linux-kernel-net-07-01.png)

回归正题，在调用sk->sk_prot->connect()之后，在switch分支之外，我们首先会设置一个timeout（timeo变量），然后判断sock对象的状态。学过计算机网络的读者肯定看见很熟悉的理论了，这个if会判断SYN信号的状态，其中SYN信号是tcp三次握手中必要的信息传递。

我们不妨在这里复习一下tcp三次握手的流程。我这个人向来是不喜欢死记硬背的，读者不妨思考一下为什么tcp需要三次握手。在我看来无非是为了确认通信双方是具有收发信息的能力的。

1. 首先client向server发送SYN，当server收到了SYN，那么表明了client有发送信息的能力。
2. server向client发送SYN+ACK信息，当client收到了SYN+ACK，那么表明了服务器接收到了client发送的信息，并且做出了回应，代表了服务器肯定同时具有收发信息的能力。如果server只发送SYN呢？那么client可能会误解这是server想要主动建立tcp连接。
3. client这时候需要再次回复一个SYN+ACK给服务器，因为服务器知道客户端可以发出信息，但是还不确定客户端是否有收到信息的能力，因此这个SYN+ACK也是必要的。

这里其实就是在判断SYN的状态是SENT还是RECV。如果是SENT，那么就是客户端已经发出了SYNC信号；如果是RECV，那么说明服务器搞得很快，对面的ACK信号已经过来了并且处理完成了。总之我们可以开始我们的下一步了，即inet_wait_for_connect()。当完成这些步骤之后就完成了整个connect的过程。

```c
timeo = sock_sndtimeo(sk, flags & O_NONBLOCK);

if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
	int writebias = (sk->sk_protocol == IPPROTO_TCP) &&
			tcp_sk(sk)->fastopen_req &&
			tcp_sk(sk)->fastopen_req->data ? 1 : 0;

	/* Error code is set above */
	if (!timeo || !inet_wait_for_connect(sk, timeo, writebias))
		goto out;

	err = sock_intr_errno(timeo);
	if (signal_pending(current))
		goto out;
}

if (sk->sk_state == TCP_CLOSE)
	goto sock_error;

sock->state = SS_CONNECTED;
err = 0;

out:
	return err;
```

可以看见inet_wait_for_connect()就是一个while循环在等待连接完成，这可能和一些读者是期望不太一样，其中并没有三次握手相关的代码实现。事实上这一部分代码是由tcp协议层的实现来完成的，就是文章开头讲到的第三层，即文章刚刚提到的sk->sk_prot->connect()。这里是主要用于定期唤醒线程，检测连接状态，减去耗时判断是否超时。当连接状态不再是SENT或者RECV时，就可以说明

```c
static long inet_wait_for_connect(struct sock *sk, long timeo, int writebias)
{
	DEFINE_WAIT_FUNC(wait, woken_wake_function);

	add_wait_queue(sk_sleep(sk), &wait);
	sk->sk_write_pending += writebias;
	sk->sk_wait_pending++;

	/* Basic assumption: if someone sets sk->sk_err, he _must_
	 * change state of the socket from TCP_SYN_*.
	 * Connect() does not allow to get error notifications
	 * without closing the socket.
	 */
	while ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV)) {
		release_sock(sk);
		timeo = wait_woken(&wait, TASK_INTERRUPTIBLE, timeo);
		lock_sock(sk);
		if (signal_pending(current) || !timeo)
			break;
	}
	remove_wait_queue(sk_sleep(sk), &wait);
	sk->sk_write_pending -= writebias;
	sk->sk_wait_pending--;
	return timeo;
}
```

## sk->sk_prot->connect的实现

查看之前几集反复提到的inetsw_array，我们可以查找到sk->sk_prot->connect的tcp实现函数是tcp_v4_connect()。这一个函数相当长，让我们来分段看一看。函数一开始就是一大堆的变量定义，其中涉及到了一些路由表和路由的概念，例如nexthop。然后还有dxxx和sxxx的变量（例如sport，dport，daddr等），代表destination和source，即目标和源。当然，也还要结合语境和上下文来理解，比如sin_addr.s_addr中的s_addr只是代表socket而不是source。inet_timewait_death_row则代表了已经超时的链接。

```c
int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	__be16 orig_sport, orig_dport;
	__be32 daddr, nexthop;
	struct flowi4 *fl4;
	struct rtable *rt;
	int err;
	struct ip_options_rcu *inet_opt;
	struct inet_timewait_death_row *tcp_death_row = &sock_net(sk)->ipv4.tcp_death_row;
```

接着我们做了一些判断来确保传入的参数没有错误。

```c
if (addr_len < sizeof(struct sockaddr_in))
	return -EINVAL;

if (usin->sin_family != AF_INET)
	return -EAFNOSUPPORT;
```

这一段代码首先根据给定的目标地址去找到一个有效的路由。其中nexthop代表了下一跳的地址，但是在此处有一些迷惑。因为假设目标IP地址是跨网段的，并且没有开启srr，那么这里的nexthop就为目标地址，这有些迷惑，因为在路由的概念中，nexthop通常会是网关。但是这不是最终结果，在路由决策层还会有变化（但是不在这个函数里）。所以个人私下认为nexthop这个名字有一点误导性。

顺带一提，SRR，即Source Route Record，源路由记录。它是IP包头部的一个选项，用于指定一个数据包在到达最终目的地前必须经过的确切路径。其也分为LSRR和SSRR，即松散（loose）/严格（strict）源路由记录。如果是松散源路由记录，那么这个在IP包头的指定地址仅作为参考，而严格路由下则必须经过此记录的IP。当然考虑到路由器有非标准的实现，也许也有实现忽略这个限制。

下面是ip_route_connect函数接受目标地址，源地址，网络设备接口等参数，返回一个路由表项。如果存在可能的路由，那么这个路由表项就将被用于实际的数据传输。此处暂时不深入这个函数，否则有太多内容需要讲解了。

```c
nexthop = daddr = usin->sin_addr.s_addr;
inet_opt = rcu_dereference_protected(inet->inet_opt,
				     lockdep_sock_is_held(sk));
if (inet_opt && inet_opt->opt.srr) {
	if (!daddr)
		return -EINVAL;
	nexthop = inet_opt->opt.faddr;
}

orig_sport = inet->inet_sport;
orig_dport = usin->sin_port;
fl4 = &inet->cork.fl.u.ip4;
rt = ip_route_connect(fl4, nexthop, inet->inet_saddr,
		      RT_CONN_FLAGS(sk), sk->sk_bound_dev_if,
		      IPPROTO_TCP,
		      orig_sport, orig_dport, sk);
if (IS_ERR(rt)) {
	err = PTR_ERR(rt);
	if (err == -ENETUNREACH)
		IP_INC_STATS(sock_net(sk), IPSTATS_MIB_OUTNOROUTES);
	return err;
}
```

接下来这段代码主要是检测一些设置和完成连接初始化。如果上面路由表的结果是一个多播地址或者广播地址，那么这在tpc中是不允许的，返回错误。

下一步，如果没有启用源路由，那么目标地址就是会被赋值为fl4->daddr。其中fl4代表ipv4的路由流信息，类型缩写为flowi4。它是通过上面ip_route_connect调用中被设置的（以指针的形式）。如果源地址没有被设置，那么同样使用路由表的信息来设置源地址。对于客户端来说，这可能发生在多网卡的环境下，此时主机ip地址不唯一，会根据路由出口来决定ip地址。最后是一些无聊配置，例如端口，时间戳，ip包头大小等，没有太多我们关心的内容。

```c
if (rt->rt_flags & (RTCF_MULTICAST | RTCF_BROADCAST)) {
	ip_rt_put(rt);
	return -ENETUNREACH;
}

if (!inet_opt || !inet_opt->opt.srr)
	daddr = fl4->daddr;

if (!inet->inet_saddr)
	inet->inet_saddr = fl4->saddr;
sk_rcv_saddr_set(sk, inet->inet_saddr);

if (tp->rx_opt.ts_recent_stamp && inet->inet_daddr != daddr) {
	/* Reset inherited state */
	tp->rx_opt.ts_recent	   = 0;
	tp->rx_opt.ts_recent_stamp = 0;
	if (likely(!tp->repair))
		WRITE_ONCE(tp->write_seq, 0);
}

inet->inet_dport = usin->sin_port;
sk_daddr_set(sk, daddr);

inet_csk(sk)->icsk_ext_hdr_len = 0;
if (inet_opt)
	inet_csk(sk)->icsk_ext_hdr_len = inet_opt->opt.optlen;

tp->rx_opt.mss_clamp = TCP_MSS_DEFAULT;
```

这一步是很关键的，我特意贴出了注释。这时候客户端大概率是没有指定端口的，这时候我们需要访问inet的hash表来给socket分配一个端口。这个函数会在下一小节详细介绍。

```c
/* Socket identity is still unknown (sport may be zero).
 * However we set state to SYN-SENT and not releasing socket
 * lock select source port, enter ourselves into the hash tables and
 * complete initialization after this.
 */
tcp_set_state(sk, TCP_SYN_SENT);
err = inet_hash_connect(tcp_death_row, sk);
if (err)
	goto failure;

sk_set_txhash(sk);
```

由于前面更新了端口，这里我们需要使用ip_route_newports更新一下路由表，并且得到一个新的路由。这里可能读者有疑问，为什么不先使用inet_hash_connect，然后直接使用新的端口进行ip_route_newports得到路由，这样似乎浪费了一次访问路由表的时间。但是我个人认为这样做是因为确认端口资源不被浪费。通过先确定路由的有效性，可以避免在无法建立连接的情况下浪费本地端口资源。如果先分配了端口但后面发现无法建立路由，则之前分配的端口就被无谓地占用了。如果这样做会显著影响性能，那么在最新的linux源码中大概率会被调整，但是到现在这块代码都还在。

```c
rt = ip_route_newports(fl4, rt, orig_sport, orig_dport,
		       inet->inet_sport, inet->inet_dport, sk);
if (IS_ERR(rt)) {
	err = PTR_ERR(rt);
	rt = NULL;
	goto failure;
}
```

现在向我们正式计算出“终点”调用tcp_connect发送我们的数据包。其中SKB_GSO_TCPV4的GSO代表Generic Segmentation Offload，即通用分段。设置它会启用tcp报文文分段。

```c
/* OK, now commit destination to socket.  */
sk->sk_gso_type = SKB_GSO_TCPV4;
sk_setup_caps(sk, &rt->dst);
rt = NULL;

if (likely(!tp->repair)) {
	if (!tp->write_seq)
		WRITE_ONCE(tp->write_seq,
			   secure_tcp_seq(inet->inet_saddr,
					  inet->inet_daddr,
					  inet->inet_sport,
					  usin->sin_port));
	tp->tsoffset = secure_tcp_ts_off(sock_net(sk),
					 inet->inet_saddr,
					 inet->inet_daddr);
}

inet->inet_id = prandom_u32();

if (tcp_fastopen_defer_connect(sk, &err))
	return err;
if (err)
	goto failure;

err = tcp_connect(sk);
```

现在先让我们来看看tcp端口分配的逻辑，inet_hash_connect函数，再去看tcp_connect的实现。

## inet_hash_connect的实现

首先还是一些无聊的变量初始化，这里可以重新强调一下在第五集中提到的内容。在inet_hashinfo这个结构体中存储了socket状态信息，包括已经bind的socket，记录在bhash中。已经establish的socket，记录在ehash中。已经在listening状态的socket，记录在lhash2和listening_hash中。

```c
int __inet_hash_connect(struct inet_timewait_death_row *death_row,
		struct sock *sk, u64 port_offset,
		int (*check_established)(struct inet_timewait_death_row *,
			struct sock *, __u16, struct inet_timewait_sock **))
{
	struct inet_hashinfo *hinfo = death_row->hashinfo;
	struct inet_timewait_sock *tw = NULL;
	struct inet_bind_hashbucket *head;
	int port = inet_sk(sk)->inet_num;
	struct net *net = sock_net(sk);
	struct inet_bind_bucket *tb;
	u32 remaining, offset;
	int ret, i, low, high;
	u32 index;
```

接下来代码会检测sock是否已经有了一个端口号，如果已经有了，那么函数会直接结束返回。

```c
if (port) {
	local_bh_disable();
	ret = check_established(death_row, sk, port, NULL);
	local_bh_enable();
	return ret;
}
```

这里是使用了inet_get_local_port_range函数来获取可用端口范围，并且给high++，这是为了使用for循环，把闭区间变成左闭右开区间。额外的，remaining计算出可用端口数量，并且取偶数（使用位运算把最低位清零）。这样做是有历史原因的，在过去IBM的NCP（Network Control Program）上，通常使用奇偶来区分入站和出站流量。并且这种习惯已经保留到了今天，尽管你可以使用奇数来作为客户端端口，或者偶数来作为服务器端口，技术上没有任何问题（例如http 80和8080）。

```c
void inet_get_local_port_range(struct net *net, int *low, int *high)
{
	unsigned int seq;

	do {
		seq = read_seqbegin(&net->ipv4.ip_local_ports.lock);

		*low = net->ipv4.ip_local_ports.range[0];
		*high = net->ipv4.ip_local_ports.range[1];
	} while (read_seqretry(&net->ipv4.ip_local_ports.lock, seq));
}

inet_get_local_port_range(net, &low, &high);
high++; /* [32768, 60999] -> [32768, 61000[ */
remaining = high - low;
if (likely(remaining > 1))
	remaining &= ~1U;
```

这个数值是静态并且可配置的，大家可以在/proc/sys/net/ipv4/ip_local_port_range中设置，或者使用cat输出。其查找方法也很简单，只是一个简单的配置读取，inet_get_local_port_range函数中的循环仅作为自旋锁使用。

![](images/linux-kernel-net-07-02.png)

接下来我们会随机生成一个开始查找的起点。这里一个小知识点是我们使用了get_random_slow_once函数（其实是一个宏定义），这里的slow代表了较慢的随机数生成操作，通常只会在函数或者代码块的首次调用时使用slow宏。

```c
get_random_slow_once(table_perturb,
		     INET_TABLE_PERTURB_SIZE * sizeof(*table_perturb));
index = port_offset & (INET_TABLE_PERTURB_SIZE - 1);

offset = READ_ONCE(table_perturb[index]) + (port_offset >> 32);
offset %= remaining;
```

接下来的这段代码很有意思，首先这段代码是通过一个循环来查找可用的端口，但是有一些特殊的处理。

1. 我们使用了随机初始化的偏移量
2. 我们对offset使用了`offset &= ~1U`，这代表了对数值1二进制取反，然后再对其和offset进行按位与运算，即清零最低位，保证其是一个偶数。
3. for循环的步长为2

这样做其实就是首先遍历了所有偶数端口。我们可以看见有goto标签other_parity_scan，这就是为了当在极端情况下如果所有偶数端口都不可用时，我们可以查找奇数端口。但是这里还需要注意一点，就是`port = low + offset`。如果我们从`[low + offset,high]`这个集合搜索端口，有没有可能错过`[low,low + offset)`的可用端口呢，极端情况下是否可能存在可用端口但是找不到吗。

答案是否定的，但是为什么呢？关键在于上一步生成随机数中，我们使用了`offset %= remaining`。即offset的取值范围为`[0,remaining - 1]`。假设remaining为x，那么offset最大为x-1。假设最坏的情况下，low+offset跳过的端口号全是可用的，那么剩余范围内至少还有一个端口是可用的。通过求模运算实现了这样的功能个人感觉十分优雅高效，不愧是linux的内核源码。

这里还可以思考一个问题，什么我们需要使用随机数来初始化搜索的起点而不是从一个固定起点开始。这主要是为了在高并发场景下避免端口碰撞。当然，我们也可以加更大的锁来避免碰撞，但是这样比较低效。可以先看到循环结束，如果没有找到何时的端口就不会`goto ok`，这时候会走到`offset++`这个语句，把offset变成奇数，然后再次开始搜索。也就是说，尽管linux尊重历史的发展，但是在极端情况下还是会使用奇数端口作为客户端tcp端口号。

中间的inet_bind_bucket_for_each是在inet_hashinfo的bhash哈希链表中查找端口号，如果已经创建了对应的端口，且不可以端口复用时，那么就检查下一个端口。这一部分解释起来比较复杂，可以查看一篇cloudflare的文章来得到答案，我会在参考资料中贴出。简单来说，如果fastreuse为0或1，那么我们的通过connect的，系统自动选择创建的临时端口不可以复用这个端口。如果fastreuse为-1，那我们则可以复用。

接着，如果可以复用，那么我们尝试去查找这个端口是否有已经建立的连接，如果没有，那么就可以使用这个端口。这里的逻辑就是如果socket只绑定了相同的端口，但是没有建立连接的话，那么就谁先建立连接谁就能用到。端口复用只是指绑定阶段，建立连接还是唯一的。

如果我们没有在哈希表中找到我们的端口，那么很幸运，没有遇到冲突问题，我们可以直接创建一个新的元素在这个哈希表中，然后fastreuse设置为-1。这和上面的内容有关联，具体来说-1代表socket是来自于一个临时端口，0和1也有不同的代表。考虑到端口冲突时，当前哈希表内的fastreuse的数值和当前连接的状况（临时，非临时，有没有设置允许复用）的排列组合的情况，处理的结果有很多种，更多信息可以看参考资料的内容。

```c
	offset &= ~1U;
other_parity_scan:
	port = low + offset;
	for (i = 0; i < remaining; i += 2, port += 2) {
		if (unlikely(port >= high))
			port -= remaining;
		if (inet_is_local_reserved_port(net, port))
			continue;
		head = &hinfo->bhash[inet_bhashfn(net, port,
						  hinfo->bhash_size)];
		spin_lock_bh(&head->lock);

		/* Does not bother with rcv_saddr checks, because
		 * the established check is already unique enough.
		 */
		inet_bind_bucket_for_each(tb, &head->chain) {
			if (net_eq(ib_net(tb), net) && tb->port == port) {
				if (tb->fastreuse >= 0 ||
				    tb->fastreuseport >= 0)
					goto next_port;
				WARN_ON(hlist_empty(&tb->owners));
				if (!check_established(death_row, sk,
						       port, &tw))
					goto ok;
				goto next_port;
			}
		}

		tb = inet_bind_bucket_create(hinfo->bind_bucket_cachep,
					     net, head, port);
		if (!tb) {
			spin_unlock_bh(&head->lock);
			return -ENOMEM;
		}
		tb->fastreuse = -1;
		tb->fastreuseport = -1;
		goto ok;
next_port:
		spin_unlock_bh(&head->lock);
		cond_resched();
	}

	offset++;
	if ((offset & 1) && remaining > 1)
		goto other_parity_scan;

	return -EADDRNOTAVAIL;
```

这样一来，tcp客户端发起连接的端口选择算法就已经介绍完了。下面让我们看看tcp_connect，其中包含了真正的三次握手相关的内容。

## tcp_connect的实现

希望大家还记得之前我们的tcp_v4_connect在最后调用了tcp_connect。它将会完成tcp三次握手中第一个SYN包的发送。这里我们可以先简单过下主流程，因为其中细节太多，尤其涉及到更底层的驱动和硬件。

首先可以看见开始就是一些初始化，主要关注的是sk_buff。当我们要发送一个socket数据包/报文时，内核都是使用sk_buff这个结构体来构建的。

```c
/* Build a SYN and send it off. */
int tcp_connect(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *buff;
	int err;

	tcp_call_bpf(sk, BPF_SOCK_OPS_TCP_CONNECT_CB, 0, NULL);

	if (inet_csk(sk)->icsk_af_ops->rebuild_header(sk))
		return -EHOSTUNREACH; /* Routing failure or similar. */
```

然后下面这一段主要负责在tcp socket上初始化并发送一个SYN包。tcp_connect_init首先配置tcp sock的一些属性，包括tcp包头长度，md5签名信息，最大分段大小，tcp滑动窗口大小，缓冲区大小，超时重传，tcp序列号等信息。

sk_stream_alloc_skb函数为SYN包分配一个新的套接字缓冲区（skb）。然后tcp_init_nondata_skb函数初始化分配的skb。该函数设置tcp包头，并将包类型设置为SYN控制段，用于建立连接。tp->write_seq++更新了tcp的序列号。接下来tcp_mstamp_refresh和tcp_time_stamp分别设置了tcp socket的时间戳和重传时间戳。如果当前时间减去重传时间戳大于超时时间，那么就会触发tcp重传机制。

最后，我们使用tcp_connect_queue_skb将包加入到发送队列中，并且设置tcp_ecn_send_syn，即显式拥塞通知（ECN，Explicit Congestion Notification）。它并不是最初tcp协议中的内容，我们大概率没有在学校教材中学到过它。它告诉其他网络设备可以在网络拥塞时发送端支持ecn，即发送端在可以接收拥塞通知，并且会做出合理的决定。这样接收端可以期待发送端不发送或者少发送重传的包，而发送端也可以期待接收端慢慢处理这个包，而不是认为这个包被丢弃了。从而最终提高网络利用率。最后，我们还是需要使用tcp_rbtree_insert将tcp包加入到重传红黑树中，以防万一我们确实需要重传。

```c
tcp_connect_init(sk);

if (unlikely(tp->repair)) {
	tcp_finish_connect(sk, NULL);
	return 0;
}

buff = sk_stream_alloc_skb(sk, 0, sk->sk_allocation, true);
if (unlikely(!buff))
	return -ENOBUFS;

tcp_init_nondata_skb(buff, tp->write_seq++, TCPHDR_SYN);
tcp_mstamp_refresh(tp);
tp->retrans_stamp = tcp_time_stamp(tp);
tcp_connect_queue_skb(sk, buff);
tcp_ecn_send_syn(sk, buff);
tcp_rbtree_insert(&sk->tcp_rtx_queue, buff);
```

需要注意的是，上面的tcp_connect_queue_skb仅仅是逻辑上将tcp包加入到了发送队列，而没有物理意义上发送出去。而tcp_transmit_skb这个函数负责实际的数据包发送工作，不仅限于控制段，还包括数据段的发送。

```c
err = tp->fastopen_req ? tcp_send_syn_data(sk, buff) :
      tcp_transmit_skb(sk, buff, 1, sk->sk_allocation);
if (err == -ECONNREFUSED)
	return err;
```

我们不妨来看看tcp_connect_queue_skb的实现，它只是简单的修改了序号等信息，没有任务队列相关的逻辑。也就是说，它是用来在多线程的环境下让其他线程知道socket当前总的发送状态，数据统计，以保证可以编号出合理地tcp序列号。

```c
static void tcp_connect_queue_skb(struct sock *sk, struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);

	tcb->end_seq += skb->len;
	__skb_header_release(skb);
	sk->sk_wmem_queued += skb->truesize;
	sk_mem_charge(sk, skb->truesize);
	WRITE_ONCE(tp->write_seq, tcb->end_seq);
	tp->packets_out += tcp_skb_pcount(skb);
}
```

最后我们设置下下一个发送的tcp包的序号等信息，然后设置一个重传计时器。这里我们没有直接设置相关的回调函数，而是通过给定了sk的指针，即届时定时器可以通过访问tcp sock来得到处理重传相关的逻辑。这里暂时也不展开，这部分细节太多。

```c
	tp->snd_nxt = tp->write_seq;
	tp->pushed_seq = tp->write_seq;
	buff = tcp_send_head(sk);
	if (unlikely(buff)) {
		tp->snd_nxt	= TCP_SKB_CB(buff)->seq;
		tp->pushed_seq	= TCP_SKB_CB(buff)->seq;
	}
	TCP_INC_STATS(sock_net(sk), TCP_MIB_ACTIVEOPENS);

	/* Timer for repeating the SYN until an answer. */
	inet_csk_reset_xmit_timer(sk, ICSK_TIME_RETRANS,
				  inet_csk(sk)->icsk_rto, TCP_RTO_MAX);
	return 0;
}
```

## 总结

总的来说，和我们一开始的猜想类似，我们最外围的系统调用定义和inet层处理通用socket的逻辑还算简单。但是tcp部分，即处理核心struct sock的部分还是比较复杂的。这篇文章主要详细讲述了tcp的端口选择算法，然后了解了tcp连接建立的主流程，并且了解到了第一个syn包是怎么发出的。

## 参考资料

关于端口奇偶数的历史背景: https://news.ycombinator.com/item?id=14178776
关于端口复用的扩展：https://blog.cloudflare.com/the-quantum-state-of-a-tcp-port