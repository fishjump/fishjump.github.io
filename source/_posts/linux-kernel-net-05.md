---
title: 从内核出发手撕Linux网络协议栈(五)
---

（最近在外地，没有自己的PC，只能周末腹泻式更新）

## Listen系统调用

昨天介绍了`bind`系统调用，下一步就是`listen`系统调用了。它的参数很简单，只有两个。第一个是`int fd`，读者想必已经非常熟悉了，就是我们socket所对应的文件描述符；而第二个参数则是代表了最大连接请求等待队列的长度。也就是在`listen`完成之后，如果同一时间有多台主机向服务器发起连接请求，那么服务器允许的最大队列长度。同样地，以上介绍读者都可以通过`man listen`命令自行查阅，以证明我不是在乱说。

接着，让我们使用同样的方法，搜索`"SYSCALL_DEFINE.\(listen"`来找到`listen`函数的入口，如下所示。其中`sockfd_lookup_light`已经在上一集中介绍过了，其作用是给定一个`fd`，找到其所对应的`struct socket`对象。

紧接着，如果我们给定的`backlog`超过了系统所允许的上限，那么以系统的参数为准。这里可以稍微进行一下扩展，`somaxconn`代表了socket max connection，这是一个内核参数。我们有两种办法可以修改这个参数。

1. 我们可以直接修改对应的文件，例如修改为2048，`echo 2048 > /proc/sys/net/core/somaxconn`。这样的修改是临时的，当系统重启之后就会失效。
2. 我们可以在`/etc/sysctl.conf`文件中进行修改，加上或者修改现有配置为`net.core.somaxconn = 2048`，重启后生效。或者使用命令`sysctl -w net.core.somaxconn=2048 >> /etc/sysctl.conf`，更改会立即并永久生效，无需重启。

```c
int __sys_listen(int fd, int backlog)
{
	struct socket *sock;
	int err, fput_needed;
	int somaxconn;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (sock) {
		somaxconn = sock_net(sock->sk)->core.sysctl_somaxconn;
		if ((unsigned int)backlog > somaxconn)
			backlog = somaxconn;

		err = security_socket_listen(sock, backlog);
		if (!err)
			err = sock->ops->listen(sock, backlog);

		fput_light(sock->file, fput_needed);
	}
	return err;
}

SYSCALL_DEFINE2(listen, int, fd, int, backlog)
{
	return __sys_listen(fd, backlog);
}
```

## inet_listen的实现

通过和之前一样的方法，找到`inetsw_array`中TCP的数组，listen中的`sock->ops->listen`对应了`inet_stream_ops->listen`，即`inet_listen`。可以看见其的内部实现也相对简单，首先我们判断这个socket是否是未连接状态（`sock->state != SS_UNCONNECTED`），并且它是不是有连接的socket（`sock->type != SOCK_STREAM`）。如果已经连接或者socket类型就不对，那么自然是退出。

然后判断`struct sock sk`当前的状态，如果已经是`TCP_CLOSE`或者`TCP_LISTEN`那么也是错误的状态，需要退出。这里有一个小细节，那就是代码中使用了`TCPF_CLOSE`和`TCPF_LISTEN`的位运算来判断，其中F代表Flag，这样做可以加速运算。跳转到`include/net/tcp_states.h`可以看见TCPF_XXX的定义就是(1 << TCP_XXX)。例如`TCPF_ESTABLISHED = (1 << TCP_ESTABLISHED)`。

```c
enum {
	TCP_ESTABLISHED = 1,
    // 其他定义。。。
};

enum {
	TCPF_ESTABLISHED = (1 << TCP_ESTABLISHED),
    // 其他定义。。。
};

```

之后的if判断中大部分是和tcp_fastopen相关的实现，这一段可以暂时跳过，核心业务逻辑代码其实只有一行`inet_csk_listen_start`。

```c
int inet_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	unsigned char old_state;
	int err, tcp_fastopen;

	lock_sock(sk);

	err = -EINVAL;
	if (sock->state != SS_UNCONNECTED || sock->type != SOCK_STREAM)
		goto out;

	old_state = sk->sk_state;
	if (!((1 << old_state) & (TCPF_CLOSE | TCPF_LISTEN)))
		goto out;

	/* Really, if the socket is already in listen state
	 * we can only allow the backlog to be adjusted.
	 */
	if (old_state != TCP_LISTEN) {
		/* Enable TFO w/o requiring TCP_FASTOPEN socket option.
		 * Note that only TCP sockets (SOCK_STREAM) will reach here.
		 * Also fastopen backlog may already been set via the option
		 * because the socket was in TCP_LISTEN state previously but
		 * was shutdown() rather than close().
		 */
		tcp_fastopen = sock_net(sk)->ipv4.sysctl_tcp_fastopen;
		if ((tcp_fastopen & TFO_SERVER_WO_SOCKOPT1) &&
		    (tcp_fastopen & TFO_SERVER_ENABLE) &&
		    !inet_csk(sk)->icsk_accept_queue.fastopenq.max_qlen) {
			fastopen_queue_tune(sk, backlog);
			tcp_fastopen_init_key_once(sock_net(sk));
		}

		err = inet_csk_listen_start(sk, backlog);
		if (err)
			goto out;
		tcp_call_bpf(sk, BPF_SOCK_OPS_TCP_LISTEN_CB, 0, NULL);
	}
	sk->sk_max_ack_backlog = backlog;
	err = 0;

out:
	release_sock(sk);
	return err;
}
```

## inet_csk_listen_start的实现

可以看见这里再次用到了icsk和inet，也就是sk的上层封装。这个函数的前半段主要进行一些初始化操作，设置了等待队列。紧接着，最关键的一行是`inet_sk_state_store(sk, TCP_LISTEN)`，它将我们socket的状态设置为`TCP_LISTEN`，代表我们的socket已经允许接受外部的连接。

这时候，我们再次尝试获取端口号，如果成功，那么就listen成功。否则，我们重新将sk的状态设置为`TCP_CLOSE`并且返回错误。额外的，可以看注释说明的，这里其实有一个竞争窗口，如果有其他进程也在访问`get_port`会发生什么事？其实我们不用担心，因为在`get_port`当中调用了`spin_lock_bh`自旋锁，又或者其他协议的`get_port`有义务保证其自身的线程安全。

这里可以还引出一个疑问，即我们已经在`bind`中调用过`inet_csk_get_port`了，为什么这里还需要再使用一次`get_port`？原因其实很简单，linux中允许端口复用。假设我们设置允许端口复用，此时，另一个进程也以允许重用的方式`bind`了相同的端口，并且以更快的速度完成了`listen`。那么此时，这个端口就被完全占用直到其被释放。此时，尽管我们之前`bind`成功，我们也无法完成`listen`。具体的逻辑可以查看`inet_csk_bind_conflict`函数，它被定义在`net/ipv4/inet_connection_sock.c`中，由`inet_csk_get_port`调用。

假设我们成功完成了`get_port`，下一步我们将会将我们sk放入到TCP协议的全局hash表中。这里的hash表和bind中的不同，让我们看看`sk->sk_prot->hash`函数的定义（也就是`inet_hash`）和`bind`中使用的哈希表的区别。

```c
int inet_csk_listen_start(struct sock *sk, int backlog)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct inet_sock *inet = inet_sk(sk);
	int err = -EADDRINUSE;

	reqsk_queue_alloc(&icsk->icsk_accept_queue);

	sk->sk_max_ack_backlog = backlog;
	sk->sk_ack_backlog = 0;
	inet_csk_delack_init(sk);

	/* There is race window here: we announce ourselves listening,
	 * but this transition is still not validated by get_port().
	 * It is OK, because this socket enters to hash table only
	 * after validation is complete.
	 */
	inet_sk_state_store(sk, TCP_LISTEN);
	if (!sk->sk_prot->get_port(sk, inet->inet_num)) {
		inet->inet_sport = htons(inet->inet_num);

		sk_dst_reset(sk);
		err = sk->sk_prot->hash(sk);

		if (likely(!err))
			return 0;
	}

	inet_sk_set_state(sk, TCP_CLOSE);
	return err;
}
```

## inet_hash的实现

`inet_hash`的主要逻辑实现在`__inet_hash`当中。可以看见和bind中不同，bind中将数据放入到哈希表发生在`get_port`函数中，即`inet_csk_get_port`，将数据写入`bhash`。而`inet_hash`主要将数据写入`listening_hash`。更进一步地，进入到`inet_hash2`函数的实现中，另一部分的数据写入了`lhash2`哈希表中。

```c
static void inet_hash2(struct inet_hashinfo *h, struct sock *sk)
{
	struct inet_listen_hashbucket *ilb2;

	if (!h->lhash2)
		return;

	ilb2 = inet_lhash2_bucket_sk(h, sk);

	spin_lock(&ilb2->lock);
	if (sk->sk_reuseport && sk->sk_family == AF_INET6)
		hlist_add_tail_rcu(&inet_csk(sk)->icsk_listen_portaddr_node,
				   &ilb2->head);
	else
		hlist_add_head_rcu(&inet_csk(sk)->icsk_listen_portaddr_node,
				   &ilb2->head);
	ilb2->count++;
	spin_unlock(&ilb2->lock);
}

int __inet_hash(struct sock *sk, struct sock *osk)
{
	struct inet_hashinfo *hashinfo = sk->sk_prot->h.hashinfo;
	struct inet_listen_hashbucket *ilb;
	int err = 0;

	if (sk->sk_state != TCP_LISTEN) {
		inet_ehash_nolisten(sk, osk);
		return 0;
	}
	WARN_ON(!sk_unhashed(sk));
	ilb = &hashinfo->listening_hash[inet_sk_listen_hashfn(sk)];

	spin_lock(&ilb->lock);
	if (sk->sk_reuseport) {
		err = inet_reuseport_add_sock(sk, ilb);
		if (err)
			goto unlock;
	}
	if (IS_ENABLED(CONFIG_IPV6) && sk->sk_reuseport &&
		sk->sk_family == AF_INET6)
		hlist_add_tail_rcu(&sk->sk_node, &ilb->head);
	else
		hlist_add_head_rcu(&sk->sk_node, &ilb->head);
	inet_hash2(hashinfo, sk);
	ilb->count++;
	sock_set_flag(sk, SOCK_RCU_FREE);
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
unlock:
	spin_unlock(&ilb->lock);

	return err;
}
```

我们可以直接查看`struct inet_hashinfo`的定义。可以看见这个哈希表主要由三部分构成，分别是已经建立连接状态的socket的哈希表，已经bind的，和已经进入listen状态的。那么此时我们又要提出另外一个问题，为什么我们需要两个listening哈希表呢？

```c
struct inet_hashinfo {
	struct inet_ehash_bucket	*ehash;
	spinlock_t			*ehash_locks;
	unsigned int			ehash_mask;
	unsigned int			ehash_locks_mask;

	struct kmem_cache		*bind_bucket_cachep;
	struct inet_bind_hashbucket	*bhash;
	unsigned int			bhash_size;

	unsigned int			lhash2_mask;
	struct inet_listen_hashbucket	*lhash2;

	struct inet_listen_hashbucket	listening_hash[INET_LHTABLE_SIZE]
					____cacheline_aligned_in_smp;
};
```

这其实是有历史原因的，在过去，Linux的listening哈希表只使用端口号来做hash。如下面代码，如果没有配置`CONFIG_NET_NS`，即网络命名空间，哈希函数的结果就只取决于端口号。`inet_sk_listen_hashfn`在`__inet_hash`中被调用。在过去，这个行为就还好，无非是监听不同IP地址的相同端口时会出现哈希碰撞。但是在加入端口重用之后，哈希碰撞的问题变得严重，哈希表常常退化成一个链表。这样一来，为了性能引入了`lhash2`。同时，为了兼容性，保留了`listening_hash`。可以看见在第二版实现中，同时计算了地址和端口，加强了哈希随机性，使得哈希桶的占用情况更加均匀。

```c
// 第一版listening hashtable的哈希函数
static inline u32 net_hash_mix(const struct net *net)
{
#ifdef CONFIG_NET_NS
	return (u32)(((unsigned long)net) >> ilog2(sizeof(*net)));
#else
	return 0;
#endif
}

static inline u32 inet_lhashfn(const struct net *net, const unsigned short num)
{
	return (num + net_hash_mix(net)) & (INET_LHTABLE_SIZE - 1);
}

static inline int inet_sk_listen_hashfn(const struct sock *sk)
{
	return inet_lhashfn(sock_net(sk), inet_sk(sk)->inet_num);
}

// 第二版listening hashtable的哈希函数
static struct inet_listen_hashbucket *
inet_lhash2_bucket_sk(struct inet_hashinfo *h, struct sock *sk)
{
	u32 hash;

#if IS_ENABLED(CONFIG_IPV6)
	if (sk->sk_family == AF_INET6)
		hash = ipv6_portaddr_hash(sock_net(sk),
					  &sk->sk_v6_rcv_saddr,
					  inet_sk(sk)->inet_num);
	else
#endif
		hash = ipv4_portaddr_hash(sock_net(sk),
					  inet_sk(sk)->inet_rcv_saddr,
					  inet_sk(sk)->inet_num);
	return inet_lhash2_bucket(h, hash);
}
```

## listen系统调用小结

总的来说，`listen`的实现相当简单。首先还是通过`fd`来找到对应的socket。在拿到socket后，将其设置为`TCP_LISTEN`状态，尝试再次占用它的端口确保没有任何竞争状态发生，并且调用hash函数将其写入到listening hashtable当中。其中我们还涉及到了listening hashtable的一些历史遗留问题。如果尝试再次获取端口失败，则将socket重置为`TCP_CLOSE`状态，并且返回错误。


## 参考资料

设置somaxconn：()[https://access.redhat.com/documentation/zh-cn/red_hat_enterprise_linux/8/html/managing_monitoring_and_updating_the_kernel/configuring-kernel-parameters-permanently-with-sysctl_configuring-kernel-parameters-at-runtime]

lhash2的历史背景：()[https://segmentfault.com/a/1190000020536287]
