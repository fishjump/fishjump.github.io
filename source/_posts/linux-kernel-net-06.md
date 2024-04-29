---
title: 从内核出发手撕Linux网络协议栈(六)
---

（从外地回来赶上周天调休，鸽了一周）
我自己又反复读了一下我的内容，感觉直接贴出长篇的代码有点不利于理解，这次尝试代码分段讲解。有兴趣的朋友也可以自己去网上找到完整的源码，以便查证我贴出来的内容是不是在断章取义。

## Accept系统调用

这次让我们来学习accept系统调用，这个系统调用的形式如下，sockfd即服务器的socket，而参数struct sockaddr *addr与socklen_t *addrlen是对应类型的指针，用于获取客户端的IP。额外的，accept4是拥有四个参数的accept，第四个参数flags有两个可能的选项（可以使用按位或，即`|`，来进行多选），如果flags为0，那么表现和accept一样。

1. SOCK_NONBLOCK：它很好理解，即客户端的socket（即accept的返回值）将被设置为非阻塞模式，如果没有连接请求到达，那么它会立即返回错误`EAGAIN`。
2. SOCK_CLOEXEC：这个flag代表close-on-exec，那么我们创建的客户端socket将会自动在成功调用fork或者exec系列函数的时候被关闭。这样做可以防止文件描述符（fd）被意外泄漏给子线程/进程，从而导致数据竞争或者其他问题。

accept逻辑上用于服务器接收客户端发送来的数据。实质上，这个函数并没有从“客户端”接收数据，而是从网卡驱动给定的缓冲区读取数据。现在让我们来具体了解一下这个函数。

```c
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
```

## __sys_accept4的实现

利用之前几篇文章所讲到的方法，我们已经可以快速定位到accept系统调用的实现是__sys_accept4函数。其主流程非常清晰。首先，我们还是尝试从fd获取到对应的socket。

```c
sock = sockfd_lookup_light(fd, &err, &fput_needed);
if (!sock)
	goto out;
```

然后我们会创建一个新的socket，即客户端的socket连接，并且复制客户端的类型（socket连接类型，例如TCP是SOCK_STREAM）和操作（即SOCK_STREAM类型协议会用到的函数指针的集合）。

```c
newsock = sock_alloc();
if (!newsock)
	goto out_put;

newsock->type = sock->type;
newsock->ops = sock->ops; 
```

接下来，类似于socket系统调用中我们创建新的服务器socket，这里我们也要为客户端socket分配fd和创建file对象。

```c
newfd = get_unused_fd_flags(flags);
if (unlikely(newfd < 0)) {
	err = newfd;
	sock_release(newsock);
	goto out_put;
}
newfile = sock_alloc_file(newsock, flags, sock->sk->sk_prot_creator->name);
if (IS_ERR(newfile)) {
	err = PTR_ERR(newfile);
	put_unused_fd(newfd);
	goto out_put;
}
```

随后，我们会调用sock->ops->accept来接受数据，也就是之前提到过很多次的inetsw_array中TCP所对应的元素的ops，在这里是inet_accept。sock即我们的服务器socket，newsock是我们的客户端socket，f_flags即我们之前的flags，在函数调用sock_alloc_file中赋值给了file。感兴趣的读者可以自行一层一层翻下去，还是很好找到这一行的。

```c
err = sock->ops->accept(sock, newsock, sock->file->f_flags, false);
if (err < 0)
	goto out_fd;
```

最后，内核会检测用户传入的socket地址是否合法（不为NULL），如果不为NULL的话，那么就把内核态的客户端地址信息拷贝到用户空间。当然从代码可以看出，用户如果选择了传入NULL也没事，这并不会导致返回错误，仅代表用户不关心这个数据。结尾处，我们同样如同第一章介绍socket_create时那样，将fd和file关联起来，并且返回fd的值。至此accept的主流程就完成了。

```c
if (upeer_sockaddr) {
	len = newsock->ops->getname(newsock,
				(struct sockaddr *)&address, 2);
	if (len < 0) {
		err = -ECONNABORTED;
		goto out_fd;
	}
	err = move_addr_to_user(&address,
				len, upeer_sockaddr, upeer_addrlen);
	if (err < 0)
		goto out_fd;
}

/* File flags are not inherited via accept() unlike another OSes. */

fd_install(newfd, newfile);
err = newfd;
```

## inet_accept的实现（sock->ops->accept）

上面走完了__sys_accept的主流程，现在让我们来它的实现。函数一开始创建了两个sock，sk1从sock得到，而sk2则是调用tcp协议的accept获取。我们同样可以从inetsw_array中找到，这个函数为inet_csk_accept，我们等会介绍。

```c
int inet_accept(struct socket *sock, struct socket *newsock, int flags,
		bool kern)
{
	struct sock *sk1 = sock->sk;
	int err = -EINVAL;
	struct sock *sk2 = sk1->sk_prot->accept(sk1, flags, &err, kern);
	// 剩余代码 ...
```

接下来的代码就是给sk2加锁，并且将sk2赋值给newsock->sk，这一步在sock_graft中实现。然后将newsock的状态设置为CONNECTED。

```c
if (!sk2)
	goto do_err;

lock_sock(sk2);

sock_rps_record_flow(sk2);
WARN_ON(!((1 << sk2->sk_state) &
	  (TCPF_ESTABLISHED | TCPF_SYN_RECV |
	  TCPF_CLOSE_WAIT | TCPF_CLOSE)));

sock_graft(sk2, newsock);

newsock->state = SS_CONNECTED;
err = 0;
release_sock(sk2);
```

我们可以来看看sock_graft的实现，除去加锁之外，主要就是将socket和sock联系起来。

```c
static inline void sock_graft(struct sock *sk, struct socket *parent)
{
	WARN_ON(parent->sk);
	write_lock_bh(&sk->sk_callback_lock);
	rcu_assign_pointer(sk->sk_wq, parent->wq);
	parent->sk = sk;
	sk_set_socket(sk, parent);
	sk->sk_uid = SOCK_INODE(parent)->i_uid;
	security_sock_graft(sk, parent);
	write_unlock_bh(&sk->sk_callback_lock);
}
```

## inet_csk_accept的实现（sk1->sk_prot->accept）

除去开头的变量创建之外，首先我们是加锁并且判断sk当前的状态时LISTEN，这一步是为了防止连接在其他线程被断掉。

```c
lock_sock(sk);

/* We need to make sure that this socket is listening,
 * and that it has something pending.
 */
error = -EINVAL;
if (sk->sk_state != TCP_LISTEN)
	goto out_err;
```

下一步，我们需要从等待连接队列中取出sock并建立连接，并且将其赋值给newsk。其中reqsk_queue_empty判断等待队列是否为空。若为空则在inet_csk_wait_for_connect函数中进行等待，其中timeo为timeout的缩写。

```c
if (reqsk_queue_empty(queue)) {
	long timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);

	/* If this is a non blocking socket don't sleep */
	error = -EAGAIN;
	if (!timeo)
		goto out_err;

	error = inet_csk_wait_for_connect(sk, timeo);
	if (error)
		goto out_err;
}
req = reqsk_queue_remove(queue, sk);
newsk = req->sk;
```

到此，inet_csk_accept的主流程就已经完毕。下一步让我们看看inet_csk_wait_for_connect的实现。

## inet_csk_wait_for_connect的实现

inet_csk_wait_for_connect的实现相当直观，其中比较tricky的部分是schedule函数，这部分逻辑涉及到任务调度方面的源码，我们可以暂且跳过。它的大概功能是，schedule使得当前线程休眠直到某个调度点到来。这个调度点是由唤醒函数决定的，它被定义在DEFINE_WAIT宏中，在这里是autoremove_wake_function。通常来说，当驱动程序完成了一个I/O操作时，就会调用唤醒函数来唤醒正在等待的进程。

当我们从schedule_timeout返回时，检测等待队列中是否有需要连接的客户端请求。如果有，整个流程结束并且使用finish_wait从等待队列中删除当前进程上下文。如果没有，那么考虑如果sock当前状态不为TCP_LISTEN或者timeo为0，即已经超时。这时候设置对应的错误码并且结束等待并返回。

```c
static int inet_csk_wait_for_connect(struct sock *sk, long timeo)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	DEFINE_WAIT(wait);
	int err;
	for (;;) {
		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);
		release_sock(sk);
		if (reqsk_queue_empty(&icsk->icsk_accept_queue))
			timeo = schedule_timeout(timeo);
		sched_annotate_sleep();
		lock_sock(sk);
		err = 0;
		if (!reqsk_queue_empty(&icsk->icsk_accept_queue))
			break;
		err = -EINVAL;
		if (sk->sk_state != TCP_LISTEN)
			break;
		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			break;
		err = -EAGAIN;
		if (!timeo)
			break;
	}
	finish_wait(sk_sleep(sk), &wait);
	return err;
}
```

## 小结

到此为止整个accept的流程已经走完。总的来说它简单的创建了一个新的客户端socket并且等待更底层的代码将可以连接的程序放入icsk_accept_queue这个队列中。到此为止读者肯定也不太满足，这部分放入队列的逻辑肯定也是大家最关心的逻辑。我计划将会在介绍完connect之后深入更底层的内容。
