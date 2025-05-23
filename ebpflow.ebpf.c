int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    eBPFevent event = { .etype = eTCP_SEND, .ip_version = 4 };
    if (fill_event(ctx, &event, sk, NULL, 0, IPPROTO_TCP, 0) == 0) {
        event.len = size;  // Set packet length from size parameter
        event.etype = eTCP_SEND;
        ebpf_events.perf_submit(ctx, &event, sizeof(eBPFevent));
    }
    return 0;
}

int trace_tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied) {
    if (copied <= 0) return 0;
    eBPFevent event = { .etype = eTCP_RECV, .ip_version = 4 };
    if (fill_event(ctx, &event, sk, NULL, 0, IPPROTO_TCP, 1) == 0) {
        event.len = copied;  // Set packet length from copied parameter
        event.etype = eTCP_RECV;
        ebpf_events.perf_submit(ctx, &event, sizeof(eBPFevent));
    }
    return 0;
}

int trace_tcp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len, int nonblock, int flags, int *addr_len) {
    if (len <= 0) return 0;
    eBPFevent event = { .etype = eTCP_RECV, .ip_version = 4 };
    if (fill_event(ctx, &event, sk, NULL, 0, IPPROTO_TCP, 1) == 0) {
        event.len = len;  // Set packet length from len parameter
        event.etype = eTCP_RECV;
        ebpf_events.perf_submit(ctx, &event, sizeof(eBPFevent));
    }
    return 0;
}

static int fill_event(struct pt_regs *ctx, eBPFevent *ev,
          struct sock *sk,
          void *msg,
          u64 begin_ts,
          u8 proto, u8 swap_peers) {
  
  u16 family;
  u64 delta;
  u32 pid    = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  u32 saddr  = 0, daddr = 0;
  ktime_t kt = { bpf_ktime_get_ns() };
  u32 len = 0;

  ev->sent_packet = (swap_peers == 0) ? 1 : 0;

  // Get packet length from sk_buff
  struct sk_buff *skb;
  if(ev->sent_packet) {
    // For outgoing packets, check write queue
    bpf_probe_read(&skb, sizeof(skb), &sk->sk_write_queue.next);
  } else {
    // For incoming packets, check receive queue
    bpf_probe_read(&skb, sizeof(skb), &sk->sk_receive_queue.next);
  }
  
  if(skb) {
    bpf_probe_read(&len, sizeof(len), &skb->len);
    ev->len = len;
  }

  bpf_probe_read(&family, sizeof(family), &sk->__sk_common.skc_family);
  if((family != AF_INET) && (family != AF_INET6)) return(-1);

  bpf_probe_read(&sport, sizeof(u16), &sk->__sk_common.skc_num);
  bpf_probe_read(&dport, sizeof(u16), &sk->__sk_common.skc_dport);

  if(msg) {
    struct sockaddr_in usin;

    bpf_probe_read(&usin, sizeof(usin), msg);
    family = usin.sin_family;

    if(usin.sin_family == AF_INET) {
      daddr = usin.sin_addr.s_addr;
      dport = usin.sin_port;
    }
  }

  if(begin_ts > 0) {
    delta = bpf_ktime_get_ns() - begin_ts;
    delta /= 1000;
  } else
    delta = 0;

  dport = ntohs(dport); /* This has to be done all the time */

  if((sport == 0) && (dport == 0))
    return(-1);

  ev->proc.pid = pid;

  if(family == AF_INET) {
    ev->ip_version = 4;

    if(saddr == 0)
      bpf_probe_read(&ev->addr.v4.saddr, sizeof(u32), &sk->__sk_common.skc_rcv_saddr);
    else
      ev->addr.v4.saddr = saddr;

    if(daddr == 0)
      bpf_probe_read(&ev->addr.v4.daddr, sizeof(u32), &sk->__sk_common.skc_daddr);
    else
      ev->addr.v4.daddr = daddr;
  } else /* (family == AF_INET6)  */ {
    ev->ip_version = 6;

    bpf_probe_read(&ev->addr.v6.saddr, sizeof(ev->addr.v6.saddr),
       sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    bpf_probe_read(&ev->addr.v6.daddr, sizeof(ev->addr.v6.daddr), sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

    if(/* Implement in a better way */
       (((ev->addr.v6.saddr) & 0xFFFFFFFF) == 0)
       && (((ev->addr.v6.saddr >> 32) & 0xFFFFFFFF) == 0)
       ) {
      ev->ip_version = 4;
      ev->proc.pid = pid;
      ev->addr.v4.saddr = ev->addr.v6.saddr >> 96;
      ev->sport = sport;
      ev->addr.v4.daddr = ev->addr.v6.daddr >> 96;
    }
  }

  ev->dport = dport;
  ev->sport = sport;
  ev->latency_usec = delta;
  ev->proto = proto;
  bpf_get_current_comm(&ev->proc.task, sizeof(ev->proc.task));
  ev->proc.pid = pid;

  fill_task_info((char*)ev->container_id, &ev->proc, &ev->father);

  if(swap_peers) swap_event_peers(ev);

  fill_ifname(ev, sk);

  ev->ktime = kt;
  return(0);
} 