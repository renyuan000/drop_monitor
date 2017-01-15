# drop_monitor

Utilizes netlink drop_monitor to view information about dropped SKBs.

# Example Output

```Shell
./udp_drops 
  #                  ip                         sym+off                        location
  2    0xffffffffc092c534            ieee80211_iface_work+212       net/mac80211/iface.c:1225
 20    0xffffffffc092c534            ieee80211_iface_work+212       net/mac80211/iface.c:1225
 21    0xffffffffc092c534            ieee80211_iface_work+212       net/mac80211/iface.c:1225
 17    0xffffffff84796148              unix_dgram_sendmsg+1176         net/unix/af_unix.c:1823
...
```

```Shell
$ drop_monitor 
  #                  ip                         sym+off                        location
  3    0xffffffff8470f9e1                fq_codel_dequeue+1601   include/net/sch_generic.h:580
  1    0xffffffffc092c534            ieee80211_iface_work+212       net/mac80211/iface.c:1225
 16    0xffffffff8470f9e1                fq_codel_dequeue+1601   include/net/sch_generic.h:580
  9    0xffffffffc092c534            ieee80211_iface_work+212       net/mac80211/iface.c:1225
  1    0xffffffff8470f6bb                fq_codel_dequeue+795   include/net/sch_generic.h:580
  6    0xffffffffc092c534            ieee80211_iface_work+212       net/mac80211/iface.c:1225
  8    0xffffffff8470f9e1                fq_codel_dequeue+1601   include/net/sch_generic.h:580
  1    0xffffffff8470f6bb                fq_codel_dequeue+795   include/net/sch_generic.h:580
  1    0xffffffff8470f6bb                fq_codel_dequeue+795   include/net/sch_generic.h:580
  1    0xffffffff8470f9e1                fq_codel_dequeue+1601   include/net/sch_generic.h:580
  1    0xffffffff847be0fa                      icmpv6_rcv+458             net/ipv6/icmp.c:894
 10    0xffffffffc092c534            ieee80211_iface_work+212       net/mac80211/iface.c:1225
 11    0xffffffffc092c534            ieee80211_iface_work+212       net/mac80211/iface.c:1225
  3    0xffffffffc092c534            ieee80211_iface_work+212       net/mac80211/iface.c:1225
  7    0xffffffffc092c534            ieee80211_iface_work+212       net/mac80211/iface.c:1225
  1    0xffffffff846cdaf7           sk_stream_kill_queues+87     include/linux/skbuff.h:1478
```

```Shell
$ kallsyms_dump
have 117863 + 1727 = 119590 symbols
0x0 irq_stack_union/__per_cpu_start
0x4000 exception_stacks
0x9000 gdt_page
0xa000 espfix_waddr
0xa008 espfix_stack
0xa020 cpu_llc_id
0xa028 cpu_llc_shared_map
0xa030 cpu_core_map
0xa038 cpu_sibling_map
0xa040 cpu_info
```

```Shell
$ kallsyms_dump  | grep ieee80211_iface_work -A 1 -B 1
have 117863 + 1727 = 119590 symbols
0xffffffffc092c440 ieee80211_recalc_smps_work
0xffffffffc092c460 ieee80211_iface_work
0xffffffffc092c870 ieee80211_netdev_select_queue
```

# Build instructions
```Shell
./bootstrap.sh
./configure && make
```
