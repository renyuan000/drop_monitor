#include "netlink_dropmon.hh"

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>

#include <linux/net_dropmon.h>

#include "common.hh"

//#ifdef TEST_DRIVER
#include <cassert>

drop_mon_t::drop_mon_t(const std::function<void(void *, size_t)> &callback)
    : callback(callback)
{
    // resolve family id
    sock = nl_socket_alloc();
    int err = genl_connect(sock);
    if (err < 0) {
        puts(nl_geterror(err));
        nl_socket_free(sock);
        sock = nullptr;
        return;
    }

    family = genl_ctrl_resolve(sock, "NET_DM");
    if (family < 0) {
        nl_close(sock);
        nl_socket_free(sock);
        sock = nullptr;
        puts(nl_geterror(family));
        return;
    }
    nl_close(sock);

    nl_join_groups(sock, NET_DM_GRP_ALERT);
    err = nl_connect(sock, NETLINK_GENERIC);
    if (err < 0) {
        puts(nl_geterror(err));
        nl_socket_free(sock);
        sock = nullptr;
        return;
    }
}

drop_mon_t::~drop_mon_t()
{
    if (sock) {
        nl_close(sock);
        nl_socket_free(sock);
    }
}

bool drop_mon_t::start()
{
    if (send(NLM_F_REQUEST | NLM_F_ACK, NET_DM_CMD_START)) {
        nl_socket_set_nonblocking(sock);
        return true;
    }
    return false;
}

bool drop_mon_t::stop()
{
    return send(NLM_F_REQUEST | NLM_F_ACK, NET_DM_CMD_STOP);
}

int drop_mon_t::get_fd() const { return sock ? nl_socket_get_fd(sock) : -1; }


const char *net_dm_string(uint8_t cmd)
{
    switch (cmd) {
    case NET_DM_CMD_UNSPEC: return "NET_DM_CMD_UNSPEC";
    case NET_DM_CMD_ALERT: return "NET_DM_CMD_ALERT";
    case NET_DM_CMD_CONFIG: return "NET_DM_CMD_CONFIG";
    case NET_DM_CMD_START: return "NET_DM_CMD_START";
    case NET_DM_CMD_STOP: return "NET_DM_CMD_STOP";
    case _NET_DM_CMD_MAX: return "_NET_DM_CMD_MAX";
    default: return "unknown";
    }
}

const char *nlmsg_type_string(uint16_t nlmsg_type)
{
    switch (nlmsg_type) {
    case NLMSG_NOOP: return "NLMSG_NOOP";
    case NLMSG_ERROR: return "NLMSG_ERROR";
    case NLMSG_DONE: return "NLMSG_DONE";
    case NLMSG_OVERRUN: return "NLMSG_OVERRUN";
    default: return "unknown";
    }
}

bool drop_mon_t::try_rx() const
{
    int len = 0;
    unsigned char *buf = nullptr;
    do {
        sockaddr_nl addr;
        int rc = nl_recv(sock, &addr, &buf, NULL);
        if (rc < 0) {
            if (errno == EINTR) {
                perror("nl_recv");
                continue;
            }
            else if (errno == EAGAIN) {
                //perror("nl_recv");
                break;
            }
            perror("nl_recv");
            free(buf);
            return false;
        }
        // printf("nl_recv: %d from pid %d\n", rc, addr.nl_pid);
        len += rc;
    } while (false);

    for (nlmsghdr *nlhdr = (nlmsghdr *)buf; nlmsg_ok(nlhdr, len); nlhdr = nlmsg_next(nlhdr, &len)) {

        // fprintf(stderr, "  type: %d/%s total=%d nlmsg_len=%u flags=0x%x ",
        //         nlhdr->nlmsg_type,
        //         nlmsg_type_string(nlhdr->nlmsg_type),
        //         len, nlhdr->nlmsg_len, nlhdr->nlmsg_flags);

        if (nlhdr->nlmsg_type == NLMSG_NOOP) {
            continue;
        } else if (nlhdr->nlmsg_type == NLMSG_ERROR) {
            if (nlhdr->nlmsg_len < NLMSG_LENGTH(sizeof(nlmsgerr))) {
                printf("INVALID LENGTH %u < %zu assumed err=%d\n",
                       nlhdr->nlmsg_len, NLMSG_LENGTH(sizeof(nlmsgerr)),
                       ((nlmsgerr *)(NLMSG_DATA(nlhdr)))->error);
                for (size_t i = 0; i < (unsigned)len; i++)
                    printf(" 0x%02x", ((unsigned char *)nlhdr)[i]);
                puts("");
            }
            else if (((nlmsgerr *)(NLMSG_DATA(nlhdr)))->error == 0)
                ; //fprintf(stderr, "ACK\n");
            else
                fprintf(stderr, "ERROR %d %s\n",
                        ((nlmsgerr *)(NLMSG_DATA(nlhdr)))->error,
                        strerror(-((nlmsgerr *)(NLMSG_DATA(nlhdr)))->error));
            continue;
        } else if (nlhdr->nlmsg_type == family) {
            auto glh = (genlmsghdr *)nlmsg_data(nlhdr);

            // printf("  genlmsghdr: type=%x/%s version=%x\n", glh->cmd,
            //        net_dm_string(glh->cmd), glh->version);

            if (glh->cmd == NET_DM_CMD_ALERT) {
                auto genl_hdr = (genlmsghdr *)nlmsg_data(nlhdr);
                auto nla_hdr = (nlattr *)genlmsg_data(genl_hdr);
                auto nla_payload = (net_dm_alert_msg *)nla_data(nla_hdr);
                auto entries = nla_payload->entries;
                // fprintf(stderr, "  net_dm_alert_msg:\n"
                //         "    nlmsghdr::nlmsg_len=%u / sizeof=%zu\n"
                //         "    genlmsghdr::len=%zu / sizeof=%zu\n"
                //         "    nlattr::(nla_len=%u, nla_type=%u) / sizeof=%zu\n"
                //         "    net_dm_alert_msg::entries=%u / sizeof=%zu\n"
                //         "    net_dm_drop_point sizeof=%zu\n",
                //         nlhdr->nlmsg_len, sizeof(*nlhdr),
                //         (char *)nla_hdr - (char *)genl_hdr, sizeof(genlmsghdr),
                //         nla_hdr->nla_len, nla_hdr->nla_type, sizeof(struct nlattr),
                //         nla_payload->entries, sizeof(net_dm_alert_msg),
                //         sizeof(net_dm_drop_point));
                assert(nla_hdr->nla_type == 0); // NLA_UNSPEC
                for (size_t i = 0; i < entries; i++) {
                    const auto &drop_point = ((net_dm_drop_point *)nla_payload->points)[i];
                    void *loc;
                    memcpy(&loc, drop_point.pc, sizeof loc);
                    // fprintf(stderr, "        drop_point -> 0x%p * %u\n", loc, drop_point.count);
                    callback(loc, drop_point.count);
                }

                // 16 + 4 + 4 + 4 + x * 12
                const auto nlmsg_len = sizeof(nlmsghdr) + sizeof(genlmsghdr)
                    + sizeof(nlattr) + sizeof(net_dm_alert_msg)
                    + nla_payload->entries * sizeof(net_dm_drop_point);
                if (nlhdr->nlmsg_len != nlmsg_len) {
                    // fprintf(stderr, "fixing up nlmsg_len %u -> %zu/%d\n",
                    //         nlhdr->nlmsg_len, nlmsg_len, len);
                    nlhdr->nlmsg_len = nlmsg_len;
                }
            }
            // fprintf(stderr, "  ... nlmsg_len=%u/%d -> ", nlhdr->nlmsg_len, len);
            //nlhdr = nlmsg_next(nlhdr, &len);
            // printf("%u/%d\n", nlhdr->nlmsg_len, len);
        } else {
            puts("IGNORED");
        }

    }
    // fprintf(stderr, "\n");

    free(buf);
    return true;
}

bool drop_mon_t::send(int flags, uint8_t cmd)
{
    auto buf = unique_ptr<nl_msg>(nlmsg_alloc(), nlmsg_free);
    if (!buf)
        return false;
    auto msg = genlmsg_put(buf.get(), NL_AUTO_PORT, seq, family, 0, flags, cmd, 1);
    if (!msg)
        return false;
    const auto err = nl_send(sock, buf.get());
    if (err < 0) {
        puts(nl_geterror(err));
        return false;
    }
    seq++;
    return true;
}
