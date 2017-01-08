#pragma once

#include <functional>

struct nl_sock;

struct drop_mon_t {
    drop_mon_t(const std::function<void(void *, size_t)> &callback);
    ~drop_mon_t();
    bool start();
    bool stop();
    int get_fd() const;

    bool try_rx() const;

private:
    bool send(int flags, uint8_t cmd);

    int family;
    struct nl_sock *sock;
    uint32_t seq;
    const std::function<void(void *, size_t)> callback;
};
