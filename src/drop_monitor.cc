
#include <csignal>
#include <future>
#include <poll.h>

#include "common.hh"
#include "dwarf_lookup.hh"
#include "kallsyms_lookup.hh"
#include "netlink_dropmon.hh"

volatile bool sigint;
void sighandler(int)
{
    sigint = true;
}

struct receiver_ctx {
    receiver_ctx()
    {
        dwarf_ok = dwarf;
        if (!dwarf_ok)
            fprintf(stderr, "dwarf_lookup disabled\n");
    }

    void rx_callback(void *loc, size_t count)
    {
        const auto loc64 = reinterpret_cast<uint64_t>(loc);
        const auto kallsym = kcache ? kcache->lookup_symbol(loc64) : std::make_pair(nullptr, 0);

        auto dwarf_sym_it = dwarf_cache.find(loc64);
        if (dwarf_sym_it == std::end(dwarf_cache)) {
            auto sym = dwarf.lookup(loc64);
            if (sym.second.empty()) {
                dwarf_ok = false;
            } else {
                const auto insert = dwarf_cache.insert(std::make_pair(loc64, std::move(sym)));
                if (!insert.second)
                    dwarf_sym_it == std::end(dwarf_cache);
                else
                    dwarf_sym_it = insert.first;
            }
        }

        if (!kallsym.first)
            printf("%*zu  %*p%*s", 3, count, 20, loc, 32,
                   dwarf_sym_it == std::end(dwarf_cache) ||
                   dwarf_sym_it->second.second.empty() ? "n/a" :
                   dwarf_sym_it->second.second.c_str());
        else
            printf("%*zu  %*p%*s+%zu", 3, count, 20, loc,
                   32, kallsym.first, kallsym.second);

        if (dwarf_sym_it == std::end(dwarf_cache))
            printf("%*s", 32, "n/a");
        else
            printf("%*s", 32, dwarf_sym_it->second.first.c_str());
        printf("\n");
    }

    std::map<uint64_t, std::pair<std::string, std::string> > dwarf_cache;
    dwarf_lookup dwarf;
    std::unique_ptr<kallsyms_cache> kcache;
    bool dwarf_ok = dwarf;
};

int main()
{
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = sighandler;
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGINT, &sa, NULL) == -1)
        perror("sigaction");

    auto kcache_future = std::async(std::launch::async, []() { return make_unique<kallsyms_cache>(); });
    receiver_ctx rx_ctx;

    drop_mon_t dropmon(std::bind(&receiver_ctx::rx_callback, &rx_ctx, std::placeholders::_1, std::placeholders::_2));
    if (dropmon.get_fd() == -1)
        return -1;
    if (!dropmon.start())
        return -1;
    pollfd pfd[1];
    pfd[0].events = POLLIN;
    pfd[0].fd = dropmon.get_fd();
    printf("%*s%*s%*s%*s\n", 3, "#", 20, "ip", 32, "sym+off", 32, "location");
    while (!sigint) {
        const auto mux = poll(pfd, 1, 250);
        if (mux == 0) {
            continue;
        } else if (mux == -1) {
            if (errno == EINTR)
                continue;
            perror("poll");
            break;
        }

        if (!rx_ctx.kcache && kcache_future.valid()
            && kcache_future.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready) {
            rx_ctx.kcache = std::move(kcache_future.get());
            if ((!rx_ctx.kcache || !*rx_ctx.kcache) && !rx_ctx.dwarf) {
                fprintf(stderr, "kallsyms and dwarf lookup not available. Terminating.");
                break;
            }
        }

        if (!dropmon.try_rx())
            sigint = true;
    }

    dropmon.stop();
}
