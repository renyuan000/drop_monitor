#include "kallsyms_lookup.hh"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <cassert>
#include <cstring>
#include <functional>
#include <vector>

int readall(int fd, void *buff, size_t len)
{
    size_t nread = 0;

    do {
        int n = read(fd, &((char *)buff)[nread], len-nread);
        if (n == -1) {
            if (errno == EINTR)
                continue;
            else
                return -1;
        }
        if (n == 0)
            return nread;
        nread += n;
    } while (nread < len);

    return nread;
}

template<typename lambda_t>
bool foreach_blob(const char *filename, size_t blobsize, lambda_t lambda)
{
    int fd = open(filename, O_RDONLY, NULL);
    if (fd == -1) {
        perror("open");
        return false;
    }

    std::vector<char> buf(blobsize, 0);
    int ret;
    do {
        ret = readall(fd, &buf[0], buf.size());
        if (!lambda(buf, ret))
            break;
    } while (ret > 0);

    close(fd);

    return true;
}


kallsyms_cache::kallsyms_cache()
{
    std::vector<char> old;
    size_t dbg_dup = 0;
    size_t line = 0;
    auto lambda = [this, &old, &line, &dbg_dup](const std::vector<char> &buf, size_t fill) {
        const char *data = buf.data();
        size_t size = fill;
        if (!old.empty()) {
            old.insert(std::end(old), std::begin(buf), std::begin(buf) + fill);
            data = old.data();
            size = old.size();
        }
        for (const char *nl = static_cast<const char *>(memchr(data, '\n', size));
            nl != nullptr; nl = static_cast<const char *>(memchr(data, '\n', size))) {

            const size_t line_length = reinterpret_cast<uintptr_t>(nl) - reinterpret_cast<uintptr_t>(data);
            auto get_sym = [](const char *line, size_t len) {
                uint64_t addr = 0;
                std::string symbol(1024, '\0');
                const char *fmt = line[len - 1] == ']'
                ? "%llx %*c %s\t[%*[^]]\n"
                : "%llx %*c %s\n";
                if (std::sscanf(line, fmt, &addr, &symbol[0]) != 2)
                    return std::make_pair(uint64_t(0), std::string());
                return std::make_pair(addr, std::move(symbol)); };

            auto sym_data = get_sym(data, line_length);
            if (sym_data.second.empty()) {
                fprintf(stderr, "%zu: ERR \"%s\"\n", line, std::string(data, line_length).c_str());
                cache.clear();
                return false;
            }

            auto insert = cache.insert(std::make_pair(sym_data.first, std::move(sym_data.second)));
            if (!insert.second) {
                // Symbol was moved, get again. Avoid copy in general(no duplicate) case.
                sym_data = get_sym(data, line_length);
                // printf("%zu: dup(\"%s\")\n", line, sym_data.second.c_str());
                if(line >= 10 && cache.size() <= 1 && sym_data.first == 0) {
                    fprintf(stderr, "reading /proc/kallsyms failed. kptr_restrict=1? Try again with root privileges\n");
                    cache.clear();
                    return false;
                }
                dbg_dup++;
                auto &old_sym = insert.first->second;
                old_sym.replace(old_sym.find('\0'), 1, 1, '/');
                old_sym.replace(old_sym.find('\0'), sym_data.second.find('\0'), sym_data.second);
                // printf("%zu: OK: %lx \"%s\" mod=%d\n", line, sym_data.first, old_sym.c_str(),
                //        nl[line_length - 1] == ']' ? 1 : 0);
            } else {
                // printf("%zu: OK: %lx \"%s\" mod=%d\n", line, sym_data.first, insert.first->second.c_str(),
                //        nl[line_length - 1] == ']' ? 1 : 0);
            }
            ++line;
            assert(size >= (line_length + 1));
            size -= line_length + 1;
            data += line_length + 1;
        }
        old.clear();
        if (size)
            old.insert(std::begin(old), data, data + size);
        return true;
    };
    if (!foreach_blob("/proc/kallsyms", 32 * 1024, lambda))
        return;

    //fprintf(stderr, "have %zu + %zu = %zu symbols\n", cache.size(), dbg_dup, cache.size() + dbg_dup);
}

kallsyms_cache::~kallsyms_cache() {}

static const std::string EMPTY_STRING;
std::pair<const char *, size_t> kallsyms_cache::lookup_symbol(uint64_t key)
{
    auto it = cache.lower_bound(key);
    if (it == std::end(cache)) {
        assert(cache.size() == 1 || cache.empty());
        if (cache.empty())
            return std::make_pair(nullptr, 0);
        it = std::begin(cache);
    } else {
        if (it->first == key)
            return std::make_pair(it->second.c_str(), 0);
        if (it == std::begin(cache))
            return std::make_pair(nullptr, 0);
    }
    --it;
    assert(it->first < key);
    return std::make_pair(it->second.c_str(), key - it->first);
}

#ifdef TEST_DRIVER
#include <climits>
#include <future>
#include <iostream>
#include "common.hh"

int main(int argc, char *argv[])
{
    auto kcache_future = std::async(std::launch::async, []() { return make_unique<kallsyms_cache>(); });
    while (kcache_future.wait_for(std::chrono::milliseconds(50)) == std::future_status::timeout) {
        fprintf(stderr, ".");
        //fflush(stderr);
    }
    auto kcache = kcache_future.get();
    if (!kcache || !*kcache)
        return -1;

    // first
    {
        const auto r = kcache->lookup_symbol(0x0ull);
        assert(std::strcmp(r.first.c_str(), "irq_stack_union/__per_cpu_start") == 0);
        assert(r.second == 0);
    }

    {
        const auto r = kcache->lookup_symbol(0x0ull + 0x3999);
        assert(std::strcmp(r.first.c_str(), "irq_stack_union/__per_cpu_start") == 0);
        assert(r.second == 0x3999);
    }

    {
        const auto r = kcache->lookup_symbol(0x0ull + 0x4000);
        assert(std::strcmp(r.first.c_str(), "exception_stacks") == 0);
        assert(r.second == 0);
    }

    {
        const auto r = kcache->lookup_symbol(0x000000000000a038ull);
        assert(std::strcmp(r.first.c_str(), "cpu_sibling_map") == 0);
        assert(r.second == 0);
    }

    // last
    {
        const auto r = kcache->lookup_symbol(0xffffffffc0095190);
        assert(std::strcmp(r.first.c_str(), "fjes_hw_epbuf_tx_pkt_send") == 0);
        assert(r.second == 0);
    }

    {
        const auto r = kcache->lookup_symbol(0xffffffffc0095190 + 0x13);
        printf("%s %zu\n", r.first.c_str(), r.second);
        assert(std::strcmp(r.first.c_str(), "fjes_hw_epbuf_tx_pkt_send") == 0);
        assert(r.second == 0x13);
    }

    for (int i = 1; i < argc; i++) {
        const auto addr = std::strtoul(argv[i], nullptr, 0);
        const auto r = kcache->lookup_symbol(addr);
        printf("%s: %s+0x%lx\n", argv[i], r.first.c_str(), r.second);
    }
}
#endif
