#include "kallsyms_lookup.hh"

#include <climits>
#include <cstdio>
#include <cstring>
#include "common.hh"

void usage(const char *comm)
{
    fprintf(stderr, "USAGE:\n"
            "lookup addresses given as arguments:\n  %s [addr]...\n"
            "print kallsyms in sorted order:\n  %s\n", comm, comm);
}

int main(int argc, char *argv[])
{
    if (argc == 2 &&
       (std::strcmp("-h", argv[1]) == 0 ||
        std::strcmp("--help", argv[1]) == 0)) {
        usage(argv[0]);
        return 0;
    }

    kallsyms_cache kcache;
    if (!kcache)
        return -1;

    for (int i = 1; i < argc; i++) {
        errno = 0;
        const auto addr = std::strtoul(argv[i], nullptr, 0);
        if ((addr == 0 && errno) || addr == ULONG_MAX) {
            perror("strtoul");
            usage(argv[0]);
            return -1;
        }
        const auto r = kcache.lookup_symbol(addr);
        printf("%s: %s+0x%lx\n", argv[i], r.first, r.second);
    }
    if (argc != 1)
        return 0;

    for (const auto cel: kcache)
        printf("0x%lx %s\n", cel.first, cel.second.c_str());

}
