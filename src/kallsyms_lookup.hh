#pragma once

#include <map>

struct kallsyms_cache {
    kallsyms_cache();
    ~kallsyms_cache();
    operator bool() const { return !cache.empty(); }

    struct loc_result {
        const char *symbol;
        size_t offset;
    };

    std::pair<const char *, size_t> lookup_symbol(uint64_t key);

    // std::pair<const std::string &, size_t> lookup_symbol(void *pc)
    // {
    //     return lookup_symbol(reinterpret_cast<uint64_t>(pc));
    // }

    const std::map<uint64_t, std::string>::const_iterator begin() const { return cache.cbegin(); }
    const std::map<uint64_t, std::string>::const_iterator end() const { return cache.cend(); }

private:

    std::map<uint64_t, std::string> cache;
};
