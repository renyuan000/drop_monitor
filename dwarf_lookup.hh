#pragma once

#include <memory>
#include <string>

struct dwarf_lookup {
    dwarf_lookup(const char *debuginfo_path = "/usr/lib/debug/lib/modules");
    ~dwarf_lookup();
    operator bool() const;

    std::pair<std::string, std::string> lookup(uint64_t addr);
private:
    struct dwarf_lookup_impl;
    std::unique_ptr<dwarf_lookup_impl> pimpl;
};
