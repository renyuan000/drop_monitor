#include "dwarf_lookup.hh"

#include <dwarf.h>
#include <elfutils/libdwfl.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "common.hh"

struct dwarf_lookup::dwarf_lookup_impl {
    dwarf_lookup_impl(const char *debuginfo_path_)
        : debuginfo_path(strdup(debuginfo_path_ ? debuginfo_path_ :"/usr/lib/debug/lib/modules"))
    {
        memset(&callbacks, 0, sizeof(callbacks));
        callbacks.find_debuginfo = dwfl_standard_find_debuginfo;
        callbacks.debuginfo_path = const_cast<char **>(&debuginfo_path);
        callbacks.section_address = dwfl_linux_kernel_module_section_address;
        callbacks.find_elf = dwfl_linux_kernel_find_elf;

        dwfl = dwfl_begin(&callbacks);
        if (!dwfl) {
            fprintf(stderr, "dwfl_begin FAILED\n");
            return;
        }

        if (dwfl_linux_kernel_report_kernel(dwfl) != 0) {
            fprintf(stderr, "dwfl_linux_kernel_report_kernel FAILED\n");
            dwfl_end(dwfl);
            dwfl = nullptr;
            return;
        }

        if (dwfl_linux_kernel_report_modules(dwfl) != 0)
            fprintf(stderr, "dwfl_linux_kernel_report_modules FAILED\n");
    }

    ~dwarf_lookup_impl()
    {
        free((void *)debuginfo_path);
        if (dwfl)
            dwfl_end(dwfl);
    }

    operator bool() const { return dwfl != nullptr; }

    std::pair<std::string, std::string> lookup(uint64_t addr)
    {
        Dwfl_Module *mod = dwfl_addrmodule(dwfl, addr);
        if (!mod) {
            fprintf(stderr, "dwfl_addrmodule FAILED\n");
            return std::make_pair(std::string(), std::string());
        }

        auto func = parse_scopes(mod, addr);
        if (!func.second.empty())
            return std::move(func);
        const char *sym = dwfl_module_addrname(mod, addr);
        if (!sym) {
            fprintf(stderr, "dwfl_module_addrname FAILED\n");
            return std::make_pair(std::string(), std::string());
        }
        return std::make_pair(std::string(), sym);
    }

private:
    static std::pair<std::string, std::string> parse_scopes(Dwfl_Module *mod, uint64_t addr)
    {
        Dwarf_Addr bias = 0;
        Dwarf_Die *cudie = dwfl_module_addrdie(mod, addr, &bias);
        Dwarf_Die *scopes;
        int nscopes = dwarf_getscopes(cudie, addr - bias, &scopes);
        if (nscopes <= 0) {
            fprintf(stderr, "dwarf_getscopes FAILED %d\n", nscopes);

            // int nscopes_die = dwarf_getscopes_die(cudie, &scopes);
            // fprintf(stderr, "dwarf_getscopes_die -> %d\n", nscopes_die);

            return std::make_pair(std::string(), std::string());
        }

        Dwfl_Line *line = dwfl_module_getsrc(mod, addr);
        if (!line) {
            fprintf(stderr, "dwfl_module_getsrc FAILED\n");
            return std::make_pair(std::string(), std::string());
        }

        std::string cu_result;
        cu_result.reserve(512);
        int lineno;
        int linecol;
        const char *src_file = dwfl_lineinfo(line, &addr, &lineno, &linecol, nullptr, nullptr);
        if (src_file) {
            cu_result.assign(src_file);
            cu_result.append(":");
            cu_result.append(std::to_string(lineno));
            if (linecol) {
                cu_result.append(":");
                cu_result.append(std::to_string(linecol));
            }
        }

        std::string func_result;
        func_result.reserve(512);
        for (int i = nscopes - 1; i >= 0; i--) {
            switch (dwarf_tag(&scopes[i])) {
            case DW_TAG_subprogram:
            case DW_TAG_inlined_subroutine: {
                const char *name = dwarf_diename(&scopes[i]);
                name = name ? name : "??";
                func_result.append(name);
                break;
            }
            case DW_TAG_compile_unit: {
                if (!cu_result.empty()) {
                    // got compilation unit already from lineinfo lookup
                    // fprintf(stderr, "ignoring CU-tag\n");
                    break;
                }
                const char *name = dwarf_diename(&scopes[i]);
                if (!name)
                    break;
                cu_result.assign(name);
                cu_result.append(":");
                cu_result.append(std::to_string(lineno));
                if (linecol) {
                    cu_result.append(":");
                    cu_result.append(std::to_string(linecol));
                }
                break;
            }
        }
        }
        free(scopes);

        return std::make_pair(std::move(cu_result), std::move(func_result));
    }
    const char *debuginfo_path;
    Dwfl_Callbacks callbacks;
    Dwfl *dwfl;
};

dwarf_lookup::dwarf_lookup(const char *debuginfo_path)
    : pimpl(make_unique<dwarf_lookup_impl>(debuginfo_path))
{}

dwarf_lookup::~dwarf_lookup() {}
dwarf_lookup::operator bool() const { return *pimpl; }

std::pair<std::string, std::string> dwarf_lookup::lookup(uint64_t addr)
{
    return pimpl->lookup(addr);
}
