#include <cstdlib>
#include <iostream>

#include "dwarf_lookup.hh"

int main(int argc, char *argv[])
{
    dwarf_lookup dwarf;
    if (!dwarf)
        return -1;
    auto comb = [](const auto &p) { return p.first + "/" + p.second; };
    if(argc > 1) {
        for(int i = 1; i < argc; i++)
            std::cout << comb(dwarf.lookup(std::strtoul(argv[i], NULL, 0))) << "\n";
        return 0;
    }
    std::cout << comb(dwarf.lookup(0xffffffffc092c460ul)) << "\n";
    std::cout << comb(dwarf.lookup(0xffffffffc092c534ul)) << "\n";
}
