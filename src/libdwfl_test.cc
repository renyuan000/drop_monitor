#include <iostream>

#include "dwarf_lookup.hh"

int main()
{
    dwarf_lookup dwarf;
    if (!dwarf)
        return -1;
    auto comb = [](const auto &p) { return p.first + p.second; };
    std::cout << comb(dwarf.lookup(0xffffffffc092c460ul)) << "\n";
    std::cout << comb(dwarf.lookup(0xffffffffc092c534ul)) << "\n";
}
