//
// Created by MSI-PC on 2025/6/5.
//

#include "soinfo.h"
#include "Utils.h"

ElfW(Addr) soinfo::resolve_symbol_address(const ElfW(Sym)* s) const {
    if (ELF_ST_TYPE(s->st_info) == STT_GNU_IFUNC) {
        return Utils::call_ifunc_resolver(s->st_value + load_bias);
    }
    return static_cast<ElfW(Addr)>(s->st_value + load_bias);
}

bool soinfo::is_gnu_hash() {
    return (flags_ & FLAG_GNU_HASH) != 0;
}