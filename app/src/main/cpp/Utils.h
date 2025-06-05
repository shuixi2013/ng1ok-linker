//
// Created by MSI-PC on 2025/6/5.
//

#ifndef NG1OKLINKER_UTILS_H
#define NG1OKLINKER_UTILS_H

#include <stdlib.h>
#include "soinfo.h"
#include "elf.h"
#include <unistd.h>
#include <link.h>

#define PAGE_START(x) ((x) & PAGE_MASK)
#define PAGE_END(x) PAGE_START((x) + (PAGE_SIZE-1))
#define PAGE_OFFSET(x) ((x) & ~PAGE_MASK)
#define MAYBE_MAP_FLAG(x, from, to)  (((x) & (from)) ? (to) : 0)
#define PFLAGS_TO_PROT(x)            (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | \
                                      MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
                                      MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))

constexpr off64_t kPageMask = ~static_cast<off64_t>(PAGE_SIZE-1);

class soinfo;

struct Module {
    ElfW(Addr) base;
    size_t size;
};

class Utils {
public:
    static size_t page_offset(off64_t offset) ;

    static off64_t page_start(off64_t offset) ;

    static bool safe_add(off64_t* out, off64_t a, size_t b);

    static void* getMapData(int fd, off64_t base_offset, size_t elf_offset, size_t size);

    static void phdr_table_get_dynamic_section(const ElfW(Phdr)* phdr_table, size_t phdr_count,
            ElfW(Addr) load_bias, ElfW(Dyn)** dynamic,
    ElfW(Word)* dynamic_flags) ;

    static soinfo* get_soinfo(const char* so_name);


    static ElfW(Addr) call_ifunc_resolver(ElfW(Addr) resolver_addr);

    static ElfW(Addr) get_addend(ElfW(Rela)* rela, ElfW(Addr) reloc_addr __unused);

    static ElfW(Addr) get_export_func(char* path, char* func_name);

    static int phdr_table_set_gnu_relro_prot(const ElfW(Phdr)* phdr_table, size_t phdr_count,
            ElfW(Addr) load_bias, int prot_flags);

    static void load_modules();
};

#endif //NG1OKLINKER_UTILS_H