//
// Created by user on 2024/6/15.
//
#include "MyLoader.h"
#include <string>
#include <unordered_map>
#include "gnu_helper.h"
#include "Utils.h"

int myneed[20];
uint32_t needed_count = 0;
std::unordered_map<std::string, Module> g_modules;


const char* get_realpath() {
    return "";
}


const char* soinfo::get_realpath() const {
    return "";
}

const char* soinfo::get_string(ElfW(Word) index) const {
    return strtab_ + index;
}

void soinfo::set_dt_flags_1(uint32_t dt_flags_1) {
    if (has_min_version(1)) {
        if ((dt_flags_1 & DF_1_GLOBAL) != 0) {
            rtld_flags_ |= RTLD_GLOBAL;
        }

        if ((dt_flags_1 & DF_1_NODELETE) != 0) {
            rtld_flags_ |= RTLD_NODELETE;
        }

        dt_flags_1_ = dt_flags_1;
    }
}


bool soinfo::prelink_image() {
    /* Extract dynamic section */
    ElfW(Word) dynamic_flags = 0;
    Utils::phdr_table_get_dynamic_section(phdr, phnum, load_bias, &dynamic, &dynamic_flags);

    if (dynamic == nullptr) {
        return false;
    } else {
    }


//    uint32_t needed_count = 0;
    for (ElfW(Dyn)* d = dynamic; d->d_tag != DT_NULL; ++d) {
        LOGD("d = %p, d[0](tag) = %p d[1](val) = %p",
              d, reinterpret_cast<void*>(d->d_tag), reinterpret_cast<void*>(d->d_un.d_val));
        switch (d->d_tag) {
            case DT_SONAME:
                // this is parsed after we have strtab initialized (see below).
                break;

            case DT_HASH:
                nbucket_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[0];
                nchain_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[1];
                bucket_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr + 8);
                chain_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr + 8 + nbucket_ * 4);
                break;

            case DT_GNU_HASH: {

                gnu_nbucket_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[0];
                // skip symndx
                gnu_maskwords_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[2];
                gnu_shift2_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[3];

                gnu_bloom_filter_ = reinterpret_cast<ElfW(Addr)*>(load_bias + d->d_un.d_ptr + 16);
                gnu_bucket_ = reinterpret_cast<uint32_t*>(gnu_bloom_filter_ + gnu_maskwords_);
                // amend chain for symndx = header[1]
                gnu_chain_ = gnu_bucket_ + gnu_nbucket_ -
                             reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[1];


                if (!powerof2(gnu_maskwords_)) {
                    LOGE("invalid maskwords for gnu_hash = 0x%x, in \"%s\" expecting power to two",
                           gnu_maskwords_, "");
                    return false;
                }
                --gnu_maskwords_;

                flags_ |= FLAG_GNU_HASH;


                break;
            }
            case DT_STRTAB:
                strtab_ = reinterpret_cast<const char*>(load_bias + d->d_un.d_ptr);
                break;

            case DT_STRSZ:
                strtab_size_ = d->d_un.d_val;
                break;

            case DT_SYMTAB:
                symtab_ = reinterpret_cast<ElfW(Sym)*>(load_bias + d->d_un.d_ptr);
                break;

            case DT_SYMENT:
                if (d->d_un.d_val != sizeof(ElfW(Sym))) {
                    LOGD("invalid DT_SYMENT: %zd in \"%s\"",
                           static_cast<size_t>(d->d_un.d_val), "");
                    return false;
                }
                break;

            case DT_PLTREL:
#if defined(USE_RELA)
                if (d->d_un.d_val != DT_RELA) {
                  LOGD("unsupported DT_PLTREL in \"%s\"; expected DT_RELA", get_realpath());
                  return false;
                }
#else
                if (d->d_un.d_val != DT_REL) {
                    LOGD("unsupported DT_PLTREL in \"%s\"; expected DT_REL", "");
                    LOGD("d->d_un.d_val = %x", d->d_un.d_val);
                    return false;
                }
#endif
                break;

            case DT_JMPREL:
#if defined(USE_RELA)
                plt_rela_ = reinterpret_cast<ElfW(Rela)*>(load_bias + d->d_un.d_ptr);
#else
                plt_rel_ = reinterpret_cast<ElfW(Rel)*>(load_bias + d->d_un.d_ptr);
#endif
                break;

            case DT_PLTRELSZ:
#if defined(USE_RELA)
                plt_rela_count_ = d->d_un.d_val / sizeof(ElfW(Rela));
#else
                plt_rel_count_ = d->d_un.d_val / sizeof(ElfW(Rel));
#endif
                break;

            case DT_PLTGOT:
#if defined(__mips__)
                // Used by mips and mips64.
    plt_got_ = reinterpret_cast<ElfW(Addr)**>(load_bias + d->d_un.d_ptr);
#endif
                // Ignore for other platforms... (because RTLD_LAZY is not supported)
                break;

            case DT_DEBUG:
                // Set the DT_DEBUG entry to the address of _r_debug for GDB
                // if the dynamic table is writable
// FIXME: not working currently for N64
// The flags for the LOAD and DYNAMIC program headers do not agree.
// The LOAD section containing the dynamic table has been mapped as
// read-only, but the DYNAMIC header claims it is writable.
#if !(defined(__mips__) && defined(__LP64__))
                if ((dynamic_flags & PF_W) != 0) {
                    LOGD("pass code: d->d_un.d_val = reinterpret_cast<uintptr_t>(&_r_debug);");
//                        d->d_un.d_val = reinterpret_cast<uintptr_t>(&_r_debug);
                }
#endif
                break;
#if defined(USE_RELA)
                case DT_RELA:
    rela_ = reinterpret_cast<ElfW(Rela)*>(load_bias + d->d_un.d_ptr);
    break;

  case DT_RELASZ:
    rela_count_ = d->d_un.d_val / sizeof(ElfW(Rela));
    break;

  case DT_ANDROID_RELA:
    android_relocs_ = reinterpret_cast<uint8_t*>(load_bias + d->d_un.d_ptr);
    break;

  case DT_ANDROID_RELASZ:
    android_relocs_size_ = d->d_un.d_val;
    break;

  case DT_ANDROID_REL:
    LOGD("unsupported DT_ANDROID_REL in \"%s\"", get_realpath());
    return false;

  case DT_ANDROID_RELSZ:
    LOGD("unsupported DT_ANDROID_RELSZ in \"%s\"", get_realpath());
    return false;

  case DT_RELAENT:
    if (d->d_un.d_val != sizeof(ElfW(Rela))) {
      LOGD("invalid DT_RELAENT: %zd", static_cast<size_t>(d->d_un.d_val));
      return false;
    }
    break;

  // ignored (see DT_RELCOUNT comments for details)
  case DT_RELACOUNT:
    break;

  case DT_REL:
    LOGD("unsupported DT_REL in \"%s\"", get_realpath());
    return false;

  case DT_RELSZ:
    LOGD("unsupported DT_RELSZ in \"%s\"", get_realpath());
    return false;

#else
            case DT_REL:
                rel_ = reinterpret_cast<ElfW(Rel)*>(load_bias + d->d_un.d_ptr);
                break;

            case DT_RELSZ:
                rel_count_ = d->d_un.d_val / sizeof(ElfW(Rel));
                break;

            case DT_RELENT:
                if (d->d_un.d_val != sizeof(ElfW(Rel))) {
                    LOGD("invalid DT_RELENT: %zd", static_cast<size_t>(d->d_un.d_val));
                    return false;
                }
                break;

            case DT_ANDROID_REL:
                android_relocs_ = reinterpret_cast<uint8_t*>(load_bias + d->d_un.d_ptr);
                break;

            case DT_ANDROID_RELSZ:
                android_relocs_size_ = d->d_un.d_val;
                break;

            case DT_ANDROID_RELA:
                LOGD("unsupported DT_ANDROID_RELA in \"%s\"", "");
                return false;

            case DT_ANDROID_RELASZ:
                LOGD("unsupported DT_ANDROID_RELASZ in \"%s\"", "");
                return false;

                // "Indicates that all RELATIVE relocations have been concatenated together,
                // and specifies the RELATIVE relocation count."
                //
                // TODO: Spec also mentions that this can be used to optimize relocation process;
                // Not currently used by bionic linker - ignored.
            case DT_RELCOUNT:
                break;

            case DT_RELA:
                LOGD("unsupported DT_RELA in \"%s\"", "");
                return false;

            case DT_RELASZ:
                LOGD("unsupported DT_RELASZ in \"%s\"", "");
                return false;

#endif
            case DT_INIT:
                init_func_ = reinterpret_cast<linker_ctor_function_t>(load_bias + d->d_un.d_ptr);
                LOGD("%s constructors (DT_INIT) found at %p", get_realpath(), init_func_);
                break;

            case DT_FINI:
                fini_func_ = reinterpret_cast<linker_dtor_function_t>(load_bias + d->d_un.d_ptr);
                LOGD("%s destructors (DT_FINI) found at %p", get_realpath(), fini_func_);
                break;

            case DT_INIT_ARRAY:
                init_array_ = reinterpret_cast<linker_ctor_function_t*>(load_bias + d->d_un.d_ptr);
                LOGD("%s constructors (DT_INIT_ARRAY) found at %p", get_realpath(), init_array_);
                break;

            case DT_INIT_ARRAYSZ:
                init_array_count_ = static_cast<uint32_t>(d->d_un.d_val) / sizeof(ElfW(Addr));
                break;

            case DT_FINI_ARRAY:
                fini_array_ = reinterpret_cast<linker_dtor_function_t*>(load_bias + d->d_un.d_ptr);
                LOGD("%s destructors (DT_FINI_ARRAY) found at %p", get_realpath(), fini_array_);
                break;

            case DT_FINI_ARRAYSZ:
                fini_array_count_ = static_cast<uint32_t>(d->d_un.d_val) / sizeof(ElfW(Addr));
                break;

            case DT_PREINIT_ARRAY:
                preinit_array_ = reinterpret_cast<linker_ctor_function_t*>(load_bias + d->d_un.d_ptr);
                LOGD("%s constructors (DT_PREINIT_ARRAY) found at %p", get_realpath(), preinit_array_);
                break;

            case DT_PREINIT_ARRAYSZ:
                preinit_array_count_ = static_cast<uint32_t>(d->d_un.d_val) / sizeof(ElfW(Addr));
                break;

            case DT_TEXTREL:
#if defined(__LP64__)
                LOGD("\"%s\" has text relocations", get_realpath());
    return false;
#else
                has_text_relocations = true;
                break;
#endif

            case DT_SYMBOLIC:
                has_DT_SYMBOLIC = true;
                break;

            case DT_NEEDED:
                // 手動保留所有依賴庫, 用於之後的重定位
                myneed[needed_count] = d->d_un.d_val;
                ++needed_count;
                break;

            case DT_FLAGS:
                if (d->d_un.d_val & DF_TEXTREL) {
#if defined(__LP64__)
                    LOGD("\"%s\" has text relocations", get_realpath());
      return false;
#else
                    has_text_relocations = true;
#endif
                }
                if (d->d_un.d_val & DF_SYMBOLIC) {
                    has_DT_SYMBOLIC = true;
                }
                break;

            case DT_FLAGS_1:
//                    LOGE("in case DT_FLAGS_1:");
                set_dt_flags_1(d->d_un.d_val);

                if ((d->d_un.d_val & ~SUPPORTED_DT_FLAGS_1) != 0) {
                    LOGE("\"%s\" has unsupported flags DT_FLAGS_1=%p", get_realpath(), reinterpret_cast<void*>(d->d_un.d_val));
                }
                break;
#if defined(__mips__)
                case DT_MIPS_RLD_MAP:
    // Set the DT_MIPS_RLD_MAP entry to the address of _r_debug for GDB.
    {
      r_debug** dp = reinterpret_cast<r_debug**>(load_bias + d->d_un.d_ptr);
      *dp = &_r_debug;
    }
    break;
  case DT_MIPS_RLD_MAP_REL:
    // Set the DT_MIPS_RLD_MAP_REL entry to the address of _r_debug for GDB.
    {
      r_debug** dp = reinterpret_cast<r_debug**>(
          reinterpret_cast<ElfW(Addr)>(d) + d->d_un.d_val);
      *dp = &_r_debug;
    }
    break;

  case DT_MIPS_RLD_VERSION:
  case DT_MIPS_FLAGS:
  case DT_MIPS_BASE_ADDRESS:
  case DT_MIPS_UNREFEXTNO:
    break;

  case DT_MIPS_SYMTABNO:
    mips_symtabno_ = d->d_un.d_val;
    break;

  case DT_MIPS_LOCAL_GOTNO:
    mips_local_gotno_ = d->d_un.d_val;
    break;

  case DT_MIPS_GOTSYM:
    mips_gotsym_ = d->d_un.d_val;
    break;
#endif
                // Ignored: "Its use has been superseded by the DF_BIND_NOW flag"
            case DT_BIND_NOW:
                break;

            case DT_VERSYM:
                versym_ = reinterpret_cast<ElfW(Versym)*>(load_bias + d->d_un.d_ptr);
                break;

            case DT_VERDEF:
                verdef_ptr_ = load_bias + d->d_un.d_ptr;
                break;
            case DT_VERDEFNUM:
                verdef_cnt_ = d->d_un.d_val;
                break;

            case DT_VERNEED:
                verneed_ptr_ = load_bias + d->d_un.d_ptr;
                break;

            case DT_VERNEEDNUM:
                verneed_cnt_ = d->d_un.d_val;
                break;

            case DT_RUNPATH:
                // this is parsed after we have strtab initialized (see below).
                break;

            default:
                LOGE("in default:");
//                    if (!relocating_linker) {
//                        DL_WARN("\"%s\" unused DT entry: type %p arg %p", get_realpath(),
//                                reinterpret_cast<void*>(d->d_tag), reinterpret_cast<void*>(d->d_un.d_val));
//                    }
                break;
        }
    }


    LOGD("si->base = %p, si->strtab = %p, si->symtab = %p",
          reinterpret_cast<void*>(base), strtab_, symtab_);

    if (nbucket_ == 0 && gnu_nbucket_ == 0) {
        LOGD("empty/missing DT_HASH/DT_GNU_HASH in \"%s\" "
               "(new hash type from the future?)", get_realpath());
        return false;
    }
    if (strtab_ == 0) {
        LOGD("empty/missing DT_STRTAB in \"%s\"", get_realpath());
        return false;
    }
    if (symtab_ == 0) {
        LOGD("empty/missing DT_SYMTAB in \"%s\"", get_realpath());
        return false;
    }

        // second pass - parse entries relying on strtab
        for (ElfW(Dyn)* d = dynamic; d->d_tag != DT_NULL; ++d) {
            switch (d->d_tag) {
                case DT_SONAME:
                    soname_ = get_string(d->d_un.d_val);
                    LOGD("set soname = %s", soname_);
                    break;
                case DT_RUNPATH:
//                    set_dt_runpath(get_string(d->d_un.d_val));
                    LOGD("set_dt_runpath(%s)", get_string(d->d_un.d_val));
                    break;
            }
        }

    return true;
}


bool soinfo::link_image() {
    local_group_root_ = this;

    if (android_relocs_ != nullptr) {
        LOGD("android_relocs_ 不用處理?");

    } else {
        LOGE("bad android relocation header.");
//        return false;
    }


#if defined(USE_RELA)
    if (rela_ != nullptr) {
        LOGD("[ relocating %s ]", get_realpath());
        if (!relocate(plain_reloc_iterator(rela_, rela_count_))) {
          return false;
        }
    }
    if (plt_rela_ != nullptr) {
        LOGD("[ relocating %s plt ]", get_realpath());
        if (!relocate(plain_reloc_iterator(plt_rela_, plt_rela_count_))) {
          return false;
        }
    }
#else
    LOGE("TODO: !defined(USE_RELA) ");
#endif

    LOGD("[ finished linking %s ]", get_realpath());


    // We can also turn on GNU RELRO protection if we're not linking the dynamic linker
    // itself --- it can't make system calls yet, and will have to call protect_relro later.
    if (!((flags_ & FLAG_LINKER) != 0) && !protect_relro()) {
        return false;
    }

    return true;
}


template<typename ElfRelIteratorT>
bool soinfo::relocate(ElfRelIteratorT&& rel_iterator) {
    for (size_t idx = 0; rel_iterator.has_next(); ++idx) {
        const auto rel = rel_iterator.next();
        if (rel == nullptr) {
            return false;
        }


        ElfW(Word) type = ELFW(R_TYPE)(rel->r_info);
        ElfW(Word) sym = ELFW(R_SYM)(rel->r_info);

        // reloc 指向需要重定向的內容, 根據type來決定重定向成什麼
        ElfW(Addr) reloc = static_cast<ElfW(Addr)>(rel->r_offset + load_bias);
        ElfW(Addr) sym_addr = 0;
        const char* sym_name = nullptr;
        soinfo* lsi = nullptr;
        ElfW(Addr) addend = Utils::get_addend(rel, reloc);

//        LOGD("Processing \"%s\" relocation at index %zd", get_realpath(), idx);
        if (type == R_GENERIC_NONE) {
            continue;
        }

        const ElfW(Sym)* s = nullptr;

        if (sym != 0) {

            sym_name = get_string(symtab_[sym].st_name);
//            LOGD("sym = %lx   sym_name: %s   st_value: %lx", sym, sym_name, symtab_[sym].st_value);

            if(soinfo_do_lookup(sym_name, &lsi, &s)) {
                sym_addr = lsi->resolve_symbol_address(s);
            } else {
                for(int s = 0; s < needed_count; s++) {
                    void* handle = dlopen(get_string(myneed[s]),RTLD_NOW);
                    sym_addr = reinterpret_cast<Elf64_Addr>(dlsym(handle, sym_name));
                    if(sym_addr) break;
                }
            }

            LOGD("sym_addr: 0x%lx (by dlsym)", sym_addr);


            if(!sym_addr) {
                if(symtab_[sym].st_value != 0) {
                    sym_addr = load_bias + symtab_[sym].st_value;
                }else {
                    LOGE("%s find addr fail (sym: %lx)", sym_name, sym);
                }

            }else {
                LOGD("%s find addr success : %lx", sym_name, sym_addr);
            }
        }


        switch (type) {
            case R_GENERIC_JUMP_SLOT:
                *reinterpret_cast<ElfW(Addr)*>(reloc) = (sym_addr + addend);
                break;
            case R_GENERIC_GLOB_DAT:
                *reinterpret_cast<ElfW(Addr)*>(reloc) = (sym_addr + addend);
                break;
            case R_GENERIC_RELATIVE:
                *reinterpret_cast<ElfW(Addr)*>(reloc) = (load_bias + addend);
                break;
            case R_GENERIC_IRELATIVE:
                {

                    ElfW(Addr) ifunc_addr = Utils::call_ifunc_resolver(load_bias + addend);
                    *reinterpret_cast<ElfW(Addr)*>(reloc) = ifunc_addr;
                }
                break;

#if defined(__aarch64__)
                case R_AARCH64_ABS64:
    *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + addend;
    break;
  case R_AARCH64_ABS32:
    {
      const ElfW(Addr) min_value = static_cast<ElfW(Addr)>(INT32_MIN);
      const ElfW(Addr) max_value = static_cast<ElfW(Addr)>(UINT32_MAX);
      if ((min_value <= (sym_addr + addend)) &&
          ((sym_addr + addend) <= max_value)) {
        *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + addend;
      } else {
        LOGE("0x%016llx out of range 0x%016llx to 0x%016llx",
               sym_addr + addend, min_value, max_value);
        return false;
      }
    }
    break;
  case R_AARCH64_ABS16:
    {
      const ElfW(Addr) min_value = static_cast<ElfW(Addr)>(INT16_MIN);
      const ElfW(Addr) max_value = static_cast<ElfW(Addr)>(UINT16_MAX);
      if ((min_value <= (sym_addr + addend)) &&
          ((sym_addr + addend) <= max_value)) {
        *reinterpret_cast<ElfW(Addr)*>(reloc) = (sym_addr + addend);
      } else {
        LOGE("0x%016llx out of range 0x%016llx to 0x%016llx",
               sym_addr + addend, min_value, max_value);
        return false;
      }
    }
    break;
  case R_AARCH64_PREL64:
    *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + addend - rel->r_offset;
    break;
  case R_AARCH64_PREL32:
    {
      const ElfW(Addr) min_value = static_cast<ElfW(Addr)>(INT32_MIN);
      const ElfW(Addr) max_value = static_cast<ElfW(Addr)>(UINT32_MAX);
      if ((min_value <= (sym_addr + addend - rel->r_offset)) &&
          ((sym_addr + addend - rel->r_offset) <= max_value)) {
        *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + addend - rel->r_offset;
      } else {
        LOGE("0x%016llx out of range 0x%016llx to 0x%016llx",
               sym_addr + addend - rel->r_offset, min_value, max_value);
        return false;
      }
    }
    break;
  case R_AARCH64_PREL16:
    {
      const ElfW(Addr) min_value = static_cast<ElfW(Addr)>(INT16_MIN);
      const ElfW(Addr) max_value = static_cast<ElfW(Addr)>(UINT16_MAX);
      if ((min_value <= (sym_addr + addend - rel->r_offset)) &&
          ((sym_addr + addend - rel->r_offset) <= max_value)) {
        *reinterpret_cast<ElfW(Addr)*>(reloc) = sym_addr + addend - rel->r_offset;
      } else {
        LOGE("0x%016llx out of range 0x%016llx to 0x%016llx",
               sym_addr + addend - rel->r_offset, min_value, max_value);
        return false;
      }
    }
    break;

  case R_AARCH64_COPY:
    LOGE("%s R_AARCH64_COPY relocations are not supported", get_realpath());
    return false;
  case R_AARCH64_TLS_TPREL64:
    LOGD("RELO TLS_TPREL64 *** %16llx <- %16llx - %16llx\n",
               reloc, (sym_addr + addend), rel->r_offset);
    break;
  case R_AARCH64_TLS_DTPREL32:
      LOGD("RELO TLS_DTPREL32 *** %16llx <- %16llx - %16llx\n",
               reloc, (sym_addr + addend), rel->r_offset);
    break;
#endif
            default:
                LOGE("unknown reloc type %d @ %p (%zu)  sym_name: %s", type, rel, idx, sym_name);
                return false;
        }
//    */
    }
    return true;
}

void soinfo::call_constructors() {
    // 對於so文件來說, 由於沒有_start函數
    // 因此init_func_和init_array_都無法傳參, 只能是默認值

    if(init_func_) {
        LOGD("init func: %p", init_func_);
        init_func_(0, nullptr, nullptr);
    }
    if(init_array_) {
        for(int i = 0; i < init_array_count_; i++) {
            if(!init_array_[i])continue;
            init_array_[i](0, nullptr, nullptr);
        }
    }
    LOGD("init_array_count_ = %d", init_array_count_);

}

bool soinfo::protect_relro() {
    if (Utils::phdr_table_set_gnu_relro_prot(phdr, phnum, load_bias, PROT_READ) < 0) {
        LOGE("can't enable GNU RELRO protection for \"%s\": %s",
               get_realpath(), strerror(errno));
        return false;
    }
    return true;
}



bool MyLoader::Read(const char* name, int fd, off64_t file_offset, off64_t file_size) {
    bool res = false;

    name_ = name;
    fd_ = fd;
    file_offset_ = file_offset;
    file_size_ = file_size;

    if (ReadElfHeader() &&
        ReadProgramHeaders()) {
        res = true;
    }


    return res;
}

bool MyLoader::ReadElfHeader() {
    return memcpy(&(header_),start_addr_,sizeof(header_));
}

bool MyLoader::ReadProgramHeaders() {

    phdr_num_ = header_.e_phnum;

    size_t size = phdr_num_ * sizeof(ElfW(Phdr));

    void* data = Utils::getMapData(fd_, file_offset_, header_.e_phoff, size);
    if(data == nullptr) {
        LOGE("ProgramHeader mmap failed");
        return false;
    }
    phdr_table_ = static_cast<ElfW(Phdr)*>(data);

    return true;
}


bool MyLoader::Load() {
    bool res = false;
    if (ReserveAddressSpace() &&
        LoadSegments() &&
        FindPhdr()) {

        LOGD("Load Done.........");
        res = true;
    }

    // 獲取當前so (加載器的so)
    si_ = Utils::get_soinfo("libnglinker.so");

    if(!si_) {
        LOGE("si_ return nullptr");
        return false;
    }
    LOGD("si_ -> base: %lx", si_->base);

    // 使si_可以被修改
    // fix bug: 由於不同Android版本的soinfo變化較大, 因此size設置大些會好點, 以前設置為0x1000, 在aosp8能用, 但aosp10會crash, 因此改為0x2000
    mprotect((void*) PAGE_START(reinterpret_cast<ElfW(Addr)>(si_)), 0x2000, PROT_READ | PROT_WRITE);
    // 修正so
    si_->base = load_start();
    si_->size = load_size();
//        si_->set_mapped_by_caller(elf_reader.is_mapped_by_caller());
    si_->load_bias = load_bias();
    si_->phnum = phdr_count();
    si_->phdr = loaded_phdr();
    return res;
}

bool MyLoader::ReserveAddressSpace() {
    ElfW(Addr) min_vaddr;
    load_size_ = phdr_table_get_load_size(phdr_table_, phdr_num_, &min_vaddr);
    LOGD("load_size_: %x", load_size_);
    if (load_size_ == 0) {
        LOGE("\"%s\" has no loadable segments", name_.c_str());
        return false;
    }

    uint8_t* addr = reinterpret_cast<uint8_t*>(min_vaddr);

    void* start;

    // Assume position independent executable by default.
    void* mmap_hint = nullptr;

    start = mmap(mmap_hint, load_size_, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    load_start_ = start;
    load_bias_ = reinterpret_cast<uint8_t*>(start) - addr;

    return true;
}

size_t MyLoader::phdr_table_get_load_size(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                ElfW(Addr)* out_min_vaddr) {
    ElfW(Addr) min_vaddr = UINTPTR_MAX;
    ElfW(Addr) max_vaddr = 0;

    bool found_pt_load = false;
    for (size_t i = 0; i < phdr_count; ++i) {
        const ElfW(Phdr)* phdr = &phdr_table[i];

        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        found_pt_load = true;

        if (phdr->p_vaddr < min_vaddr) {
            min_vaddr = phdr->p_vaddr;
        }

        if (phdr->p_vaddr + phdr->p_memsz > max_vaddr) {
            max_vaddr = phdr->p_vaddr + phdr->p_memsz;
        }
    }
    if (!found_pt_load) {
        min_vaddr = 0;
    }

    min_vaddr = PAGE_START(min_vaddr);
    max_vaddr = PAGE_END(max_vaddr);

    if (out_min_vaddr != nullptr) {
        *out_min_vaddr = min_vaddr;
    }

    return max_vaddr - min_vaddr;
}

bool MyLoader::LoadSegments() {
    // 在這個函數中會往 ReserveAddressSpace
    // 裡mmap的那片內存填充數據


    for (size_t i = 0; i < phdr_num_; ++i) {
        const ElfW(Phdr)* phdr = &phdr_table_[i];

        if (phdr->p_type != PT_LOAD) {
            continue;
        }

        // Segment addresses in memory.
        ElfW(Addr) seg_start = phdr->p_vaddr + load_bias_;
        ElfW(Addr) seg_end   = seg_start + phdr->p_memsz;

        ElfW(Addr) seg_page_start = PAGE_START(seg_start);
        ElfW(Addr) seg_page_end   = PAGE_END(seg_end);

        ElfW(Addr) seg_file_end   = seg_start + phdr->p_filesz;

        // File offsets.
        ElfW(Addr) file_start = phdr->p_offset;
        ElfW(Addr) file_end   = file_start + phdr->p_filesz;

        ElfW(Addr) file_page_start = PAGE_START(file_start);
        ElfW(Addr) file_length = file_end - file_page_start;

        if (file_size_ <= 0) {
            LOGE("\"%s\" invalid file size: %", name_.c_str(), file_size_);
            return false;
        }

        if (file_end > static_cast<size_t>(file_size_)) {
            LOGE("invalid ELF file");
            return false;
        }

        if (file_length != 0) {
            // 按AOSP裡那樣用mmap會有問題, 因此改為直接 memcpy
            mprotect(reinterpret_cast<void *>(seg_page_start), seg_page_end - seg_page_start, PROT_WRITE);
            void* c = (char*)start_addr_ + file_page_start;
            void* res = memcpy(reinterpret_cast<void *>(seg_page_start), c, file_length);

            LOGD("[LoadSeg] %s  seg_page_start: %lx   c : %lx", strerror(errno), seg_page_start, c);

        }

        // if the segment is writable, and does not end on a page boundary,
        // zero-fill it until the page limit.
        if ((phdr->p_flags & PF_W) != 0 && PAGE_OFFSET(seg_file_end) > 0) {
            memset(reinterpret_cast<void*>(seg_file_end), 0, PAGE_SIZE - PAGE_OFFSET(seg_file_end));
        }

        seg_file_end = PAGE_END(seg_file_end);

        // seg_file_end is now the first page address after the file
        // content. If seg_end is larger, we need to zero anything
        // between them. This is done by using a private anonymous
        // map for all extra pages.

        if (seg_page_end > seg_file_end) {
            size_t zeromap_size = seg_page_end - seg_file_end;
            void* zeromap = mmap(reinterpret_cast<void*>(seg_file_end),
                                 zeromap_size,
                                 PFLAGS_TO_PROT(phdr->p_flags),
                                 MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE,
                                 -1,
                                 0);
            if (zeromap == MAP_FAILED) {
                LOGE("couldn't zero fill \"%s\" gap: %s", name_.c_str(), strerror(errno));
                return false;
            }

            // 分配.bss節
            prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, zeromap, zeromap_size, ".bss");
        }
    }


    return true;
}

bool MyLoader::FindPhdr() {

    const ElfW(Phdr)* phdr_limit = phdr_table_ + phdr_num_;

    // If there is a PT_PHDR, use it directly.
    for (const ElfW(Phdr)* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type == PT_PHDR) {
            return CheckPhdr(load_bias_ + phdr->p_vaddr);
        }
    }

    // Otherwise, check the first loadable segment. If its file offset
    // is 0, it starts with the ELF header, and we can trivially find the
    // loaded program header from it.
    for (const ElfW(Phdr)* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type == PT_LOAD) {
            if (phdr->p_offset == 0) {
                ElfW(Addr)  elf_addr = load_bias_ + phdr->p_vaddr;
                const ElfW(Ehdr)* ehdr = reinterpret_cast<const ElfW(Ehdr)*>(elf_addr);
                ElfW(Addr)  offset = ehdr->e_phoff;
                return CheckPhdr(reinterpret_cast<ElfW(Addr)>(ehdr) + offset);
            }
            break;
        }
    }

    LOGE("can't find loaded phdr for \"%s\"", name_.c_str());
    return false;
}

bool MyLoader::CheckPhdr(ElfW(Addr) loaded) {
    const ElfW(Phdr)* phdr_limit = phdr_table_ + phdr_num_;
    ElfW(Addr) loaded_end = loaded + (phdr_num_ * sizeof(ElfW(Phdr)));
    for (const ElfW(Phdr)* phdr = phdr_table_; phdr < phdr_limit; ++phdr) {
        if (phdr->p_type != PT_LOAD) {
            continue;
        }
        ElfW(Addr) seg_start = phdr->p_vaddr + load_bias_;
        ElfW(Addr) seg_end = phdr->p_filesz + seg_start;
        if (seg_start <= loaded && loaded_end <= seg_end) {
            loaded_phdr_ = reinterpret_cast<const ElfW(Phdr)*>(loaded);
            return true;
        }
    }
    LOGE("\"%s\" loaded phdr %p not in loadable segment",
           name_.c_str(), reinterpret_cast<void*>(loaded));
    return false;
}

const char* MyLoader::get_string(ElfW(Word) index) const {
    return strtab_ + index;
}



void MyLoader::run(const char* path) {
    int fd;
    struct stat sb;
    fd = open(path, O_RDONLY);
    fstat(fd, &sb);
    start_addr_ = static_cast<void **>(mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0));

    // 0. 預加載一些用到的模塊
    Utils::load_modules();

    // 1. 讀取so文件
    if(!Read(path, fd, 0, sb.st_size)){
        LOGD("Read so failed");
        munmap(start_addr_, sb.st_size);
        close(fd);
    }


    // 2. 載入so
    if(!Load()) {
        LOGD("Load so failed");
        munmap(start_addr_, sb.st_size);
        close(fd);
    }

    // 使被加載的so有執行權限, 否則在調用.init_array時會報錯
    mprotect(reinterpret_cast<void *>(load_bias_), sb.st_size, PROT_READ | PROT_WRITE | PROT_EXEC);


    // 3. 預鏈接, 主要處理 .dynamic節
    si_->prelink_image();


    // 4. 正式鏈接, 在這裡處理重定位的信息
    si_->link_image();

    // 5. 調用.init和.init_array
    si_->call_constructors();

    close(fd);
}




