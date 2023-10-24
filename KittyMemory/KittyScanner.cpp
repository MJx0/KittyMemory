#include "KittyScanner.hpp"

#ifdef __ANDROID__
#include <map>
#include <dlfcn.h>
#endif

#include "KittyUtils.hpp"

// refs
// https://github.com/learn-more/findpattern-bench

namespace KittyScanner
{

    bool compare(const char *data, const char *pattern, const char *mask)
    {
        for (; *mask; ++mask, ++data, ++pattern)
        {
            if (*mask == 'x' && *data != *pattern)
                return false;
        }
        return !*mask;
    }

    uintptr_t findInRange(const uintptr_t start, const uintptr_t end,
                   const char *pattern, const std::string& mask)
    {
        const size_t scan_size = mask.length();

        if (scan_size < 1 || ((start + scan_size) > end))
            return 0;

        const size_t length = end - start;

        for (size_t i = 0; i < length; ++i)
        {
            const uintptr_t current_end = start + i + scan_size;
            if (current_end > end)
                break;

            if (!compare(reinterpret_cast<const char *>(start + i), pattern, mask.c_str()))
                continue;

            return start + i;
        }
        return 0;
    }

    std::vector<uintptr_t> findBytesAll(const uintptr_t start, const uintptr_t end,
                                        const char *bytes, const std::string& mask)
    {
        std::vector<uintptr_t> list;

        if (start >= end || !bytes || mask.empty())
            return list;

        uintptr_t curr_search_address = start;
        const size_t scan_size = mask.length();
        do {
            if (!list.empty()) curr_search_address = list.back() + scan_size;
            
            uintptr_t found = findInRange(curr_search_address, end, bytes, mask);
            if (!found) break;

            list.push_back(found);
        } while (true);

        return list;
    }

    uintptr_t findBytesFirst(const uintptr_t start, const uintptr_t end, const char *bytes, const std::string& mask)
    {
        if (start >= end || !bytes || mask.empty())
            return 0;

        return findInRange(start, end, bytes, mask);
    }

    std::vector<uintptr_t> findHexAll(const uintptr_t start, const uintptr_t end, std::string hex, const std::string& mask)
    {
        std::vector<uintptr_t> list;
        
        if (start >= end || mask.empty() || !KittyUtils::validateHexString(hex)) return list;

        const size_t scan_size = mask.length();
        if((hex.length() / 2) != scan_size) return list;
        
        std::vector<char> pattern(scan_size);
        KittyUtils::dataFromHex(hex, &pattern[0]);

        list = findBytesAll(start, end, pattern.data(), mask);
        return list;
    }

    uintptr_t findHexFirst(const uintptr_t start, const uintptr_t end, std::string hex, const std::string& mask) 
    {
        if (start >= end || mask.empty() || !KittyUtils::validateHexString(hex)) return 0;

        const size_t scan_size = mask.length();
        if((hex.length() / 2) != scan_size) return 0;

        std::vector<char> pattern(scan_size);
        KittyUtils::dataFromHex(hex, &pattern[0]);

        return findBytesFirst(start, end, pattern.data(), mask);
    }

    std::vector<uintptr_t> findIdaPatternAll(const uintptr_t start, const uintptr_t end, const std::string &pattern)
    {
      std::vector<uintptr_t> list;

      if (start >= end)
        return list;

      std::string mask;
      std::vector<char> bytes;

      const size_t pattren_len = pattern.length();
      for (std::size_t i = 0; i < pattren_len; i++)
      {
        if (pattern[i] == '?')
        {
          bytes.push_back(0);
          mask += '?';
        }
        else if (pattren_len > i + 1 && std::isxdigit(pattern[i]) && std::isxdigit(pattern[i + 1]))
        {
          bytes.push_back(std::stoi(pattern.substr(i++, 2), nullptr, 16));
          mask += 'x';
        }
      }

      if (bytes.empty() || mask.empty() || bytes.size() != mask.size())
        return list;

      list = findBytesAll(start, end, bytes.data(), mask);
      return list;
    }

    uintptr_t findIdaPatternFirst(const uintptr_t start, const uintptr_t end, const std::string &pattern) {
      if (start >= end)
        return 0;

      std::string mask;
      std::vector<char> bytes;

      const size_t pattren_len = pattern.length();
      for (std::size_t i = 0; i < pattren_len; i++)
      {
        if (pattern[i] == '?')
        {
          bytes.push_back(0);
          mask += '?';
        }
        else if (pattren_len > i + 1 && std::isxdigit(pattern[i]) && std::isxdigit(pattern[i + 1]))
        {
          bytes.push_back(std::stoi(pattern.substr(i++, 2), nullptr, 16));
          mask += 'x';
        }
      }

      if (bytes.empty() || mask.empty() || bytes.size() != mask.size())
        return 0;

      return findBytesFirst(start, end, bytes.data(), mask);
    }

    std::vector<uintptr_t> findDataAll(const uintptr_t start, const uintptr_t end, const void *data, size_t size)
    {
        std::vector<uintptr_t> list;

        if (start >= end || !data || size < 1)
            return list;

        std::string mask(size, 'x');

        list = findBytesAll(start, end, (const char *)data, mask);
        return list;
    }

    uintptr_t findDataFirst(const uintptr_t start, const uintptr_t end, const void *data, size_t size)
    {
        if (start >= end || !data || size < 1)
            return 0;

        std::string mask(size, 'x');

        return findBytesFirst(start, end, (const char *)data, mask);
    }

#ifdef __ANDROID__

    RegisterNativeFn findRegisterNativeFn(const std::vector<KittyMemory::ProcMap> &maps, const std::string &name)
    {
        uintptr_t string_loc = 0, string_xref = 0, fn_loc = 0;
        RegisterNativeFn fn;

        if (name.empty() || maps.empty())
            return fn;
        
        for (auto &it : maps) {
            if (it.isValidELF()) {
                string_loc = KittyScanner::findDataFirst(it.startAddress, it.endAddress, name.data(), name.length());
                if (string_loc) break;
            }
        }

        if (!string_loc) {
            KITTY_LOGE("couldn't find string (%s) in selected maps", name.c_str());
            return fn;
        }

        KITTY_LOGD("string (%s) at %p", name.c_str(), (void*)string_loc);

        for (auto &it : maps) {
            if (it.is_rw) {
                string_xref = KittyScanner::findDataFirst(it.startAddress, it.endAddress, &string_loc, sizeof(uintptr_t));
                if (!string_xref) continue;

                KITTY_LOGD("string at (%p) referenced at %p", (void *)string_loc, (void *)string_xref);
                
                fn_loc = string_xref;
                break;
            }
        }

        if(!fn_loc) return fn;

        memcpy(&fn, (void *)fn_loc, sizeof(RegisterNativeFn));
        return fn;
    }
	
// for old ndk
#ifndef DT_GNU_HASH
#define DT_GNU_HASH 0x6ffffef5
#endif

    uintptr_t findSymbol(const KittyMemory::ProcMap &baseMap, const std::string &symbol_name)
    {
        if (!baseMap.isValidELF()) {
            KITTY_LOGE("findSymbol: map is not a valid ELF [%p - %p] \"%s\".",
                    (void*)baseMap.startAddress, (void*)baseMap.endAddress, baseMap.pathname.c_str());
            return 0;
        }

        auto ident = reinterpret_cast<unsigned char *>(baseMap.startAddress);
        if (ident[EI_CLASS] != ELF_EICLASS_) {
            KITTY_LOGE("findSymbol: ELF class mismatch [%p - %p] \"%s\".",
                    (void*)baseMap.startAddress, (void*)baseMap.endAddress, baseMap.pathname.c_str());
            return 0;
        }

        auto *ehdr = reinterpret_cast<ElfW_(Ehdr) *>(baseMap.startAddress);
        if (!ehdr->e_phnum || !ehdr->e_phentsize || !ehdr->e_shnum || !ehdr->e_shentsize) {
            KITTY_LOGE("findSymbol: Invalid header values [%p - %p] \"%s\".",
                    (void*)baseMap.startAddress, (void*)baseMap.endAddress, baseMap.pathname.c_str());
            return 0;
        }

        int loads = 0;
        uintptr_t min_vaddr = UINTPTR_MAX, load_bias = 0, strtab = 0, symtab = 0, elf_hash = 0, gnu_hash = 0;
        size_t strsz = 0, syment = 0;
        for (ElfW_(Half) i = 0; i < ehdr->e_phnum; i++) {
            auto *phdr = reinterpret_cast<ElfW_(Phdr) *>((baseMap.startAddress + ehdr->e_phoff) + (i * ehdr->e_phentsize));
            if (phdr->p_type == PT_LOAD) {
                if (phdr->p_vaddr < min_vaddr) {
                    min_vaddr = phdr->p_vaddr;
                    load_bias = baseMap.startAddress - _PAGE_START_OF_(min_vaddr);
                }
                loads++;
            } else if (phdr->p_type == PT_DYNAMIC) {
                auto *dyn_curr = reinterpret_cast<ElfW_(Dyn) *>(load_bias + phdr->p_vaddr);
                auto *dyn_end = dyn_curr + (phdr->p_memsz / sizeof(ElfW_(Dyn)));
                for (; dyn_curr && dyn_curr < dyn_end && dyn_curr->d_tag != DT_NULL; dyn_curr++) {
                    switch (dyn_curr->d_tag) {
                        case DT_STRTAB:   // string table
                            strtab = dyn_curr->d_un.d_ptr;
                            break;
                        case DT_SYMTAB:   // symbol table
                            symtab = dyn_curr->d_un.d_ptr;
                            break;
                        case DT_HASH:     // hash table
                            elf_hash = dyn_curr->d_un.d_ptr;
                            break;
                        case DT_GNU_HASH: // gnu hash table
                            gnu_hash = dyn_curr->d_un.d_ptr;
                            break;
                        case DT_STRSZ:    // string table size
                            strsz = dyn_curr->d_un.d_val;
                            break;
                        case DT_SYMENT:   // symbol table entry size
                            syment = dyn_curr->d_un.d_val;
                            break;
                        default:
                            break;
                    }
                }
            }
        }

        // Check that we have all program headers required for dynamic linking
        if (!loads || !strtab || !symtab || !strsz || !syment) {
            KITTY_LOGE("findSymbol: failed to require all program headers for dynamic linking.");
            KITTY_LOGE("findSymbol: loads: %d | strtab=%p | symtab=%p", loads, (void *) strtab, (void *) symtab);
            KITTY_LOGE("[%p - %p] \"%s\".", (void*)baseMap.startAddress, (void*)baseMap.endAddress, baseMap.pathname.c_str());
            return 0;
        }

        auto fix_table_address = [&](uintptr_t &table_addr) {
            if (table_addr && table_addr < load_bias) table_addr += load_bias;
        };
        auto get_sym_address = [&](const ElfW_(Sym) *sym_ent) -> uintptr_t {
            return sym_ent->st_value < load_bias ? load_bias + sym_ent->st_value : sym_ent->st_value;
        };

        fix_table_address(strtab);
        fix_table_address(symtab);
        fix_table_address(elf_hash);
        fix_table_address(gnu_hash);

        // try gnu hash first
        if (gnu_hash) {
            const auto *sym = KittyUtils::Elf::GnuHash::LookupByName(gnu_hash, symtab, strtab, syment, strsz, symbol_name.c_str());
            if (sym && sym->st_value) {
                return get_sym_address(sym);
            }
        }

        if (elf_hash) {
            const auto *sym = KittyUtils::Elf::ElfHash::LookupByName(elf_hash, symtab, strtab, syment, strsz, symbol_name.c_str());
            if (sym && sym->st_value) {
                return get_sym_address(sym);
            }
        }

#if 0
        // linear search
        uintptr_t sym_entry = symtab;
        for (; sym_entry; sym_entry += syment) {
            const auto *curr_sym = reinterpret_cast<const ElfW_(Sym) *>(sym_entry);
            if (curr_sym->st_name >= strsz)
                break;

            if (!curr_sym->st_name || !curr_sym->st_value)
                continue;

            std::string sym_str = std::string((const char *) (strtab + curr_sym->st_name));
            if (!sym_str.empty() && sym_str == symbol_name)
                return get_sym_address(curr_sym);
        }
#endif

        return 0;
    }

    uintptr_t findSymbol(uintptr_t libBase, const std::string &symbol_name)
    {
        auto baseMap = KittyMemory::getAddressMap((void*) libBase);
        if (!baseMap.isValid()) {
            KITTY_LOGE("findSymbol: Couldn't find map of address (%p).", (void*)libBase);
            return 0;
        }
        return findSymbol(baseMap, symbol_name);
    }

    uintptr_t findSymbol(const std::string &lib, const std::string &symbol_name)
    {
        auto baseMap = KittyMemory::getElfBaseMap(lib);
        if (!baseMap.isValid()) {
            KITTY_LOGE("findSymbol: Couldn't find base map of \"%s\".", lib.c_str());
            return 0;
        }
        return findSymbol(baseMap, symbol_name);
    }

    std::vector<std::pair<uintptr_t, std::string>> findSymbolAll(const std::string &symbol_name)
    {
        std::vector<std::pair<uintptr_t, std::string>> ret{};

        auto maps = KittyMemory::getAllMaps();
        if (maps.empty()) {
            KITTY_LOGE("findSymbolAll: Failed to get process maps.");
            return ret;
        }

        std::map<uintptr_t , bool> checkedMaps{};
        for (auto &it: maps) {
            if (checkedMaps.count(it.startAddress) > 0)
                continue;

            if (it.isUnknown() || it.writeable || !it.is_private || !it.isValidELF())
                continue;

            // skip dladdr check for linker/linker64
            if (!strstr(it.pathname.c_str(), "/system/bin/linker")) {
                Dl_info info{};
                int rt = dladdr((void *) it.startAddress, &info);
                // check dli_fname and dli_fbase if NULL
                if (rt == 0 || !info.dli_fname || !info.dli_fbase || it.startAddress != (uintptr_t) info.dli_fbase)
                    continue;

                // re-assigning the pathname in case when library is zipped inside base.apk
                // dli_fname returns basename sometimes, so check basename before re-assigning the full pathname
                if (KittyUtils::fileNameFromPath(it.pathname) !=
                    KittyUtils::fileNameFromPath(info.dli_fname)) {
                    it.pathname = info.dli_fname;
                }
            }

            checkedMaps[it.startAddress] = true;

            uintptr_t sym = KittyScanner::findSymbol(it, symbol_name);
            if (sym != 0) {
                ret.emplace_back(sym, it.pathname);
            }
        }

        return ret;
    }

#endif // __ANDROID__

}