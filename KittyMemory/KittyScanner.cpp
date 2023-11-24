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
        
        if (start >= end || mask.empty() || !KittyUtils::String::ValidateHex(hex)) return list;

        const size_t scan_size = mask.length();
        if((hex.length() / 2) != scan_size) return list;
        
        std::vector<char> pattern(scan_size);
        KittyUtils::dataFromHex(hex, &pattern[0]);

        list = findBytesAll(start, end, pattern.data(), mask);
        return list;
    }

    uintptr_t findHexFirst(const uintptr_t start, const uintptr_t end, std::string hex, const std::string& mask) 
    {
        if (start >= end || mask.empty() || !KittyUtils::String::ValidateHex(hex)) return 0;

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
        if (pattern[i] == ' ') continue;

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
        if (pattern[i] == ' ') continue;
        
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

    RegisterNativeFn findRegisterNativeFn(const class ElfScanner &elf, const std::string &name)
    {
        uintptr_t string_loc = 0, string_xref = 0, fn_loc = 0;
        RegisterNativeFn fn;

        if (name.empty() || !elf.isValid())
            return fn;
        
        string_loc = KittyScanner::findDataFirst(elf.baseSegment().startAddress, elf.baseSegment().endAddress, name.data(), name.length());
        if (!string_loc) {
            KITTY_LOGE("findRegisterNativeFn: Couldn't find string (%s) in selected maps", name.c_str());
            return fn;
        }

        KITTY_LOGD("findRegisterNativeFn: String (%s) at %p", name.c_str(), (void*)string_loc);

        for (auto &it : elf.segments()) {
            if (it.is_rw) {
                string_xref = KittyScanner::findDataFirst(it.startAddress, it.endAddress, &string_loc, sizeof(uintptr_t));
                if (!string_xref) continue;

                KITTY_LOGD("findRegisterNativeFn: String at (%p) referenced at %p", (void *)string_loc, (void *)string_xref);
                
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

/* ======================= ElfScanner ======================= */

// refs https://gist.github.com/resilar/24bb92087aaec5649c9a2afc0b4350c8

    ElfScanner::ElfScanner(uintptr_t elfBase, const std::vector<KittyMemory::ProcMap> &maps)
    {
        _elfBase = 0;
        _ehdr = {};
        _phdr = 0;
        _loads = 0;
        _loadBias = 0;
        _loadSize = 0;
        _bss = 0;
        _bssSize = 0;
        _dynamic = 0;
        _stringTable = 0;
        _symbolTable = 0;
        _elfHashTable = 0;
        _gnuHashTable = 0;
        _strsz = 0;
        _syment = 0;

        if (!elfBase)
            return;

        // verify address
        auto elfBaseMap = KittyMemory::getAddressMap(maps, (const void *)elfBase);
        if (!elfBaseMap.isValid() || !elfBaseMap.readable || elfBase != elfBaseMap.startAddress)
        {
            KITTY_LOGD("ElfScanner: (%p) is not a valid ELF base address.", (void*)elfBase);
            return;
        }

        // verify ELF header
        if (!elfBaseMap.isValidELF())
        {
            KITTY_LOGD("ElfScanner: (%p) is not a valid ELF.", (void*)elfBase);
            return;
        }

        _elfBase = elfBase;

        // read ELF header
        _ehdr = *(ElfW_(Ehdr)*)elfBase;

        // check ELF bit
        if (_ehdr.e_ident[EI_CLASS] != ELF_EICLASS_) {
            KITTY_LOGD("ElfScanner: ELF class mismatch (%p).", (void*)elfBase);
            return;
        }

        // check common header values
        if (!_ehdr.e_phnum || !_ehdr.e_phentsize || !_ehdr.e_shnum || !_ehdr.e_shentsize) {
            KITTY_LOGD("ElfScanner: Invalid header values (%p).", (void*)elfBase);
            return;
        }

        _phdr = elfBase + _ehdr.e_phoff;

        // read all program headers
        std::vector<char> phdrs_buf(_ehdr.e_phnum * _ehdr.e_phentsize);
        if (!memcpy(&phdrs_buf[0], (const void*)_phdr, phdrs_buf.size())) {
            KITTY_LOGD("ElfScanner: Failed to read ELF (%p) program headers.", (void*)elfBase);
            return;
        }

        // find load bias
        uintptr_t min_vaddr = UINTPTR_MAX, max_vaddr = 0;
        uintptr_t load_vaddr = 0, load_memsz = 0, load_filesz = 0;
        for (ElfW_(Half) i = 0; i < _ehdr.e_phnum; i++) {
            ElfW_(Phdr) phdr_entry = {};
            memcpy(&phdr_entry, phdrs_buf.data() + (i * _ehdr.e_phentsize), _ehdr.e_phentsize);
            _phdrs.push_back(phdr_entry);

            if (phdr_entry.p_type == PT_LOAD) {
                _loads++;

                load_vaddr = phdr_entry.p_vaddr;
                load_memsz = phdr_entry.p_memsz;
                load_filesz = phdr_entry.p_filesz;

                if (phdr_entry.p_vaddr < min_vaddr)
                    min_vaddr = phdr_entry.p_vaddr;

                if (phdr_entry.p_vaddr + phdr_entry.p_memsz > max_vaddr)
                    max_vaddr = phdr_entry.p_vaddr + phdr_entry.p_memsz;
            }
        }

        if (!_loads) {
            KITTY_LOGD("ElfScanner: No loads entry for ELF (%p).", (void*)elfBase);
            return;
        }

        if (!max_vaddr) {
            KITTY_LOGD("ElfScanner: Failed to find load size for ELF (%p).", (void*)elfBase);
            return;
        }

        min_vaddr = KT_PAGE_START(min_vaddr);
        max_vaddr = KT_PAGE_END(max_vaddr);

        _loadBias = elfBase - min_vaddr;
        _loadSize = max_vaddr - min_vaddr;

        uintptr_t seg_start = load_vaddr + _loadBias;
        uintptr_t seg_mem_end = KT_PAGE_END((seg_start + load_memsz));
        uintptr_t seg_file_end = KT_PAGE_END((seg_start + load_filesz));
        if (seg_mem_end > seg_file_end) {
            _bss = seg_file_end;
            _bssSize = size_t(seg_mem_end - seg_file_end);
        }

        // read all dynamics
        for (auto& phdr : _phdrs) {
            if (phdr.p_type == PT_DYNAMIC) {
                _dynamic = _loadBias + phdr.p_vaddr;
                std::vector<ElfW_(Dyn)> dyn_buff(phdr.p_memsz / sizeof(ElfW_(Dyn)));
                if (!memcpy(&dyn_buff[0], (const void*)_dynamic, phdr.p_memsz)) {
                    KITTY_LOGD("ElfScanner: Failed to read dynamic for ELF (%p).", (void*)elfBase);
                    break;
                }

                for (auto& dyn : dyn_buff) {
                    if (dyn.d_tag == DT_NULL)
                        break;

                    // set required dynamics for symbol lookup
                    switch (dyn.d_tag) {
                        // mandatory
                    case DT_STRTAB: // string table
                        _stringTable = dyn.d_un.d_ptr;
                        break;
                        // mandatory
                    case DT_SYMTAB: // symbol table
                        _symbolTable = dyn.d_un.d_ptr;
                        break;
                    case DT_HASH: // hash table
                        _elfHashTable = dyn.d_un.d_ptr;
                        break;
                    case DT_GNU_HASH: // gnu hash table
                        _gnuHashTable = dyn.d_un.d_ptr;
                        break;
                        // mandatory
                    case DT_STRSZ: // string table size
                        _strsz = dyn.d_un.d_val;
                        break;
                        // mandatory
                    case DT_SYMENT: // symbol entry size
                        _syment = dyn.d_un.d_val;
                        break;
                    default:
                        break;
                    }

                    _dynamics.push_back(dyn);
                }
            }
        }

        // check required dynamics for symbol lookup
        if (!_stringTable || !_symbolTable || !_strsz || !_syment) {
            KITTY_LOGD("ElfScanner: Failed to require dynamics for symbol lookup.");
            KITTY_LOGD("ElfScanner: elfBase: %p | strtab=%p | symtab=%p | strsz=%p | syment=%p",
                (void*)elfBase, (void*)_stringTable, (void*)_symbolTable, (void*)_strsz, (void*)_syment);
            return;
        }

        auto fix_table_address = [&](uintptr_t& table_addr) {
            if (table_addr && table_addr < _loadBias)
                table_addr += _loadBias;
        };

        fix_table_address(_stringTable);
        fix_table_address(_symbolTable);
        fix_table_address(_elfHashTable);
        fix_table_address(_gnuHashTable);

        bool fixBSS = !_bss;

        for (auto& it : maps) {
            if (it.startAddress >= _elfBase && it.endAddress <= (_elfBase + _loadSize)) {
                _segments.push_back(it);
                if (fixBSS && it.pathname == "[anon:.bss]") {
                    if (!_bss)
                        _bss = it.startAddress;

                    _bssSize = it.endAddress - _bss;
                }
            }

            if (it.endAddress > (_elfBase + _loadSize))
                break;
        }

        if (!_segments.empty())
            _base_segment = _segments.front();
    }

    uintptr_t ElfScanner::findSymbol(const std::string& symbolName) const
    {
        if (!isValid()) return 0;

        auto get_sym_address = [&](const ElfW_(Sym) *sym_ent) -> uintptr_t {
            return sym_ent->st_value < _loadBias ? _loadBias + sym_ent->st_value : sym_ent->st_value;
        };

        // try gnu hash first
        if (_gnuHashTable) {
            const auto *sym = KittyUtils::Elf::GnuHash::LookupByName(_gnuHashTable, _symbolTable, _stringTable, _syment, _strsz, symbolName.c_str());
            if (sym && sym->st_value) {
                return get_sym_address(sym);
            }
        }

        if (_elfHashTable) {
            const auto *sym = KittyUtils::Elf::ElfHash::LookupByName(_elfHashTable, _symbolTable, _stringTable, _syment, _strsz, symbolName.c_str());
            if (sym && sym->st_value) {
                return get_sym_address(sym);
            }
        }

        return 0;
    }

    std::vector<ElfScanner> ElfScanner::getAllELFs()
    {
        std::vector<ElfScanner> elfs;

        auto maps = KittyMemory::getAllMaps();
        if (maps.empty()) {
            KITTY_LOGE("getAllELFs: Failed to get process maps.");
            return elfs;
        }

        std::map<uintptr_t , bool> checkedMaps{};
        for (auto &it: maps) {
            if (checkedMaps.count(it.startAddress) > 0)
                continue;

            if (!it.readable || it.offset != 0 || it.isUnknown() || it.inode == 0 || !it.is_private || !it.isValidELF())
                continue;

            // skip dladdr check for linker/linker64
            if (!strstr(it.pathname.c_str(), "/bin/linker")) {
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
            elfs.push_back(ElfScanner(it.startAddress, maps));
        }

        return elfs;
    }

    std::vector<std::pair<uintptr_t, ElfScanner>> ElfScanner::findSymbolAll(const std::string &symbolName)
    {
        std::vector<std::pair<uintptr_t, ElfScanner>> ret{};

        auto elfs = getAllELFs();
        for (auto &it: elfs) {
            uintptr_t sym = it.findSymbol(symbolName);
            if (sym != 0) {
                ret.emplace_back(sym, it);
            }
        }

        return ret;
    }

#endif // __ANDROID__

}