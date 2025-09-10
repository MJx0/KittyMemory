#include "KittyScanner.hpp"
#include "KittyPtrValidator.hpp"
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>

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

    uintptr_t findInRange(const uintptr_t start, const uintptr_t end, const char *pattern, const std::string &mask)
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

    std::vector<uintptr_t> findBytesAll(const uintptr_t start, const uintptr_t end, const char *bytes,
                                        const std::string &mask)
    {
        std::vector<uintptr_t> list;

        if (start >= end || !bytes || mask.empty())
            return list;

        uintptr_t curr_search_address = start;
        const size_t scan_size = mask.length();
        do
        {
            if (!list.empty())
                curr_search_address = list.back() + scan_size;

            uintptr_t found = findInRange(curr_search_address, end, bytes, mask);
            if (!found)
                break;

            list.push_back(found);
        } while (true);

        return list;
    }

    uintptr_t findBytesFirst(const uintptr_t start, const uintptr_t end, const char *bytes, const std::string &mask)
    {
        if (start >= end || !bytes || mask.empty())
            return 0;

        return findInRange(start, end, bytes, mask);
    }

    std::vector<uintptr_t> findHexAll(const uintptr_t start, const uintptr_t end, std::string hex,
                                      const std::string &mask)
    {
        std::vector<uintptr_t> list;

        if (start >= end || mask.empty() || !KittyUtils::String::ValidateHex(hex))
            return list;

        const size_t scan_size = mask.length();
        if ((hex.length() / 2) != scan_size)
            return list;

        std::vector<char> pattern(scan_size);
        KittyUtils::dataFromHex(hex, &pattern[0]);

        list = findBytesAll(start, end, pattern.data(), mask);
        return list;
    }

    uintptr_t findHexFirst(const uintptr_t start, const uintptr_t end, std::string hex, const std::string &mask)
    {
        if (start >= end || mask.empty() || !KittyUtils::String::ValidateHex(hex))
            return 0;

        const size_t scan_size = mask.length();
        if ((hex.length() / 2) != scan_size)
            return 0;

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
            if (pattern[i] == ' ')
                continue;

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

    uintptr_t findIdaPatternFirst(const uintptr_t start, const uintptr_t end, const std::string &pattern)
    {
        if (start >= end)
            return 0;

        std::string mask;
        std::vector<char> bytes;

        const size_t pattren_len = pattern.length();
        for (std::size_t i = 0; i < pattren_len; i++)
        {
            if (pattern[i] == ' ')
                continue;

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
        _dynamic = 0;
        _stringTable = 0;
        _symbolTable = 0;
        _elfHashTable = 0;
        _gnuHashTable = 0;
        _strsz = 0;
        _syment = sizeof(KT_ElfW(Sym));
        _fixedBySoInfo = false;
        _dsymbols_init = false;

        // verify address
        auto elfBaseMap = KittyMemory::getAddressMap(elfBase, maps);
        if (!elfBaseMap.isValid() || !elfBaseMap.readable || elfBase != elfBaseMap.startAddress)
        {
            KITTY_LOGD("ElfScanner: (%p) is not a valid ELF base address.", (void *)elfBase);
            return;
        }

        // verify ELF header
        if (!elfBaseMap.isValidELF())
        {
            KITTY_LOGD("ElfScanner: (%p) is not a valid ELF.", (void *)elfBase);
            return;
        }

        _elfBase = elfBase;

        // read ELF header
        _ehdr = *(KT_ElfW(Ehdr) *)_elfBase;

        // check ELF bit
        if (_ehdr.e_ident[EI_CLASS] != KT_ELF_EICLASS)
        {
            KITTY_LOGD("ElfScanner: ELF class mismatch (%p).", (void *)_elfBase);
            return;
        }

        if (_ehdr.e_ident[EI_DATA] != ELFDATA2LSB)
        {
            KITTY_LOGD("ElfScanner: (%p) data encoding is not little endian.", (void *)elfBase);
            return;
        }

        if (_ehdr.e_ident[EI_VERSION] != EV_CURRENT)
        {
            KITTY_LOGD("ElfScanner: (%p) ELF header version mismatch.", (void *)elfBase);
            return;
        }

        if (_ehdr.e_type != ET_EXEC && _ehdr.e_type != ET_DYN)
        {
            KITTY_LOGD("ElfScanner: (%p) is not a executable or dynamic "
                       "library.",
                       (void *)elfBase);
            return;
        }

        // check common header values
        if (!_ehdr.e_phoff || !_ehdr.e_phnum || !_ehdr.e_phentsize)
        {
            KITTY_LOGD("ElfScanner: Invalid header values (%p).", (void *)_elfBase);
            return;
        }

        if (!KittyMemory::getAddressMap(_elfBase + _ehdr.e_phoff, maps).readable)
        {
            KITTY_LOGD("ElfScanner: Invalid phdr (%p + %p) = %p.", (void *)_elfBase, (void *)_ehdr.e_phoff,
                       (void *)(_elfBase + _ehdr.e_phoff));
            return;
        }

        _phdr = _elfBase + _ehdr.e_phoff;

        // find load bias
        uintptr_t min_vaddr = UINTPTR_MAX, max_vaddr = 0;
        uintptr_t load_vaddr = 0, load_memsz = 0, load_filesz = 0;
        for (KT_ElfW(Half) i = 0; i < _ehdr.e_phnum; i++)
        {
            if (!KittyMemory::getAddressMap(_phdr + (i * _ehdr.e_phentsize), maps).readable)
                continue;

            KT_ElfW(Phdr) phdr_entry = {};
            memcpy(&phdr_entry, (const void *)(_phdr + (i * _ehdr.e_phentsize)), _ehdr.e_phentsize);
            _phdrs.push_back(phdr_entry);

            if (phdr_entry.p_type == PT_LOAD)
            {
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

        if (!_loads)
        {
            KITTY_LOGD("ElfScanner: No loads entry for ELF (%p).", (void *)_elfBase);
            return;
        }

        if (!max_vaddr)
        {
            KITTY_LOGD("ElfScanner: Failed to find max_vaddr for ELF (%p).", (void *)_elfBase);
            return;
        }

        min_vaddr = KT_PAGE_START(min_vaddr);
        max_vaddr = KT_PAGE_END(max_vaddr);

        _loadBias = _elfBase - min_vaddr;
        _loadSize = max_vaddr - min_vaddr;

        uintptr_t seg_start = load_vaddr + _loadBias;
        uintptr_t seg_mem_end = KT_PAGE_END((seg_start + load_memsz));
        uintptr_t seg_file_end = KT_PAGE_END((seg_start + load_filesz));
        uintptr_t bss_start = 0, bss_end = 0;
        if (seg_mem_end > seg_file_end)
        {
            bss_start = seg_file_end;
            bss_end = seg_mem_end;
        }

        for (const auto &it : maps)
        {
            if (it.startAddress >= _elfBase && it.endAddress <= (_elfBase + _loadSize))
            {
                if (it.startAddress == _elfBase)
                {
                    _baseSegment = it;
                }

                _segments.push_back(it);

                if (it.readable && !it.executable &&
                    (it.pathname == "[anon:.bss]" || (elfBaseMap.inode != 0 && it.inode == 0) ||
                     (it.startAddress >= bss_start && it.endAddress <= bss_end)))
                {
                    _bssSegments.push_back(it);
                }
            }

            if (it.endAddress >= (_elfBase + _loadSize))
                break;
        }

        // read all dynamics
        for (auto &phdr : _phdrs)
        {
            if (phdr.p_type == PT_DYNAMIC)
            {
                if (phdr.p_vaddr == 0 || phdr.p_memsz == 0)
                    break;
                if (!KittyMemory::getAddressMap(_loadBias + phdr.p_vaddr, maps).readable)
                    break;
                if (!KittyMemory::getAddressMap((_loadBias + phdr.p_vaddr) + phdr.p_memsz - 1, maps).readable)
                    break;

                _dynamic = _loadBias + phdr.p_vaddr;

                std::vector<KT_ElfW(Dyn)> dyn_buff(phdr.p_memsz / sizeof(KT_ElfW(Dyn)));
                memcpy(&dyn_buff[0], (const void *)_dynamic, phdr.p_memsz);

                for (auto &dyn : dyn_buff)
                {
                    if (dyn.d_tag == DT_NULL)
                        break;

                    // set required dynamics for symbol lookup
                    switch (dyn.d_tag)
                    {
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

                break;
            }
        }

        auto fix_table_address = [&](uintptr_t &table_addr) {
            if (table_addr && table_addr < _loadBias)
                table_addr += _loadBias;

            if (!KittyMemory::getAddressMap(table_addr, maps).readable)
                table_addr = 0;
        };

        fix_table_address(_stringTable);
        fix_table_address(_symbolTable);
        fix_table_address(_elfHashTable);
        fix_table_address(_gnuHashTable);

        _filepath = elfBaseMap.pathname;
        _realpath = elfBaseMap.pathname;
        if (!elfBaseMap.pathname.empty() && elfBaseMap.offset != 0)
        {
            std::string inZipPath =
                KittyUtils::Zip::GetFileInfoByDataOffset(elfBaseMap.pathname, elfBaseMap.offset).fileName;
            if (!inZipPath.empty())
            {
                _realpath += '!';
                _realpath += inZipPath;
            }
        }
    }

    ElfScanner::ElfScanner(const kitty_soinfo_t &soinfo, const std::vector<KittyMemory::ProcMap> &maps)
    {
        _elfBase = 0;
        _ehdr = {};
        _phdr = 0;
        _loads = 0;
        _loadBias = 0;
        _loadSize = 0;
        _dynamic = 0;
        _stringTable = 0;
        _symbolTable = 0;
        _elfHashTable = 0;
        _gnuHashTable = 0;
        _strsz = 0;
        _syment = 0;
        _fixedBySoInfo = false;
        _dsymbols_init = false;

        _elfBase = soinfo.base;
        _phdr = soinfo.phdr;
        _loadBias = soinfo.bias;
        _loadSize = soinfo.size;
        _dynamic = soinfo.dyn;
        _stringTable = soinfo.strtab;
        _symbolTable = soinfo.symtab;
        _strsz = soinfo.strsz;
        _syment = sizeof(KT_ElfW(Sym));
        _filepath = soinfo.path;
        _realpath = soinfo.realpath;

        bool isLinker = KittyUtils::String::EndsWith(soinfo.path, "/linker") ||
                        KittyUtils::String::EndsWith(soinfo.path, "/linker64");
        if (!isLinker && (_elfBase == 0 || _loadSize == 0 || _loadBias == 0 || _phdr == 0 || _dynamic == 0 ||
                          _stringTable == 0 || _symbolTable == 0))
        {
            KITTY_LOGD("ElfScanner: Invalid soinfo!");
            KITTY_LOGD("ElfScanner: elfBase: %p | bias: %p | phdr: %p | dyn: %p | strtab=%p | symtab=%p | strsz=%p | "
                       "syment=%p",
                       (void *)_elfBase, (void *)_loadBias, (void *)_phdr, (void *)_dynamic, (void *)_stringTable,
                       (void *)_symbolTable, (void *)_strsz, (void *)_syment);
            *this = ElfScanner();
            return;
        }

        // fix for linker
        if (_elfBase == 0)
            _elfBase = KittyMemory::getAddressMap(soinfo.bias, maps).startAddress;
        if (_elfBase == 0)
            _elfBase = KittyMemory::getAddressMap(soinfo.phdr, maps).startAddress;
        if (_elfBase == 0)
            _elfBase = KittyMemory::getAddressMap(soinfo.dyn, maps).startAddress;
        if (_elfBase == 0)
            _elfBase = KittyMemory::getAddressMap(soinfo.symtab, maps).startAddress;
        if (_elfBase == 0)
            _elfBase = KittyMemory::getAddressMap(soinfo.strtab, maps).startAddress;

        // verify address
        auto elfBaseMap = KittyMemory::getAddressMap(_elfBase, maps);
        if (!elfBaseMap.isValid() || !elfBaseMap.readable || _elfBase != elfBaseMap.startAddress)
        {
            KITTY_LOGD("ElfScanner: Invalid base(%p) for soinfo(%p)", (void *)_elfBase, (void *)soinfo.ptr);
            *this = ElfScanner();
            return;
        }

        // check if header is corrupted
        // some games like farlight have corrupted header and needs to be fixed by soinfo
        if (!isLinker && (memcmp(_ehdr.e_ident, "\177ELF", 4) != 0 || _ehdr.e_ident[EI_CLASS] != KT_ELF_EICLASS ||
                          _ehdr.e_ident[EI_DATA] != ELFDATA2LSB || _ehdr.e_ident[EI_VERSION] != EV_CURRENT ||
                          (_ehdr.e_type != ET_EXEC && _ehdr.e_type != ET_DYN) ||
                          _ehdr.e_ehsize != sizeof(KT_ElfW(Ehdr)) || _ehdr.e_phentsize != sizeof(KT_ElfW(Phdr)) ||
                          _ehdr.e_phnum != soinfo.phnum || _ehdr.e_phoff != (soinfo.phdr - soinfo.base)))
        {
            KITTY_LOGD("ElfScanner: soinfo(%p) has corrupted header, fixing by soinfo...", (void *)soinfo.ptr);

            _ehdr.e_ident[EI_MAG0] = 0x7F;
            _ehdr.e_ident[EI_MAG1] = 'E';
            _ehdr.e_ident[EI_MAG2] = 'L';
            _ehdr.e_ident[EI_MAG3] = 'F';
            _ehdr.e_ident[EI_CLASS] = KT_ELF_EICLASS;
            _ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
            _ehdr.e_ident[EI_VERSION] = EV_CURRENT;
            _ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;
            _ehdr.e_ident[EI_ABIVERSION] = 0;

            _ehdr.e_type = ET_DYN;
            _ehdr.e_machine = soinfo.e_machine;
            _ehdr.e_version = EV_CURRENT;
            _ehdr.e_entry = 0;
            _ehdr.e_phoff = soinfo.phdr ? (soinfo.phdr - soinfo.base) : 0;
            _ehdr.e_phnum = soinfo.phnum;
            _ehdr.e_ehsize = sizeof(KT_ElfW(Ehdr));
            _ehdr.e_phentsize = sizeof(KT_ElfW(Phdr));
            _ehdr.e_shoff = 0;
            _ehdr.e_shentsize = sizeof(KT_ElfW(Shdr));
            _ehdr.e_shnum = 0;
            _ehdr.e_shstrndx = 0;
            _ehdr.e_flags = 0;

            _fixedBySoInfo = true;
        }

        // fix for linker
        if (_phdr == 0)
            _phdr = _elfBase + _ehdr.e_phoff;

        auto phdrMap = KittyMemory::getAddressMap(_phdr, maps);
        if (!phdrMap.readable || phdrMap.startAddress < _elfBase ||
            (_loadSize && phdrMap.endAddress > (_elfBase + _loadSize)))
        {
            KITTY_LOGD("ElfScanner: Invalid phdr(%p) for soinfo(%p).", (void *)_phdr, (void *)soinfo.ptr);
            *this = ElfScanner();
            return;
        }

        if (!isLinker)
        {
            auto dynMap = KittyMemory::getAddressMap(_dynamic, maps);
            if (!(dynMap.readable && dynMap.startAddress >= _elfBase && dynMap.endAddress <= (_elfBase + _loadSize)))
            {
                KITTY_LOGD("ElfScanner: Invalid dyn(%p) for soinfo(%p).", (void *)_dynamic, (void *)soinfo.ptr);
                *this = ElfScanner();
                return;
            }
        }

        // fix for ldplayer
        auto biasMap = KittyMemory::getAddressMap(_loadBias, maps);
        if (!(biasMap.readable && biasMap.startAddress >= _elfBase && biasMap.endAddress <= (_elfBase + _loadSize)))
        {
            KITTY_LOGD("ElfScanner: Invalid bias(%p) for soinfo(%p).", (void *)_loadBias, (void *)soinfo.ptr);
            _loadBias = 0;
        }

        uintptr_t min_vaddr = UINTPTR_MAX, max_vaddr = 0;
        uintptr_t load_vaddr = 0, load_memsz = 0, load_filesz = 0;
        for (KT_ElfW(Half) i = 0; i < _ehdr.e_phnum; i++)
        {
            if (!KittyMemory::getAddressMap(_phdr + (i * _ehdr.e_phentsize), maps).readable)
                continue;

            KT_ElfW(Phdr) phdr_entry = {};
            memcpy(&phdr_entry, (const void *)(_phdr + (i * _ehdr.e_phentsize)), _ehdr.e_phentsize);
            _phdrs.push_back(phdr_entry);

            if (phdr_entry.p_type == PT_LOAD)
            {
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

        if (!_loads)
        {
            KITTY_LOGD("ElfScanner: No loads entry for ELF (%p).", (void *)_elfBase);
            *this = ElfScanner();
            return;
        }

        if (!max_vaddr)
        {
            KITTY_LOGD("ElfScanner: Failed to find max_vaddr for ELF (%p).", (void *)_elfBase);
            *this = ElfScanner();
            return;
        }

        min_vaddr = KT_PAGE_START(min_vaddr);
        max_vaddr = KT_PAGE_END(max_vaddr);

        // fix for linker
        {
            if (_loadBias == 0)
                _loadBias = _elfBase - min_vaddr;

            if (_loadSize == 0)
                _loadSize = max_vaddr - min_vaddr;
        }

        uintptr_t seg_start = load_vaddr + _loadBias;
        uintptr_t seg_mem_end = KT_PAGE_END((seg_start + load_memsz));
        uintptr_t seg_file_end = KT_PAGE_END((seg_start + load_filesz));
        uintptr_t bss_start = 0, bss_end = 0;
        if (seg_mem_end > seg_file_end)
        {
            bss_start = seg_file_end;
            bss_end = seg_mem_end;
        }

        for (const auto &it : maps)
        {
            if (it.startAddress >= _elfBase && it.endAddress <= (_elfBase + _loadSize))
            {
                if (it.startAddress == _elfBase)
                {
                    _baseSegment = it;
                }

                _segments.push_back(it);

                if (it.readable && !it.executable &&
                    (it.pathname == "[anon:.bss]" || (elfBaseMap.inode != 0 && it.inode == 0) ||
                     (it.startAddress >= bss_start && it.endAddress <= bss_end)))
                {
                    _bssSegments.push_back(it);
                }
            }

            if (it.endAddress >= (_elfBase + _loadSize))
                break;
        }

        // read all dynamics
        for (auto &phdr : _phdrs)
        {
            if (phdr.p_type == PT_DYNAMIC)
            {
                // fix for linker
                if (_dynamic == 0 && phdr.p_vaddr)
                    _dynamic = _loadBias + phdr.p_vaddr;

                if (_dynamic == 0 || phdr.p_memsz == 0)
                    break;
                if (!KittyMemory::getAddressMap(_dynamic, maps).readable)
                    break;
                if (!KittyMemory::getAddressMap(_dynamic + phdr.p_memsz - 1, maps).readable)
                    break;

                std::vector<KT_ElfW(Dyn)> dyn_buff(phdr.p_memsz / sizeof(KT_ElfW(Dyn)));
                memcpy(&dyn_buff[0], (const void *)_dynamic, phdr.p_memsz);

                for (auto &dyn : dyn_buff)
                {
                    if (dyn.d_tag == DT_NULL)
                        break;

                    switch (dyn.d_tag)
                    {
                    case DT_STRTAB:
                        if (_stringTable == 0)
                            _stringTable = dyn.d_un.d_ptr;
                        break;
                    case DT_SYMTAB:
                        if (_symbolTable == 0)
                            _symbolTable = dyn.d_un.d_ptr;
                        break;
                    case DT_STRSZ:
                        if (_strsz == 0)
                            _strsz = dyn.d_un.d_val;
                        break;
                    case DT_SYMENT:
                        _syment = dyn.d_un.d_val;
                        break;
                    case DT_HASH: // hash table
                        _elfHashTable = dyn.d_un.d_ptr;
                        break;
                    case DT_GNU_HASH: // gnu hash table
                        _gnuHashTable = dyn.d_un.d_ptr;
                        break;
                    default:
                        break;
                    }

                    _dynamics.push_back(dyn);
                }

                break;
            }
        }

        auto fix_table_address = [&](uintptr_t &table_addr) {
            if (table_addr && table_addr < _loadBias)
                table_addr += _loadBias;

            if (!KittyMemory::getAddressMap(table_addr, maps).readable)
                table_addr = 0;
        };

        fix_table_address(_symbolTable);
        fix_table_address(_stringTable);
        fix_table_address(_gnuHashTable);
        fix_table_address(_gnuHashTable);
    }

    uintptr_t ElfScanner::findSymbol(const std::string &symbolName) const
    {
        if (_loadBias && _stringTable && _symbolTable && _strsz && _syment)
        {
            auto get_sym_address = [&](const KT_ElfW(Sym) * sym_ent) -> uintptr_t {
                return sym_ent->st_value < _loadBias ? _loadBias + sym_ent->st_value : sym_ent->st_value;
            };

            // try gnu hash first
            if (_gnuHashTable)
            {
                const auto *sym = KittyUtils::Elf::GnuHash::LookupByName(_gnuHashTable, _symbolTable, _stringTable,
                                                                         _syment, _strsz, symbolName.c_str());
                if (sym && sym->st_value)
                {
                    return get_sym_address(sym);
                }
            }

            if (_elfHashTable)
            {
                const auto *sym = KittyUtils::Elf::ElfHash::LookupByName(_elfHashTable, _symbolTable, _stringTable,
                                                                         _syment, _strsz, symbolName.c_str());
                if (sym && sym->st_value)
                {
                    return get_sym_address(sym);
                }
            }
        }

        return 0;
    }

    std::unordered_map<std::string, uintptr_t> ElfScanner::dsymbols()
    {
        if (!_dsymbols_init && _loadBias && !_filepath.empty())
        {
            _dsymbols_init = true;

            auto get_sym_address = [&](const KT_ElfW(Sym) * sym_ent) -> uintptr_t {
                return sym_ent->st_value < _loadBias ? _loadBias + sym_ent->st_value : sym_ent->st_value;
            };

            KittyUtils::Zip::ZipFileMMap mmap_info = {nullptr, 0};
            auto baseSeg = baseSegment();
            if (baseSeg.offset != 0)
            {
                mmap_info = KittyUtils::Zip::MMapFileByDataOffset(_filepath, baseSeg.offset);
            }
            else
            {
                errno = 0;
                int fd = KT_EINTR_RETRY(open(_filepath.c_str(), O_RDONLY));
                if (fd < 0)
                {
                    KITTY_LOGD("Failed to open file <%s> err(%d)", _filepath.c_str(), errno);
                    return _dsymbolsMap;
                }

                struct stat flstats;
                memset(&flstats, 0, sizeof(struct stat));
                int fstat_ret = fstat(fd, &flstats);
                size_t elfSize = flstats.st_size;
                if (fstat_ret == -1 || elfSize <= 0)
                {
                    close(fd);
                    KITTY_LOGD("stat failed for <%s>", _filepath.c_str());
                    return _dsymbolsMap;
                }
                mmap_info.data = mmap(nullptr, elfSize, PROT_READ, MAP_PRIVATE, fd, 0);
                mmap_info.size = elfSize;
                close(fd);
            }

            if (mmap_info.size == 0 || !mmap_info.data || mmap_info.data == ((void *)-1))
            {
                KITTY_LOGD("Failed to mmap <%s>", realPath().c_str());
                return _dsymbolsMap;
            }

            auto cleanup = [&] { munmap(mmap_info.data, mmap_info.size); };

            KT_ElfW(Ehdr) *ehdr = static_cast<KT_ElfW(Ehdr) *>(mmap_info.data);

            if (memcmp(ehdr->e_ident, "\177ELF", 4) != 0)
            {
                KITTY_LOGD("<%s> is not a valid ELF", realPath().c_str());
                cleanup();
                return _dsymbolsMap;
            }

            if (ehdr->e_phoff == 0 || ehdr->e_phentsize == 0 || ehdr->e_phnum == 0 ||
                ehdr->e_phoff + ehdr->e_phnum * sizeof(KT_ElfW(Phdr)) > mmap_info.size)
            {
                KITTY_LOGD("Invalid program header table in <%s>", filePath().c_str());
                cleanup();
                return _dsymbolsMap;
            }

            if (ehdr->e_shoff == 0 || ehdr->e_shentsize == 0 || ehdr->e_shnum == 0 ||
                ehdr->e_shoff + ehdr->e_shnum * sizeof(KT_ElfW(Shdr)) > mmap_info.size)
            {
                KITTY_LOGD("Invalid section header table in <%s>", filePath().c_str());
                cleanup();
                return _dsymbolsMap;
            }

            const KT_ElfW(Shdr) *shdr = reinterpret_cast<KT_ElfW(Shdr) *>(static_cast<char *>(mmap_info.data) +
                                                                          ehdr->e_shoff);
            const KT_ElfW(Shdr) *shstrtab_shdr = shdr + ehdr->e_shstrndx;
            const char *sectionstr = reinterpret_cast<char *>(static_cast<char *>(mmap_info.data) +
                                                              shstrtab_shdr->sh_offset);
            for (uint16_t i = 0; i < ehdr->e_shnum; ++i)
            {
                if (shdr[i].sh_type != SHT_SYMTAB)
                    continue;

                std::string section_name = std::string(reinterpret_cast<const char *>(sectionstr + shdr[i].sh_name));
                if (section_name.compare(".symtab") != 0)
                    continue;

                if ((shdr[i].sh_offset + shdr[i].sh_size) > mmap_info.size || shdr[i].sh_link >= ehdr->e_shnum ||
                    (shdr[shdr[i].sh_link].sh_offset + shdr[shdr[i].sh_link].sh_size) > mmap_info.size)
                    continue;

                const KT_ElfW(Sym) *symtab = reinterpret_cast<KT_ElfW(Sym) *>(static_cast<char *>(mmap_info.data) +
                                                                              shdr[i].sh_offset);
                const size_t symCount = shdr[i].sh_size / shdr[i].sh_entsize;
                const KT_ElfW(Shdr) *strtabShdr = &shdr[shdr[i].sh_link];
                const char *strtab = reinterpret_cast<char *>(static_cast<char *>(mmap_info.data) +
                                                              strtabShdr->sh_offset);

                for (size_t j = 0; j < symCount; ++j)
                {
                    const KT_ElfW(Sym) *curr_sym = &symtab[j];
                    if (!curr_sym || curr_sym->st_name >= strtabShdr->sh_size)
                        continue;

                    if (intptr_t(curr_sym->st_value) <= 0 || intptr_t(curr_sym->st_size) <= 0)
                        continue;

                    if (KT_ELF_ST_TYPE(curr_sym->st_info) != STT_OBJECT &&
                        KT_ELF_ST_TYPE(curr_sym->st_info) != STT_FUNC)
                        continue;

                    std::string sym_str = std::string(reinterpret_cast<const char *>(strtab + curr_sym->st_name));
                    if (!sym_str.empty() && sym_str.data())
                        _dsymbolsMap[sym_str] = get_sym_address(curr_sym);
                }
            }
            cleanup();
        }
        return _dsymbolsMap;
    }

    uintptr_t ElfScanner::findDebugSymbol(const std::string &symbolName)
    {
        const auto &syms = dsymbols();
        auto it = syms.find(symbolName);
        return it != syms.end() ? it->second : 0;
    }

    RegisterNativeFn ElfScanner::findRegisterNativeFn(const std::string &name, const std::string &signature) const
    {
        uintptr_t fn_loc = 0;
        RegisterNativeFn fn;

        if (name.empty() || !isValid())
            return fn;

        std::vector<uintptr_t> string_locs;
        for (auto &it : segments())
        {
            if (it.readable && it.inode != 0)
            {
                uintptr_t string_loc = KittyScanner::findDataFirst(it.startAddress, it.endAddress, name.data(),
                                                                   name.length());
                if (string_loc != 0)
                    string_locs.push_back(string_loc);
            }
        }

        if (string_locs.empty())
        {
            KITTY_LOGD("findRegisterNativeFn: Couldn't find string (%s) "
                       "in selected maps",
                       name.c_str());
            return fn;
        }

        for (auto &it : segments())
        {
            if (it.readable && it.inode != 0)
            {
                for (auto &string_loc : string_locs)
                {
                    uintptr_t string_xref = KittyScanner::findDataFirst(it.startAddress, it.endAddress, &string_loc,
                                                                        sizeof(uintptr_t));
                    if (!string_xref)
                        continue;

                    uintptr_t signature_ptr = *(uintptr_t *)(string_xref + sizeof(uintptr_t));
                    if (signature_ptr == 0)
                        continue;

                    std::vector<char> buf(signature.length() + 1, 0);
                    KittyMemory::syscallMemRead(signature_ptr, buf.data(), buf.size());

                    if (std::string(buf.data()) == signature)
                    {
                        fn_loc = string_xref;
                        break;
                    }
                }
            }
        }

        if (fn_loc != 0)
        {
            memcpy(&fn, (void *)fn_loc, sizeof(RegisterNativeFn));
        }

        return fn;
    }

    bool ElfScanner::dumpToDisk(const std::string &destination) const
    {
        bool dumped = (isValid() && KittyMemory::dumpMemToDisk(_elfBase, _loadSize, destination));
        if (dumped && _fixedBySoInfo)
        {
            KittyIOFile destIO(destination, O_WRONLY);
            destIO.Open();
            KT_ElfW(Ehdr) fixedHdr = header();
            destIO.Write(0, &fixedHdr, sizeof(fixedHdr));
            destIO.Close();
        }
        return dumped;
    }

    ElfScanner &ElfScanner::getProgramElf()
    {
        static ElfScanner progElf{};
        if (!progElf.isValid() || !progElf.dynamic())
        {
            const char *path = "/proc/self/exe";
            char exePath[0xff] = {0};
            errno = 0;
            int ret = int(KT_EINTR_RETRY(readlink(path, exePath, 0xff)));
            if (ret == -1)
            {
                int err = errno;
                KITTY_LOGE("Failed to readlink \"%s\", error(%d): %s.", path, err, strerror(err));
                return progElf;
            }

            const auto allMaps = KittyMemory::getAllMaps();
            const auto maps = KittyMemory::getMaps(KittyMemory::EProcMapFilter::Equal, exePath, allMaps);
            for (const auto &it : maps)
            {
                if (!it.readable || it.writeable)
                    continue;

                progElf = ElfScanner(it.startAddress, allMaps);
                if (progElf.isValid() && progElf.dynamic())
                    break;
            }
        }
        return progElf;
    }

    std::vector<ElfScanner> ElfScanner::getAllELFs(EScanElfType type, EScanElfFilter filter)
    {
        static std::mutex mtx;
        std::lock_guard<std::mutex> lock(mtx);

        static std::unordered_map<uintptr_t, ElfScanner> cached_elfs;
        std::vector<ElfScanner> elfs;

        auto maps = KittyMemory::getAllMaps();
        if (maps.empty())
        {
            KITTY_LOGD("getAllELFs: Failed to get process maps.");
            return elfs;
        }

        std::vector<uintptr_t> invalid_keys;
        for (auto &it : cached_elfs)
        {
            if (it.first && !KittyMemory::getAddressMap(it.first, maps).readable)
            {
                invalid_keys.push_back(it.first);
            }
        }

        for (auto &it : invalid_keys)
        {
            cached_elfs.erase(it);
        }

        const auto progMachine = getProgramElf().header().e_machine;
        static auto eMachineCheck = [](EScanElfType type, int a, int b) -> bool {
            return a == 0 || b == 0 || type == EScanElfType::Any || (type == EScanElfType::Native && a == b) ||
                   (type == EScanElfType::Emulated && a != b);
        };

        const bool isAppFilter = filter == EScanElfFilter::App;
        const bool isSysFilter = filter == EScanElfFilter::System;

        unsigned long lastElfNode = 0;

        for (const auto &it : maps)
        {
#ifdef __LP64__
            if (it.startAddress >= (0x7fffffffffff-0x1000))
                continue;
#else
            if (it.startAddress >= (0xffffffff-0x1000))
                continue;
#endif

            if (!it.isValid() || !it.readable || it.writeable || it.is_shared ||
                (it.inode != 0 && it.inode == lastElfNode))
                continue;

            if (isAppFilter)
            {
                if (it.inode == 0 || (!KittyUtils::String::StartsWith(it.pathname, "/data/") &&
                                      !KittyUtils::String::StartsWith(it.pathname, "/proc/") &&
                                      !KittyUtils::String::StartsWith(it.pathname, "/memfd:")))
                    continue;
            }
            else if (isSysFilter)
            {
                if ((it.inode == 0 && it.pathname != "[vdso]") ||
                    (!KittyUtils::String::StartsWith(it.pathname, "/system/") &&
                     !KittyUtils::String::StartsWith(it.pathname, "/apex/")))
                    continue;
            }

            if (cached_elfs.size() && cached_elfs.count(it.startAddress) > 0)
            {
                auto elf = cached_elfs[it.startAddress];
                if (elf.filePath() == it.pathname)
                {
                    if (eMachineCheck(type, progMachine, elf.header().e_machine))
                    {
                        elfs.push_back(elf);
                    }
                    lastElfNode = elf.baseSegment().inode;
                    continue;
                }
                else
                {
                    cached_elfs.erase(it.startAddress);
                }
            }

            bool isFile = (!it.pathname.empty() && it.inode != 0);
            if (!isFile && it.pathname != "[vdso]" && !KittyUtils::String::StartsWith(it.pathname, "/memfd:"))
                continue;

            if (it.pathname == "cfi shadow")
                continue;

            if (KittyUtils::String::StartsWith(it.pathname, "/dev/") ||
                KittyUtils::String::StartsWith(it.pathname, "/system/fonts/") ||
                KittyUtils::String::StartsWith(it.pathname, "/data/priv-downloads/") ||
                KittyUtils::String::StartsWith(it.pathname, "/data/misc/"))
                continue;

            if (KittyUtils::String::StartsWith(it.pathname, "/system/etc/") &&
                !KittyUtils::String::EndsWith(it.pathname, ".so"))
                continue;

            if ((KittyUtils::String::StartsWith(it.pathname, "/data/dalvik-cache/") ||
                 KittyUtils::String::StartsWith(it.pathname, "/system/") ||
                 KittyUtils::String::StartsWith(it.pathname, "/apex/com.android.") ||
                 (KittyUtils::String::StartsWith(it.pathname, "/data/app/") &&
                  KittyUtils::String::Contains(it.pathname, "/oat/"))) &&
                (KittyUtils::String::EndsWith(it.pathname, ".jar") ||
                 KittyUtils::String::EndsWith(it.pathname, ".art") ||
                 KittyUtils::String::EndsWith(it.pathname, ".oat") ||
                 KittyUtils::String::EndsWith(it.pathname, ".odex") ||
                 KittyUtils::String::EndsWith(it.pathname, ".dex")))
                continue;

            auto elf = ElfScanner(it.startAddress, maps);
            if (elf.isValid())
            {
                if (eMachineCheck(type, progMachine, elf.header().e_machine))
                {
                    elfs.push_back(elf);
                }
                lastElfNode = elf.baseSegment().inode;
                cached_elfs[it.startAddress] = elf;
            }
        }

        return elfs;
    }

    ElfScanner ElfScanner::findElf(const std::string &path, EScanElfType type, EScanElfFilter filter)
    {
        ElfScanner ret{};

        if (path.empty())
            return ret;

        std::vector<ElfScanner> elfs;
        std::vector<ElfScanner> dyn_elfs;

        const auto allElfs = ElfScanner::getAllELFs(type, filter);
        for (const auto &it : allElfs)
        {
            if (it.isValid() && KittyUtils::String::EndsWith(it.realPath(), path))
            {
                if (it.dynamic() && it.dynamics().size() > 0)
                    dyn_elfs.push_back(it);
                else
                    elfs.push_back(it);
            }
        }

        if (elfs.empty() && dyn_elfs.empty())
            return ret;

        if (dyn_elfs.size() > 0)
        {
            if (dyn_elfs.size() == 1)
                return dyn_elfs[0];

            int nMostSegments = 0;
            for (auto &it : dyn_elfs)
            {
                int numSegments = it.segments().size();
                if (numSegments > nMostSegments)
                {
                    ret = it;
                    nMostSegments = numSegments;
                }
            }
        }
        else if (elfs.size() > 0)
        {
            if (elfs.size() == 1)
                return elfs[0];

            int nMostSegments = 0;
            for (auto &it : elfs)
            {
                int numSegments = it.segments().size();
                if (numSegments > nMostSegments)
                {
                    ret = it;
                    nMostSegments = numSegments;
                }
            }
        }

        return ret;
    }

    std::vector<std::pair<uintptr_t, ElfScanner>> ElfScanner::findSymbolAll(const std::string &symbolName,
                                                                            EScanElfType type, EScanElfFilter filter)
    {
        std::vector<std::pair<uintptr_t, ElfScanner>> ret{};

        auto elfs = getAllELFs(type, filter);
        for (auto &it : elfs)
        {
            uintptr_t sym = it.findSymbol(symbolName);
            if (sym != 0)
            {
                ret.emplace_back(sym, it);
            }
        }

        return ret;
    }

    LinkerScanner::LinkerScanner(uintptr_t linkerBase) : ElfScanner(linkerBase)
    {
        memset(&_linker_syms, 0, sizeof(_linker_syms));
        memset(&_soinfo_offsets, 0, sizeof(_soinfo_offsets));
        _init = false;

        if (!isValid())
            return;

        init();
    }

    LinkerScanner::LinkerScanner(const ElfScanner &linkerElf) : ElfScanner(linkerElf)
    {
        memset(&_linker_syms, 0, sizeof(_linker_syms));
        memset(&_soinfo_offsets, 0, sizeof(_soinfo_offsets));
        _init = false;

        if (!isValid())
            return;

        init();
    }

    bool LinkerScanner::init()
    {
        if (!isValid())
            return false;

        if (_init)
            return true;

        for (const auto &sym : dsymbols())
        {
            if (KittyUtils::String::StartsWith(sym.first, "__dl__ZL6solist"))
            {
                _linker_syms.solist = sym.second;
                continue;
            }
            if (KittyUtils::String::StartsWith(sym.first, "__dl__ZL6somain"))
            {
                _linker_syms.somain = sym.second;
                continue;
            }
            if (KittyUtils::String::StartsWith(sym.first, "__dl__ZL6sonext"))
            {
                _linker_syms.sonext = sym.second;
                continue;
            }
            if (_linker_syms.solist && _linker_syms.somain && _linker_syms.sonext)
                break;
        }

        if (!(_linker_syms.solist && _linker_syms.somain && _linker_syms.sonext))
        {
            return false;
        }

        KITTY_LOGD("solist(%zx) | somain(%zx) | sonext(%zx)", solist(), somain(), sonext());

        auto maps = KittyMemory::getAllMaps();

        uintptr_t solist_ptr = solist();
        std::vector<char> solist_buf(KT_SOINFO_BUFFER_SZ, 0);
        for (size_t i = 0; i < solist_buf.size(); i += sizeof(uintptr_t))
        {
            if (KittyMemory::getAddressMap(solist_ptr + i, maps).readable)
            {
                memcpy((void *)(solist_buf.data() + i), (const void *)(solist_ptr + i), sizeof(uintptr_t));
            }
        }

        std::vector<char> si_buf(KT_SOINFO_BUFFER_SZ, 0);
        uintptr_t somain_ptr = (somain() ? somain() : sonext());
        for (size_t i = 0; i < si_buf.size(); i += sizeof(uintptr_t))
        {
            if (KittyMemory::getAddressMap(somain_ptr + i, maps).readable)
            {
                memcpy((void *)(si_buf.data() + i), (const void *)(somain_ptr + i), sizeof(uintptr_t));
            }
        }

        ElfScanner si_elf{};
        for (size_t i = 0; i < si_buf.size(); i += sizeof(uintptr_t))
        {
            uintptr_t possible_base = *(uintptr_t *)&si_buf[i];

            auto tmp_map = KittyMemory::getAddressMap(possible_base, maps);
            if (possible_base != tmp_map.startAddress || !tmp_map.isValid() || !tmp_map.readable || tmp_map.writeable ||
                tmp_map.is_shared)
                continue;

            si_elf = ElfScanner(possible_base, maps);
            if (si_elf.isValid())
            {
                _soinfo_offsets.base = i;
                break;
            }
        }

        KITTY_LOGD("soinfo_base(%zx)", _soinfo_offsets.base);

        if (_soinfo_offsets.base == 0)
            return false;

        for (size_t i = 0; i < si_buf.size(); i += sizeof(uintptr_t))
        {
            uintptr_t value = *(uintptr_t *)&si_buf[i];

            if (value == si_elf.phdr())
                _soinfo_offsets.phdr = i;
            if (value == si_elf.programHeaders().size())
                _soinfo_offsets.phnum = i;
            else if (value == si_elf.loadSize() ||
                     value == (si_elf.loadSize() + KittyMemory::getAddressMap(si_elf.end(), maps).length))
                _soinfo_offsets.size = i;
            else if (value == si_elf.dynamic())
                _soinfo_offsets.dyn = i;
            else if (value == si_elf.stringTable())
                _soinfo_offsets.strtab = i;
            else if (value == si_elf.symbolTable())
                _soinfo_offsets.symtab = i;
            else if (value == si_elf.loadBias() && i != _soinfo_offsets.base)
                _soinfo_offsets.bias = i;
            else if (value == si_elf.stringTableSize())
                _soinfo_offsets.strsz = i;
        }

        KITTY_LOGD("soinfo_bias(%zx) | soinfo_size(%zx)", _soinfo_offsets.bias, _soinfo_offsets.size);
        KITTY_LOGD("soinfo_phdr(%zx, %zx) | soinfo_dyn(%zx)", _soinfo_offsets.phdr, _soinfo_offsets.phnum,
                   _soinfo_offsets.dyn);
        KITTY_LOGD("soinfo_strtab(%zx, %zx) | soinfo_symtab(%zx)", _soinfo_offsets.strtab, _soinfo_offsets.strsz,
                   _soinfo_offsets.symtab);

        if (!(_soinfo_offsets.size && _soinfo_offsets.bias && _soinfo_offsets.dyn && _soinfo_offsets.symtab &&
              _soinfo_offsets.strtab))
        {
            return false;
        }

        for (size_t i = 0; i < solist_buf.size(); i += sizeof(uintptr_t))
        {
            uintptr_t possible_next = *(uintptr_t *)&solist_buf[i];

            if (!KittyMemory::getAddressMap(possible_next + _soinfo_offsets.base, maps).readable)
                continue;

            uintptr_t possible_base = *(uintptr_t *)(possible_next + _soinfo_offsets.base);
            auto tmp_map = KittyMemory::getAddressMap(possible_base, maps);
            if (!tmp_map.isValid() || !tmp_map.readable || tmp_map.writeable || tmp_map.is_shared)
                continue;

            auto tmp_elf = ElfScanner(possible_base, maps);
            if (tmp_elf.isValid())
            {
                if (!KittyMemory::getAddressMap(possible_next + _soinfo_offsets.size, maps).readable)
                    continue;

                size_t possible_size = *(uintptr_t *)(possible_next + _soinfo_offsets.size);
                if (possible_size == tmp_elf.loadSize() ||
                    possible_size == (tmp_elf.loadSize() + KittyMemory::getAddressMap(tmp_elf.end(), maps).length))
                {
                    _soinfo_offsets.next = i;
                    break;
                }
            }
        }

        KITTY_LOGD("soinfo_sonext(%zx)", _soinfo_offsets.next);

        _init = _soinfo_offsets.next != 0;
        return _init;
    }

    std::vector<kitty_soinfo_t> LinkerScanner::allSoInfo() const
    {
        std::vector<kitty_soinfo_t> infos{};

        if (!isValid() || !_init)
            return infos;

        auto maps = KittyMemory::getAllMaps();
        uintptr_t si = solist();
        while (si && KittyMemory::getAddressMap(si, maps).readable)
        {
            kitty_soinfo_t info = infoFromSoInfo_(si, maps);
            infos.push_back(info);

            si = *(uintptr_t *)(si + _soinfo_offsets.next);
        }
        return infos;
    }

    kitty_soinfo_t LinkerScanner::findSoInfo(const std::string &name) const
    {
        const auto list = allSoInfo();
        for (const auto &it : list)
        {
            if (KittyUtils::String::EndsWith(it.realpath, name))
            {
                return it;
            }
        }
        return {};
    }

    kitty_soinfo_t LinkerScanner::infoFromSoInfo_(uintptr_t si, const std::vector<KittyMemory::ProcMap> &maps) const
    {
        kitty_soinfo_t info{};

        if (!_init)
            return info;

        info.ptr = si;
        info.base = *(uintptr_t *)(si + _soinfo_offsets.base);
        info.size = *(uintptr_t *)(si + _soinfo_offsets.size);
        info.phdr = *(uintptr_t *)(si + _soinfo_offsets.phdr);
        info.phnum = *(uintptr_t *)(si + _soinfo_offsets.phnum);
        info.dyn = *(uintptr_t *)(si + _soinfo_offsets.dyn);
        info.strtab = *(uintptr_t *)(si + _soinfo_offsets.strtab);
        info.symtab = *(uintptr_t *)(si + _soinfo_offsets.symtab);
        info.strsz = _soinfo_offsets.strsz ? *(uintptr_t *)(si + _soinfo_offsets.strsz) : 0;
        info.bias = *(uintptr_t *)(si + _soinfo_offsets.bias);
        info.next = *(uintptr_t *)(si + _soinfo_offsets.next);
        info.e_machine = header().e_machine;

        uintptr_t start_map_addr = info.base;
        if (start_map_addr == 0)
            start_map_addr = info.base;
        if (start_map_addr == 0)
            start_map_addr = info.bias;
        if (start_map_addr == 0)
            start_map_addr = info.phdr;
        if (start_map_addr == 0)
            start_map_addr = info.dyn;
        if (start_map_addr == 0)
            start_map_addr = info.strtab;
        if (start_map_addr == 0)
            start_map_addr = info.symtab;

        auto si_map = KittyMemory::getAddressMap(start_map_addr, maps);
        if (si_map.isValid())
        {
            info.path = si_map.pathname;
            info.realpath = si_map.pathname;
            if (si_map.offset != 0)
            {
                std::string inZipPath =
                    KittyUtils::Zip::GetFileInfoByDataOffset(si_map.pathname, si_map.offset).fileName;
                if (!inZipPath.empty())
                {
                    info.realpath += '!';
                    info.realpath += inZipPath;
                }
            }
        }

        return info;
    }

    bool NativeBridgeScanner::init()
    {
        if (_init)
            return true;

        _nbElf = ElfScanner::findElf("/libnativebridge.so", EScanElfType::Native, EScanElfFilter::System);
        if (!_nbElf.isValid())
        {
            KITTY_LOGD("NativeBridgeScanner: Failed to find libnativebrdge.so");
            return false;
        }

        _nbImplElf = ElfScanner::findElf("/libhoudini.so", EScanElfType::Native, EScanElfFilter::System);
        if (_nbImplElf.isValid())
            _isHoudini = true;
        else
            _nbImplElf = ElfScanner::findElf("/libndk_translation.so", EScanElfType::Native, EScanElfFilter::System);

        if (!_nbImplElf.isValid())
        {
            KITTY_LOGD("NativeBridgeScanner: Failed to find nativebridge implementation");
            return false;
        }

        _nbItf = _nbImplElf.findSymbol("NativeBridgeItf");
        if (_nbItf == 0)
        {
            KITTY_LOGD("NativeBridgeScanner: Failed to find export NativeBridgeItf");
            return false;
        }

        _nbItf_data.version = *(int *)_nbItf;
        switch (_nbItf_data.version)
        {
        case 2: // SIGNAL_VERSION
            _nbItf_data_size = sizeof(uintptr_t) * 8;
            break;
        case 3: // NAMESPACE_VERSION
            _nbItf_data_size = sizeof(uintptr_t) * 15;
            break;
        case 4: // VENDOR_NAMESPACE_VERSION
            _nbItf_data_size = sizeof(uintptr_t) * 16;
            break;
        case 5: // RUNTIME_NAMESPACE_VERSION
            _nbItf_data_size = sizeof(uintptr_t) * 17;
            break;
        case 6: // PRE_ZYGOTE_FORK_VERSION
            _nbItf_data_size = sizeof(uintptr_t) * 18;
            break;
        case 7: // CRITICAL_NATIVE_SUPPORT_VERSION
            _nbItf_data_size = sizeof(uintptr_t) * 19;
            break;
        case 8: // IDENTIFY_NATIVELY_BRIDGED_FUNCTION_POINTERS_VERSION
            _nbItf_data_size = sizeof(uintptr_t) * 21;
            break;
        default:
            KITTY_LOGD("NativeBridgeScanner: Unsupported nativebridge version (%d)", _nbItf_data.version);
            return false;
        }

        KITTY_LOGD("NativeBridgeScanner: Using nativebridge version (%d), data size (%p)", _nbItf_data.version,
                   (void *)_nbItf_data_size);

        memcpy(&_nbItf_data, (const void *)(_nbItf), _nbItf_data_size);

        *(uintptr_t *)&fnNativeBridgeInitialized = _nbElf.findSymbol("NativeBridgeInitialized");
        if (fnNativeBridgeInitialized == nullptr)
            *(uintptr_t *)&fnNativeBridgeInitialized = _nbElf.findSymbol("_ZN7android23NativeBridgeInitializedEv");

        // replace for nb v2
        if (_nbItf_data.version < 3)
        {
            uintptr_t pLoadLibrary = _nbElf.findSymbol("NativeBridgeLoadLibrary");
            if (pLoadLibrary == 0)
                pLoadLibrary = _nbElf.findSymbol("_ZN7android23NativeBridgeLoadLibraryEPKci");

            uintptr_t pGetTrampoline = _nbElf.findSymbol("NativeBridgeGetTrampoline");
            if (pGetTrampoline == 0)
                pGetTrampoline = _nbElf.findSymbol("_ZN7android25NativeBridgeGetTrampolineEPvPKcS2_j");

            if (pLoadLibrary != 0)
                *(uintptr_t *)&_nbItf_data.loadLibrary = pLoadLibrary;

            if (pGetTrampoline != 0)
                *(uintptr_t *)&_nbItf_data.getTrampoline = pGetTrampoline;
        }

        _sodlElf = ElfScanner::findElf("/libdl.so", EScanElfType::Emulated, EScanElfFilter::System);
        if (!_sodlElf.isValid())
        {
            KITTY_LOGD("NativeBridgeScanner: Failed to find emulated libdl.so");
            return false;
        }

        struct
        {
            uintptr_t phdr = 0;
            size_t phnum = 0;
        } data;

	data.phdr = _sodlElf.phdr();
	data.phnum = _sodlElf.programHeaders().size();

        KITTY_LOGD("NativeBridgeScanner: sodl phdr { %p, %zu }", (void *)(data.phdr), data.phnum);

        auto maps = KittyMemory::getAllMaps();

        // search in bss frst
        for (auto &it : _nbImplElf.bssSegments())
        {
            _sodl = findDataFirst(it.startAddress, it.endAddress, &data, sizeof(data));
            if (_sodl)
            {
                KITTY_LOGD("NativeBridgeScanner: Found sodl->phdr ref (%p) at %s", (void *)_sodl,
                           it.toString().c_str());
                break;
            }
        }

        if (_sodl == 0)
        {
            // search in read-only "[anon:Mem_" or "[anon:linker_alloc]"
            for (auto &it : maps)
            {
                if (!it.is_private || !it.is_ro || it.inode != 0)
                    continue;

                if (!KittyUtils::String::StartsWith(it.pathname, "[anon:Mem_") && it.pathname != "[anon:linker_alloc]")
                    continue;

                _sodl = findDataFirst(it.startAddress, it.endAddress, &data, sizeof(data));
                if (_sodl)
                {
                    KITTY_LOGD("NativeBridgeScanner: Found sodl->phdr ref (%p) at %s", (void *)_sodl,
                               it.toString().c_str());
                    break;
                }
            }
        }

        if (_sodl == 0)
        {
            KITTY_LOGD("NativeBridgeScanner: Failed to find refs to emulated libdl.so phdr data");
            return false;
        }

        std::vector<char> si_buf(KT_SOINFO_BUFFER_SZ, 0);
        for (size_t i = 0; i < si_buf.size(); i += sizeof(uintptr_t))
        {
            if (KittyMemory::getAddressMap(_sodl + i, maps).readable)
            {
                memcpy((void *)(si_buf.data() + i), (const void *)(_sodl + i), sizeof(uintptr_t));
            }
        }

        for (size_t i = 0; i < si_buf.size(); i += sizeof(uintptr_t))
        {
            uintptr_t possible_next = *(uintptr_t *)&si_buf[i];
            if (!KittyMemory::getAddressMap(possible_next, maps).readable)
                continue;

            std::vector<char> si_buf_inner(KT_SOINFO_BUFFER_SZ, 0);
            for (size_t j = 0; j < si_buf_inner.size(); j += sizeof(uintptr_t))
            {
                if (KittyMemory::getAddressMap(possible_next + j, maps).readable)
                {
                    memcpy((void *)(si_buf_inner.data() + j), (const void *)(possible_next + j), sizeof(uintptr_t));
                }
            }

            ElfScanner si_elf{};
            for (size_t j = 0; j < si_buf_inner.size(); j += sizeof(uintptr_t))
            {
                uintptr_t possible_base = *(uintptr_t *)&si_buf_inner[j];

                auto tmp_map = KittyMemory::getAddressMap(possible_base, maps);
                if (possible_base != tmp_map.startAddress || !tmp_map.isValid() || !tmp_map.readable ||
                    tmp_map.writeable || tmp_map.is_shared)
                    continue;

                si_elf = ElfScanner(possible_base, maps);
                if (si_elf.isValid())
                {
                    _soinfo_offsets.base = j;
                    break;
                }
            }

            if (_soinfo_offsets.base == 0)
                continue;

            for (size_t j = 0; j < si_buf_inner.size(); j += sizeof(uintptr_t))
            {
                uintptr_t value = *(uintptr_t *)&si_buf_inner[j];
                if (value == si_elf.phdr())
                    _soinfo_offsets.phdr = j;
                if (value == si_elf.programHeaders().size())
                    _soinfo_offsets.phnum = j;
                else if (value == si_elf.loadSize() ||
                         value == (si_elf.loadSize() + KittyMemory::getAddressMap(si_elf.end(), maps).length))
                    _soinfo_offsets.size = j;
                else if (value == si_elf.dynamic())
                    _soinfo_offsets.dyn = j;
                else if (value == si_elf.stringTable())
                    _soinfo_offsets.strtab = j;
                else if (value == si_elf.symbolTable())
                    _soinfo_offsets.symtab = j;
                else if (j > _soinfo_offsets.size && value == si_elf.loadBias())
                    _soinfo_offsets.bias = j;
                else if (value == si_elf.stringTableSize())
                    _soinfo_offsets.strsz = j;
            }

            if (_soinfo_offsets.size && _soinfo_offsets.bias && _soinfo_offsets.dyn && _soinfo_offsets.symtab &&
                _soinfo_offsets.strtab)
            {
                // phdr offset might not be 0
                _sodl -= _soinfo_offsets.phdr;
                _soinfo_offsets.next = _soinfo_offsets.phdr + i;
                break;
            }
        }

        KITTY_LOGD("nb_soinfo_base(%zx) | nb_soinfo_size(%zx) | nb_soinfo_bias(%zx)", _soinfo_offsets.base,
                   _soinfo_offsets.size, _soinfo_offsets.bias);
        KITTY_LOGD("nb_soinfo_phdr(%zx, %zx) | nb_soinfo_dyn(%zx)", _soinfo_offsets.phdr, _soinfo_offsets.phnum,
                   _soinfo_offsets.dyn);
        KITTY_LOGD("nb_soinfo_strtab(%zx, %zx) | nb_soinfo_symtab(%zx)", _soinfo_offsets.strtab, _soinfo_offsets.strsz,
                   _soinfo_offsets.symtab);

        KITTY_LOGD("nb_soinfo_next(%zx)", _soinfo_offsets.next);

        _init = _soinfo_offsets.next != 0;
        return _init;
    }

    std::vector<kitty_soinfo_t> NativeBridgeScanner::allSoInfo() const
    {
        std::vector<kitty_soinfo_t> infos{};

        if (!_init)
            return infos;

        auto maps = KittyMemory::getAllMaps();
        uintptr_t si = _sodl;
        while (si && KittyMemory::getAddressMap(si, maps).readable)
        {
            kitty_soinfo_t info = infoFromSoInfo_(si, maps);
            infos.push_back(info);

            si = *(uintptr_t *)(si + _soinfo_offsets.next);
        }
        return infos;
    }

    kitty_soinfo_t NativeBridgeScanner::findSoInfo(const std::string &name) const
    {
        kitty_soinfo_t ret{};
        const auto list = allSoInfo();
        for (const auto &it : list)
        {
            if (KittyUtils::String::EndsWith(it.realpath, name))
            {
                ret = it;
                break;
            }
        }
        return ret;
    }

    kitty_soinfo_t NativeBridgeScanner::infoFromSoInfo_(uintptr_t si,
                                                        const std::vector<KittyMemory::ProcMap> &maps) const
    {
        kitty_soinfo_t info{};

        if (!_init)
            return info;

        info.ptr = si;
        info.base = *(uintptr_t *)(si + _soinfo_offsets.base);
        info.size = *(uintptr_t *)(si + _soinfo_offsets.size);
        info.phdr = *(uintptr_t *)(si + _soinfo_offsets.phdr);
        info.phnum = *(uintptr_t *)(si + _soinfo_offsets.phnum);
        info.dyn = *(uintptr_t *)(si + _soinfo_offsets.dyn);
        info.strtab = *(uintptr_t *)(si + _soinfo_offsets.strtab);
        info.symtab = *(uintptr_t *)(si + _soinfo_offsets.symtab);
        info.strsz = _soinfo_offsets.strsz ? *(uintptr_t *)(si + _soinfo_offsets.strsz) : 0;
        info.bias = *(uintptr_t *)(si + _soinfo_offsets.bias);
        info.next = *(uintptr_t *)(si + _soinfo_offsets.next);
        info.e_machine = _sodlElf.header().e_machine;

        uintptr_t start_map_addr = info.base;
        if (start_map_addr == 0)
            start_map_addr = info.base;
        if (start_map_addr == 0)
            start_map_addr = info.bias;
        if (start_map_addr == 0)
            start_map_addr = info.phdr;
        if (start_map_addr == 0)
            start_map_addr = info.dyn;
        if (start_map_addr == 0)
            start_map_addr = info.strtab;
        if (start_map_addr == 0)
            start_map_addr = info.symtab;

        auto si_map = KittyMemory::getAddressMap(start_map_addr, maps);
        if (si_map.isValid())
        {
            info.path = si_map.pathname;
            info.realpath = si_map.pathname;
            if (si_map.offset != 0)
            {
                std::string inZipPath =
                    KittyUtils::Zip::GetFileInfoByDataOffset(si_map.pathname, si_map.offset).fileName;
                if (!inZipPath.empty())
                {
                    info.realpath += '!';
                    info.realpath += inZipPath;
                }
            }
        }

        return info;
    }

    void *NativeBridgeLinker::dlopen(const std::string &path, int flags)
    {
#if !defined(__x86_64__) && !defined(__i386__)
        return nullptr;
#endif
        auto &nb = NativeBridgeScanner::Get();
        auto nbData = nb.nbItfData();

        if (path.empty() || !nb.init())
            return nullptr;

        if (nbData.version < 2)
        {
            KITTY_LOGD("nb_dlopen: nativebridge version (%d) is not supported", nbData.version);
            return nullptr;
        }

        if (nb.fnNativeBridgeInitialized && !nb.fnNativeBridgeInitialized())
        {
            KITTY_LOGD("nb_dlopen: nativebridge is not initialized");
            return nullptr;
        }

        /*if ((nbData..version == 2 && !nbData.isSupported(path.c_str())) ||
            !nbData.isPathSupported(path.c_str()))
        {
            KITTY_LOGD("nb_dlopen: path not supported (%s)", path.c_str());
            return nullptr;
        }*/

        if (nbData.version == 2)
            return nbData.loadLibrary(path.c_str(), flags);

        void *default_ns = nullptr;
        if (nb.isHoudini())
        {
            default_ns = (void *)uintptr_t(nbData.version >= 5 ? 5 : 3);
            if (nbData.version >= 5)
            {
                uintptr_t tmp_ns = (uintptr_t)nbData.getExportedNamespace("classloader-namespace");
                if (tmp_ns > 0 && tmp_ns <= 25)
                    default_ns = (void *)tmp_ns;
            }
        }
        else
        {
            if (nbData.getExportedNamespace)
                default_ns = nbData.getExportedNamespace("default");
            else if (nbData.getVendorNamespace)
                default_ns = nbData.getVendorNamespace();
        }

        if (!default_ns)
        {
            KITTY_LOGD("nb_dlopen: Failed to find default namespace");
            return nullptr;
        }

        return nbData.loadLibraryExt(path.c_str(), flags, default_ns);
    }

    void *NativeBridgeLinker::dlsym(void *handle, const std::string &sym_name)
    {
#if !defined(__x86_64__) && !defined(__i386__)
        return nullptr;
#endif
        auto &nb = NativeBridgeScanner::Get();
        auto nbData = nb.nbItfData();

        if (!handle || !nb.init())
            return nullptr;

        if (nbData.version < 28)
        {
            KITTY_LOGD("nb_dlsym: nativebridge version (%d) is not supported", nbData.version);
            return nullptr;
        }

        if (nb.fnNativeBridgeInitialized && !nb.fnNativeBridgeInitialized())
        {
            KITTY_LOGD("nb_dlsym: nativebridge is not initialized");
            return nullptr;
        }

        if (nbData.version < 7)
        {
            return nbData.getTrampoline(handle, sym_name.c_str(), nullptr, 0);
        }

        return nbData.getTrampolineWithJNICallType(handle, sym_name.c_str(), nullptr, 0, KT_JNICallTypeRegular);
    }

    const char *NativeBridgeLinker::dlerror()
    {
#if !defined(__x86_64__) && !defined(__i386__)
        return nullptr;
#endif
        auto &nb = NativeBridgeScanner::Get();
        auto nbData = nb.nbItfData();

        if (nbData.version < 3)
        {
            KITTY_LOGD("nb_dlerror: nativebridge version (%d) is not supported", nbData.version);
            return nullptr;
        }

        if (nb.fnNativeBridgeInitialized && !nb.fnNativeBridgeInitialized())
        {
            KITTY_LOGD("nb_dlerror: nativebridge is not initialized");
            return nullptr;
        }

        return nbData.getError ? nbData.getError() : nullptr;
    }

    bool NativeBridgeLinker::dladdr(const void *addr, kitty_soinfo_t *info)
    {
        for (const auto &it : NativeBridgeScanner::Get().allSoInfo())
        {
            if (uintptr_t(addr) >= it.base && uintptr_t(addr) < (it.base + it.size))
            {
                if (info)
                    *info = it;
                return true;
            }
        }

        return false;
    }

    void NativeBridgeLinker::dl_iterate_phdr(const std::function<bool(const kitty_soinfo_t *)> &callback)
    {
        if (!callback)
            return;

        for (const auto &it : NativeBridgeScanner::Get().allSoInfo())
        {
            if (callback(&it))
                break;
        }
    }

#endif // __ANDROID__

} // namespace KittyScanner
