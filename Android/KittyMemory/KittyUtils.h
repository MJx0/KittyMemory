#pragma once

#include <string>
#include <cstdint>
#include <algorithm>
#include <sstream>
#include <iomanip>

#include <elf.h>
#ifdef __LP64__
#define ELFCLASS_BITS_ 64
#define ELF_EICLASS_ 2
#define ElfW_(x) Elf64_##x
#define ELFW_(x) ELF64_##x
#else
#define ELFCLASS_BITS_ 32
#define ELF_EICLASS_ 1
#define ElfW_(x) Elf32_##x
#define ELFW_(x) ELF32_##x
#endif

namespace KittyUtils {

    std::string fileNameFromPath(const std::string &filePath);

    void trim_string(std::string &str);
    bool validateHexString(std::string &hex);

    std::string data2Hex(const void *data, const size_t dataLength);
    void dataFromHex(const std::string &in, void *data);

    template <size_t rowSize=8, bool showASCII=true>
    std::string HexDump(const void *address, size_t len)
    {
        if (!address || len == 0 || rowSize == 0)
            return ""; 

        const unsigned char *data = static_cast<const unsigned char *>(address);

        std::stringstream ss;
        ss << std::hex << std::uppercase << std::setfill('0');

        size_t i, j;

        for (i = 0; i < len; i += rowSize)
        {
            // offset
            ss << std::setw(8) << i << ": ";

            // row bytes
            for (j = 0; (j < rowSize) && ((i + j) < len); j++)
                ss << std::setw(2) << static_cast<unsigned int>(data[i + j]) << " ";

            // fill row empty space
            for (; j < rowSize; j++)
                ss << "   ";

            // ASCII
            if (showASCII)
            {
                ss << " ";

                for (j = 0; (j < rowSize) && ((i + j) < len); j++)
                {
                    if (std::isprint(data[i + j]))
                        ss << data[i + j];
                    else
                        ss << '.';
                }
            }

            ss << std::endl;
        }

        return ss.str();
    }

    namespace Elf {
        namespace ElfHash {
            const ElfW_(Sym) *LookupByName(uintptr_t elfhash,
                                           uintptr_t symtab,
                                           uintptr_t strtab,
                                           size_t syment,
                                           size_t strsz,
                                           const char *symbol_name);
        }

        namespace GnuHash {
            const ElfW_(Sym) *LookupByName(uintptr_t gnuhash,
                                           uintptr_t symtab,
                                           uintptr_t strtab,
                                           size_t syment,
                                           size_t strsz,
                                           const char *symbol_name);
        }
    }

}