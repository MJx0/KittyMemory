#pragma once

#include <string>
#include <cstdint>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstdarg>
#include <vector>
#include <utility>
#include <random>

#ifdef __ANDROID__

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

#endif // __ANDROID__

namespace KittyUtils {

#ifdef __ANDROID__
    std::string getExternalStorage();
    int getAndroidVersion();
    int getAndroidSDK();
#endif

    std::string fileNameFromPath(const std::string &filePath);
    std::string fileDirectory(const std::string &filePath);
    std::string fileExtension(const std::string &filePath);

    namespace String
    {
        static inline bool StartsWith(const std::string &str, const std::string &str2)
        {
            return str.length() >= str2.length() && str.compare(0, str2.length(), str2) == 0;
        }
        
        static inline bool Contains(const std::string &str, const std::string &str2)
        {
            return str.length() >= str2.length() && str.find(str2) != std::string::npos;
        }
        
        static inline bool EndsWith(const std::string &str, const std::string &str2)
        {
            return str.length() >= str2.length() && str.compare(str.length() - str2.length(), str2.length(), str2) == 0;
        }
        
        void Trim(std::string &str);

        bool ValidateHex(std::string &hex);

        std::string Fmt(const char *fmt, ...);

        std::string Random(size_t length);
    } // namespace String

    template <typename T>
    T randInt(T min, T max)
    {
        using param_type = typename std::uniform_int_distribution<T>::param_type;

        thread_local static std::mt19937 gen{std::random_device{}()};
        thread_local static std::uniform_int_distribution<T> dist;

        return dist(gen, param_type{min, max});
    }

    template <typename T> std::string data2Hex(const T &data)
    {
      const auto *byteData = reinterpret_cast<const unsigned char *>(&data);
      std::stringstream hexStringStream;

      hexStringStream << std::hex << std::setfill('0');
      for (size_t index = 0; index < sizeof(T); ++index)
        hexStringStream << std::setw(2) << static_cast<int>(byteData[index]);
    
      return hexStringStream.str();
    }

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

#ifdef __ANDROID__

    namespace Elf {
        namespace ElfHash {
            /**
             * Lookup symbol by name in hash table
             * 
             * @elfhash: DT_HASH hash table address
             * @symtab: DT_SYMTAB symbol table address
             * @strtab: DT_STRTAB string table address
             * @syment: DT_SYMENT symbol table entry size address
             * @syment: DT_STRSZ string table size
             *
             * @return ElfSym pointer
             */
            const ElfW_(Sym) *LookupByName(uintptr_t elfhash,
                                           uintptr_t symtab,
                                           uintptr_t strtab,
                                           size_t syment,
                                           size_t strsz,
                                           const char *symbol_name);
        }

        namespace GnuHash {
            /**
             * Lookup symbol by name in gnu hash table
             * 
             * @elfhash: DT_GNU_HASH gnu hash table address
             * @symtab: DT_SYMTAB symbol table address
             * @strtab: DT_STRTAB string table address
             * @syment: DT_SYMENT symbol table entry size address
             * @syment: DT_STRSZ string table size
             *
             * @return ElfSym pointer
             */
            const ElfW_(Sym) *LookupByName(uintptr_t gnuhash,
                                           uintptr_t symtab,
                                           uintptr_t strtab,
                                           size_t syment,
                                           size_t strsz,
                                           const char *symbol_name);
        }
    }

#endif // __ANDROID__

}