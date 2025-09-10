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
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include <inttypes.h>
#include <dirent.h>
#include <mutex>

#define KT_PAGE_SIZE (sysconf(_SC_PAGE_SIZE))

#define KT_PAGE_START(x) (uintptr_t(x) & ~(KT_PAGE_SIZE - 1))
#define KT_PAGE_END(x) (KT_PAGE_START(uintptr_t(x) + KT_PAGE_SIZE - 1))
#define KT_PAGE_OFFSET(x) (uintptr_t(x) - KT_PAGE_START(x))
#define KT_PAGE_LEN(x) (size_t(KT_PAGE_SIZE - KT_PAGE_OFFSET(x)))

#define KT_PAGE_END2(x, len) (KT_PAGE_START((uintptr_t(x) + len) + KT_PAGE_SIZE - 1))
#define KT_PAGE_LEN2(x, len) (KT_PAGE_END2(x, len) - KT_PAGE_START(x))

#define KT_PROT_RWX (PROT_READ | PROT_WRITE | PROT_EXEC)
#define KT_PROT_RX (PROT_READ | PROT_EXEC)
#define KT_PROT_RW (PROT_READ | PROT_WRITE)

#define KITTY_LOG_TAG "KittyMemory"

#ifdef __ANDROID__
#include <android/log.h>

#ifdef kITTYMEMORY_DEBUG
#define KITTY_LOGD(fmt, ...) ((void)__android_log_print(ANDROID_LOG_DEBUG, KITTY_LOG_TAG, fmt, ##__VA_ARGS__))
#else
#define KITTY_LOGD(fmt, ...)                                                                                           \
    do                                                                                                                 \
    {                                                                                                                  \
    } while (0)
#endif

#define KITTY_LOGI(fmt, ...) ((void)__android_log_print(ANDROID_LOG_INFO, KITTY_LOG_TAG, fmt, ##__VA_ARGS__))
#define KITTY_LOGE(fmt, ...) ((void)__android_log_print(ANDROID_LOG_ERROR, KITTY_LOG_TAG, fmt, ##__VA_ARGS__))

#elif __APPLE__
#include <os/log.h>

#ifdef kITTYMEMORY_DEBUG
#define KITTY_LOGD(fmt, ...) os_log(OS_LOG_DEFAULT, "D " KITTY_LOG_TAG ": " fmt, ##__VA_ARGS__)
#else
#define KITTY_LOGD(fmt, ...)                                                                                           \
    do                                                                                                                 \
    {                                                                                                                  \
    } while (0)
#endif

#define KITTY_LOGI(fmt, ...) os_log(OS_LOG_DEFAULT, "I " KITTY_LOG_TAG ": " fmt, ##__VA_ARGS__)
#define KITTY_LOGE(fmt, ...) os_log_error(OS_LOG_DEFAULT, "E " KITTY_LOG_TAG ": " fmt, ##__VA_ARGS__)

#endif

#define KT_EINTR_RETRY(exp)                                                                                            \
    ({                                                                                                                 \
        __typeof__(exp) _rc;                                                                                           \
        do                                                                                                             \
        {                                                                                                              \
            _rc = (exp);                                                                                               \
        } while (_rc == -1 && errno == EINTR);                                                                         \
        _rc;                                                                                                           \
    })

#ifdef __ANDROID__

#include <elf.h>
#ifdef __LP64__
#define KT_ELFCLASS_BITS 64
#define KT_ELF_EICLASS 2
#define KT_ElfW(x) Elf64_##x
#define KT_ELFW(x) ELF64_##x
#else
#define KT_ELFCLASS_BITS 32
#define KT_ELF_EICLASS 1
#define KT_ElfW(x) Elf32_##x
#define KT_ELFW(x) ELF32_##x
#endif
#define KT_ELF_ST_BIND(val) (((unsigned char)(val)) >> 4)
#define KT_ELF_ST_TYPE(val) ((val) & 0xf)
#define KT_ELF_ST_INFO(bind, type) (((bind) << 4) + ((type) & 0xf))
#define KT_ELF_ST_VISIBILITY(o) ((o) & 0x03)

#endif // __ANDROID__

namespace KittyUtils
{

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

        static std::mutex mtx;
        std::lock_guard<std::mutex> lock(mtx);

        static std::mt19937 gen{std::random_device{}()};
        static std::uniform_int_distribution<T> dist;

        return dist(gen, param_type{min, max});
    }

    template <typename T>
    std::string data2Hex(const T &data)
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

    template <size_t rowSize = 8, bool showASCII = true>
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

    namespace Elf
    {
        namespace ElfHash
        {
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
            const KT_ElfW(Sym) * LookupByName(uintptr_t elfhash, uintptr_t symtab, uintptr_t strtab, size_t syment,
                                              size_t strsz, const char *symbol_name);
        } // namespace ElfHash

        namespace GnuHash
        {
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
            const KT_ElfW(Sym) * LookupByName(uintptr_t gnuhash, uintptr_t symtab, uintptr_t strtab, size_t syment,
                                              size_t strsz, const char *symbol_name);
        } // namespace GnuHash
    } // namespace Elf

    namespace Zip
    {
#define KT_EOCD_SIGNATURE 0x06054b50
#define KT_ZIP64_EOCD_SIGNATURE 0x06064b50
#define KT_ZIP64_EOCD_LOCATOR 0x07064b50
#define KT_CENTRAL_DIR_SIGNATURE 0x02014b50
#define KT_LOCAL_HEADER_SIGNATURE 0x04034b50
#define KT_ZIP64_EXTRA_ID 0x0001
#define KT_MAX_NAME_LEN 65535 // ZIP max file name length

        struct ZipFileInfo
        {
            std::string fileName;
            uint64_t compressedSize = 0;
            uint64_t uncompressedSize = 0;
            uint16_t compressionMethod = 0;
            uint32_t crc32 = 0;
            uint16_t modTime = 0;
            uint16_t modDate = 0;
            uint64_t dataOffset = 0;
        };

        struct ZipFileMMap
        {
            void *data = nullptr;
            size_t size = 0;
			
	    ZipFileMMap() = default;
	    ZipFileMMap(void *data, size_t size) : data(data), size(size) {}
        };

        bool GetCentralDirInfo(int fd, uint64_t fileSize, bool &isZip64, uint64_t &cdOffset, uint64_t &totalEntries);

        std::vector<ZipFileInfo> listFilesInZip(const std::string &zipPath);

        ZipFileInfo GetFileInfoByDataOffset(const std::string &zipPath, uint64_t dataOffset);
        ZipFileMMap MMapFileByDataOffset(const std::string &zipPath, uint64_t dataOffset);
    } // namespace Zip

#endif // __ANDROID__
} // namespace KittyUtils
