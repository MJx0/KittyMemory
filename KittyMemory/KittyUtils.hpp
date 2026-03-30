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
#include <functional>
#include <cctype>

/**
 * @brief Returns the memory page size.
 */
inline size_t KTGetPageSize()
{
    static size_t pageSize = 0;
    if (pageSize == 0)
        pageSize = (sysconf(_SC_PAGE_SIZE));

    return pageSize;
}

#define KT_PAGE_SIZE (KTGetPageSize())

#define KT_PAGE_START(x) (uintptr_t(x) & ~(KT_PAGE_SIZE - 1))
#define KT_PAGE_END(x) (KT_PAGE_START(uintptr_t(x) + KT_PAGE_SIZE - 1))
#define KT_PAGE_OFFSET(x) (uintptr_t(x) - KT_PAGE_START(x))
#define KT_PAGE_LEN(x) (size_t(KT_PAGE_SIZE - KT_PAGE_OFFSET(x)))

#define KT_PAGE_END2(x, len) (KT_PAGE_START((uintptr_t(x) + len) + KT_PAGE_SIZE - 1))
#define KT_PAGE_LEN2(x, len) (KT_PAGE_END2(x, len) - KT_PAGE_START(x))

#define KT_PROT_RWX (PROT_READ | PROT_WRITE | PROT_EXEC)
#define KT_PROT_RX (PROT_READ | PROT_EXEC)
#define KT_PROT_RW (PROT_READ | PROT_WRITE)

#define KT_ALIGN_UP(ptr, align) (((uintptr_t)(ptr) + (align) - 1) & ~((align) - 1))
#define KT_ALIGN_DOWN(ptr, align) (((uintptr_t)(ptr)) & ~((uintptr_t)(align) - 1))

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

/**
 * @brief Provides general utility functions.
 */
namespace KittyUtils
{

#ifdef __ANDROID__
    /**
     * @brief Returns the path to the external storage directory.
     */
    std::string getExternalStorage();

    /**
     * @brief Returns the version of the Android operating system.
     */
    int getAndroidVersion();

    /**
     * @brief Returns the SDK version of the Android operating system.
     */
    int getAndroidSDK();
#endif

    /**
     * @brief Untags a heap pointer by removing the top byte (TBI).
     * @note Currently only implemented for android 11+ arm64
     *
     * @param p The heap pointer to be untagged.
     * @return The untagged pointer.
     */
    inline uintptr_t untagHeepPtr(uintptr_t p)
    {
#if defined(__LP64__) && defined(__ANDROID__)
        return (p & ((static_cast<uintptr_t>(1) << 56) - 1));
#else
        return p;
#endif
    }

    inline void *untagHeepPtr(void *p)
    {
        return reinterpret_cast<void *>(untagHeepPtr(uintptr_t(p)));
    }

    inline const void *untagHeepPtr(const void *p)
    {
        return reinterpret_cast<const void *>(untagHeepPtr(uintptr_t(p)));
    }

    /**
     * @brief Provides utility functions for paths.
     */
    namespace Path
    {
        /**
         * @brief Extracts the file name from a given file path.
         *
         * @param filePath The full path of the file.
         *
         * @return file name.
         */
        std::string fileName(const std::string &filePath);

        /**
         * @brief Extracts the directory from a given file path.
         *
         * @param filePath The full path of the file.
         *
         * @return The directory path.
         */
        std::string fileDirectory(const std::string &filePath);

        /**
         * @brief Extracts the file extension from a given file path.
         *
         * @param filePath The full path of the file.
         *
         * @return The file extension.
         */
        std::string fileExtension(const std::string &filePath);
    } // namespace Path

    /**
     * @brief Provides utility functions for strings.
     */
    namespace String
    {
        /**
         * @brief Helper to compare two characters case-insensitively.
         */
        inline bool charEqualsIgnoreCase(char a, char b)
        {
            return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
        }

        /**
         * @brief Checks if a string starts with a given prefix.
         *
         * @param str The string to check.
         * @param prefix The prefix to look for.
         * @param sensitive Whether the comparison should be case-sensitive (default is true).
         *
         * @return true if str starts with prefix, false otherwise.
         */
        bool startsWith(const std::string &str, const std::string &prefix, bool sensitive = true);

        /**
         * @brief Checks if a string contains a given substring.
         *
         * @param str The string to check.
         * @param substring The substring to look for.
         * @param sensitive Whether the comparison should be case-sensitive (default is true).
         *
         * @return true if str contains substring, false otherwise.
         */
        bool contains(const std::string &str, const std::string &substring, bool sensitive = true);

        /**
         * @brief Checks if a string ends with a given suffix.
         *
         * @param str The string to check.
         * @param suffix The suffix to look for.
         * @param sensitive Whether the comparison should be case-sensitive (default is true).
         *
         * @return true if str ends with suffix, false otherwise.
         */
        bool endsWith(const std::string &str, const std::string &suffix, bool sensitive = true);

        /**
         * @brief Trims whitespace from the beginning and end of a string.
         *
         * @param str The string to be trimmed.
         */
        void trim(std::string &str);

        /**
         * @brief Checks if the provided string is a valid hexadecimal representation.
         *
         * This function validates if the given string is a valid hexadecimal number.
         * A valid hexadecimal number can contain characters '0'-'9' and 'A-F' or 'a-f'.
         *
         * @param hex The string to validate as a hexadecimal number.
         * @return true if the string is a valid hexadecimal number, false otherwise.
         */
        bool isValidHex(const std::string &hex);

        /**
         * @brief Validates a hexadecimal string.
         *
         * @param hex The hexadecimal string to validate.
         * @return True if the string was validated, false otherwise.
         */
        bool validateHex(std::string &hex);

        /**
         * @brief Formats a string using a printf-style format.
         *
         * @param fmt The format string.
         * @param ... Variable arguments to be formatted.
         * @return The formatted string.
         */
        std::string fmt(const char *fmt, ...);

        /**
         * @brief Generates a random string of a specified length.
         *
         * @param length The length of the random string to generate.
         * @return A random string.
         */
        std::string random(size_t length);
    } // namespace String

    /**
     * @brief Generates a random number of type T within a specified range.
     *
     * @tparam T The type of the number.
     * @param min The minimum range.
     * @param min The maximum range.
     * @return A random number.
     */
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

    /**
     * @brief Provides utility functions for data.
     */
    namespace Data
    {
        /**
         * @brief Converts a hexadecimal string to a binary data buffer.
         * @note data buffer must be large enough to fit.
         *
         * @param in The hexadecimal string to convert.
         * @param data Pointer to the destination buffer where the binary data will be stored.
         *
         * @return True if the conversion was successful, false otherwise.
         */
        bool fromHex(std::string in, void *data);

        /**
         * @brief Converts binary data to a hexadecimal string.
         *
         * @param data Pointer to the source binary data.
         * @param dataLength Length of the binary data.
         *
         * @return A hexadecimal string representation of the binary data.
         */
        std::string toHex(const void *data, const size_t dataLength);

        /**
         * @brief Converts a binary representation of a type T to a hexadecimal string.
         *
         * @tparam T The type of the binary data.
         * @param data The instance of type T to convert.
         *
         * @return A hexadecimal string representation of the binary data.
         */
        template <typename T>
        std::string toHex(const T &data)
        {
            return toHex(&data, sizeof(T));
        }

        /**
         * @brief Hex dumps the memory block at the specified address.
         *
         * @tparam rowSize The size of each row in the hex dump. Default is 8 bytes.
         * @tparam showASCII Whether to include ASCII representation of the memory block. Defult is true.
         *
         * @param address Pointer to the start of the memory block to dump.
         * @param len Length of the memory block to dump.
         *
         * @return A string containing the hex dump of the memory block.
         *
         * @details This function generates a human-readable hex dump of a memory block.
         * It prints the address, hexadecimal values, and ASCII representation of the block.
         * The dump is formatted into rows of specified size, and each row includes the offset,
         * byte values, and ASCII characters. The ASCII representation only includes printable
         * characters, and non-printable characters are represented by '.'.
         */
        template <size_t rowSize = 8, bool showASCII = true>
        std::string hexDump(const void *address, size_t len)
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
    } // namespace Data

#ifdef __ANDROID__

    /**
     * @brief Provides utility functions for Elfs.
     */
    namespace Elf
    {
        namespace ElfHash
        {
            /**
             * @brief Look up a symbol by name in a hash table
             *
             * This function searches through a symbol table using ELF hash table to find a symbol by its name.
             *
             * @param elfhash The address of the ELF hash table
             * @param symtab The address of the symbol table
             * @param strtab The address of the string table
             * @param syment The size of a symbol table entry
             * @param strsz The size of the string table
             * @param symbol_name The name of the symbol to look up
             *
             * @return A pointer to the ElfSym structure representing the symbol, or NULL if not found
             */
            const KT_ElfW(Sym) * lookupByName(uintptr_t elfhash,
                                              uintptr_t symtab,
                                              uintptr_t strtab,
                                              size_t syment,
                                              size_t strsz,
                                              const char *symbol_name);
        } // namespace ElfHash

        namespace GnuHash
        {
            /**
             * @brief Look up a symbol by name in a hash table
             *
             * This function searches through a symbol table using GNU hash table to find a symbol by its name.
             *
             * @param elfhash The address of the GNU hash table
             * @param symtab The address of the symbol table
             * @param strtab The address of the string table
             * @param syment The size of a symbol table entry
             * @param strsz The size of the string table
             * @param symbol_name The name of the symbol to look up
             *
             * @return A pointer to the ElfSym structure representing the symbol, or NULL if not found
             */
            const KT_ElfW(Sym) * lookupByName(uintptr_t gnuhash,
                                              uintptr_t symtab,
                                              uintptr_t strtab,
                                              size_t syment,
                                              size_t strsz,
                                              const char *symbol_name);
        } // namespace GnuHash
    } // namespace Elf

    /**
     * @brief Provides utility functions for handling ZIP files.
     */
    namespace Zip
    {
        /**
         * @brief Structure to hold ZIP entry info.
         */
        struct ZipEntryInfo
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

        /**
         * @brief Structure to hold memory mapped ZIP entry info.
         */
        struct ZipEntryMMap
        {
            void *mappingBase = nullptr;
            size_t mappingSize = 0;
            uint8_t *data = nullptr;
            uint64_t size = 0;
        };

        /**
         * @brief Finds the central directory of a ZIP file.
         *
         * @param data Pointer to the ZIP file data.
         * @param fileSize Size of the ZIP file in bytes.
         * @param cdOffset Pointer to store the offset of the central directory.
         * @param totalEntries Pointer to store the total number of entries in the ZIP file.
         *
         * @return True if the central directory is found, false otherwise.
         */
        bool findCentralDirectory(const uint8_t *data, uint64_t fileSize, uint64_t *cdOffset, uint64_t *totalEntries);

        /**
         * @brief Lists all entries in a ZIP file.
         *
         * @param zipPath Path to the ZIP file.
         *
         * @return A vector of ZipEntryInfo objects containing information about each entry.
         */
        std::vector<ZipEntryInfo> listEntriesInZip(const std::string &zipPath);

        /**
         * @brief Finds the ZipEntryInfo for an entry by its data offset.
         *
         * @param zipPath Path to the ZIP file.
         * @param dataOffset Offset of the entry in the ZIP file.
         * @param out Pointer to store the ZipEntryInfo object if found.
         *
         * @return True if the entry info is found, false otherwise.
         */
        bool findEntryInfoByDataOffset(const std::string &zipPath, uint64_t dataOffset, ZipEntryInfo *out);

        /**
         * @brief Maps an entry in a ZIP file by its data offset.
         *
         * @param zipPath Path to the ZIP file.
         * @param dataOffset Offset of the entry in the ZIP file.
         * @param out Pointer to store the ZipEntryMMap object if found.
         *
         * @return True if the entry is mapped, false otherwise.
         */
        bool mmapEntryByDataOffset(const std::string &zipPath, uint64_t dataOffset, ZipEntryMMap *out);
    } // namespace Zip

#endif // __ANDROID__
} // namespace KittyUtils
