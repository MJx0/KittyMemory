#pragma once

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <regex.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#include <errno.h>
#include <inttypes.h>

#include <cerrno>
#include <cstring>
#include <cstdint>
#include <cstdarg>
#include <cctype>

#include <string>
#include <sstream>
#include <iomanip>
#include <memory>
#include <algorithm>
#include <vector>
#include <utility>
#include <map>
#include <random>
#include <functional>
#include <mutex>
#include <type_traits>

/**
 * @brief Returns the memory page size.
 */
inline size_t KTGetPageSize()
{
    static long pageSize = 0;

    if (pageSize <= 0)
        pageSize = sysconf(_SC_PAGESIZE);

    return pageSize > 0 ? static_cast<size_t>(pageSize) : 4096;
}

#define KT_PAGE_SIZE (KTGetPageSize())

#define KT_PAGE_START(x) (uintptr_t(x) & ~(KT_PAGE_SIZE - 1))
#define KT_PAGE_END(x) (KT_PAGE_START(uintptr_t(x) + KT_PAGE_SIZE - 1))
#define KT_PAGE_OFFSET(x) (uintptr_t(x) - KT_PAGE_START(x))
#define KT_PAGE_REMAIN(x) (size_t(KT_PAGE_SIZE - KT_PAGE_OFFSET(x)))

#define KT_PAGE_END2(x, len) (KT_PAGE_START((uintptr_t(x) + len) + KT_PAGE_SIZE - 1))
#define KT_PAGE_REMAIN2(x, len) (KT_PAGE_END2(x, len) - KT_PAGE_START(x))

#define KT_PROT_RWX (PROT_READ | PROT_WRITE | PROT_EXEC)
#define KT_PROT_RX (PROT_READ | PROT_EXEC)
#define KT_PROT_RW (PROT_READ | PROT_WRITE)

#define KT_ALIGN_UP(ptr, align) (((uintptr_t)(ptr) + (align) - 1) & ~((align) - 1))
#define KT_ALIGN_DOWN(ptr, align) (((uintptr_t)(ptr)) & ~((uintptr_t)(align) - 1))

#define KT_IS_ALIGNED_OF(ptr, align) ((((uintptr_t)(ptr)) & ((uintptr_t)(align) - 1)) == 0)

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
typedef off_t kt_off64_t;
typedef struct stat kt_stat64_t;
#define kt_lseek64 ::lseek
#define kt_pread64 ::pread
#define kt_pwrite64 ::pwrite
#define kt_stat64 ::stat
#else
typedef off64_t kt_off64_t;
typedef struct stat64 kt_stat64_t;
#define kt_lseek64 ::lseek64
#define kt_pread64 ::pread64
#define kt_pwrite64 ::pwrite64
#define kt_stat64 ::stat64
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

#define KITTY_LOG_TAG "KittyMemory"

#ifdef __ANDROID__
#include <android/log.h>
#include <sys/system_properties.h>

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
#define KITTY_LOGD(fmt, ...) os_log(OS_LOG_DEFAULT, "(D) " KITTY_LOG_TAG ": " fmt, ##__VA_ARGS__)
#else
#define KITTY_LOGD(fmt, ...)                                                                                           \
    do                                                                                                                 \
    {                                                                                                                  \
    } while (0)
#endif

#define KITTY_LOGI(fmt, ...) os_log(OS_LOG_DEFAULT, "(I) " KITTY_LOG_TAG ": " fmt, ##__VA_ARGS__)
#define KITTY_LOGE(fmt, ...) os_log_error(OS_LOG_DEFAULT, "(E) " KITTY_LOG_TAG ": " fmt, ##__VA_ARGS__)

#endif

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
    /**
     * @brief RAII for file descriptor
     */
    class KTScopedFD
    {
    public:
        explicit KTScopedFD(int fd) : _fd(fd)
        {
        }

        ~KTScopedFD()
        {
            if (_fd >= 0)
                KT_EINTR_RETRY(close(_fd));
        }

        int get() const
        {
            return _fd;
        }

        KTScopedFD(const KTScopedFD &) = delete;
        KTScopedFD &operator=(const KTScopedFD &) = delete;

    private:
        int _fd;
    };

    /**
     * @brief RAII for file descriptor
     */
    class KTScopedMMap
    {
    public:
        KTScopedMMap(void *ptr, size_t size) : _ptr(ptr), _size(size)
        {
        }

        ~KTScopedMMap()
        {
            if (_ptr && _ptr != MAP_FAILED)
                munmap(_ptr, _size);
        }

        uint8_t *data() const
        {
            return static_cast<uint8_t *>(_ptr);
        }

        size_t size() const
        {
            return _size;
        }

        bool valid() const
        {
            return _ptr && _ptr != MAP_FAILED;
        }

    private:
        void *_ptr;
        size_t _size;
    };

#ifdef __ANDROID__
    /**
     * @brief Provides utility functions for Android.
     */
    namespace Android
    {
        inline int getUserId()
        {
            uid_t uid = getuid(); // Linux UID
            return uid / 100000;  // approximate Android user ID
        }

        /**
         * @brief Get an Android system property as a typed value.
         *
         * Supports std::string, bool, integral, and floating-point types.
         * Returns `defaultValue` if the property is missing or conversion fails.
         *
         * @tparam T Desired type
         * @param key Property name (e.g., "ro.build.version.sdk")
         * @param defaultValue Value returned if property not found or conversion fails
         * @return Property value converted to T
         */
        template <typename T>
        inline T getSystemProperty(const std::string &key, T defaultValue)
        {
            static_assert(
                std::is_same_v<T, std::string> || std::is_same_v<T, bool> || std::is_integral_v<T> ||
                    std::is_floating_point_v<T>,
                "getSystemProperty: unsupported type. Supported types: string, bool, integral, floating-point.");

            char value[PROP_VALUE_MAX] = {0};
            int len = __system_property_get(key.c_str(), value);
            if (len <= 0)
                return defaultValue;

            if constexpr (std::is_same_v<T, std::string>)
            {
                return std::string(value, len);
            }
            else if constexpr (std::is_same_v<T, bool>)
            {
                for (int i = 0; i < len; ++i)
                    value[i] = std::tolower(value[i]);

                if (std::strcmp(value, "1") == 0 || std::strcmp(value, "true") == 0 || std::strcmp(value, "y") == 0 ||
                    std::strcmp(value, "yes") == 0)
                    return true;

                if (std::strcmp(value, "0") == 0 || std::strcmp(value, "false") == 0 || std::strcmp(value, "n") == 0 ||
                    std::strcmp(value, "no") == 0)
                    return false;

                return defaultValue;
            }
            else if constexpr (std::is_integral_v<T>)
            {
                char *end = nullptr;
                long long result = std::strtoll(value, &end, 0);
                if (end == value)
                    return defaultValue;
                return static_cast<T>(result);
            }
            else if constexpr (std::is_floating_point_v<T>)
            {
                char *end = nullptr;
                double result = std::strtod(value, &end);
                if (end == value)
                    return defaultValue;
                return static_cast<T>(result);
            }

            // unsupported type
            return defaultValue;
        }

        /**
         * @brief Returns the version of the Android operating system.
         */
        int getVersion();

        /**
         * @brief Returns the SDK version of the Android operating system.
         */
        int getSDK();

        /**
         * @brief Returns true if Android operating system supports 64bit.
         */
        bool is64BitSupported();

        /**
         * @brief Get the base external storage directory.
         *
         * Usually:
         * /storage/emulated/0
         *
         * Uses the EXTERNAL_STORAGE environment variable.
         *
         * @return Absolute path to external storage root, falls back to "/sdcard" if not defined.
         */
        inline std::string getExternalStorage()
        {
            const char *storage = std::getenv("EXTERNAL_STORAGE");
            return (storage && storage[0] != '\0') ? storage : "/sdcard";
        }

        /**
         * @brief Get the internal data directory for the current Android app.
         *
         * Equivalent to:
         * Context.getDataDir()
         *
         * Example:
         * /data/user/<user_id>/<package_name>
         *
         * @return Absolute path to app internal data directory.
         */
        std::string getAppInternalDataDir();

        /**
         * @brief Get the internal files directory for the current Android app.
         *
         * Equivalent to:
         * Context.getFilesDir()
         *
         * Example:
         * /data/user/<user_id>/<package_name>/files
         *
         * @return Absolute path to app internal files directory.
         */
        std::string getAppInternalFilesDir();

        /**
         * @brief Get the internal cache directory for the current Android app.
         * the system usually sets the TMPDIR environment variable.
         * If TMPDIR is not set, it falls back to `/data/user/<user_id>/<package_name>/cache`
         *
         * Equivalent to:
         * Context.getCacheDir()
         *
         * Example:
         * /data/user/<user_id>/<package_name>/cache
         *
         * @return Absolute path to app internal cache directory.
         */
        std::string getAppInternalCacheDir();

        /**
         * @brief Get the external data directory for the current Android app.
         *
         * Example:
         * /storage/emulated/0/Android/data/<package>
         *
         * @return Absolute path to app external data.
         */
        inline std::string getAppExternalDataDir()
        {
            return getExternalStorage() + "/Android/data/" + getprogname();
        }

        /**
         * @brief Get the external files directory for the current Android app.
         *
         * Equivalent to:
         * Context.getExternalFilesDir(null)
         *
         * Example:
         * /storage/emulated/0/Android/data/<package>/files
         *
         * @return Absolute path to external files directory.
         */
        inline std::string getAppExternalFilesDir()
        {
            return getAppExternalDataDir() + "/files";
        }

        /**
         * @brief Get the external cache directory for the current Android app.
         *
         * Equivalent to:
         * Context.getExternalCacheDir()
         *
         * Example:
         * /storage/emulated/0/Android/data/<package>/cache
         *
         * @return Absolute path to external cache directory.
         */
        inline std::string getAppExternalCacheDir()
        {
            return getAppExternalDataDir() + "/cache";
        }

        /**
         * @brief Get the external media directory for the current Android app (Android 10+).
         *
         * Example:
         * /storage/emulated/0/Android/media/<package>
         *
         * @return Absolute path to external media directory.
         */
        inline std::string getAppExternalMediaDir()
        {
            return getExternalStorage() + "/Android/media/" + getprogname();
        }

        /**
         * @brief Get the OBB directory for current Android app.
         *
         * Example:
         * /storage/emulated/0/Android/obb/<package>
         *
         * @return Absolute path to OBB directory.
         */
        inline std::string getAppObbDir()
        {
            return getExternalStorage() + "/Android/obb/" + getprogname();
        }
    } // namespace Android
#endif

    /**
     * @brief Removes AArch64 top-byte pointer tags from an address.
     *
     * On Android ARM64 systems, pointers may contain TBI/MTE tag bits in
     * the top byte. This function removes those bits and returns the
     * canonical virtual address suitable for comparisons against
     * /proc/self/maps ranges.
     *
     * @param ptr Address value to untag.
     * @return Canonical untagged address.
     */
    inline uintptr_t untagPointer(uintptr_t ptr)
    {
#if defined(__LP64__) && defined(__ANDROID__)
        return ptr & ((static_cast<uintptr_t>(1) << 56) - 1);
#else
        return ptr;
#endif
    }

    /**
     * @overload untagPointer(uintptr_t)
     *
     * @param ptr Pointer value to untag.
     * @return Pointer of the same type with the top-byte tag removed.
     */
    template <typename T>
    inline T *untagPointer(T *ptr)
    {
        return reinterpret_cast<T *>(untagPointer(reinterpret_cast<uintptr_t>(ptr)));
    }

    /**
     * @overload untagPointer(uintptr_t)
     *
     * @param ptr Const pointer value to untag.
     * @return Const pointer of the same type with the top-byte tag removed.
     */
    template <typename T>
    inline const T *untagPointer(const T *ptr)
    {
        return reinterpret_cast<const T *>(untagPointer(reinterpret_cast<uintptr_t>(ptr)));
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
         * @brief Checks if a string starts with any of the given prefixes.
         *
         * @param str The string to check.
         * @param prefixes A list of prefixes to look for.
         * @param sensitive Whether the comparison should be case-sensitive (default is true).
         *
         * @return true if str starts with at least one prefix in prefixes, false otherwise.
         */
        bool startsWith(const std::string &str, const std::vector<std::string> &prefixes, bool sensitive = true);

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
         * @brief Checks if a string contains any of the given substrings.
         *
         * @param str The string to check.
         * @param substrings A list of substrings to look for.
         * @param sensitive Whether the comparison should be case-sensitive (default is true).
         *
         * @return true if str contains at least one substring in substrings, false otherwise.
         */
        bool contains(const std::string &str, const std::vector<std::string> &substrings, bool sensitive = true);

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
         * @brief Checks if a string ends with any of the given suffixes.
         *
         * @param str The string to check.
         * @param suffixes A list of suffixes to look for.
         * @param sensitive Whether the comparison should be case-sensitive (default is true).
         *
         * @return true if str ends with at least one suffix in suffixes, false otherwise.
         */
        bool endsWith(const std::string &str, const std::vector<std::string> &suffixes, bool sensitive = true);

        /**
         * @brief Trims whitespace from the beginning and end of a string.
         *
         * @param str The string to be trimmed.
         */
        void trim(std::string &str);

        /**
         * @brief Removes all whitespace characters from a string, not just leading/trailing.
         *
         * @param str The string to strip whitespace from.
         */
        void removeAllWhitespace(std::string &str);

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

        std::uniform_int_distribution<T> dist;
        return dist(gen, param_type{min, max});
    }

    /**
     * @brief Generates a random bytes of a specified length.
     *
     * @param length The length of the random bytes to generate.
     * @return Vector containing random byte values in the range [0, 255].
     */
    std::vector<uint8_t> randomBytes(std::size_t length);

    /**
     * @brief Generates a random string of a specified length.
     *
     * @param length The length of the random string to generate.
     * @return A random string.
     */
    std::string randomString(size_t length);

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
         * @brief Structure to hold ZIP Central Directory info.
         */
        struct CentralDirectoryInfo
        {
            uint64_t offset = 0;
            uint64_t size = 0;
            uint64_t entries = 0;
            bool zip64 = false;
        };

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
         * @param info Pointer to store the central directory info.
         *
         * @return True if the central directory is found, false otherwise.
         */
        bool findCentralDirectory(const uint8_t *data, uint64_t fileSize, CentralDirectoryInfo *info);

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
