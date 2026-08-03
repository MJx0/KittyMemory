#include "KittyUtils.hpp"

namespace KittyUtils
{

    std::vector<uint8_t> randomBytes(std::size_t length)
    {
        static std::mutex mtx;
        std::lock_guard<std::mutex> lock(mtx);

        static std::mt19937 gen{std::random_device{}()};

        std::uniform_int_distribution<uint16_t> dist(0, 255);

        std::vector<uint8_t> data(length);
        for (auto &b : data)
        {
            b = static_cast<uint8_t>(dist(gen));
        }

        return data;
    }

    std::string randomString(size_t length)
    {
        static const std::string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        static std::mutex mtx;
        std::lock_guard<std::mutex> lock(mtx);

        static std::default_random_engine rnd(std::random_device{}());

        std::uniform_int_distribution<std::string::size_type> dist(0, chars.size() - 1);

        std::string str(length, '\0');
        for (size_t i = 0; i < length; ++i)
            str[i] = chars[dist(rnd)];

        return str;
    }

#ifdef __ANDROID__
    int Android::getVersion()
    {
        static int ver = 0;
        if (ver > 0)
            return ver;

        ver = getSystemProperty<int>("ro.build.version.release", 0);
        return ver;
    }

    int Android::getSDK()
    {
        static int sdk = 0;
        if (sdk > 0)
            return sdk;

        sdk = getSystemProperty<int>("ro.build.version.sdk", 0);
        return sdk;
    }

    bool Android::is64BitSupported()
    {
        static bool once = false;
        static bool is64 = false;
        if (!once)
        {
            char value[0xff]{};
            if (__system_property_get("ro.product.cpu.abilist", value) == 0)
                __system_property_get("ro.product.cpu.abi", value);

            std::string abi = value;
            is64 = abi.find("64") != std::string::npos;
            once = true;
        }
        return is64;
    }

    std::string Android::getAppInternalDataDir()
    {
        std::string dir = getAppInternalCacheDir();
        if (!dir.empty())
        {
            return Path::fileDirectory(dir);
        }
        return dir;
    }

    std::string Android::getAppInternalFilesDir()
    {
        std::string dir = getAppInternalCacheDir();
        if (!dir.empty())
        {
            dir = Path::fileDirectory(dir);
            dir += "/files";
        }
        return dir;
    }

    std::string Android::getAppInternalCacheDir()
    {
        const char *tmpdir = std::getenv("TMPDIR");
        if (tmpdir && tmpdir[0] != '\0' && access(tmpdir, F_OK) == 0)
            return tmpdir;

        std::string dir = "/data/data/";
        dir += getprogname();
        dir += "/cache";
        if (access(dir.c_str(), F_OK) == 0)
            return dir;

        dir = "/data/user/";
        dir += std::to_string(getUserId());
        dir += "/";
        dir += getprogname();
        dir += "/cache";
        if (access(dir.c_str(), F_OK) == 0)
            return dir;

        return std::string();
    }
#endif

    std::string Path::fileName(const std::string &filePath)
    {
        std::string filename;
        const size_t last_slash_idx = filePath.find_last_of("/\\");
        if (std::string::npos != last_slash_idx)
            filename = filePath.substr(last_slash_idx + 1);
        return filename;
    }

    std::string Path::fileDirectory(const std::string &filePath)
    {
        std::string directory;
        const size_t last_slash_idx = filePath.find_last_of("/\\");
        if (std::string::npos != last_slash_idx)
            directory = filePath.substr(0, last_slash_idx);
        return directory;
    }

    std::string Path::fileExtension(const std::string &filePath)
    {
        std::string ext;
        const size_t last_slash_idx = filePath.find_last_of(".");
        if (std::string::npos != last_slash_idx)
            ext = filePath.substr(last_slash_idx + 1);
        return ext;
    }

    bool String::startsWith(const std::string &str, const std::string &prefix, bool sensitive)
    {
        if (str.length() < prefix.length())
            return false;
        if (sensitive)
        {
            return str.compare(0, prefix.length(), prefix) == 0;
        }
        return std::equal(prefix.begin(), prefix.end(), str.begin(), charEqualsIgnoreCase);
    }

    bool String::contains(const std::string &str, const std::string &substring, bool sensitive)
    {
        if (str.length() < substring.length())
            return false;
        if (sensitive)
        {
            return str.find(substring) != std::string::npos;
        }
        auto it = std::search(str.begin(), str.end(), substring.begin(), substring.end(), charEqualsIgnoreCase);
        return it != str.end();
    }

    bool String::endsWith(const std::string &str, const std::string &suffix, bool sensitive)
    {
        if (str.length() < suffix.length())
            return false;
        if (sensitive)
        {
            return str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
        }
        return std::equal(suffix.rbegin(), suffix.rend(), str.rbegin(), charEqualsIgnoreCase);
    }

    bool String::startsWith(const std::string &str, const std::vector<std::string> &prefixes, bool sensitive)
    {
        for (const auto &prefix : prefixes)
        {
            if (startsWith(str, prefix, sensitive))
                return true;
        }
        return false;
    }

    bool String::contains(const std::string &str, const std::vector<std::string> &substrings, bool sensitive)
    {
        for (const auto &substring : substrings)
        {
            if (contains(str, substring, sensitive))
                return true;
        }
        return false;
    }

    bool String::endsWith(const std::string &str, const std::vector<std::string> &suffixes, bool sensitive)
    {
        for (const auto &suffix : suffixes)
        {
            if (endsWith(str, suffix, sensitive))
                return true;
        }
        return false;
    }

    void String::trim(std::string &str)
    {
        str.erase(str.begin(), std::find_if(str.begin(), str.end(), [](unsigned char c) { return !std::isspace(c); }));
        str.erase(std::find_if(str.rbegin(), str.rend(), [](unsigned char c) { return !std::isspace(c); }).base(),
                  str.end());
    }

    void String::removeAllWhitespace(std::string &str)
    {
        str.erase(std::remove_if(str.begin(), str.end(), ::isspace), str.end());
    }

    bool String::isValidHex(const std::string &hex)
    {
        if (hex.empty())
            return false;

        const char *data = hex.c_str();
        size_t len = hex.length();
        size_t i = 0;

        while (i < len && ::isspace(static_cast<unsigned char>(data[i])))
        {
            i++;
        }

        if (i + 2 <= len && data[i] == '0' && (data[i + 1] == 'x' || data[i + 1] == 'X'))
        {
            i += 2;
        }

        size_t digitCount = 0;

        for (; i < len; ++i)
        {
            unsigned char c = static_cast<unsigned char>(data[i]);

            if (::isspace(c))
            {
                continue;
            }

            if (!::isxdigit(c))
            {
                return false;
            }

            digitCount++;
        }

        return (digitCount > 0 && (digitCount % 2 == 0));
    }

    bool String::validateHex(std::string &hex)
    {
        if (hex.empty())
            return false;

        size_t len = hex.length();
        size_t startOffset = (len >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) ? 2 : 0;

        size_t actualByteCount = 0;
        bool needsCleaning = (startOffset > 0);

        for (size_t i = startOffset; i < len; ++i)
        {
            unsigned char c = static_cast<unsigned char>(hex[i]);

            if (::isspace(c))
            {
                needsCleaning = true;
                continue;
            }

            if (!::isxdigit(c))
                return false;

            actualByteCount++;
        }

        if (actualByteCount == 0 || (actualByteCount % 2 != 0))
            return false;

        if (needsCleaning)
        {
            std::string cleaned;
            cleaned.reserve(actualByteCount);
            for (size_t i = startOffset; i < len; ++i)
            {
                unsigned char c = static_cast<unsigned char>(hex[i]);
                if (!::isspace(c))
                {
                    cleaned.push_back(c);
                }
            }
            hex = std::move(cleaned);
        }

        return true;
    }

    std::string String::fmt(const char *fmt, ...)
    {
        if (!fmt)
            return "";

        va_list args;
        va_start(args, fmt);
        int size = vsnprintf(nullptr, 0, fmt, args);
        va_end(args);

        if (size <= 0)
            return "";

        std::string str;
        str.resize(static_cast<size_t>(size));

        va_start(args, fmt);
        vsnprintf(&str[0], static_cast<size_t>(size) + 1, fmt, args);
        va_end(args);

        return str;
    }

    bool Data::fromHex(std::string in, void *data)
    {
        if (in.empty() || !data || !String::validateHex(in))
            return false;

        size_t length = in.length();
        auto *byteData = reinterpret_cast<uint8_t *>(data);

        auto charToNibble = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
            return 0;
        };

        for (size_t strIndex = 0, dataIndex = 0; strIndex < length; strIndex += 2, ++dataIndex)
        {
            byteData[dataIndex] = (charToNibble(in[strIndex]) << 4) | charToNibble(in[strIndex + 1]);
        }

        return true;
    }

    std::string Data::toHex(const void *data, const size_t dataLength)
    {
        if (!data || dataLength == 0)
            return "";

        static const char hexTable[] = "0123456789ABCDEF";
        const auto *byteData = reinterpret_cast<const uint8_t *>(data);

        std::string hexString;
        hexString.resize(dataLength * 2);

        for (size_t i = 0; i < dataLength; ++i)
        {
            hexString[i * 2] = hexTable[(byteData[i] >> 4) & 0x0F];
            hexString[i * 2 + 1] = hexTable[byteData[i] & 0x0F];
        }

        return hexString;
    }

#ifdef __ANDROID__

    // refs to
    // https://refspecs.linuxfoundation.org/elf/elf.pdf
    // https://flapenguin.me/elf-dt-hash
    // https://flapenguin.me/elf-dt-gnu-hash

    namespace Elf
    {
        namespace ElfHash
        {
            uint32_t hashSymName(const char *name)
            {
                uint32_t h = 0, g;
                for (; *name; name++)
                {
                    h = (h << 4) + static_cast<uint8_t>(*name);
                    g = h & 0xf0000000;
                    if (g)
                        h ^= g >> 24;
                    h &= ~g;
                }
                return h;
            }

            const KT_ElfW(Sym) * lookupByName(uintptr_t elfhash,
                                              uintptr_t symtab,
                                              uintptr_t strtab,
                                              size_t syment,
                                              size_t strsz,
                                              const char *symbol_name)
            {
                if (!elfhash || !symtab || !strtab || !symbol_name)
                    return nullptr;

                const auto *elf_hash = reinterpret_cast<const uint32_t *>(elfhash);
                const auto *symbol_table = reinterpret_cast<const uint8_t *>(symtab);
                const auto *string_table = reinterpret_cast<const char *>(strtab);

                const size_t num_bucket = elf_hash[0];
                if (!num_bucket)
                    return nullptr;

                const size_t num_chain = elf_hash[1];
                if (!num_chain)
                    return nullptr;

                const uint32_t *bucket = elf_hash + 2;
                const uint32_t *chain = bucket + num_bucket;

                uint32_t name_hash = hashSymName(symbol_name);

                uint32_t i = bucket[name_hash % num_bucket];

                while (i != 0 && i < num_chain)
                {
                    const KT_ElfW(Sym) *symbol = reinterpret_cast<const KT_ElfW(Sym) *>(symbol_table + syment * i);

                    if (!symbol || symbol->st_name >= strsz)
                    {
                        i = chain[i];
                        continue;
                    }

                    const char *sym_str = string_table + symbol->st_name;

                    const char *p1 = sym_str;
                    const char *p2 = symbol_name;
                    bool match = true;
                    while (*p1 && *p2)
                    {
                        if (*p1 != *p2)
                        {
                            match = false;
                            break;
                        }
                        p1++;
                        p2++;
                    }
                    if (match && *p2 == '\0')
                        return symbol;

                    i = chain[i];
                }

                return nullptr;
            }
        } // namespace ElfHash
    } // namespace Elf

    namespace Elf
    {
        namespace GnuHash
        {
            uint32_t hashSymName(const char *name)
            {
                uint32_t h = 5381;
                for (; *name; name++)
                    h = ((h << 5) + h) + static_cast<uint8_t>(*name); // h*33 + c
                return h;
            }

            const KT_ElfW(Sym) * lookupByName(uintptr_t gnuhash,
                                              uintptr_t symtab,
                                              uintptr_t strtab,
                                              size_t syment,
                                              size_t strsz,
                                              const char *symbol_name)
            {
                if (!gnuhash || !symtab || !strtab || !symbol_name)
                    return nullptr;

                const auto *gnu_hash = reinterpret_cast<const uint32_t *>(gnuhash);
                const auto *symbol_table = reinterpret_cast<const uint8_t *>(symtab);
                const auto *string_table = reinterpret_cast<const char *>(strtab);

                const uint32_t num_buckets = gnu_hash[0];
                if (!num_buckets)
                    return nullptr;

                const uint32_t sym_offset = gnu_hash[1];
                const uint32_t bloom_size = gnu_hash[2];
                // must be a power of 2
                if (!bloom_size || (bloom_size & (bloom_size - 1)) != 0)
                    return nullptr;

                const uint32_t bloom_shift = gnu_hash[3];
                const auto *bloom = reinterpret_cast<const uintptr_t *>(&gnu_hash[4]);
                const auto *buckets = reinterpret_cast<const uint32_t *>(&bloom[bloom_size]);
                const uint32_t *chain = &buckets[num_buckets];

                uint32_t name_hash = hashSymName(symbol_name);

                uintptr_t word = bloom[(name_hash / (sizeof(uintptr_t) * 8)) % bloom_size];
                uintptr_t mask = ((uintptr_t)1 << (name_hash % (sizeof(uintptr_t) * 8))) |
                                 ((uintptr_t)1 << ((name_hash >> bloom_shift) % (sizeof(uintptr_t) * 8)));

                // If at least one bit is not set, a symbol is surely missing.
                if ((word & mask) != mask)
                    return nullptr;

                uint32_t sym_idx = buckets[name_hash % num_buckets];
                if (sym_idx < sym_offset)
                    return nullptr;

                while (true)
                {
                    const KT_ElfW(Sym) *symbol = reinterpret_cast<const KT_ElfW(Sym) *>(symbol_table +
                                                                                        syment * sym_idx);

                    if (!symbol || symbol->st_name >= strsz)
                        break;

                    uint32_t hash = chain[sym_idx - sym_offset];
                    if ((name_hash | 1) == (hash | 1))
                    {
                        const char *sym_str = string_table + symbol->st_name;

                        const char *p1 = sym_str;
                        const char *p2 = symbol_name;
                        bool match = true;
                        while (*p1 && *p2)
                        {
                            if (*p1 != *p2)
                            {
                                match = false;
                                break;
                            }
                            p1++;
                            p2++;
                        }
                        if (match && *p2 == '\0')
                            return symbol;
                    }

                    if (hash & 1)
                        break;

                    sym_idx++;
                }

                return nullptr;
            }
        } // namespace GnuHash
    } // namespace Elf

    namespace Zip
    {
        constexpr uint32_t KT_EOCD_SIGNATURE = 0x06054B50;
        constexpr uint32_t KT_ZIP64_EOCD_SIGNATURE = 0x06064B50;
        constexpr uint32_t KT_ZIP64_LOCATOR_SIGNATURE = 0x07064B50;
        constexpr uint32_t KT_CENTRAL_DIR_SIGNATURE = 0x02014B50;
        constexpr uint32_t KT_LOCAL_HEADER_SIGNATURE = 0x04034B50;

        constexpr uint16_t KT_ZIP64_EXTRA_ID = 0x0001;

        constexpr uint64_t KT_MIN_EOCD_SIZE = 22;
        constexpr uint64_t KT_CENTRAL_DIR_HEADER_SIZE = 46;
        constexpr uint64_t KT_LOCAL_HEADER_SIZE = 30;
        constexpr uint64_t KT_MAX_EOCD_SEARCH = KT_MIN_EOCD_SIZE + 65535;

        constexpr uint16_t KT_ZIP_ENTRY_MAX_FILENAME_LENGTH = 65535;

        inline bool addOverflow(uint64_t a, uint64_t b, uint64_t &out)
        {
#if defined(__has_builtin)

#if __has_builtin(__builtin_add_overflow)
            return __builtin_add_overflow(a, b, &out);
#endif

#endif

            out = a + b;
            return out < a;
        }

        inline bool read16(const uint8_t *base, uint64_t size, uint64_t offset, uint16_t &out)
        {
            if (offset > size || size - offset < sizeof(out))
                return false;

            memcpy(&out, base + offset, sizeof(out));
            return true;
        }

        inline bool read32(const uint8_t *base, uint64_t size, uint64_t offset, uint32_t &out)
        {
            if (offset > size || size - offset < sizeof(out))
                return false;

            memcpy(&out, base + offset, sizeof(out));
            return true;
        }

        inline bool read64(const uint8_t *base, uint64_t size, uint64_t offset, uint64_t &out)
        {
            if (offset > size || size - offset < sizeof(out))
                return false;

            memcpy(&out, base + offset, sizeof(out));
            return true;
        }

        bool findCentralDirectory(const uint8_t *data, uint64_t fileSize, CentralDirectoryInfo *info)
        {
            if (info)
                *info = {};

            if (!data)
                return false;

            if (fileSize < KT_MIN_EOCD_SIZE)
                return false;

            const uint64_t searchStart = (fileSize > KT_MAX_EOCD_SEARCH) ? fileSize - KT_MAX_EOCD_SEARCH : 0;

            uint64_t eocdOffset = UINT64_MAX;

            //
            // Search backwards for the End Of Central Directory.
            //
            for (int64_t off = static_cast<int64_t>(fileSize - KT_MIN_EOCD_SIZE);
                 off >= static_cast<int64_t>(searchStart);
                 --off)
            {
                uint32_t sig;

                if (!read32(data, fileSize, static_cast<uint64_t>(off), sig))
                    continue;

                if (sig != KT_EOCD_SIGNATURE)
                    continue;

                uint16_t commentLength;

                if (!read16(data, fileSize, static_cast<uint64_t>(off) + 20, commentLength))
                    continue;

                //
                // EOCD must terminate the archive.
                //
                uint64_t eocdEnd;
                if (addOverflow(static_cast<uint64_t>(off), KT_MIN_EOCD_SIZE, eocdEnd))
                    continue;

                if (addOverflow(eocdEnd, commentLength, eocdEnd))
                    continue;

                if (eocdEnd > fileSize)
                    continue;

                eocdOffset = static_cast<uint64_t>(off);
                break;
            }

            if (eocdOffset == UINT64_MAX)
                return false;

            //
            // Read EOCD.
            //
            uint16_t diskNumber;
            uint16_t cdDisk;
            uint16_t entriesThisDisk;
            uint16_t totalEntries;

            uint32_t cdSize32;
            uint32_t cdOffset32;

            if (!read16(data, fileSize, eocdOffset + 4, diskNumber))
                return false;

            if (!read16(data, fileSize, eocdOffset + 6, cdDisk))
                return false;

            if (!read16(data, fileSize, eocdOffset + 8, entriesThisDisk))
                return false;

            if (!read16(data, fileSize, eocdOffset + 10, totalEntries))
                return false;

            if (!read32(data, fileSize, eocdOffset + 12, cdSize32))
                return false;

            if (!read32(data, fileSize, eocdOffset + 16, cdOffset32))
                return false;

            //
            // Only support single-disk archives.
            //
            if (diskNumber != 0 || cdDisk != 0)
                return false;

            if (entriesThisDisk != totalEntries && totalEntries != 0xFFFF)
                return false;

            //
            // Normal ZIP?
            //
            const bool needZip64 = (totalEntries == 0xFFFF) || (cdSize32 == 0xFFFFFFFF) || (cdOffset32 == 0xFFFFFFFF);

            if (!needZip64)
            {
                if (cdOffset32 > fileSize)
                    return false;

                if (cdSize32 > fileSize - cdOffset32)
                    return false;

                //
                // Minimum possible directory size.
                //
                if (totalEntries != 0 && cdSize32 / KT_CENTRAL_DIR_HEADER_SIZE < totalEntries)
                    return false;

                if (info)
                {
                    info->offset = cdOffset32;
                    info->size = cdSize32;
                    info->entries = totalEntries;
                    info->zip64 = false;
                }

                return true;
            }

            //
            // ZIP64 locator.
            //
            if (eocdOffset < 20)
                return false;

            const uint64_t locatorOffset = eocdOffset - 20;

            uint32_t locatorSig;
            uint32_t locatorDisk;
            uint32_t totalDisks;
            uint64_t zip64EOCDOffset;

            if (!read32(data, fileSize, locatorOffset, locatorSig))
                return false;

            if (locatorSig != KT_ZIP64_LOCATOR_SIGNATURE)
                return false;

            if (!read32(data, fileSize, locatorOffset + 4, locatorDisk))
                return false;

            if (!read64(data, fileSize, locatorOffset + 8, zip64EOCDOffset))
                return false;

            if (!read32(data, fileSize, locatorOffset + 16, totalDisks))
                return false;

            //
            // Reject multi-disk archives.
            //
            if (locatorDisk != 0)
                return false;

            if (totalDisks != 1)
                return false;

            //
            // We read up to offset+56.
            //
            if (zip64EOCDOffset >= fileSize)
                return false;

            if (zip64EOCDOffset > fileSize - 56)
                return false;

            uint32_t zip64Sig;
            uint64_t zip64RecordSize;

            if (!read32(data, fileSize, zip64EOCDOffset, zip64Sig))
                return false;

            if (zip64Sig != KT_ZIP64_EOCD_SIGNATURE)
                return false;

            if (!read64(data, fileSize, zip64EOCDOffset + 4, zip64RecordSize))
                return false;

            //
            // Version 1 ZIP64 EOCD payload is 44 bytes.
            //
            if (zip64RecordSize < 44)
                return false;

            uint64_t zip64PayloadStart;
            if (addOverflow(zip64EOCDOffset, 12, zip64PayloadStart))
                return false;

            uint64_t zip64End;
            if (addOverflow(zip64PayloadStart, zip64RecordSize, zip64End))
                return false;

            if (zip64End > fileSize)
                return false;

            uint64_t totalEntries64;
            uint64_t cdSize64;
            uint64_t cdOffset64;

            if (!read64(data, fileSize, zip64EOCDOffset + 24, totalEntries64))
                return false;

            if (!read64(data, fileSize, zip64EOCDOffset + 40, cdSize64))
                return false;

            if (!read64(data, fileSize, zip64EOCDOffset + 48, cdOffset64))
                return false;

            if (cdOffset64 > fileSize)
                return false;

            if (cdSize64 > fileSize - cdOffset64)
                return false;

            if (totalEntries64 != 0 && cdSize64 / KT_CENTRAL_DIR_HEADER_SIZE < totalEntries64)
                return false;

            if (info)
            {
                info->offset = cdOffset64;
                info->size = cdSize64;
                info->entries = totalEntries64;
                info->zip64 = true;
            }

            return true;
        }

        std::vector<ZipEntryInfo> listEntriesInZip(const std::string &zipPath)
        {
            std::vector<ZipEntryInfo> ents;

            kt_stat64_t st{};
            if (kt_stat64(zipPath.c_str(), &st) < 0 || !S_ISREG(st.st_mode))
                return ents;

            const uint64_t fileSize = static_cast<uint64_t>(st.st_size);
            if (fileSize < KT_MIN_EOCD_SIZE)
                return ents;

            KTScopedFD fd(KT_EINTR_RETRY(open(zipPath.c_str(), O_RDONLY)));
            if (fd.get() < 0)
                return ents;

            KTScopedMMap map(mmap(nullptr, fileSize, PROT_READ, MAP_PRIVATE, fd.get(), 0), fileSize);
            if (!map.valid())
                return ents;

            const uint8_t *data = static_cast<const uint8_t *>(map.data());

            CentralDirectoryInfo cd{};

            if (!findCentralDirectory(data, fileSize, &cd))
                return ents;

            if (cd.size == 0 && cd.entries == 0)
                return ents;

            if (cd.offset > fileSize)
                return ents;

            if (cd.size > fileSize - cd.offset)
                return ents;

            //
            // Avoid pathological allocations.
            //
            if (cd.entries > static_cast<uint64_t>(SIZE_MAX))
                return ents;

            ents.reserve(static_cast<size_t>(cd.entries));

            uint64_t cdEnd;
            if (addOverflow(cd.offset, cd.size, cdEnd))
                return ents;

            uint64_t offset = cd.offset;
            uint64_t parsedEntries = 0;

            while (parsedEntries < cd.entries)
            {
                if (offset > cdEnd)
                    break;

                if (KT_CENTRAL_DIR_HEADER_SIZE > cdEnd - offset)
                    break;

                uint32_t sig{};

                if (!read32(data, fileSize, offset, sig))
                    break;

                if (sig != KT_CENTRAL_DIR_SIGNATURE)
                    break;

                ZipEntryInfo info{};

                uint16_t flags{};
                uint16_t nameLen{};
                uint16_t extraLen{};
                uint16_t commentLen{};

                uint32_t compSize32{};
                uint32_t uncompSize32{};
                uint32_t localHeaderOffset32{};

                if (!read16(data, fileSize, offset + 8, flags))
                    break;

                if (!read16(data, fileSize, offset + 10, info.compressionMethod))
                    break;

                if (!read16(data, fileSize, offset + 12, info.modTime))
                    break;

                if (!read16(data, fileSize, offset + 14, info.modDate))
                    break;

                if (!read32(data, fileSize, offset + 16, info.crc32))
                    break;

                if (!read32(data, fileSize, offset + 20, compSize32))
                    break;

                if (!read32(data, fileSize, offset + 24, uncompSize32))
                    break;

                if (!read16(data, fileSize, offset + 28, nameLen))
                    break;

                if (!read16(data, fileSize, offset + 30, extraLen))
                    break;

                if (!read16(data, fileSize, offset + 32, commentLen))
                    break;

                if (!read32(data, fileSize, offset + 42, localHeaderOffset32))
                    break;

                //
                // Validate central directory entry size.
                //
                uint64_t entrySize = KT_CENTRAL_DIR_HEADER_SIZE;

                uint64_t tmp{};

                if (addOverflow(entrySize, nameLen, tmp))
                    break;

                entrySize = tmp;

                if (addOverflow(entrySize, extraLen, tmp))
                    break;

                entrySize = tmp;

                if (addOverflow(entrySize, commentLen, tmp))
                    break;

                entrySize = tmp;

                if (entrySize > cdEnd - offset)
                    break;

                if (nameLen > KT_ZIP_ENTRY_MAX_FILENAME_LENGTH)
                    break;

                //
                // Copy filename.
                //
                info.fileName.assign(reinterpret_cast<const char *>(data + offset + KT_CENTRAL_DIR_HEADER_SIZE),
                                     nameLen);

                info.compressedSize = compSize32;
                info.uncompressedSize = uncompSize32;

                uint64_t localHeaderOffset = localHeaderOffset32;

                //
                // Parse ZIP64 extra field if needed.
                //
                const bool needsZip64 = compSize32 == 0xFFFFFFFF || uncompSize32 == 0xFFFFFFFF ||
                                        localHeaderOffset32 == 0xFFFFFFFF;

                if (needsZip64)
                {
                    const uint64_t extraStart = offset + KT_CENTRAL_DIR_HEADER_SIZE + nameLen;

                    uint64_t extraEnd{};

                    if (addOverflow(extraStart, extraLen, extraEnd))
                        break;

                    bool foundZip64 = false;

                    uint64_t extraOffset = extraStart;

                    while (extraOffset < extraEnd)
                    {
                        //
                        // Need header ID + size.
                        //
                        if (extraEnd - extraOffset < 4)
                            break;

                        uint16_t extraId{};
                        uint16_t extraSize{};

                        if (!read16(data, fileSize, extraOffset, extraId))
                            break;

                        if (!read16(data, fileSize, extraOffset + 2, extraSize))
                            break;

                        uint64_t fieldStart = extraOffset + 4;

                        if (fieldStart > extraEnd || extraSize > extraEnd - fieldStart)
                            break;

                        if (extraId == KT_ZIP64_EXTRA_ID)
                        {
                            foundZip64 = true;

                            uint64_t fieldOffset = fieldStart;

                            uint64_t fieldEnd;
                            if (addOverflow(fieldStart, extraSize, fieldEnd))
                                break;

                            if (uncompSize32 == 0xFFFFFFFF)
                            {
                                if (fieldEnd - fieldOffset < 8)
                                    break;

                                if (!read64(data, fileSize, fieldOffset, info.uncompressedSize))
                                    break;

                                fieldOffset += 8;
                            }

                            if (compSize32 == 0xFFFFFFFF)
                            {
                                if (fieldEnd - fieldOffset < 8)
                                    break;

                                if (!read64(data, fileSize, fieldOffset, info.compressedSize))
                                    break;

                                fieldOffset += 8;
                            }

                            if (localHeaderOffset32 == 0xFFFFFFFF)
                            {
                                if (fieldEnd - fieldOffset < 8)
                                    break;

                                if (!read64(data, fileSize, fieldOffset, localHeaderOffset))
                                    break;
                            }

                            break;
                        }


                        extraOffset = fieldStart + extraSize;
                    }

                    //
                    // ZIP64 was required but missing.
                    //
                    if (!foundZip64)
                        break;
                }

                //
                // Reject encrypted entries.
                //
                // This parser exposes compressed bytes directly.
                // Encrypted ZIP entries cannot be safely consumed
                // without decryption support.
                //
                if (flags & 0x0001)
                    break;

                //
                // Validate local header offset.
                //
                if (localHeaderOffset >= fileSize)
                    break;

                if (KT_LOCAL_HEADER_SIZE > fileSize - localHeaderOffset)
                    break;

                //
                // Validate local header signature.
                //
                uint32_t localSig{};

                if (!read32(data, fileSize, localHeaderOffset, localSig))
                    break;

                if (localSig != KT_LOCAL_HEADER_SIGNATURE)
                    break;

                uint16_t localFlags{};
                uint16_t localMethod{};
                uint16_t localNameLen{};
                uint16_t localExtraLen{};

                if (!read16(data, fileSize, localHeaderOffset + 6, localFlags))
                    break;

                if (!read16(data, fileSize, localHeaderOffset + 8, localMethod))
                    break;

                if (!read16(data, fileSize, localHeaderOffset + 26, localNameLen))
                    break;

                if (!read16(data, fileSize, localHeaderOffset + 28, localExtraLen))
                    break;

                //
                // Local header consistency checks.
                //
                if (localFlags & 0x0001)
                    break;

                if (localFlags != flags)
                    break;

                if (localMethod != info.compressionMethod)
                    break;

                //
                // Calculate compressed data offset safely.
                //
                uint64_t dataOffset = localHeaderOffset;

                if (dataOffset > fileSize - KT_LOCAL_HEADER_SIZE)
                    break;

                dataOffset += KT_LOCAL_HEADER_SIZE;

                if (dataOffset > fileSize - localNameLen)
                    break;

                dataOffset += localNameLen;

                if (dataOffset > fileSize - localExtraLen)
                    break;

                dataOffset += localExtraLen;

                info.dataOffset = dataOffset;

                //
                // Validate compressed payload exists.
                //
                if (info.dataOffset > fileSize)
                    break;

                if (info.compressedSize > fileSize - info.dataOffset)
                    break;

                uint64_t dataEnd;
                if (addOverflow(info.dataOffset, info.compressedSize, dataEnd))
                    break;

                if (dataEnd > cd.offset)
                    break;

                //
                // Entry is valid.
                //
                ents.push_back(std::move(info));

                if (addOverflow(offset, entrySize, offset))
                    break;

                ++parsedEntries;
            }

            return ents;
        }

        bool findEntryInfoByDataOffset(const std::string &zipPath, uint64_t dataOffset, ZipEntryInfo *out)
        {
            if (out)
                *out = {};

            const auto ents = listEntriesInZip(zipPath);
            for (const auto &it : ents)
            {
                if (it.dataOffset == dataOffset)
                {
                    if (out)
                        *out = it;

                    return true;
                }
            }

            return false;
        }

        bool mmapEntryByDataOffset(const std::string &zipPath, uint64_t dataOffset, ZipEntryMMap *out)
        {
            if (out)
                *out = {};

            ZipEntryInfo ent{};
            if (!findEntryInfoByDataOffset(zipPath, dataOffset, &ent))
                return false;

            uint64_t compressedSize = ent.compressedSize;
            if (compressedSize == 0)
                return false;

            kt_stat64_t st{};
            if (kt_stat64(zipPath.c_str(), &st) < 0 || st.st_size < 0)
                return false;

            uint64_t fileSize = static_cast<uint64_t>(st.st_size);

            if (dataOffset >= fileSize || compressedSize > fileSize - dataOffset)
                return false;

            KTScopedFD fd(KT_EINTR_RETRY(open(zipPath.c_str(), O_RDONLY)));
            if (fd.get() < 0)
                return false;

            const size_t pageSize = KTGetPageSize();
            uint64_t alignedOffset = dataOffset & ~(uint64_t(pageSize - 1));
            uint64_t offsetDiff = dataOffset - alignedOffset;
            uint64_t mapSize = 0;
            if (addOverflow(offsetDiff, compressedSize, mapSize))
                return false;

            void *map = mmap(nullptr, mapSize, PROT_READ, MAP_PRIVATE, fd.get(), alignedOffset);
            if (!map || map == MAP_FAILED)
                return false;

            if (out)
            {
                out->mappingBase = map;
                out->mappingSize = mapSize;
                out->data = static_cast<uint8_t *>(map) + offsetDiff;
                out->size = compressedSize;
            }

            return true;
        }
    } // namespace Zip

#endif // __ANDROID__

} // namespace KittyUtils
