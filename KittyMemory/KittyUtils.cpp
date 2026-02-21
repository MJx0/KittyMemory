#include "KittyUtils.hpp"

#ifdef __ANDROID__
#include <sys/system_properties.h>
#endif

namespace KittyUtils
{

#ifdef __ANDROID__
    std::string getExternalStorage()
    {
        char *storage = getenv("EXTERNAL_STORAGE");
        return storage ? storage : "/sdcard";
    }

    int getAndroidVersion()
    {
        static int ver = 0;
        if (ver > 0)
            return ver;

        char buf[0xff] = {0};
        if (__system_property_get("ro.build.version.release", buf))
            ver = std::atoi(buf);

        return ver;
    }

    int getAndroidSDK()
    {
        static int sdk = 0;
        if (sdk > 0)
            return sdk;

        char buf[0xff] = {0};
        if (__system_property_get("ro.build.version.sdk", buf))
            sdk = std::atoi(buf);

        return sdk;
    }
#endif

    std::string fileNameFromPath(const std::string &filePath)
    {
        std::string filename;
        const size_t last_slash_idx = filePath.find_last_of("/\\");
        if (std::string::npos != last_slash_idx)
            filename = filePath.substr(last_slash_idx + 1);
        return filename;
    }

    std::string fileDirectory(const std::string &filePath)
    {
        std::string directory;
        const size_t last_slash_idx = filePath.find_last_of("/\\");
        if (std::string::npos != last_slash_idx)
            directory = filePath.substr(0, last_slash_idx);
        return directory;
    }

    std::string fileExtension(const std::string &filePath)
    {
        std::string ext;
        const size_t last_slash_idx = filePath.find_last_of(".");
        if (std::string::npos != last_slash_idx)
            ext = filePath.substr(last_slash_idx + 1);
        return ext;
    }

    void String::Trim(std::string &str)
    {
        // https://www.techiedelight.com/remove-whitespaces-string-cpp/
        str.erase(std::remove_if(str.begin(), str.end(), [](char c)
        { return (c == ' ' || c == '\n' || c == '\r' ||
                  c == '\t' || c == '\v' || c == '\f'); }),
                  str.end());
    }

    bool String::ValidateHex(std::string &hex)
    {
        if (hex.empty()) return false;

        if (hex.compare(0, 2, "0x") == 0)
            hex.erase(0, 2);

        Trim(hex);  // first remove spaces

        if (hex.length() < 2 || hex.length() % 2 != 0) return false;

        for (size_t i = 0; i < hex.length(); i++)
        {
            if (!std::isxdigit((unsigned char)hex[i]))
                return false;
        }

        return true;
    }

    std::string String::Fmt(const char *fmt, ...)
    {
        if (!fmt)
            return "";

        va_list args;

        va_start(args, fmt);
        size_t size = vsnprintf(nullptr, 0, fmt, args) + 1;  // extra space for '\0'
        va_end(args);

        std::vector<char> buffer(size, '\0');

        va_start(args, fmt);
        vsnprintf(&buffer[0], size, fmt, args);
        va_end(args);

        return std::string(&buffer[0]);
    }

    std::string String::Random(size_t length)
    {
        static const std::string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        static std::mutex mtx;
        std::lock_guard<std::mutex> lock(mtx);

        static std::default_random_engine rnd(std::random_device{}());
        static std::uniform_int_distribution<std::string::size_type> dist(0, chars.size() - 1);

        std::string str(length, '\0');
        for (size_t i = 0; i < length; ++i)
            str[i] = chars[dist(rnd)];

        return str;
    }

    // https://tweex.net/post/c-anything-tofrom-a-hex-string/

    /*
        Convert a block of data to a hex string
    */
    std::string data2Hex(
        const void *data,        //!< Data to convert
        const size_t dataLength  //!< Length of the data to convert
    )
    {
        const auto *byteData = reinterpret_cast<const unsigned char *>(data);
        std::stringstream hexStringStream;

        hexStringStream << std::hex << std::setfill('0');
        for (size_t index = 0; index < dataLength; ++index)
            hexStringStream << std::setw(2) << static_cast<int>(byteData[index]);
        return hexStringStream.str();
    }

    /*
        Convert a hex string to a block of data
    */
    void dataFromHex(
        const std::string &in,  //!< Input hex string
        void *data              //!< Data store
    )
    {
        size_t length = in.length();
        auto *byteData = reinterpret_cast<unsigned char *>(data);

        std::stringstream hexStringStream;
        hexStringStream >> std::hex;
        for (size_t strIndex = 0, dataIndex = 0; strIndex < length; ++dataIndex)
        {
            // Read out and convert the string two characters at a time
            const char tmpStr[3] = {in[strIndex++], in[strIndex++], 0};

            // Reset and fill the string stream
            hexStringStream.clear();
            hexStringStream.str(tmpStr);

            // Do the conversion
            int tmpValue = 0;
            hexStringStream >> tmpValue;
            byteData[dataIndex] = static_cast<unsigned char>(tmpValue);
        }
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
            uint32_t HashSymName(const char *name)
            {
                uint32_t h = 0, g;
                for (; *name; name++)
                {
                    h = (h << 4) + *name;
                    g = h & 0xf0000000;
                    if (g)
                        h ^= g >> 24;
                    h &= ~g;
                }
                return h;
            }

            const KT_ElfW(Sym) * LookupByName(uintptr_t elfhash,
                                              uintptr_t symtab,
                                              uintptr_t strtab,
                                              size_t syment,
                                              size_t strsz,
                                              const char *symbol_name)
            {
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

                const uint32_t name_hash = HashSymName(symbol_name);
                for (uint32_t i = bucket[name_hash % num_bucket]; i != 0 && i < num_chain; i = chain[i])
                {
                    const auto *symbol = reinterpret_cast<const KT_ElfW(Sym) *>(symbol_table + (syment * i));
                    if (!symbol || symbol->st_name >= strsz)
                        break;

                    std::string sym_str = std::string(string_table + symbol->st_name);
                    if (!sym_str.empty() && sym_str == symbol_name)
                        return symbol;
                }

                return nullptr;
            }
        }  // namespace ElfHash
    }  // namespace Elf

    namespace Elf
    {
        namespace GnuHash
        {
            uint32_t HashSymName(const char *name)
            {
                uint32_t h = 5381;
                for (; *name; name++)
                    h = (h << 5) + h + *name;
                return h;
            }

            const KT_ElfW(Sym) * LookupByName(uintptr_t gnuhash,
                                              uintptr_t symtab,
                                              uintptr_t strtab,
                                              size_t syment,
                                              size_t strsz,
                                              const char *symbol_name)
            {
                const auto *gnu_hash = reinterpret_cast<const uint32_t *>(gnuhash);
                const auto *symbol_table = reinterpret_cast<const uint8_t *>(symtab);
                const auto *string_table = reinterpret_cast<const char *>(strtab);

                const uint32_t name_hash = HashSymName(symbol_name);

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

                uintptr_t word = bloom[(name_hash / KT_ELFCLASS_BITS) % bloom_size];
                uintptr_t mask = 0 | (uintptr_t)1 << (name_hash % KT_ELFCLASS_BITS) | (uintptr_t)1 << ((name_hash >> bloom_shift) % KT_ELFCLASS_BITS);

                // If at least one bit is not set, a symbol is surely missing.
                if ((word & mask) != mask)
                    return nullptr;

                uint32_t sym_idx = buckets[name_hash % num_buckets];
                if (sym_idx < sym_offset)
                    return nullptr;

                // Loop through the chain.
                while (true)
                {
                    const auto *symbol = reinterpret_cast<const KT_ElfW(Sym) *>(symbol_table + (syment * sym_idx));
                    if (!symbol || symbol->st_name >= strsz)
                        break;

                    const uint32_t hash = chain[sym_idx - sym_offset];
                    if ((name_hash | 1) == (hash | 1))
                    {
                        std::string sym_str = std::string(string_table + symbol->st_name);
                        if (!sym_str.empty() && sym_str == symbol_name)
                            return symbol;
                    }

                    // Chain ends with an element with the lowest bit set to 1.
                    if (hash & 1)
                        break;

                    sym_idx++;
                }

                return nullptr;
            }
        }  // namespace GnuHash
    }  // namespace Elf

    namespace Zip
    {
#define KT_MIN_EOCD_SIZE 22
#define KT_EOCD_SIGNATURE 0x06054b50
#define KT_ZIP64_EOCD_SIGNATURE 0x06064b50
#define KT_ZIP64_EOCD_LOCATOR 0x07064b50
#define KT_CENTRAL_DIR_SIGNATURE 0x02014b50
#define KT_LOCAL_HEADER_SIGNATURE 0x04034b50
#define KT_ZIP64_EXTRA_ID 0x0001
#define KT_MAX_NAME_LEN 65535
#define KT_MAX_EOCD_SEARCH (1024 * 64)
#define KT_CENTRAL_DIR_SIZE 46
#define KT_LOCAL_HEADER_SIZE 30

        inline bool read16(const uint8_t *base, uint64_t size, uint64_t offset, uint16_t &out)
        {
            if (offset + 2 > size)
                return false;
            std::memcpy(&out, base + offset, 2);
            return true;
        }

        inline bool read32(const uint8_t *base, uint64_t size, uint64_t offset, uint32_t &out)
        {
            if (offset + 4 > size)
                return false;
            std::memcpy(&out, base + offset, 4);
            return true;
        }

        inline bool read64(const uint8_t *base, uint64_t size, uint64_t offset, uint64_t &out)
        {
            if (offset + 8 > size)
                return false;
            std::memcpy(&out, base + offset, 8);
            return true;
        }

        bool findCentralDirectory(const uint8_t *data, uint64_t fileSize, uint64_t *cdOffset, uint64_t *totalEntries)
        {
            if (fileSize < KT_MIN_EOCD_SIZE)
                return false;

            uint64_t searchStart = (fileSize > KT_MAX_EOCD_SEARCH) ? fileSize - KT_MAX_EOCD_SEARCH : 0;

            for (int64_t offset = fileSize - 4; offset >= (int64_t)searchStart; --offset)
            {
                uint32_t sig;
                if (!read32(data, fileSize, offset, sig))
                    continue;

                if (sig == KT_EOCD_SIGNATURE)
                {
                    uint16_t entries16;
                    uint32_t cdOff32;

                    if (!read16(data, fileSize, offset + 10, entries16))
                        return false;
                    if (!read32(data, fileSize, offset + 16, cdOff32))
                        return false;

                    if (totalEntries)
                        *totalEntries = entries16;

                    if (cdOffset)
                        *cdOffset = cdOff32;

                    return true;
                }

                if (sig == KT_ZIP64_EOCD_LOCATOR)
                {
                    uint64_t zip64EOCDOffset;
                    if (!read64(data, fileSize, offset + 8, zip64EOCDOffset))
                        return false;

                    uint32_t zip64sig;
                    if (!read32(data, fileSize, zip64EOCDOffset, zip64sig))
                        return false;

                    if (zip64sig != KT_ZIP64_EOCD_SIGNATURE)
                        return false;

                    uint64_t entries64;
                    uint64_t cdOff64;

                    if (!read64(data, fileSize, zip64EOCDOffset + 24, entries64))
                        return false;

                    if (!read64(data, fileSize, zip64EOCDOffset + 48, cdOff64))
                        return false;

                    if (totalEntries)
                        *totalEntries = entries64;

                    if (cdOffset)
                        *cdOffset = cdOff64;

                    return true;
                }
            }

            return false;
        }

        std::vector<ZipEntryInfo> listEntriesInZip(const std::string &zipPath)
        {
            std::vector<ZipEntryInfo> ents;

            int fd = KT_EINTR_RETRY(open(zipPath.c_str(), O_RDONLY));
            if (fd < 0)
                return ents;

            struct stat st{};
            if (fstat(fd, &st) < 0)
            {
                KT_EINTR_RETRY(close(fd));
                return ents;
            }

            uint64_t fileSize = st.st_size;
            if (fileSize < KT_MIN_EOCD_SIZE)
            {
                KT_EINTR_RETRY(close(fd));
                return ents;
            }

            void *map = mmap(nullptr, fileSize, PROT_READ, MAP_PRIVATE, fd, 0);
            if (!map || map == MAP_FAILED)
            {
                KT_EINTR_RETRY(close(fd));
                return ents;
            }

            const uint8_t *data = static_cast<uint8_t *>(map);

            uint64_t cdOffset = 0;
            uint64_t totalEntries = 0;

            if (!findCentralDirectory(data, fileSize, &cdOffset, &totalEntries))
            {
                munmap(map, fileSize);
                KT_EINTR_RETRY(close(fd));
                return ents;
            }

            if (cdOffset >= fileSize)
            {
                munmap(map, fileSize);
                KT_EINTR_RETRY(close(fd));
                return ents;
            }

            uint64_t offset = cdOffset;
            uint64_t parsedEntries = 0;

            while (offset + KT_CENTRAL_DIR_SIZE <= fileSize)
            {
                uint32_t sig;
                if (!read32(data, fileSize, offset, sig))
                    break;

                if (sig != KT_CENTRAL_DIR_SIGNATURE)
                    break;

                ZipEntryInfo info{};

                read16(data, fileSize, offset + 10, info.compressionMethod);
                read16(data, fileSize, offset + 12, info.modTime);
                read16(data, fileSize, offset + 14, info.modDate);
                read32(data, fileSize, offset + 16, info.crc32);

                uint32_t compSize32, uncompSize32;
                read32(data, fileSize, offset + 20, compSize32);
                read32(data, fileSize, offset + 24, uncompSize32);

                info.compressedSize = compSize32;
                info.uncompressedSize = uncompSize32;

                uint16_t nameLen, extraLen, commentLen;
                read16(data, fileSize, offset + 28, nameLen);
                read16(data, fileSize, offset + 30, extraLen);
                read16(data, fileSize, offset + 32, commentLen);

                uint32_t localHeaderOffset32;
                read32(data, fileSize, offset + 42, localHeaderOffset32);

                uint64_t entrySize = KT_CENTRAL_DIR_SIZE + nameLen + extraLen + commentLen;
                if (offset + entrySize > fileSize)
                    break;

                if (nameLen > KT_MAX_NAME_LEN)
                    break;

                info.fileName.assign(reinterpret_cast<const char *>(data + offset + KT_CENTRAL_DIR_SIZE), nameLen);

                uint64_t localHeaderOffset = localHeaderOffset32;

                // ZIP64 handling
                if (compSize32 == 0xFFFFFFFF || uncompSize32 == 0xFFFFFFFF || localHeaderOffset32 == 0xFFFFFFFF)
                {
                    uint64_t extraOffset = offset + KT_CENTRAL_DIR_SIZE + nameLen;
                    uint64_t endExtra = extraOffset + extraLen;

                    while (extraOffset + 4 <= endExtra)
                    {
                        uint16_t id, size;
                        read16(data, fileSize, extraOffset, id);
                        read16(data, fileSize, extraOffset + 2, size);

                        if (extraOffset + 4 + size > endExtra)
                            break;

                        if (id == KT_ZIP64_EXTRA_ID)
                        {
                            uint64_t fieldOffset = extraOffset + 4;

                            if (uncompSize32 == 0xFFFFFFFF)
                            {
                                read64(data, fileSize, fieldOffset, info.uncompressedSize);
                                fieldOffset += 8;
                            }

                            if (compSize32 == 0xFFFFFFFF)
                            {
                                read64(data, fileSize, fieldOffset, info.compressedSize);
                                fieldOffset += 8;
                            }

                            if (localHeaderOffset32 == 0xFFFFFFFF)
                            {
                                read64(data, fileSize, fieldOffset, localHeaderOffset);
                            }

                            break;
                        }

                        extraOffset += 4 + size;
                    }
                }

                // Validate local header
                if (localHeaderOffset + KT_LOCAL_HEADER_SIZE > fileSize)
                    break;

                uint16_t localNameLen, localExtraLen;
                read16(data, fileSize, localHeaderOffset + 26, localNameLen);
                read16(data, fileSize, localHeaderOffset + 28, localExtraLen);

                info.dataOffset = localHeaderOffset + KT_LOCAL_HEADER_SIZE + localNameLen + localExtraLen;

                if (info.dataOffset > fileSize)
                    break;

                ents.push_back(std::move(info));

                offset += entrySize;
                parsedEntries++;

                if (parsedEntries >= totalEntries)
                    break;
            }

            munmap(map, fileSize);
            KT_EINTR_RETRY(close(fd));

            return ents;
        }

        bool GetEntryInfoByDataOffset(const std::string &zipPath, uint64_t dataOffset, ZipEntryInfo *out)
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

        bool MMapEntryByDataOffset(const std::string &zipPath, uint64_t dataOffset, ZipEntryMMap *out)
        {
            if (out)
                *out = {};

            ZipEntryInfo ent{};
            if (!GetEntryInfoByDataOffset(zipPath, dataOffset, &ent))
                return false;

            uint64_t compressedSize = ent.compressedSize;

            int fd = KT_EINTR_RETRY(open(zipPath.c_str(), O_RDONLY));
            if (fd < 0)
                return false;

            struct stat st{};
            if (fstat(fd, &st) < 0)
            {
                KT_EINTR_RETRY(close(fd));
                return false;
            }

            uint64_t fileSize = st.st_size;

            if (dataOffset >= fileSize || dataOffset + compressedSize > fileSize)
            {
                KT_EINTR_RETRY(close(fd));
                return false;
            }

            const size_t pageSize = sysconf(_SC_PAGE_SIZE);
            uint64_t alignedOffset = dataOffset & ~(uint64_t(pageSize - 1));
            uint64_t offsetDiff = dataOffset - alignedOffset;
            uint64_t mapSize = offsetDiff + compressedSize;

            void *map = mmap(nullptr, mapSize, PROT_READ, MAP_PRIVATE, fd, alignedOffset);

            KT_EINTR_RETRY(close(fd));

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

#endif  // __ANDROID__

}  // namespace KittyUtils
