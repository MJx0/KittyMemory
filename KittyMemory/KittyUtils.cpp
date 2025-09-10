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
        bool GetCentralDirInfo(int fd, uint64_t fileSize, bool &isZip64, uint64_t &cdOffset, uint64_t &totalEntries)
        {
            if (fileSize < 22)
            {
                KITTY_LOGD("File too small: %" PRIx64 " bytes", fileSize);
                return false;
            }

            void *map = mmap(nullptr, fileSize, PROT_READ, MAP_PRIVATE, fd, 0);
            if (map == MAP_FAILED)
            {
                KITTY_LOGD("mmap failed: %s", strerror(errno));
                return false;
            }

            uint8_t *data = static_cast<uint8_t *>(map);

            // Find EOCD or ZIP64 EOCD locator
            int64_t offset = fileSize - 22;
            uint32_t sig;
            while (offset >= 0)
            {
                sig = *reinterpret_cast<uint32_t *>(data + offset);
                if (sig == KT_EOCD_SIGNATURE || (sig == KT_ZIP64_EOCD_LOCATOR && *reinterpret_cast<uint32_t *>(data + offset - 20) == KT_ZIP64_EOCD_SIGNATURE))
                {
                    break;
                }
                --offset;
            }

            if (offset < 0)
            {
                KITTY_LOGD("EOCD not found");
                munmap(map, fileSize);
                return false;
            }

            // Read EOCD or ZIP64 EOCD
            isZip64 = (sig == KT_ZIP64_EOCD_LOCATOR);
            if (isZip64)
            {
                totalEntries = *reinterpret_cast<uint64_t *>(data + offset - 20 + 12);
                cdOffset = *reinterpret_cast<uint64_t *>(data + offset - 20 + 36);
            }
            else
            {
                totalEntries = *reinterpret_cast<uint16_t *>(data + offset + 8);
                cdOffset = *reinterpret_cast<uint32_t *>(data + offset + 16);
            }

            munmap(map, fileSize);
            return true;
        }

        std::vector<ZipFileInfo> listFilesInZip(const std::string &zipPath)
        {
            std::vector<ZipFileInfo> files;
            int fd = KT_EINTR_RETRY(open(zipPath.c_str(), O_RDONLY));
            if (fd < 0)
            {
                KITTY_LOGD("open failed: %s, error: %s", zipPath.c_str(), strerror(errno));
                return files;
            }

            // Get file size
            struct stat st = {};
            if (fstat(fd, &st) < 0)
            {
                KITTY_LOGD("fstat failed: %s", strerror(errno));
                close(fd);
                return files;
            }
            uint64_t fileSize = st.st_size;

            // Get central directory info
            bool isZip64;
            uint64_t cdOffset, totalEntries;
            if (!GetCentralDirInfo(fd, fileSize, isZip64, cdOffset, totalEntries))
            {
                close(fd);
                return files;
            }

            // Map file for parsing
            void *map = mmap(nullptr, fileSize, PROT_READ, MAP_PRIVATE, fd, 0);
            if (map == MAP_FAILED)
            {
                KITTY_LOGD("mmap failed: %s", strerror(errno));
                close(fd);
                return files;
            }
            uint8_t *data = static_cast<uint8_t *>(map);

            // Parse central directory
            for (uint64_t offset = cdOffset, i = 0; i < totalEntries; ++i)
            {
                if (*reinterpret_cast<uint32_t *>(data + offset) != KT_CENTRAL_DIR_SIGNATURE)
                {
                    KITTY_LOGD("Invalid central directory signature at entry %" PRIu64, i);
                    break;
                }

                ZipFileInfo info;
                info.compressionMethod = *reinterpret_cast<uint16_t *>(data + offset + 10);
                info.modTime = *reinterpret_cast<uint16_t *>(data + offset + 12);
                info.modDate = *reinterpret_cast<uint16_t *>(data + offset + 14);
                info.crc32 = *reinterpret_cast<uint32_t *>(data + offset + 16);
                uint32_t compSize32 = *reinterpret_cast<uint32_t *>(data + offset + 20);
                uint32_t uncompSize32 = *reinterpret_cast<uint32_t *>(data + offset + 24);
                info.compressedSize = compSize32;
                info.uncompressedSize = uncompSize32;
                uint16_t nameLen = *reinterpret_cast<uint16_t *>(data + offset + 28);
                uint16_t extraLen = *reinterpret_cast<uint16_t *>(data + offset + 30);
                uint16_t commentLen = *reinterpret_cast<uint16_t *>(data + offset + 32);

                // Read file name
                if (nameLen <= KT_MAX_NAME_LEN)
                {
                    info.fileName.assign(reinterpret_cast<char *>(data + offset + 46), nameLen);

                    // Get local header offset
                    uint64_t localOffset = isZip64 && compSize32 == 0xFFFFFFFF ? *reinterpret_cast<uint64_t *>(data + offset + 46 + nameLen + (extraLen >= 24 ? 20 : extraLen)) : *reinterpret_cast<uint32_t *>(data + offset + 42);

                    // Update sizes for ZIP64
                    if (isZip64 && compSize32 == 0xFFFFFFFF)
                    {
                        for (uint16_t j = 0; j < extraLen;)
                        {
                            uint16_t id = *reinterpret_cast<uint16_t *>(data + offset + 46 + nameLen + j);
                            uint16_t size = *reinterpret_cast<uint16_t *>(data + offset + 46 + nameLen + j + 2);
                            if (id == KT_ZIP64_EXTRA_ID && size >= 16)
                            {
                                info.uncompressedSize = *reinterpret_cast<uint64_t *>(data + offset + 46 + nameLen + j + 4);
                                info.compressedSize = *reinterpret_cast<uint64_t *>(data + offset + 46 + nameLen + j + 12);
                                break;
                            }
                            j += 4 + size;
                        }
                    }

                    // Calculate data offset
                    uint16_t localNameLen = *reinterpret_cast<uint16_t *>(data + localOffset + 26);
                    uint16_t localExtraLen = *reinterpret_cast<uint16_t *>(data + localOffset + 28);
                    info.dataOffset = localOffset + 30 + localNameLen + localExtraLen;

                    files.push_back(info);
                }

                offset += 46 + nameLen + extraLen + commentLen;
            }

            munmap(map, fileSize);
            close(fd);
            return files;
        }

        ZipFileInfo GetFileInfoByDataOffset(const std::string &zipPath, uint64_t dataOffset)
        {
            ZipFileInfo info{};

            const auto files = listFilesInZip(zipPath);
            for (const auto &it : files)
            {
                if (it.dataOffset == dataOffset)
                {
                    info = it;
                    break;
                }
            }

            return info;
        }

        ZipFileMMap MMapFileByDataOffset(const std::string &zipPath, uint64_t dataOffset)
        {
            ZipFileMMap result;
            int fd = KT_EINTR_RETRY(open(zipPath.c_str(), O_RDONLY));
            if (fd < 0)
            {
                KITTY_LOGD("open failed: %s, error: %s", zipPath.c_str(), strerror(errno));
                return result;
            }

            // Get file info to obtain compressed size
            ZipFileInfo info = GetFileInfoByDataOffset(zipPath, dataOffset);
            if (info.fileName.empty())
            {
                KITTY_LOGD("No file found at offset %" PRIx64, dataOffset);
                close(fd);
                return result;
            }

            // mmap the data
            result.size = info.compressedSize;
            result.data = mmap(nullptr, result.size, PROT_READ, MAP_PRIVATE, fd, dataOffset);
            if (result.data == MAP_FAILED)
            {
                KITTY_LOGD("mmap failed at offset %" PRIx64 ": %s", dataOffset, strerror(errno));
                result.size = 0;
            }

            close(fd);
            return result;
        }
    }  // namespace Zip

#endif  // __ANDROID__

}  // namespace KittyUtils
