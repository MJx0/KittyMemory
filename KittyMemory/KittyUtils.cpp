#include "KittyUtils.hpp"

namespace KittyUtils {

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

        char buf[0xff] = { 0 };
        if (__system_property_get("ro.build.version.release", buf))
            ver = std::atoi(buf);

        return ver;
    }

    int getAndroidSDK()
    {
        static int sdk = 0;
        if (sdk > 0)
            return sdk;

        char buf[0xff] = { 0 };
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

        Trim(hex); // first remove spaces
        
        if (hex.length() < 2 || hex.length() % 2 != 0) return false;

        for (size_t i = 0; i < hex.length(); i++) {
            if (!std::isxdigit((unsigned char) hex[i]))
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
      size_t size = vsnprintf(nullptr, 0, fmt, args) + 1; // extra space for '\0'
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
        
        thread_local static std::default_random_engine rnd(std::random_device{}());
        thread_local static std::uniform_int_distribution<std::string::size_type> dist(0, chars.size()-1);

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
            const size_t dataLength //!< Length of the data to convert
    ) {
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
            const std::string &in, //!< Input hex string
            void *data       //!< Data store
    ) {
        size_t length = in.length();
        auto *byteData = reinterpret_cast<unsigned char *>(data);

        std::stringstream hexStringStream;
        hexStringStream >> std::hex;
        for (size_t strIndex = 0, dataIndex = 0; strIndex < length; ++dataIndex) {
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

    namespace Elf {
        namespace ElfHash {
            uint32_t HashSymName(const char *name) {
                uint32_t h = 0, g;
                for (; *name; name++) {
                    h = (h << 4) + *name;
                    g = h & 0xf0000000;
                    if (g)
                        h ^= g >> 24;
                    h &= ~g;
                }
                return h;
            }

            const ElfW_(Sym) *LookupByName(uintptr_t elfhash,
                                           uintptr_t symtab,
                                           uintptr_t strtab,
                                           size_t syment,
                                           size_t strsz,
                                           const char *symbol_name) {

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
                for (uint32_t i = bucket[name_hash % num_bucket]; i != 0 && i < num_chain; i = chain[i]) {
                    const auto *symbol = reinterpret_cast<const ElfW_(Sym) *>(symbol_table + (syment * i));
                    if (!symbol || symbol->st_name >= strsz)
                        break;

                    std::string sym_str = std::string(string_table + symbol->st_name);
                    if (!sym_str.empty() && sym_str == symbol_name)
                        return symbol;
                }

                return nullptr;
            }
        }
    }

    namespace Elf {
        namespace GnuHash {
            uint32_t HashSymName(const char *name) {
                uint32_t h = 5381;
                for (; *name; name++)
                    h = (h << 5) + h + *name;
                return h;
            }

            const ElfW_(Sym) *LookupByName(uintptr_t gnuhash,
                                           uintptr_t symtab,
                                           uintptr_t strtab,
                                           size_t syment,
                                           size_t strsz,
                                           const char *symbol_name) {

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

                uintptr_t word = bloom[(name_hash / ELFCLASS_BITS_) % bloom_size];
                uintptr_t mask = 0
                                 | (uintptr_t) 1 << (name_hash % ELFCLASS_BITS_)
                                 | (uintptr_t) 1 << ((name_hash >> bloom_shift) % ELFCLASS_BITS_);

                // If at least one bit is not set, a symbol is surely missing.
                if ((word & mask) != mask)
                    return nullptr;

                uint32_t sym_idx = buckets[name_hash % num_buckets];
                if (sym_idx < sym_offset)
                    return nullptr;

                // Loop through the chain.
                while (true) {
                    const auto *symbol = reinterpret_cast<const ElfW_(Sym) *>(symbol_table + (syment * sym_idx));
                    if (!symbol || symbol->st_name >= strsz)
                        break;

                    const uint32_t hash = chain[sym_idx - sym_offset];
                    if ((name_hash | 1) == (hash | 1)) {
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
        }
    }

#endif // __ANDROID__

}