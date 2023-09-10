#include "KittyUtils.hpp"

namespace KittyUtils {

    std::string fileNameFromPath(const std::string &filePath)
    {
        std::string filename;
        const size_t last_slash_idx = filePath.find_last_of("/\\");
        if (std::string::npos != last_slash_idx)
            filename = filePath.substr(last_slash_idx + 1);
        return filename;
    }
    
    void trim_string(std::string &str) 
    {
        // https://www.techiedelight.com/remove-whitespaces-string-cpp/
        str.erase(std::remove_if(str.begin(), str.end(), [](char c)
                                 { return (c == ' ' || c == '\n' || c == '\r' ||
                                           c == '\t' || c == '\v' || c == '\f'); }),
                  str.end());
    }

    bool validateHexString(std::string &hex) 
    {
        if (hex.empty()) return false;

        if (hex.compare(0, 2, "0x") == 0)
            hex.erase(0, 2);

        trim_string(hex); // first remove spaces
        
        if (hex.length() < 2 || hex.length() % 2 != 0) return false;

        for (size_t i = 0; i < hex.length(); i++) {
            if (!std::isxdigit((unsigned char) hex[i]))
                return false;
        }
        
        return true;
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

}