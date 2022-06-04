#pragma once

#include <string>
#include <algorithm>

namespace KittyUtils {

    bool validateHexString(std::string &xstr);
    void toHex(void *const data, const size_t dataLength, std::string &dest);
    void fromHex(const std::string &in, void *const data);

}