#pragma once

#include <string>
#include <cstddef>

namespace SignedKeyGen {

int configure(const std::string& file_name);

std::string generateSignedKey(
    const std::string& param1, 
    const std::string& param2, 
    size_t keyLength = 32
);

bool verifySignedKey(const std::string& token);

} // namespace SignedKeyGen
