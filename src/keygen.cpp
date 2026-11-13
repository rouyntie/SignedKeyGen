#include "SignedKeyGen/keygen.hpp"

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <fstream>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

namespace SignedKeyGen {
namespace {

std::string SERVER_SECRET;

std::string toHex(const unsigned char* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return oss.str();
}

std::vector<unsigned char> fromHex(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Invalid hex string length");
    }
    std::vector<unsigned char> bytes;
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        unsigned char byte = static_cast<unsigned char>(std::stoi(hex.substr(i, 2), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::vector<unsigned char> computeHmac(const std::string& data) {
    std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);
    unsigned int digestLen = 0;

    unsigned char* result = HMAC(
        EVP_sha256(),
        SERVER_SECRET.data(),
        static_cast<int>(SERVER_SECRET.size()),
        reinterpret_cast<const unsigned char*>(data.data()),
        data.size(),
        digest.data(),
        &digestLen
    );

    if (!result) {
        throw std::runtime_error("HMAC computation failed");
    }

    digest.resize(digestLen);
    return digest;
}

std::string readFile(const std::string& file_name) {
    std::ifstream file(file_name);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open secret file: " + file_name);
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();

    while (!content.empty() && (content.back() == '\n' || content.back() == '\r')) {
        content.pop_back();
    }

    if (content.empty()) {
        throw std::runtime_error("Secret file is empty: " + file_name);
    }

    return content;
}

} // namespace

int configure(const std::string& file_name) {
    try {       
        SERVER_SECRET = readFile(file_name);
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
    return 0;
}

std::string generateSignedKey(
    const std::string& input_1,
    const std::string& input_2,
    size_t keyLength
) {
    if (SERVER_SECRET.empty()) {
        throw std::runtime_error("Library is not configured. Call configure() first.");
    }

    std::vector<unsigned char> salt(16);
    if (RAND_bytes(salt.data(), salt.size()) != 1) {
        throw std::runtime_error("Salt generation failed");
    }

    std::string inputData = input_1 + ":" + input_2;
    std::vector<unsigned char> derivedKey(keyLength);

    if (PKCS5_PBKDF2_HMAC(
            inputData.c_str(), static_cast<int>(inputData.length()),
            salt.data(), static_cast<int>(salt.size()),
            10000, EVP_sha256(),
            static_cast<int>(derivedKey.size()), derivedKey.data()) != 1) {
        throw std::runtime_error("PBKDF2 derivation failed");
    }

    std::string rawKeyHex = toHex(derivedKey.data(), derivedKey.size());
    std::vector<unsigned char> signature = computeHmac(rawKeyHex);
    std::string signatureHex = toHex(signature.data(), signature.size());

    return rawKeyHex + "." + signatureHex;
}

bool verifySignedKey(const std::string& token) {
    if (SERVER_SECRET.empty()) {
        return false;
    }

    size_t dotPos = token.find('.');
    if (dotPos == std::string::npos || dotPos == 0 || dotPos == token.length() - 1) {
        return false;
    }

    std::string rawKeyHex = token.substr(0, dotPos);
    std::string providedSigHex = token.substr(dotPos + 1);

    try {
        std::vector<unsigned char> providedSig = fromHex(providedSigHex);
        std::vector<unsigned char> expectedSig = computeHmac(rawKeyHex);

        if (providedSig.size() != expectedSig.size()) {
            return false;
        }

        return CRYPTO_memcmp(providedSig.data(), expectedSig.data(), expectedSig.size()) == 0;
    } catch (...) {
        return false;
    }
}

} // namespace SignedKeyGen
