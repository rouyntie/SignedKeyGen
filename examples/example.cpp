#include <iostream>
#include <string>
#include <exception>

#include "SignedKeyGen/keygen.hpp"

int main() {
    // Mock data
    std::string login = "rouytnie";
    std::string time = "11.01.2026";

    // Check status
    if (SignedKeyGen::configure("secret_key.txt") != 0) {
        std::cerr << "Failed initialize lib. Check secret_key.txt" << std::endl;
        return 1;
    }

    try {
        // Generate signed key
        std::string key = SignedKeyGen::generateSignedKey(login, time);
        std::cout << "Generated key: " << key << std::endl;

        // Check identity key
        bool isValid = SignedKeyGen::verifySignedKey(key);
        std::cout << "Key is valid: " << std::boolalpha << isValid << std::endl;

        // Example of verification a faked signed key
        std::string fakeKey = key + "a";
        std::cout << "Key is valid: " << SignedKeyGen::verifySignedKey(fakeKey) << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error work on key: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
