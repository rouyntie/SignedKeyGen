# SignedKeyGen

A lightweight C++17 library for generating and verifying HMAC-SHA256 signed tokens derived via PBKDF2 using OpenSSL.

---

## Installation & Compilation

### 1. Install dependencies
* **Ubuntu/Debian/Mint:**
  ```bash
  sudo apt update && sudo apt install -y g++ cmake libssl-dev
  ```
* **Fedora/RHEL/CentOS:**
  ```bash
  sudo dnf install -y gcc-c++ cmake openssl-devel
  ```
* **Arch/Manjaro:**
  ```bash
  sudo pacman -S --needed gcc cmake openssl
  ```

### 2. Build with CMake
```bash
git clone https://github.com
cd SignedKeyGen
cmake -B build
cmake --build build
```

*(Optional) Manual compilation without CMake:*
```bash
g++ -std=c++17 -Iinclude src/keygen.cpp examples/example.cpp -lssl -lcrypto -o program
```

---

## Usage

Create a `secret_key.txt` file containing your server secret key before running the program.

```cpp
#include <iostream>
#include <string>
#include <exception>

#include "SignedKeyGen/keygen.hpp"

int main() {
    std::string login = "login123";
    std::string time = "11.01.2026";

    if (SignedKeyGen::configure("secret_key.txt") != 0) {
        std::cerr << "Failed to initialize library. Check secret_key.txt" << std::endl;
        return 1;
    }

    try {
        std::string key = SignedKeyGen::generateSignedKey(login, time);
        std::cout << "Generated key: " << key << std::endl;

        bool isValid = SignedKeyGen::verifySignedKey(key);
        std::cout << "Valid: " << std::boolalpha << isValid << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
```

### Example Output
**Signed Key (`<derived_key>.<hmac_signature>`):**
```text
3e649a34faa74fe8bfabe2f06e88e0ea1809cf8d66d834eea7ae32b8048eaedd.c776ed4a3c12fd32a3a9299d063c11ccc46f3807494bd9bbecf807c48d0b79e3
```

**Verification:**
```text
Valid: true
```