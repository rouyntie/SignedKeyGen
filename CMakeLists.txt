cmake_minimum_required(VERSION 3.14)
project(SignedKeyGen VERSION 1.0.0 LANGUAGES CXX)

# Используем стандарт C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Ищем установленный OpenSSL в системе
find_package(OpenSSL REQUIRED)

# Создаем библиотеку
add_library(SignedKeyGen src/keygen.cpp)
add_library(SignedKeyGen::SignedKeyGen ALIAS SignedKeyGen)

# Указываем папку с заголовочными файлами
target_include_directories(SignedKeyGen
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# Подключаем криптографическую часть OpenSSL
target_link_libraries(SignedKeyGen PUBLIC OpenSSL::Crypto)

# Опция для сборки примера (по умолчанию включена)
option(SIGNEDKEYGEN_BUILD_EXAMPLES "Build example executable" ON)

if(SIGNEDKEYGEN_BUILD_EXAMPLES)
    add_executable(example examples/example.cpp)
    target_link_libraries(example PRIVATE SignedKeyGen::SignedKeyGen)
endif()
