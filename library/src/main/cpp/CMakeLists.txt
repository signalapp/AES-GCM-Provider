
cmake_minimum_required(VERSION 3.4.1)


add_subdirectory(third_party/boringssl/src/)

add_library(aesgcm SHARED AesGcmCipher.cpp)

target_include_directories(aesgcm PUBLIC third_party/boringssl/src/include/)

add_compile_options(-ffunction-sections -fdata-sections)
set (CMAKE_SHARED_LINKER_FLAGS "-Wl,-gc-sections")

target_link_libraries(aesgcm crypto)
