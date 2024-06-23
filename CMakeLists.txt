# Minimum CMake version required
cmake_minimum_required(VERSION 3.10)

# Project name and version
project(cfcrypt VERSION 1.0)

# Specify the C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

# Find the OpenSSL library
find_package(OpenSSL REQUIRED)

set(SOURCES
    src/aes.c
    src/engine.c
    src/helper.c
    src/file_handler.c
)

# Include directories
include_directories(${OPENSSL_INCLUDE_DIR})

# Add the executable
add_executable(cfcrypt 
    src/cfcrypt.c 
    ${SOURCES}
)

# Link the OpenSSL libraries
target_link_libraries(cfcrypt ${OPENSSL_LIBRARIES})


# Testing
enable_testing()

# AES Test Case
add_executable(test_aes_128
    tests/test_aes_128.c
    ${SOURCES}
)

# Add tests
add_test(NAME test_aes_128 COMMAND test_aes_128)

# Link the OpenSSL libraries
target_link_libraries(test_aes_128 ${OPENSSL_LIBRARIES})
target_link_options(test_aes_128 PRIVATE -fsanitize=address)


# AES Test Case
add_executable(test_aes_192
    tests/test_aes_192.c
    ${SOURCES}
)

# Add tests
add_test(NAME test_aes_192 COMMAND test_aes_192)

# Link the OpenSSL libraries
target_link_libraries(test_aes_192 ${OPENSSL_LIBRARIES})
target_link_options(test_aes_192 PRIVATE -fsanitize=address)


# AES Test Case
add_executable(test_aes_256
    tests/test_aes_256.c
    ${SOURCES}
)

# Add tests
add_test(NAME test_aes_256 COMMAND test_aes_256)

# Link the OpenSSL libraries
target_link_libraries(test_aes_256 ${OPENSSL_LIBRARIES})
target_link_options(test_aes_256 PRIVATE -fsanitize=address)

# AES Test Case
add_executable(test_aes_128_passwd
    tests/test_aes_128_passwd.c
    ${SOURCES}
)

# Add tests
add_test(NAME test_aes_128_passwd COMMAND test_aes_128_passwd)

# Link the OpenSSL libraries
target_link_libraries(test_aes_128_passwd ${OPENSSL_LIBRARIES})
target_link_options(test_aes_128_passwd PRIVATE -fsanitize=address)


# AES Test Case
add_executable(test_aes_192_passwd
    tests/test_aes_192_passwd.c
    ${SOURCES}
)

# Add tests
add_test(NAME test_aes_192_passwd COMMAND test_aes_192_passwd)

# Link the OpenSSL libraries
target_link_libraries(test_aes_192_passwd ${OPENSSL_LIBRARIES})
target_link_options(test_aes_192_passwd PRIVATE -fsanitize=address)


# AES Test Case
add_executable(test_aes_256_passwd
    tests/test_aes_256_passwd.c
    ${SOURCES}
)

# Add tests
add_test(NAME test_aes_256_passwd COMMAND test_aes_256_passwd)

# Link the OpenSSL libraries
target_link_libraries(test_aes_256_passwd ${OPENSSL_LIBRARIES})
target_link_options(test_aes_256_passwd PRIVATE -fsanitize=address)