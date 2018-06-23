# Copyright (c) 2018 The Luxcore developers

project(Lux)

set(CMAKE_CXX_STANDARD 11)

# The library
add_library(crypto
    sha1.cpp
	sha256.cpp
	sha512.cpp
	hmac_sha256.cpp
	rfc6979_hmac_sha256.cpp
	hmac_sha512.cpp
	scrypt.cpp
	ripemd160.cpp
)

target_include_directories(crypto
     PRIVATE
        ..
     PUBLIC
        # To access the config.
        ${CMAKE_CURRENT_BINARY_DIR}/..
        ${CMAKE_CURRENT_BINARY_DIR}/../config
)

target_compile_definitions(crypto PUBLIC HAVE_CONFIG_H)
