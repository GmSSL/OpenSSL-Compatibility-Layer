if (CMAKE_VERSION VERSION_LESS "3.0")
	cmake_minimum_required(VERSION 2.8)
else()
	cmake_minimum_required(VERSION 3.6)
endif()

project(OpenSSL-Compatible-Layer C)

option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

include_directories(${PROJECT_SOURCE_DIR}/include /usr/local/include)
link_directories(/usr/local/lib)

set(crypto_src
	src/err.c
	src/bio.c
	src/evp.c
	src/rand.c
	src/asn1.c
	src/x509.c
	src/x509_vfy.c
	src/crypto.c
	src/pem.c
	src/dh.c
)

add_library(crypto ${crypto_src})
target_link_libraries(crypto gmssl)

set(ssl_src src/ssl.c)

add_library(ssl ${ssl_src})
target_link_libraries(ssl crypto)

install(TARGETS crypto ssl DESTINATION lib)
install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/openssl DESTINATION include)

