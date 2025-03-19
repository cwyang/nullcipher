# OpenSSL3 Simple Cipher Provider
# 18 Mar 2025, Chul-Woong Yang
#
# $ cmake -DCMAKE_PREFIX_PATH=/home/cwyang/.local -S . -B build
#
cmake_minimum_required(VERSION 3.20 FATAL_ERROR)
project(
  simplecipher-provider
  VERSION 0.1
  DESCRIPTION "OpenSSL 3 Simple Cipher Provider"
  LANGUAGES C)
set(CMAKE_C_STANDARD 99)

set(null "nullcipher")
set(aria "ariacipher")
set(OPENSSL_ROOT "/home/cwyang/.local")

add_compile_definitions(AUTHOR="@cwyang")

# ctest
enable_testing()

# find openssl
find_package(OpenSSL 3.0 REQUIRED)

MESSAGE("OpenSSL_FOUND=${OpenSSL_FOUND}")
MESSAGE("To see OpenSSL environment, call cmake with --log-level=DEBUG")
MESSAGE(DEBUG "OPENSSL_ROOT_DIR=${OPENSSL_ROOT_DIR}")
MESSAGE(DEBUG "OpenSSL_CONFIG=${OpenSSL_CONFIG}")
MESSAGE(DEBUG "OpenSSL_VERSION=${OpenSSL_VERSION}")
MESSAGE(DEBUG "OpenSSL_VERSION_COUNT=${OpenSSL_VERSION_COUNT}")
MESSAGE(DEBUG "OpenSSL_VERSION_MAJOR=${OpenSSL_VERSION_MAJOR}")
MESSAGE(DEBUG "OpenSSL_VERSION_MINOR=${OpenSSL_VERSION_MINOR}")
MESSAGE(DEBUG "OpenSSL_VERSION_PATCH=${OpenSSL_VERSION_PATCH}")
MESSAGE(DEBUG "OpenSSL_VERSION_TWEAK=${OpenSSL_VERSION_TWEAK}")
MESSAGE(DEBUG "OPENSSL_CRYPTO_LIBRARY=${OPENSSL_CRYPTO_LIBRARY}")
MESSAGE(DEBUG "OPENSSL_CRYPTO_LIBRARIES=${OPENSSL_CRYPTO_LIBRARIES}")
MESSAGE(DEBUG "OPENSSL_SSL_LIBRARY=${OPENSSL_SSL_LIBRARY}")
MESSAGE(DEBUG "OPENSSL_SSL_LIBRARIES=${OPENSSL_SSL_LIBRARIES}")
MESSAGE(DEBUG "OPENSSL_LIBRARIES=${OPENSSL_LIBRARIES}")

# null provider
set(sources cipher_null.c)
add_library(${null} MODULE ${sources})
set_target_properties(${null} PROPERTIES
  PREFIX "" OUTPUT_NAME "${null}" SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
target_compile_definitions(${null} PRIVATE
  VERSION="${CMAKE_PROJECT_VERSION}"
  BUILDTYPE="${CMAKE_BUILD_TYPE}"
  )
target_include_directories(${null} PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(${null} PRIVATE ${libraries})

# aria provider
set(aria-sources cipher_aria.c)
add_library(${aria} MODULE ${aria-sources})
set_target_properties(${aria} PROPERTIES
  PREFIX "" OUTPUT_NAME "${aria}" SUFFIX ${CMAKE_SHARED_LIBRARY_SUFFIX})
target_compile_definitions(${aria} PRIVATE
  VERSION="${CMAKE_PROJECT_VERSION}"
  BUILDTYPE="${CMAKE_BUILD_TYPE}"
  )
target_include_directories(${aria} PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(${aria} PRIVATE ${libraries})

  
set(MODULE_DIRECTORY "${CMAKE_BINARY_DIR}")
message(STATUS "Module Directory=${MODULE_DIRECTORY}")

set(TEST_ENVIRONMENT
  "OPENSSL_MODULES=${MODULE_DIRECTORY}"
  "OPENSSL_PROGRAM=${OPENSSL_PROGRAM}"
  "OPENSSL_RUNTIME_DIR=${OPENSSL_ROOT}/bin"
  "OPENSSL_LIBRARY_DIR=${OPENSSL_ROOT}/lib64"
  "SOURCEDIR=${CMAKE_CURRENT_SOURCE_DIR}"
  "PERL5LIB=${CMAKE_CURRENT_SOURCE_DIR}/t"
  )

add_executable(test_nullcipher test_nullcipher.c)
target_link_libraries(test_nullcipher PRIVATE OpenSSL::Crypto)
add_test(NAME nullcipher
  COMMAND test_nullcipher)
set_tests_properties(nullcipher PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")

add_executable(test_ariacipher test_ariacipher.c)
target_link_libraries(test_ariacipher PRIVATE OpenSSL::Crypto)
add_test(NAME ariacipher
  COMMAND test_ariacipher)
set_tests_properties(ariacipher PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")

add_test(NAME openssl
  COMMAND prove -PWrapOpenSSL ${CMAKE_CURRENT_SOURCE_DIR}/t)
set_tests_properties(openssl PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")

