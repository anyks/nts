# Устанавливаем имя цели проверок модуля хеширования «Стрибог»
SET(TEST_STREEBOG_NAME streebog)

# Добавляем цель проверок модуля хеширования «Стрибог»
add_executable(${TEST_STREEBOG_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/streebog.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_STREEBOG_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_STREEBOG_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_STREEBOG_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_STREEBOG_NAME} COMMAND ${TEST_STREEBOG_NAME})

# Устанавливаем имя цели проверок модуля имитовставки HMAC
SET(TEST_HMAC_NAME hmac)

# Добавляем цель проверок модуля имитовставки HMAC
add_executable(${TEST_HMAC_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/hmac.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_HMAC_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_HMAC_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_HMAC_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_HMAC_NAME} COMMAND ${TEST_HMAC_NAME})

# Устанавливаем имя цели проверок модуля выработки производного ключа
SET(TEST_KDF_NAME kdf)

# Добавляем цель проверок модуля выработки производного ключа
add_executable(${TEST_KDF_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/kdf.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_KDF_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_KDF_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_KDF_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_KDF_NAME} COMMAND ${TEST_KDF_NAME})

SET(TEST_SHA2_NAME sha2)

# Добавляем цель проверок модуля имитовставки HMAC
add_executable(${TEST_SHA2_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/sha2.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_SHA2_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_SHA2_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_SHA2_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_SHA2_NAME} COMMAND ${TEST_SHA2_NAME})

SET(TEST_SHA1_NAME sha1)

# Добавляем цель проверок модуля имитовставки HMAC
add_executable(${TEST_SHA1_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/sha1.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_SHA1_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_SHA1_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_SHA1_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_SHA1_NAME} COMMAND ${TEST_SHA1_NAME})

SET(TEST_MD5_NAME md5)

# Добавляем цель проверок модуля имитовставки HMAC
add_executable(${TEST_MD5_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/md5.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_MD5_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_MD5_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_MD5_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_MD5_NAME} COMMAND ${TEST_MD5_NAME})

SET(TEST_HASH_NAME hash)

# Добавляем цель проверок модуля имитовставки HMAC
add_executable(${TEST_HASH_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/hash.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_HASH_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_HASH_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_HASH_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_HASH_NAME} COMMAND ${TEST_HASH_NAME})

SET(TEST_HKDF_NAME hkdf)

# Добавляем цель проверок модуля имитовставки HMAC
add_executable(${TEST_HKDF_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/hkdf.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_HKDF_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_HKDF_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_HKDF_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_HKDF_NAME} COMMAND ${TEST_HKDF_NAME})

SET(TEST_PBKDF2_NAME pbkdf2)

# Добавляем цель проверок модуля имитовставки HMAC
add_executable(${TEST_PBKDF2_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/pbkdf2.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_PBKDF2_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_PBKDF2_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_PBKDF2_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_PBKDF2_NAME} COMMAND ${TEST_PBKDF2_NAME})

# Устанавливаем имя цели проверок модуля хеширования SHA-3
SET(TEST_SHA3_NAME sha3)

# Добавляем цель проверок модуля хеширования SHA-3
add_executable(${TEST_SHA3_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/sha3.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_SHA3_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_SHA3_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_SHA3_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_SHA3_NAME} COMMAND ${TEST_SHA3_NAME})

# Устанавливаем имя цели проверок модуля cSHAKE и KMAC
SET(TEST_CSHAKE_NAME cshake)

# Добавляем цель проверок модуля cSHAKE и KMAC
add_executable(${TEST_CSHAKE_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/cshake.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_CSHAKE_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_CSHAKE_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_CSHAKE_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_CSHAKE_NAME} COMMAND ${TEST_CSHAKE_NAME})

# Устанавливаем имя цели проверок модуля blake2
SET(TEST_BLAKE2_NAME blake2)

# Добавляем цель проверок модуля blake2
add_executable(${TEST_BLAKE2_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/blake2.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_BLAKE2_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_BLAKE2_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_BLAKE2_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_BLAKE2_NAME} COMMAND ${TEST_BLAKE2_NAME})

# Устанавливаем имя цели проверок модуля argon2
SET(TEST_ARGON2_NAME argon2)

# Добавляем цель проверок модуля argon2
add_executable(${TEST_ARGON2_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/argon2.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_ARGON2_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_ARGON2_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_ARGON2_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_ARGON2_NAME} COMMAND ${TEST_ARGON2_NAME})

# Устанавливаем имя цели проверок модуля SipHash
SET(TEST_SIPHASH_NAME siphash)

# Добавляем цель проверок модуля SipHash
add_executable(${TEST_SIPHASH_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/siphash.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_SIPHASH_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_SIPHASH_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_SIPHASH_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_SIPHASH_NAME} COMMAND ${TEST_SIPHASH_NAME})
