# Устанавливаем имя цели проверок модуля хеширования «Стрибог»
SET(TEST_STREEBOG_NAME streebog)

# Добавляем цель проверок модуля хеширования «Стрибог»
add_executable(${TEST_STREEBOG_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/streebog.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_STREEBOG_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_STREEBOG_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

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
target_include_directories(${TEST_HMAC_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

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
target_include_directories(${TEST_KDF_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

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
target_include_directories(${TEST_SHA2_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

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
target_include_directories(${TEST_SHA1_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

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
target_include_directories(${TEST_MD5_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

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
target_include_directories(${TEST_HASH_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

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
target_include_directories(${TEST_HKDF_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

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
target_include_directories(${TEST_PBKDF2_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_PBKDF2_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_PBKDF2_NAME} COMMAND ${TEST_PBKDF2_NAME})
