# Устанавливаем имя цели проверок модуля электронной подписи
SET(TEST_GOST_NAME gost)

# Добавляем цель проверок модуля электронной подписи
add_executable(${TEST_GOST_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/gost.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_GOST_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_GOST_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_GOST_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_GOST_NAME} COMMAND ${TEST_GOST_NAME})

# Устанавливаем имя цели проверок модуля электронной подписи Ed25519
SET(TEST_ED25519_NAME ed25519)

# Добавляем цель проверок модуля электронной подписи Ed25519
add_executable(${TEST_ED25519_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/ed25519.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_ED25519_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_ED25519_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_ED25519_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_ED25519_NAME} COMMAND ${TEST_ED25519_NAME})

SET(TEST_ECDSA_NAME ecdsa)

# Добавляем цель проверок модуля электронной подписи ECDSA
add_executable(${TEST_ECDSA_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/ecdsa.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_ECDSA_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_ECDSA_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_ECDSA_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_ECDSA_NAME} COMMAND ${TEST_ECDSA_NAME})

# Устанавливаем имя цели проверок модуля электронной подписи SM2
SET(TEST_SM2_NAME sm2)

# Добавляем цель проверок модуля электронной подписи SM2
add_executable(${TEST_SM2_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/sm2.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_SM2_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_SM2_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_SM2_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_SM2_NAME} COMMAND ${TEST_SM2_NAME})

SET(TEST_RSA_NAME rsa)

# Добавляем цель проверок модуля RSA
add_executable(${TEST_RSA_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/rsa.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_RSA_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_RSA_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_RSA_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_RSA_NAME} COMMAND ${TEST_RSA_NAME})

SET(TEST_MLDSA_NAME mldsa)

# Добавляем цель проверок модуля электронной подписи ML-DSA
add_executable(${TEST_MLDSA_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/mldsa.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_MLDSA_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_MLDSA_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Передаем расположение набора контрольных примеров
target_compile_definitions(${TEST_MLDSA_NAME} PRIVATE ANTS_CORPUS="${ANTS_ROOT}/tests/corpus")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_MLDSA_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_MLDSA_NAME} COMMAND ${TEST_MLDSA_NAME})

SET(TEST_SLHDSA_NAME slhdsa)

# Добавляем цель проверок модуля электронной подписи SLH-DSA
add_executable(${TEST_SLHDSA_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/slhdsa.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_SLHDSA_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_SLHDSA_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Передаем расположение набора контрольных примеров
target_compile_definitions(${TEST_SLHDSA_NAME} PRIVATE ANTS_CORPUS="${ANTS_ROOT}/tests/corpus")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_SLHDSA_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_SLHDSA_NAME} COMMAND ${TEST_SLHDSA_NAME})
