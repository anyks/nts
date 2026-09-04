# Устанавливаем имя цели проверок модуля электронной подписи
SET(TEST_GOST_NAME gost)

# Добавляем цель проверок модуля электронной подписи
add_executable(${TEST_GOST_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/gost.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_GOST_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_GOST_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

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
target_include_directories(${TEST_ED25519_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

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
target_include_directories(${TEST_ECDSA_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_ECDSA_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_ECDSA_NAME} COMMAND ${TEST_ECDSA_NAME})

SET(TEST_RSA_NAME rsa)

# Добавляем цель проверок модуля RSA
add_executable(${TEST_RSA_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/rsa.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_RSA_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_RSA_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_RSA_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_RSA_NAME} COMMAND ${TEST_RSA_NAME})
