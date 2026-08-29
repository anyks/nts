# Устанавливаем имя цели проверок модуля хеширования «Стрибог»
SET(TEST_STREEBOG_NAME streebog)

# Добавляем цель проверок модуля хеширования «Стрибог»
add_executable(${TEST_STREEBOG_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/streebog.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_STREEBOG_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_STREEBOG_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_STREEBOG_NAME} ${TLS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

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
target_link_libraries(${TEST_HMAC_NAME} ${TLS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_HMAC_NAME} COMMAND ${TEST_HMAC_NAME})
