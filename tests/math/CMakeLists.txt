# Устанавливаем имя цели проверок модуля арифметики
SET(TEST_NUMBER_NAME number)

# Добавляем цель проверок модуля арифметики
add_executable(${TEST_NUMBER_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/number.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_NUMBER_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_NUMBER_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_NUMBER_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_NUMBER_NAME} COMMAND ${TEST_NUMBER_NAME})

# Устанавливаем имя цели проверок модуля арифметики поля 2^255 - 19
SET(TEST_FIELD25519_NAME field25519)

# Добавляем цель проверок модуля арифметики поля 2^255 - 19
add_executable(${TEST_FIELD25519_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/field25519.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_FIELD25519_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_FIELD25519_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_FIELD25519_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_FIELD25519_NAME} COMMAND ${TEST_FIELD25519_NAME})

SET(TEST_INTEGER_NAME integer)

# Добавляем цель проверок модуля многоразрядных целых чисел
add_executable(${TEST_INTEGER_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/integer.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_INTEGER_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_INTEGER_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_INTEGER_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_INTEGER_NAME} COMMAND ${TEST_INTEGER_NAME})
