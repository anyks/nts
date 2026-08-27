# Устанавливаем имя цели проверок модуля ASN.1
SET(TEST_ASN1_NAME asn1)

# Добавляем цель проверок модуля ASN.1
add_executable(${TEST_ASN1_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/asn1.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_ASN1_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_ASN1_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_ASN1_NAME} ${TLS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_ASN1_NAME} COMMAND ${TEST_ASN1_NAME})
