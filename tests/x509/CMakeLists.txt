# Устанавливаем имя цели проверок модуля сертификатов X.509
SET(TEST_X509_NAME x509)

# Добавляем цель проверок модуля сертификатов X.509
add_executable(${TEST_X509_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/x509.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_X509_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_X509_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_X509_NAME} ${TLS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_X509_NAME} COMMAND ${TEST_X509_NAME})
