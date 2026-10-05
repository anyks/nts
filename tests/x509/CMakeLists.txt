# Устанавливаем имя цели проверок модуля сертификатов X.509
SET(TEST_X509_NAME x509)

# Добавляем цель проверок модуля сертификатов X.509
add_executable(${TEST_X509_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/x509.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_X509_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Объявляем путь к набору образцов проверок
target_compile_definitions(${TEST_X509_NAME} PRIVATE ANTS_CORPUS="${ANTS_ROOT}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_X509_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_X509_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_X509_NAME} COMMAND ${TEST_X509_NAME})

# Устанавливаем имя цели проверок модуля проверки подписи сертификата
SET(TEST_SIGNATURE_NAME signature)

# Добавляем цель проверок модуля проверки подписи сертификата
add_executable(${TEST_SIGNATURE_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/signature.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_SIGNATURE_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Объявляем путь к набору образцов проверок
target_compile_definitions(${TEST_SIGNATURE_NAME} PRIVATE ANTS_CORPUS="${ANTS_ROOT}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_SIGNATURE_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_SIGNATURE_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_SIGNATURE_NAME} COMMAND ${TEST_SIGNATURE_NAME})

# Устанавливаем имя цели проверок модуля запросов на сертификат PKCS #10
SET(TEST_REQUEST_NAME request)

# Добавляем цель проверок модуля запросов на сертификат PKCS #10
add_executable(${TEST_REQUEST_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/request.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_REQUEST_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Объявляем путь к набору образцов проверок
target_compile_definitions(${TEST_REQUEST_NAME} PRIVATE ANTS_CORPUS="${ANTS_ROOT}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_REQUEST_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_REQUEST_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_REQUEST_NAME} COMMAND ${TEST_REQUEST_NAME})

# Устанавливаем имя цели проверок модуля выпуска сертификатов X.509
SET(TEST_ISSUE_NAME issue)

# Добавляем цель проверок модуля выпуска сертификатов X.509
add_executable(${TEST_ISSUE_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/issue.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_ISSUE_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Объявляем путь к набору образцов проверок
target_compile_definitions(${TEST_ISSUE_NAME} PRIVATE ANTS_CORPUS="${ANTS_ROOT}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_ISSUE_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_ISSUE_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_ISSUE_NAME} COMMAND ${TEST_ISSUE_NAME})

# Устанавливаем имя цели проверок модуля списков отзыва сертификатов
SET(TEST_CRL_NAME crl)

# Добавляем цель проверок модуля списков отзыва сертификатов
add_executable(${TEST_CRL_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/crl.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_CRL_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Объявляем путь к набору образцов проверок
target_compile_definitions(${TEST_CRL_NAME} PRIVATE ANTS_CORPUS="${ANTS_ROOT}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_CRL_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_CRL_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_CRL_NAME} COMMAND ${TEST_CRL_NAME})
