# Устанавливаем имя цели проверок модулей блочного шифрования
SET(TEST_CIPHER_NAME cipher)

# Добавляем цель проверок модулей блочного шифрования
add_executable(${TEST_CIPHER_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/cipher.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_CIPHER_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_CIPHER_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_CIPHER_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_CIPHER_NAME} COMMAND ${TEST_CIPHER_NAME})

# Устанавливаем имя цели проверок модуля режимов работы блочных шифров
SET(TEST_MODE_NAME mode)

# Добавляем цель проверок модуля режимов работы блочных шифров
add_executable(${TEST_MODE_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/mode.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_MODE_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_MODE_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_MODE_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_MODE_NAME} COMMAND ${TEST_MODE_NAME})

# Устанавливаем имя цели проверок модуля режима шифрования с проверкой целостности
SET(TEST_MGM_NAME mgm)

# Добавляем цель проверок модуля режима шифрования с проверкой целостности
add_executable(${TEST_MGM_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/mgm.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_MGM_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_MGM_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_MGM_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_MGM_NAME} COMMAND ${TEST_MGM_NAME})

SET(TEST_AES_NAME aes)

# Добавляем цель проверок модуля режима шифрования с проверкой целостности
add_executable(${TEST_AES_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/aes.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_AES_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_AES_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_AES_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_AES_NAME} COMMAND ${TEST_AES_NAME})

SET(TEST_GCM_NAME gcm)

# Добавляем цель проверок модуля режима шифрования с проверкой целостности
add_executable(${TEST_GCM_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/gcm.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_GCM_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_GCM_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_GCM_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_GCM_NAME} COMMAND ${TEST_GCM_NAME})
