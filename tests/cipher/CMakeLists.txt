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

# Устанавливаем имя цели проверок модуля поточной обёртки шифрования
SET(TEST_STREAM_NAME stream)

# Добавляем цель проверок модуля поточной обёртки шифрования
add_executable(${TEST_STREAM_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/stream.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_STREAM_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_STREAM_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_STREAM_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_STREAM_NAME} COMMAND ${TEST_STREAM_NAME})

# Устанавливаем имя цели проверок модуля поточного шифра ChaCha20
SET(TEST_CHACHA_NAME chacha)

# Добавляем цель проверок модуля поточного шифра ChaCha20
add_executable(${TEST_CHACHA_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/chacha.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_CHACHA_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_CHACHA_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_CHACHA_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_CHACHA_NAME} COMMAND ${TEST_CHACHA_NAME})

# Устанавливаем имя цели проверок модуля имитовставки Poly1305
SET(TEST_POLY1305_NAME poly1305)

# Добавляем цель проверок модуля имитовставки Poly1305
add_executable(${TEST_POLY1305_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/poly1305.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_POLY1305_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_POLY1305_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_POLY1305_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_POLY1305_NAME} COMMAND ${TEST_POLY1305_NAME})

# Устанавливаем имя цели проверок модуля шифрования с проверкой целостности ChaCha20-Poly1305
SET(TEST_CHACHAPOLY_NAME chachapoly)

# Добавляем цель проверок модуля шифрования с проверкой целостности ChaCha20-Poly1305
add_executable(${TEST_CHACHAPOLY_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/chachapoly.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_CHACHAPOLY_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_CHACHAPOLY_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_CHACHAPOLY_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_CHACHAPOLY_NAME} COMMAND ${TEST_CHACHAPOLY_NAME})

# Устанавливаем имя цели проверок сырых поточных шифров
SET(TEST_RAW_NAME raw)

# Добавляем цель проверок сырых поточных шифров
add_executable(${TEST_RAW_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/raw.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_RAW_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_RAW_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_RAW_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_RAW_NAME} COMMAND ${TEST_RAW_NAME})
