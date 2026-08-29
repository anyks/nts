# Устанавливаем имя цели проверок модуля сообщений подтверждения подлинности
SET(TEST_MESSAGE_NAME message)

# Добавляем цель проверок модуля сообщений подтверждения подлинности
add_executable(${TEST_MESSAGE_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/message.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_MESSAGE_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_MESSAGE_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_MESSAGE_NAME} ${TLS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_MESSAGE_NAME} COMMAND ${TEST_MESSAGE_NAME})

