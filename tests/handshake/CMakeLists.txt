# Устанавливаем имя цели проверок модуля обвязки сообщений рукопожатия
SET(TEST_HANDSHAKE_NAME handshake)

# Добавляем цель проверок модуля обвязки сообщений рукопожатия
add_executable(${TEST_HANDSHAKE_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/handshake.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_HANDSHAKE_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_HANDSHAKE_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_HANDSHAKE_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_HANDSHAKE_NAME} COMMAND ${TEST_HANDSHAKE_NAME})

