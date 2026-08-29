# Устанавливаем имя цели проверок модуля приветствий рукопожатия
SET(TEST_HELLO_NAME hello)

# Добавляем цель проверок модуля приветствий рукопожатия
add_executable(${TEST_HELLO_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/hello.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_HELLO_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_HELLO_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_HELLO_NAME} ${TLS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_HELLO_NAME} COMMAND ${TEST_HELLO_NAME})

