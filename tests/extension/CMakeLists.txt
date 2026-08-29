# Устанавливаем имя цели проверок модуля расширений приветствий
SET(TEST_EXTENSION_NAME extension)

# Добавляем цель проверок модуля расширений приветствий
add_executable(${TEST_EXTENSION_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/extension.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_EXTENSION_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_EXTENSION_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_EXTENSION_NAME} ${TLS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_EXTENSION_NAME} COMMAND ${TEST_EXTENSION_NAME})

