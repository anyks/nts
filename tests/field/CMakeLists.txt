# Устанавливаем имя цели проверок модуля полей протокола
SET(TEST_FIELD_NAME field)

# Добавляем цель проверок модуля полей протокола
add_executable(${TEST_FIELD_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/field.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_FIELD_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_FIELD_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_FIELD_NAME} ${TLS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_FIELD_NAME} COMMAND ${TEST_FIELD_NAME})

