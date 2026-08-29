# Устанавливаем имя цели проверок модуля электронной подписи
SET(TEST_GOST_NAME gost)

# Добавляем цель проверок модуля электронной подписи
add_executable(${TEST_GOST_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/gost.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_GOST_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_GOST_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_GOST_NAME} ${TLS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_GOST_NAME} COMMAND ${TEST_GOST_NAME})
