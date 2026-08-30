# Устанавливаем имя цели проверок ворошителя разборщиков
SET(TEST_FUZZER_NAME fuzzer)

# Добавляем цель проверок ворошителя разборщиков
add_executable(${TEST_FUZZER_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/fuzzer.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_FUZZER_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_FUZZER_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_FUZZER_NAME} ${TLS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_FUZZER_NAME} COMMAND ${TEST_FUZZER_NAME})

