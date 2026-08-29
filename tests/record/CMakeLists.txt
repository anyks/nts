# Устанавливаем имя цели проверок модуля слоя записей протокола TLS
SET(TEST_RECORD_NAME record)

# Добавляем цель проверок модуля слоя записей протокола TLS
add_executable(${TEST_RECORD_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/record.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_RECORD_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_RECORD_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_RECORD_NAME} ${TLS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_RECORD_NAME} COMMAND ${TEST_RECORD_NAME})
