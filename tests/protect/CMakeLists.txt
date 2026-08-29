# Устанавливаем имя цели проверок модуля защиты записей протокола TLS
SET(TEST_PROTECT_NAME protect)

# Добавляем цель проверок модуля защиты записей протокола TLS
add_executable(${TEST_PROTECT_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/protect.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_PROTECT_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_PROTECT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_PROTECT_NAME} ${TLS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_PROTECT_NAME} COMMAND ${TEST_PROTECT_NAME})

