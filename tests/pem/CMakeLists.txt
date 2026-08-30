# Устанавливаем имя цели проверок модуля хранения записей в виде PEM
SET(TEST_PEM_NAME pem)

# Добавляем цель проверок модуля хранения записей в виде PEM
add_executable(${TEST_PEM_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/pem.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_PEM_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_PEM_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_PEM_NAME} ${TLS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_PEM_NAME} COMMAND ${TEST_PEM_NAME})

