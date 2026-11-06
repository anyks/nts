# Устанавливаем имя цели проверок кодека основания 64
SET(TEST_BASE64_NAME base64)

# Добавляем цель проверок кодека основания 64
add_executable(${TEST_BASE64_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/base64.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_BASE64_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_BASE64_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_BASE64_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_BASE64_NAME} COMMAND ${TEST_BASE64_NAME})
