# Устанавливаем имя цели проверок модуля фасадов связи
SET(TEST_CONTEXT_NAME context)

# Добавляем цель проверок модуля фасадов связи
add_executable(${TEST_CONTEXT_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/context.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_CONTEXT_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_CONTEXT_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_CONTEXT_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_CONTEXT_NAME} COMMAND ${TEST_CONTEXT_NAME})

