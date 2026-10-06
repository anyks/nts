# Устанавливаем имя цели проверок модуля протокола управления сертификатами
SET(TEST_CMP_NAME cmp)

# Добавляем цель проверок модуля протокола управления сертификатами
add_executable(${TEST_CMP_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/cmp.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_CMP_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Объявляем путь к набору образцов проверок
target_compile_definitions(${TEST_CMP_NAME} PRIVATE ANTS_CORPUS="${ANTS_ROOT}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_CMP_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_CMP_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_CMP_NAME} COMMAND ${TEST_CMP_NAME})
