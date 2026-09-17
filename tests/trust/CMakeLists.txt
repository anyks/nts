# Устанавливаем имя цели проверок модуля доверия цепочке сертификатов
SET(TEST_TRUST_NAME trust)

# Добавляем цель проверок модуля доверия цепочке сертификатов
add_executable(${TEST_TRUST_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/trust.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_TRUST_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Объявляем путь к набору образцов проверок
target_compile_definitions(${TEST_TRUST_NAME} PRIVATE ANTS_CORPUS="${ANTS_ROOT}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_TRUST_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_TRUST_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_TRUST_NAME} COMMAND ${TEST_TRUST_NAME})

