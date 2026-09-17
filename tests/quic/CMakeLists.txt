# Устанавливаем имя цели проверок рукопожатия по уровням для QUIC
SET(TEST_QUIC_NAME quic)

# Добавляем цель проверок рукопожатия по уровням для QUIC
add_executable(${TEST_QUIC_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/quic.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_QUIC_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Передаём путь к набору ключей для сличения: проверки читают его по абсолютному пути
target_compile_definitions(${TEST_QUIC_NAME} PRIVATE ANTS_CORPUS="${ANTS_ROOT}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_QUIC_NAME} PRIVATE "${ANTS_ROOT}/tests" "${ANTS_ROOT}/tests/classic")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_QUIC_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_QUIC_NAME} COMMAND ${TEST_QUIC_NAME})
