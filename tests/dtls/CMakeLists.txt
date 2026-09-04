# Устанавливаем имя цели проверок связи поверх дейтаграмм DTLS 1.3
SET(TEST_DTLS_NAME dtls)

# Добавляем цель проверок связи поверх дейтаграмм DTLS 1.3
add_executable(${TEST_DTLS_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/dtls.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_DTLS_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Передаём путь к набору ключей для сличения: проверки читают его по абсолютному пути
target_compile_definitions(${TEST_DTLS_NAME} PRIVATE ANTS_CORPUS="${CMAKE_SOURCE_DIR}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_DTLS_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests" "${CMAKE_SOURCE_DIR}/tests/classic")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_DTLS_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_DTLS_NAME} COMMAND ${TEST_DTLS_NAME})
