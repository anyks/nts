# Устанавливаем имя цели проверок находок аудита
SET(TEST_AUDIT_NAME audit)

# Добавляем цель проверок находок аудита
add_executable(${TEST_AUDIT_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/audit.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_AUDIT_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Передаём путь к набору ключей
target_compile_definitions(${TEST_AUDIT_NAME} PRIVATE ANTS_CORPUS="${CMAKE_SOURCE_DIR}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_AUDIT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_AUDIT_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_AUDIT_NAME} COMMAND ${TEST_AUDIT_NAME})
