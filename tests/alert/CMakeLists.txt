# Устанавливаем имя цели проверок модуля извещений
SET(TEST_ALERT_NAME alert)

# Добавляем цель проверок модуля извещений
add_executable(${TEST_ALERT_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/alert.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_ALERT_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_ALERT_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_ALERT_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_ALERT_NAME} COMMAND ${TEST_ALERT_NAME})

