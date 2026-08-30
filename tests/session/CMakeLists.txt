# Устанавливаем имя цели проверок модуля состояния связи
SET(TEST_SESSION_NAME session)

# Добавляем цель проверок модуля состояния связи
add_executable(${TEST_SESSION_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/session.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_SESSION_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_SESSION_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_SESSION_NAME} ${TLS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_SESSION_NAME} COMMAND ${TEST_SESSION_NAME})

