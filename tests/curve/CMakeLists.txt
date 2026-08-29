# Устанавливаем имя цели проверок модуля эллиптических кривых
SET(TEST_CURVE_NAME curve)

# Добавляем цель проверок модуля эллиптических кривых
add_executable(${TEST_CURVE_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/curve.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_CURVE_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_CURVE_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_CURVE_NAME} ${TLS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_CURVE_NAME} COMMAND ${TEST_CURVE_NAME})

# Устанавливаем имя цели проверок наборов параметров эллиптических кривых
SET(TEST_PARAMETERS_NAME parameters)

# Добавляем цель проверок наборов параметров эллиптических кривых
add_executable(${TEST_PARAMETERS_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/parameters.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_PARAMETERS_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_PARAMETERS_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_PARAMETERS_NAME} ${TLS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_PARAMETERS_NAME} COMMAND ${TEST_PARAMETERS_NAME})
