# Устанавливаем имя цели проверок модуля протокола ACME
SET(TEST_ACME_NAME acme)

# Добавляем цель проверок модуля протокола ACME
add_executable(${TEST_ACME_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/acme.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_ACME_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Объявляем путь к набору образцов проверок
target_compile_definitions(${TEST_ACME_NAME} PRIVATE NTS_CORPUS="${NTS_ROOT}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_ACME_NAME} PRIVATE "${NTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_ACME_NAME} ${NTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_ACME_NAME} COMMAND ${TEST_ACME_NAME})

# Устанавливаем имя цели проверок связи модуля ACME с эталонным сервером
SET(TEST_ACME_INTEROP_NAME acme_interop)

# Добавляем цель проверок связи модуля ACME с эталонным сервером
add_executable(${TEST_ACME_INTEROP_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/interop.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_ACME_INTEROP_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Объявляем путь к набору образцов проверок
target_compile_definitions(${TEST_ACME_INTEROP_NAME} PRIVATE NTS_CORPUS="${NTS_ROOT}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_ACME_INTEROP_NAME} PRIVATE "${NTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_ACME_INTEROP_NAME} ${NTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_ACME_INTEROP_NAME} COMMAND ${TEST_ACME_INTEROP_NAME})
