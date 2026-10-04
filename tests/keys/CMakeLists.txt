# Устанавливаем имя цели проверок модуля кодеков ключей
SET(TEST_KEYS_NAME keys)

# Добавляем цель проверок модуля кодеков ключей
add_executable(${TEST_KEYS_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/keys.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_KEYS_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Передаём путь к набору ключей для сличения: проверки читают его по абсолютному пути
target_compile_definitions(${TEST_KEYS_NAME} PRIVATE ANTS_CORPUS="${ANTS_ROOT}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_KEYS_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_KEYS_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_KEYS_NAME} COMMAND ${TEST_KEYS_NAME})

# Устанавливаем имя цели проверок модуля формата openssh-key-v1
SET(TEST_OPENSSH_NAME openssh)

# Добавляем цель проверок модуля формата openssh-key-v1
add_executable(${TEST_OPENSSH_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/openssh.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_OPENSSH_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_OPENSSH_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_OPENSSH_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_OPENSSH_NAME} COMMAND ${TEST_OPENSSH_NAME})
