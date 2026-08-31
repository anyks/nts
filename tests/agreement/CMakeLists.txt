# Устанавливаем имя цели проверок модуля выработки общего ключа
SET(TEST_VKO_NAME vko)

# Добавляем цель проверок модуля выработки общего ключа
add_executable(${TEST_VKO_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/vko.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_VKO_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_VKO_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_VKO_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_VKO_NAME} COMMAND ${TEST_VKO_NAME})

# Устанавливаем имя цели проверок модуля обмена мимолётными ключами
SET(TEST_ECDHE_NAME ecdhe)

# Добавляем цель проверок модуля обмена мимолётными ключами
add_executable(${TEST_ECDHE_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/ecdhe.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_ECDHE_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_ECDHE_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_ECDHE_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_ECDHE_NAME} COMMAND ${TEST_ECDHE_NAME})
