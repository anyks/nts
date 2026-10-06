# Устанавливаем имя цели проверок модуля подписей JWS
SET(TEST_JWS_NAME jws)

# Добавляем цель проверок модуля подписей JWS
add_executable(${TEST_JWS_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/jws.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_JWS_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Объявляем путь к набору образцов проверок
target_compile_definitions(${TEST_JWS_NAME} PRIVATE ANTS_CORPUS="${ANTS_ROOT}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_JWS_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_JWS_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_JWS_NAME} COMMAND ${TEST_JWS_NAME})
