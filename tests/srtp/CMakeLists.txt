# Устанавливаем имя цели проверок модуля защиты транспорта реального времени
SET(TEST_SRTP_NAME srtp)

# Добавляем цель проверок модуля защиты транспорта реального времени
add_executable(${TEST_SRTP_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/srtp.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_SRTP_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Объявляем путь к набору образцов проверок
target_compile_definitions(${TEST_SRTP_NAME} PRIVATE ANTS_CORPUS="${ANTS_ROOT}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_SRTP_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_SRTP_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_SRTP_NAME} COMMAND ${TEST_SRTP_NAME})
