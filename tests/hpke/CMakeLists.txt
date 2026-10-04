# Устанавливаем имя цели проверок модуля гибридного шифрования HPKE
SET(TEST_HPKE_NAME hpke)

# Добавляем цель проверок модуля гибридного шифрования HPKE
add_executable(${TEST_HPKE_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/hpke.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_HPKE_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_HPKE_NAME} PRIVATE "${ANTS_ROOT}/tests" "${CMAKE_CURRENT_SOURCE_DIR}")

# Определяем каталог контрольных примеров
target_compile_definitions(${TEST_HPKE_NAME} PRIVATE ANTS_CORPUS="${ANTS_ROOT}/tests/corpus")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_HPKE_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_HPKE_NAME} COMMAND ${TEST_HPKE_NAME})
