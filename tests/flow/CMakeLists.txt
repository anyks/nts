# Устанавливаем имя цели проверок модуля хода рукопожатия
SET(TEST_FLOW_NAME flow)

# Добавляем цель проверок модуля хода рукопожатия
add_executable(${TEST_FLOW_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/flow.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_FLOW_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_FLOW_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_FLOW_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_FLOW_NAME} COMMAND ${TEST_FLOW_NAME})

