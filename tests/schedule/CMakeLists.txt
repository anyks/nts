# Устанавливаем имя цели проверок модуля расписания ключей
SET(TEST_SCHEDULE_NAME schedule)

# Добавляем цель проверок модуля расписания ключей
add_executable(${TEST_SCHEDULE_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/schedule.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_SCHEDULE_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_SCHEDULE_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_SCHEDULE_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_SCHEDULE_NAME} COMMAND ${TEST_SCHEDULE_NAME})

