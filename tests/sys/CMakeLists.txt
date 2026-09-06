# Устанавливаем имя цели проверок служебных средств
SET(TEST_SYS_NAME wipe)

# Добавляем цель проверок затирания памяти
add_executable(${TEST_SYS_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/wipe.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_SYS_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_SYS_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_SYS_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_SYS_NAME} COMMAND ${TEST_SYS_NAME})

# Устанавливаем имя цели проверок признаков машины
SET(TEST_MACHINE_NAME machine)

# Добавляем цель проверок признаков машины
add_executable(${TEST_MACHINE_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/machine.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_MACHINE_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_MACHINE_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_MACHINE_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_MACHINE_NAME} COMMAND ${TEST_MACHINE_NAME})
