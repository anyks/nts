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

# Устанавливаем имя цели проверок укрытого хранилища
SET(TEST_VAULT_NAME vault)

# Добавляем цель проверок укрытого хранилища
add_executable(${TEST_VAULT_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/vault.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_VAULT_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_VAULT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_VAULT_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_VAULT_NAME} COMMAND ${TEST_VAULT_NAME})

# Устанавливаем имя цели проверки связи без укрытого участка
SET(TEST_DEMAND_NAME demand)

# Добавляем цель проверки связи без укрытого участка
add_executable(${TEST_DEMAND_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/demand.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_DEMAND_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_DEMAND_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_DEMAND_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_DEMAND_NAME} COMMAND ${TEST_DEMAND_NAME})

# Устанавливаем имя цели проверки следа ключа в куче
SET(TEST_TRACE_NAME trace)

# Добавляем цель проверки следа ключа в куче
add_executable(${TEST_TRACE_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/trace.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_TRACE_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_TRACE_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_TRACE_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_TRACE_NAME} COMMAND ${TEST_TRACE_NAME})

# Устанавливаем имя цели проверок стока журнала
SET(TEST_LOG_NAME log)

# Добавляем цель проверок стока журнала
add_executable(${TEST_LOG_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/log.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_LOG_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_LOG_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_LOG_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_LOG_NAME} COMMAND ${TEST_LOG_NAME})
