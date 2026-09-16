# Устанавливаем имя цели проверок модуля зашивания ключа в образ
SET(TEST_EMBED_NAME embed)

# Добавляем цель проверок модуля зашивания ключа в образ
add_executable(${TEST_EMBED_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/embed.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_EMBED_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_EMBED_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_EMBED_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_EMBED_NAME} COMMAND ${TEST_EMBED_NAME})
