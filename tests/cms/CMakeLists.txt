# Устанавливаем имя цели проверок модуля синтаксиса криптографических сообщений
SET(TEST_CMS_NAME cms)

# Добавляем цель проверок модуля синтаксиса криптографических сообщений
add_executable(${TEST_CMS_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/cms.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_CMS_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Объявляем путь к набору образцов проверок
target_compile_definitions(${TEST_CMS_NAME} PRIVATE ANTS_CORPUS="${ANTS_ROOT}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_CMS_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_CMS_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_CMS_NAME} COMMAND ${TEST_CMS_NAME})
