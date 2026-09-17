# Устанавливаем имя цели проверок отпечатков приветствия
SET(TEST_FINGERPRINT_NAME fingerprint)

# Добавляем цель проверок отпечатков приветствия
add_executable(${TEST_FINGERPRINT_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/fingerprint.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_FINGERPRINT_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Передаём путь к набору ключей для сличения: проверки читают его по абсолютному пути
target_compile_definitions(${TEST_FINGERPRINT_NAME} PRIVATE ANTS_CORPUS="${ANTS_ROOT}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_FINGERPRINT_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_FINGERPRINT_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_FINGERPRINT_NAME} COMMAND ${TEST_FINGERPRINT_NAME})

# Под системами Sun функции сокетов живут в отдельных библиотеках
if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
	target_link_libraries(${TEST_FINGERPRINT_NAME} socket nsl)
endif()
