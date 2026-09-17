# Устанавливаем имя цели проверок обмена классических наборов TLS 1.3 с системным openssl
SET(TEST_INTEROP_NAME interop)

# Добавляем цель проверок обмена классических наборов TLS 1.3 с системным openssl
add_executable(${TEST_INTEROP_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/interop.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_INTEROP_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Передаём путь к набору ключей для сличения: проверки читают его по абсолютному пути
target_compile_definitions(${TEST_INTEROP_NAME} PRIVATE ANTS_CORPUS="${ANTS_ROOT}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_INTEROP_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_INTEROP_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_INTEROP_NAME} COMMAND ${TEST_INTEROP_NAME})

# Под системами Sun функции сокетов живут в отдельных библиотеках
if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
	target_link_libraries(${TEST_INTEROP_NAME} socket nsl)
endif()
