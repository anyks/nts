# Устанавливаем имя цели проверок связи поверх дейтаграмм DTLS 1.2
SET(TEST_DTLS12_NAME dtls12)

# Добавляем цель проверок связи поверх дейтаграмм DTLS 1.2
add_executable(${TEST_DTLS12_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/dtls12.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_DTLS12_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Передаём путь к набору ключей для сличения: проверки читают его по абсолютному пути
target_compile_definitions(${TEST_DTLS12_NAME} PRIVATE ANTS_CORPUS="${CMAKE_SOURCE_DIR}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_DTLS12_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests" "${CMAKE_SOURCE_DIR}/tests/classic")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_DTLS12_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_DTLS12_NAME} COMMAND ${TEST_DTLS12_NAME})

# Под системами Sun функции сокетов живут в отдельных библиотеках
if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
	target_link_libraries(${TEST_DTLS12_NAME} socket nsl)
endif()
