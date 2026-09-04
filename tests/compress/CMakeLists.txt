# Устанавливаем имя цели проверок сжатия цепочки сертификатов по RFC 8879
SET(TEST_COMPRESS_NAME compress)

# Добавляем цель проверок сжатия цепочки сертификатов
add_executable(${TEST_COMPRESS_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/compress.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_COMPRESS_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Передаём путь к набору ключей для сличения: проверки читают его по абсолютному пути
target_compile_definitions(${TEST_COMPRESS_NAME} PRIVATE ANTS_CORPUS="${CMAKE_SOURCE_DIR}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_COMPRESS_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_COMPRESS_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_COMPRESS_NAME} COMMAND ${TEST_COMPRESS_NAME})

# Под системами Sun функции сокетов живут в отдельных библиотеках
if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
	target_link_libraries(${TEST_COMPRESS_NAME} socket nsl)
endif()
