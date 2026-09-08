# Устанавливаем имя цели проверок издания DTLS 1.0
SET(TEST_DTLS10_NAME dtls10)

# Добавляем цель проверок издания DTLS 1.0
add_executable(${TEST_DTLS10_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/dtls10.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_DTLS10_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Передаём путь к набору ключей
target_compile_definitions(${TEST_DTLS10_NAME} PRIVATE ANTS_CORPUS="${CMAKE_SOURCE_DIR}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_DTLS10_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_DTLS10_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_DTLS10_NAME} COMMAND ${TEST_DTLS10_NAME})

# Если сборка ведётся под Solaris либо illumos
if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
	# Подключаем библиотеки сокетов
	target_link_libraries(${TEST_DTLS10_NAME} socket nsl)
endif()

