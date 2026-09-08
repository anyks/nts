# Устанавливаем имя цели проверок выработки протокола NPN
SET(TEST_LIMIT_NAME limit)

# Добавляем цель проверок выработки протокола NPN
add_executable(${TEST_LIMIT_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/limit.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_LIMIT_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Передаём путь к набору ключей
target_compile_definitions(${TEST_LIMIT_NAME} PRIVATE ANTS_CORPUS="${CMAKE_SOURCE_DIR}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_LIMIT_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_LIMIT_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_LIMIT_NAME} COMMAND ${TEST_LIMIT_NAME})

# Если сборка ведётся под Solaris либо illumos
if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
	# Подключаем библиотеки сокетов
	target_link_libraries(${TEST_LIMIT_NAME} socket nsl)
endif()

