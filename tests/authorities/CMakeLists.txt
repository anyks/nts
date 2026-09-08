# Устанавливаем имя цели проверок перечня доверенных центров
SET(TEST_AUTHORITIES_NAME authorities)

# Добавляем цель проверок перечня доверенных центров
add_executable(${TEST_AUTHORITIES_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/authorities.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_AUTHORITIES_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Передаём путь к набору ключей
target_compile_definitions(${TEST_AUTHORITIES_NAME} PRIVATE ANTS_CORPUS="${CMAKE_SOURCE_DIR}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_AUTHORITIES_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_AUTHORITIES_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_AUTHORITIES_NAME} COMMAND ${TEST_AUTHORITIES_NAME})

# Если сборка ведётся под Solaris либо illumos
if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
	# Подключаем библиотеки сокетов
	target_link_libraries(${TEST_AUTHORITIES_NAME} socket nsl)
endif()

