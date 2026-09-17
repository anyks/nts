# Устанавливаем имя цели проверок выработки протокола NPN
SET(TEST_NPN_NAME npn)

# Добавляем цель проверок выработки протокола NPN
add_executable(${TEST_NPN_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/npn.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_NPN_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Передаём путь к набору ключей
target_compile_definitions(${TEST_NPN_NAME} PRIVATE ANTS_CORPUS="${ANTS_ROOT}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_NPN_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_NPN_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_NPN_NAME} COMMAND ${TEST_NPN_NAME})

# Если сборка ведётся под Solaris либо illumos
if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
	# Подключаем библиотеки сокетов
	target_link_libraries(${TEST_NPN_NAME} socket nsl)
endif()

