# Устанавливаем имя цели проверок меток времени сертификата SCT
SET(TEST_SCT_NAME sct)

# Добавляем цель проверок меток времени сертификата SCT
add_executable(${TEST_SCT_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/sct.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_SCT_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Передаём путь к набору ключей
target_compile_definitions(${TEST_SCT_NAME} PRIVATE ANTS_CORPUS="${ANTS_ROOT}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_SCT_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_SCT_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_SCT_NAME} COMMAND ${TEST_SCT_NAME})

# Если сборка ведётся под Solaris либо illumos
if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
	# Подключаем библиотеки сокетов
	target_link_libraries(${TEST_SCT_NAME} socket nsl)
endif()

