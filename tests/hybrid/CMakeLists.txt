# Устанавливаем имя цели проверок гибридной группы X25519MLKEM768
SET(TEST_HYBRID_NAME hybrid)

# Добавляем цель проверок гибридной группы X25519MLKEM768
add_executable(${TEST_HYBRID_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/hybrid.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_HYBRID_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Передаём путь к набору ключей
target_compile_definitions(${TEST_HYBRID_NAME} PRIVATE ANTS_CORPUS="${CMAKE_SOURCE_DIR}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_HYBRID_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_HYBRID_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_HYBRID_NAME} COMMAND ${TEST_HYBRID_NAME})

# Если сборка ведётся под Solaris либо illumos
if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
	# Подключаем библиотеки сокетов
	target_link_libraries(${TEST_HYBRID_NAME} socket nsl)
endif()
