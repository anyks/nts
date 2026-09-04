# Устанавливаем имя цели проверок классических наборов TLS 1.3
SET(TEST_CLASSIC_NAME classic)

# Добавляем цель проверок классических наборов TLS 1.3
add_executable(${TEST_CLASSIC_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/classic.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_CLASSIC_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Передаём путь к набору ключей для сличения: проверки читают его по абсолютному пути
target_compile_definitions(${TEST_CLASSIC_NAME} PRIVATE ANTS_CORPUS="${CMAKE_SOURCE_DIR}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_CLASSIC_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_CLASSIC_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_CLASSIC_NAME} COMMAND ${TEST_CLASSIC_NAME})

# Под системами Sun функции сокетов живут в отдельных библиотеках
if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
	target_link_libraries(${TEST_CLASSIC_NAME} socket nsl)
endif()
