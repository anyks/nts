# Устанавливаем имя цели проверок состояния сертификата OCSP и сшивки ответа
SET(TEST_OCSP_NAME ocsp)

# Добавляем цель проверок состояния сертификата OCSP
add_executable(${TEST_OCSP_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/ocsp.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_OCSP_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Передаём путь к набору ключей для сличения: проверки читают его по абсолютному пути
target_compile_definitions(${TEST_OCSP_NAME} PRIVATE ANTS_CORPUS="${CMAKE_SOURCE_DIR}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_OCSP_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_OCSP_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_OCSP_NAME} COMMAND ${TEST_OCSP_NAME})

# Под системами Sun функции сокетов живут в отдельных библиотеках
if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
	target_link_libraries(${TEST_OCSP_NAME} socket nsl)
endif()
