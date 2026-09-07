# Устанавливаем имя цели проверок модуля зашифрованного приветствия клиента ECH
SET(TEST_ECH_NAME ech)

# Добавляем цель проверок модуля зашифрованного приветствия клиента ECH
add_executable(${TEST_ECH_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/ech.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_ECH_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Передаём путь к набору образцов: проверки читают конфигурации BoringSSL по абсолютному пути
target_compile_definitions(${TEST_ECH_NAME} PRIVATE ANTS_CORPUS="${CMAKE_SOURCE_DIR}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_ECH_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests" "${CMAKE_CURRENT_SOURCE_DIR}")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_ECH_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_ECH_NAME} COMMAND ${TEST_ECH_NAME})

# Под системами Sun функции сокетов живут в отдельных библиотеках
if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
	target_link_libraries(${TEST_ECH_NAME} socket nsl)
endif()
