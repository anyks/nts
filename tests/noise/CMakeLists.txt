# Устанавливаем имя цели проверок каркаса Noise
SET(TEST_NOISE_NAME noise)

# Добавляем цель проверок каркаса Noise
add_executable(${TEST_NOISE_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/noise.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_NOISE_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Передаём путь к набору ключей
target_compile_definitions(${TEST_NOISE_NAME} PRIVATE ANTS_CORPUS="${CMAKE_SOURCE_DIR}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_NOISE_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_NOISE_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_NOISE_NAME} COMMAND ${TEST_NOISE_NAME})

# Если сборка ведётся под Solaris либо illumos
if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
	# Подключаем библиотеки сокетов
	target_link_libraries(${TEST_NOISE_NAME} socket nsl)
endif()

# Устанавливаем имя цели проверок кадров WireGuard поверх Noise
SET(TEST_WIREGUARD_NAME wireguard)

# Добавляем цель проверок кадров WireGuard
add_executable(${TEST_WIREGUARD_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/wireguard.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_WIREGUARD_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Передаём путь к набору корпусов
target_compile_definitions(${TEST_WIREGUARD_NAME} PRIVATE ANTS_CORPUS="${CMAKE_SOURCE_DIR}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_WIREGUARD_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_WIREGUARD_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_WIREGUARD_NAME} COMMAND ${TEST_WIREGUARD_NAME})

# Если сборка ведётся под Solaris либо illumos
if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
	# Подключаем библиотеки сокетов
	target_link_libraries(${TEST_WIREGUARD_NAME} socket nsl)
endif()

# Устанавливаем имя цели проверок PQNoise
SET(TEST_PQNOISE_NAME pqnoise)

# Добавляем цель проверок PQNoise
add_executable(${TEST_PQNOISE_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/pqnoise.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_PQNOISE_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Передаём путь к набору корпусов
target_compile_definitions(${TEST_PQNOISE_NAME} PRIVATE ANTS_CORPUS="${CMAKE_SOURCE_DIR}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_PQNOISE_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_PQNOISE_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_PQNOISE_NAME} COMMAND ${TEST_PQNOISE_NAME})

# Если сборка ведётся под Solaris либо illumos
if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
	# Подключаем библиотеки сокетов
	target_link_libraries(${TEST_PQNOISE_NAME} socket nsl)
endif()
