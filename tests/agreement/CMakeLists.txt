# Устанавливаем имя цели проверок модуля выработки общего ключа
SET(TEST_VKO_NAME vko)

# Добавляем цель проверок модуля выработки общего ключа
add_executable(${TEST_VKO_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/vko.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_VKO_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_VKO_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_VKO_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_VKO_NAME} COMMAND ${TEST_VKO_NAME})

# Устанавливаем имя цели проверок модуля обмена мимолётными ключами
SET(TEST_ECDHE_NAME ecdhe)

# Добавляем цель проверок модуля обмена мимолётными ключами
add_executable(${TEST_ECDHE_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/ecdhe.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_ECDHE_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_ECDHE_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_ECDHE_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_ECDHE_NAME} COMMAND ${TEST_ECDHE_NAME})

# Устанавливаем имя цели проверок модуля выработки общего ключа X25519
SET(TEST_X25519_NAME x25519)

# Добавляем цель проверок модуля выработки общего ключа X25519
add_executable(${TEST_X25519_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/x25519.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_X25519_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_X25519_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_X25519_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_X25519_NAME} COMMAND ${TEST_X25519_NAME})

# Устанавливаем имя цели проверок модуля инкапсуляции ключа ML-KEM
SET(TEST_MLKEM_NAME mlkem)

# Добавляем цель проверок модуля инкапсуляции ключа ML-KEM
add_executable(${TEST_MLKEM_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/mlkem.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_MLKEM_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Передаём путь к набору векторов
target_compile_definitions(${TEST_MLKEM_NAME} PRIVATE ANTS_CORPUS="${ANTS_ROOT}/tests/corpus")

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_MLKEM_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_MLKEM_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_MLKEM_NAME} COMMAND ${TEST_MLKEM_NAME})

# Устанавливаем имя цели проверок модуля выработки общего ключа X448
SET(TEST_X448_NAME x448)

# Добавляем цель проверок модуля выработки общего ключа X448
add_executable(${TEST_X448_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/x448.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_X448_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_X448_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_X448_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_X448_NAME} COMMAND ${TEST_X448_NAME})

# Устанавливаем имя цели проверок модуля выработки общего ключа в конечном поле RFC 7919
SET(TEST_FFDHE_NAME ffdhe)

# Добавляем цель проверок модуля выработки общего ключа в конечном поле RFC 7919
add_executable(${TEST_FFDHE_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/ffdhe.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_FFDHE_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_FFDHE_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_FFDHE_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_FFDHE_NAME} COMMAND ${TEST_FFDHE_NAME})

# Устанавливаем имя цели проверок модуля инкапсуляции ключа sntrup761
SET(TEST_SNTRUP761_NAME sntrup761)

# Добавляем цель проверок модуля инкапсуляции ключа sntrup761
add_executable(${TEST_SNTRUP761_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/sntrup761.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_SNTRUP761_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_SNTRUP761_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_SNTRUP761_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_SNTRUP761_NAME} COMMAND ${TEST_SNTRUP761_NAME})

# Устанавливаем имя цели проверок модуля гибридного обмена sntrup761x25519
SET(TEST_SNTRUP761X25519_NAME sntrup761x25519)

# Добавляем цель проверок модуля гибридного обмена sntrup761x25519
add_executable(${TEST_SNTRUP761X25519_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/sntrup761x25519.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_SNTRUP761X25519_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_SNTRUP761X25519_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_SNTRUP761X25519_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_SNTRUP761X25519_NAME} COMMAND ${TEST_SNTRUP761X25519_NAME})
