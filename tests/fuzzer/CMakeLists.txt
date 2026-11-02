# Устанавливаем имя цели проверок ворошителя разборщиков
SET(TEST_FUZZER_NAME fuzzer)

# Добавляем цель проверок ворошителя разборщиков
add_executable(${TEST_FUZZER_NAME} "${CMAKE_CURRENT_SOURCE_DIR}/fuzzer.cpp")

# Включаем флаги компиляции проверок
target_compile_options(${TEST_FUZZER_NAME} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

# Подключаем каталог общих заголовочных файлов набора проверок
target_include_directories(${TEST_FUZZER_NAME} PRIVATE "${ANTS_ROOT}/tests")

# Выполняем подключение зависимостей цели проверок
target_link_libraries(${TEST_FUZZER_NAME} ${ANTS_LIB_NAME}_test GTest::gtest_main ${GCC_COVERAGE_LIBS})

# Регистрируем цель проверок
add_test(NAME ${TEST_FUZZER_NAME} COMMAND ${TEST_FUZZER_NAME})

# Если запрошены ворошители с управлением от покрытия
if (CMAKE_BUILD_LIBFUZZER)
    # Копируем исходные зерна в каталог сборки: новые входы не попадают в дерево исходников
    file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/corpus/" DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/corpus")
    # Если сборка идёт Apple Clang на macOS
    if (APPLE AND CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang")
        ##
         # Xcode несёт рабочие ASan/UBSan, но не содержит runtime libFuzzer. Берём его
         # из полного LLVM Homebrew: интерфейс инструментирования у линеек общий,
         # а санитайзеры остаются от Xcode и не входят в конфликт с инициализацией macOS
         ##
        file(GLOB ANTS_LIBFUZZER_RUNTIMES
            "/opt/homebrew/opt/llvm/lib/clang/*/lib/darwin/libclang_rt.fuzzer_osx.a"
            "/usr/local/opt/llvm/lib/clang/*/lib/darwin/libclang_rt.fuzzer_osx.a"
        )
        # Если runtime libFuzzer не найден
        if (NOT ANTS_LIBFUZZER_RUNTIMES)
            # Сообщаем о необходимости полного LLVM
            message(FATAL_ERROR "Apple Clang requires libclang_rt.fuzzer_osx.a from Homebrew LLVM (brew install llvm)")
        endif()
        # Берём первый найденный runtime libFuzzer
        list(GET ANTS_LIBFUZZER_RUNTIMES 0 ANTS_LIBFUZZER_LINK)
    # На остальных конфигурациях runtime подключается штатным ключом собирателя
    else()
        # Устанавливаем ключи компиляции и связывания ворошителя
        set(ANTS_LIBFUZZER_LINK -fsanitize=fuzzer)
    endif()
    ##
     # Функция создания ворошителя одного семейства разборщиков
     #
     # Аргумент:
     #  name - имя семейства разборщиков и его стартового корпуса
     ##
    function(add_parser_fuzzer name)
        # Устанавливаем имя цели ворошителя
        set(target fuzzer_${name})
        # Добавляем исполняемый файл ворошителя
        add_executable(${target} "${CMAKE_CURRENT_SOURCE_DIR}/libfuzzer/${name}.cpp")
        # Включаем санитайзеры и инструментирование входной точки
        target_compile_options(${target} PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})
        # Подключаем проверочную библиотеку и runtime ворошителя
        target_link_libraries(${target} ${ANTS_LIB_NAME}_test Threads::Threads ${GCC_COVERAGE_LIBS} ${ANTS_LIBFUZZER_LINK})
        # Регистрируем ограниченный повторимый прогон стартового корпуса
        add_test(NAME ${target} COMMAND ${target} "${CMAKE_CURRENT_BINARY_DIR}/corpus/${name}" -runs=1024 -seed=1 -max_len=65536 -timeout=10 -rss_limit_mb=2048)
        # Останавливаем прогон на первой находке санитайзеров
        set_tests_properties(${target} PROPERTIES ENVIRONMENT "ASAN_OPTIONS=abort_on_error=1;UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_stacktrace=1")
    endfunction()
    # Добавляем ворошитель записей ASN.1
    add_parser_fuzzer(asn1)
    # Добавляем ворошитель контейнеров ключей
    add_parser_fuzzer(keys)
    # Добавляем ворошитель записей инфраструктуры сертификатов
    add_parser_fuzzer(x509)
    # Добавляем ворошитель криптографических сообщений
    add_parser_fuzzer(cms)
    # Добавляем ворошитель сообщений управления сертификатами
    add_parser_fuzzer(cmp)
endif()

