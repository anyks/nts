# Устанавливаем минимальную версию CMake
cmake_minimum_required(VERSION 3.15)

# Устанавливаем название проекта
project(anyks-tls LANGUAGES CXX)

# Устанавливаем полное название проекта
SET(PROJECT_VENDOR_LONG "ANYKS - SSL")

# Опции сборки
SET(PROJECT_COPYRIGHT "Copyright (c) ${CURRENT_YEAR} ${PROJECT_VENDOR_LONG}")

# Тип сборки
# cmake -DCMAKE_BUILD_TYPE=Release ..
if (NOT CMAKE_BUILD_TYPE)
    # Активируем режим отладки
    SET(CMAKE_BUILD_TYPE Debug)
endif (NOT CMAKE_BUILD_TYPE)

# Выводим сообщение о типе сборки
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}\n")

##
 # Указываем что проверки нужно собрать под санитайзерами
 #
 # @note Ключ объявляется здесь, а не рядом с проверками: объектные файлы с
 #       санитайзерами и без них несовместимы, и каталог сборки под него берётся свой
 ##
option(CMAKE_BUILD_SANITIZE "Build unit tests with sanitizers" OFF)

# Набор включаемых санитайзеров
SET(CMAKE_BUILD_SANITIZE_LIST "address,undefined" CACHE STRING "Sanitizers enabled for unit tests")

# Указываем что нужно собрать набор проверок
option(CMAKE_BUILD_TESTS "Build unit tests" OFF)

# Указываем что нужно собрать динамическую библиотеку вместо статической
option(CMAKE_SHARED_BUILD_LIB "Build shared library instead of static one" OFF)

# Устанавливаем стандарт языка
SET(CMAKE_CXX_STANDARD 17)
SET(CMAKE_CXX_STANDARD_REQUIRED ON)

# Отключаем расширения собирателя
SET(CMAKE_CXX_EXTENSIONS OFF)

# Устанавливаем флаги компиляции
if (NOT MSVC)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
endif (NOT MSVC)

##
 # Скрываем символы, не помеченные к вывозу наружу
 #
 # Правило это касается и статической сборки: набор вывозимых наружу символов обязан
 # быть одним и тем же у обоих видов библиотеки, иначе потребитель, собранный с одной,
 # перестаёт собираться с другой
 ##
SET(CMAKE_CXX_VISIBILITY_PRESET hidden)
SET(CMAKE_VISIBILITY_INLINES_HIDDEN ON)

# Подключаем каталог заголовочных файлов проекта
include_directories(${CMAKE_SOURCE_DIR}/include)

##
 # Подключаем каталог исходных файлов проекта
 #
 # Каталог нужен для внутренних модулей: они лежат в src/internal и подключаются
 # записью вида <internal/имя/имя.hpp> из файлов реализации
 ##
include_directories(${CMAKE_SOURCE_DIR}/src)

##
 # Заслон от вывоза внутренних модулей в наружный вид библиотеки
 #
 # Внутренние модули переносятся из AWH и переделываются под задачи проекта. Попав в
 # заголовочный файл каталога include, они закрепили бы собой наружный договор
 # библиотеки - а вместе с ним и своё устройство, выбранное под другие задачи.
 #
 # Правило это без проверки не соблюдается: подключение внутреннего модуля из
 # наружного заголовочного файла собирается и работает, и заметить его можно только
 # тогда, когда менять наружный вид уже поздно
 ##
file(GLOB_RECURSE PUBLIC_HEADERS "${CMAKE_SOURCE_DIR}/include/*.hpp")

# Выполняем обход наружных заголовочных файлов библиотеки
foreach (HEADER ${PUBLIC_HEADERS})
    # Читаем содержимое наружного заголовочного файла
    file(STRINGS "${HEADER}" HEADER_LINES REGEX "^[ \t]*#[ \t]*include.*internal/")
    # Если внутренний модуль подключается из наружного заголовочного файла
    if (HEADER_LINES)
        # Получаем имя файла относительно корня проекта
        file(RELATIVE_PATH HEADER_NAME "${CMAKE_SOURCE_DIR}" "${HEADER}")
        # Обрываем настройку сборки отказом
        message(FATAL_ERROR "Internal module is exposed in the public header ${HEADER_NAME}: ${HEADER_LINES}. Internal modules must be included from .cpp files only")
    endif()
endforeach()

# Устанавливаем список исходных файлов библиотеки
SET(SOURCE_FILES
    "${CMAKE_SOURCE_DIR}/src/field/field.cpp"
    "${CMAKE_SOURCE_DIR}/src/asn1/asn1.cpp"
    "${CMAKE_SOURCE_DIR}/src/x509/x509.cpp"
    "${CMAKE_SOURCE_DIR}/src/x509/signature.cpp"
    "${CMAKE_SOURCE_DIR}/src/digest/streebog.cpp"
    "${CMAKE_SOURCE_DIR}/src/digest/hmac.cpp"
    "${CMAKE_SOURCE_DIR}/src/digest/kdf.cpp"
    "${CMAKE_SOURCE_DIR}/src/cipher/kuznyechik.cpp"
    "${CMAKE_SOURCE_DIR}/src/cipher/magma.cpp"
    "${CMAKE_SOURCE_DIR}/src/cipher/mode.cpp"
    "${CMAKE_SOURCE_DIR}/src/cipher/mgm.cpp"
    "${CMAKE_SOURCE_DIR}/src/math/number.cpp"
    "${CMAKE_SOURCE_DIR}/src/entropy/entropy.cpp"
    "${CMAKE_SOURCE_DIR}/src/curve/curve.cpp"
    "${CMAKE_SOURCE_DIR}/src/curve/parameters.cpp"
    "${CMAKE_SOURCE_DIR}/src/sign/gost.cpp"
    "${CMAKE_SOURCE_DIR}/src/agreement/vko.cpp"
    "${CMAKE_SOURCE_DIR}/src/agreement/ecdhe.cpp"
    "${CMAKE_SOURCE_DIR}/src/record/record.cpp"
    "${CMAKE_SOURCE_DIR}/src/protect/protect.cpp"
    "${CMAKE_SOURCE_DIR}/src/handshake/handshake.cpp"
    "${CMAKE_SOURCE_DIR}/src/schedule/schedule.cpp"
    "${CMAKE_SOURCE_DIR}/src/hello/hello.cpp"
    "${CMAKE_SOURCE_DIR}/src/extension/extension.cpp"
    "${CMAKE_SOURCE_DIR}/src/message/message.cpp"
    "${CMAKE_SOURCE_DIR}/src/session/session.cpp"
    "${CMAKE_SOURCE_DIR}/src/flow/flow.cpp"
    "${CMAKE_SOURCE_DIR}/src/alert/alert.cpp"
    "${CMAKE_SOURCE_DIR}/src/internal/engine/engine.cpp"
    "${CMAKE_SOURCE_DIR}/src/client/client.cpp"
    "${CMAKE_SOURCE_DIR}/src/server/server.cpp"
)

# Устанавливаем имя библиотеки
SET(TLS_LIB_NAME ${PROJECT_NAME})

# Если нужно собрать динамическую библиотеку
if (CMAKE_SHARED_BUILD_LIB)
    # Добавляем динамическую библиотеку
    add_library(${TLS_LIB_NAME} SHARED ${SOURCE_FILES})
    # Выполняем экспорт методов доступных извне в динамических библиотеках
    target_compile_definitions(${TLS_LIB_NAME} PRIVATE ANYKS_TLS_SHARED_LIBRARY_EXPORT)
# Если нужно собрать статическую библиотеку
else (CMAKE_SHARED_BUILD_LIB)
    # Активируем сборку статической библиотеки
    add_compile_definitions(ANYKS_TLS_STATICLIB)
    # Добавляем статическую библиотеку
    add_library(${TLS_LIB_NAME} STATIC ${SOURCE_FILES})
endif (CMAKE_SHARED_BUILD_LIB)

# Если сборка ведётся под Windows
if (WIN32)
    # Источник случайности системы там живёт в отдельной библиотеке
    target_link_libraries(${TLS_LIB_NAME} bcrypt)
endif (WIN32)

# Если необходимо собрать набор проверок
if (CMAKE_BUILD_TESTS)
    # Активируем сборку набора проверок
    enable_testing()

    # Указываем что нужно собирать статистику покрытия кода проверками
    option(CMAKE_BUILD_COVERAGE "Enable code coverage instrumentation for tests" ON)

    # Если сбор статистики покрытия кода активирован
    if (CMAKE_BUILD_COVERAGE)
        # Флаги компиляции для инструментирования кода (gcov/llvm-cov)
        SET(GCC_COVERAGE_COMPILE_FLAGS --coverage)
        # Зависимости линковки для подключения рантайма сбора статистики покрытия
        SET(GCC_COVERAGE_LIBS --coverage)
    # Если сбор статистики покрытия кода отключён
    else()
        # Обнуляем флаги компиляции инструментирования кода
        SET(GCC_COVERAGE_COMPILE_FLAGS "")
        # Обнуляем зависимости линковки рантайма сбора статистики покрытия
        SET(GCC_COVERAGE_LIBS "")
    endif()

    # Если сборка проверок под санитайзерами активирована
    if (CMAKE_BUILD_SANITIZE)
        ##
         # Дополняем флаги компиляции проверок флагами санитайзеров
         #
         # @note Кадровый указатель сохраняется намеренно: без него отчёт санитайзера
         #       остаётся без внятного следа вызовов, и место дефекта приходится искать
         #       заново
         ##
        SET(GCC_COVERAGE_COMPILE_FLAGS ${GCC_COVERAGE_COMPILE_FLAGS} -fsanitize=${CMAKE_BUILD_SANITIZE_LIST} -fno-omit-frame-pointer -g)
        # Дополняем зависимости линковки проверок рантаймом санитайзеров
        SET(GCC_COVERAGE_LIBS ${GCC_COVERAGE_LIBS} -fsanitize=${CMAKE_BUILD_SANITIZE_LIST})

        # Выводим сообщение о сборке проверок под санитайзерами
        message(STATUS "Build unit tests with sanitizers: ${CMAKE_BUILD_SANITIZE_LIST}\n")
    endif (CMAKE_BUILD_SANITIZE)

    ##
     # Собираем библиотеку проверок из тех же исходников, что и рабочую
     #
     # Отдельная цель нужна потому, что флаги инструментирования и санитайзеров обязаны
     # попасть и в саму библиотеку: без этого покрытие считается по одним проверкам,
     # а обращения к памяти внутри библиотеки остаются без надзора
     ##
    add_library(${TLS_LIB_NAME}_test STATIC ${SOURCE_FILES})
    # Если сборка ведётся под Windows
    if (WIN32)
        # Источник случайности системы там живёт в отдельной библиотеке
        target_link_libraries(${TLS_LIB_NAME}_test bcrypt)
    endif (WIN32)
    # Включаем флаги компиляции проверок для библиотеки проверок
    target_compile_options(${TLS_LIB_NAME}_test PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

    ##
     # Каталог пакетов операционной системы добавляется к путям поиска
     #
     # Набор GTest ставится туда, куда его кладёт хранилище пакетов системы: у NetBSD и
     # OpenBSD это /usr/pkg, у FreeBSD - /usr/local, у macOS - каталог Homebrew. Ни
     # одного из них нет среди путей, где find_package() ищет по умолчанию
     ##
    if (${CMAKE_SYSTEM_NAME} STREQUAL "NetBSD" OR ${CMAKE_SYSTEM_NAME} STREQUAL "OpenBSD")
        # Добавляем каталог пакетов pkgsrc к путям поиска
        list(APPEND CMAKE_PREFIX_PATH "/usr/pkg")
    elseif (${CMAKE_SYSTEM_NAME} STREQUAL "FreeBSD" OR ${CMAKE_SYSTEM_NAME} STREQUAL "DragonFly")
        # Добавляем каталог пакетов портов к путям поиска
        list(APPEND CMAKE_PREFIX_PATH "/usr/local")
    elseif (${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
        # Добавляем каталоги Homebrew к путям поиска
        list(APPEND CMAKE_PREFIX_PATH "/opt/homebrew" "/usr/local")
    endif()

    # Выполняем поиск Google Test
    find_package(GTest)

    ##
     # Отсутствие GTest объявляется отказом, а не пропускается молча
     #
     # Набор проверок просили собрать явно ключом CMAKE_BUILD_TESTS, и молчаливый его
     # пропуск означал бы, что просьба обслужена, - тогда как ни одной проверки не собрано
     ##
    if (NOT GTest_FOUND AND NOT GTEST_FOUND)
        message(FATAL_ERROR "GTest not found: unit tests were requested but cannot be built. Install it (brew install googletest, pkgin install googletest, pkg install googletest, apt install libgtest-dev, dnf install gtest-devel) or configure without CMAKE_BUILD_TESTS")
    endif()

    # Выполняем подключение набора проверок
    add_subdirectory(tests)
endif (CMAKE_BUILD_TESTS)

# Указываем что нужно собрать образцы работы с библиотекой
option(CMAKE_BUILD_SAMPLES "Build library samples" OFF)

# Если необходимо собрать образцы работы с библиотекой
if (${CMAKE_BUILD_SAMPLES})
    # Указываем каталог для ВСЕХ исполняемых файлов образцов
    SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/samples)

    ##
     # Функция создания образца
     #
     # Аргументы:
     #  name - имя исполняемого файла образца
     #  src  - исходный файл образца
     #  dir  - каталог, в который кладётся исполняемый файл
     ##
    function(add_sample name src dir)
        # Выполняем создание приложения образца
        add_executable(${name} ${src})
        # Выполняем подключение библиотеки к приложению образца
        target_link_libraries(${name} ${TLS_LIB_NAME})
        # Указываем каталог для исполняемого файла образца
        set_target_properties(${name} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${dir}
        )
    endfunction()

    # Устанавливаем имя приложения работы с хешем «Стрибог»
    SET(DIGEST_APP_NAME digest-streebog)
    # Указываем что нужно собрать приложение работы с хешем «Стрибог»
    option(CMAKE_BUILD_DIGEST_APP_SAMPLE "Build Streebog app sample" ON)

    # Устанавливаем имя приложения работы с блочным шифром «Кузнечик»
    SET(CIPHER_APP_NAME cipher-kuznyechik)
    # Указываем что нужно собрать приложение работы с блочным шифром «Кузнечик»
    option(CMAKE_BUILD_CIPHER_APP_SAMPLE "Build Kuznyechik app sample" ON)

    # Устанавливаем имя приложения работы с электронной подписью
    SET(SIGN_APP_NAME sign-gost)
    # Указываем что нужно собрать приложение работы с электронной подписью
    option(CMAKE_BUILD_SIGN_APP_SAMPLE "Build signature app sample" ON)

    # Устанавливаем имя приложения работы со слоем записей
    SET(RECORD_APP_NAME record-layer)
    # Указываем что нужно собрать приложение работы со слоем записей
    option(CMAKE_BUILD_RECORD_APP_SAMPLE "Build record layer app sample" ON)

    # Устанавливаем имя приложения работы с защитой записей
    SET(PROTECT_APP_NAME record-protect)
    # Указываем что нужно собрать приложение работы с защитой записей
    option(CMAKE_BUILD_PROTECT_APP_SAMPLE "Build record protection app sample" ON)

    # Устанавливаем имя приложения работы с приветствиями рукопожатия
    SET(HELLO_APP_NAME handshake-hello)
    # Указываем что нужно собрать приложение работы с приветствиями рукопожатия
    option(CMAKE_BUILD_HELLO_APP_SAMPLE "Build handshake hello app sample" ON)

    # Если нужно собрать образец работы с хешем «Стрибог»
    if (${CMAKE_BUILD_DIGEST_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample DIGEST: Yes")
        # Выполняем создание приложения работы с хешем «Стрибог»
        add_sample(${DIGEST_APP_NAME} sample/digest/streebog.cpp digest)
    # Если образец работы с хешем «Стрибог» собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample DIGEST: No")
    endif (${CMAKE_BUILD_DIGEST_APP_SAMPLE})

    # Если нужно собрать образец работы с блочным шифром «Кузнечик»
    if (${CMAKE_BUILD_CIPHER_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample CIPHER: Yes")
        # Выполняем создание приложения работы с блочным шифром «Кузнечик»
        add_sample(${CIPHER_APP_NAME} sample/cipher/kuznyechik.cpp cipher)
    # Если образец работы с блочным шифром собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample CIPHER: No")
    endif (${CMAKE_BUILD_CIPHER_APP_SAMPLE})

    # Если нужно собрать образец работы с электронной подписью
    if (${CMAKE_BUILD_SIGN_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample SIGN: Yes")
        # Выполняем создание приложения работы с электронной подписью
        add_sample(${SIGN_APP_NAME} sample/sign/gost.cpp sign)
    # Если образец работы с электронной подписью собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample SIGN: No")
    endif (${CMAKE_BUILD_SIGN_APP_SAMPLE})

    # Если нужно собрать образец работы со слоем записей
    if (${CMAKE_BUILD_RECORD_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample RECORD: Yes")
        # Выполняем создание приложения работы со слоем записей
        add_sample(${RECORD_APP_NAME} sample/record/record.cpp record)
    # Если образец работы со слоем записей собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample RECORD: No")
    endif (${CMAKE_BUILD_RECORD_APP_SAMPLE})

    # Если нужно собрать образец работы с защитой записей
    if (${CMAKE_BUILD_PROTECT_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample PROTECT: Yes")
        # Выполняем создание приложения работы с защитой записей
        add_sample(${PROTECT_APP_NAME} sample/protect/protect.cpp record)
    # Если образец работы с защитой записей собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample PROTECT: No")
    endif (${CMAKE_BUILD_PROTECT_APP_SAMPLE})

    # Устанавливаем имя приложения работы с подтверждением подлинности
    SET(MESSAGE_APP_NAME handshake-message)
    # Указываем что нужно собрать приложение работы с подтверждением подлинности
    option(CMAKE_BUILD_MESSAGE_APP_SAMPLE "Build handshake authentication app sample" ON)

    # Устанавливаем имя приложения работы с состоянием связи
    SET(SESSION_APP_NAME session-state)
    # Указываем что нужно собрать приложение работы с состоянием связи
    option(CMAKE_BUILD_SESSION_APP_SAMPLE "Build session state app sample" ON)

    # Устанавливаем имя приложения работы с полным рукопожатием
    SET(FLOW_APP_NAME handshake-flow)
    # Указываем что нужно собрать приложение работы с полным рукопожатием
    option(CMAKE_BUILD_FLOW_APP_SAMPLE "Build full handshake app sample" ON)

    # Устанавливаем имя приложения работы с извещениями
    SET(ALERT_APP_NAME alert-notice)
    # Указываем что нужно собрать приложение работы с извещениями
    option(CMAKE_BUILD_ALERT_APP_SAMPLE "Build alert app sample" ON)

    # Устанавливаем имя приложения работы с обменом мимолётными ключами
    SET(ECDHE_APP_NAME agreement-ecdhe)
    # Указываем что нужно собрать приложение работы с обменом мимолётными ключами
    option(CMAKE_BUILD_ECDHE_APP_SAMPLE "Build ephemeral key exchange app sample" ON)

    # Устанавливаем имя приложения работы с фасадами связи
    SET(CONTEXT_APP_NAME tls-connection)
    # Указываем что нужно собрать приложение работы с фасадами связи
    option(CMAKE_BUILD_CONTEXT_APP_SAMPLE "Build connection facades app sample" ON)

    # Если нужно собрать образец работы с приветствиями рукопожатия
    if (${CMAKE_BUILD_HELLO_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample HELLO: Yes")
        # Выполняем создание приложения работы с приветствиями рукопожатия
        add_sample(${HELLO_APP_NAME} sample/hello/hello.cpp handshake)
    # Если образец работы с приветствиями собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample HELLO: No")
    endif (${CMAKE_BUILD_HELLO_APP_SAMPLE})

    # Если нужно собрать образец работы с подтверждением подлинности
    if (${CMAKE_BUILD_MESSAGE_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample MESSAGE: Yes")
        # Выполняем создание приложения работы с подтверждением подлинности
        add_sample(${MESSAGE_APP_NAME} sample/message/message.cpp handshake)
    # Если образец работы с подтверждением подлинности собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample MESSAGE: No")
    endif (${CMAKE_BUILD_MESSAGE_APP_SAMPLE})

    # Если нужно собрать образец работы с состоянием связи
    if (${CMAKE_BUILD_SESSION_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample SESSION: Yes")
        # Выполняем создание приложения работы с состоянием связи
        add_sample(${SESSION_APP_NAME} sample/session/session.cpp session)
    # Если образец работы с состоянием связи собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample SESSION: No")
    endif (${CMAKE_BUILD_SESSION_APP_SAMPLE})

    # Если нужно собрать образец работы с полным рукопожатием
    if (${CMAKE_BUILD_FLOW_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample FLOW: Yes")
        # Выполняем создание приложения работы с полным рукопожатием
        add_sample(${FLOW_APP_NAME} sample/flow/flow.cpp handshake)
    # Если образец работы с полным рукопожатием собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample FLOW: No")
    endif (${CMAKE_BUILD_FLOW_APP_SAMPLE})

    # Если нужно собрать образец работы с извещениями
    if (${CMAKE_BUILD_ALERT_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample ALERT: Yes")
        # Выполняем создание приложения работы с извещениями
        add_sample(${ALERT_APP_NAME} sample/alert/alert.cpp alert)
    # Если образец работы с извещениями собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample ALERT: No")
    endif (${CMAKE_BUILD_ALERT_APP_SAMPLE})

    # Если нужно собрать образец работы с обменом мимолётными ключами
    if (${CMAKE_BUILD_ECDHE_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample ECDHE: Yes")
        # Выполняем создание приложения работы с обменом мимолётными ключами
        add_sample(${ECDHE_APP_NAME} sample/agreement/ecdhe.cpp agreement)
    # Если образец работы с обменом мимолётными ключами собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample ECDHE: No")
    endif (${CMAKE_BUILD_ECDHE_APP_SAMPLE})

    # Если нужно собрать образец работы с фасадами связи
    if (${CMAKE_BUILD_CONTEXT_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample CONTEXT: Yes")
        # Выполняем создание приложения работы с фасадами связи
        add_sample(${CONTEXT_APP_NAME} sample/context/context.cpp context)
    # Если образец работы с фасадами связи собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample CONTEXT: No")
    endif (${CMAKE_BUILD_CONTEXT_APP_SAMPLE})
endif (${CMAKE_BUILD_SAMPLES})

# Выполняем установку заголовочных файлов проекта
install(DIRECTORY "${CMAKE_SOURCE_DIR}/include/" DESTINATION "${CMAKE_INSTALL_PREFIX}/include/${CMAKE_PROJECT_NAME}" FILES_MATCHING PATTERN "*.hpp")

# Выполняем установку библиотеки
install(TARGETS ${TLS_LIB_NAME} DESTINATION "${CMAKE_INSTALL_PREFIX}/lib")
