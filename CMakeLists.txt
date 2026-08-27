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
    "${CMAKE_SOURCE_DIR}/src/asn1/asn1.cpp"
    "${CMAKE_SOURCE_DIR}/src/x509/x509.cpp"
    "${CMAKE_SOURCE_DIR}/src/digest/streebog.cpp"
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

# Выполняем установку заголовочных файлов проекта
install(DIRECTORY "${CMAKE_SOURCE_DIR}/include/" DESTINATION "${CMAKE_INSTALL_PREFIX}/include/${CMAKE_PROJECT_NAME}" FILES_MATCHING PATTERN "*.hpp")

# Выполняем установку библиотеки
install(TARGETS ${TLS_LIB_NAME} DESTINATION "${CMAKE_INSTALL_PREFIX}/lib")
