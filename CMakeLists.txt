# Устанавливаем минимальную версию CMake
cmake_minimum_required(VERSION 3.15)

# Устанавливаем название и версию проекта
project(nts VERSION 1.0.0 LANGUAGES CXX)

##
 # Корень проекта для вложенных списков сборки: через add_subdirectory корневые
 # переменные CMAKE_SOURCE_DIR и CMAKE_BINARY_DIR указывают на проект потребителя,
 # потому все пути внутри проекта идут от текущих каталогов и от этой переменной
 ##
SET(ANTS_ROOT ${CMAKE_CURRENT_SOURCE_DIR})

# Устанавливаем полное название проекта
SET(PROJECT_VENDOR_LONG "ANYKS - Network Transport Security (A-NTS)")

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

# Находим Doxygen
find_package(Doxygen QUIET)

# Если Doxygen найден
if(Doxygen_FOUND)
    # Предположим, что Doxyfile лежит в корне исходников
    SET(DOXYFILE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile)

    # Проверяем, что файл существует
    if(EXISTS ${DOXYFILE_PATH})
        # Выводим сообщение, что мы нашли файл для генерации документации Doxyfile
        message(STATUS "Doxyfile found at ${DOXYFILE_PATH}\n")

        # Языки, для которых собирается документация: суффикс файла настроек -> имя языка
        SET(DOXYGEN_LANGUAGES ru en)

        # Список целей по языкам, собираемый ниже для общей цели «doc»
        SET(DOXYGEN_LANGUAGE_TARGETS)

        # Перебираем все языки документации
        foreach(DOXYGEN_LANGUAGE IN LISTS DOXYGEN_LANGUAGES)
            # Формируем путь к файлу настроек конкретного языка
            SET(DOXYFILE_LANGUAGE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.${DOXYGEN_LANGUAGE})

            # Проверяем, что файл настроек языка существует
            if(EXISTS ${DOXYFILE_LANGUAGE_PATH})
                # Создаём цель сборки документации на конкретном языке
                add_custom_target(doc-${DOXYGEN_LANGUAGE}
                    # Каталог назначения создаём сами: Doxygen заводит лишь один уровень вложенности
                    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_SOURCE_DIR}/doc/${DOXYGEN_LANGUAGE}
                    COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYFILE_LANGUAGE_PATH}
                    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                    COMMENT "Generating API documentation with Doxygen [${DOXYGEN_LANGUAGE}]"
                    VERBATIM
                )
                # Запоминаем цель для общей сборки
                LIST(APPEND DOXYGEN_LANGUAGE_TARGETS doc-${DOXYGEN_LANGUAGE})
            # Если файл настроек языка не найден
            else()
                # Выводим сообщение об отсутствии файла настроек языка
                message(STATUS "Doxyfile.${DOXYGEN_LANGUAGE} not found — doc-${DOXYGEN_LANGUAGE} target skipped\n")
            # Конец проверки файла настроек языка
            endif()
        # Конец перебора языков документации
        endforeach()

        # Если хотя бы одна языковая цель создана
        if(DOXYGEN_LANGUAGE_TARGETS)
            # Создаём общую цель, собирающую документацию на всех языках
            add_custom_target(doc DEPENDS ${DOXYGEN_LANGUAGE_TARGETS})
        # Если языковых файлов настроек нет вовсе
        else()
            # Создаём кастомную цель на основе базового файла настроек
            add_custom_target(doc
                COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYFILE_PATH}
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                COMMENT "Generating API documentation with Doxygen"
                VERBATIM
            )
        # Конец проверки языковых целей
        endif()
    # Если файл не найден
    else()
        # Выводим сообщение об отсутствии Doxyfile
        message(STATUS "Doxyfile not found at ${DOXYFILE_PATH} — doc target skipped\n")
    # Конец проверки файла
    endif()
# Если Doxygen не найден
else()
    # Выводим сообщение об отсутствии Doxygen
    message(STATUS "Doxygen not found — 'doc' target will not be available\n")
endif()

# Подключаем каталог заголовочных файлов проекта
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

##
 # Подключаем каталог исходных файлов проекта
 #
 # Каталог нужен для внутренних модулей: они лежат в src/internal и подключаются
 # записью вида <internal/имя/имя.hpp> из файлов реализации
 ##
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

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
file(GLOB_RECURSE PUBLIC_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp")

# Выполняем обход наружных заголовочных файлов библиотеки
foreach (HEADER ${PUBLIC_HEADERS})
    # Читаем содержимое наружного заголовочного файла
    file(STRINGS "${HEADER}" HEADER_LINES REGEX "^[ \t]*#[ \t]*include.*internal/")
    # Если внутренний модуль подключается из наружного заголовочного файла
    if (HEADER_LINES)
        # Получаем имя файла относительно корня проекта
        file(RELATIVE_PATH HEADER_NAME "${CMAKE_CURRENT_SOURCE_DIR}" "${HEADER}")
        # Обрываем настройку сборки отказом
        message(FATAL_ERROR "Internal module is exposed in the public header ${HEADER_NAME}: ${HEADER_LINES}. Internal modules must be included from .cpp files only")
    endif()
endforeach()

# Устанавливаем список исходных файлов библиотеки
SET(SOURCE_FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/sys/machine.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/sys/wipe.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/sys/vault.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/sys/log.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/field/field.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/asn1/asn1.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/x509/x509.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/x509/signature.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/x509/request.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/x509/issue.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/x509/crl.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/jws/jws.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/acme/acme.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/cms/cms.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/cmp/cmp.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/srtp/srtp.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/ocsp/ocsp.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/digest/streebog.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/digest/sm3.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/digest/sha2.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/digest/sha3.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/digest/cshake.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/digest/blake2.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/digest/argon2.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/digest/siphash.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/digest/sha1.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/digest/md5.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/digest/hash.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/digest/hkdf.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/digest/pbkdf2.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/digest/bcrypt.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/digest/hmac.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/digest/kdf.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/embed/embed.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/cipher/kuznyechik.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/cipher/aes.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/cipher/sm4.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/cipher/blowfish.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/cipher/magma.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/cipher/mode.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/cipher/ccm.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/cipher/mgm.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/cipher/gcm.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/cipher/stream.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/cipher/chacha.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/cipher/poly1305.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/cipher/chachapoly.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/math/number.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/entropy/entropy.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/curve/curve.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/curve/parameters.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/sign/gost.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/sign/rsa.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/sign/mldsa.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/sign/slhdsa.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/math/integer.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/sign/ecdsa.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/sign/sm2.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/sign/ed25519.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/agreement/x25519.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/agreement/x448.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/agreement/ffdhe.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/agreement/mlkem.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/agreement/sntrup761.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/noise/noise.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/noise/patterns.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/noise/cipher.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/noise/symmetric.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/noise/handshake.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/noise/kem.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/math/field25519.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/agreement/vko.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/hpke/hpke.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/ech/ech.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/fingerprint/fingerprint.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/agreement/ecdhe.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/record/record.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/protect/protect.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/datagram/datagram.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/handshake/handshake.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/schedule/schedule.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/hello/hello.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/extension/extension.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/message/message.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/session/session.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/flow/flow.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/alert/alert.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/context/context.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/trust/trust.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/pem/pem.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/keys/keys.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/keys/openssh.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/internal/flight/flight.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/internal/ticket/ticket.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/internal/engine/engine.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/client/client.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/server/server.cpp"
)

##
 # Указываем что кратные точки основания заготавливаются при сборке
 #
 # @note Точка основания у кривой одна и известна заранее, оттого кратные её
 #       заготавливаются отдельной программой прямо во время сборки, а подпись
 #       обращается в перебор заготовленного. Заготовка стоит около четырёх умножений
 #       на точку, тогда как связь тратит их три: в работе она не окупается, и держать
 #       её в объекте кривой либо заводить при первом обращении смысла нет
 #
 # @note Ключ выключает заготовку у того, кому дорог размер двоичного файла: таблицы
 #       всех девяти наборов параметров занимают около 1,3 МБ. Выключенной заготовкой
 #       подпись идёт общим умножением на точку, и итог её не меняется
 #
 # @note Заготовка требует ЗАПУСКА собранной программы, оттого при сборке на одной
 #       машине под другую она выключается сама
 ##
option(CMAKE_CURVE_TABLES "Precompute the multiples of the base point at the build time" ON)

# Если сборка ведётся на одной машине под другую
if (CMAKE_CROSSCOMPILING AND CMAKE_CURVE_TABLES)
    # Выключаем заготовку кратных точки основания
    SET(CMAKE_CURVE_TABLES OFF)
    # Выводим сообщение о выключенной заготовке
    message(STATUS "Base point tables: disabled, cross-compiling\n")
endif (CMAKE_CROSSCOMPILING AND CMAKE_CURVE_TABLES)

# Если кратные точки основания заготавливаются при сборке
if (CMAKE_CURVE_TABLES)
    ##
     # Собираем ту часть библиотеки, которой довольно программе вычисления кратных
     #
     # @note Сама программа собирается с ПУСТЫМИ кратными: вычислять их ей неоткуда,
     #       ибо она их и вычисляет. Отсутствие заготовленных кратных отказом не
     #       является, и умножение точки основания там отступает к общему
     ##
    add_library(nts_tables_bootstrap STATIC
        "${CMAKE_CURRENT_SOURCE_DIR}/src/sys/wipe.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/sys/machine.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/math/number.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/field/field.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/curve/curve.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/curve/parameters.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/curve/tables.cpp"
    )

    # Добавляем цель программы вычисления кратных точки основания
    add_executable(nts-tables "${CMAKE_CURRENT_SOURCE_DIR}/tools/tables.cpp")

    # Выполняем подключение зависимостей программы вычисления кратных
    ##
     # Вспомогательные цели всегда статические: при сборке динамической библиотеки
     # заголовки без признака ANTS_STATICLIB объявляют символы импортом из DLL, и
     # программа вычисления кратных под Windows не связывается
     ##
    target_compile_definitions(nts_tables_bootstrap PUBLIC ANTS_STATICLIB)
    target_link_libraries(nts-tables nts_tables_bootstrap)

    # Устанавливаем место вычисленного исходного файла кратных
    SET(CURVE_TABLES_SOURCE "${CMAKE_CURRENT_BINARY_DIR}/generated/tables.cpp")

    # Добавляем правило вычисления кратных точки основания
    add_custom_command(
        OUTPUT ${CURVE_TABLES_SOURCE}
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/generated"
        COMMAND nts-tables > ${CURVE_TABLES_SOURCE}
        DEPENDS nts-tables
        COMMENT "Precomputing the multiples of the base point"
        VERBATIM
    )

    ##
     # Заводим цель вычисления кратных отдельно от самих библиотек
     #
     # @note Вычисленный файл входит в состав ДВУХ библиотек - самой и её проверочной
     #       копии, - и без отдельной цели правило вычисления пришлось бы на всякую из
     #       них. Под многопоточной сборкой обе принялись бы писать один файл разом
     ##
    add_custom_target(nts_curve_tables DEPENDS ${CURVE_TABLES_SOURCE})

    # Помечаем вычисленный исходный файл кратных вырабатываемым
    set_source_files_properties(${CURVE_TABLES_SOURCE} PROPERTIES GENERATED TRUE)

    # Добавляем вычисленный исходный файл кратных в состав библиотеки
    SET(SOURCE_FILES ${SOURCE_FILES} ${CURVE_TABLES_SOURCE})

    # Выводим сообщение о заготовке кратных точки основания
    message(STATUS "Base point tables: precomputed at the build time\n")
# Если кратные точки основания не заготавливаются
else (CMAKE_CURVE_TABLES)
    # Добавляем пустые кратные точки основания в состав библиотеки
    SET(SOURCE_FILES ${SOURCE_FILES} "${CMAKE_CURRENT_SOURCE_DIR}/src/curve/tables.cpp")
    # Выводим сообщение об отсутствии заготовки
    message(STATUS "Base point tables: none, the general multiplication is used\n")
endif (CMAKE_CURVE_TABLES)

##
 # Указываем что берётся машинное умножение без переносов
 #
 # @note Ключ добавляет собирателю признак наличия у машины команд умножения без
 #       переносов. Включать его дозволено лишь тогда, когда команды эти у целевой
 #       машины есть: собранное с ним не пойдёт там, где их нет. У Apple Silicon
 #       собиратель объявляет их сам, и ключ там не нужен
 ##
option(CMAKE_CIPHER_CARRYLESS "Build with the carry-less multiplication instructions" OFF)

# Если берётся машинное умножение без переносов
if (CMAKE_CIPHER_CARRYLESS)
    # Подключаем проверку пригодности ключей собирателя
    include(CheckCXXCompilerFlag)

    # Если сборка ведётся под ARM64
    if (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
        # Выполняем проверку пригодности ключа расширения команд
        check_cxx_compiler_flag("-march=armv8-a+crypto" CARRYLESS_ARM_FLAG)
        # Если ключ расширения команд собирателем принят
        if (CARRYLESS_ARM_FLAG)
            # Добавляем ключ расширения команд
            add_compile_options(-march=armv8-a+crypto)
            # Выводим сообщение о машинном умножении без переносов
            message(STATUS "Carry-less multiplication: PMULL\n")
        endif (CARRYLESS_ARM_FLAG)
    # Если сборка ведётся под x86-64
    elseif (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
        # Выполняем проверку пригодности ключа расширения команд
        check_cxx_compiler_flag("-mpclmul -maes -msha -mssse3" CARRYLESS_X86_FLAG)
        # Если ключи расширений команд собирателем приняты
        if (CARRYLESS_X86_FLAG)
            # Добавляем ключи расширений команд: умножение без переносов, AES-NI и SHA-NI
            add_compile_options(-mpclmul -maes -msha -mssse3)
            # Выводим сообщение о машинных командах
            message(STATUS "Machine instructions: PCLMULQDQ, AES-NI, SHA-NI\n")
        endif (CARRYLESS_X86_FLAG)
    endif (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64|ARM64")
endif (CMAKE_CIPHER_CARRYLESS)

##
 # Указываем что блочный шифр собирается малыми таблицами
 #
 # @note Развёрнутые таблицы преобразования занимают 128 КБ памяти на весь ход работы и
 #       дают восьмикратную скорость; малые занимают 4 КБ и годятся там, где памяти
 #       считанные килобайты, а скорость шифрования не решает
 ##
option(CMAKE_CIPHER_COMPACT "Build the block cipher with the compact tables" OFF)

# Если блочный шифр собирается малыми таблицами
if (CMAKE_CIPHER_COMPACT)
    # Объявляем сборке блочного шифра работу малыми таблицами
    add_compile_definitions(ANTS_CIPHER_COMPACT)
    # Выводим сообщение о способе сборки блочного шифра
    message(STATUS "Block cipher tables: compact\n")
# Если блочный шифр собирается развёрнутыми таблицами
else (CMAKE_CIPHER_COMPACT)
    # Выводим сообщение о способе сборки блочного шифра
    message(STATUS "Block cipher tables: spread\n")
endif (CMAKE_CIPHER_COMPACT)

# Устанавливаем имя библиотеки
SET(ANTS_LIB_NAME ${PROJECT_NAME})

# Если нужно собрать динамическую библиотеку
if (CMAKE_SHARED_BUILD_LIB)
    # Добавляем динамическую библиотеку
    add_library(${ANTS_LIB_NAME} SHARED ${SOURCE_FILES})
    # Выполняем экспорт методов доступных извне в динамических библиотеках
    target_compile_definitions(${ANTS_LIB_NAME} PRIVATE ANTS_SHARED_LIBRARY_EXPORT)
# Если нужно собрать статическую библиотеку
else (CMAKE_SHARED_BUILD_LIB)
    # Активируем сборку статической библиотеки
    add_compile_definitions(ANTS_STATICLIB)
    # Добавляем статическую библиотеку
    add_library(${ANTS_LIB_NAME} STATIC ${SOURCE_FILES})
    ##
     # Признак статической сборки обязан доехать до потребителя цели: без него
     # заголовки под Windows объявляют символы как импорт из динамической
     # библиотеки, и потребитель libnts.a не связывается. На прочих системах
     # ветвь даёт лишь видимость символов и молчит, оттого дефект виден
     # только под Windows
     ##
    target_compile_definitions(${ANTS_LIB_NAME} PUBLIC ANTS_STATICLIB)
endif (CMAKE_SHARED_BUILD_LIB)

##
 # Пути заголовков потребителя: в дереве сборки - каталог include проекта, после
 # установки - каталог include/nts под префиксом. Так цель годна и через
 # add_subdirectory, и через find_package(nts CONFIG)
 ##
target_include_directories(${ANTS_LIB_NAME} PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include/${PROJECT_NAME}>
)

# Требуемый стандарт языка доезжает до потребителя цели
target_compile_features(${ANTS_LIB_NAME} PUBLIC cxx_std_17)

# Потоки: замок укрытого хранилища (std::mutex) и обработчик разветвления (pthread_atfork)
find_package(Threads REQUIRED)
target_link_libraries(${ANTS_LIB_NAME} PUBLIC Threads::Threads)

# Псевдоним пакета в дереве сборки: потребитель через add_subdirectory зовёт ту же цель nts::nts
add_library(${PROJECT_NAME}::${ANTS_LIB_NAME} ALIAS ${ANTS_LIB_NAME})

# Версия и имя динамической библиотеки: libnts.so.1 → libnts.so.1.0.0, nts.dll под Windows
set_target_properties(${ANTS_LIB_NAME} PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    OUTPUT_NAME ${PROJECT_NAME}
)

# Если кратные точки основания заготавливаются при сборке
if (CMAKE_CURVE_TABLES)
    # Ставим вычисление кратных прежде сборки самой библиотеки
    add_dependencies(${ANTS_LIB_NAME} nts_curve_tables)
endif (CMAKE_CURVE_TABLES)

# Если сборка ведётся под Windows
if (WIN32)
    # Источник случайности системы там живёт в отдельной библиотеке: доезжает и до потребителя статической цели
    target_link_libraries(${ANTS_LIB_NAME} PUBLIC bcrypt)
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
    add_library(${ANTS_LIB_NAME}_test STATIC ${SOURCE_FILES})
    # Проверочная копия библиотеки всегда статическая: признак доезжает до проверок и при сборке DLL
    target_compile_definitions(${ANTS_LIB_NAME}_test PUBLIC ANTS_STATICLIB)

    # Если кратные точки основания заготавливаются при сборке
    if (CMAKE_CURVE_TABLES)
        # Ставим вычисление кратных прежде сборки проверочной копии библиотеки
        add_dependencies(${ANTS_LIB_NAME}_test nts_curve_tables)
    endif (CMAKE_CURVE_TABLES)
    # Если сборка ведётся под Windows
    if (WIN32)
        # Источник случайности системы там живёт в отдельной библиотеке; оснастка проверок ведёт сокеты Winsock
        target_link_libraries(${ANTS_LIB_NAME}_test PUBLIC bcrypt ws2_32)
        ##
         # Проверки под MinGW и clang связываются со статическим runtime: подмена
         # operator new в проверке (нехватка памяти, учёт кучи) не видна библиотеке,
         # если оператор живёт в libstdc++-6.dll / libc++.dll
         ##
        if (NOT MSVC)
            SET(GCC_COVERAGE_LIBS ${GCC_COVERAGE_LIBS} -static-libstdc++ -static-libgcc -static)
        endif (NOT MSVC)
    endif (WIN32)
    # Включаем флаги компиляции проверок для библиотеки проверок
    target_compile_options(${ANTS_LIB_NAME}_test PRIVATE ${GCC_COVERAGE_COMPILE_FLAGS})

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

##
 # Указываем что нужно собрать набор замеров
 #
 # @note Замеры собираются только сборкой Release: отладочная сборка замедляет всё разом
 #       и ровно, изображая точечную просадку там, где её нет
 ##
option(CMAKE_BUILD_BENCHMARKS "Build library benchmarks" OFF)

# Если необходимо собрать набор замеров
if (${CMAKE_BUILD_BENCHMARKS})
    # Указываем что замеры нужно сличать с эталоном OpenSSL
    option(CMAKE_BENCHMARK_OPENSSL "Compare benchmarks against the OpenSSL reference" ON)

    # Выполняем создание приложения набора замеров
    add_executable(bench "${CMAKE_CURRENT_SOURCE_DIR}/bench/bench.cpp")

    # Подключаем каталог общих заголовочных файлов набора проверок
    target_include_directories(bench PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/tests")

    # Подключаем каталог образца сжатия: частный кодек цепочки общий с набором замеров
    target_include_directories(bench PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/sample/compress")

    # Передаём путь к набору ключей для сличения: замер обмена RSA читает подлинность из него
    target_compile_definitions(bench PRIVATE ANTS_CORPUS="${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus")

    # Выполняем подключение библиотеки к приложению набора замеров
    target_link_libraries(bench ${ANTS_LIB_NAME})

    # Указываем каталог для исполняемого файла набора замеров
    set_target_properties(bench PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bench)

    # Если замеры нужно сличать с эталоном OpenSSL
    if (${CMAKE_BENCHMARK_OPENSSL})
        # Выполняем поиск эталона OpenSSL
        find_package(OpenSSL)

        # Если эталон OpenSSL в системе найден
        if (OPENSSL_FOUND)
            # Выводим сообщение о сличении замеров с эталоном
            message(STATUS "Benchmark reference OpenSSL: Yes")
            # Объявляем сборке набора замеров наличие эталона
            target_compile_definitions(bench PRIVATE ANTS_BENCH_OPENSSL)
            # Выполняем подключение эталона к приложению набора замеров
            target_link_libraries(bench OpenSSL::SSL OpenSSL::Crypto)
        # Если эталона OpenSSL в системе нет
        else()
            # Выводим сообщение о сличении замеров с эталоном
            message(STATUS "Benchmark reference OpenSSL: No")
        endif (OPENSSL_FOUND)
    endif (${CMAKE_BENCHMARK_OPENSSL})
endif (${CMAKE_BUILD_BENCHMARKS})

# Указываем что нужно собрать образцы работы с библиотекой
option(CMAKE_BUILD_SAMPLES "Build library samples" OFF)

# Если необходимо собрать образцы работы с библиотекой
if (${CMAKE_BUILD_SAMPLES})
    # Указываем каталог для ВСЕХ исполняемых файлов образцов
    SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/samples)

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
        target_link_libraries(${name} ${ANTS_LIB_NAME})
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

    # Устанавливаем имя приложения работы с доверием цепочке сертификатов
    SET(TRUST_APP_NAME trust-chain)
    # Указываем что нужно собрать приложение работы с доверием цепочке
    option(CMAKE_BUILD_TRUST_APP_SAMPLE "Build certificate chain trust app sample" ON)

    # Устанавливаем имя приложения выбора прикладного протокола
    SET(PROTOCOL_APP_NAME alpn-choice)
    # Указываем что нужно собрать приложение выбора прикладного протокола
    option(CMAKE_BUILD_PROTOCOL_APP_SAMPLE "Build application protocol choice app sample" ON)

    # Устанавливаем имя приложения работы с записями в виде PEM
    SET(PEM_APP_NAME pem-storage)
    # Указываем что нужно собрать приложение работы с записями в виде PEM
    option(CMAKE_BUILD_PEM_APP_SAMPLE "Build PEM storage app sample" ON)

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

    # Если нужно собрать образец работы с доверием цепочке сертификатов
    if (${CMAKE_BUILD_TRUST_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample TRUST: Yes")
        # Выполняем создание приложения работы с доверием цепочке
        add_sample(${TRUST_APP_NAME} sample/trust/trust.cpp trust)
    # Если образец работы с доверием цепочке собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample TRUST: No")
    endif (${CMAKE_BUILD_TRUST_APP_SAMPLE})

    # Если нужно собрать образец работы с записями в виде PEM
    if (${CMAKE_BUILD_PEM_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample PEM: Yes")
        # Выполняем создание приложения работы с записями в виде PEM
        add_sample(${PEM_APP_NAME} sample/pem/pem.cpp pem)
    # Если образец работы с записями в виде PEM собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample PEM: No")
    endif (${CMAKE_BUILD_PEM_APP_SAMPLE})

    # Если нужно собрать образец выбора прикладного протокола
    if (${CMAKE_BUILD_PROTOCOL_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample PROTOCOL: Yes")
        # Выполняем создание приложения выбора прикладного протокола
        add_sample(${PROTOCOL_APP_NAME} sample/protocol/protocol.cpp protocol)
    # Если образец выбора прикладного протокола собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample PROTOCOL: No")
    endif (${CMAKE_BUILD_PROTOCOL_APP_SAMPLE})

    ##
     # Функция создания образца, читающего ключи и ответы из набора tests/corpus
     #
     # Аргументы:
     #  name - имя исполняемого файла образца
     #  src  - исходный файл образца
     #  dir  - каталог, в который кладётся исполняемый файл
     #
     # @note Образцам издания 1.2, дейтаграмм, уровней, сшивки OCSP и сжатия нужны
     #       сертификаты ECDSA и RSA с ответами ответчика: вырабатывать их на месте
     #       образцу не по чину, и берутся они из набора проверок
     ##
    function(add_corpus_sample name src dir)
        # Выполняем создание приложения образца
        add_sample(${name} ${src} ${dir})
        # Передаём путь к набору ключей и ответов
        target_compile_definitions(${name} PRIVATE ANTS_CORPUS="${CMAKE_CURRENT_SOURCE_DIR}/tests/corpus")
    endfunction()

    # Устанавливаем имя приложения рукопожатия издания TLS 1.2
    SET(TLS12_APP_NAME tls12-handshake)
    # Указываем что нужно собрать приложение рукопожатия издания TLS 1.2
    option(CMAKE_BUILD_TLS12_APP_SAMPLE "Build TLS 1.2 handshake app sample" ON)

    # Устанавливаем имя приложения заранее разделённого ключа
    SET(PSK_APP_NAME tls12-psk)
    # Указываем что нужно собрать приложение заранее разделённого ключа
    option(CMAKE_BUILD_PSK_APP_SAMPLE "Build pre-shared key app sample" ON)

    # Устанавливаем имя приложения наборов CBC с порядком RFC 7366
    SET(CBC_APP_NAME tls12-cbc)
    # Указываем что нужно собрать приложение наборов CBC
    option(CMAKE_BUILD_CBC_APP_SAMPLE "Build CBC suites with encrypt-then-MAC app sample" ON)

    # Устанавливаем имя приложения связи поверх дейтаграмм
    SET(DTLS_APP_NAME dtls-datagrams)
    # Указываем что нужно собрать приложение связи поверх дейтаграмм
    option(CMAKE_BUILD_DTLS_APP_SAMPLE "Build DTLS 1.3 and DTLS 1.2 app sample" ON)

    # Устанавливаем имя приложения рукопожатия по уровням
    SET(QUIC_APP_NAME quic-levels)
    # Указываем что нужно собрать приложение рукопожатия по уровням
    option(CMAKE_BUILD_QUIC_APP_SAMPLE "Build QUIC levels handshake app sample" ON)

    # Устанавливаем имя приложения состояния сертификата
    SET(OCSP_APP_NAME ocsp-stapling)
    # Указываем что нужно собрать приложение состояния сертификата
    option(CMAKE_BUILD_OCSP_APP_SAMPLE "Build OCSP stapling app sample" ON)

    # Устанавливаем имя приложения отпечатков приветствия
    SET(FINGERPRINT_APP_NAME fingerprint-profile)
    # Указываем что нужно собрать приложение отпечатков приветствия
    option(CMAKE_BUILD_FINGERPRINT_APP_SAMPLE "Build fingerprint profile app sample" ON)

    # Устанавливаем имя приложения зашифрованного приветствия ECH
    SET(ECH_APP_NAME ech-hello)
    # Указываем что нужно собрать приложение зашифрованного приветствия ECH
    option(CMAKE_BUILD_ECH_APP_SAMPLE "Build encrypted client hello app sample" ON)

    # Устанавливаем имя приложения сжатия цепочки сертификатов
    SET(COMPRESS_APP_NAME compress-chain)
    # Указываем что нужно собрать приложение сжатия цепочки сертификатов
    option(CMAKE_BUILD_COMPRESS_APP_SAMPLE "Build certificate chain compression app sample" ON)
    # Указываем что образец сжатия сличается с системным zlib, если тот в системе есть
    option(CMAKE_SAMPLE_COMPRESS_ZLIB "Use the system zlib in the compression app sample when found" ON)

    # Устанавливаем имя приложения кодеков ключей
    SET(KEYS_APP_NAME keys-codec)
    # Указываем что нужно собрать приложение кодеков ключей
    option(CMAKE_BUILD_KEYS_APP_SAMPLE "Build keys codec app sample" ON)

    # Устанавливаем имя приложения поточного шифрования
    SET(STREAM_APP_NAME cipher-stream)
    # Указываем что нужно собрать приложение поточного шифрования
    option(CMAKE_BUILD_STREAM_APP_SAMPLE "Build stream encryption app sample" ON)

    # Устанавливаем название приложения работы с хешами SHA-3, BLAKE2 и SipHash
    SET(SHA3_APP_NAME digest-sha3)
    # Указываем что нужно собрать приложение работы с хешами SHA-3, BLAKE2 и SipHash
    option(CMAKE_BUILD_SHA3_APP_SAMPLE "Build SHA-3, BLAKE2 and SipHash digests app sample" ON)

    # Устанавливаем название приложения выработки ключа из пароля Argon2
    SET(ARGON2_APP_NAME digest-argon2)
    # Указываем что нужно собрать приложение выработки ключа из пароля Argon2
    option(CMAKE_BUILD_ARGON2_APP_SAMPLE "Build Argon2 password hashing app sample" ON)

    # Устанавливаем название приложения вывода зашитого в образ ключа
    SET(EMBED_APP_NAME embed-key)
    # Указываем что нужно собрать приложение вывода зашитого в образ ключа
    option(CMAKE_BUILD_EMBED_APP_SAMPLE "Build embedded key derivation app sample" ON)

    # Устанавливаем название приложения укрытого хранилища ключевого материала
    SET(VAULT_APP_NAME sys-vault)
    # Указываем что нужно собрать приложение укрытого хранилища ключевого материала
    option(CMAKE_BUILD_VAULT_APP_SAMPLE "Build sheltered key storage app sample" ON)

    # Устанавливаем название приложения стока журнала
    SET(LOG_APP_NAME sys-log)
    # Указываем что нужно собрать приложение стока журнала
    option(CMAKE_BUILD_LOG_APP_SAMPLE "Build log sink app sample" ON)

    # Устанавливаем имя приложения затирания памяти с тайнами
    SET(WIPE_APP_NAME sys-wipe)
    # Указываем что нужно собрать приложение затирания памяти с тайнами
    option(CMAKE_BUILD_WIPE_APP_SAMPLE "Build memory wiping app sample" ON)

    # Устанавливаем название приложения упаковки ключа ML-KEM и гибрида
    SET(MLKEM_APP_NAME agreement-mlkem)
    # Указываем что нужно собрать приложение упаковки ключа ML-KEM и гибрида
    option(CMAKE_BUILD_MLKEM_APP_SAMPLE "Build ML-KEM and hybrid key encapsulation app sample" ON)

    # Устанавливаем название приложения гибридного шифрования HPKE
    SET(HPKE_APP_NAME hpke-hpke)
    # Указываем что нужно собрать приложение гибридного шифрования HPKE
    option(CMAKE_BUILD_HPKE_APP_SAMPLE "Build HPKE hybrid public key encryption app sample" ON)

    # Устанавливаем название приложения каркаса Noise и PQNoise
    SET(NOISE_APP_NAME noise-noise)
    # Указываем что нужно собрать приложение каркаса Noise и PQNoise
    option(CMAKE_BUILD_NOISE_APP_SAMPLE "Build Noise and PQNoise handshakes app sample" ON)

    # Устанавливаем название приложения сырого поточного шифра без имитовставки
    SET(RAW_APP_NAME stream-raw)
    # Указываем что нужно собрать приложение сырого поточного шифра без имитовставки
    option(CMAKE_BUILD_RAW_APP_SAMPLE "Build raw stream cipher without authentication app sample" ON)

    # Если нужно собрать образец рукопожатия издания TLS 1.2
    if (${CMAKE_BUILD_TLS12_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample TLS12: Yes")
        # Выполняем создание приложения рукопожатия издания TLS 1.2
        add_corpus_sample(${TLS12_APP_NAME} sample/tls12/tls12.cpp tls12)
    # Если образец рукопожатия издания TLS 1.2 собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample TLS12: No")
    endif (${CMAKE_BUILD_TLS12_APP_SAMPLE})

    # Если нужно собрать образец заранее разделённого ключа
    if (${CMAKE_BUILD_PSK_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample PSK: Yes")
        # Выполняем создание приложения заранее разделённого ключа
        add_sample(${PSK_APP_NAME} sample/psk/psk.cpp tls12)
    # Если образец заранее разделённого ключа собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample PSK: No")
    endif (${CMAKE_BUILD_PSK_APP_SAMPLE})

    # Если нужно собрать образец наборов CBC
    if (${CMAKE_BUILD_CBC_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample CBC: Yes")
        # Выполняем создание приложения наборов CBC
        add_corpus_sample(${CBC_APP_NAME} sample/cbc/cbc.cpp tls12)
    # Если образец наборов CBC собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample CBC: No")
    endif (${CMAKE_BUILD_CBC_APP_SAMPLE})

    # Если нужно собрать образец связи поверх дейтаграмм
    if (${CMAKE_BUILD_DTLS_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample DTLS: Yes")
        # Выполняем создание приложения связи поверх дейтаграмм
        add_corpus_sample(${DTLS_APP_NAME} sample/dtls/dtls.cpp dtls)
    # Если образец связи поверх дейтаграмм собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample DTLS: No")
    endif (${CMAKE_BUILD_DTLS_APP_SAMPLE})

    # Если нужно собрать образец рукопожатия по уровням
    if (${CMAKE_BUILD_QUIC_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample QUIC: Yes")
        # Выполняем создание приложения рукопожатия по уровням
        add_corpus_sample(${QUIC_APP_NAME} sample/quic/quic.cpp quic)
    # Если образец рукопожатия по уровням собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample QUIC: No")
    endif (${CMAKE_BUILD_QUIC_APP_SAMPLE})

    # Если нужно собрать образец состояния сертификата
    if (${CMAKE_BUILD_OCSP_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample OCSP: Yes")
        # Выполняем создание приложения состояния сертификата
        add_corpus_sample(${OCSP_APP_NAME} sample/ocsp/ocsp.cpp ocsp)
    # Если образец состояния сертификата собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample OCSP: No")
    endif (${CMAKE_BUILD_OCSP_APP_SAMPLE})

    # Если нужно собрать образец отпечатков приветствия
    if (${CMAKE_BUILD_FINGERPRINT_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample fingerprint: Yes")
        # Выполняем создание приложения отпечатков приветствия
        add_corpus_sample(${FINGERPRINT_APP_NAME} sample/fingerprint/fingerprint.cpp fingerprint)
    # Если образец отпечатков приветствия собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample fingerprint: No")
    endif (${CMAKE_BUILD_FINGERPRINT_APP_SAMPLE})

    # Если нужно собрать образец зашифрованного приветствия ECH
    if (${CMAKE_BUILD_ECH_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample ECH: Yes")
        # Выполняем создание приложения зашифрованного приветствия ECH
        add_corpus_sample(${ECH_APP_NAME} sample/ech/ech.cpp ech)
    # Если образец зашифрованного приветствия ECH собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample ECH: No")
    endif (${CMAKE_BUILD_ECH_APP_SAMPLE})

    # Если нужно собрать образец сжатия цепочки сертификатов
    if (${CMAKE_BUILD_COMPRESS_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample COMPRESS: Yes")
        # Выполняем создание приложения сжатия цепочки сертификатов
        add_corpus_sample(${COMPRESS_APP_NAME} sample/compress/compress.cpp compress)
        ##
         # Если образец сличается с системным zlib. Под MSVC поиск пропускается: на
         # стендах с MSYS2 find_package находит zlib из клона MinGW/clang, и его
         # заголовки тянут в сборку cl.exe чужой vadefs.h - сборка образца валится
         ##
        if (${CMAKE_SAMPLE_COMPRESS_ZLIB} AND NOT MSVC)
            # Выполняем поиск системного zlib
            find_package(ZLIB)
            # Если системный zlib найден
            if (ZLIB_FOUND)
                # Выводим сообщение о сличении с zlib
                message(STATUS "Compression sample zlib: Yes")
                # Объявляем образцу наличие zlib
                target_compile_definitions(${COMPRESS_APP_NAME} PRIVATE ANTS_SAMPLE_ZLIB)
                # Выполняем подключение zlib к образцу
                target_link_libraries(${COMPRESS_APP_NAME} ZLIB::ZLIB)
            # Если системного zlib нет
            else()
                # Выводим сообщение о сличении с zlib
                message(STATUS "Compression sample zlib: No")
            endif (ZLIB_FOUND)
        endif (${CMAKE_SAMPLE_COMPRESS_ZLIB} AND NOT MSVC)
    # Если образец сжатия цепочки собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample COMPRESS: No")
    endif (${CMAKE_BUILD_COMPRESS_APP_SAMPLE})

    # Если нужно собрать образец кодеков ключей
    if (${CMAKE_BUILD_KEYS_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample KEYS: Yes")
        # Выполняем создание приложения кодеков ключей
        add_sample(${KEYS_APP_NAME} sample/keys/keys.cpp keys)
    # Если образец кодеков ключей собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample KEYS: No")
    endif (${CMAKE_BUILD_KEYS_APP_SAMPLE})

    # Если нужно собрать образец поточного шифрования
    if (${CMAKE_BUILD_STREAM_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample STREAM: Yes")
        # Выполняем создание приложения поточного шифрования
        add_sample(${STREAM_APP_NAME} sample/stream/stream.cpp cipher)
    # Если образец поточного шифрования собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample STREAM: No")
    endif (${CMAKE_BUILD_STREAM_APP_SAMPLE})

    # Если нужно собрать образец работы с хешами SHA-3, BLAKE2 и SipHash
    if (${CMAKE_BUILD_SHA3_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample SHA3: Yes")
        # Выполняем создание приложения работы с хешами SHA-3, BLAKE2 и SipHash
        add_sample(${SHA3_APP_NAME} sample/digest/sha3.cpp digest)
    # Если образец работы с хешами SHA-3, BLAKE2 и SipHash собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample SHA3: No")
    endif (${CMAKE_BUILD_SHA3_APP_SAMPLE})

    # Если нужно собрать образец выработки ключа из пароля Argon2
    if (${CMAKE_BUILD_ARGON2_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample ARGON2: Yes")
        # Выполняем создание приложения выработки ключа из пароля Argon2
        add_sample(${ARGON2_APP_NAME} sample/digest/argon2.cpp digest)
    # Если образец выработки ключа из пароля Argon2 собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample ARGON2: No")
    endif (${CMAKE_BUILD_ARGON2_APP_SAMPLE})

    # Если нужно собрать образец упаковки ключа ML-KEM и гибрида
    if (${CMAKE_BUILD_MLKEM_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample MLKEM: Yes")
        # Выполняем создание приложения упаковки ключа ML-KEM и гибрида
        add_sample(${MLKEM_APP_NAME} sample/agreement/mlkem.cpp agreement)
    # Если образец упаковки ключа ML-KEM и гибрида собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample MLKEM: No")
    endif (${CMAKE_BUILD_MLKEM_APP_SAMPLE})

    # Если нужно собрать образец гибридного шифрования HPKE
    if (${CMAKE_BUILD_HPKE_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample HPKE: Yes")
        # Выполняем создание приложения гибридного шифрования HPKE
        add_sample(${HPKE_APP_NAME} sample/hpke/hpke.cpp hpke)
    # Если образец гибридного шифрования HPKE собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample HPKE: No")
    endif (${CMAKE_BUILD_HPKE_APP_SAMPLE})

    # Если нужно собрать образец каркаса Noise и PQNoise
    if (${CMAKE_BUILD_NOISE_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample NOISE: Yes")
        # Выполняем создание приложения каркаса Noise и PQNoise
        add_sample(${NOISE_APP_NAME} sample/noise/noise.cpp noise)
    # Если образец каркаса Noise и PQNoise собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample NOISE: No")
    endif (${CMAKE_BUILD_NOISE_APP_SAMPLE})

    # Если нужно собрать образец сырого поточного шифра без имитовставки
    if (${CMAKE_BUILD_RAW_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample RAW: Yes")
        # Выполняем создание приложения сырого поточного шифра без имитовставки
        add_sample(${RAW_APP_NAME} sample/stream/raw.cpp cipher)
    # Если образец сырого поточного шифра без имитовставки собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample RAW: No")
    endif (${CMAKE_BUILD_RAW_APP_SAMPLE})

    # Если нужно собрать образец вывода зашитого в образ ключа
    if (${CMAKE_BUILD_EMBED_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample EMBED: Yes")
        # Выполняем создание приложения вывода зашитого в образ ключа
        add_sample(${EMBED_APP_NAME} sample/embed/embed.cpp embed)
    # Если образец вывода зашитого в образ ключа собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample EMBED: No")
    endif (${CMAKE_BUILD_EMBED_APP_SAMPLE})

    # Если нужно собрать образец укрытого хранилища ключевого материала
    if (${CMAKE_BUILD_VAULT_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample VAULT: Yes")
        # Выполняем создание приложения укрытого хранилища ключевого материала
        add_sample(${VAULT_APP_NAME} sample/sys/vault.cpp sys)
    # Если образец укрытого хранилища ключевого материала собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample VAULT: No")
    endif (${CMAKE_BUILD_VAULT_APP_SAMPLE})

    # Если нужно собрать образец затирания памяти с тайнами
    if (${CMAKE_BUILD_WIPE_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample WIPE: Yes")
        # Выполняем создание приложения затирания памяти с тайнами
        add_sample(${WIPE_APP_NAME} sample/sys/wipe.cpp sys)
    # Если образец затирания памяти с тайнами собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample WIPE: No")
    endif (${CMAKE_BUILD_WIPE_APP_SAMPLE})

    # Если нужно собрать образец стока журнала
    if (${CMAKE_BUILD_LOG_APP_SAMPLE})
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample LOG: Yes")
        # Выполняем создание приложения стока журнала
        add_corpus_sample(${LOG_APP_NAME} sample/sys/log.cpp sys)
    # Если образец стока журнала собирать не нужно
    else()
        # Выводим сообщение о сборке образца
        message(STATUS "Build sample LOG: No")
    endif (${CMAKE_BUILD_LOG_APP_SAMPLE})
endif (${CMAKE_BUILD_SAMPLES})

##
 # Установка и конфиг пакета для find_package(nts CONFIG)
 #
 # Ставятся заголовки в include/nts, библиотека в lib (динамическая под Windows -
 # в bin), описание целей ntsTargets.cmake и файлы ntsConfig.cmake /
 # ntsConfigVersion.cmake в lib/cmake/nts. Потребитель пишет:
 #   find_package(nts CONFIG REQUIRED)
 #   target_link_libraries(app PRIVATE nts::nts)
 # Совместимость версий - в пределах старшего номера
 ##
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

# Выполняем установку заголовочных файлов проекта
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}" FILES_MATCHING PATTERN "*.hpp")

# Выполняем установку библиотеки с описанием цели для экспорта
install(TARGETS ${ANTS_LIB_NAME}
    EXPORT ${PROJECT_NAME}Targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}
)

# Выполняем установку описания целей пакета
install(EXPORT ${PROJECT_NAME}Targets
    FILE ${PROJECT_NAME}Targets.cmake
    NAMESPACE ${PROJECT_NAME}::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)

# Составляем файл настройки пакета
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/${PROJECT_NAME}Config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)

# Составляем файл версии пакета: совместимость в пределах старшего номера
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

# Выполняем установку файлов настройки и версии пакета
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Config.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)

# Описание целей доступно и из дерева сборки без установки
export(EXPORT ${PROJECT_NAME}Targets
    FILE "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}Targets.cmake"
    NAMESPACE ${PROJECT_NAME}::
)
