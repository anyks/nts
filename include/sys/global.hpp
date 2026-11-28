/**
 * @file global.hpp
 * @date 2026-08-26
 *
 * @license{LicenseRef-A-NTS-1.0}
 *
 * @author Yuriy Lobarev
 *
 * @telegram{forman}
 * @phone{+7 (910) 983-95-90}
 *
 * @email forman@anyks.com
 * @site https://anyks.com
 *
 * \~russian
 * @brief Общий заголовочный файл проекта — признаки сборки, правила экспорта символов
 *        и определения, общие для всех модулей библиотеки
 *
 * \~english
 * @brief Common header file of the project — build definitions, symbol export rules
 *        and definitions shared by all the modules of the library
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#pragma once

/**
 * Стандартные заголовочные файлы
 */
#include <cstddef>
#include <cstdint>

/**
 * \~russian
 * @note Проверка ведётся через defined, а не значением: заголовок <windows.h> у mingw-w64
 *       определяет WIN32 пустым макросом, отчего условие вида «|| WIN32 ||» теряет операнд
 *
 * \~english
 * @note The check is done via defined, not by value: the <windows.h> header of mingw-w64
 *       defines WIN32 as an empty macro, so a condition like «|| WIN32 ||» loses the operand
 *
 * \~
 */
#if defined(_MSC_VER) || defined(WIN64) || defined(_WIN64) || defined(__WIN64__) || defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
	/**
	 * \~russian
	 * Экспорт символов из динамической библиотеки
	 *
	 * \~english
	 * Exporting symbols from a dynamic library
	 *
	 * \~
	 */
	#define __NTS_DECL_EXPORT__ __declspec(dllexport)
	/**
	 * \~russian
	 * Импорт символов из динамической библиотеки
	 *
	 * \~english
	 * Importing symbols from a dynamic library
	 *
	 * \~
	 */
	#define __NTS_DECL_IMPORT__ __declspec(dllimport)
/**
 * Ветвь для прочих платформ: экспорт и импорт символов через атрибут видимости
 */
#else
	/**
	 * \~russian
	 * Экспорт символов из динамической библиотеки
	 *
	 * \~english
	 * Exporting symbols from a dynamic library
	 *
	 * \~
	 */
	#define __NTS_DECL_EXPORT__ __attribute__((visibility("default")))
	/**
	 * \~russian
	 * Импорт символов из динамической библиотеки
	 *
	 * \~english
	 * Importing symbols from a dynamic library
	 *
	 * \~
	 */
	#define __NTS_DECL_IMPORT__ __attribute__((visibility("default")))
#endif

/**
 * Если библиотека собирается статически
 */
#if defined(NTS_STATICLIB)
	/**
	 * \~russian
	 * Обозначение символов, доступных снаружи библиотеки
	 *
	 * \~english
	 * Designation of symbols accessible from outside the library
	 *
	 * \~
	 */
	#define __NTS_SHARED_EXPORT__
/**
 * Если производится сборка самой динамической библиотеки
 */
#elif defined(NTS_SHARED_LIBRARY_EXPORT)
	/**
	 * \~russian
	 * Обозначение символов, доступных снаружи библиотеки
	 *
	 * \~english
	 * Designation of symbols accessible from outside the library
	 *
	 * \~
	 */
	#define __NTS_SHARED_EXPORT__ __NTS_DECL_EXPORT__
/**
 * Если динамическая библиотека подключается потребителем
 */
#else
	/**
	 * \~russian
	 * Обозначение символов, доступных снаружи библиотеки
	 *
	 * \~english
	 * Designation of symbols accessible from outside the library
	 *
	 * \~
	 */
	#define __NTS_SHARED_EXPORT__ __NTS_DECL_IMPORT__
#endif

/**
 * \~russian
 * Принудительное встраивание вызова
 *
 * @note Обычного inline здесь мало: собиратель судит о встраивании по размеру тела,
 *       а внутренние преобразования шифров и хешей велики телом и при этом зовутся
 *       десятками раз на один блок. Оставленные вызовами, они гоняют состояние
 *       через стек: у «Стрибога» невстроенное преобразование LPS стоило трети полосы
 *
 * @note Под MSVC обозначения даются своими ключевыми словами: сборка Visual Studio
 *       (x64 и ARM64) входит в охват переноса по плану работ от 17.09.2026, а
 *       машинные ветви шифров и хешей там пока идут переносимым путём
 *
 * \~english
 * Forced inlining of a call
 *
 * @note A plain inline is not enough here: the compiler judges inlining by the size of the body,
 *       and the internal transformations of the ciphers and hashes are large in body and yet are
 *       called dozens of times per block. Left as calls, they drive the state through the stack:
 *       at «Streebog» the non-inlined LPS transformation cost a third of the bandwidth
 *
 * @note Under MSVC the designations are given by their own keywords: the Visual Studio build
 *       (x64 and ARM64) is included in the scope of the port by the work plan of 17.09.2026, and
 *       the machine branches of the ciphers and hashes there still go the portable way
 *
 * \~
 */
#if defined(_MSC_VER)
	/**
	 * \~russian
	 * Принудительная подстановка средствами Visual Studio
	 *
	 * \~english
	 * Forced substitution using Visual Studio tools
	 *
	 * \~
	 */
	#define __NTS_INLINE__ __forceinline
	/**
	 * \~russian
	 * Обозначение вызова, встраивание которого запрещено
	 *
	 * \~english
	 * Designation of a call that is prohibited from being embedded
	 *
	 * \~
	 */
	#define __NTS_NO_INLINE__ __declspec(noinline)
/**
 * \~russian
 * Если компилятор принадлежит к семейству GCC или Clang
 *
 * \~english
 * If the compiler belongs to the GCC or Clang family
 *
 * \~
 */
#else
	/**
	 * \~russian
	 * Принудительная подстановка средствами GCC и Clang
	 *
	 * \~english
	 * Forced inlining via GCC and Clang
	 *
	 * \~
	 */
	#define __NTS_INLINE__ inline __attribute__((always_inline))
	/**
	 * \~russian
	 * Обозначение вызова, встраивание которого запрещено
	 *
	 * \~english
	 * Designation of a call that is prohibited from being embedded
	 *
	 * \~
	 */
	#define __NTS_NO_INLINE__ __attribute__((noinline))
#endif

/**
 * \~russian
 * Признак сборки под ASan без оптимизации
 *
 * @note Ядра на ассемблере x86-64 занимают все четырнадцать регистров общего назначения,
 *       а ASan без оптимизации держит адреса своего стека в регистрах, и собиратель
 *       отвечает «вставке не хватает регистров» (Xeon, clang 18, круг 38); с оптимизацией
 *       те же вставки под ASan собираются. Ядра, занимающие все регистры, под этим
 *       признаком не берутся, и отладочная сборка с ASan идёт переносимыми путями.
 *       gcc объявляет признак ASan сам, clang отвечает на вопрос о свойстве
 *
 * \~english
 * The flag of the ASan build without optimization
 *
 * @note The x86-64 assembler kernels occupy all fourteen general-purpose registers,
 *       and ASan without optimization keeps the addresses of its stack in registers, and the
 *       compiler answers «not enough registers for the insertion» (Xeon, clang 18, round 38); with
 *       optimization the same insertions are compiled under ASan. The kernels occupying all registers
 *       are not taken under this flag, and the debug build with ASan goes the portable ways.
 *       gcc declares the ASan flag itself, clang answers the question about the property
 *
 * \~
 */
#if !defined(__OPTIMIZE__)
	/**
	 * Если адрес принадлежит санитайзеру
	 */
	#if defined(__SANITIZE_ADDRESS__)
		/**
		 * \~russian
		 * Признак сборки под ASan без оптимизации
		 *
		 * \~english
		 * Build configuration for ASan without optimization
		 *
		 * \~
		 */
		#define __NTS_ASAN_UNOPTIMIZED__ 1
	/**
	 * Если сборка выполняется под Clang LLVM
	 */
	#elif defined(__has_feature)
		/**
		 * Если адрес принадлежит санитайзеру
		 */
		#if __has_feature(address_sanitizer)
			/**
			 * \~russian
			 * Признак сборки под ASan без оптимизации
			 *
			 * \~english
			 * Build configuration for ASan without optimization
			 *
			 * \~
			 */
			#define __NTS_ASAN_UNOPTIMIZED__ 1
		#endif
	#endif
#endif

/**
 * \~russian
 * Признаки сборки под собирателем Microsoft Visual C++ по целевой архитектуре
 *
 * @note Сами по себе _M_X64, _M_AMD64 и _M_ARM64 признаком собирателя не служат:
 *       mingw-w64 объявляет их в собственных системных заголовках, и довольно
 *       подключения <cstdint>, чтобы _M_X64 оказался определён под GCC. Условие
 *       на один признак архитектуры открывает под MinGW ветвь, написанную для
 *       cl.exe, - сборка падает на интринсиках, которым не дан ключ набора команд,
 *       либо на объявлении функции, чьё имя совпало с макросом другого заголовка.
 *       Верный признак собирателя - _MSC_VER, и здесь он соединён с архитектурой,
 *       оттого стены ядер пользуют готовые признаки вместо пары условий
 *
 * \~english
 * The flags of the Microsoft Visual C++ build by target architecture
 *
 * @note The _M_X64, _M_AMD64 and _M_ARM64 alone are not the compiler sign:
 *       mingw-w64 declares them in its own system headers, and the inclusion
 *       of <cstdint> is enough for _M_X64 to be defined under GCC. A condition
 *       on the architecture sign alone opens under MinGW the branch written for
 *       cl.exe - the build fails on the intrinsics given no instruction set key,
 *       or on the function declaration whose name collides with a macro of
 *       another header. The valid compiler sign is _MSC_VER, and here it is
 *       joined with the architecture, so the kernel walls use the ready flags
 *       instead of a pair of conditions
 *
 * \~
 */
#if defined(_MSC_VER) && defined(_M_X64)
	/**
	 * \~russian
	 * Признак сборки под x86-64 собирателем Microsoft Visual C++
	 *
	 * \~english
	 * Indication of a build for x86-64 using the Microsoft Visual C++ compiler
	 *
	 * \~
	 */
	#define __NTS_MSVC_X64__ 1
#endif

/**
 * Если сборка ведётся под ARM64 собирателем Microsoft Visual C++
 */
#if defined(_MSC_VER) && (defined(_M_ARM64) || defined(_M_ARM64EC))
	/**
	 * \~russian
	 * Признак сборки под ARM64 собирателем Microsoft Visual C++
	 *
	 * \~english
	 * Indication of a build for ARM64 by the Microsoft Visual C++ compiler
	 *
	 * \~
	 */
	#define __NTS_MSVC_ARM64__ 1
#endif

/**
 * \~russian
 * @brief Основное пространство имён
 *
 * \~english
 * @brief Main namespace
 *
 * \~
 */
namespace nts {
	/**
	 * \~russian
	 * @brief Просмотр области байтов
	 *
	 * @details Пара «указатель и длина», не владеющая содержимым. Применяется
	 *          повсеместно вместо передачи двух отдельных доводов: рассогласовать
	 *          указатель и длину при таком виде передачи нельзя, а именно этим
	 *          рассогласованием и порождается большинство выходов за границы
	 *          буфера при разборе недоверенных данных.
	 *
	 * \~english
	 * @brief View of a byte area
	 *
	 * @details A pair of «pointer and length» which does not own the content. It is used
	 *          everywhere instead of passing two separate arguments: the pointer and the
	 *          length cannot be desynchronized with such a way of passing, and it is
	 *          exactly this desynchronization that produces most of the buffer overruns
	 *          during the parsing of untrusted data.
	 *
	 * \~
	 */
	typedef struct View {
		// Размер области байтов
		size_t size;
		// Указатель на начало области байтов
		const uint8_t * data;
		/**
		 * \~russian
		 * @brief Конструктор
		 *
		 * \~english
		 * @brief Constructor
		 *
		 * \~
		 */
		constexpr View() noexcept : size(0), data(nullptr) {}
		/**
		 * \~russian
		 * @brief Конструктор
		 *
		 * @param data указатель на начало области байтов
		 * @param size размер области байтов
		 *
		 * \~english
		 * @brief Constructor
		 *
		 * @param data pointer to the beginning of the byte area
		 * @param size size of the byte area
		 *
		 * \~
		 */
		constexpr View(const uint8_t * data, const size_t size) noexcept : size(size), data(data) {}
	} view_t;
};
