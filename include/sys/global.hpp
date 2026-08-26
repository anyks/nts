/**
 * @file global.hpp
 * @date 2026-08-26
 *
 * @license{LicenseRef-ANYKS-SSL-1.0}
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
#ifndef __ANYKS_SSL_GLOBAL__
#define __ANYKS_SSL_GLOBAL__

/**
 * Стандартные заголовочные файлы
 */
#include <cstddef>
#include <cstdint>

/**
 * @note Проверка ведётся через defined, а не значением: заголовок <windows.h> у mingw-w64
 *       определяет WIN32 пустым макросом, отчего условие вида «|| WIN32 ||» теряет операнд
 */
#if defined(_MSC_VER) || defined(WIN64) || defined(_WIN64) || defined(__WIN64__) || defined(WIN32) || defined(_WIN32) || defined(__WIN32__) || defined(__NT__)
	/**
	 * Экспорт символов из динамической библиотеки
	 */
	#define __ANYKS_SSL_DECL_EXPORT__ __declspec(dllexport)
	/**
	 * Импорт символов из динамической библиотеки
	 */
	#define __ANYKS_SSL_DECL_IMPORT__ __declspec(dllimport)
#else
	/**
	 * Экспорт символов из динамической библиотеки
	 */
	#define __ANYKS_SSL_DECL_EXPORT__ __attribute__((visibility("default")))
	/**
	 * Импорт символов из динамической библиотеки
	 */
	#define __ANYKS_SSL_DECL_IMPORT__ __attribute__((visibility("default")))
#endif

/**
 * Если библиотека собирается статически
 */
#if defined(ANYKS_SSL_STATICLIB)
	/**
	 * Обозначение символов, доступных снаружи библиотеки
	 */
	#define __ANYKS_SSL_SHARED_EXPORT__
/**
 * Если производится сборка самой динамической библиотеки
 */
#elif defined(ANYKS_SSL_SHARED_LIBRARY_EXPORT)
	/**
	 * Обозначение символов, доступных снаружи библиотеки
	 */
	#define __ANYKS_SSL_SHARED_EXPORT__ __ANYKS_SSL_DECL_EXPORT__
/**
 * Если динамическая библиотека подключается потребителем
 */
#else
	/**
	 * Обозначение символов, доступных снаружи библиотеки
	 */
	#define __ANYKS_SSL_SHARED_EXPORT__ __ANYKS_SSL_DECL_IMPORT__
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
namespace anyks {
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
		const uint8_t * data; // Указатель на начало области байтов
		size_t size;          // Размер области байтов
		/**
		 * @brief Конструктор пустого просмотра
		 *
		 */
		View() noexcept : data(nullptr), size(0) {}
		/**
		 * @brief Конструктор просмотра области байтов
		 *
		 * @param data указатель на начало области байтов
		 * @param size размер области байтов
		 */
		View(const uint8_t * data, const size_t size) noexcept : data(data), size(size) {}
	} view_t;
};

#endif // __ANYKS_SSL_GLOBAL__
