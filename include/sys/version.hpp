/**
 * @file version.hpp
 * @date 2026-11-07
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
 * @brief Заголовочный файл издания библиотеки
 *
 * \~english
 * @brief Header file of the library edition
 *
 * \~
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
#include <cstdint>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>

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
	 * @brief Пространство имён служебных средств
	 *
	 * \~english
	 * @brief Namespace of the system services
	 *
	 * \~
	 */
	namespace sys {
		/**
		 * \~russian
		 * @brief Функция получения строки издания библиотеки
		 *
		 * @details Издание живёт в строке project() сборки и доезжает сюда определением
		 *          ANTS_VERSION: строка вида "1.0.0". Потребителю, которому издание нужно
		 *          для решения о вызовах, короче сравнить сводное число из number() либо
		 *          ворот условной компиляции \#if ANTS_VERSION_NUMBER >= 1000000
		 *
		 * @return строка издания библиотеки
		 *
		 * \~english
		 * @brief Function of the search of the library edition string
		 *
		 * @details The edition lives in the project() line of the build and arrives
		 *          here by the ANTS_VERSION definition: a string like "1.0.0". A consumer
		 *          deciding by the edition is better served by the summary number of
		 *          number() or by the conditional compilation gate \#if ANTS_VERSION_NUMBER >= 1000000
		 *
		 * @return the library edition string
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ const char * version() noexcept;
		/**
		 * \~russian
		 * @brief Функция получения сводного числа издания библиотеки
		 *
		 * @details Число сводится из номеров издания как старший * 1000000 + младший * 1000
		 *          + заплатка: сравнение чисел одним знаком и решает, какое издание новее.
		 *          То же число заведено макросом ANTS_VERSION_NUMBER для условной компиляции
		 *
		 * @return сводное число издания библиотеки
		 *
		 * \~english
		 * @brief Function of the search of the summary number of the library edition
		 *
		 * @details The number is summarized from the edition numbers as major * 1000000 + minor * 1000
		 *          + patch: a single number comparison then decides which edition is newer.
		 *          The same number is set by the ANTS_VERSION_NUMBER macro for conditional compilation
		 *
		 * @return the summary number of the library edition
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ uint32_t number() noexcept;
		/**
		 * \~russian
		 * @brief Функция получения старшего номера издания библиотеки
		 *
		 * @details Старший номер меняется при ломке наружного договора библиотеки
		 *
		 * @return старший номер издания библиотеки
		 *
		 * \~english
		 * @brief Function of the search of the major number of the library edition
		 *
		 * @details The major number changes when the outer contract of the library breaks
		 *
		 * @return the major number of the library edition
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ uint32_t majorVersion() noexcept;
		/**
		 * \~russian
		 * @brief Функция получения младшего номера издания библиотеки
		 *
		 * @details Младший номер растёт при добавлении вызовов без ломки прежних
		 *
		 * @return младший номер издания библиотеки
		 *
		 * \~english
		 * @brief Function of the search of the minor number of the library edition
		 *
		 * @details The minor number grows when calls are added without breaking the old ones
		 *
		 * @return the minor number of the library edition
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ uint32_t minorVersion() noexcept;
		/**
		 * \~russian
		 * @brief Функция получения заплатки издания библиотеки
		 *
		 * @details Заплатка меняется при правках, не трогающих наружный договор
		 *
		 * @return заплатка издания библиотеки
		 *
		 * \~english
		 * @brief Function of the search of the patch of the library edition
		 *
		 * @details The patch changes on fixes that do not touch the outer contract
		 *
		 * @return the patch of the library edition
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ uint32_t patchVersion() noexcept;
	};
};
