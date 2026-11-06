/**
 * @file version.cpp
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
 * @brief Модуль издания библиотеки
 *
 * @details Издание живёт в строке project() сборки и доезжает определениями ANTS_VERSION:
 *          они ставятся цели библиотеки сборкой и вручную нигде не повторяются. Сводное
 *          число сводится из номеров издания здесь же при компиляции, и расхождение
 *          числа со строкой сборки ловит запрет компиляции
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/version.hpp>

/**
 * @brief Служебные объекты модуля
 *
 */
namespace {
	/**
	 * Сводное число обязано сходиться со своими номерами: опечатка сборки ловится здесь
	 */
	static_assert((ANTS_VERSION_MAJOR * 1000000 + ANTS_VERSION_MINOR * 1000 + ANTS_VERSION_PATCH) == ANTS_VERSION_NUMBER, "сводное число издания не сходится с номерами");
}

/**
 * @brief Метод получения строки издания библиотеки
 *
 * @return строка издания библиотеки
 *
 */
const char * nts::sys::version() noexcept {
	// Выводим строку издания из определения сборки
	return ANTS_VERSION;
}
/**
 * @brief Метод получения сводного числа издания библиотеки
 *
 * @return сводное число издания библиотеки
 *
 */
uint32_t nts::sys::number() noexcept {
	// Выводим сводное число издания из определения сборки
	return ANTS_VERSION_NUMBER;
}
/**
 * @brief Метод получения старшего номера издания библиотеки
 *
 * @return старший номер издания библиотеки
 *
 */
uint32_t nts::sys::majorVersion() noexcept {
	// Выводим старший номер издания из определения сборки
	return ANTS_VERSION_MAJOR;
}
/**
 * @brief Метод получения младшего номера издания библиотеки
 *
 * @return младший номер издания библиотеки
 *
 */
uint32_t nts::sys::minorVersion() noexcept {
	// Выводим младший номер издания из определения сборки
	return ANTS_VERSION_MINOR;
}
/**
 * @brief Метод получения заплатки издания библиотеки
 *
 * @return заплатка издания библиотеки
 *
 */
uint32_t nts::sys::patchVersion() noexcept {
	// Выводим заплатку издания из определения сборки
	return ANTS_VERSION_PATCH;
}
