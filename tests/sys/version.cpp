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
 * @brief Проверки издания библиотеки
 *
 * @details Издание обязано сходиться во всех видах: строка вызова равна строке макроса,
 *          числа вызовов равны числам макросов, сводное число равно своей арифметике,
 *          и строка собирается из своих номеров
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <sys/version.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Проверка строки издания
 *
 */
TEST(VersionTest, String) {
	// Строка вызова равна строке макроса сборки
	ASSERT_STREQ(sys::version(), ANTS_VERSION);
	// Строка не пуста
	ASSERT_GT(std::string(ANTS_VERSION).size(), static_cast <size_t> (0));
}
/**
 * @brief Проверка номеров издания
 *
 */
TEST(VersionTest, Numbers) {
	// Старший номер вызова равен числу макроса
	ASSERT_EQ(sys::majorVersion(), static_cast <uint32_t> (ANTS_VERSION_MAJOR));
	// Младший номер вызова равен числу макроса
	ASSERT_EQ(sys::minorVersion(), static_cast <uint32_t> (ANTS_VERSION_MINOR));
	// Заплатка вызова равна числу макроса
	ASSERT_EQ(sys::patchVersion(), static_cast <uint32_t> (ANTS_VERSION_PATCH));
	// Сводное число равно своей арифметике из номеров
	ASSERT_EQ(sys::number(), static_cast <uint32_t> ((ANTS_VERSION_MAJOR * 1000000) + (ANTS_VERSION_MINOR * 1000) + ANTS_VERSION_PATCH));
	// Сводное число вызова равно числу макроса
	ASSERT_EQ(sys::number(), static_cast <uint32_t> (ANTS_VERSION_NUMBER));
}
/**
 * @brief Проверка сборки строки из номеров
 *
 */
TEST(VersionTest, Composition) {
	// Строка издания собирается из своих номеров точками
	const std::string built = (std::to_string(ANTS_VERSION_MAJOR) + "." + std::to_string(ANTS_VERSION_MINOR) + "." + std::to_string(ANTS_VERSION_PATCH));
	// Строка вызова равна собранной строке
	ASSERT_STREQ(sys::version(), built.c_str());
}
