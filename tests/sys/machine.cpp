/**
 * @file machine.cpp
 * @date 2026-09-04
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
 * @brief Проверки признаков машины и их запрета окружением
 *
 * @note Переменная ANTS_MACHINE: «0» запрещает все расширения, число - маску разрядов
 *       feature_t; щупы приёмки принуждают ею выбор пути помимо опроса машины
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <cstdlib>
#include <cstdint>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <sys/machine.hpp>

/**
 * Установка переменной окружения: у Windows нет setenv, есть _putenv_s
 */
static bool assign(const char * name, const char * value) noexcept {
	#if defined(_WIN32)
		return (::_putenv_s(name, value) == 0);
	#else
		return (::setenv(name, value, 1) == 0);
	#endif
}

/**
 * Пространство имён библиотеки
 */
using namespace nts;

/**
 * Проверка маски запрета расширений окружением: первое обращение к машине читает
 * ANTS_MACHINE, число в ней снимает названные разряды, оставляя прочие
 */
TEST(MachineTest, Denied) {
	// Запрещаем окружением расширения AVX2 и SSSE3 до первого обращения к машине
	ASSERT_TRUE(::assign("ANTS_MACHINE", "0x60"));
	// Проверяем, что запрещённые расширения не признаны
	ASSERT_FALSE(machine::has(machine::feature_t::AVX2));
	// Проверяем, что запрещённые расширения не признаны
	ASSERT_FALSE(machine::has(machine::feature_t::SSSE3));
	/**
	 * Векторные команды основания набора есть у всякой машины ARM64 либо x86-64,
	 * и маска, не называющая их, обязана их оставить
	 */
	#if defined(__aarch64__) || defined(__x86_64__)
		// Проверяем, что незапрещённое расширение осталось
		ASSERT_TRUE(machine::has(machine::feature_t::VECTOR));
	#endif
}
