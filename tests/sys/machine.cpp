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
 * Если сборка ведётся под x86-64 собирателем семейства GCC
 */
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
	/**
	 * Подключаем заголовочный файл опроса машины
	 */
	#include <cpuid.h>
#endif

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
	#if defined(__aarch64__) || defined(__x86_64__) || (defined(__e2k__) && defined(__iset__) && (__iset__ >= 5))
		// Проверяем, что незапрещённое расширение осталось
		ASSERT_TRUE(machine::has(machine::feature_t::VECTOR));
	#endif
}

/**
 * Проверка признаков x86-64, снимаемых опросом машины: кодировка VEX и загрузка с
 * перестановкой байтов обязаны сходиться с ответом собирателя о той же машине;
 * маска запрета из проверки выше их не называет
 */
TEST(MachineTest, Flags) {
	#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
		// Если собиратель видит у машины AVX, разрешённый системой
		if(__builtin_cpu_supports("avx"))
			// Проверяем, что кодировка VEX признана
			ASSERT_TRUE(machine::has(machine::feature_t::AVX));
		// Иначе кодировка VEX не признаётся
		else
			ASSERT_FALSE(machine::has(machine::feature_t::AVX));
		// Регистры опроса первого листа: clang не знает имени movbe у встроенной проверки, оттого опрос прямой
		unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
		// Если первый лист опроса снят и несёт MOVBE: разряд 22 ECX
		if(::__get_cpuid(1, &eax, &ebx, &ecx, &edx) && (ecx & (1U << 22)))
			// Проверяем, что загрузка с перестановкой байтов признана
			ASSERT_TRUE(machine::has(machine::feature_t::MOVBE));
		// Иначе загрузка с перестановкой байтов не признаётся
		else
			ASSERT_FALSE(machine::has(machine::feature_t::MOVBE));
		// Регистры опроса седьмого листа
		unsigned int eax7 = 0, ebx7 = 0, ecx7 = 0, edx7 = 0;
		// Если седьмой лист снят и несёт BMI2 (разряд 8 EBX) вместе с ADX (разряд 19 EBX)
		if(::__get_cpuid_count(7, 0, &eax7, &ebx7, &ecx7, &edx7) && (ebx7 & (1U << 8)) && (ebx7 & (1U << 19)))
			// Проверяем, что умножение без флагов признано
			ASSERT_TRUE(machine::has(machine::feature_t::ADX));
		// Иначе умножение без флагов не признаётся
		else
			ASSERT_FALSE(machine::has(machine::feature_t::ADX));
	#else
		// У прочих машин признаков x86-64 нет
		ASSERT_FALSE(machine::has(machine::feature_t::AVX));
		ASSERT_FALSE(machine::has(machine::feature_t::MOVBE));
		ASSERT_FALSE(machine::has(machine::feature_t::ADX));
	#endif
}
