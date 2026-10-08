/**
 * @file wipe.hpp
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
 * \~russian
 * @brief Заголовочный файл затирания областей памяти с тайнами
 *
 * \~english
 * @brief Header file of the wiping of the memory areas holding secrets
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
#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>

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
	 * Подписываемся на стандартное пространство имён
	 */
	using namespace std;

	/**
	 * \~russian
	 * @brief Пространство имён служебных средств
	 *
	 * \~english
	 * @brief Namespace of the utility means
	 *
	 * \~
	 */
	namespace sys {
		/**
		 * \~russian
		 * @brief Метод затирания области памяти
		 *
		 * @details Затирание идёт вызовом memset через изменчивый указатель на функцию, а за
		 *          вызовом стоит барьер собирателя. Голый memset собиратель вправе выбросить
		 *          по правилу «как если бы», когда итог записи никто не читает; вызов же по
		 *          указателю, прочитанному из изменчивой переменной, обязан состояться, а
		 *          барьер объявляет область прочитанной. Скорость - как у самого memset
		 *
		 * @param data затираемая область памяти
		 * @param size размер затираемой области памяти в байтах
		 *
		 * @note Намеренное решение: голый memset здесь запрещён. Разбор порождённого кода
		 *       clang, GCC и lcc (круг 32 CONFORMANCE.md) показал: с голым memset выпадает и
		 *       затирание, и байты ключа остаются на стеке, а под сквозной оптимизацией
		 *       (-flto, у AWH включена под Windows) проверкой этого не поймать. Вызов через
		 *       изменчивый указатель (путь OpenSSL, crypto/mem_clr.c) и барьер (путь BoringSSL
		 *       и libsodium) удерживают затирание у всех трёх собирателей и под -flto. До круга
		 *       32 затирание шло пословной изменчивой записью: гарантия та же, полоса 35 ГБ/с
		 *       на M4 и 6 на Эльбрусе против 140 и 43 у memset. Гарантия сверяется разбором
		 *       порождённого кода щупом tools/wipe, а не проверкой
		 *
		 * \~english
		 * @brief Method of the wiping of a memory area
		 * @details The wiping goes by a memset call through a volatile function pointer, and a compiler
		 *          barrier stands after the call. A plain memset may be dropped by the compiler by the as-if
		 *          rule when nobody reads the result of the write; a call through a pointer read from a
		 *          volatile variable has to take place, and the barrier declares the area read. The speed
		 *          is that of memset itself
		 * @param data the memory area being wiped
		 * @param size the size of the memory area being wiped in bytes
		 * @note Deliberate decision: a plain memset is forbidden here. The inspection of the generated code
		 *       of clang, GCC and lcc (round 32 of CONFORMANCE.md) showed: with a plain memset both the wiping
		 *       drops out and the bytes of the key remain on the stack, and under the link-time optimization
		 *       (-flto, enabled at AWH on Windows) a test cannot catch this. The call through a volatile
		 *       pointer (the way of OpenSSL, crypto/mem_clr.c) and the barrier (the way of BoringSSL and
		 *       libsodium) keep the wiping at all three compilers and under -flto. Before round 32 the wiping
		 *       went by a word-wise volatile write: the same guarantee, a bandwidth of 35 GB/s on M4 and 6 on
		 *       Elbrus against 140 and 43 of memset. The guarantee is verified by the inspection of the
		 *       generated code with the tools/wipe probe, not by a test
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ void wipe(void * data, const size_t size) noexcept;
		/**
		 * \~russian
		 * @brief Метод затирания набора байтов с его опустошением
		 *
		 * @param data затираемый набор байтов; после затирания пуст
		 *
		 * \~english
		 * @brief Method of the wiping of a byte vector with its emptying
		 * @param data the byte vector being wiped; empty after the wiping
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ void wipe(vector <uint8_t> & data) noexcept;
		/**
		 * \~russian
		 * @brief Метод затирания строки с её опустошением
		 *
		 * @param data затираемая строка; после затирания пуста
		 *
		 * \~english
		 * @brief Method of the wiping of a string with its emptying
		 * @param data the string being wiped; empty after the wiping
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ void wipe(string & data) noexcept;
	};
};

