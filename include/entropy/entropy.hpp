/**
 * @file entropy.hpp
 * @date 2026-08-29
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
 * @brief Заголовочный файл модуля источника случайных значений
 *
 * \~english
 * @brief Header file of the module of the source of the random values
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_ENTROPY__
#define __ANTS_ENTROPY__

/**
 * Стандартные заголовочные файлы
 */
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <math/number.hpp>

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
	 * @brief Пространство имён модуля источника случайных значений
	 *
	 * @details Случайность берётся у системы и своим порождателем не разбавляется:
	 *          собственный порождатель пришлось бы наполнять из того же источника, а
	 *          всякое лишнее звено между ядром и потребителем - это ещё одно место, где
	 *          случайность вырождается незаметно. У macOS и BSD источником служит
	 *          порождатель самой libc (arc4random_buf), названный системой предпочтительным
	 *          и наполняемый её ядром, у Linux и Windows - вызов ядра
	 *
	 * @note Пространство названо entropy, а не random: свободная функция random входит
	 *       в POSIX, и одноимённое пространство имён сделало бы её вызов у потребителя,
	 *       написавшего using namespace nts, двусмысленным
	 *
	 * \~english
	 * @brief Namespace of the module of the source of the random values
	 * @details The randomness is taken from the system and is not diluted by a generator of
	 *          its own: a generator of its own would have to be filled from the same source,
	 *          while every extra link between the kernel and the consumer is one more place
	 *          where the randomness degenerates unnoticed. At macOS and BSD the source is the
	 *          generator of the libc itself (arc4random_buf), named by the system as the
	 *          preferred one and filled by its kernel, at Linux and Windows a call of the kernel
	 * @note The namespace is named entropy and not random: the free function random is a part
	 *       of POSIX, and a namespace of the same name would make its call ambiguous for a
	 *       consumer who wrote using namespace nts
	 *
	 * \~
	 */
	namespace entropy {
		/**
		 * \~russian
		 * @brief Метод получения случайных байтов
		 *
		 * @param data место, в которое помещаются случайные байты
		 * @param size число получаемых случайных байтов
		 *
		 * @return признак успешности получения случайных байтов
		 *
		 * @note Отказ источника случайности означает, что случайных байтов нет вовсе:
		 *       подменять их чем бы то ни было нельзя, вызов обязан отказать
		 *
		 * \~english
		 * @brief Method of getting the random bytes
		 * @param data the place the random bytes are put into
		 * @param size the number of the random bytes being received
		 * @return the flag of the success of the getting of the random bytes
		 * @note A refusal of the source of the randomness means that there are no random bytes
		 *       at all: it is forbidden to substitute them by anything whatsoever, the call must refuse
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool bytes(uint8_t * data, const size_t size) noexcept;
		/**
		 * \~russian
		 * @brief Метод получения случайного числа по модулю
		 *
		 * @param modulus модуль, меньше которого получается случайное число
		 * @param result  место, в которое помещается случайное число
		 *
		 * @return признак успешности получения случайного числа
		 *
		 * @note Число получается отбором: выпавшее значение, не меньшее модуля либо
		 *       нулевое, отбрасывается целиком, а не приводится по модулю. Приведение
		 *       сделало бы младшие значения вероятнее прочих, а сдвиг вероятностей и есть
		 *       то, чем ломают подпись
		 *
		 * \~english
		 * @brief Method of getting a random number by a modulus
		 * @param modulus the modulus a random number less than which is received
		 * @param result  the place the random number is put into
		 * @return the flag of the success of the getting of the random number
		 * @note The number is received by a selection: a fallen out value not less than the
		 *       modulus or a zero one is discarded entirely and is not reduced by the modulus.
		 *       A reduction would make the junior values more probable than the rest, and a
		 *       shift of the probabilities is exactly what a signature is broken by
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool number(const math::modulus_t & modulus, math::number_t & result) noexcept;
	};
};

#endif // __ANTS_ENTROPY__
