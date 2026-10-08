/**
 * @file ecdhe.hpp
 * @date 2026-08-30
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
 * @brief Заголовочный файл модуля обмена мимолётными ключами протокола TLS 1.3 —
 *        выработка пары ключей и общего значения по разделу 6.1.1 описания наборов
 *        шифрования на алгоритмах ГОСТ
 *
 * \~english
 * @brief Header file of the module of the exchange of the ephemeral keys of the TLS 1.3
 *        protocol — the production of a pair of the keys and of the shared value according to
 *        the section 6.1.1 of the description of the cipher suites on the GOST algorithms
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
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <curve/curve.hpp>

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
	 * @brief Пространство имён модулей выработки общего ключа
	 *
	 * \~english
	 * @brief Namespace of the modules of the production of a shared key
	 *
	 * \~
	 */
	namespace agreement {
		/**
		 * \~russian
		 * @brief Метод выработки мимолётной пары ключей
		 *
		 * @param curve  эллиптическая кривая обмена мимолётными ключами
		 * @param secret место, в которое помещается секретный ключ длиной в размер кривой
		 * @param key    место, в которое помещается открытый ключ длиной в два размера кривой
		 *
		 * @return       признак успешности выработки мимолётной пары ключей
		 *
		 * @details Раздел 6.1.1.3 описания наборов шифрования на алгоритмах ГОСТ: открытый
		 *          ключ записывается двумя координатами точки подряд, каждая из которых идёт
		 *          младшим байтом вперёд. Секретный ключ записан тем же порядком.
		 *
		 * @note Секретный ключ берётся из области от единицы до порядка подгруппы точек
		 *       кривой отбором: приведение случайного значения по остатку сместило бы
		 *       выбор к младшим значениям
		 *
		 * \~english
		 * @brief Method of the production of an ephemeral pair of the keys
		 * @param curve  the elliptic curve of the exchange of the ephemeral keys
		 * @param secret the place the secret key of a length of the size of the curve is put into
		 * @param key    the place the public key of a length of two sizes of the curve is put into
		 * @return       the flag of the success of the production of the ephemeral pair of the keys
		 * @details The section 6.1.1.3 of the description of the cipher suites on the GOST algorithms:
		 *          the public key is written by the two coordinates of a point in a row, each of which
		 *          goes with the junior byte ahead. The secret key is written by the same order.
		 * @note The secret key is taken from the area from a unit to the order of the subgroup of the
		 *       points of the curve by a selection: the reduction of a random value by a remainder would
		 *       shift the choice towards the junior values
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool generate(const curve::curve_t & curve, uint8_t * secret, uint8_t * key) noexcept;
		/**
		 * \~russian
		 * @brief Метод выработки общего значения обмена мимолётными ключами
		 *
		 * @param curve  эллиптическая кривая обмена мимолётными ключами
		 * @param secret секретный ключ своей стороны, записанный младшим байтом вперёд
		 * @param key    открытый ключ встречной стороны, записанный младшим байтом вперёд
		 * @param result место, в которое помещается общее значение длиной в размер кривой
		 *
		 * @return       признак успешности выработки общего значения
		 *
		 * @details Раздел 6.1.1 описания наборов шифрования на алгоритмах ГОСТ: обе стороны
		 *          получают первую координату кратной точки от произведения кофактора кривой
		 *          и своего секретного ключа на открытый ключ встречной стороны
		 *
		 * @note Открытый ключ встречной стороны проверяется на принадлежность кривой, а
		 *       кратная точка — на обращение в ноль: обе проверки требует стандарт, и обе
		 *       выдают секретный ключ своей стороны, если их не делать
		 *
		 * \~english
		 * @brief Method of the production of the shared value of the exchange of the ephemeral keys
		 * @param curve  the elliptic curve of the exchange of the ephemeral keys
		 * @param secret the secret key of one's own side written with the junior byte ahead
		 * @param key    the public key of the opposite side written with the junior byte ahead
		 * @param result the place the shared value of a length of the size of the curve is put into
		 * @return       the flag of the success of the production of the shared value
		 * @details The section 6.1.1 of the description of the cipher suites on the GOST algorithms: both
		 *          sides receive the first coordinate of the multiple point from the product of the cofactor
		 *          of the curve and of one's own secret key by the public key of the opposite side
		 * @note The public key of the opposite side is checked for the belonging to the curve, and the
		 *       multiple point — for the turning into a zero: the standard demands both checks, and both
		 *       give away the secret key of one's own side if they are not done
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool ecdhe(const curve::curve_t & curve, const view_t & secret, const view_t & key, uint8_t * result) noexcept;
	};
};

