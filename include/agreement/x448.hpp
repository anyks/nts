/**
 * @file x448.hpp
 * @date 2026-09-09
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
 * @brief Заголовочный файл модуля выработки общего ключа на кривой Curve448 —
 *        функция X448 по RFC 7748
 *
 * \~english
 * @brief Header file of the module of the production of a shared key on the curve
 *        Curve448 — the function X448 according to RFC 7748
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
		 * @brief Размер ключей и общего значения X448 в байтах
		 *
		 * \~english
		 * @brief Size of the keys and of the shared value of X448 in bytes
		 *
		 * \~
		 */
		static constexpr size_t X448_SIZE = 56;

		/**
		 * \~russian
		 * @brief Функция выработки общего значения на кривой Curve448
		 *
		 * @param secret секретный ключ своей стороны длиной в пятьдесят шесть байтов
		 * @param point  открытый ключ встречной стороны длиной в пятьдесят шесть байтов
		 * @param result место, в которое помещается общее значение длиной в пятьдесят шесть байтов
		 * @return       признак успешности выработки общего значения
		 *
		 * @details Раздел 5 RFC 7748: секретный ключ зажимается - два младших разряда
		 *          сбрасываются, а разряд 447 ставится, - после чего первая координата
		 *          открытого ключа множится на него лестницей Монтгомери за постоянное
		 *          время в арифметике по модулю 2^448 - 2^224 - 1. Все записи идут младшим
		 *          байтом вперёд
		 *
		 * @note Общее значение, обратившееся в ноль, отвергается, как велит раздел 6.2
		 *       RFC 7748: оно означает открытый ключ малого порядка
		 *
		 * \~english
		 * @brief Function of the production of the shared value on the curve Curve448
		 *
		 * @param secret the secret key of one's own side of a length of fifty six bytes
		 * @param point  the public key of the opposite side of a length of fifty six bytes
		 * @param result the place the shared value of a length of fifty six bytes is put into
		 * @return       the flag of the success of the production of the shared value
		 *
		 * @details The section 5 of RFC 7748: the secret key is clamped - the two junior bits are
		 *          cleared and the bit 447 is set, - after which the first coordinate of the public
		 *          key is multiplied by it by the Montgomery ladder in a constant time in the
		 *          arithmetic by the modulus 2^448 - 2^224 - 1. All the records go with the junior
		 *          byte ahead
		 *
		 * @note A shared value turned into a zero is rejected, as the section 6.2 of RFC 7748
		 *       orders: it means a public key of a small order
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool x448(const view_t & secret, const view_t & point, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Функция выработки открытого ключа на кривой Curve448
		 *
		 * @param secret секретный ключ длиной в пятьдесят шесть байтов
		 * @param result место, в которое помещается открытый ключ длиной в пятьдесят шесть байтов
		 * @return       признак успешности выработки открытого ключа
		 *
		 * @details Раздел 6.2 RFC 7748: открытый ключ есть произведение секретного ключа на
		 *          точку основания с первой координатой пять
		 *
		 * \~english
		 * @brief Function of the production of the public key on the curve Curve448
		 *
		 * @param secret the secret key of a length of fifty six bytes
		 * @param result the place the public key of a length of fifty six bytes is put into
		 * @return       the flag of the success of the production of the public key
		 *
		 * @details The section 6.2 of RFC 7748: the public key is the product of the secret key
		 *          by the base point with the first coordinate five
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool x448(const view_t & secret, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Функция порождения пары ключей на кривой Curve448
		 *
		 * @param secret место, в которое помещается секретный ключ длиной в пятьдесят шесть байтов
		 * @param key    место, в которое помещается открытый ключ длиной в пятьдесят шесть байтов
		 * @return       признак успешности порождения пары ключей
		 *
		 * @details Раздел 5 RFC 7748: секретный ключ есть пятьдесят шесть случайных байтов,
		 *          зажатых на месте; при отказе оба места затираются
		 *
		 * \~english
		 * @brief Function of the generation of a pair of the keys on the curve Curve448
		 *
		 * @param secret the place the secret key of a length of fifty six bytes is put into
		 * @param key    the place the public key of a length of fifty six bytes is put into
		 * @return       the flag of the success of the generation of the pair of the keys
		 *
		 * @details The section 5 of RFC 7748: the secret key is fifty six random bytes clamped in
		 *          place; at a failure both the places are wiped
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool pair448(uint8_t * secret, uint8_t * key) noexcept;
	};
};

