/**
 * @file x25519.hpp
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
 * @brief Заголовочный файл модуля выработки общего ключа на кривой Curve25519 —
 *        функция X25519 по RFC 7748
 *
 * \~english
 * @brief Header file of the module of the production of a shared key on the curve
 *        Curve25519 — the function X25519 according to RFC 7748
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
		 * @brief Размер ключей и общего значения X25519 в байтах
		 *
		 * \~english
		 * @brief Size of the keys and of the shared value of X25519 in bytes
		 *
		 * \~
		 */
		static constexpr size_t X25519_SIZE = 32;

		/**
		 * \~russian
		 * @brief Функция выработки общего значения на кривой Curve25519
		 *
		 * @param secret секретный ключ своей стороны длиной в тридцать два байта
		 * @param point  открытый ключ встречной стороны длиной в тридцать два байта
		 * @param result место, в которое помещается общее значение длиной в тридцать два байта
		 * @return       признак успешности выработки общего значения
		 *
		 * @details Раздел 5 RFC 7748: секретный ключ зажимается - три младших разряда
		 *          сбрасываются, старший разряд сбрасывается, а разряд 254 ставится, -
		 *          после чего первая координата открытого ключа множится на него лестницей
		 *          Монтгомери за постоянное время. Все записи идут младшим байтом вперёд.
		 *
		 * @note Общее значение, обратившееся в ноль, отвергается, как велит раздел 6.1
		 *       RFC 7748: оно означает открытый ключ малого порядка, а с ним встречная
		 *       сторона узнала бы общее значение, не зная секретного ключа
		 *
		 * \~english
		 * @brief Function of the production of the shared value on the curve Curve25519
		 *
		 * @param secret the secret key of one's own side of a length of thirty two bytes
		 * @param point  the public key of the opposite side of a length of thirty two bytes
		 * @param result the place the shared value of a length of thirty two bytes is put into
		 * @return       the flag of the success of the production of the shared value
		 *
		 * @details The section 5 of RFC 7748: the secret key is clamped - the three junior bits
		 *          are cleared, the senior bit is cleared, and the bit 254 is set, - after which
		 *          the first coordinate of the public key is multiplied by it by the Montgomery
		 *          ladder in a constant time. All the records go with the junior byte ahead.
		 *
		 * @note A shared value turned into a zero is rejected, as the section 6.1 of RFC 7748
		 *       orders: it means a public key of a small order, and with it the opposite side
		 *       would learn the shared value without knowing the secret key
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool x25519(const view_t & secret, const view_t & point, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Функция выработки открытого ключа на кривой Curve25519
		 *
		 * @param secret секретный ключ длиной в тридцать два байта
		 * @param result место, в которое помещается открытый ключ длиной в тридцать два байта
		 * @return       признак успешности выработки открытого ключа
		 *
		 * @details Раздел 6.1 RFC 7748: открытый ключ есть произведение секретного ключа на
		 *          точку основания с первой координатой девять
		 *
		 * \~english
		 * @brief Function of the production of the public key on the curve Curve25519
		 *
		 * @param secret the secret key of a length of thirty two bytes
		 * @param result the place the public key of a length of thirty two bytes is put into
		 * @return       the flag of the success of the production of the public key
		 *
		 * @details The section 6.1 of RFC 7748: the public key is the product of the secret key
		 *          by the base point with the first coordinate nine
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool x25519(const view_t & secret, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Функция порождения пары ключей на кривой Curve25519
		 *
		 * @param secret место, в которое помещается секретный ключ длиной в тридцать два байта
		 * @param key    место, в которое помещается открытый ключ длиной в тридцать два байта
		 * @return       признак успешности порождения пары ключей
		 *
		 * @details Раздел 5 RFC 7748: секретный ключ есть тридцать два случайных байта,
		 *          у которых сброшены три младших разряда и старший разряд, а разряд 254
		 *          поставлен, - тот же зажим, что выполняется при всяком умножении; открытый
		 *          ключ выводится из него как при однодоводном x25519
		 *
		 * @note Пара пригодна и как мимолётная, и как долговременная: порождение одно и то
		 *       же, а срок жизни ключа определяет вызывающая сторона. Записанный секретный
		 *       ключ уже зажат, оттого запись PKCS #8 через keys читается любой стороной
		 *       одинаково. Отказ источника случайности отвечает отказом порождения, места
		 *       ключей при этом затёрты
		 *
		 * \~english
		 * @brief Function of the generation of a pair of keys on the curve Curve25519
		 *
		 * @param secret the place the secret key of a length of thirty two bytes is put into
		 * @param key    the place the public key of a length of thirty two bytes is put into
		 * @return       the flag of the success of the generation of the pair of keys
		 *
		 * @details The section 5 of RFC 7748: the secret key is thirty two random bytes with the
		 *          three junior bits and the senior bit cleared and the bit 254 set - the same
		 *          clamping that is performed at every multiplication; the public key is derived
		 *          from it as at the one-argument x25519
		 *
		 * @note The pair is fit both as an ephemeral and as a long-term one: the generation is
		 *       the same, while the lifetime of the key is defined by the calling side. The
		 *       written secret key is already clamped, therefore the record PKCS #8 via keys is
		 *       read by any side identically. A refusal of the source of the randomness answers
		 *       by a refusal of the generation, the places of the keys are wiped at that
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool generate(uint8_t * secret, uint8_t * key) noexcept;
	};
};

