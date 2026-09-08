/**
 * @file ffdhe.hpp
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
 * @brief Заголовочный файл модуля выработки общего ключа Диффи-Хеллмана в конечном
 *        поле на группах RFC 7919 (ffdhe2048 … ffdhe8192)
 *
 * \~english
 * @brief Header file of the module of the production of a shared key by Diffie-Hellman
 *        in a finite field on the groups of RFC 7919 (ffdhe2048 … ffdhe8192)
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_FFDHE__
#define __ANTS_FFDHE__

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
		 * @brief Наибольшая длина модуля групп RFC 7919 в байтах (ffdhe8192)
		 *
		 * \~english
		 * @brief Greatest length of the modulus of the groups of RFC 7919 in bytes (ffdhe8192)
		 *
		 * \~
		 */
		static constexpr size_t FFDHE_MOST = 1024;

		/**
		 * \~russian
		 * @brief Метод получения простого модуля группы RFC 7919 по его длине
		 * @param size длина модуля в байтах: 256, 384, 512, 768 либо 1024
		 * @return     модуль от старшего байта к младшему; пустой просмотр у неведомой длины
		 * @details Приложение A RFC 7919: модули выведены из разложения числа e и заданы
		 *          таблицей, образующая у всех групп равна двум
		 * \~english
		 * @brief Method of getting the prime modulus of a group of RFC 7919 by its length
		 * @param size the length of the modulus in bytes: 256, 384, 512, 768 or 1024
		 * @return     the modulus from the senior byte to the junior one; an empty view at an unknown length
		 * @details The appendix A of RFC 7919: the moduli are derived from the expansion of the number e
		 *          and are given by a table, the generator of all the groups equals two
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ view_t prime(const size_t size) noexcept;
		/**
		 * \~russian
		 * @brief Метод получения длины секретного показателя группы RFC 7919
		 * @param size длина модуля в байтах
		 * @return     длина показателя в байтах, ноль у неведомой длины модуля
		 * @details Раздел 5.2 RFC 7919: показатель берётся не короче удвоенной стойкости
		 *          группы (приложение A RFC 7919: не короче 225, 275, 325, 375 и 400 разрядов) - здесь 256,
		 *          288, 336, 384 и 448 разрядов
		 * \~english
		 * @brief Method of getting the length of the secret exponent of a group of RFC 7919
		 * @param size the length of the modulus in bytes
		 * @return     the length of the exponent in bytes, zero at an unknown length of the modulus
		 * @details The section 5.2 of RFC 7919: the exponent is taken not shorter than the doubled
		 *          strength of the group (the appendix A of RFC 7919: not shorter than 225, 275, 325, 375 and 400
		 *          bits) - here 256, 288, 336, 384 and 448 bits
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ size_t exponent(const size_t size) noexcept;
		/**
		 * \~russian
		 * @brief Метод выработки открытого ключа группы RFC 7919
		 * @param size   длина модуля в байтах
		 * @param secret секретный показатель от старшего байта к младшему, не длиннее модуля (своя сторона берёт `exponent(size)`)
		 * @param result место, в которое помещается открытый ключ длиной в модуль, дополненный нулями спереди
		 * @return       признак успешности выработки открытого ключа
		 * @details Раздел 4.2.8.1 RFC 8446: открытый ключ есть 2^x mod p, записанный длиной модуля
		 * \~english
		 * @brief Method of the production of the public key of a group of RFC 7919
		 * @param size   the length of the modulus in bytes
		 * @param secret the secret exponent from the senior byte to the junior one, not longer than the modulus (one's own side takes `exponent(size)`)
		 * @param result the place the public key of the length of the modulus, padded with zeros ahead, is put into
		 * @return       the flag of the success of the production of the public key
		 * @details The section 4.2.8.1 of RFC 8446: the public key is 2^x mod p written by the length of the modulus
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool ffdhe(const size_t size, const view_t & secret, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Метод выработки общего значения группы RFC 7919
		 * @param size   длина модуля в байтах
		 * @param secret секретный показатель своей стороны, не длиннее модуля
		 * @param key    открытый ключ встречной стороны длиной в модуль
		 * @param result место, в которое помещается общее значение длиной в модуль, дополненное нулями спереди
		 * @return       признак успешности выработки общего значения
		 * @details Раздел 7.4.1 RFC 8446: общее значение есть Y^x mod p длиной модуля. Открытый ключ
		 *          встречной стороны сверяется прежде выработки: 1 < Y < p - 1, как велит раздел 4.2.8.1
		 *          RFC 8446; проверки Y^q mod p = 1 нет намеренно - модули RFC 7919 безопасные простые, а
		 *          возведение в q стоило бы у ffdhe8192 около секунды на рукопожатие
		 * \~english
		 * @brief Method of the production of the shared value of a group of RFC 7919
		 * @param size   the length of the modulus in bytes
		 * @param secret the secret exponent of one's own side, not longer than the modulus
		 * @param key    the public key of the opposite side of the length of the modulus
		 * @param result the place the shared value of the length of the modulus, padded with zeros ahead, is put into
		 * @return       the flag of the success of the production of the shared value
		 * @details The section 7.4.1 of RFC 8446: the shared value is Y^x mod p by the length of the modulus.
		 *          The public key of the opposite side is checked before the production: 1 < Y < p - 1, as the
		 *          section 4.2.8.1 of RFC 8446 orders; there is no Y^q mod p = 1 check deliberately - the moduli of
		 *          RFC 7919 are safe primes, and the raise into q would cost about a second per handshake at ffdhe8192
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool ffdhe(const size_t size, const view_t & secret, const view_t & key, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Метод порождения пары ключей группы RFC 7919
		 * @param size   длина модуля в байтах
		 * @param secret место, в которое помещается секретный показатель длиной `exponent(size)`
		 * @param key    место, в которое помещается открытый ключ длиной в модуль
		 * @return       признак успешности порождения пары ключей
		 * @details Показатель берётся случайными байтами; при отказе оба места затираются
		 * \~english
		 * @brief Method of the generation of a pair of the keys of a group of RFC 7919
		 * @param size   the length of the modulus in bytes
		 * @param secret the place the secret exponent of the length `exponent(size)` is put into
		 * @param key    the place the public key of the length of the modulus is put into
		 * @return       the flag of the success of the generation of the pair of the keys
		 * @details The exponent is taken by random bytes; at a failure both the places are wiped
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool pairffdhe(const size_t size, uint8_t * secret, uint8_t * key) noexcept;
	};
};

#endif // __ANTS_FFDHE__
