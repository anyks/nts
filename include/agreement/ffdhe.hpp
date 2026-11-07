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
 *        поле на группах RFC 7919 (ffdhe2048 … ffdhe8192) и RFC 3526 (modp14 … modp18)
 *
 * \~english
 * @brief Header file of the module of the production of a shared key by Diffie-Hellman
 *        in a finite field on the groups of RFC 7919 (ffdhe2048 … ffdhe8192) and RFC 3526 (modp14 … modp18)
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
		 * @brief Функция получения простого модуля группы RFC 7919 по его длине
		 *
		 * @param size длина модуля в байтах: 256, 384, 512, 768 либо 1024
		 * @return     модуль от старшего байта к младшему; пустой просмотр у неведомой длины
		 *
		 * @details Приложение A RFC 7919: модули выведены из разложения числа e и заданы
		 *          таблицей, образующая у всех групп равна двум
		 *
		 * \~english
		 * @brief Function of getting the prime modulus of a group of RFC 7919 by its length
		 *
		 * @param size the length of the modulus in bytes: 256, 384, 512, 768 or 1024
		 * @return     the modulus from the senior byte to the junior one; an empty view at an unknown length
		 *
		 * @details The appendix A of RFC 7919: the moduli are derived from the expansion of the number e
		 *          and are given by a table, the generator of all the groups equals two
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ view_t prime(const size_t size) noexcept;
		/**
		 * \~russian
		 * @brief Функция получения длины секретного показателя группы RFC 7919
		 *
		 * @param size длина модуля в байтах
		 * @return     длина показателя в байтах, ноль у неведомой длины модуля
		 *
		 * @details Раздел 5.2 RFC 7919: показатель берётся не короче удвоенной стойкости
		 *          группы (приложение A RFC 7919: не короче 225, 275, 325, 375 и 400 разрядов) - здесь 256,
		 *          288, 336, 384 и 448 разрядов
		 *
		 * \~english
		 * @brief Function of getting the length of the secret exponent of a group of RFC 7919
		 *
		 * @param size the length of the modulus in bytes
		 * @return     the length of the exponent in bytes, zero at an unknown length of the modulus
		 *
		 * @details The section 5.2 of RFC 7919: the exponent is taken not shorter than the doubled
		 *          strength of the group (the appendix A of RFC 7919: not shorter than 225, 275, 325, 375 and 400
		 *          bits) - here 256, 288, 336, 384 and 448 bits
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ size_t exponent(const size_t size) noexcept;
		/**
		 * \~russian
		 * @brief Функция выработки открытого ключа группы RFC 7919
		 *
		 * @param size   длина модуля в байтах
		 * @param secret секретный показатель от старшего байта к младшему, не длиннее модуля (своя сторона берёт `exponent(size)`)
		 * @param result место, в которое помещается открытый ключ длиной в модуль, дополненный нулями спереди
		 * @return       признак успешности выработки открытого ключа
		 *
		 * @details Раздел 4.2.8.1 RFC 8446: открытый ключ есть 2^x mod p, записанный длиной модуля
		 *
		 * \~english
		 * @brief Function of the production of the public key of a group of RFC 7919
		 *
		 * @param size   the length of the modulus in bytes
		 * @param secret the secret exponent from the senior byte to the junior one, not longer than the modulus (one's own side takes `exponent(size)`)
		 * @param result the place the public key of the length of the modulus, padded with zeros ahead, is put into
		 * @return       the flag of the success of the production of the public key
		 *
		 * @details The section 4.2.8.1 of RFC 8446: the public key is 2^x mod p written by the length of the modulus
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool ffdhe(const size_t size, const view_t & secret, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Функция выработки общего значения группы RFC 7919
		 *
		 * @param size   длина модуля в байтах
		 * @param secret секретный показатель своей стороны, не длиннее модуля
		 * @param key    открытый ключ встречной стороны длиной в модуль
		 * @param result место, в которое помещается общее значение длиной в модуль, дополненное нулями спереди
		 * @return       признак успешности выработки общего значения
		 *
		 * @details Раздел 7.4.1 RFC 8446: общее значение есть Y^x mod p длиной модуля. Открытый ключ
		 *          встречной стороны сверяется прежде выработки: 1 < Y < p - 1, как велит раздел 4.2.8.1
		 *          RFC 8446; проверки Y^q mod p = 1 нет намеренно - модули RFC 7919 безопасные простые, а
		 *          возведение в q стоило бы у ffdhe8192 около секунды на рукопожатие
		 *
		 * \~english
		 * @brief Function of the production of the shared value of a group of RFC 7919
		 *
		 * @param size   the length of the modulus in bytes
		 * @param secret the secret exponent of one's own side, not longer than the modulus
		 * @param key    the public key of the opposite side of the length of the modulus
		 * @param result the place the shared value of the length of the modulus, padded with zeros ahead, is put into
		 * @return       the flag of the success of the production of the shared value
		 *
		 * @details The section 7.4.1 of RFC 8446: the shared value is Y^x mod p by the length of the modulus.
		 *          The public key of the opposite side is checked before the production: 1 < Y < p - 1, as the
		 *          section 4.2.8.1 of RFC 8446 orders; there is no Y^q mod p = 1 check deliberately - the moduli of
		 *          RFC 7919 are safe primes, and the raise into q would cost about a second per handshake at ffdhe8192
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool ffdhe(const size_t size, const view_t & secret, const view_t & key, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Функция порождения пары ключей группы RFC 7919
		 *
		 * @param size   длина модуля в байтах
		 * @param secret место, в которое помещается секретный показатель длиной `exponent(size)`
		 * @param key    место, в которое помещается открытый ключ длиной в модуль
		 * @return       признак успешности порождения пары ключей
		 *
		 * @details Показатель берётся случайными байтами; при отказе оба места затираются
		 *
		 * \~english
		 * @brief Function of the generation of a pair of the keys of a group of RFC 7919
		 *
		 * @param size   the length of the modulus in bytes
		 * @param secret the place the secret exponent of the length `exponent(size)` is put into
		 * @param key    the place the public key of the length of the modulus is put into
		 * @return       the flag of the success of the generation of the pair of the keys
		 *
		 * @details The exponent is taken by random bytes; at a failure both the places are wiped
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool pairffdhe(const size_t size, uint8_t * secret, uint8_t * key) noexcept;
		/**
		 * \~russian
		 * @brief Функция получения простого модуля группы RFC 3526 по её опознавателю
		 *
		 * @param id опознаватель группы: 14 (modp2048), 15 (modp3072), 16 (modp4096)
		 * @return   модуль от старшего байта к младшему; пустой просмотр у неведомого опознавателя
		 *
		 * \~english
		 * @brief Function of getting the prime modulus of a group of RFC 3526 by its identifier
		 *
		 * @param id the identifier of the group: 14 (modp2048), 15 (modp3072), 16 (modp4096)
		 * @return   the modulus from the senior byte to the junior one; an empty view at an unknown identifier
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ view_t prime3526(const uint8_t id) noexcept;
		/**
		 * \~russian
		 * @brief Функция получения длины секретного показателя группы RFC 3526
		 *
		 * @param id опознаватель группы
		 * @return   длина показателя в байтах, ноль у неведомого опознавателя
		 *
		 * @details Берётся та же длина, что у групп RFC 7919 той же размерности: 256, 288
		 *          и 336 разрядов для modp14, modp15 и modp16
		 *
		 * \~english
		 * @brief Function of getting the length of the secret exponent of a group of RFC 3526
		 *
		 * @param id the identifier of the group
		 * @return   the length of the exponent in bytes, zero at an unknown identifier
		 *
		 * @details The same length as the groups of RFC 7919 of the same size is taken: 256, 288
		 *          and 336 bits for modp14, modp15 and modp16
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ size_t exponent3526(const uint8_t id) noexcept;
		/**
		 * \~russian
		 * @brief Функция выработки открытого ключа по произвольному простому модулю и образующей
		 *
		 * @param prime     простой нечётный модуль от старшего байта к младшему
		 * @param generator образующая группы, 1 < g < p
		 * @param secret    секретный показатель, 1 < secret < p − 1
		 * @param result    место, в которое помещается открытый ключ длиной в модуль
		 * @return          признак успешности выработки открытого ключа
		 *
		 * @details Общий вид: g^secret mod p. Модуль нечётный и не длиннее 8192 разрядов,
		 *          образующая и показатель сверяются с границами
		 *
		 * \~english
		 * @brief Function of the production of the public key by an arbitrary prime modulus and generator
		 *
		 * @param prime     the odd prime modulus from the senior byte to the junior one
		 * @param generator the generator of the group, 1 < g < p
		 * @param secret    the secret exponent, 1 < secret < p − 1
		 * @param result    the place the public key of the length of the modulus is put into
		 * @return          the flag of the success of the production of the public key
		 *
		 * @details The general form is g^secret mod p. The modulus is odd and not longer than 8192 bits,
		 *          the generator and the exponent are checked against the bounds
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool ffdhe(const view_t & prime, const view_t & generator, const view_t & secret, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Функция выработки общего значения по произвольному простому модулю и образующей
		 *
		 * @param prime     простой нечётный модуль от старшего байта к младшему
		 * @param generator образующая группы, 1 < g < p
		 * @param secret    секретный показатель своей стороны, 1 < secret < p − 1
		 * @param key       открытый ключ встречной стороны длиной в модуль, 1 < key < p − 1
		 * @param result    место, в которое помещается общее значение длиной в модуль
		 * @return          признак успешности выработки общего значения
		 *
		 * @details Общий вид: key^secret mod p. Ключ встречной стороны, образующая и показатель
		 *          сверяются с границами; общее значение 1 и p − 1 отвергаются как вырожденные
		 *
		 * \~english
		 * @brief Function of the production of the shared value by an arbitrary prime modulus and generator
		 *
		 * @param prime     the odd prime modulus from the senior byte to the junior one
		 * @param generator the generator of the group, 1 < g < p
		 * @param secret    the secret exponent of one's own side, 1 < secret < p − 1
		 * @param key       the public key of the opposite side of the length of the modulus, 1 < key < p − 1
		 * @param result    the place the shared value of the length of the modulus is put into
		 * @return          the flag of the success of the production of the shared value
		 *
		 * @details The general form is key^secret mod p. The public key of the opposite side, the generator
		 *          and the exponent are checked against the bounds; the shared values 1 and p − 1 are
		 *          rejected as degenerate
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool ffdhe(const view_t & prime, const view_t & generator, const view_t & secret, const view_t & key, uint8_t * result) noexcept;
		/**
		 * \~russian
		 * @brief Функция порождения пары ключей по произвольному простому модулю и образующей
		 *
		 * @param prime     простой нечётный модуль от старшего байта к младшему
		 * @param generator образующая группы, 1 < g < p
		 * @param length    длина секретного показателя в байтах
		 * @param secret    место, в которое помещается секретный показатель длиной length
		 * @param key       место, в которое помещается открытый ключ длиной в модуль
		 * @return          признак успешности порождения пары ключей
		 *
		 * @details Показатель берётся случайными байтами, старший разряд выставляется; если у
		 *          произвольного модуля показатель вышел за границу (1, p - 1), разряд снимается;
		 *          при отказе оба места затираются
		 *
		 * \~english
		 * @brief Function of the generation of a pair of keys by an arbitrary prime modulus and generator
		 *
		 * @param prime     the odd prime modulus from the senior byte to the junior one
		 * @param generator the generator of the group, 1 < g < p
		 * @param length    the length of the secret exponent in bytes
		 * @param secret    the place the secret exponent of the length length is put into
		 * @param key       the place the public key of the length of the modulus is put into
		 * @return          the flag of the success of the generation of the pair of keys
		 *
		 * @details The exponent is taken by random bytes, the senior bit is set; at a failure
		 *          both places are wiped
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool pairffdhe(const view_t & prime, const view_t & generator, const size_t length, uint8_t * secret, uint8_t * key) noexcept;
	};
};

