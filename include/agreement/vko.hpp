/**
 * @file vko.hpp
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
 * @brief Заголовочный файл модуля выработки общего ключа VKO по RFC 7836
 *
 * \~english
 * @brief Header file of the module of the production of a shared key VKO according to RFC 7836
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
		 * @brief Метод выработки общего ключа
		 *
		 * @param curve  эллиптическая кривая выработки общего ключа
		 * @param secret секретный ключ своей стороны
		 * @param x      первая координата открытого ключа встречной стороны
		 * @param y      вторая координата открытого ключа встречной стороны
		 * @param ukm    добавочное значение сторон, задаваемое протоколом
		 * @param result место, в которое помещается общий ключ
		 * @param size   требуемая длина общего ключа в байтах
		 *
		 * @return признак успешности выработки общего ключа
		 *
		 * @details Раздел 4.3 RFC 7836: обе стороны получают одно и то же значение,
		 *          поскольку кратная точка от произведения своего секретного ключа на
		 *          открытый ключ встречной стороны у них общая. Общий ключ выходит хешем
		 *          координат этой точки: длина 32 байта берёт хеш длиной 256 разрядов,
		 *          длина 64 байта - хеш длиной 512 разрядов.
		 *
		 * @note Добавочное значение вправе быть пустым: стандарт полагает его равным
		 *       единице по умолчанию. Совпадение его у сторон обязательно, а вот
		 *       неповторимость требуется лишь тогда, когда хоть одна из сторон применяет
		 *       постоянный ключ
		 *
		 * @note Открытый ключ встречной стороны проверяется на принадлежность кривой:
		 *       без этой проверки подставная точка малого порядка выдаёт секретный ключ
		 *
		 * \~english
		 * @brief Method of the production of a shared key
		 * @param curve  the elliptic curve of the production of the shared key
		 * @param secret the secret key of one's own side
		 * @param x      the first coordinate of the public key of the opposite side
		 * @param y      the second coordinate of the public key of the opposite side
		 * @param ukm    the user keying material given by the protocol
		 * @param result the place the shared key is put into
		 * @param size   the required length of the shared key in bytes
		 * @return the flag of the success of the production of the shared key
		 * @details The section 4.3 of RFC 7836: both sides receive one and the same value, since
		 *          the multiple point from the product of one's own secret key by the public key
		 *          of the opposite side is common to them. The shared key comes out as a hash of
		 *          the coordinates of this point: a length of 32 bytes takes a hash of a length of
		 *          256 bits, a length of 64 bytes takes a hash of a length of 512 bits.
		 * @note The user keying material may be empty: the standard considers it equal to a unit by
		 *       default. Its coincidence at the sides is obligatory, while its uniqueness is required
		 *       only when at least one of the sides applies a constant key
		 * @note The public key of the opposite side is checked for the belonging to the curve: without
		 *       this check a substituted point of a small order gives away the secret key
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool vko(const curve::curve_t & curve, const view_t & secret, const view_t & x, const view_t & y, const view_t & ukm, uint8_t * result, const size_t size) noexcept;
	};
};

