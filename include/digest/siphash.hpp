/**
 * @file siphash.hpp
 * @date 2026-09-07
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
 * @brief Модуль ключевой хеш-функции SipHash-2-4 (Аумассон, Бернштейн) с итогом в 64 и 128 разрядов
 *
 * \~english
 * @brief Module of the keyed hash function SipHash-2-4 (Aumasson, Bernstein) with the output of 64 and 128 bits
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
	 * @brief Пространство имён модулей хеширования
	 *
	 * \~english
	 * @brief Namespace of the hashing modules
	 *
	 * \~
	 */
	namespace digest {
		/**
		 * \~russian
		 * @brief Длина ключа SipHash в байтах
		 *
		 * \~english
		 * @brief Length of the SipHash key in bytes
		 *
		 * \~
		 */
		static constexpr size_t SIPHASH_KEY = 16;
		/**
		 * \~russian
		 * @brief Функция вычисления SipHash-2-4
		 *
		 * @details Два круга сжатия на слово сообщения и четыре круга завершения; итог в
		 *          восемь байтов (64 разряда) либо в шестнадцать (SipHash-2-4-128), записанный
		 *          от младшего байта, как в векторах статьи. Ключ - ровно шестнадцать байтов.
		 *          Назначение - ключи хеш-таблиц и короткие метки (WireGuard), не замена HMAC
		 *
		 * @param key    ключ в шестнадцать байтов
		 * @param data   сообщение любой длины
		 * @param result место, в которое помещается итог
		 * @param size   длина итога: 8 либо 16
		 * @return       признак того, что итог вычислен
		 *
		 * \~english
		 * @brief Function of the computation of SipHash-2-4
		 *
		 * @details Two compression rounds per message word and four finalization rounds; the
		 *          result of eight bytes (64 bits) or of sixteen (SipHash-2-4-128), written from
		 *          the least significant byte as in the vectors of the paper. The key is exactly
		 *          sixteen bytes. Meant for hash table keys and short tags (WireGuard), not a
		 *          replacement of HMAC
		 *
		 * @param key    key of sixteen bytes
		 * @param data   message of any length
		 * @param result place into which the result is put
		 * @param size   length of the result: 8 or 16
		 * @return       sign that the result is computed
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool siphash(const view_t & key, const view_t & data, uint8_t * result, const size_t size) noexcept;
		/**
		 * \~russian
		 * @brief Функция вычисления SipHash-2-4 числом
		 *
		 * @param key    ключ в шестнадцать байтов
		 * @param data   сообщение любой длины
		 * @param result число, в которое помещается 64-разрядный итог
		 * @return       признак того, что итог вычислен
		 *
		 * \~english
		 * @brief Function of the computation of SipHash-2-4 as a number
		 *
		 * @param key    key of sixteen bytes
		 * @param data   message of any length
		 * @param result number into which the 64-bit result is put
		 * @return       sign that the result is computed
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool siphash(const view_t & key, const view_t & data, uint64_t & result) noexcept;
	};
};

