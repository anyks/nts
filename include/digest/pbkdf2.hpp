/**
 * @file pbkdf2.hpp
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
 * @brief Заголовочный файл модуля вывода ключа из пароля PBKDF2 по RFC 8018 над
 *        любым хешем библиотеки
 *
 * \~english
 * @brief Header file of the PBKDF2 password-based key derivation module according to
 *        RFC 8018 over any hash of the library
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
#include <digest/hash.hpp>

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
		 * @brief Функция вывода ключа из пароля PBKDF2-HMAC
		 *
		 * @param algorithm  алгоритм хеширования имитовставки
		 * @param password   пароль, вправе быть пустым
		 * @param salt       соль, вправе быть пустой
		 * @param iterations число оборотов, не меньше одного
		 * @param result     место, в которое помещается выведенный ключ
		 * @param size       требуемая длина ключа, не меньше одного байта
		 * @return           признак успешности вывода
		 *
		 * @details Раздел 5.2 RFC 8018: ключ складывается блоками длиной в хеш,
		 *          блок - сумма по модулю два оборотов U(1) = HMAC(P, S | i),
		 *          U(j) = HMAC(P, U(j-1)). Ключ имитовставки заводится один раз на
		 *          весь вывод: обороты стоят по два хеширования, а не по четыре
		 *
		 * @note Число оборотов задаётся вызывающим: библиотека умолчания не навязывает,
		 *       ибо оно меняется с годами и зависит от назначения ключа
		 *
		 * \~english
		 * @brief Function of the derivation of a key from a password by PBKDF2-HMAC
		 *
		 * @param algorithm  the hashing algorithm of the authentication code
		 * @param password   the password, may be empty
		 * @param salt       the salt, may be empty
		 * @param iterations the number of the iterations, not less than one
		 * @param result     the place the derived key is put into
		 * @param size       the required length of the key, not less than one byte
		 * @return           the flag of the success of the derivation
		 *
		 * @details The section 5.2 of RFC 8018: the key is composed of the blocks of the length of
		 *          the hash, a block is the sum modulo two of the iterations U(1) = HMAC(P, S | i),
		 *          U(j) = HMAC(P, U(j-1)). The key of the authentication code is set once for the
		 *          whole derivation: the iterations cost two hashings, not four
		 *
		 * @note The number of the iterations is given by the caller: the library imposes no default,
		 *       for it changes over the years and depends on the purpose of the key
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool pbkdf2(const hash_t algorithm, const view_t & password, const view_t & salt, const uint32_t iterations, uint8_t * result, const size_t size) noexcept;
	};
};

