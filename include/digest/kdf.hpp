/**
 * @file kdf.hpp
 * @date 2026-08-29
 *
 * @license{LicenseRef-ANYKS-TLS-1.0}
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
 * @brief Заголовочный файл модуля функции выработки производного ключа по RFC 7836
 *
 * \~english
 * @brief Header file of the module of the function of the derivation of a key
 *        according to RFC 7836
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANYKS_TLS_KDF__
#define __ANYKS_TLS_KDF__

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
namespace anyks {
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
		 * @brief Длина производного ключа в байтах
		 *
		 * \~english
		 * @brief Length of a derived key in bytes
		 *
		 * \~
		 */
		static constexpr size_t KDF_KEY = 32;

		/**
		 * \~russian
		 * @brief Наибольшая длина метки и затравки выработки ключа в байтах
		 *
		 * @details Раздел 4.5 RFC 7836 длины метки и затравки не ограничивает, их
		 *          назначает протокол. Предел здесь взят с большим запасом от всего,
		 *          что назначено протоколом TLS, и введён лишь затем, чтобы обойтись
		 *          без выделения памяти на пути выработки ключа
		 *
		 * \~english
		 * @brief Greatest length of the label and of the seed of the derivation of a key in bytes
		 * @details The section 4.5 of RFC 7836 does not limit the lengths of the label and of the
		 *          seed, they are assigned by a protocol. The limit here is taken with a large
		 *          reserve from everything assigned by the TLS protocol and is introduced only in
		 *          order to do without an allocation of memory on the path of the derivation of a key
		 *
		 * \~
		 */
		static constexpr size_t KDF_LIMIT = 128;

		/**
		 * \~russian
		 * @brief Метод выработки производного ключа
		 *
		 * @param key    ключ выработки производного ключа
		 * @param label  метка назначения производного ключа
		 * @param seed   затравка выработки производного ключа
		 * @param result место, в которое помещается производный ключ
		 *
		 * @return       признак успешности выработки производного ключа
		 *
		 * @details Раздел 4.5 RFC 7836: имитовставка на хеше длиной 256 разрядов берётся
		 *          от слитной строки 0x01, метки, 0x00, затравки, 0x01 и 0x00
		 *
		 * @note Место итога обязано вмещать KDF_KEY байтов
		 *
		 * \~english
		 * @brief Method of the derivation of a key
		 * @param key    the key of the derivation of the derived key
		 * @param label  the label of the purpose of the derived key
		 * @param seed   the seed of the derivation of the derived key
		 * @param result the place the derived key is put into
		 * @return       the flag of the success of the derivation of the key
		 * @details The section 4.5 of RFC 7836: an authentication code on a hash of a length of 256
		 *          bits is taken from the concatenated string of 0x01, of the label, of 0x00, of the
		 *          seed, of 0x01 and of 0x00
		 * @note The place of the outcome is obliged to hold KDF_KEY bytes
		 *
		 * \~
		 */
		__ANYKS_TLS_SHARED_EXPORT__ bool kdf(const view_t & key, const view_t & label, const view_t & seed, uint8_t * result) noexcept;
	};
};

#endif // __ANYKS_TLS_KDF__
