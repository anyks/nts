/**
 * @file hash.hpp
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
 * @brief Заголовочный файл общего хеширования — один договор над всеми алгоритмами
 *        хеша библиотеки, выбираемыми значением перечисления
 *
 * \~english
 * @brief Header file of the common hashing — one contract over all the hash algorithms of
 *        the library, chosen by a value of an enumeration
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
#include <digest/md5.hpp>
#include <digest/sha1.hpp>
#include <digest/sha2.hpp>
#include <digest/sm3.hpp>
#include <digest/ripemd.hpp>
#include <digest/streebog.hpp>
#include <digest/blake2.hpp>

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
		 * @brief Алгоритм хеширования
		 *
		 * @details Одно перечисление на все хеши библиотеки: им выбирается хеш у
		 *          имитовставки, вывода ключей и подписей, где алгоритм - довод, а не
		 *          устройство. Значения не совпадают с длинами хешей нарочно: два
		 *          алгоритма с одной длиной различны
		 *
		 * \~english
		 * @brief Hashing algorithm
		 * @details One enumeration for all the hashes of the library: the hash of the
		 *          authentication code, of the key derivation and of the signatures is chosen by
		 *          it, where the algorithm is an argument and not a construction. The values
		 *          deliberately do not coincide with the lengths of the hashes: two algorithms
		 *          with one length are different
		 *
		 * \~
		 */
		enum class hash_t : uint8_t {
			NONE        = 0x00, /*!< \~russian Алгоритм не установлен \~english The algorithm is not set \~ */
			MD5         = 0x01, /*!< \~russian MD5 по RFC 1321, 128 разрядов \~english MD5 according to RFC 1321, 128 bits \~ */
			SHA1        = 0x02, /*!< \~russian SHA-1 по FIPS 180-4, 160 разрядов \~english SHA-1 according to FIPS 180-4, 160 bits \~ */
			SHA224      = 0x03, /*!< \~russian SHA-224 по FIPS 180-4 \~english SHA-224 according to FIPS 180-4 \~ */
			SHA256      = 0x04, /*!< \~russian SHA-256 по FIPS 180-4 \~english SHA-256 according to FIPS 180-4 \~ */
			SHA384      = 0x05, /*!< \~russian SHA-384 по FIPS 180-4 \~english SHA-384 according to FIPS 180-4 \~ */
			SHA512      = 0x06, /*!< \~russian SHA-512 по FIPS 180-4 \~english SHA-512 according to FIPS 180-4 \~ */
			STREEBOG256 = 0x07, /*!< \~russian «Стрибог» по ГОСТ Р 34.11-2012, 256 разрядов \~english «Streebog» according to GOST R 34.11-2012, 256 bits \~ */
			STREEBOG512 = 0x08, /*!< \~russian «Стрибог» по ГОСТ Р 34.11-2012, 512 разрядов \~english «Streebog» according to GOST R 34.11-2012, 512 bits \~ */
			BLAKE2S256  = 0x09, /*!< \~russian BLAKE2s по RFC 7693, 256 разрядов, блок 64 байта (Noise, WireGuard) \~english BLAKE2s according to RFC 7693, 256 bits, 64-byte block (Noise, WireGuard) \~ */
			BLAKE2B512  = 0x0A, /*!< \~russian BLAKE2b по RFC 7693, 512 разрядов, блок 128 байтов \~english BLAKE2b according to RFC 7693, 512 bits, 128-byte block \~ */
			SM3         = 0x0B, /*!< \~russian SM3 по GB/T 32905-2016, 256 разрядов (RFC 8998) \~english SM3 according to GB/T 32905-2016, 256 bits (RFC 8998) \~ */
			RIPEMD160   = 0x0C  /*!< \~russian RIPEMD-160 (Доббертин, Босселарс, Пренел), 160 разрядов \~english RIPEMD-160 (Dobbertin, Bosselaers, Preneel), 160 bits \~ */
		};

		/**
		 * \~russian
		 * @brief Метод получения длины хеша алгоритма
		 *
		 * @param algorithm алгоритм хеширования
		 *
		 * @return          длина хеша в байтах, ноль у неустановленного алгоритма
		 *
		 * \~english
		 * @brief Method of getting the length of the hash of an algorithm
		 * @param algorithm the hashing algorithm
		 * @return          the length of the hash in bytes, zero at an unset algorithm
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ size_t length(const hash_t algorithm) noexcept;
		/**
		 * \~russian
		 * @brief Метод получения размера блока сжатия алгоритма
		 *
		 * @param algorithm алгоритм хеширования
		 *
		 * @return          размер блока в байтах, ноль у неустановленного алгоритма
		 *
		 * @note Размер блока нужен имитовставке: ключ дополняется до блока либо
		 *       хешируется, если его длиннее
		 *
		 * \~english
		 * @brief Method of getting the size of the compression block of an algorithm
		 * @param algorithm the hashing algorithm
		 * @return          the size of the block in bytes, zero at an unset algorithm
		 * @note The size of the block is needed by the authentication code: the key is padded
		 *       to the block or hashed if it is longer
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ size_t block(const hash_t algorithm) noexcept;

		/**
		 * \~russian
		 * @brief Хеширование выбранным алгоритмом
		 *
		 * @details Держит по объекту каждого алгоритма и передаёт вызовы тому, который
		 *          выбран сбросом: ни виртуальности, ни выделений памяти. Договор
		 *          повторяет договор каждого хеша: update кусками, finish однократно,
		 *          reset для повторного хеширования
		 *
		 * \~english
		 * @brief Hashing by a chosen algorithm
		 * @details Holds an object of each algorithm and passes the calls to the one chosen by
		 *          the reset: neither virtuality nor memory allocations. The contract repeats the
		 *          contract of each hash: update by chunks, finish once, reset for a repeated hashing
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Hasher {
			private:
				// Выбранный алгоритм хеширования
				hash_t _type;
				// Признак порченой подачи: кусок задан длиной без места, хеш не снимается
				bool _spoiled;
			private:
				// Хеширование MD5
				md5_t _md5;
				// Хеширование SHA-1
				sha1_t _sha1;
				// Хеширование SHA-2
				sha2_t _sha2;
				// Хеширование «Стрибог»
				streebog_t _streebog;
				// Хеш BLAKE2 без ключа: ключевой режим потребитель берёт у blake2_t напрямую, HMAC идёт поверх
				blake2_t _blake2;
				// Хеширование SM3
				sm3_t _sm3;
				// Хеширование RIPEMD-160
				ripemd_t _ripemd;
			public:
				/**
				 * \~russian
				 * @brief Метод получения выбранного алгоритма хеширования
				 *
				 * @return выбранный алгоритм хеширования
				 *
				 * \~english
				 * @brief Method of getting the chosen hashing algorithm
				 * @return the chosen hashing algorithm
				 *
				 * \~
				 */
				hash_t type() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод сброса состояния хеширования
				 *
				 * @param algorithm алгоритм хеширования
				 *
				 * \~english
				 * @brief Method of the reset of the state of the hashing
				 * @param algorithm the hashing algorithm
				 *
				 * \~
				 */
				void reset(const hash_t algorithm) noexcept;
				/**
				 * \~russian
				 * @brief Метод подачи куска сообщения
				 *
				 * @param data подаваемый кусок сообщения
				 *
				 * \~english
				 * @brief Method of feeding a chunk of the message
				 * @param data the chunk of the message being fed
				 *
				 * \~
				 */
				void update(const view_t & data) noexcept;
				/**
				 * \~russian
				 * @brief Метод снятия выработанного хеша
				 *
				 * @param result место, в которое записывается хеш
				 * @param size   размер места в байтах, не меньше длины хеша
				 *
				 * @return       признак успешности снятия хеша
				 *
				 * \~english
				 * @brief Method of taking the produced hash
				 * @param result the place the hash is written into
				 * @param size   the size of the place in bytes, not less than the length of the hash
				 * @return       the flag of the success of the taking of the hash
				 *
				 * \~
				 */
				bool finish(uint8_t * result, const size_t size) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Конструктор
				 *
				 * @param algorithm алгоритм хеширования
				 *
				 * \~english
				 * @brief Constructor
				 * @param algorithm the hashing algorithm
				 *
				 * \~
				 */
				Hasher(const hash_t algorithm = hash_t::NONE) noexcept;
		} hasher_t;

		/**
		 * \~russian
		 * @brief Метод выработки хеша целого сообщения выбранным алгоритмом
		 *
		 * @param algorithm алгоритм хеширования
		 * @param data      хешируемое сообщение
		 * @param result    место, в которое записывается хеш
		 * @param size      размер места в байтах, не меньше длины хеша
		 *
		 * @return          признак успешности выработки хеша
		 *
		 * \~english
		 * @brief Method of the production of the hash of a whole message by a chosen algorithm
		 * @param algorithm the hashing algorithm
		 * @param data      the message being hashed
		 * @param result    the place the hash is written into
		 * @param size      the size of the place in bytes, not less than the length of the hash
		 * @return          the flag of the success of the production of the hash
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool hash(const hash_t algorithm, const view_t & data, uint8_t * result, const size_t size) noexcept;
	};
};

