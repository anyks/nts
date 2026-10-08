/**
 * @file hmac.hpp
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
 * @brief Заголовочный файл модуля имитовставки HMAC и порождающей функции протокола
 *        TLS на хеше по ГОСТ Р 34.11-2012
 *
 * \~english
 * @brief Header file of the module of the HMAC authentication code and of the
 *        pseudorandom function of the TLS protocol on the hash according to GOST R 34.11-2012
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
#include <digest/streebog.hpp>
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
		 * @brief Метод выработки имитовставки HMAC
		 *
		 * @param type   длина хеша, на котором вырабатывается имитовставка
		 * @param key    ключ выработки имитовставки
		 * @param data   сообщение, на котором вырабатывается имитовставка
		 * @param result место, в которое помещается имитовставка
		 * @param size   требуемая длина имитовставки в байтах
		 *
		 * @return признак успешности выработки имитовставки
		 *
		 * @details Раздел 4.1 RFC 7836: построение HMAC взято из RFC 2104 без изменений,
		 *          длина блока сжатия у обеих длин хеша равна шестидесяти четырём байтам.
		 *
		 * @note Хеш здесь идёт строкой байтов, а не вектором: имитовставка есть величина
		 *       протокола, а не число криптографии
		 *
		 * \~english
		 * @brief Method of the production of an HMAC authentication code
		 * @param type   the length of the hash the authentication code is produced on
		 * @param key    the key of the production of the authentication code
		 * @param data   the message the authentication code is produced on
		 * @param result the place the authentication code is put into
		 * @param size   the required length of the authentication code in bytes
		 * @return the flag of the success of the production of the authentication code
		 * @details The section 4.1 of RFC 7836: the construction of HMAC is taken from RFC 2104
		 *          without changes, the length of the block of the compression at both lengths of
		 *          the hash equals sixty four bytes.
		 * @note The hash goes here as a string of bytes and not as a vector: an authentication code
		 *       is a value of a protocol and not a number of the cryptography
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool hmac(const type_t type, const view_t & key, const view_t & data, uint8_t * result, const size_t size) noexcept;
		/**
		 * \~russian
		 * @brief Метод выработки имитовставки HMAC выбранным алгоритмом хеширования
		 *
		 * @param algorithm алгоритм хеширования, на котором вырабатывается имитовставка
		 * @param key       ключ выработки имитовставки
		 * @param data      сообщение, на котором вырабатывается имитовставка
		 * @param result    место, в которое помещается имитовставка
		 * @param size      требуемая длина имитовставки в байтах, не больше длины хеша
		 *
		 * @return          признак успешности выработки имитовставки
		 *
		 * @details RFC 2104 над любым хешем библиотеки: ключ длиннее блока сжатия
		 *          хешируется, короче - дополняется нулями до блока; блок берётся у
		 *          алгоритма (64 байта, у SHA-384 и SHA-512 - 128)
		 *
		 * @note Имитовставка вправе быть короче хеша: усечение берёт старшие байты,
		 *       как велит раздел 5 RFC 2104
		 *
		 * \~english
		 * @brief Method of the production of an HMAC authentication code by a chosen hashing algorithm
		 * @param algorithm the hashing algorithm the authentication code is produced on
		 * @param key       the key of the production of the authentication code
		 * @param data      the message the authentication code is produced on
		 * @param result    the place the authentication code is put into
		 * @param size      the required length of the authentication code in bytes, not more than the length of the hash
		 * @return          the flag of the success of the production of the authentication code
		 * @details RFC 2104 over any hash of the library: a key longer than the compression block is
		 *          hashed, a shorter one is padded by zeros to the block; the block is taken from the
		 *          algorithm (64 bytes, at SHA-384 and SHA-512 - 128)
		 * @note The authentication code may be shorter than the hash: the truncation takes the senior
		 *       bytes, as the section 5 of RFC 2104 orders
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool hmac(const hash_t algorithm, const view_t & key, const view_t & data, uint8_t * result, const size_t size) noexcept;
		/**
		 * \~russian
		 * @brief Поточная выработка имитовставки HMAC выбранным алгоритмом хеширования
		 *
		 * @details Ключ задаётся вызовом start, сообщение подаётся кусками вызовами
		 *          update, имитовставка снимается вызовом finish. Повторная выработка
		 *          на том же ключе требует нового start: ключ хранится лишь в виде
		 *          внутреннего и внешнего заполнений и затирается вызовом clear и
		 *          деструктором
		 *
		 * \~english
		 * @brief Streaming production of an HMAC authentication code by a chosen hashing algorithm
		 * @details The key is set by a call of start, the message is fed by chunks by the calls of
		 *          update, the authentication code is taken by a call of finish. A repeated production
		 *          on the same key requires a new start: the key is kept only as the inner and the
		 *          outer paddings and is wiped by a call of clear and by the destructor
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Mac {
			private:
				// Признак того, что ключ установлен
				bool _ready;
			private:
				// Алгоритм хеширования
				hash_t _type;
				// Размер блока сжатия алгоритма
				size_t _width;
			private:
				// Внутреннее заполнение ключа
				uint8_t _inner[128];
				// Внешнее заполнение ключа
				uint8_t _outer[128];
			private:
				// Объект хеширования
				hasher_t _hasher;
			public:
				/**
				 * \~russian
				 * @brief Метод проверки готовности к выработке
				 *
				 * @return признак того, что ключ установлен
				 *
				 * \~english
				 * @brief Method of checking the readiness for the production
				 * @return the flag of the key being set
				 *
				 * \~
				 */
				bool ready() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки ключа и начала выработки
				 *
				 * @param algorithm алгоритм хеширования
				 * @param key       ключ выработки имитовставки, вправе быть пустым
				 *
				 * @return          признак успешности установки ключа
				 *
				 * \~english
				 * @brief Method of setting the key and of the start of the production
				 * @param algorithm the hashing algorithm
				 * @param key       the key of the production of the authentication code, may be empty
				 * @return          the flag of the success of the setting of the key
				 *
				 * \~
				 */
				bool start(const hash_t algorithm, const view_t & key) noexcept;
				/**
				 * \~russian
				 * @brief Метод повторного начала выработки на установленном ключе
				 *
				 * @return признак того, что ключ установлен
				 *
				 * \~english
				 * @brief Method of the repeated start of the production on the set key
				 * @return the flag of the key being set
				 *
				 * \~
				 */
				bool restart() noexcept;
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
				 * @brief Метод снятия имитовставки
				 *
				 * @param result место, в которое записывается имитовставка
				 * @param size   требуемая длина имитовставки, от одного байта до длины хеша
				 *
				 * @return       признак успешности снятия
				 *
				 * \~english
				 * @brief Method of taking the authentication code
				 * @param result the place the authentication code is written into
				 * @param size   the required length of the authentication code, from one byte to the length of the hash
				 * @return       the flag of the success of the taking
				 *
				 * \~
				 */
				bool finish(uint8_t * result, const size_t size) noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса ключа
				 *
				 * \~english
				 * @brief Method of the reset of the key
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Конструктор
				 *
				 * \~english
				 * @brief Constructor
				 *
				 * \~
				 */
				Mac() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Mac() noexcept;
		} mac_t;
		/**
		 * \~russian
		 * @brief Метод выработки порождающей последовательности протокола TLS
		 *
		 * @param type   длина хеша, на котором вырабатывается последовательность
		 * @param key    ключ выработки последовательности
		 * @param label  метка назначения последовательности
		 * @param seed   затравка выработки последовательности
		 * @param result место, в которое помещается выработанная последовательность
		 * @param size   требуемая длина последовательности в байтах
		 *
		 * @return признак успешности выработки последовательности
		 *
		 * @details Раздел 4.2.1 RFC 7836: та же функция P_hash, что и в разделе 5
		 *          RFC 5246, но на имитовставке HMAC с хешем по ГОСТ Р 34.11-2012.
		 *          Метка и затравка идут подряд одной строкой, а длина последовательности
		 *          ничем не ограничена
		 *
		 * \~english
		 * @brief Method of the production of a pseudorandom sequence of the TLS protocol
		 * @param type   the length of the hash the sequence is produced on
		 * @param key    the key of the production of the sequence
		 * @param label  the label of the purpose of the sequence
		 * @param seed   the seed of the production of the sequence
		 * @param result the place the produced sequence is put into
		 * @param size   the required length of the sequence in bytes
		 * @return the flag of the success of the production of the sequence
		 * @details The section 4.2.1 of RFC 7836: the same P_hash function as in the section 5 of
		 *          RFC 5246, but on the HMAC authentication code with a hash according to
		 *          GOST R 34.11-2012. The label and the seed go in a row as a single string, while
		 *          the length of the sequence is not limited by anything
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool prf(const type_t type, const view_t & key, const view_t & label, const view_t & seed, uint8_t * result, const size_t size) noexcept;
		/**
		 * \~russian
		 * @brief Метод выработки порождающей последовательности протокола TLS 1.2 выбранным хешем
		 *
		 * @param algorithm хеш, на имитовставке которого вырабатывается последовательность
		 * @param key       ключ выработки последовательности
		 * @param label     метка назначения последовательности
		 * @param seed      затравка выработки последовательности
		 * @param result    место, в которое помещается выработанная последовательность
		 * @param size      требуемая длина последовательности в байтах
		 *
		 * @return          признак успешности выработки последовательности
		 *
		 * @details Раздел 5 RFC 5246: PRF(secret, label, seed) = P_hash(secret, label + seed), где
		 *          P_hash идёт на HMAC с хешем набора шифрования (SHA-256 у наборов с SHA-256 в
		 *          имени, SHA-384 у наборов с SHA-384). Хеши «Стрибог» ведёт метод с длиной хеша
		 *
		 * \~english
		 * @brief Method of the production of a pseudorandom sequence of the TLS 1.2 protocol by the chosen hash
		 * @param algorithm the hash on the HMAC of which the sequence is produced
		 * @param key       the key of the production of the sequence
		 * @param label     the label of the purpose of the sequence
		 * @param seed      the seed of the production of the sequence
		 * @param result    the place the produced sequence is put into
		 * @param size      the required length of the sequence in bytes
		 * @return          the flag of the success of the production of the sequence
		 * @details The section 5 of RFC 5246: PRF(secret, label, seed) = P_hash(secret, label + seed), where
		 *          P_hash goes on HMAC with the hash of the cipher suite (SHA-256 at the suites with SHA-256
		 *          in the name, SHA-384 at the suites with SHA-384). The «Streebog» hashes are conducted by
		 *          the method with the length of the hash
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool prf(const hash_t algorithm, const view_t & key, const view_t & label, const view_t & seed, uint8_t * result, const size_t size) noexcept;
		/**
		 * \~russian
		 * @brief Метод выработки псевдослучайной последовательности PRF изданий TLS 1.0 и 1.1
		 *
		 * @param key    секрет, делимый пополам между P_MD5 и P_SHA1 (при нечётной длине середина в обеих половинах)
		 * @param label  метка выработки
		 * @param seed   семя выработки
		 * @param result место, в которое помещается последовательность
		 * @param size   длина последовательности в байтах
		 *
		 * @return       признак успешности выработки
		 *
		 * @details Раздел 5 RFC 4346: `P_MD5(S1, label ‖ seed) ⊕ P_SHA1(S2, label ‖ seed)`;
		 *          нужна изданию DTLS 1.0 (RFC 4347 поверх TLS 1.1) и только ему - MD5 здесь
		 *          требование издания, а не выбор
		 *
		 * \~english
		 * @brief Method of the production of the pseudo-random sequence PRF of the TLS 1.0 and 1.1 editions
		 * @param key    the secret divided in halves between P_MD5 and P_SHA1 (at an odd length the middle is in both halves)
		 * @param label  the label of the production
		 * @param seed   the seed of the production
		 * @param result the place the sequence is put into
		 * @param size   the length of the sequence in bytes
		 * @return       the flag of the success of the production
		 * @details The section 5 of RFC 4346: `P_MD5(S1, label ‖ seed) ⊕ P_SHA1(S2, label ‖ seed)`;
		 *          needed by the DTLS 1.0 edition (RFC 4347 over TLS 1.1) and by it alone - MD5 here
		 *          is a requirement of the edition, not a choice
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool legacy(const view_t & key, const view_t & label, const view_t & seed, uint8_t * result, const size_t size) noexcept;
	};
};

