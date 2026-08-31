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
#ifndef __ANTS_HMAC__
#define __ANTS_HMAC__

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
	};
};

#endif // __ANTS_HMAC__
