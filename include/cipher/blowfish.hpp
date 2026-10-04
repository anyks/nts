/**
 * @file blowfish.hpp
 * @date 2026-10-04
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
 * @brief Заголовочный файл модуля блочного шифра Blowfish
 *
 * \~english
 * @brief Header file of the module of the Blowfish block cipher
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_BLOWFISH__
#define __ANTS_BLOWFISH__

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
	 * @brief Пространство имён модулей шифрования
	 *
	 * \~english
	 * @brief Namespace of the encryption modules
	 *
	 * \~
	 */
	namespace cipher {
		/**
		 * \~russian
		 * @brief Контекст Blowfish: P-array из 18 слов и четыре S-box по 256 слов
		 *
		 * \~english
		 * @brief Blowfish context: P-array of 18 words and four S-boxes of 256 words
		 *
		 * \~
		 */
		typedef struct Blowfish {
			// P-array
			uint32_t P[18];
			// S-boxes
			uint32_t S[4][256];
		} blowfish_t;

		/**
		 * \~russian
		 * @brief Метод инициализации контекста константами числа π
		 *
		 * @param ctx контекст Blowfish
		 *
		 * \~english
		 * @brief Method of the initialization of the context with the digits of Pi
		 *
		 * @param ctx Blowfish context
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ void init(blowfish_t * ctx) noexcept;
		/**
		 * \~russian
		 * @brief Метод расширения ключа без соли (eksblowfish phase 0)
		 *
		 * @param ctx     контекст Blowfish
		 * @param key     ключ
		 * @param keylen  длина ключа в байтах
		 *
		 * \~english
		 * @brief Method of the key expansion without salt (eksblowfish phase 0)
		 *
		 * @param ctx     Blowfish context
		 * @param key     key
		 * @param keylen  length of the key in bytes
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ void expand0(blowfish_t * ctx, const uint8_t * key, const size_t keylen) noexcept;
		/**
		 * \~russian
		 * @brief Метод расширения ключа с солью (eksblowfish phase 1)
		 *
		 * @param ctx     контекст Blowfish
		 * @param data    соль
		 * @param datalen длина соли в байтах
		 * @param key     ключ
		 * @param keylen  длина ключа в байтах
		 *
		 * \~english
		 * @brief Method of the key expansion with salt (eksblowfish phase 1)
		 *
		 * @param ctx     Blowfish context
		 * @param data    salt
		 * @param datalen length of the salt in bytes
		 * @param key     key
		 * @param keylen  length of the key in bytes
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ void expand(blowfish_t * ctx, const uint8_t * data, const size_t datalen, const uint8_t * key, const size_t keylen) noexcept;
		/**
		 * \~russian
		 * @brief Метод шифрования блока
		 *
		 * @param ctx контекст Blowfish
		 * @param xl  левая половина блока
		 * @param xr  правая половина блока
		 *
		 * \~english
		 * @brief Method of the encryption of a block
		 *
		 * @param ctx Blowfish context
		 * @param xl  left half of the block
		 * @param xr  right half of the block
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ void encipher(const blowfish_t * ctx, uint32_t * xl, uint32_t * xr) noexcept;
		/**
		 * \~russian
		 * @brief Метод шифрования нескольких блоков
		 *
		 * @param ctx    контекст Blowfish
		 * @param data   данные (массив uint32)
		 * @param blocks число блоков по 8 байтов
		 *
		 * \~english
		 * @brief Method of the encryption of several blocks
		 *
		 * @param ctx    Blowfish context
		 * @param data   data (array of uint32)
		 * @param blocks number of 8-byte blocks
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ void encrypt(const blowfish_t * ctx, uint32_t * data, const size_t blocks) noexcept;
		/**
		 * \~russian
		 * @brief Метод извлечения слова из потока байтов с зацикливанием
		 *
		 * @param data    поток байтов
		 * @param datalen длина потока
		 * @param current текущая позиция (обновляется)
		 *
		 * @return        слово uint32
		 *
		 * \~english
		 * @brief Method of the extraction of a word from a byte stream with wraparound
		 *
		 * @param data    byte stream
		 * @param datalen length of the stream
		 * @param current current position (updated)
		 *
		 * @return        uint32 word
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ uint32_t stream2word(const uint8_t * data, const size_t datalen, size_t * current) noexcept;
	};
};

#endif // __ANTS_BLOWFISH__
