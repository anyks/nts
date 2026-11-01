/**
 * @file cipher.hpp
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
 * @brief Модуль состояния шифра Noise (CipherState, §5.1)
 *
 * \~english
 * @brief Module of the cipher state of Noise (CipherState, §5.1)
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
#include <cipher/aes.hpp>
#include <noise/noise.hpp>

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
	 * @brief Пространство имён каркаса Noise
	 *
	 * \~english
	 * @brief Namespace of the Noise framework
	 *
	 * \~
	 */
	namespace noise {
		/**
		 * \~russian
		 * @brief Класс состояния шифра: ключ и счётчик вложений
		 *
		 * @details Намеренные решения:
		 *          1. Счётчик 64-разрядный, значение 2^64-1 запретно: отказ и на шифровании, и
		 *             на расшифровании, до какого-либо действия; по кругу счётчик не идёт.
		 *          2. При несошедшейся метке счётчик не растёт.
		 *          3. Перевыработка ключа (rekey) вынесена наружу и внутри не зовётся никогда;
		 *             счётчик она не сбрасывает - сбросом ведает потребитель.
		 *          4. Сырой доступ с явным счётчиком (WireGuard: свой счётчик и окно повтора)
		 *             внутреннего счётчика не трогает.
		 *
		 * \~english
		 * @brief Class of the cipher state: a key and a nonce counter
		 *
		 * @details Deliberate decisions:
		 *          1. The counter is 64-bit, the value 2^64-1 is forbidden: a refusal both on
		 *             encryption and on decryption, before any action; the counter never wraps.
		 *          2. On a mismatched tag the counter does not grow.
		 *          3. Rekey is exposed and is never called inside; it does not reset the
		 *             counter - the consumer does.
		 *          4. Raw access with an explicit counter (WireGuard: own counter and replay
		 *             window) does not touch the inner counter.
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Cipher {
			private:
				// Функция шифрования с подлинностью
				aead_t _aead;
				// Признак установленного ключа
				bool _has;
				// Счётчик вложений
				uint64_t _nonce;
				// Ключ шифра
				uint8_t _key[KEY];
				// Объект AES с развёрнутым ключом
				cipher::aes_t _aes;
			private:
				/**
				 * \~russian
				 * @brief Метод шифрования с явным счётчиком
				 *
				 * @param nonce      счётчик вложений
				 * @param associated сопутствующие данные
				 * @param source     открытые данные
				 * @param result     место шифротекста
				 * @param tag        место метки в TAG байтов
				 * @return           признак того, что данные зашифрованы
				 *
				 * \~english
				 * @brief Method of the encryption with an explicit counter
				 *
				 * @param nonce      the nonce counter
				 * @param associated the associated data
				 * @param source     the plain data
				 * @param result     the place of the ciphertext
				 * @param tag        the place of the tag in TAG bytes
				 * @return           the flag of the data being encrypted
				 *
				 * \~
				 */
				bool seal(const uint64_t nonce, const view_t & associated, const view_t & source, uint8_t * result, uint8_t * tag) const noexcept;
				/**
				 * \~russian
				 * @brief Метод расшифрования с явным счётчиком
				 *
				 * @param nonce      счётчик вложений
				 * @param associated сопутствующие данные
				 * @param source     шифротекст
				 * @param tag        метка в TAG байтов
				 * @param result     место открытых данных
				 * @return           признак того, что данные подлинны и расшифрованы
				 *
				 * \~english
				 * @brief Method of the decryption with an explicit counter
				 *
				 * @param nonce      the nonce counter
				 * @param associated the associated data
				 * @param source     the ciphertext
				 * @param tag        the tag in TAG bytes
				 * @param result     the place of the plain data
				 * @return           the flag of the data being authentic and decrypted
				 *
				 * \~
				 */
				bool open(const uint64_t nonce, const view_t & associated, const view_t & source, const view_t & tag, uint8_t * result) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод установки функции шифрования
				 *
				 * @param aead функция шифрования с подлинностью
				 * @return     признак того, что функция поддержана
				 *
				 * \~english
				 * @brief Method of setting the encryption function
				 *
				 * @param aead authenticated encryption function
				 * @return     sign that the function is supported
				 *
				 * \~
				 */
				bool start(const aead_t aead) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки ключа (InitializeKey): счётчик обнуляется
				 *
				 * @param key ключ в KEY байтов
				 * @return    признак того, что ключ установлен
				 *
				 * \~english
				 * @brief Method of setting the key (InitializeKey): the counter is zeroed
				 *
				 * @param key key of KEY bytes
				 * @return    sign that the key is set
				 *
				 * \~
				 */
				bool key(const view_t & key) noexcept;
				/**
				 * \~russian
				 * @brief Метод выдачи ключа наружу (для таблиц пар WireGuard)
				 *
				 * @param result место ключа в KEY байтов
				 * @return       признак того, что ключ есть и выдан
				 *
				 * \~english
				 * @brief Method of giving the key out (for WireGuard peer tables)
				 *
				 * @param result place of the key of KEY bytes
				 * @return       sign that the key exists and is given
				 *
				 * \~
				 */
				bool key(uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки наличия ключа (HasKey)
				 *
				 * @return признак того, что ключ установлен
				 *
				 * \~english
				 * @brief Method of the key presence check (HasKey)
				 *
				 * @return sign that the key is set
				 *
				 * \~
				 */
				bool has() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения счётчика вложений
				 *
				 * @return счётчик вложений
				 *
				 * \~english
				 * @brief Method of getting the nonce counter
				 *
				 * @return nonce counter
				 *
				 * \~
				 */
				uint64_t nonce() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки счётчика вложений (SetNonce)
				 *
				 * @param nonce счётчик вложений, 2^64-1 запретно
				 * @return      признак того, что счётчик установлен
				 *
				 * \~english
				 * @brief Method of setting the nonce counter (SetNonce)
				 *
				 * @param nonce nonce counter, 2^64-1 is forbidden
				 * @return      sign that the counter is set
				 *
				 * \~
				 */
				bool nonce(const uint64_t nonce) noexcept;
				/**
				 * \~russian
				 * @brief Метод шифрования по счётчику (EncryptWithAd): счётчик растёт на единицу
				 *
				 * @param associated сопутствующие данные
				 * @param source     открытые данные, не длиннее MESSAGE - TAG
				 * @param result     место шифротекста той же длины
				 * @param tag        место метки в TAG байтов
				 * @return           признак того, что данные зашифрованы
				 *
				 * \~english
				 * @brief Method of encryption by the counter (EncryptWithAd): the counter grows by one
				 *
				 * @param associated associated data
				 * @param source     plaintext, not longer than MESSAGE - TAG
				 * @param result     place of the ciphertext of the same length
				 * @param tag        place of the tag of TAG bytes
				 * @return           sign that the data is encrypted
				 *
				 * \~
				 */
				bool encrypt(const view_t & associated, const view_t & source, uint8_t * result, uint8_t * tag) noexcept;
				/**
				 * \~russian
				 * @brief Метод расшифрования по счётчику (DecryptWithAd): счётчик растёт только при подлинности
				 *
				 * @param associated сопутствующие данные
				 * @param source     шифротекст, не длиннее MESSAGE - TAG
				 * @param tag        метка в TAG байтов
				 * @param result     место открытых данных той же длины
				 * @return           признак того, что данные подлинны и расшифрованы
				 *
				 * \~english
				 * @brief Method of decryption by the counter (DecryptWithAd): the counter grows only on authenticity
				 *
				 * @param associated associated data
				 * @param source     ciphertext, not longer than MESSAGE - TAG
				 * @param tag        tag of TAG bytes
				 * @param result     place of the plaintext of the same length
				 * @return           sign that the data is authentic and decrypted
				 *
				 * \~
				 */
				bool decrypt(const view_t & associated, const view_t & source, const view_t & tag, uint8_t * result) noexcept;
				/**
				 * \~russian
				 * @brief Метод шифрования с явным счётчиком: внутренний счётчик не трогается
				 *
				 * @param nonce      счётчик вложений, 2^64-1 запретно
				 * @param associated сопутствующие данные
				 * @param source     открытые данные
				 * @param result     место шифротекста
				 * @param tag        место метки в TAG байтов
				 * @return           признак того, что данные зашифрованы
				 *
				 * \~english
				 * @brief Method of encryption with an explicit counter: the inner counter is untouched
				 *
				 * @param nonce      nonce counter, 2^64-1 is forbidden
				 * @param associated associated data
				 * @param source     plaintext
				 * @param result     place of the ciphertext
				 * @param tag        place of the tag of TAG bytes
				 * @return           sign that the data is encrypted
				 *
				 * \~
				 */
				bool encrypt(const uint64_t nonce, const view_t & associated, const view_t & source, uint8_t * result, uint8_t * tag) const noexcept;
				/**
				 * \~russian
				 * @brief Метод расшифрования с явным счётчиком: внутренний счётчик не трогается
				 *
				 * @param nonce      счётчик вложений, 2^64-1 запретно
				 * @param associated сопутствующие данные
				 * @param source     шифротекст
				 * @param tag        метка в TAG байтов
				 * @param result     место открытых данных
				 * @return           признак того, что данные подлинны и расшифрованы
				 *
				 * \~english
				 * @brief Method of decryption with an explicit counter: the inner counter is untouched
				 *
				 * @param nonce      nonce counter, 2^64-1 is forbidden
				 * @param associated associated data
				 * @param source     ciphertext
				 * @param tag        tag of TAG bytes
				 * @param result     place of the plaintext
				 * @return           sign that the data is authentic and decrypted
				 *
				 * \~
				 */
				bool decrypt(const uint64_t nonce, const view_t & associated, const view_t & source, const view_t & tag, uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод перевыработки ключа (Rekey): k = ENCRYPT(k, 2^64-1, пусто, нули); счётчик не сбрасывается
				 *
				 * @return признак того, что ключ перевыработан
				 *
				 * \~english
				 * @brief Method of the key renewal (Rekey): k = ENCRYPT(k, 2^64-1, empty, zeros); the counter is not reset
				 *
				 * @return sign that the key is renewed
				 *
				 * \~
				 */
				bool rekey() noexcept;
				/**
				 * \~russian
				 * @brief Метод затирания состояния
				 *
				 * \~english
				 * @brief Method of wiping the state
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
				Cipher() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Cipher() noexcept;
		} cipher_t;
	};
};

