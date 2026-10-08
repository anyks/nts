/**
 * @file sm4.hpp
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
 * @brief Заголовочный файл модуля блочного шифра SM4 — зашифрование и
 *        расшифрование блока длиной 128 разрядов по GB/T 32907-2016
 *
 * \~english
 * @brief Header file of the SM4 block cipher module — the encryption and
 *        the decryption of a block of a length of 128 bits according to GB/T 32907-2016
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
	 * @brief Пространство имён модулей блочного шифрования
	 *
	 * \~english
	 * @brief Namespace of the block encryption modules
	 *
	 * \~
	 */
	namespace cipher {
		/**
		 * \~russian
		 * @brief Размер блока шифра SM4 в байтах
		 *
		 * \~english
		 * @brief Size of the block of the SM4 cipher in bytes
		 *
		 * \~
		 */
		static constexpr size_t SM4_BLOCK = 16;

		/**
		 * \~russian
		 * @brief Размер ключа шифра SM4 в байтах
		 *
		 * \~english
		 * @brief Size of the key of the SM4 cipher in bytes
		 *
		 * \~
		 */
		static constexpr size_t SM4_KEY = 16;

		/**
		 * \~russian
		 * @brief Блочный шифр SM4
		 *
		 * @details Ключ устанавливается вызовом key, после чего блоки преобразуются
		 *          вызовами encrypt и decrypt. Развёрнутые раундовые ключи затираются
		 *          вызовом clear и деструктором.
		 *
		 * @note SM4 - национальный блочный шифр КНР: блок и ключ по 128 разрядов, 32
		 *       круга; в TLS входит наборами TLS_SM4_GCM_SM3 и TLS_SM4_CCM_SM3 по
		 *       RFC 8998
		 *
		 * \~english
		 * @brief The SM4 block cipher
		 * @details The key is set by a call of key, after which the blocks are transformed
		 *          by the calls of encrypt and decrypt. The expanded round keys are wiped
		 *          by a call of clear and by the destructor.
		 * @note SM4 is the national block cipher of the PRC: a block and a key of 128 bits
		 *       each, 32 rounds; it enters TLS by the suites TLS_SM4_GCM_SM3 and
		 *       TLS_SM4_CCM_SM3 according to RFC 8998
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Sm4 {
			private:
				// Признак того, что ключ установлен
				bool _ready;
			private:
				// Раундовые ключи
				uint32_t _keys[32];
			public:
				/**
				 * \~russian
				 * @brief Метод проверки готовности шифра к работе
				 *
				 * @return признак того, что ключ установлен
				 *
				 * \~english
				 * @brief Method of checking the readiness of the cipher for the work
				 * @return the flag of the key being set
				 *
				 * \~
				 */
				bool ready() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки ключа шифрования
				 *
				 * @param key устанавливаемый ключ шифрования
				 *
				 * @return признак успешности установки ключа
				 *
				 * \~english
				 * @brief Method of setting the encryption key
				 * @param key the encryption key being set
				 * @return the flag of the success of the setting of the key
				 *
				 * \~
				 */
				bool key(const view_t & key) noexcept;
				/**
				 * \~russian
				 * @brief Метод затирания раундовых ключей
				 *
				 * \~english
				 * @brief Method of wiping the round keys
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод зашифрования блока
				 *
				 * @param source зашифровываемый блок
				 * @param result место, в которое помещается зашифрованный блок
				 *
				 * @return признак успешности зашифрования
				 *
				 * @note Место итога вправе совпадать с местом исходного блока
				 *
				 * \~english
				 * @brief Method of the encryption of a block
				 * @param source the block being encrypted
				 * @param result the place the encrypted block is put into
				 * @return the flag of the success of the encryption
				 * @note The place of the result may coincide with the place of the source block
				 *
				 * \~
				 */
				bool encrypt(const uint8_t * source, uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод расшифрования блока
				 *
				 * @param source расшифровываемый блок
				 * @param result место, в которое помещается расшифрованный блок
				 *
				 * @return признак успешности расшифрования
				 *
				 * @note Место итога вправе совпадать с местом исходного блока
				 *
				 * \~english
				 * @brief Method of the decryption of a block
				 * @param source the block being decrypted
				 * @param result the place the decrypted block is put into
				 * @return the flag of the success of the decryption
				 * @note The place of the result may coincide with the place of the source block
				 *
				 * \~
				 */
				bool decrypt(const uint8_t * source, uint8_t * result) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Конструктор
				 *
				 *
				 * \~english
				 * @brief Constructor
				 *
				 * \~
				 */
				Sm4() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Sm4() noexcept;
		} sm4_t;
	};
};

