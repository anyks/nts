/**
 * @file des.hpp
 * @date 2026-10-10
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
 * @brief Модуль блочного шифра DES и 3DES (FIPS 46-3)
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
		 * @brief Размер блока DES в байтах
		 *
		 * \~english
		 * @brief Size of the block of the DES cipher in bytes
		 *
		 * \~
		 */
		static constexpr size_t DES_BLOCK = 8;
		/**
		 * \~russian
		 * @brief Длина ключа DES в байтах
		 *
		 * \~english
		 * @brief Length of the DES key in bytes
		 *
		 * \~
		 */
		static constexpr size_t DES_KEY = 8;
		/**
		 * \~russian
		 * @brief Длина ключа 3DES в байтах (три ключа DES)
		 *
		 * \~english
		 * @brief Length of the 3DES key in bytes (three DES keys)
		 *
		 * \~
		 */
		static constexpr size_t DES3_KEY = 24;
		/**
		 * \~russian
		 * @brief Блочный шифр DES и 3DES
		 * @details Ключ устанавливается вызовом key, после чего блоки преобразуются
		 *          вызовами encrypt и decrypt: у одиночного DES ключ в восемь байтов,
		 *          у 3DES - в двадцать четыре (три ключа DES, шифрование идёт чередом
		 *          зашифрования-расшифрования-зашифрования, EDE). Раундовые ключи
		 *          затираются вызовом clear и деструктором. Шифр устарел и слаб: он
		 *          здесь лишь для связи с устаревшими собеседниками (3des-cbc у SSH)
		 *          и выключен по умолчанию там, где выбираются наборы
		 *
		 * \~english
		 * @brief The DES and 3DES block cipher
		 * @details The key is set by a call of key, after which the blocks are
		 *          transformed by the calls of encrypt and decrypt: the single DES
		 *          takes a key of eight bytes, 3DES takes twenty four (three DES keys,
		 *          the encryption goes by the alternation of encryption-decryption-
		 *          encryption, EDE). The round keys are wiped by a call of clear and
		 *          by the destructor. The cipher is obsolete and weak: it is here only
		 *          for the intercourse with obsolete interlocutors (3des-cbc of SSH)
		 *          and is off by default where the suites are chosen
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Des {
			private:
				// Признак того, что ключ установлен
				bool _ready;
			private:
				// Число ключей DES: один у DES, три у 3DES
				size_t _keys;
				// Раундовые ключи: по шестнадцать на ключ DES, до трёх ключей
				uint64_t _rounds[3][16];
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
				 * @details Ключ в восемь байтов задаёт одиночный DES, в двадцать
				 *          четыре - 3DES; разряды чётности байтов ключа не сверяются
				 *          и в расписание не входят
				 *
				 * @param key устанавливаемый ключ шифрования (8 или 24 байта)
				 *
				 * @return признак успешности установки ключа
				 *
				 * \~english
				 * @brief Method of setting the encryption key
				 *
				 * @details A key of eight bytes sets the single DES, of twenty four -
				 *          3DES; the parity bits of the key bytes are not checked and
				 *          do not enter the schedule
				 *
				 * @param key the encryption key being set (8 or 24 bytes)
				 *
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
				 * @param source зашифровываемый блок (восемь байтов)
				 * @param result место, в которое помещается зашифрованный блок
				 *
				 * @return признак успешности зашифрования
				 *
				 * @note Место итога вправе совпадать с местом исходного блока
				 *
				 * \~english
				 * @brief Method of the encryption of a block
				 * @param source the block being encrypted (eight bytes)
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
				 * @param source расшифровываемый блок (восемь байтов)
				 * @param result место, в которое помещается расшифрованный блок
				 *
				 * @return признак успешности расшифрования
				 *
				 * @note Место итога вправе совпадать с местом исходного блока
				 *
				 * \~english
				 * @brief Method of the decryption of a block
				 * @param source the block being decrypted (eight bytes)
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
				 * \~english
				 * @brief Constructor
				 *
				 * \~
				 */
				Des() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Des() noexcept;
		} des_t;
	};
};
