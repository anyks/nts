/**
 * @file kuznyechik.hpp
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
 * @brief Заголовочный файл модуля блочного шифра «Кузнечик» — зашифрование и
 *        расшифрование блока длиной 128 разрядов по ГОСТ Р 34.12-2015
 *
 * \~english
 * @brief Header file of the «Kuznyechik» block cipher module — the encryption and
 *        the decryption of a block of a length of 128 bits according to GOST R 34.12-2015
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
	 * @details Шифры преобразуют единственный блок и режимами работы не занимаются:
	 *          режимы шифрования, выработки имитовставки и шифрования с проверкой
	 *          целостности лежат выше и от выбранного шифра не зависят.
	 *
	 * @note Внутри шифров нет ни исключений, ни шаблонов, ни виртуальности, ни
	 *       выделения памяти: всё это порождает ветвление либо переход по указателю
	 *       на пути, зависящем от секретного значения
	 *
	 * \~english
	 * @brief Namespace of the block encryption modules
	 * @details The ciphers transform a single block and do not deal with the modes of
	 *          operation: the modes of the encryption, of the production of an imitation
	 *          insert and of the encryption with an integrity check lie above and do not
	 *          depend on the chosen cipher.
	 * @note There are neither exceptions, nor templates, nor virtuality, nor memory
	 *       allocation inside the ciphers: all of this produces a branch or a jump by a
	 *       pointer on a path depending on a secret value
	 *
	 * \~
	 */
	namespace cipher {
		/**
		 * \~russian
		 * @brief Размер блока шифра «Кузнечик» в байтах
		 *
		 * \~english
		 * @brief Size of the block of the «Kuznyechik» cipher in bytes
		 *
		 * \~
		 */
		static constexpr size_t KUZNYECHIK_BLOCK = 16;

		/**
		 * \~russian
		 * @brief Размер ключа шифра «Кузнечик» в байтах
		 *
		 * \~english
		 * @brief Size of the key of the «Kuznyechik» cipher in bytes
		 *
		 * \~
		 */
		static constexpr size_t KUZNYECHIK_KEY = 32;

		/**
		 * \~russian
		 * @brief Блочный шифр «Кузнечик»
		 *
		 * @details Ключ устанавливается вызовом key, после чего блоки преобразуются
		 *          вызовами encrypt и decrypt. Развёрнутые раундовые ключи затираются
		 *          вызовом clear и деструктором.
		 *
		 * \~english
		 * @brief The «Kuznyechik» block cipher
		 * @details The key is set by a call of key, after which the blocks are transformed
		 *          by the calls of encrypt and decrypt. The expanded round keys are wiped
		 *          by a call of clear and by the destructor.
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Kuznyechik {
			private:
				// Признак того, что ключ установлен
				bool _ready;
			private:
				// Раундовые ключи
				uint8_t _keys[10][KUZNYECHIK_BLOCK];
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
				 * @brief Метод зашифрования нескольких независимых блоков разом
				 *
				 * @param sources зашифровываемые блоки подряд
				 * @param blocks  число блоков
				 * @param results место, в которое помещаются зашифрованные блоки подряд
				 *
				 * @return признак успешности зашифрования
				 *
				 * @note Блоки независимы, и шифр ведёт их по четыре в одном теле: чтения
				 *       таблиц разных блоков идут внахлёст, что даёт выигрыш на процессорах
				 *       с широкой командой либо глубоким конвейером. Место итога вправе
				 *       совпадать с местом исходных блоков
				 *
				 * \~english
				 * @brief Method of the encryption of several independent blocks at once
				 * @param sources the blocks being encrypted, one after another
				 * @param blocks  the number of the blocks
				 * @param results the place the encrypted blocks are put into, one after another
				 * @return the flag of the success of the encryption
				 * @note The blocks are independent and the cipher drives them four at a time in one
				 *       body: the table reads of different blocks overlap, which gives a gain on the
				 *       processors with a wide instruction or a deep pipeline. The place of the result
				 *       may coincide with the place of the source blocks
				 *
				 * \~
				 */
				bool batch(const uint8_t * sources, const size_t blocks, uint8_t * results) const noexcept;
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
				Kuznyechik() noexcept;
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
				~Kuznyechik() noexcept;
		} kuznyechik_t;
	};
};

