/**
 * @file aes.hpp
 * @date 2026-09-09
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
 * @brief Заголовочный файл модуля блочного шифра AES — преобразование блока в 128
 *        разрядов ключом в 128, 192 либо 256 разрядов по FIPS 197
 *
 * \~english
 * @brief Header file of the AES block cipher module — the transformation of a 128-bit block
 *        by a key of 128, 192 or 256 bits according to FIPS 197
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_AES__
#define __ANTS_AES__

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
		 * @brief Размер блока шифра AES в байтах
		 *
		 * \~english
		 * @brief Size of the block of the AES cipher in bytes
		 *
		 * \~
		 */
		static constexpr size_t AES_BLOCK = 16;

		/**
		 * \~russian
		 * @brief Наибольший размер ключа шифра AES в байтах
		 *
		 * @details Ключ бывает в 16, 24 либо 32 байта; число раундов - 10, 12 либо 14
		 *
		 * \~english
		 * @brief Largest size of the key of the AES cipher in bytes
		 * @details The key is of 16, 24 or 32 bytes; the number of the rounds is 10, 12 or 14
		 *
		 * \~
		 */
		static constexpr size_t AES_KEY = 32;

		/**
		 * \~russian
		 * @brief Блочный шифр AES
		 *
		 * @details Ключ устанавливается вызовом key, после чего блоки преобразуются
		 *          вызовами encrypt и decrypt. Развёрнутые раундовые ключи затираются
		 *          вызовом clear и деструктором. Таблицы преобразования вычисляются
		 *          при сборке из поля Галуа, а не переписываются из стандарта.
		 *
		 * @note Ход по таблицам зависит от данных обращениями к памяти: это свойство
		 *       переносимой реализации, ветвь на машинных командах AES его лишена
		 *
		 * \~english
		 * @brief The AES block cipher
		 * @details The key is set by a call of key, after which the blocks are transformed
		 *          by the calls of encrypt and decrypt. The expanded round keys are wiped
		 *          by a call of clear and by the destructor. The tables of the transformation
		 *          are computed at the build from the Galois field and not copied from the standard.
		 * @note The course over the tables depends on the data by the memory accesses: it is a
		 *       property of the portable implementation, the branch on the AES machine instructions
		 *       is free of it
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Aes {
			private:
				// Признак того, что ключ установлен
				bool _ready;
			private:
				// Число раундов по длине ключа
				size_t _rounds;
			private:
				// Раундовые ключи зашифрования: до пятнадцати по четыре слова
				uint32_t _encryption[60];
				// Раундовые ключи расшифрования
				uint32_t _decryption[60];
			private:
				// Раундовые ключи зашифрования байтами в порядке памяти: для машинных команд
				uint8_t _sealing[240];
				// Раундовые ключи расшифрования байтами в порядке памяти: для машинных команд
				uint8_t _opening[240];
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
				/**
				 * \~russian
				 * @brief Метод выработки гаммы счётчика
				 *
				 * @param counter начальный блок счётчика: младшие 32 разряда растут от старшего байта
				 * @param blocks  число блоков гаммы
				 * @param result  место, в которое записывается гамма: 16 байтов на блок
				 *
				 * @return        признак успешности выработки
				 *
				 * @details Первый блок гаммы - зашифрованный счётчик, увеличенный на единицу;
				 *          так устроен счётчик GCM. Командами машины блоки шифруются по
				 *          четыре разом с ключами в регистрах: в этом и выигрыш против
				 *          поблочного вызова
				 *
				 * \~english
				 * @brief Method of the production of the counter gamma
				 * @param counter the initial counter block: the low 32 bits grow from the senior byte
				 * @param blocks  the number of the gamma blocks
				 * @param result  the place the gamma is written into: 16 bytes per block
				 * @return        the flag of the success of the production
				 * @details The first block of the gamma is the encrypted counter increased by one; so is
				 *          the GCM counter arranged. By the machine instructions the blocks are encrypted
				 *          four at once with the keys in the registers: that is the gain against the
				 *          per-block call
				 *
				 * \~
				 */
				bool stream(const uint8_t * counter, const size_t blocks, uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения расписания ключа зашифрования для слитых ядер режимов
				 *
				 * @return расписание ключа: ключей на один больше числа кругов, по шестнадцать байтов; пусто без ключа либо без команд машины
				 *
				 * @note Расписание принадлежит шифру и живёт, пока жив он: режимы лишь читают его в
				 *       своих ядрах, где гамма счётчика и хеш идут одним проходом
				 *
				 * \~english
				 * @brief Method of getting the encryption key schedule for the fused kernels of the modes
				 * @return the key schedule: one key more than the rounds, sixteen bytes each; empty without a key or without the machine instructions
				 * @note The schedule belongs to the cipher and lives as long as it does: the modes only read
				 *       it in their kernels, where the counter gamma and the hash go in one pass
				 *
				 * \~
				 */
				const uint8_t * schedule() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения числа кругов шифра
				 *
				 * @return число кругов: 10, 12 либо 14 по длине ключа, ноль без ключа
				 *
				 * \~english
				 * @brief Method of getting the number of the rounds of the cipher
				 * @return the number of the rounds: 10, 12 or 14 by the length of the key, zero without a key
				 *
				 * \~
				 */
				size_t rounds() const noexcept;
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
				Aes() noexcept;
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
				~Aes() noexcept;
		} aes_t;
	};
};

#endif // __ANTS_AES__
