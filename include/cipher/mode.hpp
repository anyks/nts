/**
 * @file mode.hpp
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
 * @brief Заголовочный файл модуля режимов работы блочных шифров по
 *        ГОСТ Р 34.13-2015
 *
 * \~english
 * @brief Header file of the module of the modes of operation of the block ciphers
 *        according to GOST R 34.13-2015
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_MODE__
#define __ANTS_MODE__

/**
 * Стандартные заголовочные файлы
 */
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <cipher/magma.hpp>
#include <cipher/kuznyechik.hpp>
#include <cipher/aes.hpp>

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
		 * @brief Наибольший размер блока поддерживаемых шифров в байтах
		 *
		 * \~english
		 * @brief Greatest size of the block of the supported ciphers in bytes
		 *
		 * \~
		 */
		static constexpr size_t MODE_BLOCK = 16;

		/**
		 * \~russian
		 * @brief Наибольший размер регистра сдвига в байтах
		 *
		 * @details Величина m стандартом сверху не ограничена, но память режимы не
		 *          выделяют, оттого регистр отведён восемью блоками наибольшего шифра
		 *
		 * \~english
		 * @brief Greatest size of the shift register in bytes
		 * @details The value of m is not limited from above by the standard, but the modes
		 *          do not allocate memory, therefore the register is given eight blocks of
		 *          the greatest cipher
		 *
		 * \~
		 */
		static constexpr size_t MODE_REGISTER = (MODE_BLOCK * 8);

		/**
		 * \~russian
		 * @brief Базовый алгоритм блочного шифрования
		 *
		 * @details Режимы от выбранного шифра не зависят и обращаются к нему через
		 *          этот набор указателей. Виртуальность не применяется намеренно:
		 *          переход по указателю здесь один и от секретного значения не зависит,
		 *          а таблица виртуальных методов тянула бы за собой ещё и приведение
		 *          типов на пути шифрования.
		 *
		 * @note Объект шифра должен пережить всякий режим, которому он передан
		 *
		 * \~english
		 * @brief Base block encryption algorithm
		 * @details The modes do not depend on the chosen cipher and address it through
		 *          this set of pointers. The virtuality is not applied deliberately: the
		 *          jump by a pointer here is a single one and does not depend on a secret
		 *          value, while a table of the virtual methods would drag along a cast of
		 *          the types on the path of the encryption as well.
		 * @note The object of the cipher must outlive every mode it is passed to
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Block {
			// Размер блока базового алгоритма блочного шифрования
			size_t size;
			// Объект базового алгоритма блочного шифрования
			const void * cipher;
			// Функция зашифрования блока базовым алгоритмом блочного шифрования
			bool (* encrypt)(const void * cipher, const uint8_t * source, uint8_t * result) noexcept;
			// Функция расшифрования блока базовым алгоритмом блочного шифрования
			bool (* decrypt)(const void * cipher, const uint8_t * source, uint8_t * result) noexcept;
			// Функция выработки гаммы счётчика по многу блоков разом: у шифров без неё пуста
			bool (* stream)(const void * cipher, const uint8_t * counter, const size_t blocks, uint8_t * result) noexcept;
			// Функция зашифрования нескольких независимых блоков разом: у шифров без неё пуста
			bool (* batch)(const void * cipher, const uint8_t * sources, const size_t blocks, uint8_t * results) noexcept;
			// Расписание ключа зашифрования AES для слитых ядер режимов: у прочих шифров и без команд машины пусто
			const uint8_t * schedule;
			// Число кругов AES при заданном расписании
			size_t rounds;
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
			Block() noexcept;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * @param cipher объект блочного шифра «Магма»
			 *
			 * \~english
			 * @brief Constructor
			 * @param cipher the object of the «Magma» block cipher
			 *
			 * \~
			 */
			Block(const magma_t & cipher) noexcept;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * @param cipher объект блочного шифра «Кузнечик»
			 *
			 * \~english
			 * @brief Constructor
			 * @param cipher the object of the «Kuznyechik» block cipher
			 *
			 * \~
			 */
			Block(const kuznyechik_t & cipher) noexcept;
			/**
			 * \~russian
			 * @brief Конструктор
			 *
			 * @param cipher объект блочного шифра AES
			 *
			 * \~english
			 * @brief Constructor
			 * @param cipher the object of the AES block cipher
			 *
			 * \~
			 */
			Block(const aes_t & cipher) noexcept;
		} block_t;

		/**
		 * \~russian
		 * @brief Режим простой замены (ECB)
		 *
		 * @details Раздел 5.1 ГОСТ Р 34.13-2015. Длина сообщения обязана быть кратна
		 *          длине блока: дополнением режим не занимается.
		 *
		 * @note Режим не скрывает совпадения блоков открытого текста и годен лишь
		 *       для преобразования отдельных величин длиной в блок
		 *
		 * \~english
		 * @brief Electronic codebook mode (ECB)
		 * @details Section 5.1 of GOST R 34.13-2015. The length of the message must be a
		 *          multiple of the length of the block: the mode does not deal with the padding.
		 * @note The mode does not hide the coincidences of the blocks of the plain text and
		 *       is suitable only for the transformation of separate values of a length of a block
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Codebook {
			private:
				// Признак того, что режим готов к работе
				bool _ready;
			private:
				// Базовый алгоритм блочного шифрования
				block_t _block;
			public:
				/**
				 * \~russian
				 * @brief Метод проверки готовности режима к работе
				 *
				 * @return признак готовности режима к работе
				 *
				 * \~english
				 * @brief Method of checking the readiness of the mode for the work
				 * @return the flag of the readiness of the mode for the work
				 *
				 * \~
				 */
				bool ready() const noexcept;
				/**
				 * \~russian
				 * @brief Метод запуска режима работы
				 *
				 * @param block базовый алгоритм блочного шифрования
				 *
				 * @return признак успешности запуска режима работы
				 *
				 * \~english
				 * @brief Method of the start of the mode of operation
				 * @param block the base block encryption algorithm
				 * @return the flag of the success of the start of the mode of operation
				 *
				 * \~
				 */
				bool start(const block_t & block) noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса состояния режима работы
				 *
				 * \~english
				 * @brief Method of the reset of the state of the mode of operation
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод зашифрования сообщения
				 *
				 * @param source зашифровываемое сообщение
				 * @param result место, в которое помещается шифртекст
				 *
				 * @return признак успешности зашифрования
				 *
				 * @note Место итога вправе совпадать с местом исходного сообщения
				 *
				 * \~english
				 * @brief Method of the encryption of a message
				 * @param source the message being encrypted
				 * @param result the place the cipher text is put into
				 * @return the flag of the success of the encryption
				 * @note The place of the result may coincide with the place of the source message
				 *
				 * \~
				 */
				bool encrypt(const view_t & source, uint8_t * result) noexcept;
				/**
				 * \~russian
				 * @brief Метод расшифрования сообщения
				 *
				 * @param source расшифровываемый шифртекст
				 * @param result место, в которое помещается открытый текст
				 *
				 * @return признак успешности расшифрования
				 *
				 * @note Место итога вправе совпадать с местом исходного сообщения
				 *
				 * \~english
				 * @brief Method of the decryption of a message
				 * @param source the cipher text being decrypted
				 * @param result the place the plain text is put into
				 * @return the flag of the success of the decryption
				 * @note The place of the result may coincide with the place of the source message
				 *
				 * \~
				 */
				bool decrypt(const view_t & source, uint8_t * result) noexcept;
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
				Codebook() noexcept;
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
				~Codebook() noexcept;
		} codebook_t;

		/**
		 * \~russian
		 * @brief Режим гаммирования (CTR)
		 *
		 * @details Раздел 5.2 ГОСТ Р 34.13-2015. Синхропосылка занимает половину блока,
		 *          начальным значением счётчика служит IV, дополненная нулями до блока.
		 *          Дополнение сообщения режим не требует, а расшифрование от
		 *          зашифрования не отличается.
		 *
		 * @note Значения синхропосылки, выработанные на одном ключе, обязаны быть
		 *       попарно различными: повтор раскрывает сумму открытых текстов
		 *
		 * @note Состояние гаммы переносится между вызовами, оттого сообщение вправе
		 *       подаваться кусками произвольного размера
		 *
		 * @note У шифров, вырабатывающих гамму по многу блоков разом (AES), целые блоки
		 *       идут ядром шифра по сто двадцать восемь блоков, а хвост короче блока -
		 *       поблочно; итог от пути не зависит
		 *
		 * \~english
		 * @brief Counter mode (CTR)
		 * @details Section 5.2 of GOST R 34.13-2015. The initialization vector occupies a
		 *          half of the block, the initial value of the counter is the IV padded by
		 *          the zeroes up to the block. The mode does not require the padding of the
		 *          message, and the decryption does not differ from the encryption.
		 * @note The values of the initialization vector produced on a single key must be
		 *       pairwise different: a repetition reveals the sum of the plain texts
		 * @note The state of the gamma is carried between the calls, therefore the message
		 *       may be fed by the pieces of an arbitrary size
		 * @note With the ciphers producing the gamma by many blocks at once (AES), the whole
		 *       blocks go by the kernel of the cipher by one hundred twenty eight blocks, and the
		 *       tail shorter than a block - block by block; the result does not depend on the path
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Counter {
			private:
				// Признак того, что режим готов к работе
				bool _ready;
			private:
				// Размер блока гаммы в байтах
				size_t _size;
				// Количество неизрасходованных байтов блока гаммы
				size_t _rest;
			private:
				// Базовый алгоритм блочного шифрования
				block_t _block;
			private:
				// Текущее значение счётчика
				uint8_t _counter[MODE_BLOCK];
				// Текущий блок гаммы шифра
				uint8_t _gamma[MODE_BLOCK];
			public:
				/**
				 * \~russian
				 * @brief Метод проверки готовности режима к работе
				 *
				 * @return признак готовности режима к работе
				 *
				 * \~english
				 * @brief Method of checking the readiness of the mode for the work
				 * @return the flag of the readiness of the mode for the work
				 *
				 * \~
				 */
				bool ready() const noexcept;
				/**
				 * \~russian
				 * @brief Метод запуска режима работы
				 *
				 * @param block базовый алгоритм блочного шифрования
				 * @param iv    синхропосылка длиной в половину блока шифра
				 * @param size  размер блока гаммы в байтах, ноль означает длину блока шифра
				 *
				 * @return признак успешности запуска режима работы
				 *
				 * \~english
				 * @brief Method of the start of the mode of operation
				 * @param block the base block encryption algorithm
				 * @param iv    the initialization vector of a length of a half of the block of the cipher
				 * @param size  the size of the block of the gamma in bytes, a zero means the length of the block of the cipher
				 * @return the flag of the success of the start of the mode of operation
				 *
				 * \~
				 */
				bool start(const block_t & block, const view_t & iv, const size_t size = 0) noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса состояния режима работы
				 *
				 * \~english
				 * @brief Method of the reset of the state of the mode of operation
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод зашифрования сообщения
				 *
				 * @param source зашифровываемое сообщение
				 * @param result место, в которое помещается шифртекст
				 *
				 * @return признак успешности зашифрования
				 *
				 * @note Место итога вправе совпадать с местом исходного сообщения
				 *
				 * \~english
				 * @brief Method of the encryption of a message
				 * @param source the message being encrypted
				 * @param result the place the cipher text is put into
				 * @return the flag of the success of the encryption
				 * @note The place of the result may coincide with the place of the source message
				 *
				 * \~
				 */
				bool encrypt(const view_t & source, uint8_t * result) noexcept;
				/**
				 * \~russian
				 * @brief Метод расшифрования сообщения
				 *
				 * @param source расшифровываемый шифртекст
				 * @param result место, в которое помещается открытый текст
				 *
				 * @return признак успешности расшифрования
				 *
				 * @note Место итога вправе совпадать с местом исходного сообщения
				 *
				 * \~english
				 * @brief Method of the decryption of a message
				 * @param source the cipher text being decrypted
				 * @param result the place the plain text is put into
				 * @return the flag of the success of the decryption
				 * @note The place of the result may coincide with the place of the source message
				 *
				 * \~
				 */
				bool decrypt(const view_t & source, uint8_t * result) noexcept;
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
				Counter() noexcept;
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
				~Counter() noexcept;
		} counter_t;

		/**
		 * \~russian
		 * @brief Режим гаммирования с обратной связью по выходу (OFB)
		 *
		 * @details Раздел 5.3 ГОСТ Р 34.13-2015. Регистр сдвига длиной m заполняется
		 *          синхропосылкой, гамма вырабатывается зашифрованием старших разрядов
		 *          регистра, а сам выход шифра дописывается в младшие разряды.
		 *          Расшифрование от зашифрования не отличается.
		 *
		 * \~english
		 * @brief Output feedback mode (OFB)
		 * @details Section 5.3 of GOST R 34.13-2015. The shift register of a length of m is
		 *          filled by the initialization vector, the gamma is produced by the encryption
		 *          of the senior bits of the register, while the output of the cipher itself is
		 *          appended into the junior bits. The decryption does not differ from the encryption.
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Output {
			private:
				// Признак того, что режим готов к работе
				bool _ready;
			private:
				// Размер блока гаммы в байтах
				size_t _size;
				// Количество неизрасходованных байтов блока гаммы
				size_t _rest;
				// Длина регистра сдвига в байтах
				size_t _length;
			private:
				// Базовый алгоритм блочного шифрования
				block_t _block;
			private:
				// Регистр сдвига
				uint8_t _register[MODE_REGISTER];
				// Текущий блок гаммы шифра
				uint8_t _gamma[MODE_BLOCK];
			public:
				/**
				 * \~russian
				 * @brief Метод проверки готовности режима к работе
				 *
				 * @return признак готовности режима к работе
				 *
				 * \~english
				 * @brief Method of checking the readiness of the mode for the work
				 * @return the flag of the readiness of the mode for the work
				 *
				 * \~
				 */
				bool ready() const noexcept;
				/**
				 * \~russian
				 * @brief Метод запуска режима работы
				 *
				 * @param block базовый алгоритм блочного шифрования
				 * @param iv    синхропосылка длиной в целое число блоков шифра
				 * @param size  размер блока гаммы в байтах, ноль означает длину блока шифра
				 *
				 * @return признак успешности запуска режима работы
				 *
				 * \~english
				 * @brief Method of the start of the mode of operation
				 * @param block the base block encryption algorithm
				 * @param iv    the initialization vector of a length of a whole number of the blocks of the cipher
				 * @param size  the size of the block of the gamma in bytes, a zero means the length of the block of the cipher
				 * @return the flag of the success of the start of the mode of operation
				 *
				 * \~
				 */
				bool start(const block_t & block, const view_t & iv, const size_t size = 0) noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса состояния режима работы
				 *
				 * \~english
				 * @brief Method of the reset of the state of the mode of operation
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод зашифрования сообщения
				 *
				 * @param source зашифровываемое сообщение
				 * @param result место, в которое помещается шифртекст
				 *
				 * @return признак успешности зашифрования
				 *
				 * @note Место итога вправе совпадать с местом исходного сообщения
				 *
				 * \~english
				 * @brief Method of the encryption of a message
				 * @param source the message being encrypted
				 * @param result the place the cipher text is put into
				 * @return the flag of the success of the encryption
				 * @note The place of the result may coincide with the place of the source message
				 *
				 * \~
				 */
				bool encrypt(const view_t & source, uint8_t * result) noexcept;
				/**
				 * \~russian
				 * @brief Метод расшифрования сообщения
				 *
				 * @param source расшифровываемый шифртекст
				 * @param result место, в которое помещается открытый текст
				 *
				 * @return признак успешности расшифрования
				 *
				 * @note Место итога вправе совпадать с местом исходного сообщения
				 *
				 * \~english
				 * @brief Method of the decryption of a message
				 * @param source the cipher text being decrypted
				 * @param result the place the plain text is put into
				 * @return the flag of the success of the decryption
				 * @note The place of the result may coincide with the place of the source message
				 *
				 * \~
				 */
				bool decrypt(const view_t & source, uint8_t * result) noexcept;
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
				Output() noexcept;
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
				~Output() noexcept;
		} output_t;

		/**
		 * \~russian
		 * @brief Режим простой замены с зацеплением (CBC)
		 *
		 * @details Раздел 5.4 ГОСТ Р 34.13-2015. Длина сообщения обязана быть кратна
		 *          длине блока: дополнением режим не занимается. Длина регистра сдвига
		 *          m кратна длине блока и при m больше n даёт зацепление через
		 *          несколько блоков назад.
		 *
		 * \~english
		 * @brief Cipher block chaining mode (CBC)
		 * @details Section 5.4 of GOST R 34.13-2015. The length of the message must be a
		 *          multiple of the length of the block: the mode does not deal with the padding.
		 *          The length of the shift register m is a multiple of the length of the block
		 *          and at m greater than n gives a chaining through several blocks back.
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Chaining {
			private:
				// Признак того, что режим готов к работе
				bool _ready;
			private:
				// Длина регистра сдвига в байтах
				size_t _length;
			private:
				// Базовый алгоритм блочного шифрования
				block_t _block;
			private:
				// Регистр сдвига
				uint8_t _register[MODE_REGISTER];
			public:
				/**
				 * \~russian
				 * @brief Метод проверки готовности режима к работе
				 *
				 * @return признак готовности режима к работе
				 *
				 * \~english
				 * @brief Method of checking the readiness of the mode for the work
				 * @return the flag of the readiness of the mode for the work
				 *
				 * \~
				 */
				bool ready() const noexcept;
				/**
				 * \~russian
				 * @brief Метод запуска режима работы
				 *
				 * @param block базовый алгоритм блочного шифрования
				 * @param iv    синхропосылка длиной в целое число блоков шифра
				 *
				 * @return признак успешности запуска режима работы
				 *
				 * \~english
				 * @brief Method of the start of the mode of operation
				 * @param block the base block encryption algorithm
				 * @param iv    the initialization vector of a length of a whole number of the blocks of the cipher
				 * @return the flag of the success of the start of the mode of operation
				 *
				 * \~
				 */
				bool start(const block_t & block, const view_t & iv) noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса состояния режима работы
				 *
				 * \~english
				 * @brief Method of the reset of the state of the mode of operation
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод зашифрования сообщения
				 *
				 * @param source зашифровываемое сообщение
				 * @param result место, в которое помещается шифртекст
				 *
				 * @return признак успешности зашифрования
				 *
				 * @note Место итога вправе совпадать с местом исходного сообщения
				 *
				 * \~english
				 * @brief Method of the encryption of a message
				 * @param source the message being encrypted
				 * @param result the place the cipher text is put into
				 * @return the flag of the success of the encryption
				 * @note The place of the result may coincide with the place of the source message
				 *
				 * \~
				 */
				bool encrypt(const view_t & source, uint8_t * result) noexcept;
				/**
				 * \~russian
				 * @brief Метод расшифрования сообщения
				 *
				 * @param source расшифровываемый шифртекст
				 * @param result место, в которое помещается открытый текст
				 *
				 * @return признак успешности расшифрования
				 *
				 * @note Место итога вправе совпадать с местом исходного сообщения
				 *
				 * \~english
				 * @brief Method of the decryption of a message
				 * @param source the cipher text being decrypted
				 * @param result the place the plain text is put into
				 * @return the flag of the success of the decryption
				 * @note The place of the result may coincide with the place of the source message
				 *
				 * \~
				 */
				bool decrypt(const view_t & source, uint8_t * result) noexcept;
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
				Chaining() noexcept;
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
				~Chaining() noexcept;
		} chaining_t;

		/**
		 * \~russian
		 * @brief Режим гаммирования с обратной связью по шифртексту (CFB)
		 *
		 * @details Раздел 5.5 ГОСТ Р 34.13-2015. Отличие от режима гаммирования с
		 *          обратной связью по выходу в том, что в младшие разряды регистра
		 *          дописывается не выход шифра, а блок шифртекста, оттого зашифрование
		 *          и расшифрование телом отличаются.
		 *
		 * @note Длина регистра m стандартом кратной длине блока не требуется, довольно
		 *       того, что она не меньше длины блока
		 *
		 * \~english
		 * @brief Cipher feedback mode (CFB)
		 * @details Section 5.5 of GOST R 34.13-2015. The difference from the output feedback
		 *          mode is that not the output of the cipher but the block of the cipher text
		 *          is appended into the junior bits of the register, therefore the encryption
		 *          and the decryption differ by their bodies.
		 * @note The length of the register m is not required by the standard to be a multiple
		 *       of the length of the block, it is enough that it is not less than the length of the block
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Feedback {
			private:
				// Признак того, что режим готов к работе
				bool _ready;
			private:
				// Размер блока гаммы в байтах
				size_t _size;
				// Количество неизрасходованных байтов блока гаммы
				size_t _rest;
				// Длина регистра сдвига в байтах
				size_t _length;
			private:
				// Базовый алгоритм блочного шифрования
				block_t _block;
			private:
				// Регистр сдвига
				uint8_t _register[MODE_REGISTER];
				// Текущий блок гаммы шифра
				uint8_t _gamma[MODE_BLOCK];
				// Накапливаемый блок шифртекста обратной связи
				uint8_t _feedback[MODE_BLOCK];
			public:
				/**
				 * \~russian
				 * @brief Метод проверки готовности режима к работе
				 *
				 * @return признак готовности режима к работе
				 *
				 * \~english
				 * @brief Method of checking the readiness of the mode for the work
				 * @return the flag of the readiness of the mode for the work
				 *
				 * \~
				 */
				bool ready() const noexcept;
				/**
				 * \~russian
				 * @brief Метод запуска режима работы
				 *
				 * @param block базовый алгоритм блочного шифрования
				 * @param iv    синхропосылка длиной не менее длины блока шифра
				 * @param size  размер блока гаммы в байтах, ноль означает длину блока шифра
				 *
				 * @return признак успешности запуска режима работы
				 *
				 * \~english
				 * @brief Method of the start of the mode of operation
				 * @param block the base block encryption algorithm
				 * @param iv    the initialization vector of a length of not less than the length of the block of the cipher
				 * @param size  the size of the block of the gamma in bytes, a zero means the length of the block of the cipher
				 * @return the flag of the success of the start of the mode of operation
				 *
				 * \~
				 */
				bool start(const block_t & block, const view_t & iv, const size_t size = 0) noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса состояния режима работы
				 *
				 * \~english
				 * @brief Method of the reset of the state of the mode of operation
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод зашифрования сообщения
				 *
				 * @param source зашифровываемое сообщение
				 * @param result место, в которое помещается шифртекст
				 *
				 * @return признак успешности зашифрования
				 *
				 * @note Место итога вправе совпадать с местом исходного сообщения
				 *
				 * \~english
				 * @brief Method of the encryption of a message
				 * @param source the message being encrypted
				 * @param result the place the cipher text is put into
				 * @return the flag of the success of the encryption
				 * @note The place of the result may coincide with the place of the source message
				 *
				 * \~
				 */
				bool encrypt(const view_t & source, uint8_t * result) noexcept;
				/**
				 * \~russian
				 * @brief Метод расшифрования сообщения
				 *
				 * @param source расшифровываемый шифртекст
				 * @param result место, в которое помещается открытый текст
				 *
				 * @return признак успешности расшифрования
				 *
				 * @note Место итога вправе совпадать с местом исходного сообщения
				 *
				 * \~english
				 * @brief Method of the decryption of a message
				 * @param source the cipher text being decrypted
				 * @param result the place the plain text is put into
				 * @return the flag of the success of the decryption
				 * @note The place of the result may coincide with the place of the source message
				 *
				 * \~
				 */
				bool decrypt(const view_t & source, uint8_t * result) noexcept;
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
				Feedback() noexcept;
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
				~Feedback() noexcept;
		} feedback_t;

		/**
		 * \~russian
		 * @brief Режим выработки имитовставки (OMAC1)
		 *
		 * @details Раздел 5.6 ГОСТ Р 34.13-2015. Сообщение подаётся кусками
		 *          произвольного размера вызовами update, имитовставка снимается
		 *          вызовом finish. Дополнение по процедуре 3 раздела 4.1.3 выполняется
		 *          самим режимом.
		 *
		 * @note Вспомогательные ключи K1 и K2 наравне с ключом шифра секретны, оттого
		 *       затираются деструктором и вызовом clear
		 *
		 * \~english
		 * @brief Message authentication code mode (OMAC1)
		 * @details Section 5.6 of GOST R 34.13-2015. The message is fed by the pieces of an
		 *          arbitrary size by the calls of update, the imitation insert is taken by a
		 *          call of finish. The padding by the procedure 3 of the section 4.1.3 is
		 *          performed by the mode itself.
		 * @note The auxiliary keys K1 and K2 are secret on a par with the key of the cipher,
		 *       therefore they are wiped by the destructor and by a call of clear
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Imitation {
			private:
				// Признак того, что режим готов к работе
				bool _ready;
			private:
				// Количество накопленных байтов текущего блока сообщения
				size_t _size;
			private:
				// Базовый алгоритм блочного шифрования
				block_t _block;
			private:
				// Первый вспомогательный ключ
				uint8_t _first[MODE_BLOCK];
				// Второй вспомогательный ключ
				uint8_t _second[MODE_BLOCK];
			private:
				// Накопленный блок сообщения
				uint8_t _buffer[MODE_BLOCK];
				// Результат зашифрования на предыдущем шаге
				uint8_t _state[MODE_BLOCK];
			public:
				/**
				 * \~russian
				 * @brief Метод проверки готовности режима к работе
				 *
				 * @return признак готовности режима к работе
				 *
				 * \~english
				 * @brief Method of checking the readiness of the mode for the work
				 * @return the flag of the readiness of the mode for the work
				 *
				 * \~
				 */
				bool ready() const noexcept;
				/**
				 * \~russian
				 * @brief Метод запуска режима работы
				 *
				 * @param block базовый алгоритм блочного шифрования
				 *
				 * @return признак успешности запуска режима работы
				 *
				 * \~english
				 * @brief Method of the start of the mode of operation
				 * @param block the base block encryption algorithm
				 * @return the flag of the success of the start of the mode of operation
				 *
				 * \~
				 */
				bool start(const block_t & block) noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса состояния режима работы
				 *
				 * \~english
				 * @brief Method of the reset of the state of the mode of operation
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод добавления куска сообщения
				 *
				 * @param source добавляемый кусок сообщения
				 *
				 * @return признак успешности добавления куска сообщения
				 *
				 * \~english
				 * @brief Method of the addition of a piece of the message
				 * @param source the piece of the message being added
				 * @return the flag of the success of the addition of the piece of the message
				 *
				 * \~
				 */
				bool update(const view_t & source) noexcept;
				/**
				 * \~russian
				 * @brief Метод снятия имитовставки
				 *
				 * @param result место, в которое помещается имитовставка
				 * @param size   требуемая длина имитовставки в байтах
				 *
				 * @return признак успешности снятия имитовставки
				 *
				 * @note Имитовставка снимается усечением выхода шифра до старших байтов
				 *
				 * \~english
				 * @brief Method of the taking of the imitation insert
				 * @param result the place the imitation insert is put into
				 * @param size   the required length of the imitation insert in bytes
				 * @return the flag of the success of the taking of the imitation insert
				 * @note The imitation insert is taken by the truncation of the output of the cipher to the senior bytes
				 *
				 * \~
				 */
				bool finish(uint8_t * result, const size_t size) noexcept;
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
				Imitation() noexcept;
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
				~Imitation() noexcept;
		} imitation_t;
	};
};

#endif // __ANTS_MODE__
