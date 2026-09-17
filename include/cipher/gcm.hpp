/**
 * @file gcm.hpp
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
 * @brief Заголовочный файл режима шифрования с проверкой целостности GCM по
 *        NIST SP 800-38D над блочным шифром с блоком в 128 разрядов
 *
 * \~english
 * @brief Header file of the GCM authenticated encryption mode according to NIST SP 800-38D
 *        over a block cipher with a 128-bit block
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_GCM__
#define __ANTS_GCM__

/**
 * Стандартные заголовочные файлы
 */
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <cipher/mode.hpp>

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
		 * @brief Длина метки целостности GCM по умолчанию в байтах
		 *
		 * \~english
		 * @brief Default length of the GCM authentication tag in bytes
		 *
		 * \~
		 */
		static constexpr size_t GCM_TAG = 16;

		/**
		 * \~russian
		 * @brief Режим шифрования с проверкой целостности GCM
		 *
		 * @details NIST SP 800-38D. Открытый текст зашифровывается гаммированием со
		 *          счётчиком, а метка целостности снимается со значения многочлена
		 *          GHASH в поле GF(2^128) по связанным данным и шифртексту, сложенного
		 *          с зашифрованным начальным блоком счётчика. Начальное заполнение в
		 *          12 байтов идёт в счётчик напрямую, иной длины - через GHASH
		 *
		 * @note Начальное заполнение для всякого сообщения на одном ключе обязано быть
		 *       неповторимым: повтор раскрывает сумму открытых текстов и ключ метки
		 *
		 * @note Намеренные решения: повторное зашифрование одним объектом на том же
		 *       заполнении отвергается заслоном режима, как и у MGM; расшифрование под
		 *       заслон не подпадает. Метка сличается за постоянное время. Умножение в
		 *       поле идёт по таблицам в четыре разряда, вычисляемым при запуске из
		 *       ключа хеширования
		 *
		 * @note Поточный ход: после start связанные данные подаются associate (до
		 *       первого куска данных), данные - поточными encrypt либо decrypt кусками
		 *       любой длины, метка снимается finish либо сличается verify; после них
		 *       поток закрыт до нового start. Разовые encrypt и decrypt выражены тем же
		 *       потоком, оттого нарезка на итог не влияет
		 *
		 * \~english
		 * @brief GCM authenticated encryption mode
		 * @details NIST SP 800-38D. The plain text is encrypted by the gamma with a counter, while
		 *          the authentication tag is taken from the value of the GHASH polynomial in the
		 *          GF(2^128) field over the associated data and the cipher text, added to the encrypted
		 *          initial counter block. A 12-byte nonce goes into the counter directly, one of another
		 *          length - through GHASH
		 * @note The nonce of every message under a single key must be unique: a repetition reveals the
		 *       sum of the plain texts and the key of the tag
		 * @note Deliberate decisions: a repeated encryption by a single object under the same nonce is
		 *       refused by a guard of the mode, as at MGM; the decryption is not subject to the guard.
		 *       The tag is compared in constant time. The multiplication in the field goes by the
		 *       four-bit tables computed at the start from the hashing key
		 * @note The streaming course: after start the associated data is fed by associate (before the
		 *       first chunk of the data), the data - by the streaming encrypt or decrypt by chunks of
		 *       any length, the tag is taken by finish or compared by verify; after them the stream is
		 *       closed until a new start. The one-shot encrypt and decrypt are expressed by the same
		 *       stream, therefore the slicing does not affect the result
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Gcm {
			private:
				// Признак того, что режим готов к работе
				bool _ready;
				// Признак того, что начальное заполнение уже израсходовано на зашифрование
				bool _spent;
			private:
				// Длина метки целостности в байтах
				size_t _size;
			private:
				// Базовый алгоритм блочного шифрования
				block_t _block;
			private:
				// Начальный блок счётчика J0
				uint8_t _nonce[16];
				// Таблица кратных ключа хеширования: шестнадцать значений по два слова
				uint64_t _table[16][2];
				// Ключ хеширования с отражёнными разрядами байтов: для машинного умножения
				uint64_t _mirror[2];
				// Степени ключа хеширования от четвёртой до первой с отражёнными разрядами: для умножения по четыре блока
				uint64_t _powers[8][2];
			private:
				// Ступень потока: нет, связанные данные, данные, закрыт
				uint8_t _stage;
				// Направление потока: нет, зашифрование, расшифрование
				uint8_t _direction;
			private:
				// Число неизрасходованных байтов остатка блока гаммы
				size_t _rest;
				// Число накопленных байтов неполного блока многочлена
				size_t _filled;
			private:
				// Длина связанных данных в байтах
				uint64_t _associated;
				// Длина шифртекста в байтах
				uint64_t _sealed;
			private:
				// Последний использованный блок счётчика
				uint8_t _counter[16];
				// Остаток блока гаммы
				uint8_t _gamma[16];
				// Накопитель многочлена GHASH
				uint8_t _accumulator[16];
				// Неполный блок многочлена GHASH
				uint8_t _pending[16];
			private:
				/**
				 * \~russian
				 * @brief Метод умножения значения на ключ хеширования в поле GF(2^128)
				 *
				 * @param value умножаемое значение, заменяемое произведением
				 *
				 * \~english
				 * @brief Method of the multiplication of a value by the hashing key in the GF(2^128) field
				 * @param value the value being multiplied, replaced by the product
				 *
				 * \~
				 */
				void multiply(uint8_t * value) const noexcept;
				/**
				 * \~russian
				 * @brief Метод сложения четырёх блоков в накопитель многочлена одним приведением
				 *
				 * @param accumulator накопитель многочлена, заменяемый итогом
				 * @param blocks      четыре блока подряд
				 *
				 * @return            признак того, что машина умножает командами и блоки сложены
				 *
				 * \~english
				 * @brief Method of the addition of four blocks into the polynomial accumulator by one reduction
				 * @param accumulator the polynomial accumulator, replaced by the result
				 * @param blocks      four blocks in a row
				 * @return            the flag of the machine multiplying by the instructions and the blocks being added
				 *
				 * \~
				 */
				bool aggregate(uint8_t * accumulator, const uint8_t * blocks) const noexcept;
				/**
				 * \~russian
				 * @brief Метод сложения байтов в накопитель многочлена GHASH
				 *
				 * @param data складываемые байты
				 * @param size число складываемых байтов
				 *
				 * \~english
				 * @brief Method of the addition of bytes into the GHASH polynomial accumulator
				 * @param data the bytes being added
				 * @param size the number of the bytes being added
				 *
				 * \~
				 */
				void absorb(const uint8_t * data, const size_t size) noexcept;
				/**
				 * \~russian
				 * @brief Метод наложения гаммы счётчика с продолжением от остатка блока
				 *
				 * @param source накладываемые данные
				 * @param result место, в которое записывается итог наложения
				 *
				 * @return       признак успешности наложения
				 *
				 * \~english
				 * @brief Method of the application of the counter gamma continuing from the rest of the block
				 * @param source the data being covered
				 * @param result the place the result of the application is written into
				 * @return       the flag of the success of the application
				 *
				 * \~
				 */
				bool cover(const view_t & source, uint8_t * result) noexcept;
				/**
				 * \~russian
				 * @brief Метод завершения многочлена GHASH блоком длин
				 *
				 * @param result место в 16 байтов, в которое записывается значение многочлена
				 *
				 * \~english
				 * @brief Method of the completion of the GHASH polynomial by the block of the lengths
				 * @param result the 16-byte place the value of the polynomial is written into
				 *
				 * \~
				 */
				void digest(uint8_t * result) noexcept;
				/**
				 * \~russian
				 * @brief Метод вычисления метки целостности по накопленному потоку
				 *
				 * @param result место в 16 байтов, в которое записывается метка
				 *
				 * @return       признак успешности вычисления
				 *
				 * \~english
				 * @brief Method of the computation of the authentication tag over the accumulated stream
				 * @param result the 16-byte place the tag is written into
				 * @return       the flag of the success of the computation
				 *
				 * \~
				 */
				bool authenticate(uint8_t * result) noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса состояния потока
				 *
				 * \~english
				 * @brief Method of the reset of the state of the stream
				 *
				 * \~
				 */
				void reset() noexcept;
				/**
				 * \~russian
				 * @brief Метод перехода потока к данным
				 *
				 * @param direction направление потока: единица - зашифрование, двойка - расшифрование
				 *
				 * @return          признак допустимости перехода
				 *
				 * \~english
				 * @brief Method of the transition of the stream to the data
				 * @param direction the direction of the stream: one - encryption, two - decryption
				 * @return          the flag of the admissibility of the transition
				 *
				 * \~
				 */
				bool proceed(const uint8_t direction) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод проверки готовности режима к работе
				 *
				 * @return признак готовности режима
				 *
				 * \~english
				 * @brief Method of checking the readiness of the mode for the work
				 * @return the flag of the readiness of the mode
				 *
				 * \~
				 */
				bool ready() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения длины метки целостности
				 *
				 * @return длина метки в байтах
				 *
				 * \~english
				 * @brief Method of getting the length of the authentication tag
				 * @return the length of the tag in bytes
				 *
				 * \~
				 */
				size_t size() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод запуска режима
				 *
				 * @param block блочный шифр с блоком в 16 байтов и установленным ключом
				 * @param nonce начальное заполнение любой ненулевой длины, 12 байтов - прямой путь
				 * @param size  длина метки целостности от 4 до 16 байтов, ноль - 16
				 *
				 * @return      признак успешности запуска
				 *
				 * \~english
				 * @brief Method of the start of the mode
				 * @param block the block cipher with a 16-byte block and a set key
				 * @param nonce the nonce of any nonzero length, 12 bytes - the direct path
				 * @param size  the length of the authentication tag from 4 to 16 bytes, zero - 16
				 * @return      the flag of the success of the start
				 *
				 * \~
				 */
				bool start(const block_t & block, const view_t & nonce, const size_t size = 0) noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса режима
				 *
				 * \~english
				 * @brief Method of the reset of the mode
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод подачи связанных данных потока
				 *
				 * @details Допускается лишь до первого куска данных, кусками любой длины
				 *
				 * @param associated связанные данные, защищаемые лишь меткой
				 *
				 * @return           признак успешности подачи
				 *
				 * \~english
				 * @brief Method of the feeding of the associated data of the stream
				 * @details It is allowed only before the first chunk of the data, by chunks of any length
				 * @param associated the associated data protected only by the tag
				 * @return           the flag of the success of the feeding
				 *
				 * \~
				 */
				bool associate(const view_t & associated) noexcept;
				/**
				 * \~russian
				 * @brief Метод поточного зашифрования куска
				 *
				 * @details Кусок любой длины, включая пустой; первый кусок расходует заполнение
				 *
				 * @param source открытый текст
				 * @param result место, в которое записывается шифртекст той же длины
				 *
				 * @return       признак успешности зашифрования
				 *
				 * \~english
				 * @brief Method of the streaming encryption of a chunk
				 * @details A chunk of any length, including an empty one; the first chunk spends the nonce
				 * @param source the plain text
				 * @param result the place the cipher text of the same length is written into
				 * @return       the flag of the success of the encryption
				 *
				 * \~
				 */
				bool encrypt(const view_t & source, uint8_t * result) noexcept;
				/**
				 * \~russian
				 * @brief Метод поточного расшифрования куска
				 *
				 * @details Открытый текст выдаётся до сличения метки: подлинность его
				 *          подтверждается лишь успешным verify
				 *
				 * @param source шифртекст
				 * @param result место, в которое записывается открытый текст той же длины
				 *
				 * @return       признак успешности расшифрования
				 *
				 * \~english
				 * @brief Method of the streaming decryption of a chunk
				 * @details The plain text is given out before the comparison of the tag: its authenticity
				 *          is confirmed only by a successful verify
				 * @param source the cipher text
				 * @param result the place the plain text of the same length is written into
				 * @return       the flag of the success of the decryption
				 *
				 * \~
				 */
				bool decrypt(const view_t & source, uint8_t * result) noexcept;
				/**
				 * \~russian
				 * @brief Метод завершения поточного зашифрования выработкой метки
				 *
				 * @param tag место, в которое записывается метка установленной длины
				 *
				 * @return    признак успешности завершения; поток закрывается
				 *
				 * \~english
				 * @brief Method of the completion of the streaming encryption by the production of the tag
				 * @param tag the place the tag of the set length is written into
				 * @return    the flag of the success of the completion; the stream is closed
				 *
				 * \~
				 */
				bool finish(uint8_t * tag) noexcept;
				/**
				 * \~russian
				 * @brief Метод завершения поточного расшифрования сличением метки
				 *
				 * @param tag проверяемая метка установленной длины
				 *
				 * @return    признак схождения метки за постоянное время; поток закрывается
				 *
				 * \~english
				 * @brief Method of the completion of the streaming decryption by the comparison of the tag
				 * @param tag the tag of the set length being checked
				 * @return    the flag of the convergence of the tag in constant time; the stream is closed
				 *
				 * \~
				 */
				bool verify(const view_t & tag) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод зашифрования с выработкой метки целостности
				 *
				 * @param associated связанные данные, защищаемые лишь меткой
				 * @param source     открытый текст
				 * @param result     место, в которое записывается шифртекст той же длины
				 * @param tag        место, в которое записывается метка установленной длины
				 *
				 * @return           признак успешности зашифрования
				 *
				 * \~english
				 * @brief Method of the encryption with the production of the authentication tag
				 * @param associated the associated data protected only by the tag
				 * @param source     the plain text
				 * @param result     the place the cipher text of the same length is written into
				 * @param tag        the place the tag of the set length is written into
				 * @return           the flag of the success of the encryption
				 *
				 * \~
				 */
				bool encrypt(const view_t & associated, const view_t & source, uint8_t * result, uint8_t * tag) noexcept;
				/**
				 * \~russian
				 * @brief Метод расшифрования с проверкой метки целостности
				 *
				 * @param associated связанные данные
				 * @param source     шифртекст
				 * @param result     место, в которое записывается открытый текст той же длины
				 * @param tag        проверяемая метка установленной длины
				 *
				 * @return           признак схождения метки; при расхождении открытый текст не тронут
				 *
				 * \~english
				 * @brief Method of the decryption with the check of the authentication tag
				 * @param associated the associated data
				 * @param source     the cipher text
				 * @param result     the place the plain text of the same length is written into
				 * @param tag        the tag of the set length being checked
				 * @return           the flag of the convergence of the tag; at a mismatch the plain text is not touched
				 *
				 * \~
				 */
				bool decrypt(const view_t & associated, const view_t & source, uint8_t * result, const view_t & tag) noexcept;
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
				Gcm() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Gcm() noexcept;
		} gcm_t;
	};
};

#endif // __ANTS_GCM__
