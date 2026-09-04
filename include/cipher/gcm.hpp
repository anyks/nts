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
				uint64_t _powers[4][2];
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
				 * @brief Метод вычисления многочлена GHASH по связанным данным и шифртексту
				 *
				 * @param associated связанные данные
				 * @param sealed     шифртекст
				 * @param result     место, в которое записывается значение многочлена
				 *
				 * \~english
				 * @brief Method of the computation of the GHASH polynomial over the associated data and the cipher text
				 * @param associated the associated data
				 * @param sealed     the cipher text
				 * @param result     the place the value of the polynomial is written into
				 *
				 * \~
				 */
				void polynomial(const view_t & associated, const view_t & sealed, uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод наложения гаммы счётчика
				 *
				 * @param source накладываемые данные
				 * @param result место, в которое записывается итог наложения
				 *
				 * @return       признак успешности наложения
				 *
				 * \~english
				 * @brief Method of the application of the counter gamma
				 * @param source the data being covered
				 * @param result the place the result of the application is written into
				 * @return       the flag of the success of the application
				 *
				 * \~
				 */
				bool gamma(const view_t & source, uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод вычисления метки целостности
				 *
				 * @param associated связанные данные
				 * @param sealed     шифртекст
				 * @param result     место в 16 байтов, в которое записывается метка
				 *
				 * @return           признак успешности вычисления
				 *
				 * \~english
				 * @brief Method of the computation of the authentication tag
				 * @param associated the associated data
				 * @param sealed     the cipher text
				 * @param result     the 16-byte place the tag is written into
				 * @return           the flag of the success of the computation
				 *
				 * \~
				 */
				bool authenticate(const view_t & associated, const view_t & sealed, uint8_t * result) const noexcept;
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
				 * @return           признак схождения метки; при расхождении открытый текст затёрт
				 *
				 * \~english
				 * @brief Method of the decryption with the check of the authentication tag
				 * @param associated the associated data
				 * @param source     the cipher text
				 * @param result     the place the plain text of the same length is written into
				 * @param tag        the tag of the set length being checked
				 * @return           the flag of the convergence of the tag; at a mismatch the plain text is wiped
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
