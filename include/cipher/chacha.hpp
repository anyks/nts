/**
 * @file chacha.hpp
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
 * @brief Заголовочный файл поточного шифра ChaCha20 по RFC 8439
 *
 * \~english
 * @brief Header file of the ChaCha20 stream cipher according to RFC 8439
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
		 * @brief Размер ключа шифра ChaCha20 в байтах
		 *
		 * \~english
		 * @brief Size of the key of the ChaCha20 cipher in bytes
		 *
		 * \~
		 */
		static constexpr size_t CHACHA_KEY = 32;

		/**
		 * \~russian
		 * @brief Размер начального заполнения шифра ChaCha20 в байтах
		 *
		 * \~english
		 * @brief Size of the nonce of the ChaCha20 cipher in bytes
		 *
		 * \~
		 */
		static constexpr size_t CHACHA_NONCE = 12;

		/**
		 * \~russian
		 * @brief Размер блока гаммы шифра ChaCha20 в байтах
		 *
		 * \~english
		 * @brief Size of the gamma block of the ChaCha20 cipher in bytes
		 *
		 * \~
		 */
		static constexpr size_t CHACHA_BLOCK = 64;
		/**
		 * \~russian
		 * @brief Длина начального заполнения XChaCha20 в байтах (draft-irtf-cfrg-xchacha)
		 *
		 * \~english
		 * @brief Length of the XChaCha20 nonce in bytes (draft-irtf-cfrg-xchacha)
		 *
		 * \~
		 */
		static constexpr size_t CHACHA_XNONCE = 24;
		/**
		 * \~russian
		 * @brief Длина начального заполнения HChaCha20 в байтах
		 *
		 * \~english
		 * @brief Length of the HChaCha20 nonce in bytes
		 *
		 * \~
		 */
		static constexpr size_t HCHACHA_NONCE = 16;

		/**
		 * \~russian
		 * @brief Поточный шифр ChaCha20
		 *
		 * @details RFC 8439, раздел 2. Состояние в шестнадцать слов по 32 разряда:
		 *          четыре постоянных, восемь слов ключа, счётчик блока и три слова
		 *          начального заполнения. Блочная функция проводит двадцать раундов
		 *          четвертьраундов и складывает итог с исходным состоянием; гамма
		 *          накладывается на данные сложением по модулю два. Ключ в 32 байта,
		 *          заполнение в 12 байтов, счётчик в 32 разряда
		 *
		 * @note Начальное заполнение для всякого сообщения на одном ключе обязано быть
		 *       неповторимым: повтор раскрывает сумму открытых текстов
		 *
		 * @note Намеренные решения: переносимый путь на 32-разрядных операциях, а
		 *       пачки целых блоков идут векторными командами (NEON у ARM64, SSE2,
		 *       SSSE3 либо AVX2 у x86-64) с выбором на исполнении по sys/machine.hpp;
		 *       оба пути в одном двоичном файле, запрет machine::allow(false)
		 *       возвращает переносимый. Памяти не выделяется, исключений нет.
		 *       Счётчик блока в 32 разряда, как
		 *       велит RFC 8439, и переполнение его отвергается отказом, а не переносом
		 *       в заполнение: 256 ГиБ на одном заполнении никакому протоколу не нужны.
		 *       Вызов block выдаёт целый блок гаммы на текущем счётчике и отбрасывает
		 *       неизрасходованный остаток прежнего: так вырабатывается ключ Poly1305 у
		 *       AEAD до первого куска данных
		 *
		 * @note Поточный ход: после start данные подаются encrypt либо decrypt кусками
		 *       любой длины, включая пустые и по одному байту; остаток блока гаммы
		 *       переносится между вызовами, оттого нарезка на итог не влияет. Повтор
		 *       start сбрасывает состояние
		 *
		 * \~english
		 * @brief The ChaCha20 stream cipher
		 * @details RFC 8439, section 2. The state of sixteen 32-bit words: four constants, eight
		 *          words of the key, the block counter and three words of the nonce. The block
		 *          function performs twenty rounds of the quarter rounds and adds the result to the
		 *          initial state; the gamma is applied to the data by the addition modulo two. The key
		 *          is of 32 bytes, the nonce of 12 bytes, the counter of 32 bits
		 * @note The nonce of every message under a single key must be unique: a repetition reveals
		 *       the sum of the plain texts
		 * @note Deliberate decisions: the portable path is on 32-bit operations, and the packs of
		 *       whole blocks go by the vector instructions (NEON at ARM64, SSE2, SSSE3 or AVX2 at
		 *       x86-64) chosen at the run time by sys/machine.hpp; both paths are in one binary, the
		 *       ban machine::allow(false) brings the portable one back. No memory is allocated, there
		 *       are no exceptions. The block counter is of 32 bits as
		 *       RFC 8439 says, and its overflow is refused instead of being carried into the nonce:
		 *       256 GiB under a single nonce are needed by no protocol. A call of block gives out a
		 *       whole gamma block at the current counter and discards the unspent rest of the previous
		 *       one: this is how the Poly1305 key is produced at AEAD before the first chunk of the data
		 * @note The streaming course: after start the data is fed by encrypt or decrypt by chunks of
		 *       any length, including empty ones and by a single byte; the rest of the gamma block is
		 *       carried between the calls, therefore the slicing does not affect the result. A repeated
		 *       start resets the state
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Chacha {
			private:
				// Признак того, что шифр готов к работе
				bool _ready;
				// Признак того, что счётчик блока переполнен
				bool _exhausted;
			private:
				// Число неизрасходованных байтов остатка блока гаммы
				size_t _rest;
			private:
				// Состояние шифра: постоянные, ключ, счётчик, заполнение
				uint32_t _state[16];
				// Остаток блока гаммы
				uint8_t _gamma[CHACHA_BLOCK];
			private:
				/**
				 * \~russian
				 * @brief Метод выработки блока гаммы на текущем счётчике
				 *
				 * @param result место в 64 байта, в которое записывается блок гаммы
				 *
				 * \~english
				 * @brief Method of the production of the gamma block at the current counter
				 * @param result the 64-byte place the gamma block is written into
				 *
				 * \~
				 */
				void generate(uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод продвижения счётчика блока
				 *
				 * @return признак того, что счётчик не переполнился
				 *
				 * \~english
				 * @brief Method of the advance of the block counter
				 * @return the flag of the counter not having overflown
				 *
				 * \~
				 */
				bool advance() noexcept;
				/**
				 * \~russian
				 * @brief Метод покрытия гаммой пачек целых блоков векторными командами
				 *
				 * @param cursor позиция чтения данных, сдвигается на покрытое
				 * @param output позиция записи итога, сдвигается на покрытое
				 * @param left   число ещё не покрытых байтов, уменьшается на покрытое
				 *
				 * \~english
				 * @brief Method of covering the packs of whole blocks with the gamma by the vector instructions
				 * @param cursor the reading position of the data, advanced by the covered
				 * @param output the writing position of the result, advanced by the covered
				 * @param left   the number of the bytes not covered yet, decreased by the covered
				 *
				 * \~
				 */
				void pack(const uint8_t * & cursor, uint8_t * & output, size_t & left) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод четвертьраунда ChaCha20
				 *
				 * @details Раздел 2.1 RFC 8439: четыре сложения, четыре сложения по модулю
				 *          два и четыре вращения на 16, 12, 8 и 7 разрядов
				 *
				 * @param a первое слово, заменяемое итогом
				 * @param b второе слово, заменяемое итогом
				 * @param c третье слово, заменяемое итогом
				 * @param d четвёртое слово, заменяемое итогом
				 *
				 * \~english
				 * @brief Method of the ChaCha20 quarter round
				 * @details Section 2.1 of RFC 8439: four additions, four additions modulo two and four
				 *          rotations by 16, 12, 8 and 7 bits
				 * @param a the first word, replaced by the result
				 * @param b the second word, replaced by the result
				 * @param c the third word, replaced by the result
				 * @param d the fourth word, replaced by the result
				 *
				 * \~
				 */
				static void quarter(uint32_t & a, uint32_t & b, uint32_t & c, uint32_t & d) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод проверки готовности шифра к работе
				 *
				 * @return признак готовности шифра
				 *
				 * \~english
				 * @brief Method of checking the readiness of the cipher for the work
				 * @return the flag of the readiness of the cipher
				 *
				 * \~
				 */
				bool ready() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения текущего счётчика блока
				 *
				 * @return счётчик блока, который выработает следующий блок гаммы
				 *
				 * \~english
				 * @brief Method of getting the current block counter
				 * @return the block counter the next gamma block is produced by
				 *
				 * \~
				 */
				uint32_t counter() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод запуска шифра
				 *
				 * @param key     ключ в 32 байта
				 * @param nonce   начальное заполнение в 12 байтов (ChaCha20, RFC 8439) либо в 24 байта (XChaCha20)
				 * @param counter начальное значение счётчика блока
				 *
				 * @return        признак успешности запуска
				 *
				 * @details С заполнением в 24 байта шифр идёт как XChaCha20 (draft-irtf-cfrg-xchacha,
				 *          раздел 2.3): подключ выводится HChaCha20 из ключа и первых шестнадцати байтов,
				 *          заполнением ChaCha20 служат четыре нулевых байта и последние восемь. Это сырой
				 *          поток без имитовставки: гамма, наложенная на данные; целостность - дело потребителя
				 *
				 * \~english
				 * @brief Method of the start of the cipher
				 * @param key     the 32-byte key
				 * @param nonce   the 12-byte nonce (ChaCha20, RFC 8439) or the 24-byte nonce (XChaCha20)
				 * @param counter the initial value of the block counter
				 * @return        the flag of the success of the start
				 * @details With a 24-byte nonce the cipher runs as XChaCha20 (draft-irtf-cfrg-xchacha, section
				 *          2.3): the subkey is derived by HChaCha20 from the key and the first sixteen bytes, the
				 *          ChaCha20 nonce is four zero bytes and the last eight. It is a raw stream without an
				 *          authentication tag: the gamma applied to the data; the integrity is the consumer's business
				 *
				 * \~
				 */
				bool start(const view_t & key, const view_t & nonce, const uint32_t counter = 0) noexcept;
				/**
				 * \~russian
				 * @brief Метод вывода подключа HChaCha20 (draft-irtf-cfrg-xchacha, раздел 2.2)
				 *
				 * @param key    ключ в 32 байта
				 * @param nonce  начальное заполнение в 16 байтов
				 * @param result место, в которое помещается подключ в 32 байта
				 *
				 * @return       признак успешности вывода
				 *
				 * \~english
				 * @brief Method of the derivation of the HChaCha20 subkey (draft-irtf-cfrg-xchacha, section 2.2)
				 * @param key    the 32-byte key
				 * @param nonce  the 16-byte nonce
				 * @param result the place the 32-byte subkey is put into
				 * @return       the flag of the success of the derivation
				 *
				 * \~
				 */
				static bool hchacha(const view_t & key, const view_t & nonce, uint8_t * result) noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса шифра с затиранием состояния
				 *
				 * \~english
				 * @brief Method of the reset of the cipher with the wiping of the state
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод выработки целого блока гаммы
				 *
				 * @details Блок вырабатывается на текущем счётчике, счётчик продвигается,
				 *          неизрасходованный остаток прежнего блока отбрасывается
				 *
				 * @param result место в 64 байта, в которое записывается блок гаммы
				 *
				 * @return       признак успешности выработки
				 *
				 * \~english
				 * @brief Method of the production of a whole gamma block
				 * @details The block is produced at the current counter, the counter is advanced, the
				 *          unspent rest of the previous block is discarded
				 * @param result the 64-byte place the gamma block is written into
				 * @return       the flag of the success of the production
				 *
				 * \~
				 */
				bool block(uint8_t * result) noexcept;
				/**
				 * \~russian
				 * @brief Метод поточного зашифрования куска
				 *
				 * @param source открытый текст любой длины, включая пустой
				 * @param result место, в которое записывается шифртекст той же длины
				 *
				 * @return       признак успешности зашифрования
				 *
				 * \~english
				 * @brief Method of the streaming encryption of a chunk
				 * @param source the plain text of any length, including an empty one
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
				 * @param source шифртекст любой длины, включая пустой
				 * @param result место, в которое записывается открытый текст той же длины
				 *
				 * @return       признак успешности расшифрования
				 *
				 * \~english
				 * @brief Method of the streaming decryption of a chunk
				 * @param source the cipher text of any length, including an empty one
				 * @param result the place the plain text of the same length is written into
				 * @return       the flag of the success of the decryption
				 *
				 * \~
				 */
				bool decrypt(const view_t & source, uint8_t * result) noexcept;
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
				Chacha() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Chacha() noexcept;
		} chacha_t;
	};
};

