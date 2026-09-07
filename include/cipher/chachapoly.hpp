/**
 * @file chachapoly.hpp
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
 * @brief Заголовочный файл шифрования с проверкой целостности AEAD_CHACHA20_POLY1305
 *        по RFC 8439
 *
 * \~english
 * @brief Header file of the AEAD_CHACHA20_POLY1305 authenticated encryption according
 *        to RFC 8439
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_CHACHAPOLY__
#define __ANTS_CHACHAPOLY__

/**
 * Стандартные заголовочные файлы
 */
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <cipher/chacha.hpp>
#include <cipher/poly1305.hpp>

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
		 * @brief Длина метки целостности AEAD_CHACHA20_POLY1305 в байтах
		 *
		 * \~english
		 * @brief Length of the AEAD_CHACHA20_POLY1305 authentication tag in bytes
		 *
		 * \~
		 */
		static constexpr size_t CHACHAPOLY_TAG = 16;

		/**
		 * \~russian
		 * @brief Шифрование с проверкой целостности AEAD_CHACHA20_POLY1305
		 *
		 * @details RFC 8439, раздел 2.8. Одноразовый ключ Poly1305 берётся из первых
		 *          32 байтов блока ChaCha20 на счётчике ноль; открытый текст
		 *          зашифровывается ChaCha20 от счётчика один; метка снимается Poly1305
		 *          со связанных данных, дополненных нулями до 16 байтов, шифртекста,
		 *          дополненного так же, и длин обоих по 64 разряда от младшего байта.
		 *          Ключ в 32 байта, заполнение в 12 байтов, метка в 16 байтов
		 *
		 * @note Начальное заполнение для всякого сообщения на одном ключе обязано быть
		 *       неповторимым: повтор раскрывает сумму открытых текстов и ключ метки
		 *
		 * @note Намеренные решения: договор тот же, что у gcm_t, чтобы защита записей
		 *       TLS звала оба одинаково. Повторное зашифрование одним объектом на том же
		 *       заполнении отвергается заслоном _spent; расшифрование под заслон не
		 *       подпадает. Метка сличается за постоянное время. Разовое расшифрование
		 *       сличает метку прежде снятия гаммы: при расхождении выход не тронут.
		 *       Длина метки не настраивается: RFC 8439 знает лишь 16 байтов
		 *
		 * @note Поточный ход: после start связанные данные подаются associate (до
		 *       первого куска данных), данные - поточными encrypt либо decrypt кусками
		 *       любой длины, метка снимается finish либо сличается verify; после них
		 *       поток закрыт до нового start. Разовые encrypt и decrypt выражены тем же
		 *       потоком, оттого нарезка на итог не влияет
		 *
		 * \~english
		 * @brief The AEAD_CHACHA20_POLY1305 authenticated encryption
		 * @details RFC 8439, section 2.8. The one-time Poly1305 key is taken from the first 32
		 *          bytes of the ChaCha20 block at the counter zero; the plain text is encrypted by
		 *          ChaCha20 from the counter one; the tag is taken by Poly1305 over the associated
		 *          data padded by zeros to 16 bytes, the cipher text padded the same way, and the
		 *          64-bit little-endian lengths of both. The key is of 32 bytes, the nonce of
		 *          12 bytes, the tag of 16 bytes
		 * @note The nonce of every message under a single key must be unique: a repetition reveals
		 *       the sum of the plain texts and the key of the tag
		 * @note Deliberate decisions: the contract is the same as at gcm_t, so that the TLS record
		 *       protection calls both alike. A repeated encryption by a single object under the same
		 *       nonce is refused by the _spent guard; the decryption is not subject to the guard. The
		 *       tag is compared in constant time. The one-shot decryption compares the tag before the
		 *       removal of the gamma: at a mismatch the output is not touched. The length of the tag
		 *       is not adjustable: RFC 8439 knows only 16 bytes
		 * @note The streaming course: after start the associated data is fed by associate (before the
		 *       first chunk of the data), the data - by the streaming encrypt or decrypt by chunks of
		 *       any length, the tag is taken by finish or compared by verify; after them the stream is
		 *       closed until a new start. The one-shot encrypt and decrypt are expressed by the same
		 *       stream, therefore the slicing does not affect the result
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Chachapoly {
			private:
				// Признак того, что режим готов к работе
				bool _ready;
				// Признак того, что начальное заполнение уже израсходовано на зашифрование
				bool _spent;
			private:
				// Ступень потока: нет, связанные данные, данные, закрыт
				uint8_t _stage;
				// Направление потока: нет, зашифрование, расшифрование
				uint8_t _direction;
			private:
				// Длина связанных данных в байтах
				uint64_t _associated;
				// Длина шифртекста в байтах
				uint64_t _sealed;
			private:
				// Ключ шифра: хранится для сброса потока
				uint8_t _key[CHACHA_KEY];
				// Начальное заполнение: хранится для сброса потока
				uint8_t _nonce[CHACHA_NONCE];
			private:
				// Поточный шифр
				chacha_t _cipher;
				// Имитовставка
				poly1305_t _mac;
			private:
				/**
				 * \~russian
				 * @brief Метод дополнения имитовставки нулями до целого блока
				 *
				 * @param size длина поданных байтов, по которой считается дополнение
				 *
				 * @return     признак успешности дополнения
				 *
				 * \~english
				 * @brief Method of the padding of the authenticator by zeros to a whole block
				 * @param size the length of the fed bytes the padding is computed by
				 * @return     the flag of the success of the padding
				 *
				 * \~
				 */
				bool pad(const uint64_t size) noexcept;
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
				 * @return признак успешности сброса
				 *
				 * \~english
				 * @brief Method of the reset of the state of the stream
				 * @return the flag of the success of the reset
				 *
				 * \~
				 */
				bool reset() noexcept;
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
				 * @return длина метки в байтах: всегда 16
				 *
				 * \~english
				 * @brief Method of getting the length of the authentication tag
				 * @return the length of the tag in bytes: always 16
				 *
				 * \~
				 */
				size_t size() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод запуска режима
				 *
				 * @param key   ключ в 32 байта
				 * @param nonce начальное заполнение в 12 байтов либо в 24 байта (XChaCha20-Poly1305, draft-irtf-cfrg-xchacha)
				 *
				 * @return      признак успешности запуска
				 *
				 * \~english
				 * @brief Method of the start of the mode
				 * @param key   the 32-byte key
				 * @param nonce the 12-byte nonce or the 24-byte nonce (XChaCha20-Poly1305, draft-irtf-cfrg-xchacha)
				 * @return      the flag of the success of the start
				 *
				 * \~
				 */
				bool start(const view_t & key, const view_t & nonce) noexcept;
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
				 * @param tag место, в которое записывается метка в 16 байтов
				 *
				 * @return    признак успешности завершения; поток закрывается
				 *
				 * \~english
				 * @brief Method of the completion of the streaming encryption by the production of the tag
				 * @param tag the place the 16-byte tag is written into
				 * @return    the flag of the success of the completion; the stream is closed
				 *
				 * \~
				 */
				bool finish(uint8_t * tag) noexcept;
				/**
				 * \~russian
				 * @brief Метод завершения поточного расшифрования сличением метки
				 *
				 * @param tag проверяемая метка в 16 байтов
				 *
				 * @return    признак схождения метки за постоянное время; поток закрывается
				 *
				 * \~english
				 * @brief Method of the completion of the streaming decryption by the comparison of the tag
				 * @param tag the 16-byte tag being checked
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
				 * @param tag        место, в которое записывается метка в 16 байтов
				 *
				 * @return           признак успешности зашифрования
				 *
				 * \~english
				 * @brief Method of the encryption with the production of the authentication tag
				 * @param associated the associated data protected only by the tag
				 * @param source     the plain text
				 * @param result     the place the cipher text of the same length is written into
				 * @param tag        the place the 16-byte tag is written into
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
				 * @param tag        проверяемая метка в 16 байтов
				 *
				 * @return           признак схождения метки; при расхождении открытый текст не тронут
				 *
				 * \~english
				 * @brief Method of the decryption with the check of the authentication tag
				 * @param associated the associated data
				 * @param source     the cipher text
				 * @param result     the place the plain text of the same length is written into
				 * @param tag        the 16-byte tag being checked
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
				Chachapoly() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Chachapoly() noexcept;
		} chachapoly_t;
	};
};

#endif // __ANTS_CHACHAPOLY__
