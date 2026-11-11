/**
 * @file mgm.hpp
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
 * @brief Заголовочный файл модуля режима шифрования с проверкой целостности MGM
 *        по RFC 9058
 *
 * \~english
 * @brief Header file of the module of the MGM authenticated encryption mode
 *        according to RFC 9058
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
		 * @brief Наименьшая длина метки целостности в байтах
		 *
		 * @details RFC 9058 требует длины метки не менее 32 разрядов
		 *
		 * \~english
		 * @brief Least length of the authentication tag in bytes
		 *
		 * @details RFC 9058 requires the length of the tag to be not less than 32 bits
		 *
		 * \~
		 */
		static constexpr size_t MGM_TAG = 4;

		/**
		 * \~russian
		 * @brief Режим шифрования с проверкой целостности MGM
		 *
		 * @details RFC 9058. Открытый текст зашифровывается гаммированием со счётчиком,
		 *          а метка целостности снимается со значения многочлена, вычисляемого в
		 *          поле GF(2^n) по связанным данным и шифртексту: отсюда и название
		 *          режима - Multilinear Galois Mode.
		 *
		 * @note Значение начального заполнения счётчика для всякого сообщения,
		 *       зашифрованного на одном ключе, обязано быть неповторимым: повтор
		 *       раскрывает не только сумму открытых текстов, но и ключ выработки метки
		 *
		 * @note Старший разряд начального заполнения счётчика занят самим режимом и
		 *       обязан быть нулевым
		 *
		 * @note Намеренные решения: повторное зашифрование одним объектом на том же
		 *       начальном заполнении счётчика отвергается заслоном режима, а не
		 *       оставляется на совести вызывающего: после первого зашифрования объект
		 *       запоминает, что заполнение уже израсходовано на наложение защиты, и
		 *       всякое следующее зашифрование отказывает до нового запуска режима с
		 *       новым заполнением. Расшифрование под заслон не подпадает: повторная
		 *       проверка метки на том же заполнении ничего не раскрывает
		 *
		 * @note Поточный ход: после start связанные данные подаются associate (до
		 *       первого куска сообщения), сообщение - поточными encrypt либо decrypt
		 *       кусками любой длины, метка снимается finish либо сличается verify;
		 *       после них поток закрыт до нового start либо restart. Разовые encrypt и
		 *       decrypt выражены тем же потоком, оттого нарезка на итог не влияет
		 *
		 * \~english
		 * @brief MGM authenticated encryption mode
		 *
		 * @details RFC 9058. The plain text is encrypted by the gamma with a counter, while
		 *          the authentication tag is taken from the value of a polynomial computed in
		 *          the GF(2^n) field over the associated data and the cipher text: hence the
		 *          name of the mode - Multilinear Galois Mode.
		 *
		 * @note The value of the initial counter nonce for every message encrypted under a
		 *       single key must be unique: a repetition reveals not only the sum of the plain
		 *       texts but the key of the production of the tag as well
		 *
		 * @note The senior bit of the initial counter nonce is occupied by the mode itself
		 *       and must be a zero
		 *
		 * @note Deliberate decisions: a repeated encryption by a single object under the
		 *       same initial counter nonce is refused by a guard of the mode itself rather
		 *       than left to the conscience of the caller: after the first encryption the
		 *       object remembers that the nonce is already spent on the sealing, and every
		 *       following encryption fails until a new start of the mode with a new nonce.
		 *       The decryption is not subject to the guard: a repeated check of the tag
		 *       under the same nonce reveals nothing
		 *
		 * @note The streaming course: after start the associated data is fed by associate (before
		 *       the first chunk of the message), the message - by the streaming encrypt or decrypt by
		 *       chunks of any length, the tag is taken by finish or compared by verify; after them the
		 *       stream is closed until a new start or restart. The one-shot encrypt and decrypt are
		 *       expressed by the same stream, therefore the slicing does not affect the result
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Galois {
			private:
				// Признак того, что режим готов к работе
				bool _ready;
			private:
				// Признак того, что начальное заполнение счётчика уже израсходовано на зашифрование
				bool _spent;
			private:
				// Длина метки целостности в байтах
				size_t _size;
			private:
				// Базовый алгоритм блочного шифрования
				block_t _block;
			private:
				// Начальное заполнение счётчика
				uint8_t _nonce[MODE_BLOCK];
			private:
				// Ступень потока: нет, связанные данные, данные, закрыт
				uint8_t _stage;
				// Направление потока: нет, зашифрование, расшифрование
				uint8_t _direction;
			private:
				// Число неизрасходованных байтов остатка блока гаммы
				size_t _rest;
				// Число накопленных байтов неполного блока метки
				size_t _filled;
			private:
				// Длина связанных данных в байтах
				uint64_t _associated;
				// Длина шифртекста в байтах
				uint64_t _sealed;
			private:
				// Счётчик выработки гаммы: растёт младшая половина
				uint8_t _counter[MODE_BLOCK];
				// Счётчик выработки метки: растёт старшая половина
				uint8_t _marked[MODE_BLOCK];
				// Остаток блока гаммы
				uint8_t _gamma[MODE_BLOCK];
				// Накопитель суммы произведений метки
				uint8_t _sum[MODE_BLOCK];
				// Неполный блок метки
				uint8_t _pending[MODE_BLOCK];
			private:
				/**
				 * \~russian
				 * @brief Метод сброса состояния потока
				 *
				 * @return признак успешности сброса: счётчики гаммы и метки вырабатываются шифром
				 *
				 * \~english
				 * @brief Method of the reset of the state of the stream
				 *
				 * @return the flag of the success of the reset: the counters of the gamma and of the tag are produced by the cipher
				 *
				 * \~
				 */
				bool reset() noexcept;
				/**
				 * \~russian
				 * @brief Метод перехода потока к данным
				 *
				 * @param direction направление потока: единица - зашифрование, двойка - расшифрование
				 * @return          признак допустимости перехода
				 *
				 * @details Неполный блок связанных данных дополняется нулями и поглощается здесь:
				 *          счётчик метки непрерывен через обе части сообщения
				 *
				 * \~english
				 * @brief Method of the transition of the stream to the data
				 *
				 * @param direction the direction of the stream: one - encryption, two - decryption
				 * @return          the flag of the admissibility of the transition
				 *
				 * @details The incomplete block of the associated data is padded with zeroes and absorbed here:
				 *          the counter of the tag is continuous through both parts of the message
				 *
				 * \~
				 */
				bool proceed(const uint8_t direction) noexcept;
				/**
				 * \~russian
				 * @brief Метод поглощения неполного блока метки с дополнением нулями
				 *
				 * @return признак успешности поглощения
				 *
				 * \~english
				 * @brief Method of the absorption of the incomplete block of the tag with the padding by zeroes
				 *
				 * @return the flag of the success of the absorption
				 *
				 * \~
				 */
				bool flush() noexcept;
				/**
				 * \~russian
				 * @brief Метод умножения целого блока на выход шифра от счётчика метки
				 *
				 * @param data поглощаемый целый блок
				 * @return     признак успешности умножения
				 *
				 * \~english
				 * @brief Method of the multiplication of a whole block by the output of the cipher from the counter of the tag
				 *
				 * @param data the whole block being absorbed
				 * @return     the flag of the success of the multiplication
				 *
				 * \~
				 */
				bool mark(const uint8_t * data) noexcept;
				/**
				 * \~russian
				 * @brief Метод сложения части сообщения в накопитель метки
				 *
				 * @param data поглощаемые байты
				 * @param size число поглощаемых байтов
				 * @return     признак успешности сложения
				 *
				 * \~english
				 * @brief Method of the addition of a part of the message into the accumulator of the tag
				 *
				 * @param data the bytes being absorbed
				 * @param size the number of the bytes being absorbed
				 * @return     the flag of the success of the addition
				 *
				 * \~
				 */
				bool absorb(const uint8_t * data, const size_t size) noexcept;
				/**
				 * \~russian
				 * @brief Метод наложения гаммы на кусок сообщения
				 *
				 * @param source преобразуемый кусок
				 * @param result место, в которое помещается преобразованный кусок
				 * @return       признак успешности наложения гаммы
				 *
				 * \~english
				 * @brief Method of the application of the gamma to a chunk of the message
				 *
				 * @param source the chunk being transformed
				 * @param result the place the transformed chunk is put into
				 * @return       the flag of the success of the application of the gamma
				 *
				 * \~
				 */
				bool cover(const view_t & source, uint8_t * result) noexcept;
				/**
				 * \~russian
				 * @brief Метод замыкания метки целостности
				 *
				 * @param result место, в которое помещается метка длиной в блок шифра
				 * @return       признак успешности замыкания метки
				 *
				 * \~english
				 * @brief Method of the closing of the authentication tag
				 *
				 * @param result the place the tag of a length of a block of the cipher is put into
				 * @return       the flag of the success of the closing of the tag
				 *
				 * \~
				 */
				bool authenticate(uint8_t * result) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод проверки готовности режима к работе
				 *
				 * @return признак готовности режима к работе
				 *
				 * \~english
				 * @brief Method of checking the readiness of the mode for the work
				 *
				 * @return the flag of the readiness of the mode for the work
				 *
				 * \~
				 */
				bool ready() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения длины метки целостности
				 *
				 * @return длина метки целостности в байтах
				 *
				 * \~english
				 * @brief Method of getting the length of the authentication tag
				 *
				 * @return the length of the authentication tag in bytes
				 *
				 * \~
				 */
				size_t size() const noexcept;
				/**
				 * \~russian
				 * @brief Метод запуска режима работы
				 *
				 * @param block базовый алгоритм блочного шифрования
				 * @param nonce начальное заполнение счётчика длиной в блок шифра с нулевым старшим разрядом
				 * @param size  длина метки целостности в байтах, ноль означает длину блока шифра
				 * @return      признак успешности запуска режима работы
				 *
				 * \~english
				 * @brief Method of the start of the mode of operation
				 *
				 * @param block the base block encryption algorithm
				 * @param nonce the initial counter nonce of a length of a block of the cipher with a zero senior bit
				 * @param size  the length of the authentication tag in bytes, a zero means the length of the block of the cipher
				 * @return      the flag of the success of the start of the mode of operation
				 *
				 * \~
				 */
				bool start(const block_t & block, const view_t & nonce, const size_t size = 0) noexcept;
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
				/**
				 * \~russian
				 * @brief Метод смены начального заполнения счётчика без смены шифра
				 *
				 * @param nonce новое начальное заполнение длиной в блок шифра с нулевым старшим разрядом
				 * @return      признак успешности смены заполнения
				 *
				 * @details Заполнение новое: прежнее израсходованным более не считается, состояние
				 *          потока сбрасывается. Базовый шифр и длина метки остаются прежними
				 *
				 * \~english
				 * @brief Method of the change of the initial counter nonce without the change of the cipher
				 *
				 * @param nonce the new initial nonce of a length of a block of the cipher with a zero senior bit
				 * @return      the flag of the success of the change of the nonce
				 *
				 * @details The nonce is new: the previous one is no longer considered spent, the state of the
				 *          stream is reset. The base cipher and the length of the tag remain the same
				 *
				 * \~
				 */
				bool restart(const view_t & nonce) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод подачи связанных данных потоком
				 *
				 * @param associated связанные данные, целостность которых проверяется без их зашифрования
				 * @return           признак успешности подачи
				 *
				 * @note Подавать связанные данные дозволено лишь до первого куска сообщения
				 *
				 * \~english
				 * @brief Method of the feeding of the associated data by the stream
				 *
				 * @param associated the associated data the integrity of which is checked without their encryption
				 * @return           the flag of the success of the feeding
				 *
				 * @note The associated data is allowed to be fed only before the first chunk of the message
				 *
				 * \~
				 */
				bool associate(const view_t & associated) noexcept;
				/**
				 * \~russian
				 * @brief Метод поточного зашифрования куска
				 *
				 * @param source открытый текст
				 * @param result место, в которое помещается шифртекст той же длины
				 * @return       признак успешности зашифрования
				 *
				 * @note Место итога вправе совпадать с местом исходного куска
				 *
				 * \~english
				 * @brief Method of the streaming encryption of a chunk
				 *
				 * @param source the plain text
				 * @param result the place the cipher text of the same length is put into
				 * @return       the flag of the success of the encryption
				 *
				 * @note The place of the result may coincide with the place of the source chunk
				 *
				 * \~
				 */
				bool encrypt(const view_t & source, uint8_t * result) noexcept;
				/**
				 * \~russian
				 * @brief Метод поточного расшифрования куска
				 *
				 * @param source шифртекст
				 * @param result место, в которое помещается открытый текст той же длины
				 * @return       признак успешности расшифрования
				 *
				 * @note Открытый текст потока не проверен меткой до схождения verify: пользоваться
				 *       им дозволено лишь после успешного сличения метки
				 *
				 * \~english
				 * @brief Method of the streaming decryption of a chunk
				 *
				 * @param source the cipher text
				 * @param result the place the plain text of the same length is put into
				 * @return       the flag of the success of the decryption
				 *
				 * @note The plain text of the stream is not checked by the tag until verify converges: it is
				 *       allowed to be used only after the successful comparison of the tag
				 *
				 * \~
				 */
				bool decrypt(const view_t & source, uint8_t * result) noexcept;
				/**
				 * \~russian
				 * @brief Метод завершения поточного зашифрования выработкой метки
				 *
				 * @param tag место, в которое помещается метка установленной длины
				 * @return    признак успешности завершения; поток закрывается
				 *
				 * \~english
				 * @brief Method of the completion of the streaming encryption by the production of the tag
				 *
				 * @param tag the place the tag of the established length is put into
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
				 * @return    признак схождения метки за постоянное время; поток закрывается
				 *
				 * \~english
				 * @brief Method of the completion of the streaming decryption by the comparison of the tag
				 *
				 * @param tag the tag of the established length being checked
				 * @return    the flag of the convergence of the tag in constant time; the stream is closed
				 *
				 * \~
				 */
				bool verify(const view_t & tag) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод зашифрования сообщения с выработкой метки целостности
				 *
				 * @param associated связанные данные, целостность которых проверяется без их зашифрования
				 * @param source     зашифровываемое сообщение
				 * @param result     место, в которое помещается шифртекст
				 * @param tag        место, в которое помещается метка целостности
				 * @return           признак успешности зашифрования
				 *
				 * @note Место итога вправе совпадать с местом исходного сообщения
				 *
				 * @note Повторное зашифрование на том же начальном заполнении счётчика
				 *       отвергается: перед следующим зашифрованием режим обязан быть запущен
				 *       заново с новым заполнением
				 *
				 * \~english
				 * @brief Method of the encryption of a message with the production of the authentication tag
				 *
				 * @param associated the associated data the integrity of which is checked without their encryption
				 * @param source     the message being encrypted
				 * @param result     the place the cipher text is put into
				 * @param tag        the place the authentication tag is put into
				 * @return           the flag of the success of the encryption
				 *
				 * @note The place of the result may coincide with the place of the source message
				 *
				 * @note A repeated encryption under the same initial counter nonce is refused: before
				 *       the next encryption the mode must be started anew with a new nonce
				 *
				 * \~
				 */
				bool encrypt(const view_t & associated, const view_t & source, uint8_t * result, uint8_t * tag) noexcept;
				/**
				 * \~russian
				 * @brief Метод расшифрования сообщения с проверкой метки целостности
				 *
				 * @param associated связанные данные, целостность которых проверяется без их расшифрования
				 * @param source     расшифровываемый шифртекст
				 * @param result     место, в которое помещается открытый текст
				 * @param tag        проверяемая метка целостности
				 * @return           признак успешности расшифрования
				 *
				 * @note Открытый текст записывается лишь после успешной проверки метки
				 *       целостности: расшифрованное сообщение с непроверенной меткой
				 *       выдавать наружу нельзя
				 *
				 * @note Метка целостности сличается за постоянное время
				 *
				 * \~english
				 * @brief Method of the decryption of a message with the check of the authentication tag
				 *
				 * @param associated the associated data the integrity of which is checked without their decryption
				 * @param source     the cipher text being decrypted
				 * @param result     the place the plain text is put into
				 * @param tag        the authentication tag being checked
				 * @return           the flag of the success of the decryption
				 *
				 * @note The plain text is written only after a successful check of the authentication
				 *       tag: a decrypted message with an unchecked tag must not be given outside
				 *
				 * @note The authentication tag is compared in a constant time
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
				Galois() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Galois() noexcept;
		} galois_t;
	};
};

