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

