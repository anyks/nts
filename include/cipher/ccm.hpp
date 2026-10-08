/**
 * @file ccm.hpp
 * @date 2026-10-04
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
 * @brief Заголовочный файл модуля режима шифрования с проверкой целостности CCM
 *        по RFC 3610
 *
 * \~english
 * @brief Header file of the CCM authenticated encryption mode module
 *        according to RFC 3610
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
		 * @brief Длина метки целостности CCM по умолчанию в байтах
		 *
		 * \~english
		 * @brief Default length of the CCM authentication tag in bytes
		 *
		 * \~
		 */
		static constexpr size_t CCM_TAG = 16;

		/**
		 * \~russian
		 * @brief Режим шифрования с проверкой целостности CCM
		 *
		 * @details RFC 3610 и NIST SP 800-38C. Метка целостности вырабатывается
		 *          имитовставкой CBC-MAC над форматированным сообщением: блок B0 с
		 *          признаками и длиной, связанные данные с их длиной и сам открытый
		 *          текст; зашифрование идёт гаммированием со счётчиком, а метка
		 *          накладывается суммой с первым блоком гаммы. Длина одноразового
		 *          значения задаёт длину поля длины сообщения: L = 15 - nonce
		 *
		 * @note Начальное заполнение для всякого сообщения на одном ключе обязано быть
		 *       неповторимым: повтор раскрывает сумму открытых текстов
		 *
		 * @note Разовый договор: сообщение подаётся целиком, как того требует защита
		 *       записей TLS (раздел 5.2 RFC 8446 и RFC 8998): у CCM метка зависит от
		 *       длины сообщения, и поточная подача без заранее известной длины режиму
		 *       не подлежит. Метка сличается за постоянное время
		 *
		 * \~english
		 * @brief CCM authenticated encryption mode
		 * @details RFC 3610 and NIST SP 800-38C. The authentication tag is produced by the
		 *          CBC-MAC authentication code over the formatted message: the block B0 with
		 *          the flags and the length, the associated data with their length and the
		 *          plain text itself; the encryption goes by the gamma with a counter, while
		 *          the tag is overlaid by a sum with the first block of the gamma. The length
		 *          of the nonce sets the length of the message length field: L = 15 - nonce
		 * @note The nonce of every message under a single key must be unique: a repetition
		 *       reveals the sum of the plain texts
		 * @note The one-shot contract: the message is fed entirely, as the protection of the
		 *       TLS records requires (the section 5.2 of RFC 8446 and RFC 8998): at CCM the
		 *       tag depends on the length of the message, and a streaming feeding without a
		 *       length known in advance is not subject to the mode. The tag is compared in
		 *       constant time
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Ccm {
			private:
				// Признак того, что режим готов к работе
				bool _ready;
			private:
				// Длина метки целостности в байтах
				size_t _size;
				// Длина поля длины сообщения в байтах
				size_t _width;
			private:
				// Базовый алгоритм блочного шифрования
				block_t _block;
			private:
				// Начальное заполнение режима
				uint8_t _nonce[13];
				// Длина начального заполнения режима
				size_t _length;
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
				 * @param nonce начальное заполнение режима
				 * @param size  длина метки целостности в байтах: чётная, от 4 до 16
				 *
				 * @return      признак успешности запуска режима работы
				 *
				 * @note Базовый шифр обязан иметь блок в 16 байтов: иного RFC 3610 не ведёт
				 *
				 * \~english
				 * @brief Method of starting the mode of the work
				 * @param block the base block encryption algorithm
				 * @param nonce the nonce of the mode
				 * @param size  the length of the authentication tag in bytes: even, from 4 to 16
				 * @return the flag of the success of the starting of the mode of the work
				 * @note The base cipher must have a block of 16 bytes: RFC 3610 knows no other
				 *
				 * \~
				 */
				bool start(const block_t & block, const view_t & nonce, const size_t size = CCM_TAG) noexcept;
			/**
			 * \~russian
			 * @brief Метод смены начального заполнения режима
			 *
			 * @param nonce новое начальное заполнение режима
			 *
			 * @return      признак успешности смены начального заполнения
			 *
			 * @note Базовый шифр и длина метки остаются от запуска: меняется лишь
			 *       одноразовое значение, как того требует защита записей TLS на одном
			 *       ключе направления
			 *
			 * \~english
			 * @brief Method of the change of the nonce of the mode
			 * @param nonce the new nonce of the mode
			 * @return the flag of the success of the change of the nonce
			 * @note The base cipher and the length of the tag remain from the start: only
			 *       the nonce changes, as the protection of the TLS records requires under
			 *       a single key of a direction
			 *
			 * \~
			 */
			bool restart(const view_t & nonce) noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса состояния режима работы
				 *
				 * \~english
				 * @brief Method of the reset of the state of the mode of the work
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод зашифрования сообщения с выработкой метки целостности
				 *
				 * @param associated связанные данные
				 * @param source     зашифровываемое сообщение
				 * @param result     место, в которое помещается зашифрованное сообщение
				 * @param tag        место, в которое помещается метка целостности
				 *
				 * @return признак успешности зашифрования
				 *
				 * @note Место итога вправе совпадать с местом исходного сообщения
				 *
				 * \~english
				 * @brief Method of the encryption of a message with the production of the authentication tag
				 * @param associated the associated data
				 * @param source     the message being encrypted
				 * @param result     the place the encrypted message is put into
				 * @param tag        the place the authentication tag is put into
				 * @return the flag of the success of the encryption
				 * @note The place of the result may coincide with the place of the source message
				 *
				 * \~
				 */
				bool encrypt(const view_t & associated, const view_t & source, uint8_t * result, uint8_t * tag) noexcept;
				/**
				 * \~russian
				 * @brief Метод расшифрования сообщения с проверкой метки целостности
				 *
				 * @param associated связанные данные
				 * @param source     расшифровываемое сообщение
				 * @param tag        проверяемая метка целостности
				 * @param result     место, в которое помещается расшифрованное сообщение
				 *
				 * @return признак того, что метка целостности сошлась
				 *
				 * @note При несошедшейся метке место итога затирается
				 *
				 * \~english
				 * @brief Method of the decryption of a message with the check of the authentication tag
				 * @param associated the associated data
				 * @param source     the message being decrypted
				 * @param tag        the authentication tag being checked
				 * @param result     the place the decrypted message is put into
				 * @return the flag of the authentication tag having converged
				 * @note At a non-converged tag the place of the result is wiped
				 *
				 * \~
				 */
				bool decrypt(const view_t & associated, const view_t & source, const view_t & tag, uint8_t * result) noexcept;
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
				Ccm() noexcept;
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
				~Ccm() noexcept;
		} ccm_t;
	};
};

