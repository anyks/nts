/**
 * @file poly1305.hpp
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
 * @brief Заголовочный файл имитовставки Poly1305 по RFC 8439
 *
 * \~english
 * @brief Header file of the Poly1305 one-time authenticator according to RFC 8439
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_POLY1305__
#define __ANTS_POLY1305__

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
		 * @brief Размер ключа имитовставки Poly1305 в байтах
		 *
		 * \~english
		 * @brief Size of the key of the Poly1305 authenticator in bytes
		 *
		 * \~
		 */
		static constexpr size_t POLY1305_KEY = 32;

		/**
		 * \~russian
		 * @brief Размер метки имитовставки Poly1305 в байтах
		 *
		 * \~english
		 * @brief Size of the tag of the Poly1305 authenticator in bytes
		 *
		 * \~
		 */
		static constexpr size_t POLY1305_TAG = 16;

		/**
		 * \~russian
		 * @brief Имитовставка Poly1305
		 *
		 * @details RFC 8439, раздел 2.5. Ключ в 32 байта делится на r и s: r
		 *          обрезается по стандарту, сообщение читается блоками по 16 байтов
		 *          с добавленным старшим байтом в единицу, накопитель умножается на r
		 *          по модулю 2^130 - 5, и метка есть накопитель, сложенный с s по
		 *          модулю 2^128
		 *
		 * @note Ключ одноразовый: две метки на одном ключе раскрывают r, а с ним и
		 *       возможность подделки. У AEAD ключ вырабатывается на каждое сообщение
		 *
		 * @note Намеренные решения: арифметика на пяти конечностях по 26 разрядов с
		 *       произведениями в 64 разряда; ни деления, ни ветвления по данным -
		 *       окончательное приведение выбирает между накопителем и накопителем
		 *       минус модуль маской. Целые блоки складываются парами по разделу
		 *       2.5.1 RFC 8439: (h + m0) * r^2 + m1 * r, где оба произведения
		 *       независимы, а переносы проводятся один раз на пару; квадрат r
		 *       считается при запуске, итог тот же, что и поблочно. Памяти не
		 *       выделяется, исключений нет. Снятие метки finish завершает объект:
		 *       повтор требует нового start
		 *
		 * \~english
		 * @brief The Poly1305 one-time authenticator
		 * @details RFC 8439, section 2.5. The 32-byte key is split into r and s: r is clamped
		 *          by the standard, the message is read by 16-byte blocks with an appended high
		 *          byte of one, the accumulator is multiplied by r modulo 2^130 - 5, and the tag is
		 *          the accumulator added to s modulo 2^128
		 * @note The key is one-time: two tags under a single key reveal r and with it the ability
		 *       of a forgery. At AEAD the key is produced for every message
		 * @note Deliberate decisions: the arithmetic on five 26-bit limbs with 64-bit products;
		 *       neither division nor data-dependent branching - the final reduction chooses between
		 *       the accumulator and the accumulator minus the modulus by a mask. The whole blocks
		 *       are absorbed by pairs according to section 2.5.1 of RFC 8439: (h + m0) * r^2 + m1 * r,
		 *       where both products are independent and the carries are propagated once per pair;
		 *       the square of r is computed at the start, the result is the same as block by block.
		 *       No memory is allocated, there are no exceptions. The taking of the tag by finish
		 *       finishes the object: a repetition requires a new start
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Poly1305 {
			private:
				// Признак того, что имитовставка готова к работе
				bool _ready;
			private:
				// Число накопленных байтов неполного блока
				size_t _filled;
			private:
				// Обрезанный множитель r по 26 разрядов
				uint32_t _r[5];
				// Квадрат множителя r по 26 разрядов: под сложение блоков парами
				uint32_t _r2[5];
				// Накопитель по 26 разрядов
				uint32_t _h[5];
				// Слагаемое s по 32 разряда
				uint32_t _s[4];
			private:
				// Неполный блок сообщения
				uint8_t _pending[POLY1305_TAG];
			private:
				/**
				 * \~russian
				 * @brief Метод сложения целых блоков в накопитель
				 *
				 * @param data  складываемые байты, кратные блоку
				 * @param size  число складываемых байтов
				 * @param last  признак последнего неполного блока без старшего разряда
				 *
				 * \~english
				 * @brief Method of the addition of whole blocks into the accumulator
				 * @param data  the bytes being added, multiple of the block
				 * @param size  the number of the bytes being added
				 * @param last  the flag of the last partial block without the high bit
				 *
				 * \~
				 */
				void absorb(const uint8_t * data, const size_t size, const bool last) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод проверки готовности имитовставки к работе
				 *
				 * @return признак готовности имитовставки
				 *
				 * \~english
				 * @brief Method of checking the readiness of the authenticator for the work
				 * @return the flag of the readiness of the authenticator
				 *
				 * \~
				 */
				bool ready() const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод запуска имитовставки
				 *
				 * @param key одноразовый ключ в 32 байта
				 *
				 * @return    признак успешности запуска
				 *
				 * \~english
				 * @brief Method of the start of the authenticator
				 * @param key the 32-byte one-time key
				 * @return    the flag of the success of the start
				 *
				 * \~
				 */
				bool start(const view_t & key) noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса имитовставки с затиранием состояния
				 *
				 * \~english
				 * @brief Method of the reset of the authenticator with the wiping of the state
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод подачи куска сообщения
				 *
				 * @param source кусок сообщения любой длины, включая пустой
				 *
				 * @return       признак успешности подачи
				 *
				 * \~english
				 * @brief Method of the feeding of a chunk of the message
				 * @param source the chunk of the message of any length, including an empty one
				 * @return       the flag of the success of the feeding
				 *
				 * \~
				 */
				bool update(const view_t & source) noexcept;
				/**
				 * \~russian
				 * @brief Метод снятия метки
				 *
				 * @param tag место в 16 байтов, в которое записывается метка
				 *
				 * @return    признак успешности снятия; объект завершается
				 *
				 * \~english
				 * @brief Method of the taking of the tag
				 * @param tag the 16-byte place the tag is written into
				 * @return    the flag of the success of the taking; the object is finished
				 *
				 * \~
				 */
				bool finish(uint8_t * tag) noexcept;
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
				Poly1305() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Poly1305() noexcept;
		} poly1305_t;
	};
};

#endif // __ANTS_POLY1305__
