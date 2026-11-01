/**
 * @file gost.hpp
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
 * @brief Заголовочный файл модуля выработки и проверки электронной подписи по
 *        ГОСТ Р 34.10-2012
 *
 * \~english
 * @brief Header file of the module of the production and the check of an electronic
 *        signature according to GOST R 34.10-2012
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
#include <math/number.hpp>
#include <curve/curve.hpp>

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
	 * @brief Пространство имён модулей электронной подписи
	 *
	 * \~english
	 * @brief Namespace of the electronic signature modules
	 *
	 * \~
	 */
	namespace sign {
		/**
		 * \~russian
		 * @brief Электронная подпись по ГОСТ Р 34.10-2012
		 *
		 * @details Подпись состоит из двух чисел r и s, записанных подряд от старшего
		 *          байта к младшему, каждое длиной в порядок подгруппы точек кривой.
		 *
		 * @note Случайное число выработки подписи передаётся вызывающей стороной, а не
		 *       вырабатывается самим модулем: своего источника случайности у библиотеки
		 *       пока нет, и подделывать его видимость хуже, чем назвать вслух
		 *
		 * @note Значение случайного числа обязано быть непредсказуемым и неповторимым:
		 *       повтор его на одном ключе выдаёт сам ключ подписи
		 *
		 * \~english
		 * @brief Electronic signature according to GOST R 34.10-2012
		 *
		 * @details The signature consists of the two numbers r and s written in a row from
		 *          the senior byte to the junior one, each of a length of the order of the
		 *          subgroup of the points of the curve.
		 *
		 * @note The random number of the production of the signature is passed by the calling
		 *       side and is not produced by the module itself: the library has no source of
		 *       the randomness of its own yet, and to counterfeit its appearance is worse than
		 *       to name it aloud
		 *
		 * @note The value of the random number must be unpredictable and unique: a repetition
		 *       of it under a single key gives away the key of the signature itself
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Gost {
			private:
				// Признак того, что ключ подписи установлен
				bool _secret;
				// Признак того, что ключ проверки подписи установлен
				bool _public;
			private:
				// Эллиптическая кривая выработки подписи
				const curve::curve_t * _curve;
			private:
				// Ключ подписи
				math::number_t _key;
				// Ключ проверки подписи
				curve::point_t _point;
			public:
				/**
				 * \~russian
				 * @brief Метод проверки готовности модуля к работе
				 *
				 * @return признак того, что кривая установлена
				 *
				 * \~english
				 * @brief Method of checking the readiness of the module for the work
				 *
				 * @return the flag of the curve being set
				 *
				 * \~
				 */
				bool ready() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения размера подписи
				 *
				 * @return размер подписи в байтах
				 *
				 * \~english
				 * @brief Method of getting the size of a signature
				 *
				 * @return the size of a signature in bytes
				 *
				 * \~
				 */
				size_t size() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения верхнего предела длины подписи в записанном виде
				 *
				 * @return верхний предел длины подписи в байтах, ноль без ключа
				 *
				 * @details Метод size выдаёт длину сырой подписи, под которую заводится место
				 *          для make, а limit - наибольшую длину подписи в том виде, в котором она
				 *          уходит наружу: она не превышается ни при каком значении подписи, как
				 *          у EVP_PKEY_size. Подпись ГОСТ Р 34.10-2012 уходит наружу как есть - двумя числами длиной в
				 *          порядок подгруппы, оттого предел равен size: 64 байта у кривых в 256
				 *          разрядов и 128 у кривых в 512 разрядов
				 *
				 * \~english
				 * @brief Method of getting the upper limit of the length of a signature in the written form
				 *
				 * @return the upper limit of the length of a signature in bytes, zero without a key
				 *
				 * @details The method size gives the length of a raw signature the place for make is
				 *          allocated by, while limit gives the greatest length of a signature in the form
				 *          it goes outside in: it is not exceeded at any value of the signature, like
				 *          EVP_PKEY_size. A signature GOST R 34.10-2012 goes outside as is - by two numbers of the length of
				 *          the order of the subgroup, therefore the limit equals size: 64 bytes at the
				 *          curves of 256 bits and 128 at the curves of 512 bits
				 *
				 * \~
				 */
				size_t limit() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки эллиптической кривой
				 *
				 * @param curve устанавливаемая эллиптическая кривая
				 * @return      признак успешности установки эллиптической кривой
				 *
				 * @note Кривая должна пережить модуль подписи: она не переносится, а берётся
				 *       по указателю
				 *
				 * \~english
				 * @brief Method of setting the elliptic curve
				 *
				 * @param curve the elliptic curve being set
				 * @return      the flag of the success of the setting of the elliptic curve
				 *
				 * @note The curve must outlive the module of the signature: it is not moved but
				 *       is taken by a pointer
				 *
				 * \~
				 */
				bool start(const curve::curve_t & curve) noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса состояния модуля
				 *
				 * \~english
				 * @brief Method of the reset of the state of the module
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод установки ключа подписи
				 *
				 * @param secret устанавливаемый ключ подписи
				 * @return       признак успешности установки ключа подписи
				 *
				 * @note Ключ проверки подписи вырабатывается из ключа подписи сразу же
				 *
				 * \~english
				 * @brief Method of setting the key of the signature
				 *
				 * @param secret the key of the signature being set
				 * @return       the flag of the success of the setting of the key of the signature
				 *
				 * @note The key of the check of the signature is produced from the key of the signature at once
				 *
				 * \~
				 */
				bool secret(const view_t & secret) noexcept;
				/**
				 * \~russian
				 * @brief Метод порождения долговременного ключа подписи
				 *
				 * @param secret место, в которое записывается ключ подписи, записанный от старшего байта к младшему
				 * @param size   размер места ключа подписи
				 * @return       признак успешности порождения ключа подписи
				 *
				 * @details Ключ подписи берётся равномерно из отрезка [1, q-1], где q - порядок подгруппы
				 *          точек кривой, отбором: случайные байты длиной порядка, не меньшие порядка
				 *          либо нулевые, отбрасываются целиком и берутся заново, а не приводятся по
				 *          модулю. Приведение сделало бы младшие значения вероятнее прочих, что у
				 *          кривых с порядком заметно меньше степени двойки - половина кривых ГОСТ -
				 *          особенно заметно, а смещённый ключ вскрывается по множеству подписей.
				 *          Размер места обязан равняться длине порядка подгруппы
				 *
				 * @note Порождённый ключ устанавливается в модуль так же, как при secret: ключ
				 *       проверки подписи вырабатывается сразу же. Отказ источника случайности
				 *       отвечает отказом порождения, прежнее состояние модуля при этом сброшено
				 *
				 * \~english
				 * @brief Method of the generation of a long-term key of the signature
				 *
				 * @param secret the place the key of the signature written from the senior byte to the junior one is written into
				 * @param size   the size of the place of the key of the signature
				 * @return       the flag of the success of the generation of the key of the signature
				 *
				 * @details The key of the signature is taken uniformly from the segment [1, q-1], where q is the
				 *          order of the subgroup of the points of the curve, by a selection: random bytes of
				 *          the length of the order that are not less than the order or zero are discarded
				 *          entirely and taken anew, and are not reduced by the modulus. A reduction would
				 *          make the junior values more probable than the rest, which is especially noticeable
				 *          at the curves with an order noticeably less than a power of two - a half of the
				 *          GOST curves, - while a biased key is uncovered by a multitude of signatures. The
				 *          size of the place must equal the length of the order of the subgroup
				 *
				 * @note The generated key is set into the module the same way as at secret: the key of
				 *       the check of the signature is produced at once. A refusal of the source of the
				 *       randomness answers by a refusal of the generation, the former state of the module
				 *       is reset at that
				 *
				 * \~
				 */
				bool generate(uint8_t * secret, const size_t size) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки ключа проверки подписи
				 *
				 * @param x первая координата ключа проверки подписи
				 * @param y вторая координата ключа проверки подписи
				 * @return  признак успешности установки ключа проверки подписи
				 *
				 * @note Если ключ подписи уже установлен, открытый ключ из него выведен:
				 *       поданный обязан сойтись с выведенным, тогда состояние не меняется,
				 *       а чужой отвергается. Закрытый ключ этим вызовом не затирается
				 *
				 * \~english
				 * @brief Method of setting the key of the check of the signature
				 *
				 * @param x the first coordinate of the key of the check of the signature
				 * @param y the second coordinate of the key of the check of the signature
				 * @return  the flag of the success of the setting of the key of the check of the signature
				 *
				 * @note If the signing key is already set, the public key is derived from it: the given one
				 *       must coincide with the derived one, then the state does not change, and a foreign one
				 *       is rejected. The private key is not wiped by this call
				 *
				 * \~
				 */
				bool key(const view_t & x, const view_t & y) noexcept;
				/**
				 * \~russian
				 * @brief Метод получения ключа проверки подписи
				 *
				 * @param x    место, в которое записывается первая координата ключа проверки подписи
				 * @param y    место, в которое записывается вторая координата ключа проверки подписи
				 * @param size размер места, в которое записывается всякая координата
				 * @return     признак успешности получения ключа проверки подписи
				 *
				 * \~english
				 * @brief Method of getting the key of the check of the signature
				 *
				 * @param x    the place the first coordinate of the key of the check of the signature is written into
				 * @param y    the place the second coordinate of the key of the check of the signature is written into
				 * @param size the size of the place every coordinate is written into
				 * @return     the flag of the success of the getting of the key of the check of the signature
				 *
				 * \~
				 */
				bool key(uint8_t * x, uint8_t * y, const size_t size) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод выработки подписи
				 *
				 * @param digest хеш подписываемого сообщения, записанный от старшего байта к младшему
				 * @param random случайное число выработки подписи
				 * @param result место, в которое помещается подпись
				 * @return       признак успешности выработки подписи
				 *
				 * @note Отказ выработки при годном ключе означает неудачный выбор случайного
				 *       числа: раздел 6.1 ГОСТ Р 34.10-2012 велит в этом случае выбрать
				 *       новое число и повторить выработку
				 *
				 * \~english
				 * @brief Method of the production of a signature
				 *
				 * @param digest the hash of the message being signed, written from the senior byte to the junior one
				 * @param random the random number of the production of the signature
				 * @param result the place the signature is put into
				 * @return       the flag of the success of the production of the signature
				 *
				 * @note A refusal of the production at a suitable key means an unsuccessful choice of
				 *       the random number: the section 6.1 of GOST R 34.10-2012 orders to choose a new
				 *       number and to repeat the production in this case
				 *
				 * \~
				 */
				bool make(const view_t & digest, const view_t & random, uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод выработки подписи со своим случайным числом
				 *
				 * @param digest хеш подписываемого сообщения, записанный от старшего байта к младшему
				 * @param result место, в которое помещается подпись
				 * @return       признак успешности выработки подписи
				 *
				 * @note Случайное число берётся у источника случайности системы, а неудачный
				 *       его выбор разбирается повтором выработки, как того и требует раздел
				 *       6.1 ГОСТ Р 34.10-2012
				 *
				 * @note Отказ источника случайности означает отказ выработки подписи: подменять
				 *       случайное число чем бы то ни было нельзя
				 *
				 * \~english
				 * @brief Method of the production of a signature with a random number of its own
				 *
				 * @param digest the hash of the message being signed, written from the senior byte to the junior one
				 * @param result the place the signature is put into
				 * @return       the flag of the success of the production of the signature
				 *
				 * @note The random number is taken from the source of the randomness of the system,
				 *       while an unsuccessful choice of it is handled by a repetition of the production,
				 *       as the section 6.1 of GOST R 34.10-2012 requires
				 *
				 * @note A refusal of the source of the randomness means a refusal of the production of
				 *       the signature: it is forbidden to substitute the random number by anything whatsoever
				 *
				 * \~
				 */
				bool make(const view_t & digest, uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки подписи
				 *
				 * @param digest    хеш подписанного сообщения, записанный от старшего байта к младшему
				 * @param signature проверяемая подпись
				 * @return          признак того, что подпись сошлась
				 *
				 * \~english
				 * @brief Method of the check of a signature
				 *
				 * @param digest    the hash of the signed message, written from the senior byte to the junior one
				 * @param signature the signature being checked
				 * @return          the flag of the signature having converged
				 *
				 * \~
				 */
				bool check(const view_t & digest, const view_t & signature) const noexcept;
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
				Gost() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Gost() noexcept;
		} gost_t;
	};
};

