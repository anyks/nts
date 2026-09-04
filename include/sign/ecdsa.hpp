/**
 * @file ecdsa.hpp
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
 * @brief Заголовочный файл модуля выработки и проверки электронной подписи ECDSA
 *        по FIPS 186-5 и SEC 1
 *
 * \~english
 * @brief Header file of the module of the production and the check of an electronic
 *        signature ECDSA according to FIPS 186-5 and SEC 1
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_ECDSA__
#define __ANTS_ECDSA__

/**
 * Стандартные заголовочные файлы
 */
#include <vector>
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <math/number.hpp>
#include <curve/curve.hpp>
#include <digest/hash.hpp>

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
		 * @brief Электронная подпись ECDSA по FIPS 186-5 и разделу 4.1 SEC 1
		 *
		 * @details Подпись состоит из двух чисел r и s, записанных подряд от старшего
		 *          байта к младшему, каждое длиной в порядок подгруппы точек кривой:
		 *          64 байта у кривой P-256 и 96 байтов у кривой P-384. Запись подписи
		 *          в виде SEQUENCE {INTEGER r, INTEGER s} по разделу C.5 SEC 1 выполняют
		 *          отдельные методы encode и decode.
		 *
		 * @details Хеш сообщения обращается в число по разделу 4.1.3 SEC 1: берутся его
		 *          старшие разряды в числе, равном разрядности порядка подгруппы, а
		 *          хеш короче порядка берётся целиком.
		 *
		 * @note Случайное число выработки подписи либо передаётся вызывающей стороной,
		 *       либо выводится из ключа и хеша по RFC 6979: выведенное число не
		 *       требует источника случайности и повторяется на одних и тех же
		 *       данных, оттого подпись по RFC 6979 воспроизводима
		 *
		 * @note Значение переданного случайного числа обязано быть непредсказуемым и
		 *       неповторимым: повтор его на одном ключе выдаёт сам ключ подписи
		 *
		 * \~english
		 * @brief Electronic signature ECDSA according to FIPS 186-5 and the section 4.1 of SEC 1
		 * @details The signature consists of the two numbers r and s written in a row from
		 *          the senior byte to the junior one, each of a length of the order of the
		 *          subgroup of the points of the curve: 64 bytes at the curve P-256 and 96
		 *          bytes at the curve P-384. The writing of the signature in the form of
		 *          SEQUENCE {INTEGER r, INTEGER s} according to the section C.5 of SEC 1 is
		 *          performed by the separate methods encode and decode.
		 * @details The hash of the message is turned into a number according to the section
		 *          4.1.3 of SEC 1: its senior bits are taken in the number equal to the bit
		 *          width of the order of the subgroup, while a hash shorter than the order is
		 *          taken entirely.
		 * @note The random number of the production of the signature is either passed by the
		 *       calling side or is derived from the key and the hash according to RFC 6979:
		 *       the derived number does not require a source of the randomness and repeats
		 *       on the same data, therefore the signature according to RFC 6979 is reproducible
		 * @note The value of the passed random number must be unpredictable and unique: a
		 *       repetition of it under a single key gives away the key of the signature itself
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Ecdsa {
			private:
				// Признак того, что ключ подписи установлен
				bool _secret;
				// Признак того, что ключ проверки подписи установлен
				bool _public;
			private:
				// Разрядность порядка подгруппы точек кривой
				size_t _bits;
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
				 *          у EVP_PKEY_size. Подпись ECDSA уходит наружу записью SEQUENCE {INTEGER r, INTEGER s} по
				 *          sign::encode, а её длина зависит от значений: число со взведённым старшим
				 *          разрядом получает ведущий нулевой байт. Предел считается по наихудшему
				 *          случаю - ведущий нуль у обоих чисел: 72 байта у P-256 и 104 у P-384
				 *
				 * \~english
				 * @brief Method of getting the upper limit of the length of a signature in the written form
				 * @return the upper limit of the length of a signature in bytes, zero without a key
				 * @details The method size gives the length of a raw signature the place for make is
				 *          allocated by, while limit gives the greatest length of a signature in the form
				 *          it goes outside in: it is not exceeded at any value of the signature, like
				 *          EVP_PKEY_size. A signature ECDSA goes outside by the writing SEQUENCE {INTEGER r, INTEGER s}
				 *          according to sign::encode, while its length depends on the values: a number with
				 *          the senior bit set receives a leading zero byte. The limit is computed by the
				 *          worst case - a leading zero at both numbers: 72 bytes at P-256 and 104 at P-384
				 *
				 * \~
				 */
				size_t limit() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки эллиптической кривой
				 *
				 * @param curve устанавливаемая эллиптическая кривая
				 *
				 * @return признак успешности установки эллиптической кривой
				 *
				 * @note Кривая должна пережить модуль подписи: она не переносится, а берётся
				 *       по указателю
				 *
				 * \~english
				 * @brief Method of setting the elliptic curve
				 * @param curve the elliptic curve being set
				 * @return the flag of the success of the setting of the elliptic curve
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
				 * @param secret устанавливаемый ключ подписи, записанный от старшего байта к младшему
				 *
				 * @return признак успешности установки ключа подписи
				 *
				 * @note Ключ проверки подписи вырабатывается из ключа подписи сразу же
				 *
				 * \~english
				 * @brief Method of setting the key of the signature
				 * @param secret the key of the signature being set, written from the senior byte to the junior one
				 * @return the flag of the success of the setting of the key of the signature
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
				 *
				 * @return признак успешности порождения ключа подписи
				 *
				 * @details Ключ подписи берётся равномерно из отрезка [1, n-1], где n - порядок подгруппы
				 *          точек кривой, отбором по разделу A.2.2 FIPS 186-5: случайные байты длиной
				 *          порядка, не меньшие порядка либо нулевые, отбрасываются целиком и берутся
				 *          заново, а не приводятся по модулю. Приведение сделало бы младшие значения
				 *          вероятнее прочих, а смещённый ключ вскрывается по множеству подписей.
				 *          Размер места обязан равняться длине порядка подгруппы
				 *
				 * @note Порождённый ключ устанавливается в модуль так же, как при secret: ключ
				 *       проверки подписи вырабатывается сразу же. Отказ источника случайности
				 *       отвечает отказом порождения, прежнее состояние модуля при этом сброшено
				 *
				 * \~english
				 * @brief Method of the generation of a long-term key of the signature
				 * @param secret the place the key of the signature written from the senior byte to the junior one is written into
				 * @param size   the size of the place of the key of the signature
				 * @return the flag of the success of the generation of the key of the signature
				 * @details The key of the signature is taken uniformly from the segment [1, n-1], where n is the
				 *          order of the subgroup of the points of the curve, by a selection according to the
				 *          section A.2.2 of FIPS 186-5: random bytes of the length of the order that are not
				 *          less than the order or zero are discarded entirely and taken anew, and are not
				 *          reduced by the modulus. A reduction would make the junior values more probable
				 *          than the rest, while a biased key is uncovered by a multitude of signatures. The
				 *          size of the place must equal the length of the order of the subgroup
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
				 *
				 * @return признак успешности установки ключа проверки подписи
				 *
				 * @note Точка, не принадлежащая кривой, отвергается
				 *
				 * @note Если ключ подписи уже установлен, открытый ключ из него выведен:
				 *       поданный обязан сойтись с выведенным, тогда состояние не меняется,
				 *       а чужой отвергается. Закрытый ключ этим вызовом не затирается
				 *
				 * \~english
				 * @brief Method of setting the key of the check of the signature
				 * @param x the first coordinate of the key of the check of the signature
				 * @param y the second coordinate of the key of the check of the signature
				 * @return the flag of the success of the setting of the key of the check of the signature
				 * @note A point not belonging to the curve is rejected
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
				 *
				 * @return признак успешности получения ключа проверки подписи
				 *
				 * \~english
				 * @brief Method of getting the key of the check of the signature
				 * @param x    the place the first coordinate of the key of the check of the signature is written into
				 * @param y    the place the second coordinate of the key of the check of the signature is written into
				 * @param size the size of the place every coordinate is written into
				 * @return the flag of the success of the getting of the key of the check of the signature
				 *
				 * \~
				 */
				bool key(uint8_t * x, uint8_t * y, const size_t size) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод выработки подписи переданным случайным числом
				 *
				 * @param digest хеш подписываемого сообщения, записанный от старшего байта к младшему
				 * @param random случайное число выработки подписи, записанное от старшего байта к младшему
				 * @param result место, в которое помещается подпись
				 *
				 * @return признак успешности выработки подписи
				 *
				 * @note Отказ выработки при годном ключе означает неудачный выбор случайного
				 *       числа: раздел 4.1.3 SEC 1 велит в этом случае выбрать новое число и
				 *       повторить выработку
				 *
				 * \~english
				 * @brief Method of the production of a signature by a passed random number
				 * @param digest the hash of the message being signed, written from the senior byte to the junior one
				 * @param random the random number of the production of the signature, written from the senior byte to the junior one
				 * @param result the place the signature is put into
				 * @return the flag of the success of the production of the signature
				 * @note A refusal of the production at a suitable key means an unsuccessful choice of
				 *       the random number: the section 4.1.3 of SEC 1 orders to choose a new number
				 *       and to repeat the production in this case
				 *
				 * \~
				 */
				bool make(const view_t & digest, const view_t & random, uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод выработки подписи с выводом случайного числа по RFC 6979
				 *
				 * @param algorithm алгоритм хеширования, которым получен хеш сообщения
				 * @param digest    хеш подписываемого сообщения, записанный от старшего байта к младшему
				 * @param result    место, в которое помещается подпись
				 *
				 * @return признак успешности выработки подписи
				 *
				 * @details Случайное число выводится из ключа подписи и хеша сообщения
				 *          имитовставкой HMAC на том же алгоритме хеширования, которым получен
				 *          хеш, по разделу 3.2 RFC 6979: длина хеша обязана равняться длине
				 *          хеша названного алгоритма
				 *
				 * @note Неудачный выбор числа разбирается повтором вывода по разделу 3.2 RFC 6979
				 *
				 * \~english
				 * @brief Method of the production of a signature with the derivation of the random number according to RFC 6979
				 * @param algorithm the hashing algorithm the hash of the message was received by
				 * @param digest    the hash of the message being signed, written from the senior byte to the junior one
				 * @param result    the place the signature is put into
				 * @return the flag of the success of the production of the signature
				 * @details The random number is derived from the key of the signature and the hash of
				 *          the message by the authentication code HMAC on the same hashing algorithm the
				 *          hash was received by, according to the section 3.2 of RFC 6979: the length of
				 *          the hash must equal the length of the hash of the named algorithm
				 * @note An unsuccessful choice of the number is handled by a repetition of the derivation
				 *       according to the section 3.2 of RFC 6979
				 *
				 * \~
				 */
				bool make(const digest::hash_t algorithm, const view_t & digest, uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки подписи
				 *
				 * @param digest    хеш подписанного сообщения, записанный от старшего байта к младшему
				 * @param signature проверяемая подпись
				 *
				 * @return признак того, что подпись сошлась
				 *
				 * @note Подпись, всякая из частей которой лежит вне отрезка [1, n-1], отвергается
				 *       до всякого счёта по разделу 4.1.4 SEC 1
				 *
				 * \~english
				 * @brief Method of the check of a signature
				 * @param digest    the hash of the signed message, written from the senior byte to the junior one
				 * @param signature the signature being checked
				 * @return the flag of the signature having converged
				 * @note A signature every part of which lies outside of the segment [1, n-1] is
				 *       rejected before any computation according to the section 4.1.4 of SEC 1
				 *
				 * \~
				 */
				bool check(const view_t & digest, const view_t & signature) const noexcept;
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
				Ecdsa() noexcept;
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
				~Ecdsa() noexcept;
		} ecdsa_t;

		/**
		 * \~russian
		 * @brief Метод записи подписи ECDSA в структуру ASN.1 DER в готовое место
		 *
		 * @details Запись SEQUENCE {INTEGER r, INTEGER s} складывается вручную, без
		 *          записывающего объекта ASN.1 и без единого выделения памяти: оттого
		 *          отказ здесь означает негодную подпись, а не нехватку памяти, и
		 *          вызывающий вправе судить о причине. Место обязано вмещать limit()
		 *
		 * @param raw  подпись в сыром виде: r и s подряд равной длины
		 * @param der  место, в которое помещается запись
		 * @param size на входе ёмкость места, на выходе длина записи
		 *
		 * @return     признак успешности записи
		 *
		 * \~english
		 * @brief Method of the encoding of an ECDSA signature into an ASN.1 DER structure into a ready place
		 * @details The SEQUENCE {INTEGER r, INTEGER s} record is composed by hand, without the ASN.1 writer
		 *          and without a single allocation: hence a failure here means an unfit signature, not a
		 *          lack of memory, and the caller may judge the cause. The place must hold limit()
		 * @param raw  the signature in the raw form: r and s in a row of an equal length
		 * @param der  the place the record is put into
		 * @param size the capacity of the place at the input, the length of the record at the output
		 * @return     the flag of the success of the encoding
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool encode(const view_t & raw, uint8_t * der, size_t & size) noexcept;
		/**
		 * \~russian
		 * @brief Метод записи подписи ECDSA в виде ASN.1 DER
		 *
		 * @param raw подпись в сыром виде: r и s подряд, каждое в половину длины подписи
		 * @param der место, в которое помещается запись SEQUENCE {INTEGER r, INTEGER s}
		 *
		 * @return признак успешности записи подписи
		 *
		 * @note Подпись нечётной либо нулевой длины записи не подлежит
		 *
		 * @note Нехватка памяти под запись отвечает отказом, а не исключением
		 *
		 * \~english
		 * @brief Method of the writing of a signature ECDSA in the form of ASN.1 DER
		 * @param raw the signature in the raw form: r and s in a row, each of a half of the length of the signature
		 * @param der the place the writing SEQUENCE {INTEGER r, INTEGER s} is put into
		 * @return the flag of the success of the writing of the signature
		 * @note A signature of an odd or a zero length is not subject to the writing
		 * @note A lack of the memory for the writing answers by a refusal and not by an exception
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool encode(const view_t & raw, vector <uint8_t> & der) noexcept;
		/**
		 * \~russian
		 * @brief Метод разбора подписи ECDSA из записи ASN.1 DER
		 *
		 * @param der  разбираемая запись SEQUENCE {INTEGER r, INTEGER s}
		 * @param raw  место, в которое помещается подпись в сыром виде: r и s подряд
		 * @param size размер места подписи в сыром виде, две длины порядка подгруппы
		 *
		 * @return признак успешности разбора подписи
		 *
		 * @note Отрицательные числа, числа длиннее половины места и данные сверх
		 *       записи отвергаются; числа короче половины места дополняются нулями
		 *       спереди
		 *
		 * \~english
		 * @brief Method of the parsing of a signature ECDSA from a writing ASN.1 DER
		 * @param der  the writing SEQUENCE {INTEGER r, INTEGER s} being parsed
		 * @param raw  the place the signature in the raw form is put into: r and s in a row
		 * @param size the size of the place of the signature in the raw form, two lengths of the order of the subgroup
		 * @return the flag of the success of the parsing of the signature
		 * @note Negative numbers, numbers longer than a half of the place and the data beyond
		 *       the writing are rejected; numbers shorter than a half of the place are padded
		 *       by the zeroes in front
		 *
		 * \~
		 */
		__ANTS_SHARED_EXPORT__ bool decode(const view_t & der, uint8_t * raw, const size_t size) noexcept;
	};
};

#endif // __ANTS_ECDSA__
