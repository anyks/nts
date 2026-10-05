/**
 * @file sm2.hpp
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
 * @brief Заголовочный файл модуля выработки и проверки электронной подписи SM2
 *        по GB/T 32918.2-2016
 *
 * \~english
 * @brief Header file of the module of the production and the check of an electronic
 *        signature SM2 according to GB/T 32918.2-2016
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_SM2__
#define __ANTS_SM2__

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
		 * @brief Электронная подпись SM2 по GB/T 32918.2-2016
		 *
		 * @details Подпись состоит из двух чисел r и s, записанных подряд от старшего
		 *          байта к младшему, каждое длиной в порядок подгруппы точек кривой:
		 *          64 байта у кривой SM2. Запись в виде SEQUENCE {INTEGER r, INTEGER s}
		 *          выполняют общие методы sign::encode и sign::decode модуля ECDSA.
		 *
		 * @details Подписываемое значение e есть хеш SM3 от Z_A ‖ M, где Z_A - хеш
		 *          опознавателя подписывающего, параметров кривой и ключа проверки по
		 *          разделу 5.5 GB/T 32918.2-2016; модуль держит Z_A выработанным при
		 *          установке ключа, и подача сообщения идёт уже поверх него
		 *
		 * @note Случайное число выработки подписи передаётся вызывающей стороной и
		 *       обязано быть непредсказуемым и неповторимым: повтор его на одном ключе
		 *       выдаёт сам ключ подписи
		 *
		 * \~english
		 * @brief Electronic signature SM2 according to GB/T 32918.2-2016
		 * @details The signature consists of the two numbers r and s written in a row from
		 *          the senior byte to the junior one, each of a length of the order of the
		 *          subgroup of the points of the curve: 64 bytes at the curve SM2. The writing
		 *          in the form of SEQUENCE {INTEGER r, INTEGER s} is performed by the common
		 *          methods sign::encode and sign::decode of the ECDSA module.
		 * @details The signed value e is the SM3 hash of Z_A ‖ M, where Z_A is the hash of
		 *          the identifier of the signer, of the parameters of the curve and of the
		 *          verification key according to the section 5.5 of GB/T 32918.2-2016; the
		 *          module holds Z_A produced at the setting of the key, and the message is
		 *          fed already on top of it
		 * @note The random number of the production of the signature is passed by the calling
		 *       side and must be unpredictable and unique: a repetition of it under a single
		 *       key gives away the key of the signature itself
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Sm2 {
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
			private:
				// Выработанное значение Z_A: меняется сменой опознавателя при неизменном ключе
				mutable uint8_t _za[32];
			private:
				/**
				 * \~russian
				 * @brief Метод выработки значения Z_A
				 *
				 * @param id опознаватель подписывающего
				 *
				 * @return   признак успешности выработки значения Z_A
				 *
				 * @details Z_A = SM3(ENTL_A ‖ ID_A ‖ a ‖ b ‖ Gx ‖ Gy ‖ Px ‖ Py) по разделу
				 *          5.5 GB/T 32918.2-2016: коэффициенты кривой и координаты точек
				 *          записываются длиной поля, опознаватель - двухбайтовой длиной в
				 *          разрядах и самими байтами
				 *
				 * \~english
				 * @brief Method of the production of the value Z_A
				 * @param id the identifier of the signer
				 * @return the flag of the success of the production of the value Z_A
				 * @details Z_A = SM3(ENTL_A ‖ ID_A ‖ a ‖ b ‖ Gx ‖ Gy ‖ Px ‖ Py) according to
				 *          the section 5.5 of GB/T 32918.2-2016: the coefficients of the curve
				 *          and the coordinates of the points are written by the length of the
				 *          field, the identifier by a two-byte length in bits and the bytes themselves
				 *
				 * \~
				 */
				bool identify(const view_t & id) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод смены опознавателя подписывающего
				 *
				 * @param id новый опознаватель подписывающего
				 *
				 * @return   признак успешности смены опознавателя
				 *
				 * @details Ключ остаётся прежним, значение Z_A вырабатывается заново:
				 *          RFC 8998 велит опознаватель «TLSv1.3+GM+Cipher+Suite» подписи
				 *          владения ключом и «1234567812345678» подписи сертификата, и
				 *          один ключ служит обеим подписям сменой опознавателя
				 *
				 * \~english
				 * @brief Method of the change of the identifier of the signer
				 * @param id the new identifier of the signer
				 * @return the flag of the success of the change of the identifier
				 * @details The key remains the same, the value Z_A is produced anew: RFC 8998
				 *          orders the identifier "TLSv1.3+GM+Cipher+Suite" for the signature of
				 *          the key possession and "1234567812345678" for the signature of the
				 *          certificate, and a single key serves both signatures by the change
				 *          of the identifier
				 *
				 * \~
				 */
				bool reidentify(const view_t & id) const noexcept;
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
				 * @param id     опознаватель подписывающего для выработки Z_A
				 *
				 * @return признак успешности установки ключа подписи
				 *
				 * @note Ключ проверки подписи вырабатывается из ключа подписи сразу же
				 *
				 * \~english
				 * @brief Method of setting the key of the signature
				 * @param secret the key of the signature being set, written from the senior byte to the junior one
				 * @param id     the identifier of the signer for the production of Z_A
				 * @return the flag of the success of the setting of the key of the signature
				 * @note The key of the check of the signature is produced from the key of the signature at once
				 *
				 * \~
				 */
				bool secret(const view_t & secret, const view_t & id) noexcept;
				/**
				 * \~russian
				 * @brief Метод установки ключа проверки подписи
				 *
				 * @param x  первая координата ключа проверки подписи
				 * @param y  вторая координата ключа проверки подписи
				 * @param id опознаватель подписывающего для выработки Z_A
				 *
				 * @return признак успешности установки ключа проверки подписи
				 *
				 * @note Точка, не принадлежащая кривой, отвергается
				 *
				 * \~english
				 * @brief Method of setting the key of the check of the signature
				 * @param x  the first coordinate of the key of the check of the signature
				 * @param y  the second coordinate of the key of the check of the signature
				 * @param id the identifier of the signer for the production of Z_A
				 * @return the flag of the success of the setting of the key of the check of the signature
				 * @note A point not belonging to the curve is rejected
				 *
				 * \~
				 */
				bool key(const view_t & x, const view_t & y, const view_t & id) noexcept;
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
				 * @param message подписываемое сообщение
				 * @param random  случайное число выработки подписи, записанное от старшего байта к младшему
				 * @param result  место, в которое помещается подпись
				 *
				 * @return признак успешности выработки подписи
				 *
				 * @details Подписываемое значение e = SM3(Z_A ‖ M); r = (e + x1) mod n от
				 *          кратной точки k·G, s = (k − r·d) / (1 + d) mod n по разделу 6.1
				 *          GB/T 32918.2-2016; нулевое r, нулевое s либо r + k = n велят
				 *          заменить случайное число
				 *
				 * \~english
				 * @brief Method of the production of a signature by a passed random number
				 * @param message the message being signed
				 * @param random  the random number of the production of the signature, written from the senior byte to the junior one
				 * @param result  the place the signature is put into
				 * @return the flag of the success of the production of the signature
				 * @details The signed value e = SM3(Z_A ‖ M); r = (e + x1) mod n from the
				 *          multiple point k·G, s = (k − r·d) / (1 + d) mod n according to the
				 *          section 6.1 of GB/T 32918.2-2016; a zero r, a zero s or r + k = n
				 *          order to replace the random number
				 *
				 * \~
				 */
				bool make(const view_t & message, const view_t & random, uint8_t * result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки подписи
				 *
				 * @param message   подписанное сообщение
				 * @param signature проверяемая подпись
				 *
				 * @return признак того, что подпись сошлась
				 *
				 * @details Подписываемое значение e' = SM3(Z_A ‖ M); t = (r' + s') mod n,
				 *          точка s'·G + t·P, R = (e' + x1') mod n сличается с r' по разделу
				 *          7.1 GB/T 32918.2-2016; части вне отрезка [1, n-1] и нулевое t
				 *          отвергаются до счёта
				 *
				 * \~english
				 * @brief Method of the check of a signature
				 * @param message   the signed message
				 * @param signature the signature being checked
				 * @return the flag of the signature having converged
				 * @details The signed value e' = SM3(Z_A ‖ M); t = (r' + s') mod n, the point
				 *          s'·G + t·P, R = (e' + x1') mod n is compared with r' according to
				 *          the section 7.1 of GB/T 32918.2-2016; the parts outside of the
				 *          segment [1, n-1] and a zero t are rejected before any computation
				 *
				 * \~
				 */
				bool check(const view_t & message, const view_t & signature) const noexcept;
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
				Sm2() noexcept;
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
				~Sm2() noexcept;
		} sm2_t;
	};
};

#endif // __ANTS_SM2__
