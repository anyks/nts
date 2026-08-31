/**
 * @file number.hpp
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
 * @brief Заголовочный файл модуля арифметики чисел постоянной разрядности по
 *        простому модулю
 *
 * \~english
 * @brief Header file of the module of the arithmetic of the numbers of a constant
 *        bit width by a prime modulus
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_NUMBER__
#define __ANTS_NUMBER__

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
	 * @brief Пространство имён модулей арифметики
	 *
	 * @details Арифметика криптографии своя, а не общего назначения: разрядность
	 *          постоянна, память не выделяется, а время работы от значений не зависит.
	 *          Ни ветвления, ни обращения в память по секретному значению здесь нет.
	 *
	 * \~english
	 * @brief Namespace of the arithmetic modules
	 * @details The arithmetic of the cryptography is its own and not a general purpose one:
	 *          the bit width is constant, the memory is not allocated, and the time of the
	 *          work does not depend on the values. There is neither a branch nor an address
	 *          to the memory by a secret value here.
	 *
	 * \~
	 */
	namespace math {
		/**
		 * \~russian
		 * @brief Наибольшее число разрядов числа
		 *
		 * @details Наибольший модуль ГОСТ Р 34.10-2012 занимает 512 разрядов
		 *
		 * \~english
		 * @brief Greatest number of the bits of a number
		 * @details The greatest modulus of GOST R 34.10-2012 occupies 512 bits
		 *
		 * \~
		 */
		static constexpr size_t NUMBER_BITS = 512;

		/**
		 * \~russian
		 * @brief Наибольшее число слов числа
		 *
		 * \~english
		 * @brief Greatest number of the words of a number
		 *
		 * \~
		 */
		static constexpr size_t NUMBER_WORDS = (NUMBER_BITS / 64);

		/**
		 * \~russian
		 * @brief Наибольший размер числа в байтах
		 *
		 * \~english
		 * @brief Greatest size of a number in bytes
		 *
		 * \~
		 */
		static constexpr size_t NUMBER_SIZE = (NUMBER_BITS / 8);

		/**
		 * \~russian
		 * @brief Число постоянной разрядности
		 *
		 * @details Слова числа записаны от младшего к старшему, разрядность у всех чисел
		 *          одного модуля одна и та же независимо от значения: тем и достигается
		 *          постоянство времени работы
		 *
		 * \~english
		 * @brief Number of a constant bit width
		 * @details The words of the number are written from the junior one to the senior one,
		 *          the bit width of all the numbers of a single modulus is one and the same
		 *          regardless of the value: the constancy of the time of the work is achieved by that
		 *
		 * \~
		 */
		typedef struct __ANTS_SHARED_EXPORT__ Number {
			// Слова числа от младшего к старшему
			uint64_t words[NUMBER_WORDS];
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
			Number() noexcept;
		} number_t;

		/**
		 * \~russian
		 * @brief Арифметика по простому модулю
		 *
		 * @details Умножение ведётся по Монтгомери, оттого числа приводятся в область
		 *          Монтгомери вызовом enter и выводятся из неё вызовом leave. Область
		 *          вынесена наружу намеренно: сложение и вычитание в ней те же самые, а
		 *          скрытая область стоила бы двух умножений на всякое одно.
		 *
		 * @note Модуль обязан быть простым и нечётным: обращение вычисляется возведением
		 *       в степень по малой теореме Ферма
		 *
		 * \~english
		 * @brief Arithmetic by a prime modulus
		 * @details The multiplication is carried by Montgomery, therefore the numbers are
		 *          brought into the Montgomery domain by a call of enter and are taken out of
		 *          it by a call of leave. The domain is taken outside deliberately: the addition
		 *          and the subtraction in it are the same, while a hidden domain would cost
		 *          two multiplications for every single one.
		 * @note The modulus must be prime and odd: the inversion is computed by a raise into
		 *       a power by the little theorem of Fermat
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Modulus {
			private:
				// Признак того, что модуль установлен
				bool _ready;
			private:
				// Число слов модуля
				size_t _words;
				// Число байтов модуля
				size_t _size;
			private:
				// Обратное к младшему слову модуля значение со сменой знака
				uint64_t _factor;
			private:
				// Значение модуля
				number_t _modulus;
				// Квадрат основания области Монтгомери по модулю
				number_t _square;
			public:
				/**
				 * \~russian
				 * @brief Метод проверки готовности арифметики к работе
				 *
				 * @return признак того, что модуль установлен
				 *
				 * \~english
				 * @brief Method of checking the readiness of the arithmetic for the work
				 * @return the flag of the modulus being set
				 *
				 * \~
				 */
				bool ready() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения размера модуля
				 *
				 * @return размер модуля в байтах
				 *
				 * \~english
				 * @brief Method of getting the size of the modulus
				 * @return the size of the modulus in bytes
				 *
				 * \~
				 */
				size_t size() const noexcept;
				/**
				 * \~russian
				 * @brief Метод установки модуля
				 *
				 * @param modulus устанавливаемый модуль, записанный от старшего байта к младшему
				 *
				 * @return признак успешности установки модуля
				 *
				 * \~english
				 * @brief Method of setting the modulus
				 * @param modulus the modulus being set, written from the senior byte to the junior one
				 * @return the flag of the success of the setting of the modulus
				 *
				 * \~
				 */
				bool start(const view_t & modulus) noexcept;
				/**
				 * \~russian
				 * @brief Метод сброса установленного модуля
				 *
				 * \~english
				 * @brief Method of the reset of the set modulus
				 *
				 * \~
				 */
				void clear() noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод разбора числа из потока байтов
				 *
				 * @param data   разбираемый поток байтов, записанный от старшего байта к младшему
				 * @param result место, в которое помещается разобранное число
				 *
				 * @return признак успешности разбора числа
				 *
				 * @note Число, не меньшее модуля, разбору не подлежит
				 *
				 * \~english
				 * @brief Method of the parsing of a number from a stream of bytes
				 * @param data   the stream of bytes being parsed, written from the senior byte to the junior one
				 * @param result the place the parsed number is put into
				 * @return the flag of the success of the parsing of the number
				 * @note A number not less than the modulus is not subject to the parsing
				 *
				 * \~
				 */
				bool load(const view_t & data, number_t & result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод приведения потока байтов по модулю
				 *
				 * @param data   приводимый поток байтов, записанный от старшего байта к младшему
				 * @param result место, в которое помещается приведённое число
				 *
				 * @return признак успешности приведения потока байтов
				 *
				 * @note Приведение выполняется разбором потока по байту с умножением
				 *       накопленного значения на двести пятьдесят шесть, оттого разрядность
				 *       приводимого потока ничем не ограничена
				 *
				 * @note Модуль при этом обязан превышать двести пятьдесят пять
				 *
				 * \~english
				 * @brief Method of the reduction of a stream of bytes by the modulus
				 * @param data   the stream of bytes being reduced, written from the senior byte to the junior one
				 * @param result the place the reduced number is put into
				 * @return the flag of the success of the reduction of the stream of bytes
				 * @note The reduction is performed by the parsing of the stream by a byte with a
				 *       multiplication of the accumulated value by two hundred fifty six, therefore
				 *       the bit width of the stream being reduced is not limited by anything
				 *
				 * \~
				 */
				bool reduce(const view_t & data, number_t & result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод записи числа в поток байтов
				 *
				 * @param value записываемое число
				 * @param data  место, в которое записывается число
				 * @param size  размер места, в которое записывается число
				 *
				 * @return признак успешности записи числа
				 *
				 * @note Число записывается от старшего байта к младшему с дополнением нулями
				 *
				 * \~english
				 * @brief Method of the writing of a number into a stream of bytes
				 * @param value the number being written
				 * @param data  the place the number is written into
				 * @param size  the size of the place the number is written into
				 * @return the flag of the success of the writing of the number
				 * @note The number is written from the senior byte to the junior one with a padding by the zeroes
				 *
				 * \~
				 */
				bool store(const number_t & value, uint8_t * data, const size_t size) const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения числа из машинного слова
				 *
				 * @param value  значение машинного слова
				 * @param result место, в которое помещается полученное число
				 *
				 * \~english
				 * @brief Method of getting a number from a machine word
				 * @param value  the value of the machine word
				 * @param result the place the received number is put into
				 *
				 * \~
				 */
				void word(const uint64_t value, number_t & result) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод проверки числа на равенство нулю
				 *
				 * @param value проверяемое число
				 *
				 * @return признак равенства числа нулю
				 *
				 * \~english
				 * @brief Method of checking a number for the equality to a zero
				 * @param value the number being checked
				 * @return the flag of the equality of the number to a zero
				 *
				 * \~
				 */
				bool zero(const number_t & value) const noexcept;
				/**
				 * \~russian
				 * @brief Метод сличения двух чисел
				 *
				 * @param first  первое сличаемое число
				 * @param second второе сличаемое число
				 *
				 * @return признак равенства сличаемых чисел
				 *
				 * @note Сличение ведётся за постоянное время, без выхода при первом расхождении
				 *
				 * \~english
				 * @brief Method of the comparison of two numbers
				 * @param first  the first number being compared
				 * @param second the second number being compared
				 * @return the flag of the equality of the compared numbers
				 * @note The comparison is carried in a constant time, without an exit at the first difference
				 *
				 * \~
				 */
				bool equal(const number_t & first, const number_t & second) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод приведения числа в область Монтгомери
				 *
				 * @param value  приводимое число
				 * @param result место, в которое помещается приведённое число
				 *
				 * \~english
				 * @brief Method of the bringing of a number into the Montgomery domain
				 * @param value  the number being brought
				 * @param result the place the brought number is put into
				 *
				 * \~
				 */
				void enter(const number_t & value, number_t & result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод вывода числа из области Монтгомери
				 *
				 * @param value  выводимое число
				 * @param result место, в которое помещается выведенное число
				 *
				 * \~english
				 * @brief Method of the taking of a number out of the Montgomery domain
				 * @param value  the number being taken out
				 * @param result the place the taken out number is put into
				 *
				 * \~
				 */
				void leave(const number_t & value, number_t & result) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод сложения чисел по модулю
				 *
				 * @param first  первое слагаемое
				 * @param second второе слагаемое
				 * @param result место, в которое помещается сумма
				 *
				 * @note Место итога вправе совпадать с местом всякого слагаемого
				 *
				 * \~english
				 * @brief Method of the addition of the numbers by the modulus
				 * @param first  the first addend
				 * @param second the second addend
				 * @param result the place the sum is put into
				 * @note The place of the result may coincide with the place of every addend
				 *
				 * \~
				 */
				void add(const number_t & first, const number_t & second, number_t & result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод вычитания чисел по модулю
				 *
				 * @param first  уменьшаемое
				 * @param second вычитаемое
				 * @param result место, в которое помещается разность
				 *
				 * @note Место итога вправе совпадать с местом уменьшаемого либо вычитаемого
				 *
				 * \~english
				 * @brief Method of the subtraction of the numbers by the modulus
				 * @param first  the minuend
				 * @param second the subtrahend
				 * @param result the place the difference is put into
				 * @note The place of the result may coincide with the place of the minuend or of the subtrahend
				 *
				 * \~
				 */
				void subtract(const number_t & first, const number_t & second, number_t & result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод умножения чисел по модулю
				 *
				 * @param first  первый сомножитель в области Монтгомери
				 * @param second второй сомножитель в области Монтгомери
				 * @param result место, в которое помещается произведение в области Монтгомери
				 *
				 * @note Место итога вправе совпадать с местом всякого сомножителя
				 *
				 * \~english
				 * @brief Method of the multiplication of the numbers by the modulus
				 * @param first  the first factor in the Montgomery domain
				 * @param second the second factor in the Montgomery domain
				 * @param result the place the product in the Montgomery domain is put into
				 * @note The place of the result may coincide with the place of every factor
				 *
				 * \~
				 */
				void multiply(const number_t & first, const number_t & second, number_t & result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод возведения числа в степень по модулю
				 *
				 * @param base     основание степени в области Монтгомери
				 * @param exponent показатель степени вне области Монтгомери
				 * @param result   место, в которое помещается степень в области Монтгомери
				 *
				 * @note Умножение выполняется на всяком разряде показателя независимо от его
				 *       значения, а нужное из двух значений выбирается наложением маски
				 *
				 * \~english
				 * @brief Method of the raise of a number into a power by the modulus
				 * @param base     the base of the power in the Montgomery domain
				 * @param exponent the exponent of the power outside of the Montgomery domain
				 * @param result   the place the power in the Montgomery domain is put into
				 * @note The multiplication is performed at every bit of the exponent regardless of
				 *       its value, while the needed one of the two values is chosen by an overlay of a mask
				 *
				 * \~
				 */
				void power(const number_t & base, const number_t & exponent, number_t & result) const noexcept;
				/**
				 * \~russian
				 * @brief Метод обращения числа по модулю
				 *
				 * @param value  обращаемое число в области Монтгомери
				 * @param result место, в которое помещается обратное число в области Монтгомери
				 *
				 * @note Обращение вычисляется возведением в степень, меньшую модуля на два:
				 *       это верно лишь при простом модуле
				 *
				 * \~english
				 * @brief Method of the inversion of a number by the modulus
				 * @param value  the number being inverted in the Montgomery domain
				 * @param result the place the inverse number in the Montgomery domain is put into
				 * @note The inversion is computed by a raise into a power less than the modulus by
				 *       two: this is true only at a prime modulus
				 *
				 * \~
				 */
				void invert(const number_t & value, number_t & result) const noexcept;
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
				Modulus() noexcept;
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
				~Modulus() noexcept;
		} modulus_t;
	};
};

#endif // __ANTS_NUMBER__
