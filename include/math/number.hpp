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
		 * @details The greatest modulus of GOST R 34.10-2012 occupies 512 bits, the modulus of the curve
		 *          secp521r1 occupies 521 bits - nine words of sixty four bits
		 *
		 * \~
		 */
		static constexpr size_t NUMBER_BITS = 576;

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
		 * @note Простые вида 2^(64·слов) - c и 2^(64·слов - 1) + c с малым c (все кривые
		 *       ГОСТ Р 34.10-2012, кроме CryptoPro-C, и P-256 своим путём) опознаются при
		 *       установке модуля, и умножение по ним идёт прямой свёрткой старшей половины
		 *       произведения без области Монтгомери: enter и leave там обращаются в
		 *       переписывание, а договор вызовов остаётся тем же. Обращение идёт окнами
		 *       открытого показателя p - 2 по четыре разряда: 334 умножения вместо 532 на
		 *       256 разрядах, время от обращаемого числа не зависит
		 * @note Квадрат идёт своим входом square: он дешевле умножения, а умножение
		 *       совпадения сомножителей не опознаёт
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
		 * @note The primes of the form 2^(64·words) - c and 2^(64·words - 1) + c with a small c
		 *       (all the curves of GOST R 34.10-2012 except CryptoPro-C, and P-256 by its own path)
		 *       are recognised at the setting of the modulus, and the multiplication by them goes
		 *       by a direct folding of the high half of the product without the Montgomery domain:
		 *       enter and leave turn into a copying there, while the contract of the calls stays
		 *       the same. The inversion goes by the windows of the public exponent p - 2 of four
		 *       bits each: 334 multiplications instead of 532 at 256 bits, the time does not depend
		 *       on the number being inverted
		 * @note The square goes by its own entry square: it costs less than a multiplication,
		 *       while the multiplication does not recognise the coincidence of its factors
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Modulus {
			public:
				/**
				 * \~russian
				 * @brief Вид модуля, задающий путь умножения
				 *
				 * \~english
				 * @brief Form of the modulus that sets the path of the multiplication
				 *
				 * \~
				 */
				enum class form_t : uint8_t {
					GENERAL = 0x00, /*!< \~russian Произвольный модуль: умножение Монтгомери общего вида \~english Arbitrary modulus: the Montgomery multiplication of the general form \~ */
					NIST    = 0x01, /*!< \~russian Простое число кривой P-256: Монтгомери с заложенными словами модуля \~english Prime of the curve P-256: Montgomery with the embedded words of the modulus \~ */
					MINUS   = 0x02, /*!< \~russian Простое число вида 2^(64·слов) - c: прямая свёртка без области Монтгомери \~english Prime of the form 2^(64·words) - c: a direct folding without the Montgomery domain \~ */
					PLUS    = 0x03  /*!< \~russian Простое число вида 2^(64·слов - 1) + c: прямая свёртка без области Монтгомери \~english Prime of the form 2^(64·words - 1) + c: a direct folding without the Montgomery domain \~ */
				};
				/**
				 * \~russian
				 * @brief Устройство модуля для встраиваемой арифметики
				 *
				 * @details Всё, что нужно ядрам умножения, сложения и вычитания известного числа
				 *          слов: вид модуля, число слов, множитель приведения Монтгомери, хвост c
				 *          и слова самого модуля. Выдаётся методом layout, чтобы модули кривых
				 *          встраивали арифметику в свои формулы, минуя вызов через границу модуля
				 *
				 * \~english
				 * @brief Layout of the modulus for the inlined arithmetic
				 * @details Everything the kernels of the multiplication, addition and subtraction of a
				 *          known number of words need: the form of the modulus, the number of words, the
				 *          Montgomery reduction factor, the tail c and the words of the modulus itself.
				 *          It is given by the method layout so that the curve modules inline the
				 *          arithmetic into their formulas bypassing a call across the module boundary
				 *
				 * \~
				 */
				typedef struct Layout {
					form_t form;              /*!< \~russian Вид модуля \~english Form of the modulus \~ */
					size_t words;             /*!< \~russian Число слов модуля \~english Number of the words of the modulus \~ */
					uint64_t factor;          /*!< \~russian Множитель приведения Монтгомери \~english Montgomery reduction factor \~ */
					uint64_t tail;            /*!< \~russian Хвост c у модулей вида 2^k ± c \~english Tail c of the moduli of the form 2^k ± c \~ */
					const uint64_t * modulus; /*!< \~russian Слова модуля от младшего к старшему \~english Words of the modulus from the least significant \~ */
				} layout_t;
			private:
				// Признак того, что модуль установлен
				bool _ready;
				// Вид модуля
				form_t _form;
			private:
				// Число слов модуля
				size_t _words;
				// Число байтов модуля
				size_t _size;
			private:
				// Обратное к младшему слову модуля значение со сменой знака
				uint64_t _factor;
				// Хвост c у модулей вида 2^k ± c
				uint64_t _tail;
			private:
				// Значение модуля
				number_t _modulus;
				// Квадрат основания области Монтгомери по модулю
				number_t _square;
				// Основание разрядной сетки по модулю (2^(64·слов) mod p) у модулей вида 2^k ± c
				number_t _shift;
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
				 * @brief Метод получения устройства модуля для встраиваемой арифметики
				 *
				 * @return устройство модуля; указатель на слова модуля действителен, пока жив объект
				 *
				 * \~english
				 * @brief Method of getting the layout of the modulus for the inlined arithmetic
				 * @return the layout of the modulus; the pointer to the words of the modulus is valid while the object lives
				 *
				 * \~
				 */
				layout_t layout() const noexcept;
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
				 * @brief Метод возведения числа в квадрат по модулю
				 *
				 * @param value  возводимое число в области Монтгомери
				 * @param result место, в которое помещается квадрат в области Монтгомери
				 *
				 * @note Место итога вправе совпадать с местом возводимого числа
				 * @note Квадрат считается своим путём и стоит дешевле умножения; умножение
				 *       совпадения сомножителей не опознаёт, и квадраты следует брать здесь
				 *
				 * \~english
				 * @brief Method of the squaring of a number by the modulus
				 * @param value  the number being squared in the Montgomery domain
				 * @param result the place the square in the Montgomery domain is put into
				 * @note The place of the result may coincide with the place of the number being squared
				 * @note The square is computed by its own path and costs less than a multiplication; the
				 *       multiplication does not recognise the coincidence of its factors, therefore the
				 *       squares are to be taken here
				 *
				 * \~
				 */
				void square(const number_t & value, number_t & result) const noexcept;
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
				 *       это верно лишь при простом модуле. Показатель открыт, оттого у модулей
				 *       вида 2^k ± c степень берётся цепочкой сложений показателя по его
				 *       известному строению (k - 1 квадратов и около пятнадцати умножений), а у
				 *       прочих - окнами по четыре разряда с заготовкой пятнадцати степеней;
				 *       порядок действий от обращаемого числа не зависит
				 *
				 * \~english
				 * @brief Method of the inversion of a number by the modulus
				 * @param value  the number being inverted in the Montgomery domain
				 * @param result the place the inverse number in the Montgomery domain is put into
				 * @note The inversion is computed by a raise into a power less than the modulus by
				 *       two: this is true only at a prime modulus. The exponent is public, therefore
				 *       at the moduli of the form 2^k ± c the power is taken by an addition chain of
				 *       the exponent by its known structure (k - 1 squarings and about fifteen
				 *       multiplications), and at the rest by the windows of four bits with a
				 *       preparation of fifteen powers; the order of the operations does not depend
				 *       on the number being inverted
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
