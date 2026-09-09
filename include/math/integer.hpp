/**
 * @file integer.hpp
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
 * @brief Заголовочный файл модуля многоразрядных целых чисел — арифметика чисел
 *        длиной до 4096 разрядов для RSA по RFC 8017
 *
 * \~english
 * @brief Header file of the multi-precision integers module — the arithmetic of the
 *        numbers of a length of up to 4096 bits for RSA according to RFC 8017
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_INTEGER__
#define __ANTS_INTEGER__

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
	 * \~english
	 * @brief Namespace of the arithmetic modules
	 *
	 * \~
	 */
	namespace math {
		/**
		 * \~russian
		 * @brief Наибольшее число разрядов многоразрядного числа
		 *
		 * @details Наибольший модуль RSA, порождаемый библиотекой, занимает 4096 разрядов
		 *
		 * \~english
		 * @brief Greatest number of the bits of a multi-precision integer
		 * @details The greatest modulus of RSA produced by the library occupies 4096 bits, the greatest
		 *          group of RFC 7919 (ffdhe8192) occupies 8192 bits
		 *
		 * \~
		 */
		static constexpr size_t INTEGER_BITS = 8192;

		/**
		 * \~russian
		 * @brief Наибольшее число слов многоразрядного числа
		 *
		 * \~english
		 * @brief Greatest number of the words of a multi-precision integer
		 *
		 * \~
		 */
		static constexpr size_t INTEGER_WORDS = (INTEGER_BITS / 64);

		/**
		 * \~russian
		 * @brief Наибольший размер многоразрядного числа в байтах
		 *
		 * \~english
		 * @brief Greatest size of a multi-precision integer in bytes
		 *
		 * \~
		 */
		static constexpr size_t INTEGER_SIZE = (INTEGER_BITS / 8);

		/**
		 * \~russian
		 * @brief Многоразрядное целое число постоянной ёмкости
		 *
		 * @details Число без знака ёмкостью в 4096 разрядов на словах по 64 разряда,
		 *          записанных от младшего к старшему. Памяти арифметика не выделяет:
		 *          произведение двух чисел накапливается во внутреннем накопителе
		 *          двойной ёмкости на стеке. Сложение, вычитание, сравнение и
		 *          возведение в степень по модулю с признаком секретного показателя
		 *          работают за постоянное время; деление, обращение по модулю и
		 *          проверка простоты - за переменное и предназначены для порождения
		 *          ключей, где секрет ещё не установлен
		 *
		 * @note Исключений арифметика не возбуждает; слова числа затираются при
		 *       уничтожении объекта
		 *
		 * \~english
		 * @brief Multi-precision integer of a constant capacity
		 * @details An unsigned number of a capacity of 4096 bits on 64-bit words written
		 *          from the junior one to the senior one. The arithmetic does not allocate
		 *          memory: the product of two numbers is accumulated in an internal accumulator
		 *          of a double capacity on the stack. The addition, the subtraction, the comparison
		 *          and the raise into a power by a modulus with the flag of a secret exponent work
		 *          in a constant time; the division, the inversion by a modulus and the primality
		 *          check - in a variable one and are meant for the generation of the keys, where
		 *          the secret is not set yet
		 * @note The arithmetic raises no exceptions; the words of the number are wiped at the
		 *       destruction of the object
		 *
		 * \~
		 */
		typedef class __ANTS_SHARED_EXPORT__ Integer {
			private:
				// Слова числа от младшего к старшему
				uint64_t _words[INTEGER_WORDS];
			public:
				/**
				 * \~russian
				 * @brief Метод получения слов числа
				 *
				 * @return слова числа от младшего к старшему
				 *
				 * \~english
				 * @brief Method of getting the words of the number
				 * @return the words of the number from the junior one to the senior one
				 *
				 * \~
				 */
				const uint64_t * words() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения числа значимых разрядов
				 *
				 * @return число разрядов до старшего единичного включительно, ноль у нуля
				 *
				 * \~english
				 * @brief Method of getting the number of the significant bits
				 * @return the number of the bits up to the senior set one inclusive, zero for zero
				 *
				 * \~
				 */
				size_t bits() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения размера числа в байтах
				 *
				 * @return наименьшее число байтов, вмещающее значение, ноль у нуля
				 *
				 * \~english
				 * @brief Method of getting the size of the number in bytes
				 * @return the least number of bytes holding the value, zero for zero
				 *
				 * \~
				 */
				size_t size() const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки числа на ноль
				 *
				 * @return признак того, что число равно нулю
				 *
				 * \~english
				 * @brief Method of checking the number for zero
				 * @return the flag of the number being zero
				 *
				 * \~
				 */
				bool zero() const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки числа на нечётность
				 *
				 * @return признак того, что число нечётно
				 *
				 * \~english
				 * @brief Method of checking the number for oddness
				 * @return the flag of the number being odd
				 *
				 * \~
				 */
				bool odd() const noexcept;
				/**
				 * \~russian
				 * @brief Метод получения разряда числа
				 *
				 * @param index номер разряда от младшего
				 * @return      значение разряда, ноль за пределами ёмкости
				 *
				 * \~english
				 * @brief Method of getting a bit of the number
				 * @param index the number of the bit from the junior one
				 * @return      the value of the bit, zero beyond the capacity
				 *
				 * \~
				 */
				bool bit(const size_t index) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод сравнения с другим числом
				 *
				 * @param other число, с которым ведётся сравнение
				 * @return      отрицательное значение, если число меньше, ноль при равенстве, положительное, если больше
				 *
				 * @note Сравнение ведётся за постоянное время по всем словам
				 *
				 * \~english
				 * @brief Method of the comparison with another number
				 * @param other the number the comparison is carried with
				 * @return      a negative value if the number is less, zero at equality, a positive one if greater
				 * @note The comparison is carried in a constant time over all the words
				 *
				 * \~
				 */
				int compare(const Integer & other) const noexcept;
				/**
				 * \~russian
				 * @brief Метод проверки равенства с другим числом
				 *
				 * @param other число, с которым ведётся сравнение
				 * @return      признак равенства чисел
				 *
				 * \~english
				 * @brief Method of checking the equality with another number
				 * @param other the number the comparison is carried with
				 * @return      the flag of the equality of the numbers
				 *
				 * \~
				 */
				bool equal(const Integer & other) const noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод обнуления числа
				 *
				 * \~english
				 * @brief Method of zeroing the number
				 *
				 * \~
				 */
				void clear() noexcept;
				/**
				 * \~russian
				 * @brief Метод установки значения из одного слова
				 *
				 * @param value устанавливаемое значение
				 *
				 * \~english
				 * @brief Method of setting the value from a single word
				 * @param value the value being set
				 *
				 * \~
				 */
				void word(const uint64_t value) noexcept;
				/**
				 * \~russian
				 * @brief Метод разбора числа из байтов
				 *
				 * @param data байты числа от старшего к младшему
				 * @return     признак успешности разбора: значение умещается в ёмкость
				 *
				 * @note Ведущие нулевые байты допускаются
				 *
				 * \~english
				 * @brief Method of the parsing of the number from bytes
				 * @param data the bytes of the number from the senior one to the junior one
				 * @return     the flag of the success of the parsing: the value fits into the capacity
				 * @note Leading zero bytes are allowed
				 *
				 * \~
				 */
				bool load(const view_t & data) noexcept;
				/**
				 * \~russian
				 * @brief Метод записи числа в байты
				 *
				 * @param data место, в которое записывается число от старшего байта к младшему
				 * @param size размер места в байтах: число дополняется ведущими нулями
				 * @return     признак успешности записи: значение умещается в размер
				 *
				 * \~english
				 * @brief Method of writing the number into bytes
				 * @param data the place the number is written into from the senior byte to the junior one
				 * @param size the size of the place in bytes: the number is padded by leading zeros
				 * @return     the flag of the success of the writing: the value fits into the size
				 *
				 * \~
				 */
				bool store(uint8_t * data, const size_t size) const noexcept;
				/**
				 * \~russian
				 * @brief Метод выработки случайного числа
				 *
				 * @param bits число разрядов вырабатываемого числа
				 * @return     признак успешности выработки
				 *
				 * @note Старший разряд не выставляется: вырабатывается число, меньшее 2^bits
				 *
				 * \~english
				 * @brief Method of the production of a random number
				 * @param bits the number of the bits of the produced number
				 * @return     the flag of the success of the production
				 * @note The senior bit is not set: a number less than 2^bits is produced
				 *
				 * \~
				 */
				bool random(const size_t bits) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод сложения чисел
				 *
				 * @param first  первое слагаемое
				 * @param second второе слагаемое
				 * @return       признак успешности: сумма умещается в ёмкость
				 *
				 * @note При переполнении записывается младшая часть суммы
				 *
				 * \~english
				 * @brief Method of the addition of the numbers
				 * @param first  the first addend
				 * @param second the second addend
				 * @return       the flag of the success: the sum fits into the capacity
				 * @note At an overflow the junior part of the sum is written
				 *
				 * \~
				 */
				bool add(const Integer & first, const Integer & second) noexcept;
				/**
				 * \~russian
				 * @brief Метод вычитания чисел
				 *
				 * @param first  уменьшаемое
				 * @param second вычитаемое
				 * @return       признак успешности: уменьшаемое не меньше вычитаемого
				 *
				 * @note При отрицательной разности записывается её дополнение до ёмкости
				 *
				 * \~english
				 * @brief Method of the subtraction of the numbers
				 * @param first  the minuend
				 * @param second the subtrahend
				 * @return       the flag of the success: the minuend is not less than the subtrahend
				 * @note At a negative difference its complement to the capacity is written
				 *
				 * \~
				 */
				bool subtract(const Integer & first, const Integer & second) noexcept;
				/**
				 * \~russian
				 * @brief Метод умножения чисел
				 *
				 * @param first  первый сомножитель
				 * @param second второй сомножитель
				 * @return       признак успешности: произведение умещается в ёмкость
				 *
				 * \~english
				 * @brief Method of the multiplication of the numbers
				 * @param first  the first multiplier
				 * @param second the second multiplier
				 * @return       the flag of the success: the product fits into the capacity
				 *
				 * \~
				 */
				bool multiply(const Integer & first, const Integer & second) noexcept;
				/**
				 * \~russian
				 * @brief Метод сдвига числа влево
				 *
				 * @param value сдвигаемое число
				 * @param count число разрядов сдвига
				 *
				 * @note Разряды, вышедшие за ёмкость, теряются
				 *
				 * \~english
				 * @brief Method of the shift of the number to the left
				 * @param value the number being shifted
				 * @param count the number of the bits of the shift
				 * @note The bits gone beyond the capacity are lost
				 *
				 * \~
				 */
				void left(const Integer & value, const size_t count) noexcept;
				/**
				 * \~russian
				 * @brief Метод сдвига числа вправо
				 *
				 * @param value сдвигаемое число
				 * @param count число разрядов сдвига
				 *
				 * \~english
				 * @brief Method of the shift of the number to the right
				 * @param value the number being shifted
				 * @param count the number of the bits of the shift
				 *
				 * \~
				 */
				void right(const Integer & value, const size_t count) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод деления чисел с остатком
				 *
				 * @param dividend  делимое
				 * @param divisor   делитель
				 * @param remainder место, в которое помещается остаток, либо nullptr
				 * @return          признак успешности: делитель не ноль
				 *
				 * @note В само число записывается частное; время работы переменное
				 *
				 * \~english
				 * @brief Method of the division of the numbers with a remainder
				 * @param dividend  the dividend
				 * @param divisor   the divisor
				 * @param remainder the place the remainder is put into, or nullptr
				 * @return          the flag of the success: the divisor is not zero
				 * @note The quotient is written into the number itself; the time of the work is variable
				 *
				 * \~
				 */
				bool divide(const Integer & dividend, const Integer & divisor, Integer * remainder = nullptr) noexcept;
				/**
				 * \~russian
				 * @brief Метод приведения числа по модулю
				 *
				 * @param value   приводимое число
				 * @param modulus модуль
				 * @return        признак успешности: модуль не ноль
				 *
				 * @note Время работы переменное
				 *
				 * \~english
				 * @brief Method of the reduction of the number by a modulus
				 * @param value   the number being reduced
				 * @param modulus the modulus
				 * @return        the flag of the success: the modulus is not zero
				 * @note The time of the work is variable
				 *
				 * \~
				 */
				bool reduce(const Integer & value, const Integer & modulus) noexcept;
				/**
				 * \~russian
				 * @brief Метод приведения числа по нечётному модулю за постоянное время
				 *
				 * @param value   приводимое число
				 * @param modulus нечётный модуль
				 * @return        признак успешности: модуль нечётный
				 *
				 * @note Приведение ведётся проходами Монтгомери по всей ёмкости числа с
				 *       возвратом из области умножением на степень основания: ни ветвления,
				 *       ни адреса обращений от слов числа и модуля не зависят, открыто лишь
				 *       число значимых слов приводимого числа (его ёмкость). Предназначено
				 *       для секретных путей - приведения ослеплённого числа по сомножителям
				 *       RSA, где деление столбиком выдало бы сомножитель временем работы
				 *
				 * \~english
				 * @brief Method of the reduction of the number by an odd modulus in a constant time
				 * @param value   the number being reduced
				 * @param modulus the odd modulus
				 * @return        the flag of the success: the modulus is odd
				 * @note The reduction is carried by Montgomery passes over the whole capacity of the
				 *       number with a return from the domain by a multiplication by a power of the base:
				 *       neither branches nor addresses of the accesses depend on the words of the number
				 *       and the modulus, only the count of the significant words of the number (its
				 *       capacity) is public. It is meant for the secret paths - the reduction of the blinded
				 *       number by the factors of RSA, where a long division would leak the factor by the timing
				 *
				 * \~
				 */
				bool residue(const Integer & value, const Integer & modulus) noexcept;
				/**
				 * \~russian
				 * @brief Метод сложения чисел по модулю за постоянное время
				 *
				 * @param first   первое слагаемое, меньшее модуля
				 * @param second  второе слагаемое, меньшее модуля
				 * @param modulus модуль
				 * @return        признак успешности: слагаемые меньше модуля
				 *
				 * \~english
				 * @brief Method of the addition of the numbers by a modulus in a constant time
				 * @param first   the first addend, less than the modulus
				 * @param second  the second addend, less than the modulus
				 * @param modulus the modulus
				 * @return        the flag of the success: the addends are less than the modulus
				 *
				 * \~
				 */
				bool addmod(const Integer & first, const Integer & second, const Integer & modulus) noexcept;
				/**
				 * \~russian
				 * @brief Метод вычитания чисел по модулю за постоянное время
				 *
				 * @param first   уменьшаемое, меньшее модуля
				 * @param second  вычитаемое, меньшее модуля
				 * @param modulus модуль
				 * @return        признак успешности: уменьшаемое и вычитаемое меньше модуля
				 *
				 * \~english
				 * @brief Method of the subtraction of the numbers by a modulus in a constant time
				 * @param first   the minuend, less than the modulus
				 * @param second  the subtrahend, less than the modulus
				 * @param modulus the modulus
				 * @return        the flag of the success: the minuend and the subtrahend are less than the modulus
				 *
				 * \~
				 */
				bool submod(const Integer & first, const Integer & second, const Integer & modulus) noexcept;
				/**
				 * \~russian
				 * @brief Метод умножения чисел по модулю
				 *
				 * @param first   первый сомножитель
				 * @param second  второй сомножитель
				 * @param modulus модуль
				 * @param secret  признак секретных сомножителей
				 * @return        признак успешности: модуль не ноль, при секретных сомножителях нечётный и не короче их
				 *
				 * @note При секретных сомножителях умножение ведётся по Монтгомери за
				 *       постоянное время и требует нечётного модуля и сомножителей, умещающихся
				 *       в слова модуля; при открытых произведение накапливается целиком в двойной
				 *       ёмкости и делится столбиком за переменное время
				 *
				 * \~english
				 * @brief Method of the multiplication of the numbers by a modulus
				 * @param first   the first multiplier
				 * @param second  the second multiplier
				 * @param modulus the modulus
				 * @param secret  the flag of secret multipliers
				 * @return        the flag of the success: the modulus is not zero, with secret multipliers odd and not shorter than them
				 * @note With secret multipliers the multiplication is carried by Montgomery in a constant
				 *       time and requires an odd modulus and the multipliers fitting into the words of the modulus; with
				 *       public ones the product is accumulated whole in the double capacity and is divided
				 *       by the long division in a variable time
				 *
				 * \~
				 */
				bool mulmod(const Integer & first, const Integer & second, const Integer & modulus, const bool secret = true) noexcept;
				/**
				 * \~russian
				 * @brief Метод возведения в степень по модулю
				 *
				 * @param base     основание, меньшее модуля
				 * @param exponent показатель степени
				 * @param modulus  нечётный модуль
				 * @param secret   признак секретного показателя
				 * @return         признак успешности: модуль нечётный, основание меньше модуля, секретный показатель умещается в слова модуля
				 *
				 * @note Умножение ведётся по Монтгомери с окном в пять разрядов. При секретном
				 *       показателе перебор ведётся по всей разрядности слов модуля, оттого
				 *       показатель обязан умещаться в неё, а значение из
				 *       окна выбирается перебором всей таблицы без ветвлений и обращений в
				 *       память по показателю; при открытом показателе перебор ведётся по его
				 *       значимым разрядам
				 *
				 * \~english
				 * @brief Method of the raise into a power by a modulus
				 * @param base     the base, less than the modulus
				 * @param exponent the exponent
				 * @param modulus  the odd modulus
				 * @param secret   the flag of a secret exponent
				 * @return         the flag of the success: the modulus is odd, the base is less than the modulus, the secret exponent fits into the words of the modulus
				 * @note The multiplication is carried by Montgomery with a window of five bits. With a
				 *       secret exponent the scan is carried over the whole bit width of the words of the
				 *       modulus, therefore the exponent must fit into it, and
				 *       the value from the window is chosen by a scan of the whole table without branches
				 *       and memory addresses by the exponent; with a public exponent the scan is carried
				 *       over its significant bits
				 *
				 * \~
				 */
				bool power(const Integer & base, const Integer & exponent, const Integer & modulus, const bool secret = true) noexcept;
				/**
				 * \~russian
				 * @brief Метод возведения числа в степень по модулю с заданной шириной перебора показателя
				 * @param base     основание, меньшее модуля
				 * @param exponent показатель
				 * @param modulus  нечётный модуль
				 * @param bits     число разрядов показателя, по которым идёт перебор: не меньше его значимых разрядов
				 * @return         признак успешности
				 * @note Число шагов перебора задаётся вызывающим и не зависит от значения показателя:
				 *       так секретный показатель известной длины (например, 336 разрядов у ffdhe4096)
				 *       возводится без перебора всей ширины модуля и без утечки своей ширины временем
				 * \~english
				 * @brief Method of the raise into a power by a modulus with a given width of the scan of the exponent
				 * @param base     the base, less than the modulus
				 * @param exponent the exponent
				 * @param modulus  the odd modulus
				 * @param bits     the number of the bits of the exponent the scan goes over: not less than its significant bits
				 * @return         the flag of the success
				 * @note The number of the steps of the scan is set by the caller and does not depend on the value of the
				 *       exponent: thus a secret exponent of a known length (e.g. 336 bits at ffdhe4096) is raised without a
				 *       scan over the whole width of the modulus and without a leak of its width by the timing
				 * \~
				 */
				bool power(const Integer & base, const Integer & exponent, const Integer & modulus, const size_t bits) noexcept;
				/**
				 * \~russian
				 * @brief Метод обращения числа по модулю
				 *
				 * @param value   обращаемое число
				 * @param modulus модуль
				 * @return        признак успешности: число и модуль взаимно просты
				 *
				 * @note Обращение ведётся двоичным расширенным алгоритмом Евклида за
				 *       переменное время: оно предназначено для порождения ключа, где
				 *       секрет ещё не установлен; на секретных путях обратное берётся
				 *       возведением в степень по малой теореме Ферма
				 *
				 * \~english
				 * @brief Method of the inversion of the number by a modulus
				 * @param value   the number being inverted
				 * @param modulus the modulus
				 * @return        the flag of the success: the number and the modulus are coprime
				 * @note The inversion is carried by the binary extended algorithm of Euclid in a
				 *       variable time: it is meant for the generation of the key, where the secret is not
				 *       yet set; on the secret paths the inverse is taken by a raise into a power by Fermat
				 *
				 * \~
				 */
				bool invert(const Integer & value, const Integer & modulus) noexcept;
				/**
				 * \~russian
				 * @brief Метод вычисления наибольшего общего делителя
				 *
				 * @param first  первое число
				 * @param second второе число
				 * @return       признак успешности: хотя бы одно из чисел не ноль
				 *
				 * @note Время работы переменное
				 *
				 * \~english
				 * @brief Method of the computation of the greatest common divisor
				 * @param first  the first number
				 * @param second the second number
				 * @return       the flag of the success: at least one of the numbers is not zero
				 * @note The time of the work is variable
				 *
				 * \~
				 */
				bool gcd(const Integer & first, const Integer & second) noexcept;
			public:
				/**
				 * \~russian
				 * @brief Метод проверки числа на простоту
				 *
				 * @return признак того, что число вероятно простое
				 *
				 * @note Сперва пробное деление на малые простые, затем тест Миллера-Рабина
				 *       со случайными основаниями; число оборотов берётся по таблице B.1
				 *       FIPS 186-5 для простых длиной 1024, 1536 и 2048 разрядов, для более
				 *       коротких чисел оборотов больше. Время работы переменное
				 *
				 * \~english
				 * @brief Method of checking the number for primality
				 * @return the flag of the number being probably prime
				 * @note First a trial division by the small primes, then the Miller-Rabin test with
				 *       random bases; the number of the rounds is taken by the table B.1 of FIPS 186-5
				 *       for the primes of a length of 1024, 1536 and 2048 bits, for the shorter numbers
				 *       there are more rounds. The time of the work is variable
				 *
				 * \~
				 */
				bool prime() const noexcept;
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
				Integer() noexcept;
				/**
				 * \~russian
				 * @brief Деструктор
				 *
				 * \~english
				 * @brief Destructor
				 *
				 * \~
				 */
				~Integer() noexcept;
		} integer_t;
	};
};

#endif // __ANTS_INTEGER__
