/**
 * @file wide.hpp
 * @date 2026-09-17
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
 * @brief Целое число двойной разрядности для арифметики слов
 *
 * @details У GCC и Clang это __uint128_t. У MSVC такого типа нет, и здесь даётся своя
 *          запись из двух слов ровно с теми действиями, что просит арифметика слов:
 *          умножение слова на слово (внутренние функции _umul128 у x64 и __umulh у
 *          ARM64), сложение и вычитание слова с переносом и заёмом, сложение двух
 *          чисел, сдвиги, маска, остаток от деления на слово (_udiv128 у x64, деление
 *          столбиком у ARM64) и усечение к младшему слову. Иных действий нет намеренно:
 *          всякое новое действие обязано прийти сюда с проверкой против __uint128_t.
 *
 * @note Внутренний заголовок: подключается только из исходников src/math
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
#include <tuple>
#include <cstdint>
#include <cstddef>

/**
 * Для собирателя Microsoft Visual C++
 */
#if defined(_MSC_VER)
	/**
	 * Внутренние функции умножения и деления слов
	 */
	#include <intrin.h>

	/**
	 * @brief Основное пространство имён
	 *
	 */
	namespace nts {
		/**
		 * @brief Пространство имён математических модулей
		 *
		 */
		namespace math {
			/**
			 * @brief Целое число двойной разрядности из двух слов
			 *
			 */
			typedef struct Wide {
				// Младшее и старшее слова числа
				uint64_t low, high;
				/**
				 * @brief Оператор усечения к младшему слову
				 *
				 * @return младшее слово числа
				 *
				 */
				explicit operator uint64_t() const noexcept {
					// Отдаём младшее слово числа
					return this->low;
				}
				/**
				 * @brief Умножение на слово
				 *
				 * @details Старшее слово произведения берётся внутренней функцией собирателя
				 *          (_umul128 у x64, __umulh у ARM64), к нему прибавляется вклад
				 *          старшего слова числа.
				 *
				 * @param other множитель-слово
				 * @return      произведение числа на слово
				 *
				 */
				Wide operator * (const uint64_t other) const noexcept {
					// Место под произведение
					Wide result;
					/**
					 * Для архитектуры x64
					 */
					#if defined(_M_X64)
						// Младшее слово из внутренней функции
						result.low = ::_umul128(this->low, other, &result.high);
					/**
					 * Для иных архитектур
					 */
					#else
						// Младшее слово из действия слов
						result.low = (this->low * other);
						// Старшее слово из внутренней функции
						result.high = ::__umulh(this->low, other);
					#endif
					// Добавляем вклад старшего слова
					result.high += (this->high * other);
					// Возвращаем произведение
					return result;
				}
				/**
				 * @brief Сложение двух чисел
				 *
				 * @param other слагаемое-число двойной разрядности
				 * @return      сумма двух чисел
				 *
				 */
				Wide operator + (const Wide & other) const noexcept {
					// Складываем слова попарно
					Wide result(this->low + other.low, this->high + other.high);
					// Перенос уходит в старшее слово
					if(result.low < other.low)
						// Увеличиваем старшее слово на перенос
						result.high++;
					// Возвращаем итог попарного сложения слов
					return result;
				}
				/**
				 * @brief Сложение со словом
				 *
				 * @details Слово приводится к числу двойной разрядности и складывается
				 *          сложением двух чисел.
				 *
				 * @param other слагаемое-слово
				 * @return      сумма числа со словом
				 *
				 */
				Wide operator + (const uint64_t other) const noexcept {
					// Складываем через приведение слова к числу двойной разрядности
					return ((* this) + Wide(other));
				}
				/**
				 * @brief Прибавление числа
				 *
				 * @param other прибавляемое число двойной разрядности
				 * @return      ссылка на само число после прибавления
				 *
				 */
				Wide & operator += (const Wide & other) noexcept {
					// Прибавляем число сложением двух чисел
					(* this) = ((* this) + other);
					// Возвращаем ссылку на само число
					return (* this);
				}
				/**
				 * @brief Прибавление слова
				 *
				 * @param other прибавляемое слово
				 * @return      ссылка на само число после прибавления
				 *
				 */
				Wide & operator += (const uint64_t other) noexcept {
					// Прибавляем слово сложением со словом
					(* this) = ((* this) + other);
					// Возвращаем ссылку на само число
					return (* this);
				}
				/**
				 * @brief Сложение слова с числом, когда слово стоит слева
				 *
				 * @param first  слагаемое-слово, стоящее слева
				 * @param second слагаемое-число, стоящее справа
				 * @return       сумма слова с числом
				 *
				 */
				friend Wide operator + (const uint64_t first, const Wide & second) noexcept {
					// Складываем сложением числа со словом в обратном порядке
					return (second + first);
				}
				/**
				 * @brief Вычитание слова с заёмом из старшего слова
				 *
				 * @param other вычитаемое слово
				 * @return      разность числа и слова
				 *
				 */
				Wide operator - (const uint64_t other) const noexcept {
					// Вычитаем слово из младшего слова
					Wide result(this->low - other, this->high);
					// Заём уходит из старшего слова
					if(this->low < other)
						// Уменьшаем старшее слово на заём
						result.high--;
					// Возвращаем разность
					return result;
				}
				/**
				 * @brief Сдвиг вправо
				 *
				 * @param shift количество разрядов сдвига
				 * @return      число, сдвинутое вправо
				 *
				 */
				Wide operator >> (const int32_t shift) const noexcept {
					// Нулевой сдвиг ничего не меняет
					if(shift == 0)
						// Отдаём само число без изменений
						return (* this);
					// Сдвиг на ширину слова и более
					if(shift >= 64)
						// Хвост старшего слова становится младшим словом итога
						return Wide(this->high >> (shift - 64), 0);
					// Сдвиг внутри пары слов
					return Wide((this->low >> shift) | (this->high << (64 - shift)), this->high >> shift);
				}
				/**
				 * @brief Сдвиг влево
				 *
				 * @param shift количество разрядов сдвига
				 * @return      число, сдвинутое влево
				 *
				 */
				Wide operator << (const int32_t shift) const noexcept {
					// Нулевой сдвиг ничего не меняет
					if(shift == 0)
						// Отдаём само число без изменений
						return (* this);
					// Сдвиг на ширину слова и более
					if(shift >= 64)
						// Младшее слово становится старшим словом итога
						return Wide(0, this->low << (shift - 64));
					// Сдвиг внутри пары слов
					return Wide(this->low << shift, (this->high << shift) | (this->low >> (64 - shift)));
				}
				/**
				 * @brief Наложение маски на младшее слово
				 *
				 * @details Разряды младшего слова остаются лишь там, где в маске стоит
				 *          единица; старшее слово обнуляется.
				 *
				 * @param mask маска, накладываемая на младшее слово числа
				 * @return     число с замаскированным младшим словом и нулевым старшим словом
				 *
				 */
				Wide operator & (const uint64_t mask) const noexcept {
					// Накладываем маску на младшее слово, старшее слово обнуляем
					return Wide(this->low & mask, 0);
				}
				/**
				 * @brief Побитовое объединение со словом
				 *
				 * @details Разряды слова объединяются с разрядами младшего слова числа,
				 *          старшее слово остаётся без изменений.
				 *
				 * @param bits слово, разряды которого объединяются с младшим словом числа
				 * @return     число с объединёнными разрядами младшего слова
				 *
				 */
				Wide operator | (const uint64_t bits) const noexcept {
					// Объединяем разряды слова с младшим словом, старшее слово не трогаем
					return Wide(this->low | bits, this->high);
				}
				/**
				 * @brief Остаток от деления на слово
				 *
				 * @details Зовётся лишь при старшем слове меньше делителя (остаток вдвигает
				 *          слово за словом), потому у x64 довольно _udiv128; у ARM64 внутренней
				 *          функции нет, и остаток берётся делением столбиком по разрядам.
				 *
				 * @param divisor делитель-слово
				 * @return        остаток от деления числа на слово
				 *
				 */
				Wide operator % (const uint64_t divisor) const noexcept {
					/**
					 * Для архитектуры x64
					 */
					#if defined(_M_X64)
						// Место под остаток
						uint64_t remainder = 0;
						// Остаток из внутренней функции деления
						std::ignore = ::_udiv128(this->high % divisor, this->low, divisor, &remainder);
						// Возвращаем остаток
						return Wide(remainder, 0);
					/**
					 * Для иных архитектур
					 */
					#else
						// Начинаем со старшего слова
						uint64_t remainder = (this->high % divisor);
						/**
						 * @brief Вдвигаем слово за словом
						 *
						 */
						for(int32_t i = 63; i >= 0; i--){
							// Очередной разряд младшего слова
							const uint64_t bit = ((this->low >> i) & 1u);
							// Перенос из старшего разряда остатка
							const uint64_t carry = (remainder >> 63);
							// Вдвигаем разряд в остаток
							remainder = ((remainder << 1) | bit);
							// Вычитаем делитель при переносе либо достижении
							if(carry || (remainder >= divisor))
								// Гасим делитель из остатка
								remainder -= divisor;
						}
						// Возвращаем остаток
						return Wide(remainder, 0);
					#endif
				}
				/**
				 * @brief Конструктор нулевого числа
				 *
				 */
				explicit Wide() noexcept :
				 low(0), high(0) {}
				/**
				 * @brief Конструктор числа из слова
				 *
				 * @param value начальное значение младшего слова, старшее слово нулевое
				 *
				 */
				explicit Wide(const uint64_t value) noexcept :
				 low(value), high(0) {}
				/**
				 * @brief Конструктор числа из пары слов
				 *
				 * @param low  младшее слово числа
				 * @param high старшее слово числа
				 *
				 */
				explicit Wide(const uint64_t low, const uint64_t high) noexcept :
				 low(low), high(high) {}
			} wide_t;
		};
	};
/**
 * Для собирателей GCC и Clang
 */
#else
	/**
	 * @brief Основное пространство имён
	 *
	 */
	namespace nts {
		/**
		 * @brief Пространство имён математических модулей
		 *
		 */
		namespace math {
			/**
			 * @brief Целое число двойной разрядности
			 *
			 */
			using wide_t = __uint128_t;
		};
	};
#endif

/**
 * Перенос и заём между словами
 */
namespace nts {
	/**
	 * @brief Пространство имён математических модулей
	 *
	 */
	namespace math {
		/**
		 * @brief Функция сложения слов с переносом
		 *
		 * @details Собиратель сводит это к команде сложения с переносом; сложение через
		 *          число двойной разрядности стоило вдвое дороже на всякое слово.
		 *
		 * @param first  первое слагаемое
		 * @param second второе слагаемое
		 * @param carry  перенос из младшего слова, ноль либо единица
		 * @param result место, в которое помещается сумма
		 * @return       перенос в старшее слово, ноль либо единица
		 *
		 */
		static constexpr uint64_t adc(const uint64_t first, const uint64_t second, const uint64_t carry, uint64_t & result) noexcept {
			/**
			 * Для собирателя Microsoft Visual C++
			 */
			#if defined(_MSC_VER)
				// Сумма слов без переноса
				const uint64_t sum = (first + second);
				// Сумма с переносом
				result = (sum + carry);
				// Перенос возникает на любом из двух сложений
				return (static_cast <uint64_t> (sum < first) | static_cast <uint64_t> (result < sum));
			/**
			 * Для собирателей GCC и Clang
			 */
			#else
				// Сумма слов без переноса
				uint64_t sum = 0;
				// Перенос первого сложения
				const uint64_t one = static_cast <uint64_t> (__builtin_add_overflow(first, second, &sum));
				// Перенос второго сложения
				const uint64_t two = static_cast <uint64_t> (__builtin_add_overflow(sum, carry, &result));
				// Перенос возникает на любом из двух сложений
				return (one | two);
			#endif
		}
		/**
		 * @brief Функция вычитания слов с заёмом
		 *
		 * @param first  уменьшаемое
		 * @param second вычитаемое
		 * @param borrow заём из младшего слова, ноль либо единица
		 * @param result место, в которое помещается разность
		 * @return       заём из старшего слова, ноль либо единица
		 *
		 */
		static constexpr uint64_t sbb(const uint64_t first, const uint64_t second, const uint64_t borrow, uint64_t & result) noexcept {
			/**
			 * Для собирателя Microsoft Visual C++
			 */
			#if defined(_MSC_VER)
				// Разность слов без заёма
				const uint64_t difference = (first - second);
				// Разность с заёмом
				result = (difference - borrow);
				// Заём возникает на любом из двух вычитаний
				return (static_cast <uint64_t> (first < second) | static_cast <uint64_t> (difference < borrow));
			/**
			 * Для собирателей GCC и Clang
			 */
			#else
				// Разность слов без заёма
				uint64_t difference = 0;
				// Заём первого вычитания
				const uint64_t one = static_cast <uint64_t> (__builtin_sub_overflow(first, second, &difference));
				// Заём второго вычитания
				const uint64_t two = static_cast <uint64_t> (__builtin_sub_overflow(difference, borrow, &result));
				// Заём возникает на любом из двух вычитаний
				return (one | two);
			#endif
		}
	};
};
