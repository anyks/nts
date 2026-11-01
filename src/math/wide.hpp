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
 *          всякое новое действие обязано прийти сюда с проверкой против __uint128_t
 *
 * @note Внутренний заголовок: подключается только из исходников src/math
 *
 * @copyright Copyright © 2026
 *
 */

#ifndef __ANTS_MATH_WIDE__
/**
 * Макрос экранирования повторной инициализации модуля
 */
#define __ANTS_MATH_WIDE__

/**
 * Стандартные заголовочные файлы
 */
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
				// Младшее и старшее слова
				uint64_t lo, hi;
				/**
				 * @brief Усечение к младшему слову
				 *
				 */
				explicit operator uint64_t() const noexcept { return this->lo; }
				/**
				 * @brief Умножение на слово: старшее слово произведения из внутренней функции
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
						result.lo = ::_umul128(this->lo, other, &result.hi);
					/**
					 * Для иных архитектур
					 */
					#else
						// Младшее слово из действия слов
						result.lo = (this->lo * other);
						// Старшее слово из внутренней функции
						result.hi = ::__umulh(this->lo, other);
					#endif
					// Добавляем вклад старшего слова
					result.hi += (this->hi * other);
					// Возвращаем произведение
					return result;
				}
				/**
				 * @brief Сложение
				 *
				 */
				Wide operator + (const Wide & other) const noexcept {
					// Складываем слова попарно
					Wide result(this->lo + other.lo, this->hi + other.hi);
					// Перенос уходит в старшее слово
					if(result.lo < other.lo) result.hi++;
					// Возвращаем итог попарного сложения слов
					return result;
				}
				// Сложение со словом через приведение
				Wide operator + (const uint64_t other) const noexcept { return ((* this) + Wide(other)); }
				// Прибавление числа
				Wide & operator += (const Wide & other) noexcept { (* this) = ((* this) + other); return (* this); }
				// Прибавление слова
				Wide & operator += (const uint64_t other) noexcept { (* this) = ((* this) + other); return (* this); }
				// Сложение слова с числом в обратном порядке
				friend Wide operator + (const uint64_t first, const Wide & second) noexcept { return (second + first); }
				/**
				 * @brief Вычитание слова с заёмом из старшего слова
				 *
				 */
				Wide operator - (const uint64_t other) const noexcept {
					// Вычитаем слово из младшего слова
					Wide result(this->lo - other, this->hi);
					// Заём уходит из старшего слова
					if(this->lo < other) result.hi--;
					// Возвращаем разность
					return result;
				}
				/**
				 * @brief Сдвиги
				 *
				 */
				Wide operator >> (const int shift) const noexcept {
					// Нулевой сдвиг ничего не меняет
					if(shift == 0) return (* this);
					// Сдвиг на ширину слова и более
					if(shift >= 64) return Wide(this->hi >> (shift - 64), 0);
					// Сдвиг внутри пары слов
					return Wide((this->lo >> shift) | (this->hi << (64 - shift)), this->hi >> shift);
				}
				// Сдвиг влево
				Wide operator << (const int shift) const noexcept {
					// Нулевой сдвиг ничего не меняет
					if(shift == 0) return (* this);
					// Сдвиг на ширину слова и более
					if(shift >= 64) return Wide(0, this->lo << (shift - 64));
					// Сдвиг внутри пары слов
					return Wide(this->lo << shift, (this->hi << shift) | (this->lo >> (64 - shift)));
				}
				/**
				 * @brief Маска и объединение по младшему слову
				 *
				 */
				// Маска по младшему слову
				Wide operator & (const uint64_t mask) const noexcept { return Wide(this->lo & mask, 0); }
				// Объединение по младнему слову
				Wide operator | (const uint64_t bits) const noexcept { return Wide(this->lo | bits, this->hi); }
				/**
				 * @brief Остаток от деления на слово
				 *
				 * @details Зовётся лишь при старшем слове меньше делителя (остаток вдвигает
				 *          слово за словом), потому у x64 довольно _udiv128; у ARM64 внутренней
				 *          функции нет, и остаток берётся делением столбиком по разрядам
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
						(void) ::_udiv128(this->hi % divisor, this->lo, divisor, &remainder);
						// Возвращаем остаток
						return Wide(remainder, 0);
					/**
					 * Для иных архитектур
					 */
					#else
						// Начинаем со старшего слова
						uint64_t remainder = (this->hi % divisor);
						/**
						 * @brief Вдвигаем слово за словом
						 *
						 */
						for(int i = 63; i >= 0; i--){
							// Очередной разряд младшего слова
							const uint64_t bit = ((this->lo >> i) & 1u);
							// Перенос из старшего разряда остатка
							const uint64_t carry = (remainder >> 63);
							// Вдвигаем разряд в остаток
							remainder = ((remainder << 1) | bit);
							// Вычитаем делитель при переносе либо достижении
							if(carry || (remainder >= divisor)) remainder -= divisor;
						}
						// Возвращаем остаток
						return Wide(remainder, 0);
					#endif
				}
				/**
				 * @brief Конструкторы
				 *
				 */
				Wide() noexcept : lo(0), hi(0) {}
				Wide(const uint64_t value) noexcept : lo(value), hi(0) {}
				Wide(const uint64_t lo, const uint64_t hi) noexcept : lo(lo), hi(hi) {}
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
			typedef __uint128_t wide_t;
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
		 * @brief Сложение слов с переносом
		 *
		 * @details Собиратель сводит это к команде сложения с переносом; сложение через
		 *          число двойной разрядности стоило вдвое дороже на всякое слово
		 *
		 * @param first  первое слагаемое
		 * @param second второе слагаемое
		 * @param carry  перенос из младшего слова, ноль либо единица
		 * @param result место, в которое помещается сумма
		 * @return       перенос в старшее слово, ноль либо единица
		 *
		 */
		static inline uint64_t adc(const uint64_t first, const uint64_t second, const uint64_t carry, uint64_t & result) noexcept {
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
		 * @brief Вычитание слов с заёмом
		 *
		 * @param first  уменьшаемое
		 * @param second вычитаемое
		 * @param borrow заём из младшего слова, ноль либо единица
		 * @param result место, в которое помещается разность
		 * @return       заём из старшего слова, ноль либо единица
		 *
		 */
		static inline uint64_t sbb(const uint64_t first, const uint64_t second, const uint64_t borrow, uint64_t & result) noexcept {
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

#endif
