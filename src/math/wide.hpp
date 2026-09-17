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

	namespace nts {
		namespace math {
			/**
			 * @brief Целое число двойной разрядности из двух слов
			 *
			 */
			typedef struct Wide {
				// Младшее и старшее слова
				uint64_t lo, hi;
				/**
				 * @brief Конструкторы
				 *
				 */
				Wide() noexcept : lo(0), hi(0) {}
				Wide(const uint64_t value) noexcept : lo(value), hi(0) {}
				Wide(const uint64_t lo, const uint64_t hi) noexcept : lo(lo), hi(hi) {}
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
					Wide result;
					#if defined(_M_X64)
						result.lo = ::_umul128(this->lo, other, &result.hi);
					#else
						result.lo = (this->lo * other);
						result.hi = ::__umulh(this->lo, other);
					#endif
					result.hi += (this->hi * other);
					return result;
				}
				/**
				 * @brief Сложение
				 *
				 */
				Wide operator + (const Wide & other) const noexcept {
					Wide result(this->lo + other.lo, this->hi + other.hi);
					if(result.lo < other.lo) result.hi++;
					return result;
				}
				Wide operator + (const uint64_t other) const noexcept { return ((* this) + Wide(other)); }
				Wide & operator += (const Wide & other) noexcept { (* this) = ((* this) + other); return (* this); }
				Wide & operator += (const uint64_t other) noexcept { (* this) = ((* this) + other); return (* this); }
				friend Wide operator + (const uint64_t first, const Wide & second) noexcept { return (second + first); }
				/**
				 * @brief Вычитание слова с заёмом из старшего слова
				 *
				 */
				Wide operator - (const uint64_t other) const noexcept {
					Wide result(this->lo - other, this->hi);
					if(this->lo < other) result.hi--;
					return result;
				}
				/**
				 * @brief Сдвиги
				 *
				 */
				Wide operator >> (const int shift) const noexcept {
					if(shift == 0) return (* this);
					if(shift >= 64) return Wide(this->hi >> (shift - 64), 0);
					return Wide((this->lo >> shift) | (this->hi << (64 - shift)), this->hi >> shift);
				}
				Wide operator << (const int shift) const noexcept {
					if(shift == 0) return (* this);
					if(shift >= 64) return Wide(0, this->lo << (shift - 64));
					return Wide(this->lo << shift, (this->hi << shift) | (this->lo >> (64 - shift)));
				}
				/**
				 * @brief Маска и объединение по младшему слову
				 *
				 */
				Wide operator & (const uint64_t mask) const noexcept { return Wide(this->lo & mask, 0); }
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
					#if defined(_M_X64)
						uint64_t remainder = 0;
						(void) ::_udiv128(this->hi % divisor, this->lo, divisor, &remainder);
						return Wide(remainder, 0);
					#else
						uint64_t remainder = (this->hi % divisor);
						for(int i = 63; i >= 0; i--){
							const uint64_t bit = ((this->lo >> i) & 1u);
							const uint64_t carry = (remainder >> 63);
							remainder = ((remainder << 1) | bit);
							if(carry || (remainder >= divisor)) remainder -= divisor;
						}
						return Wide(remainder, 0);
					#endif
				}
			} wide_t;
		};
	};
/**
 * Для собирателей GCC и Clang
 */
#else
	namespace nts {
		namespace math {
			/**
			 * @brief Целое число двойной разрядности
			 *
			 */
			typedef __uint128_t wide_t;
		};
	};
#endif

#endif // __ANTS_MATH_WIDE__
