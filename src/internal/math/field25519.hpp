/**
 * @file field25519.hpp
 * @date 2026-09-29
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
 * @brief Заголовочный файл внутреннего модуля ядер арифметики поля по модулю 2^255 - 19
 *
 * @note Модуль внутренний: он лежит в src и наружному договору библиотеки не
 *       принадлежит. Ядра встраиваются и в арифметику поля (math/field25519.cpp), и в
 *       лестницу Монтгомери (agreement/x25519.cpp): лестница зовёт умножение и квадрат
 *       по восемь раз на каждом из 255 шагов, и вызов через границу единицы трансляции
 *       стоил седьмую часть умножения точки (M4 15,0 мкс против 13,2 при встроенных
 *       ядрах, круг 53, 29.09.2026)
 *
 * @note Переносы после произведения идут двумя переплетёнными цепочками, а не одной
 *       нитью через все конечности (решение 6 шапки field25519.cpp). Сложение и
 *       вычитание здесь без волны переносов: они для цепочек с известным запасом
 *       конечностей (лестница), общие сложение и вычитание с волной остаются в
 *       math/field25519.cpp
 *
 * @note Под x86-64 при MULX и ADCX/ADOX у машины есть второй набор ядер - на четырёх
 *       словах по шестьдесят четыре разряда (пространство имён words): перевод
 *       x25519_fe64_mul и x25519_fe64_sqr из x25519-x86_64.pl OpenSSL во встроенный
 *       ассемблер, приведение по 2^256 - 38 умножением старшей половины на 38. Лестница
 *       X25519 на них 47,8 мкс против 55,7 у libcrypto на Xeon E5-2630 v4 (0,86) при
 *       72,5 у конечностей на C++ (решение 7 x25519.cpp)
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_INTERNAL_MATH_FIELD25519__
#define __ANTS_INTERNAL_MATH_FIELD25519__

/**
 * Стандартные заголовочные файлы
 */
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <math/wide.hpp>
#include <math/field25519.hpp>

/**
 * @brief Основное пространство имён
 */
namespace nts {
	/**
	 * @brief Пространство имён математики
	 */
	namespace math {
		/**
		 * @brief Пространство имён арифметики поля по модулю 2^255 - 19
		 */
		namespace field25519 {
			/**
			 * @brief Пространство имён встраиваемых ядер поля
			 */
			namespace kernel {
				/**
				 * @brief Удвоенное слово для произведений конечностей
				 *
				 */
				typedef nts::math::wide_t wide_t;
				/**
				 * @brief Маска пятидесяти одного разряда конечности
				 *
				 */
				static constexpr uint64_t MASK = ((static_cast <uint64_t> (1) << 51) - 1);
				/**
				 * @brief Младшая конечность удвоенного модуля 2^256 - 38: 2^52 - 38
				 *
				 */
				static constexpr uint64_t DOUBLED_LOW = ((static_cast <uint64_t> (1) << 52) - 38);
				/**
				 * @brief Старшие конечности удвоенного модуля: 2^52 - 2
				 *
				 */
				static constexpr uint64_t DOUBLED_HIGH = ((static_cast <uint64_t> (1) << 52) - 2);
				/**
				 * @brief Метод сложения элементов поля без волны переносов
				 *
				 * @details Конечности после умножения и квадрата меньше 2^51 + 2^13, сумма двух
				 *          таких меньше 2^53: умножение принимает конечности до 2^54 (решение 2
				 *          field25519.cpp), и волна переносов на каждом сложении цепочке с
				 *          известным запасом не нужна (решение 6 x25519.cpp)
				 *
				 * @param first  первое слагаемое
				 * @param second второе слагаемое
				 * @param result место, в которое помещается сумма
				 *
				 */
				static __ANTS_INLINE__ void plus(const element_t & first, const element_t & second, element_t & result) noexcept {
					/**
					 * Выполняем перебор конечностей слагаемых
					 */
					for(size_t i = 0; i < LIMBS; i++)
						// Складываем очередные конечности
						result.limbs[i] = (first.limbs[i] + second.limbs[i]);
				}
				/**
				 * @brief Метод вычитания элементов поля без волны переносов
				 *
				 * @details К уменьшаемому прибавляется удвоенный модуль, чтобы разность не ушла за
				 *          ноль: разность конечностей после умножения меньше 2^52 + 2^51 + 2^13, а
				 *          сумма такой разности и суммы двух конечностей после умножения меньше
				 *          2^54, что умножение принимает (решение 6 x25519.cpp)
				 *
				 * @param first  уменьшаемое
				 * @param second вычитаемое
				 * @param result место, в которое помещается разность
				 *
				 */
				static __ANTS_INLINE__ void minus(const element_t & first, const element_t & second, element_t & result) noexcept {
					// Вычитаем младшие конечности с прибавлением удвоенного модуля
					result.limbs[0] = ((first.limbs[0] + DOUBLED_LOW) - second.limbs[0]);
					/**
					 * Выполняем перебор старших конечностей
					 */
					for(size_t i = 1; i < LIMBS; i++)
						// Вычитаем очередные конечности с прибавлением удвоенного модуля
						result.limbs[i] = ((first.limbs[i] + DOUBLED_HIGH) - second.limbs[i]);
				}
				/**
				 * @brief Метод завершения произведения: переносы двумя переплетёнными цепочками
				 *
				 * @details Разряды всякой конечности сверх пятидесяти одного уходят в следующую, перенос
				 *          из старшей возвращается в младшую с множителем девятнадцать. Цепочки идут
				 *          двумя переплетёнными нитями (третья → четвёртая → старшая → младшая → вторая и
				 *          младшая → вторая → третья → четвёртая), а не одной нитью через все конечности:
				 *          глубина зависимости четыре шага вместо семи, а итог тот же (решение 6 шапки)
				 *
				 * @param r0     младшая конечность произведения до переносов
				 * @param r1     вторая конечность произведения до переносов
				 * @param r2     третья конечность произведения до переносов
				 * @param r3     четвёртая конечность произведения до переносов
				 * @param r4     старшая конечность произведения до переносов
				 * @param result место, в которое помещается произведение
				 *
				 */
				static __ANTS_INLINE__ void finish(wide_t r0, wide_t r1, wide_t r2, wide_t r3, wide_t r4, element_t & result) noexcept {
					// Переносим разряды третьей конечности сверх пятидесяти одного в четвёртую
					r3 += static_cast <uint64_t> (r2 >> 51);
					// Отбрасываем перенесённые разряды третьей конечности
					uint64_t g2 = (static_cast <uint64_t> (r2) & MASK);
					// Переносим разряды младшей конечности сверх пятидесяти одного во вторую
					r1 += static_cast <uint64_t> (r0 >> 51);
					// Отбрасываем перенесённые разряды младшей конечности
					uint64_t g0 = (static_cast <uint64_t> (r0) & MASK);
					// Переносим разряды четвёртой конечности сверх пятидесяти одного в старшую
					r4 += static_cast <uint64_t> (r3 >> 51);
					// Отбрасываем перенесённые разряды четвёртой конечности
					uint64_t g3 = (static_cast <uint64_t> (r3) & MASK);
					// Переносим разряды второй конечности сверх пятидесяти одного в третью
					g2 += static_cast <uint64_t> (r1 >> 51);
					// Отбрасываем перенесённые разряды второй конечности
					uint64_t g1 = (static_cast <uint64_t> (r1) & MASK);
					// Сворачиваем разряды старшей конечности сверх пятидесяти одного в младшую
					g0 += (static_cast <uint64_t> (r4 >> 51) * 19);
					// Отбрасываем перенесённые разряды старшей конечности
					const uint64_t g4 = (static_cast <uint64_t> (r4) & MASK);
					// Переносим разряды третьей конечности сверх пятидесяти одного в четвёртую
					g3 += (g2 >> 51);
					// Отбрасываем перенесённые разряды третьей конечности
					g2 &= MASK;
					// Переносим разряды младшей конечности сверх пятидесяти одного во вторую
					g1 += (g0 >> 51);
					// Отбрасываем перенесённые разряды младшей конечности
					g0 &= MASK;
					// Записываем конечности произведения
					result.limbs[0] = g0;
					result.limbs[1] = g1;
					result.limbs[2] = g2;
					result.limbs[3] = g3;
					result.limbs[4] = g4;
				}
				/**
				 * @brief Метод умножения элементов поля
				 *
				 * @details Произведения идут рядами конечностей первого сомножителя, старшие
				 *          конечности второго по ходу получают множитель сворачивания девятнадцать
				 *
				 * @param first  первый сомножитель с конечностями до 2^54
				 * @param second второй сомножитель с конечностями до 2^54
				 * @param result место, в которое помещается произведение
				 *
				 */
				static __ANTS_INLINE__ void multiply(const element_t & first, const element_t & second, element_t & result) noexcept {
					// Конечности второго сомножителя: старшие по ходу получают множитель сворачивания
					uint64_t b0 = second.limbs[0], b1 = second.limbs[1], b2 = second.limbs[2], b3 = second.limbs[3], b4 = second.limbs[4];
					// Очередная конечность первого сомножителя
					uint64_t a = first.limbs[0];
					// Произведения младшей конечности первого сомножителя на все конечности второго
					wide_t r0 = (static_cast <wide_t> (a) * b0);
					wide_t r1 = (static_cast <wide_t> (a) * b1);
					wide_t r2 = (static_cast <wide_t> (a) * b2);
					wide_t r3 = (static_cast <wide_t> (a) * b3);
					wide_t r4 = (static_cast <wide_t> (a) * b4);
					// Вторая конечность первого сомножителя: старшая конечность второго сворачивается множителем девятнадцать
					a = first.limbs[1];
					r0 += (static_cast <wide_t> (a) * (b4 *= 19));
					r1 += (static_cast <wide_t> (a) * b0);
					r2 += (static_cast <wide_t> (a) * b1);
					r3 += (static_cast <wide_t> (a) * b2);
					r4 += (static_cast <wide_t> (a) * b3);
					// Третья конечность первого сомножителя
					a = first.limbs[2];
					r0 += (static_cast <wide_t> (a) * (b3 *= 19));
					r1 += (static_cast <wide_t> (a) * b4);
					r2 += (static_cast <wide_t> (a) * b0);
					r3 += (static_cast <wide_t> (a) * b1);
					r4 += (static_cast <wide_t> (a) * b2);
					// Четвёртая конечность первого сомножителя
					a = first.limbs[3];
					r0 += (static_cast <wide_t> (a) * (b2 *= 19));
					r1 += (static_cast <wide_t> (a) * b3);
					r2 += (static_cast <wide_t> (a) * b4);
					r3 += (static_cast <wide_t> (a) * b0);
					r4 += (static_cast <wide_t> (a) * b1);
					// Старшая конечность первого сомножителя
					a = first.limbs[4];
					r0 += (static_cast <wide_t> (a) * (b1 *= 19));
					r1 += (static_cast <wide_t> (a) * b2);
					r2 += (static_cast <wide_t> (a) * b3);
					r3 += (static_cast <wide_t> (a) * b4);
					r4 += (static_cast <wide_t> (a) * b0);
					// Завершаем произведение переносами
					finish(r0, r1, r2, r3, r4, result);
				}
				/**
				 * @brief Метод возведения элемента поля в квадрат
				 *
				 * @details Всякая пара разных конечностей встречается в квадрате дважды: одна из
				 *          них удваивается, старшие по ходу получают множитель сворачивания
				 *
				 * @param value  возводимый элемент с конечностями до 2^54
				 * @param result место, в которое помещается квадрат
				 *
				 */
				static __ANTS_INLINE__ void square(const element_t & value, element_t & result) noexcept {
					// Конечности возводимого элемента: по ходу удваиваются либо получают множитель сворачивания
					uint64_t g0 = value.limbs[0], g1 = value.limbs[1], g2 = value.limbs[2], g3 = value.limbs[3], g4 = value.limbs[4];
					// Квадрат младшей конечности
					wide_t r0 = (static_cast <wide_t> (g0) * g0);
					// Удвоенная младшая конечность: всякая пара разных конечностей встречается в квадрате дважды
					g0 *= 2;
					// Произведения удвоенной младшей конечности на прочие
					wide_t r1 = (static_cast <wide_t> (g0) * g1);
					wide_t r2 = (static_cast <wide_t> (g0) * g2);
					wide_t r3 = (static_cast <wide_t> (g0) * g3);
					wide_t r4 = (static_cast <wide_t> (g0) * g4);
					// Старшая конечность до сворачивания
					g0 = g4;
					// Квадрат старшей конечности сворачивается множителем девятнадцать
					r3 += (static_cast <wide_t> (g0) * (g4 *= 19));
					// Квадрат второй конечности
					r2 += (static_cast <wide_t> (g1) * g1);
					// Удвоенная вторая конечность
					g1 *= 2;
					// Произведения удвоенной второй конечности на третью, четвёртую и свёрнутую старшую
					r3 += (static_cast <wide_t> (g1) * g2);
					r4 += (static_cast <wide_t> (g1) * g3);
					r0 += (static_cast <wide_t> (g1) * g4);
					// Четвёртая конечность до сворачивания
					g0 = g3;
					// Квадрат четвёртой конечности сворачивается множителем девятнадцать
					r1 += (static_cast <wide_t> (g0) * (g3 *= 19));
					// Удвоенное произведение четвёртой и свёрнутой старшей конечностей
					r2 += (static_cast <wide_t> (g0 * 2) * g4);
					// Квадрат третьей конечности
					r4 += (static_cast <wide_t> (g2) * g2);
					// Удвоенная третья конечность
					g2 *= 2;
					// Произведения удвоенной третьей конечности на свёрнутые четвёртую и старшую
					r0 += (static_cast <wide_t> (g2) * g3);
					r1 += (static_cast <wide_t> (g2) * g4);
					// Завершаем квадрат переносами
					finish(r0, r1, r2, r3, r4, result);
				}
				/**
				 * @brief Метод умножения элемента поля на малое число
				 *
				 * @param value  умножаемый элемент
				 * @param factor множитель, не больше 2^32
				 * @param result место, в которое помещается произведение
				 *
				 */
				static __ANTS_INLINE__ void scale(const element_t & value, const uint64_t factor, element_t & result) noexcept {
					// Произведения конечностей на множитель: конечность до 2^54, множитель до 2^32
					wide_t r0 = (static_cast <wide_t> (value.limbs[0]) * factor);
					// Вторая конечность произведения
					wide_t r1 = (static_cast <wide_t> (value.limbs[1]) * factor);
					// Третья конечность произведения
					wide_t r2 = (static_cast <wide_t> (value.limbs[2]) * factor);
					// Четвёртая конечность произведения
					wide_t r3 = (static_cast <wide_t> (value.limbs[3]) * factor);
					// Старшая конечность произведения
					wide_t r4 = (static_cast <wide_t> (value.limbs[4]) * factor);
					// Завершаем произведение переносами
					finish(r0, r1, r2, r3, r4, result);
				}
			};
		};
	};
};

/**
 * Под x86-64 с GCC и clang при MULX и ADCX/ADOX у машины лестница идёт на четырёх словах по
 * шестьдесят четыре разряда: ядра - перевод x25519_fe64_mul и x25519_fe64_sqr из
 * x25519-x86_64.pl OpenSSL во встроенный ассемблер. Под ASan без оптимизации не берётся
 * (регистры общего назначения заняты целиком, признак __ANTS_ASAN_UNOPTIMIZED__ из sys/global.hpp)
 */
#if defined(__x86_64__) && defined(__GNUC__) && !defined(_MSC_VER) && !defined(__ANTS_ASAN_UNOPTIMIZED__) && !defined(ANTS_NO_MACHINE)
	/**
	 * Признак наличия ядер на словах
	 */
	#define __ANTS_FIELD25519_WORDS__
	/**
	 * Заголовочный файл встроенных команд переносов
	 */
	#include <immintrin.h>
	/**
	 * @brief Основное пространство имён
	 */
	namespace nts {
		/**
		 * @brief Пространство имён математики
		 */
		namespace math {
			/**
			 * @brief Пространство имён арифметики поля по модулю 2^255 - 19
			 */
			namespace field25519 {
				/**
				 * @brief Пространство имён ядер поля на четырёх словах
				 *
				 * @note Значения держатся в области [0, 2^256) и приводятся по 2^256 - 38 =
				 *       2 · (2^255 - 19): старшая половина произведения умножается на 38 и
				 *       прибавляется к младшей, перенос из старшего слова - ещё раз на 38.
				 *       Единственная запись по модулю 2^255 - 19 выводится лишь при записи в
				 *       байты (store), как у fe64_tobytes OpenSSL
				 *
				 */
				namespace words {
					/**
					 * @brief Элемент поля четырьмя словами от младшего к старшему
					 *
					 */
					typedef uint64_t element_t[4];
					/**
					 * @brief Нуль в памяти: источник для ADCX/ADOX, продвигающих лишь перенос
					 *
					 * @details Все четырнадцать регистров общего назначения заняты накопителями,
					 *          временными значениями и указателями, и нуль берётся из памяти
					 *
					 */
					static const uint64_t ZERO = 0;
					/**
					 * @brief Метод умножения элементов поля на словах
					 *
					 * @details Перевод x25519_fe64_mul: ряды по словам первого сомножителя двумя
					 *          цепочками переносов ADCX и ADOX, второй сомножитель читается из
					 *          памяти операндами MULX, приведение умножением старшей половины на 38
					 *
					 * @param first  первый сомножитель
					 * @param second второй сомножитель
					 * @param result место, в которое помещается произведение
					 *
					 */
					static __ANTS_INLINE__ void multiply(const element_t & first, const element_t & second, element_t & result) noexcept {
						__asm__ __volatile__(
							/* Ряд младшего слова первого сомножителя */
							"mov   8*0(%[f]), %%rdx\n\t"
							"mulx  8*0(%[g]), %%r8, %%rax\n\t"
							"xor   %%ebx, %%ebx\n\t"
							"mulx  8*1(%[g]), %%r9, %%rbx\n\t"
							"adcx  %%rax, %%r9\n\t"
							"mulx  8*2(%[g]), %%r10, %%rax\n\t"
							"adcx  %%rbx, %%r10\n\t"
							"mulx  8*3(%[g]), %%r11, %%r12\n\t"
							"mov   8*1(%[f]), %%rdx\n\t"
							"adcx  %%rax, %%r11\n\t"
							"adcx  %[zero], %%r12\n\t"
							/* Ряд второго слова */
							"mulx  8*0(%[g]), %%rax, %%rbx\n\t"
							"adox  %%rax, %%r9\n\t"
							"adcx  %%rbx, %%r10\n\t"
							"mulx  8*1(%[g]), %%rax, %%rbx\n\t"
							"adox  %%rax, %%r10\n\t"
							"adcx  %%rbx, %%r11\n\t"
							"mulx  8*2(%[g]), %%rax, %%rbx\n\t"
							"adox  %%rax, %%r11\n\t"
							"adcx  %%rbx, %%r12\n\t"
							"mulx  8*3(%[g]), %%rax, %%r13\n\t"
							"mov   8*2(%[f]), %%rdx\n\t"
							"adox  %%rax, %%r12\n\t"
							"adcx  %[zero], %%r13\n\t"
							"adox  %[zero], %%r13\n\t"
							/* Ряд третьего слова */
							"mulx  8*0(%[g]), %%rax, %%rbx\n\t"
							"adcx  %%rax, %%r10\n\t"
							"adox  %%rbx, %%r11\n\t"
							"mulx  8*1(%[g]), %%rax, %%rbx\n\t"
							"adcx  %%rax, %%r11\n\t"
							"adox  %%rbx, %%r12\n\t"
							"mulx  8*2(%[g]), %%rax, %%rbx\n\t"
							"adcx  %%rax, %%r12\n\t"
							"adox  %%rbx, %%r13\n\t"
							"mulx  8*3(%[g]), %%rax, %%r14\n\t"
							"mov   8*3(%[f]), %%rdx\n\t"
							"adcx  %%rax, %%r13\n\t"
							"adox  %[zero], %%r14\n\t"
							"adcx  %[zero], %%r14\n\t"
							/* Ряд старшего слова */
							"mulx  8*0(%[g]), %%rax, %%rbx\n\t"
							"adox  %%rax, %%r11\n\t"
							"adcx  %%rbx, %%r12\n\t"
							"mulx  8*1(%[g]), %%rax, %%rbx\n\t"
							"adox  %%rax, %%r12\n\t"
							"adcx  %%rbx, %%r13\n\t"
							"mulx  8*2(%[g]), %%rax, %%rbx\n\t"
							"adox  %%rax, %%r13\n\t"
							"adcx  %%rbx, %%r14\n\t"
							"mulx  8*3(%[g]), %%rax, %%r15\n\t"
							"mov   $38, %%edx\n\t"
							"adox  %%rax, %%r14\n\t"
							"adcx  %[zero], %%r15\n\t"
							"adox  %[zero], %%r15\n\t"
							/* Приведение: старшая половина на 38 к младшей, перенос старшего слова ещё раз на 38 */
							"mulx  %%r12, %%rax, %%rbx\n\t"
							"adcx  %%rax, %%r8\n\t"
							"adox  %%rbx, %%r9\n\t"
							"mulx  %%r13, %%rax, %%rbx\n\t"
							"adcx  %%rax, %%r9\n\t"
							"adox  %%rbx, %%r10\n\t"
							"mulx  %%r14, %%rax, %%rbx\n\t"
							"adcx  %%rax, %%r10\n\t"
							"adox  %%rbx, %%r11\n\t"
							"mulx  %%r15, %%rax, %%r12\n\t"
							"adcx  %%rax, %%r11\n\t"
							"adox  %[zero], %%r12\n\t"
							"adcx  %[zero], %%r12\n\t"
							"imulq %%rdx, %%r12\n\t"
							"add   %%r12, %%r8\n\t"
							"adc   $0, %%r9\n\t"
							"adc   $0, %%r10\n\t"
							"adc   $0, %%r11\n\t"
							"sbb   %%rax, %%rax\n\t"
							"and   $38, %%rax\n\t"
							"add   %%rax, %%r8\n\t"
							"mov   %%r9, 8*1(%[h])\n\t"
							"mov   %%r10, 8*2(%[h])\n\t"
							"mov   %%r11, 8*3(%[h])\n\t"
							"mov   %%r8, 8*0(%[h])\n\t"
							: : [h] "r" (result), [f] "r" (first), [g] "r" (second), [zero] "m" (ZERO)
							: "rax", "rbx", "rdx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "cc", "memory"
						);
					}
					/**
					 * @brief Метод возведения элемента поля в квадрат на словах
					 *
					 * @details Перевод x25519_fe64_sqr: произведения разных слов, удвоение
					 *          цепочкой ADCX с квадратами слов по цепочке ADOX, приведение как у
					 *          умножения
					 *
					 * @param value  возводимый элемент
					 * @param result место, в которое помещается квадрат
					 *
					 */
					static __ANTS_INLINE__ void square(const element_t & value, element_t & result) noexcept {
						__asm__ __volatile__(
							/* Произведения разных слов */
							"mov   8*0(%[f]), %%rdx\n\t"
							"mulx  %%rdx, %%r8, %%r15\n\t"
							"mulx  8*1(%[f]), %%r9, %%rax\n\t"
							"xor   %%ebx, %%ebx\n\t"
							"mulx  8*2(%[f]), %%r10, %%rbx\n\t"
							"adcx  %%rax, %%r10\n\t"
							"mulx  8*3(%[f]), %%r11, %%r12\n\t"
							"mov   8*1(%[f]), %%rdx\n\t"
							"adcx  %%rbx, %%r11\n\t"
							"adcx  %[zero], %%r12\n\t"
							"mulx  8*2(%[f]), %%rax, %%rbx\n\t"
							"adox  %%rax, %%r11\n\t"
							"adcx  %%rbx, %%r12\n\t"
							"mulx  8*3(%[f]), %%rax, %%r13\n\t"
							"mov   8*2(%[f]), %%rdx\n\t"
							"adox  %%rax, %%r12\n\t"
							"adcx  %[zero], %%r13\n\t"
							"mulx  8*3(%[f]), %%rax, %%r14\n\t"
							"mov   8*1(%[f]), %%rdx\n\t"
							"adox  %%rax, %%r13\n\t"
							"adcx  %[zero], %%r14\n\t"
							"adox  %[zero], %%r14\n\t"
							/* Удвоение цепочкой ADCX, квадраты слов цепочкой ADOX */
							"adcx  %%r9, %%r9\n\t"
							"adox  %%r15, %%r9\n\t"
							"adcx  %%r10, %%r10\n\t"
							"mulx  %%rdx, %%rax, %%rbx\n\t"
							"mov   8*2(%[f]), %%rdx\n\t"
							"adcx  %%r11, %%r11\n\t"
							"adox  %%rax, %%r10\n\t"
							"adcx  %%r12, %%r12\n\t"
							"adox  %%rbx, %%r11\n\t"
							"mulx  %%rdx, %%rax, %%rbx\n\t"
							"mov   8*3(%[f]), %%rdx\n\t"
							"adcx  %%r13, %%r13\n\t"
							"adox  %%rax, %%r12\n\t"
							"adcx  %%r14, %%r14\n\t"
							"adox  %%rbx, %%r13\n\t"
							"mulx  %%rdx, %%rax, %%r15\n\t"
							"mov   $38, %%edx\n\t"
							"adox  %%rax, %%r14\n\t"
							"adcx  %[zero], %%r15\n\t"
							"adox  %[zero], %%r15\n\t"
							/* Приведение как у умножения */
							"mulx  %%r12, %%rax, %%rbx\n\t"
							"adcx  %%rax, %%r8\n\t"
							"adox  %%rbx, %%r9\n\t"
							"mulx  %%r13, %%rax, %%rbx\n\t"
							"adcx  %%rax, %%r9\n\t"
							"adox  %%rbx, %%r10\n\t"
							"mulx  %%r14, %%rax, %%rbx\n\t"
							"adcx  %%rax, %%r10\n\t"
							"adox  %%rbx, %%r11\n\t"
							"mulx  %%r15, %%rax, %%r12\n\t"
							"adcx  %%rax, %%r11\n\t"
							"adox  %[zero], %%r12\n\t"
							"adcx  %[zero], %%r12\n\t"
							"imulq %%rdx, %%r12\n\t"
							"add   %%r12, %%r8\n\t"
							"adc   $0, %%r9\n\t"
							"adc   $0, %%r10\n\t"
							"adc   $0, %%r11\n\t"
							"sbb   %%rax, %%rax\n\t"
							"and   $38, %%rax\n\t"
							"add   %%rax, %%r8\n\t"
							"mov   %%r9, 8*1(%[h])\n\t"
							"mov   %%r10, 8*2(%[h])\n\t"
							"mov   %%r11, 8*3(%[h])\n\t"
							"mov   %%r8, 8*0(%[h])\n\t"
							: : [h] "r" (result), [f] "r" (value), [zero] "m" (ZERO)
							: "rax", "rbx", "rdx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "cc", "memory"
						);
					}
					/**
					 * @brief Метод умножения элемента поля на малое число
					 *
					 * @param value  умножаемый элемент
					 * @param factor множитель, не больше 2^32
					 * @param result место, в которое помещается произведение
					 *
					 */
					static __ANTS_INLINE__ void scale(const element_t & value, const uint64_t factor, element_t & result) noexcept {
						// Произведение младшего слова на множитель
						wide_t item = (static_cast <wide_t> (value[0]) * factor);
						// Младшее слово произведения
						uint64_t h0 = static_cast <uint64_t> (item);
						// Перенос в следующее слово
						uint64_t carry = static_cast <uint64_t> (item >> 64);
						// Произведение второго слова с переносом
						item = ((static_cast <wide_t> (value[1]) * factor) + carry);
						// Второе слово произведения
						uint64_t h1 = static_cast <uint64_t> (item);
						// Перенос в следующее слово
						carry = static_cast <uint64_t> (item >> 64);
						// Произведение третьего слова с переносом
						item = ((static_cast <wide_t> (value[2]) * factor) + carry);
						// Третье слово произведения
						uint64_t h2 = static_cast <uint64_t> (item);
						// Перенос в следующее слово
						carry = static_cast <uint64_t> (item >> 64);
						// Произведение старшего слова с переносом
						item = ((static_cast <wide_t> (value[3]) * factor) + carry);
						// Старшее слово произведения
						uint64_t h3 = static_cast <uint64_t> (item);
						// Перенос сверх 2^256 сворачивается множителем 38
						carry = (static_cast <uint64_t> (item >> 64) * 38);
						// Прибавляем свёрнутый перенос цепочкой переносов
						unsigned char flag = _addcarry_u64(0, h0, carry, reinterpret_cast <unsigned long long *> (&h0));
						flag = _addcarry_u64(flag, h1, 0, reinterpret_cast <unsigned long long *> (&h1));
						flag = _addcarry_u64(flag, h2, 0, reinterpret_cast <unsigned long long *> (&h2));
						flag = _addcarry_u64(flag, h3, 0, reinterpret_cast <unsigned long long *> (&h3));
						// Перенос из старшего слова сворачивается ещё раз
						h0 += ((0 - static_cast <uint64_t> (flag)) & 38);
						// Записываем слова произведения
						result[0] = h0;
						result[1] = h1;
						result[2] = h2;
						result[3] = h3;
					}
					/**
					 * @brief Метод сложения элементов поля на словах
					 *
					 * @param first  первое слагаемое
					 * @param second второе слагаемое
					 * @param result место, в которое помещается сумма
					 *
					 */
					static __ANTS_INLINE__ void plus(const element_t & first, const element_t & second, element_t & result) noexcept {
						// Слова суммы
						uint64_t h0, h1, h2, h3;
						// Складываем слова цепочкой переносов
						unsigned char flag = _addcarry_u64(0, first[0], second[0], reinterpret_cast <unsigned long long *> (&h0));
						flag = _addcarry_u64(flag, first[1], second[1], reinterpret_cast <unsigned long long *> (&h1));
						flag = _addcarry_u64(flag, first[2], second[2], reinterpret_cast <unsigned long long *> (&h2));
						flag = _addcarry_u64(flag, first[3], second[3], reinterpret_cast <unsigned long long *> (&h3));
						// Перенос сверх 2^256 сворачивается множителем 38 цепочкой переносов
						flag = _addcarry_u64(0, h0, ((0 - static_cast <uint64_t> (flag)) & 38), reinterpret_cast <unsigned long long *> (&h0));
						flag = _addcarry_u64(flag, h1, 0, reinterpret_cast <unsigned long long *> (&h1));
						flag = _addcarry_u64(flag, h2, 0, reinterpret_cast <unsigned long long *> (&h2));
						flag = _addcarry_u64(flag, h3, 0, reinterpret_cast <unsigned long long *> (&h3));
						// Перенос из старшего слова сворачивается ещё раз
						h0 += ((0 - static_cast <uint64_t> (flag)) & 38);
						// Записываем слова суммы
						result[0] = h0;
						result[1] = h1;
						result[2] = h2;
						result[3] = h3;
					}
					/**
					 * @brief Метод вычитания элементов поля на словах
					 *
					 * @param first  уменьшаемое
					 * @param second вычитаемое
					 * @param result место, в которое помещается разность
					 *
					 */
					static __ANTS_INLINE__ void minus(const element_t & first, const element_t & second, element_t & result) noexcept {
						// Слова разности
						uint64_t h0, h1, h2, h3;
						// Вычитаем слова цепочкой заёмов
						unsigned char flag = _subborrow_u64(0, first[0], second[0], reinterpret_cast <unsigned long long *> (&h0));
						flag = _subborrow_u64(flag, first[1], second[1], reinterpret_cast <unsigned long long *> (&h1));
						flag = _subborrow_u64(flag, first[2], second[2], reinterpret_cast <unsigned long long *> (&h2));
						flag = _subborrow_u64(flag, first[3], second[3], reinterpret_cast <unsigned long long *> (&h3));
						// Заём за ноль сворачивается вычитанием 38 цепочкой заёмов
						flag = _subborrow_u64(0, h0, ((0 - static_cast <uint64_t> (flag)) & 38), reinterpret_cast <unsigned long long *> (&h0));
						flag = _subborrow_u64(flag, h1, 0, reinterpret_cast <unsigned long long *> (&h1));
						flag = _subborrow_u64(flag, h2, 0, reinterpret_cast <unsigned long long *> (&h2));
						flag = _subborrow_u64(flag, h3, 0, reinterpret_cast <unsigned long long *> (&h3));
						// Заём из старшего слова сворачивается ещё раз
						h0 -= ((0 - static_cast <uint64_t> (flag)) & 38);
						// Записываем слова разности
						result[0] = h0;
						result[1] = h1;
						result[2] = h2;
						result[3] = h3;
					}
					/**
					 * @brief Метод разбора элемента поля из тридцати двух байтов
					 *
					 * @param data   разбираемые байты, записанные младшим байтом вперёд
					 * @param result место, в которое помещается разобранный элемент
					 *
					 */
					static __ANTS_INLINE__ void load(const uint8_t * data, element_t & result) noexcept {
						/**
						 * Выполняем перебор слов записи
						 */
						for(size_t i = 0; i < 4; i++){
							// Обнуляем очередное слово
							result[i] = 0;
							/**
							 * Выполняем перебор байтов очередного слова от старшего к младшему
							 */
							for(size_t j = 8; j > 0; j--)
								// Дописываем очередной байт в слово
								result[i] = ((result[i] << 8) | data[(i * 8) + (j - 1)]);
						}
						// Отбрасываем старший разряд: раздел 5 RFC 7748
						result[3] &= 0x7FFFFFFFFFFFFFFFULL;
					}
					/**
					 * @brief Метод записи элемента поля в тридцать два байта
					 *
					 * @details Единственная запись по модулю 2^255 - 19 из области [0, 2^256): как
					 *          у fe64_tobytes OpenSSL, сложение с 19 и разряд 2^255 выводят признак
					 *          «не меньше модуля», модуль вычитается по признаку без ветвлений
					 *
					 * @param value записываемый элемент
					 * @param data  место, в которое помещается запись младшим байтом вперёд
					 *
					 */
					static __ANTS_INLINE__ void store(const element_t & value, uint8_t * data) noexcept {
						// Слова записываемого элемента
						uint64_t a0 = value[0], a1 = value[1], a2 = value[2], a3 = value[3];
						// Старшее слово без разряда 2^255
						uint64_t top = ((a3 << 1) >> 1);
						// Разряд 2^255 как 19 плюс 19: сравнение с модулем тем же сложением
						uint64_t item = ((static_cast <uint64_t> (static_cast <int64_t> (a3) >> 63) & 19) + 19);
						// Прибавляем цепочкой переносов
						unsigned char flag = _addcarry_u64(0, a0, item, reinterpret_cast <unsigned long long *> (&a0));
						flag = _addcarry_u64(flag, a1, 0, reinterpret_cast <unsigned long long *> (&a1));
						flag = _addcarry_u64(flag, a2, 0, reinterpret_cast <unsigned long long *> (&a2));
						_addcarry_u64(flag, top, 0, reinterpret_cast <unsigned long long *> (&top));
						// Старшее слово без разряда 2^255
						a3 = ((top << 1) >> 1);
						// Если разряда 2^255 нет, девятнадцать вычитается обратно
						item = (static_cast <uint64_t> (~(static_cast <int64_t> (top) >> 63)) & 19);
						// Вычитаем цепочкой заёмов
						flag = _subborrow_u64(0, a0, item, reinterpret_cast <unsigned long long *> (&a0));
						flag = _subborrow_u64(flag, a1, 0, reinterpret_cast <unsigned long long *> (&a1));
						flag = _subborrow_u64(flag, a2, 0, reinterpret_cast <unsigned long long *> (&a2));
						_subborrow_u64(flag, a3, 0, reinterpret_cast <unsigned long long *> (&a3));
						// Слова записи
						const uint64_t items[4] = {a0, a1, a2, a3};
						/**
						 * Выполняем перебор слов записи
						 */
						for(size_t i = 0; i < 4; i++){
							/**
							 * Выполняем перебор байтов очередного слова от младшего к старшему
							 */
							for(size_t j = 0; j < 8; j++)
								// Записываем очередной байт слова
								data[(i * 8) + j] = static_cast <uint8_t> (items[i] >> (j * 8));
						}
					}
					/**
					 * @brief Метод условного обмена элементов поля на словах
					 *
					 * @param first  первый обмениваемый элемент
					 * @param second второй обмениваемый элемент
					 * @param flag   признак обмена
					 *
					 */
					static __ANTS_INLINE__ void swap(element_t & first, element_t & second, const uint64_t flag) noexcept {
						// Маска обмена: все разряды по признаку
						const uint64_t mask = (0 - (flag & 1));
						/**
						 * Выполняем перебор слов элементов
						 */
						for(size_t i = 0; i < 4; i++){
							// Разность слов под маской
							const uint64_t item = ((first[i] ^ second[i]) & mask);
							// Накладываем разность на первое слово
							first[i] ^= item;
							// Накладываем разность на второе слово
							second[i] ^= item;
						}
					}
					/**
					 * @brief Метод возведения элемента в степень 2^count
					 *
					 * @param value  возводимый элемент
					 * @param count  число возведений в квадрат
					 * @param result место, в которое помещается степень
					 *
					 */
					static __ANTS_INLINE__ void power(const element_t & value, const size_t count, element_t & result) noexcept {
						/**
						 * Выполняем перебор слов элемента
						 */
						for(size_t i = 0; i < 4; i++)
							// Переносим очередное слово
							result[i] = value[i];
						/**
						 * Выполняем возведение в квадрат заданное число раз
						 */
						for(size_t i = 0; i < count; i++)
							// Возводим накопленное значение в квадрат
							square(result, result);
					}
					/**
					 * @brief Метод обращения элемента поля на словах
					 *
					 * @details Та же цепочка степеней 2^255 - 21, что у обращения на конечностях
					 *          (решение 4 field25519.cpp)
					 *
					 * @param value  обращаемый элемент
					 * @param result место, в которое помещается обратный элемент
					 *
					 */
					static __ANTS_INLINE__ void invert(const element_t & value, element_t & result) noexcept {
						// Промежуточные степени цепочки
						element_t z2, z9, eleven, z10, z50, item, chain;
						// Вырабатываем z^2
						square(value, z2);
						// Вырабатываем z^4
						square(z2, item);
						// Вырабатываем z^8
						square(item, item);
						// Вырабатываем z^9
						multiply(item, value, z9);
						// Вырабатываем z^11
						multiply(z9, z2, eleven);
						// Вырабатываем z^22
						square(eleven, item);
						// Вырабатываем z^(2^5 - 1)
						multiply(item, z9, item);
						// Вырабатываем z^(2^10 - 2^5)
						power(item, 5, z10);
						// Вырабатываем z^(2^10 - 1)
						multiply(z10, item, z10);
						// Вырабатываем z^(2^20 - 2^10)
						power(z10, 10, item);
						// Вырабатываем z^(2^20 - 1)
						multiply(item, z10, item);
						// Вырабатываем z^(2^40 - 2^20)
						power(item, 20, chain);
						// Вырабатываем z^(2^40 - 1)
						multiply(chain, item, chain);
						// Вырабатываем z^(2^50 - 2^10)
						power(chain, 10, item);
						// Вырабатываем z^(2^50 - 1)
						multiply(item, z10, z50);
						// Вырабатываем z^(2^100 - 2^50)
						power(z50, 50, item);
						// Вырабатываем z^(2^100 - 1)
						multiply(item, z50, item);
						// Вырабатываем z^(2^200 - 2^100)
						power(item, 100, chain);
						// Вырабатываем z^(2^200 - 1)
						multiply(chain, item, chain);
						// Вырабатываем z^(2^250 - 2^50)
						power(chain, 50, item);
						// Вырабатываем z^(2^250 - 1)
						multiply(item, z50, chain);
						// Вырабатываем z^(2^255 - 32)
						power(chain, 5, chain);
						// Вырабатываем z^(2^255 - 21)
						multiply(chain, eleven, result);
					}
				};
			};
		};
	};
#endif

#endif // __ANTS_INTERNAL_MATH_FIELD25519__
