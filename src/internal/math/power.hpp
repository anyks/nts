/**
 * @file power.hpp
 * @date 2026-10-01
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
 * @brief Степень с фиксированным перебором 1024 разрядов на AVX2 без ADX
 *
 * @details Самостоятельная арифметика Монтгомери на 36 коэффициентах по 29 разрядов,
 *          основание области R = 2^1044. Произведение чередует четыре ряда с приведением;
 *          квадрат отдельно накапливает симметричную свёртку и приводит её. Развёртка
 *          четырёх коэффициентов квадрата намеренная: шаблонная запись оказалась медленнее.
 *
 * @section Намеренные решения
 * 1. Входы меньше 2m, m < 2^1024; коэффициенты не больше 2^29 + 64, старший - не больше
 *    1024. Четыре слова дополнения нулевые. Частичный перенос после каждых четырёх рядов
 *    ограничивает накопление: tools/math/power29.py даёт менее 0,688 от 2^64 у произведения
 *    и менее 0,860 у квадрата. Два заключительных прохода оставляют коэффициенты не больше
 *    2^29 + 43. Итог меньше m + 4m^2/R < 2m; старший коэффициент вновь меньше 1024.
 *    Доводка до m выполняется один раз после выхода из области, в обычных словах.
 * 2. Секретный показатель всегда перебирается по 1024 разрядам. Выбор записи читает всю
 *    таблицу в одном порядке; даже смещение внутри строки кеша от показателя не зависит.
 *    Произведение, младшие коэффициенты и маски индекса живут в кадре степени и затираются
 *    перед выходом. Буфер ядра не пересекается с числами, итог может совпадать с входом.
 * 3. Путь выбирается лишь для шестнадцати слов на AVX2 без ADX: ширины, признак машины и
 *    допустимость основания проверяются до вызова. Чужой код в реализации не используется;
 *    сторонняя арифметика служит эталоном результата и скорости.
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_INTERNAL_MATH_POWER__
#define __ANTS_INTERNAL_MATH_POWER__

/**
 * Стандартные заголовочные файлы
 */
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <sys/wipe.hpp>

/**
 * Векторный путь доступен gcc и clang на x86-64; прочие сборки используют обычные ядра
 */
#if defined(__x86_64__) && defined(__GNUC__) && !defined(_MSC_VER) && !defined(__ANTS_ASAN_UNOPTIMIZED__) && !defined(ANTS_NO_MACHINE)
	/**
	 * Заголовочный файл векторных команд
	 */
	#include <immintrin.h>
	/**
	 * Признак наличия степени на AVX2 для шестнадцати слов
	 */
	#define __ANTS_POWER16_AVX2__
	/**
	 * @brief Основное пространство имён
	 *
	 */
	namespace nts {
		/**
		 * @brief Пространство имён математики
		 *
		 */
		namespace math {
			/**
			 * @brief Пространство имён машинных ядер
			 *
			 */
			namespace kernel {
				/**
				 * @brief Метод умножения Монтгомери на коэффициентах по 29 разрядов
				 *
				 * @param buffer  отдельный рабочий буфер из 84 слов; затирает вызывающий
				 * @param result  итог в 40 словах; может совпадать с first либо second
				 * @param first   первый сомножитель в избыточном представлении
				 * @param second  второй сомножитель в избыточном представлении
				 * @param modulus нечётный модуль в 40 словах, нормализованный
				 * @param inverse множитель приведения по модулю 2^29
				 *
				 * @note Рабочий буфер не пересекается с входами и итогом. Числа меньше 2m,
				 *       коэффициенты ограничены договором файла; слова 36…39 входов нулевые.
				 *       Итог меньше 2m. Адреса и ветвления не зависят от чисел
				 *
				 */
				__attribute__((target("avx2"))) static void multiply29Avx2(uint64_t * __restrict__ buffer, uint64_t * result, const uint64_t * first, const uint64_t * second, const uint64_t * modulus, const uint64_t inverse) noexcept {
					// Маска коэффициента и нулевой вектор
					const __m256i mask = _mm256_set1_epi64x(0x1FFFFFFF), zero = _mm256_setzero_si256();
					// Младшие коэффициенты вынесены в рабочий кадр
					uint64_t * low = buffer;
					uint64_t carry = 0;
					low[0] = low[1] = low[2] = low[3] = 0;
					// Остальные коэффициенты накапливаются в девяти векторах
					__m256i c1 = zero;
					__m256i c2 = zero;
					__m256i c3 = zero;
					__m256i c4 = zero;
					__m256i c5 = zero;
					__m256i c6 = zero;
					__m256i c7 = zero;
					__m256i c8 = zero;
					__m256i c9 = zero;
					// Четыре ряда за проход сохраняют положение коэффициентов внутри векторов
					for(size_t i = 0; i < 36; i += 4){
						// Частичный перенос не даёт средним коэффициентам переполнить 64 разряда
						const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c3, 29), 0x93);
						c3 = _mm256_add_epi64(_mm256_and_si256(c3, mask), _mm256_blend_epi32(high, zero, 3));
						c4 = _mm256_add_epi64(c4, _mm256_blend_epi32(zero, high, 3));
						// Ряд 1: младший коэффициент становится кратным 2^29
						{
							const uint64_t word = second[i + 0];
							const __m256i wordVector = _mm256_set1_epi64x(word);
							low[0] += (word * first[0]);
							low[1] += (word * first[1]);
							low[2] += (word * first[2]);
							low[3] += (word * first[3]);
							const uint64_t reducer = ((low[0] * inverse) & 0x1FFFFFFF);
							const __m256i reducerVector = _mm256_set1_epi64x(reducer);
							low[0] += (reducer * modulus[0]);
							low[1] += (reducer * modulus[1]);
							low[2] += (reducer * modulus[2]);
							low[3] += (reducer * modulus[3]);
							carry = (low[0] >> 29);
							low[1] += carry;
							c1 = _mm256_add_epi64(c1, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 4))));
							c1 = _mm256_add_epi64(c1, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 4))));
							c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 8))));
							c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 8))));
							c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 12))));
							c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 12))));
							c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 16))));
							c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 16))));
							c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 20))));
							c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 20))));
							c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 24))));
							c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 24))));
							c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 28))));
							c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 28))));
							c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 32))));
							c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 32))));
						}
						// Ряд 2: младший коэффициент становится кратным 2^29
						{
							const uint64_t word = second[i + 1];
							const __m256i wordVector = _mm256_set1_epi64x(word);
							low[1] += (word * first[0]);
							low[2] += (word * first[1]);
							low[3] += (word * first[2]);
							const uint64_t reducer = ((low[1] * inverse) & 0x1FFFFFFF);
							const __m256i reducerVector = _mm256_set1_epi64x(reducer);
							low[1] += (reducer * modulus[0]);
							low[2] += (reducer * modulus[1]);
							low[3] += (reducer * modulus[2]);
							carry = (low[1] >> 29);
							low[2] += carry;
							c1 = _mm256_add_epi64(c1, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 3))));
							c1 = _mm256_add_epi64(c1, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 3))));
							c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 7))));
							c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 7))));
							c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 11))));
							c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 11))));
							c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 15))));
							c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 15))));
							c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 19))));
							c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 19))));
							c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 23))));
							c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 23))));
							c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 27))));
							c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 27))));
							c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 31))));
							c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 31))));
							c9 = _mm256_add_epi64(c9, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 35))));
							c9 = _mm256_add_epi64(c9, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 35))));
						}
						// Ряд 3: младший коэффициент становится кратным 2^29
						{
							const uint64_t word = second[i + 2];
							const __m256i wordVector = _mm256_set1_epi64x(word);
							low[2] += (word * first[0]);
							low[3] += (word * first[1]);
							const uint64_t reducer = ((low[2] * inverse) & 0x1FFFFFFF);
							const __m256i reducerVector = _mm256_set1_epi64x(reducer);
							low[2] += (reducer * modulus[0]);
							low[3] += (reducer * modulus[1]);
							carry = (low[2] >> 29);
							low[3] += carry;
							c1 = _mm256_add_epi64(c1, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 2))));
							c1 = _mm256_add_epi64(c1, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 2))));
							c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 6))));
							c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 6))));
							c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 10))));
							c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 10))));
							c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 14))));
							c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 14))));
							c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 18))));
							c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 18))));
							c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 22))));
							c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 22))));
							c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 26))));
							c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 26))));
							c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 30))));
							c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 30))));
							c9 = _mm256_add_epi64(c9, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 34))));
							c9 = _mm256_add_epi64(c9, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 34))));
						}
						// Ряд 4: младший коэффициент становится кратным 2^29
						{
							const uint64_t word = second[i + 3];
							const __m256i wordVector = _mm256_set1_epi64x(word);
							low[3] += (word * first[0]);
							const uint64_t reducer = ((low[3] * inverse) & 0x1FFFFFFF);
							const __m256i reducerVector = _mm256_set1_epi64x(reducer);
							low[3] += (reducer * modulus[0]);
							carry = (low[3] >> 29);
							c1 = _mm256_add_epi64(c1, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 1))));
							c1 = _mm256_add_epi64(c1, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 1))));
							c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 5))));
							c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 5))));
							c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 9))));
							c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 9))));
							c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 13))));
							c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 13))));
							c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 17))));
							c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 17))));
							c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 21))));
							c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 21))));
							c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 25))));
							c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 25))));
							c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 29))));
							c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 29))));
							c9 = _mm256_add_epi64(c9, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 33))));
							c9 = _mm256_add_epi64(c9, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 33))));
						}
						// Отбрасываем четыре нулевых младших коэффициента
						_mm256_storeu_si256(reinterpret_cast <__m256i *> (low), c1);
						low[0] += carry;
						c1 = c2;
						c2 = c3;
						c3 = c4;
						c4 = c5;
						c5 = c6;
						c6 = c7;
						c7 = c8;
						c8 = c9;
						c9 = zero;
					}
					// Собираем четыре младших коэффициента перед переносами
					__m256i c0 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (low));
					// Проводим переносы на один коэффициент: снимаем накопленные старшие части
					{
						__m256i previous = zero;
						{
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c0, 29), 0x93);
							c0 = _mm256_add_epi64(_mm256_and_si256(c0, mask), _mm256_blend_epi32(high, previous, 3));
							previous = high;
						}
						{
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c1, 29), 0x93);
							c1 = _mm256_add_epi64(_mm256_and_si256(c1, mask), _mm256_blend_epi32(high, previous, 3));
							previous = high;
						}
						{
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c2, 29), 0x93);
							c2 = _mm256_add_epi64(_mm256_and_si256(c2, mask), _mm256_blend_epi32(high, previous, 3));
							previous = high;
						}
						{
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c3, 29), 0x93);
							c3 = _mm256_add_epi64(_mm256_and_si256(c3, mask), _mm256_blend_epi32(high, previous, 3));
							previous = high;
						}
						{
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c4, 29), 0x93);
							c4 = _mm256_add_epi64(_mm256_and_si256(c4, mask), _mm256_blend_epi32(high, previous, 3));
							previous = high;
						}
						{
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c5, 29), 0x93);
							c5 = _mm256_add_epi64(_mm256_and_si256(c5, mask), _mm256_blend_epi32(high, previous, 3));
							previous = high;
						}
						{
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c6, 29), 0x93);
							c6 = _mm256_add_epi64(_mm256_and_si256(c6, mask), _mm256_blend_epi32(high, previous, 3));
							previous = high;
						}
						{
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c7, 29), 0x93);
							c7 = _mm256_add_epi64(_mm256_and_si256(c7, mask), _mm256_blend_epi32(high, previous, 3));
							previous = high;
						}
						{
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c8, 29), 0x93);
							c8 = _mm256_add_epi64(_mm256_and_si256(c8, mask), _mm256_blend_epi32(high, previous, 3));
						}
					}
					// Проводим переносы на один коэффициент: оставляем ограниченную избыточность
					{
						__m256i previous = zero;
						{
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c0, 29), 0x93);
							c0 = _mm256_add_epi64(_mm256_and_si256(c0, mask), _mm256_blend_epi32(high, previous, 3));
							previous = high;
						}
						{
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c1, 29), 0x93);
							c1 = _mm256_add_epi64(_mm256_and_si256(c1, mask), _mm256_blend_epi32(high, previous, 3));
							previous = high;
						}
						{
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c2, 29), 0x93);
							c2 = _mm256_add_epi64(_mm256_and_si256(c2, mask), _mm256_blend_epi32(high, previous, 3));
							previous = high;
						}
						{
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c3, 29), 0x93);
							c3 = _mm256_add_epi64(_mm256_and_si256(c3, mask), _mm256_blend_epi32(high, previous, 3));
							previous = high;
						}
						{
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c4, 29), 0x93);
							c4 = _mm256_add_epi64(_mm256_and_si256(c4, mask), _mm256_blend_epi32(high, previous, 3));
							previous = high;
						}
						{
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c5, 29), 0x93);
							c5 = _mm256_add_epi64(_mm256_and_si256(c5, mask), _mm256_blend_epi32(high, previous, 3));
							previous = high;
						}
						{
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c6, 29), 0x93);
							c6 = _mm256_add_epi64(_mm256_and_si256(c6, mask), _mm256_blend_epi32(high, previous, 3));
							previous = high;
						}
						{
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c7, 29), 0x93);
							c7 = _mm256_add_epi64(_mm256_and_si256(c7, mask), _mm256_blend_epi32(high, previous, 3));
							previous = high;
						}
						{
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c8, 29), 0x93);
							c8 = _mm256_add_epi64(_mm256_and_si256(c8, mask), _mm256_blend_epi32(high, previous, 3));
						}
					}
					// Записываем итог после чтения входов: совпадение указателей допустимо
					_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 0), c0);
					_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 4), c1);
					_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 8), c2);
					_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 12), c3);
					_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 16), c4);
					_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 20), c5);
					_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 24), c6);
					_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 28), c7);
					_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 32), c8);
					// Последние четыре коэффициента служат нулевым дополнением для векторных загрузок
					for(size_t i = 36; i < 40; i++)
						result[i] = 0;
					// Завершаем работу с верхними половинами векторных регистров
					_mm256_zeroupper();
				}

				/**
				 * @brief Метод квадрата Монтгомери на коэффициентах по 29 разрядов
				 *
				 * @param buffer  отдельный рабочий буфер из 84 слов; затирает вызывающий
				 * @param result  итог в 40 словах; может совпадать с value
				 * @param value   число в избыточном представлении
				 * @param modulus нечётный модуль в 40 словах, нормализованный
				 * @param inverse множитель приведения по модулю 2^29
				 * @param repeat  число последовательных квадратов, больше нуля
				 *
				 * @note Рабочий буфер не пересекается с входами и итогом. Числа меньше 2m,
				 *       коэффициенты ограничены договором файла; слова 36…39 входов нулевые.
				 *       Итог меньше 2m. Адреса и ветвления не зависят от чисел
				 *
				 */
				__attribute__((target("avx2"))) static void square29Avx2(uint64_t * __restrict__ buffer, uint64_t * result, const uint64_t * value, const uint64_t * modulus, const uint64_t inverse, const size_t repeat) noexcept {
					// Маска коэффициента и нулевой вектор
					const __m256i mask = _mm256_set1_epi64x(0x1FFFFFFF), zero = _mm256_setzero_si256();
					// Произведение и младшие коэффициенты находятся в затираемом кадре вызывающего
					uint64_t * product = buffer;
					uint64_t * low = (buffer + 80);
					// Дополнение произведения за старшим значимым коэффициентом
					for(size_t i = 72; i < 80; i++)
						product[i] = 0;
					// Последовательные квадраты окна сохраняют тот же модуль и рабочее место
					for(size_t round = 0; round < repeat; round++){
						// Четыре коэффициента произведения, начиная с номера 0
						{
							__m256i sum = zero;
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[0], 2 * value[0], 2 * value[0], value[0]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 0))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[1], value[1], 0, 0), _mm256_set_epi64x(value[2], value[1], 0, 0)));
							_mm256_storeu_si256(reinterpret_cast <__m256i *> (product + 0), sum);
						}
						// Четыре коэффициента произведения, начиная с номера 4
						{
							__m256i sum = zero;
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[0]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 4))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[1]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 3))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[2], 2 * value[2], 2 * value[2], value[2]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 2))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[3], value[3], 0, 0), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 1))));
							_mm256_storeu_si256(reinterpret_cast <__m256i *> (product + 4), sum);
						}
						// Четыре коэффициента произведения, начиная с номера 8
						{
							__m256i sum = zero;
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[0]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 8))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[1]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 7))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[2]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 6))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[3]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 5))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[4], 2 * value[4], 2 * value[4], value[4]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 4))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[5], value[5], 0, 0), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 3))));
							_mm256_storeu_si256(reinterpret_cast <__m256i *> (product + 8), sum);
						}
						// Четыре коэффициента произведения, начиная с номера 12
						{
							__m256i sum = zero;
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[0]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 12))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[1]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 11))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[2]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 10))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[3]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 9))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[4]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 8))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[5]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 7))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[6], 2 * value[6], 2 * value[6], value[6]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 6))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[7], value[7], 0, 0), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 5))));
							_mm256_storeu_si256(reinterpret_cast <__m256i *> (product + 12), sum);
						}
						// Четыре коэффициента произведения, начиная с номера 16
						{
							__m256i sum = zero;
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[0]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 16))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[1]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 15))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[2]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 14))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[3]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 13))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[4]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 12))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[5]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 11))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[6]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 10))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[7]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 9))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[8], 2 * value[8], 2 * value[8], value[8]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 8))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[9], value[9], 0, 0), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 7))));
							_mm256_storeu_si256(reinterpret_cast <__m256i *> (product + 16), sum);
						}
						// Четыре коэффициента произведения, начиная с номера 20
						{
							__m256i sum = zero;
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[0]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 20))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[1]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 19))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[2]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 18))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[3]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 17))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[4]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 16))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[5]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 15))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[6]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 14))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[7]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 13))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[8]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 12))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[9]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 11))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[10], 2 * value[10], 2 * value[10], value[10]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 10))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[11], value[11], 0, 0), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 9))));
							_mm256_storeu_si256(reinterpret_cast <__m256i *> (product + 20), sum);
						}
						// Четыре коэффициента произведения, начиная с номера 24
						{
							__m256i sum = zero;
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[0]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 24))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[1]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 23))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[2]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 22))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[3]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 21))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[4]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 20))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[5]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 19))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[6]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 18))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[7]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 17))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[8]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 16))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[9]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 15))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[10]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 14))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[11]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 13))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[12], 2 * value[12], 2 * value[12], value[12]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 12))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[13], value[13], 0, 0), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 11))));
							_mm256_storeu_si256(reinterpret_cast <__m256i *> (product + 24), sum);
						}
						// Четыре коэффициента произведения, начиная с номера 28
						{
							__m256i sum = zero;
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[0]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 28))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[1]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 27))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[2]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 26))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[3]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 25))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[4]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 24))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[5]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 23))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[6]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 22))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[7]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 21))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[8]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 20))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[9]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 19))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[10]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 18))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[11]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 17))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[12]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 16))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[13]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 15))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[14], 2 * value[14], 2 * value[14], value[14]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 14))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[15], value[15], 0, 0), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 13))));
							_mm256_storeu_si256(reinterpret_cast <__m256i *> (product + 28), sum);
						}
						// Четыре коэффициента произведения, начиная с номера 32
						{
							__m256i sum = zero;
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[0]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 32))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[1]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 31))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[2]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 30))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[3]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 29))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[4]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 28))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[5]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 27))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[6]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 26))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[7]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 25))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[8]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 24))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[9]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 23))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[10]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 22))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[11]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 21))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[12]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 20))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[13]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 19))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[14]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 18))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[15]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 17))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[16], 2 * value[16], 2 * value[16], value[16]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 16))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[17], value[17], 0, 0), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 15))));
							_mm256_storeu_si256(reinterpret_cast <__m256i *> (product + 32), sum);
						}
						// Четыре коэффициента произведения, начиная с номера 36
						{
							__m256i sum = zero;
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[1]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 35))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[2]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 34))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[3]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 33))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[4]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 32))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[5]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 31))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[6]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 30))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[7]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 29))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[8]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 28))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[9]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 27))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[10]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 26))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[11]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 25))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[12]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 24))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[13]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 23))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[14]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 22))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[15]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 21))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[16]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 20))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[17]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 19))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[18], 2 * value[18], 2 * value[18], value[18]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 18))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[19], value[19], 0, 0), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 17))));
							_mm256_storeu_si256(reinterpret_cast <__m256i *> (product + 36), sum);
						}
						// Четыре коэффициента произведения, начиная с номера 40
						{
							__m256i sum = zero;
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[5]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 35))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[6]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 34))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[7]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 33))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[8]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 32))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[9]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 31))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[10]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 30))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[11]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 29))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[12]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 28))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[13]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 27))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[14]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 26))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[15]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 25))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[16]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 24))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[17]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 23))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[18]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 22))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[19]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 21))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[20], 2 * value[20], 2 * value[20], value[20]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 20))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[21], value[21], 0, 0), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 19))));
							_mm256_storeu_si256(reinterpret_cast <__m256i *> (product + 40), sum);
						}
						// Четыре коэффициента произведения, начиная с номера 44
						{
							__m256i sum = zero;
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[9]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 35))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[10]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 34))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[11]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 33))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[12]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 32))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[13]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 31))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[14]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 30))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[15]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 29))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[16]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 28))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[17]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 27))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[18]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 26))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[19]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 25))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[20]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 24))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[21]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 23))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[22], 2 * value[22], 2 * value[22], value[22]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 22))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[23], value[23], 0, 0), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 21))));
							_mm256_storeu_si256(reinterpret_cast <__m256i *> (product + 44), sum);
						}
						// Четыре коэффициента произведения, начиная с номера 48
						{
							__m256i sum = zero;
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[13]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 35))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[14]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 34))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[15]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 33))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[16]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 32))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[17]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 31))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[18]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 30))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[19]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 29))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[20]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 28))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[21]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 27))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[22]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 26))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[23]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 25))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[24], 2 * value[24], 2 * value[24], value[24]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 24))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[25], value[25], 0, 0), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 23))));
							_mm256_storeu_si256(reinterpret_cast <__m256i *> (product + 48), sum);
						}
						// Четыре коэффициента произведения, начиная с номера 52
						{
							__m256i sum = zero;
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[17]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 35))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[18]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 34))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[19]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 33))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[20]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 32))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[21]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 31))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[22]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 30))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[23]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 29))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[24]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 28))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[25]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 27))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[26], 2 * value[26], 2 * value[26], value[26]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 26))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[27], value[27], 0, 0), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 25))));
							_mm256_storeu_si256(reinterpret_cast <__m256i *> (product + 52), sum);
						}
						// Четыре коэффициента произведения, начиная с номера 56
						{
							__m256i sum = zero;
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[21]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 35))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[22]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 34))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[23]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 33))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[24]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 32))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[25]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 31))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[26]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 30))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[27]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 29))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[28], 2 * value[28], 2 * value[28], value[28]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 28))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[29], value[29], 0, 0), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 27))));
							_mm256_storeu_si256(reinterpret_cast <__m256i *> (product + 56), sum);
						}
						// Четыре коэффициента произведения, начиная с номера 60
						{
							__m256i sum = zero;
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[25]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 35))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[26]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 34))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[27]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 33))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[28]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 32))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[29]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 31))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[30], 2 * value[30], 2 * value[30], value[30]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 30))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[31], value[31], 0, 0), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 29))));
							_mm256_storeu_si256(reinterpret_cast <__m256i *> (product + 60), sum);
						}
						// Четыре коэффициента произведения, начиная с номера 64
						{
							__m256i sum = zero;
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[29]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 35))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[30]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 34))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[31]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 33))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[32], 2 * value[32], 2 * value[32], value[32]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 32))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[33], value[33], 0, 0), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 31))));
							_mm256_storeu_si256(reinterpret_cast <__m256i *> (product + 64), sum);
						}
						// Четыре коэффициента произведения, начиная с номера 68
						{
							__m256i sum = zero;
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set1_epi64x(2 * value[33]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 35))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[34], 2 * value[34], 2 * value[34], value[34]), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 34))));
							sum = _mm256_add_epi64(sum, _mm256_mul_epu32(_mm256_set_epi64x(2 * value[35], value[35], 0, 0), _mm256_loadu_si256(reinterpret_cast <const __m256i *> (value + 33))));
							_mm256_storeu_si256(reinterpret_cast <__m256i *> (product + 68), sum);
						}
						// Младшие четыре коэффициента приводятся цепочкой скалярных переносов
						uint64_t carry = 0;
						for(size_t i = 0; i < 4; i++)
							low[i] = product[i];
						__m256i c1 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (product + 4));
						__m256i c2 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (product + 8));
						__m256i c3 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (product + 12));
						__m256i c4 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (product + 16));
						__m256i c5 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (product + 20));
						__m256i c6 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (product + 24));
						__m256i c7 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (product + 28));
						__m256i c8 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (product + 32));
						__m256i c9 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (product + 36));
						// Четыре ряда за проход сохраняют положение коэффициентов внутри векторов
						for(size_t i = 0; i < 36; i += 4){
							// Частичный перенос не даёт средним коэффициентам переполнить 64 разряда
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c3, 29), 0x93);
							c3 = _mm256_add_epi64(_mm256_and_si256(c3, mask), _mm256_blend_epi32(high, zero, 3));
							c4 = _mm256_add_epi64(c4, _mm256_blend_epi32(zero, high, 3));
							// Ряд 1: младший коэффициент становится кратным 2^29
							{
								const uint64_t reducer = ((low[0] * inverse) & 0x1FFFFFFF);
								const __m256i reducerVector = _mm256_set1_epi64x(reducer);
								low[0] += (reducer * modulus[0]);
								low[1] += (reducer * modulus[1]);
								low[2] += (reducer * modulus[2]);
								low[3] += (reducer * modulus[3]);
								carry = (low[0] >> 29);
								low[1] += carry;
								c1 = _mm256_add_epi64(c1, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 4))));
								c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 8))));
								c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 12))));
								c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 16))));
								c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 20))));
								c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 24))));
								c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 28))));
								c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 32))));
							}
							// Ряд 2: младший коэффициент становится кратным 2^29
							{
								const uint64_t reducer = ((low[1] * inverse) & 0x1FFFFFFF);
								const __m256i reducerVector = _mm256_set1_epi64x(reducer);
								low[1] += (reducer * modulus[0]);
								low[2] += (reducer * modulus[1]);
								low[3] += (reducer * modulus[2]);
								carry = (low[1] >> 29);
								low[2] += carry;
								c1 = _mm256_add_epi64(c1, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 3))));
								c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 7))));
								c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 11))));
								c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 15))));
								c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 19))));
								c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 23))));
								c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 27))));
								c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 31))));
								c9 = _mm256_add_epi64(c9, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 35))));
							}
							// Ряд 3: младший коэффициент становится кратным 2^29
							{
								const uint64_t reducer = ((low[2] * inverse) & 0x1FFFFFFF);
								const __m256i reducerVector = _mm256_set1_epi64x(reducer);
								low[2] += (reducer * modulus[0]);
								low[3] += (reducer * modulus[1]);
								carry = (low[2] >> 29);
								low[3] += carry;
								c1 = _mm256_add_epi64(c1, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 2))));
								c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 6))));
								c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 10))));
								c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 14))));
								c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 18))));
								c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 22))));
								c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 26))));
								c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 30))));
								c9 = _mm256_add_epi64(c9, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 34))));
							}
							// Ряд 4: младший коэффициент становится кратным 2^29
							{
								const uint64_t reducer = ((low[3] * inverse) & 0x1FFFFFFF);
								const __m256i reducerVector = _mm256_set1_epi64x(reducer);
								low[3] += (reducer * modulus[0]);
								carry = (low[3] >> 29);
								c1 = _mm256_add_epi64(c1, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 1))));
								c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 5))));
								c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 9))));
								c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 13))));
								c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 17))));
								c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 21))));
								c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 25))));
								c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 29))));
								c9 = _mm256_add_epi64(c9, _mm256_mul_epu32(reducerVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 33))));
							}
							// Отбрасываем четыре нулевых младших коэффициента
							_mm256_storeu_si256(reinterpret_cast <__m256i *> (low), c1);
							low[0] += carry;
							c1 = c2;
							c2 = c3;
							c3 = c4;
							c4 = c5;
							c5 = c6;
							c6 = c7;
							c7 = c8;
							c8 = c9;
							c9 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (product + i + 40));
						}
						// Собираем четыре младших коэффициента перед переносами
						__m256i c0 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (low));
						// Проводим переносы на один коэффициент: снимаем накопленные старшие части
						{
							__m256i previous = zero;
							{
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c0, 29), 0x93);
								c0 = _mm256_add_epi64(_mm256_and_si256(c0, mask), _mm256_blend_epi32(high, previous, 3));
								previous = high;
							}
							{
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c1, 29), 0x93);
								c1 = _mm256_add_epi64(_mm256_and_si256(c1, mask), _mm256_blend_epi32(high, previous, 3));
								previous = high;
							}
							{
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c2, 29), 0x93);
								c2 = _mm256_add_epi64(_mm256_and_si256(c2, mask), _mm256_blend_epi32(high, previous, 3));
								previous = high;
							}
							{
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c3, 29), 0x93);
								c3 = _mm256_add_epi64(_mm256_and_si256(c3, mask), _mm256_blend_epi32(high, previous, 3));
								previous = high;
							}
							{
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c4, 29), 0x93);
								c4 = _mm256_add_epi64(_mm256_and_si256(c4, mask), _mm256_blend_epi32(high, previous, 3));
								previous = high;
							}
							{
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c5, 29), 0x93);
								c5 = _mm256_add_epi64(_mm256_and_si256(c5, mask), _mm256_blend_epi32(high, previous, 3));
								previous = high;
							}
							{
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c6, 29), 0x93);
								c6 = _mm256_add_epi64(_mm256_and_si256(c6, mask), _mm256_blend_epi32(high, previous, 3));
								previous = high;
							}
							{
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c7, 29), 0x93);
								c7 = _mm256_add_epi64(_mm256_and_si256(c7, mask), _mm256_blend_epi32(high, previous, 3));
								previous = high;
							}
							{
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c8, 29), 0x93);
								c8 = _mm256_add_epi64(_mm256_and_si256(c8, mask), _mm256_blend_epi32(high, previous, 3));
							}
						}
						// Проводим переносы на один коэффициент: оставляем ограниченную избыточность
						{
							__m256i previous = zero;
							{
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c0, 29), 0x93);
								c0 = _mm256_add_epi64(_mm256_and_si256(c0, mask), _mm256_blend_epi32(high, previous, 3));
								previous = high;
							}
							{
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c1, 29), 0x93);
								c1 = _mm256_add_epi64(_mm256_and_si256(c1, mask), _mm256_blend_epi32(high, previous, 3));
								previous = high;
							}
							{
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c2, 29), 0x93);
								c2 = _mm256_add_epi64(_mm256_and_si256(c2, mask), _mm256_blend_epi32(high, previous, 3));
								previous = high;
							}
							{
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c3, 29), 0x93);
								c3 = _mm256_add_epi64(_mm256_and_si256(c3, mask), _mm256_blend_epi32(high, previous, 3));
								previous = high;
							}
							{
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c4, 29), 0x93);
								c4 = _mm256_add_epi64(_mm256_and_si256(c4, mask), _mm256_blend_epi32(high, previous, 3));
								previous = high;
							}
							{
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c5, 29), 0x93);
								c5 = _mm256_add_epi64(_mm256_and_si256(c5, mask), _mm256_blend_epi32(high, previous, 3));
								previous = high;
							}
							{
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c6, 29), 0x93);
								c6 = _mm256_add_epi64(_mm256_and_si256(c6, mask), _mm256_blend_epi32(high, previous, 3));
								previous = high;
							}
							{
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c7, 29), 0x93);
								c7 = _mm256_add_epi64(_mm256_and_si256(c7, mask), _mm256_blend_epi32(high, previous, 3));
								previous = high;
							}
							{
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c8, 29), 0x93);
								c8 = _mm256_add_epi64(_mm256_and_si256(c8, mask), _mm256_blend_epi32(high, previous, 3));
							}
						}
						// Записываем итог после чтения входов: совпадение указателей допустимо
						_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 0), c0);
						_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 4), c1);
						_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 8), c2);
						_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 12), c3);
						_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 16), c4);
						_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 20), c5);
						_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 24), c6);
						_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 28), c7);
						_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 32), c8);
						// Последние четыре коэффициента служат нулевым дополнением для векторных загрузок
						for(size_t i = 36; i < 40; i++)
							result[i] = 0;
						// Следующий квадрат берёт только что записанный итог
						value = result;
					}
					// Завершаем работу с верхними половинами векторных регистров
					_mm256_zeroupper();
				}

				/**
				 * @brief Метод перевода шестнадцати слов в коэффициенты по 29 разрядов
				 *
				 * @param value  число в шестнадцати словах
				 * @param result место для 40 коэффициентов с нулевым дополнением
				 *
				 */
				static void encode29Avx2(const uint64_t * value, uint64_t * result) noexcept {
					// Разбиваем число по открытым положениям разрядов
					for(size_t i = 0; i < 36; i++){
						// Положение младшего разряда коэффициента в исходных словах
						const size_t bit = (i * 29), word = (bit / 64), shift = (bit % 64);
						// Часть коэффициента из первого слова
						uint64_t item = (value[word] >> shift);
						// Если коэффициент пересекает границу слова и следующее слово существует
						if((shift > 35) && (word < 15))
							// Дополняем коэффициент частью следующего слова
							item |= (value[word + 1] << (64 - shift));
						// Оставляем 29 разрядов коэффициента
						result[i] = (item & 0x1FFFFFFF);
					}
					// Нулевое дополнение для загрузок в конце числа
					for(size_t i = 36; i < 40; i++)
						result[i] = 0;
				}
				/**
				 * @brief Метод выбора степени полным перебором таблицы
				 *
				 * @param table  таблица из 32 степеней: по четыре коэффициента в каждом из девяти блоков
				 * @param index  номер степени от нуля до 31
				 * @param result выбранное число в 40 словах
				 * @param masks  шестнадцать векторных масок в затираемом кадре вызывающего
				 *
				 * @note Все записи читаются в одном порядке при любом индексе. Таблица,
				 *       результат и маски выровнены на 32 байта
				 *
				 */
				__attribute__((target("avx2"))) static void choose29Avx2(const uint32_t table[9][32][4], const uint64_t index, uint64_t * result, __m256i * masks) noexcept {
					// Искомый номер во всех дорожках
					const __m256i wanted = _mm256_set1_epi32(static_cast <int> (index));
					// Каждая маска охватывает две соседние записи
					for(size_t i = 0; i < 16; i++){
						// Номера записей открыты и помещаются в int
						const int first = static_cast <int> (2 * i), second = (first + 1);
						// Совпадение даёт все единицы в соответствующей половине вектора
						masks[i] = _mm256_cmpeq_epi32(wanted, _mm256_set_epi32(second, second, second, second, first, first, first, first));
					}
					// Читаем каждый блок целиком, адреса от индекса не зависят
					for(size_t k = 0; k < 9; k++){
						// Начало блока из 32 записей по четыре коэффициента
						const __m256i * data = reinterpret_cast <const __m256i *> (table[k]);
						// Первая пара записей
						__m256i sum = _mm256_and_si256(_mm256_load_si256(data), masks[0]);
						// Остальные пары записей
						for(size_t i = 1; i < 16; i++)
							// Накапливаем единственную выбранную запись
							sum = _mm256_or_si256(sum, _mm256_and_si256(_mm256_load_si256(data + i), masks[i]));
						// Объединяем половины: только одна может быть ненулевой
						const __m128i half = _mm_or_si128(_mm256_castsi256_si128(sum), _mm256_extracti128_si256(sum, 1));
						// Расширяем четыре коэффициента до 64 разрядов
						_mm256_store_si256(reinterpret_cast <__m256i *> (result + (4 * k)), _mm256_cvtepu32_epi64(half));
					}
					// Нулевое дополнение выбранного числа
					for(size_t i = 36; i < 40; i++)
						result[i] = 0;
					// Завершаем работу с верхними половинами векторных регистров
					_mm256_zeroupper();
				}
				/**
				 * @brief Метод чтения окна показателя по открытому положению
				 *
				 * @param exponent шестнадцать слов показателя
				 * @param position младший разряд окна
				 * @param count    ширина окна: четыре либо пять разрядов
				 * @return         значение окна
				 *
				 */
				static uint64_t window29Avx2(const uint64_t * exponent, const size_t position, const size_t count) noexcept {
					// Положение окна в словах показателя
					const size_t word = (position / 64), shift = (position % 64);
					// Часть окна из первого слова
					uint64_t result = (exponent[word] >> shift);
					// Если окно пересекает границу слова
					if((shift + count) > 64)
						// Дополняем окно частью следующего слова
						result |= (exponent[word + 1] << (64 - shift));
					// Оставляем разряды окна
					return (result & ((static_cast <uint64_t> (1) << count) - 1));
				}
				/**
				 * @brief Метод степени с фиксированным перебором 1024 разрядов на AVX2
				 *
				 * @param base     основание, меньшее модуля, в шестнадцати словах
				 * @param exponent показатель в шестнадцати словах
				 * @param modulus  нечётный модуль от 961 до 1024 разрядов
				 * @param rr       квадрат основания области 2^1024 по модулю
				 * @param inverse  множитель приведения по модулю 2^64
				 * @param result   итог в семнадцати словах, меньше 2m; доводит и затирает вызывающий
				 *
				 * @note Наличие AVX2, ширину чисел и допустимость основания проверяет вызывающий.
				 *       Первое окно имеет четыре разряда, следующие 204 окна - по пять.
				 *       Рабочие массивы и маски выбора затираются перед выходом
				 *
				 */
				__attribute__((target("avx2"))) static void power16Avx2(const uint64_t * base, const uint64_t * exponent, const uint64_t * modulus, const uint64_t * rr, const uint64_t inverse, uint64_t * result) noexcept {
					// Общий буфер произведения и младших коэффициентов
					alignas(1024) uint64_t scratch[128];
					// Маски индекса остаются в кадре до общего затирания
					alignas(32) __m256i masks[16];
					// Рабочие числа с отдельным выравниванием
					alignas(512) uint64_t field[64], entered[64], square[64], one[64] = {}, adjustment[64] = {}, accumulator[64], chosen[64];
					// Таблица степеней и её запись по блокам для полного перебора
					alignas(512) uint64_t table[32][64];
					alignas(32) uint32_t columns[9][32][4];
					// Единица и поправка 2^80 для перехода между основаниями областей
					one[0] = 1;
					adjustment[2] = (static_cast <uint64_t> (1) << 22);
					// Переводим входные числа в коэффициенты по 29 разрядов
					encode29Avx2(modulus, field);
					encode29Avx2(base, entered);
					encode29Avx2(rr, square);
					// Два произведения переводят 2^2048 в квадрат нового основания: 2^3052, затем 2^2088
					multiply29Avx2(scratch, square, square, square, field, inverse);
					multiply29Avx2(scratch, square, square, adjustment, field, inverse);
					// Нулевая и первая степени в новой области
					multiply29Avx2(scratch, table[0], square, one, field, inverse);
					multiply29Avx2(scratch, table[1], entered, square, field, inverse);
					// Чётные записи получаем квадратом, нечётные - умножением на основание
					for(size_t i = 2; i < 32; i++){
						// Если запись чётная
						if((i % 2) == 0)
							// Возводим половинную запись в квадрат
							square29Avx2(scratch, table[i], table[i / 2], field, inverse, 1);
						// Иначе умножаем предыдущую запись на основание
						else multiply29Avx2(scratch, table[i], table[i - 1], table[1], field, inverse);
					}
					// Укладываем коэффициенты по четыре в строку каждого блока
					for(size_t k = 0; k < 9; k++){
						// Перебираем степени окна
						for(size_t i = 0; i < 32; i++){
							// Коэффициенты после переноса помещаются в 32 разряда
							for(size_t j = 0; j < 4; j++)
								columns[k][i][j] = static_cast <uint32_t> (table[i][(k * 4) + j]);
						}
					}
					// Начинаем с записи первого окна, включая нулевую степень
					choose29Avx2(columns, window29Avx2(exponent, 1020, 4), accumulator, masks);
					// Перебираем оставшиеся окна по открытому счётчику
					for(size_t position = 1020; position > 0;){
						// Положение следующего окна
						position -= 5;
						// Пять квадратов окна одним вызовом
						square29Avx2(scratch, accumulator, accumulator, field, inverse, 5);
						// Выбираем запись полным перебором таблицы
						choose29Avx2(columns, window29Avx2(exponent, position, 5), chosen, masks);
						// Дополняем степень выбранным множителем
						multiply29Avx2(scratch, accumulator, accumulator, chosen, field, inverse);
					}
					// Выводим накопитель из области Монтгомери
					multiply29Avx2(scratch, accumulator, accumulator, one, field, inverse);
					// Обнуляем место для перевода в обычные слова
					for(size_t i = 0; i < 17; i++)
						result[i] = 0;
					// Перенос при окончательной нормализации коэффициентов
					uint64_t carry = 0;
					// Собираем число без избыточности в семнадцать слов
					for(size_t i = 0; i < 36; i++){
						// Нормализованный коэффициент и перенос к следующему
						const uint64_t item = (accumulator[i] + carry), word = (item & 0x1FFFFFFF);
						carry = (item >> 29);
						// Положение коэффициента в обычных словах
						const size_t bit = (i * 29), slot = (bit / 64), shift = (bit % 64);
						// Записываем младшую часть коэффициента
						result[slot] |= (word << shift);
						// Если коэффициент пересекает границу слова
						if((shift > 35) && (slot < 16))
							// Записываем оставшуюся часть в следующее слово
							result[slot + 1] |= (word >> (64 - shift));
					}
					// Затираем все явно выделенные рабочие массивы и маски индекса
					sys::wipe(scratch, sizeof(scratch));
					sys::wipe(masks, sizeof(masks));
					sys::wipe(field, sizeof(field));
					sys::wipe(entered, sizeof(entered));
					sys::wipe(square, sizeof(square));
					sys::wipe(one, sizeof(one));
					sys::wipe(adjustment, sizeof(adjustment));
					sys::wipe(accumulator, sizeof(accumulator));
					sys::wipe(chosen, sizeof(chosen));
					sys::wipe(table, sizeof(table));
					sys::wipe(columns, sizeof(columns));
				}
			};
		};
	};
#endif

#endif
