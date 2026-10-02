/**
 * @file power.hpp
 * @date 2026-10-02
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
 *          квадрат отдельно накапливает симметричную свёртку и приводит её парами коэффициентов.
 *          Недиагональная сумма удваивается целиком; диагональ не удваивается. Развёртка
 *          четырёх коэффициентов квадрата намеренная: шаблонная запись оказалась медленнее.
 *
 * @section Намеренные решения
 * 1. Входы меньше 2m, m < 2^1024; коэффициенты не больше 2^29 + 64, старший - не больше
 *    1024. Четыре слова дополнения нулевые. Произведение переносит старшие части после каждых
 *    четырёх рядов; квадрат - один раз в коэффициентах 28…39 готовой свёртки. Модель
 *    tools/math/power29.py даёт менее 0,688 от 2^64 у произведения и менее 0,922 у квадрата.
 *    Два заключительных прохода оставляют коэффициенты не больше 2^29 + 43 и 2^29 + 59
 *    соответственно. Итог меньше m + 4m^2/R < 2m; старший коэффициент вновь меньше 1024.
 *    Доводка до m выполняется один раз после выхода из области, в обычных словах.
 * 2. Секретный показатель всегда перебирается по 1024 разрядам. Выбор записи читает всю
 *    таблицу в одном порядке; даже смещение внутри строки кеша от показателя не зависит.
 *    Произведение и младшие коэффициенты живут в кадре степени и затираются перед выходом.
 *    Буфер ядра не пересекается с числами, итог может совпадать с входом.
 * 3. Путь выбирается лишь для шестнадцати слов на AVX2 без ADX: ширины, признак машины и
 *    допустимость основания проверяются до вызова. Чужой код в реализации не используется;
 *    сторонняя арифметика служит эталоном результата и скорости.
 * 4. Два множителя приведения получаем сразу: B = 2^29, T = low[0] + B * low[1],
 *    Q = -T / m по модулю B². Младшие и старшие 29 разрядов Q совпадают с двумя
 *    последовательными множителями. Шаг inverse * (2 + m * inverse) наращивает известные
 *    29 разрядов отрицательного обратного до 58. Беззнаковое переполнение при упаковке
 *    и умножении намеренное: остаются лишь младшие 58 разрядов. Скалярные переносы и
 *    договор коэффициентов сохранены; произведение остаётся на одиночном приведении по замеру.
 * 5. Свёртка квадрата вынесена в невстраиваемый метод: её временные векторы не живут
 *    одновременно с состоянием приведения. Диагональные коэффициенты выбираются масками
 *    после произведения; недиагональные суммы удваиваются один раз на четыре коэффициента.
 * 6. Выбор степени держит девять накопителей и одну текущую маску, читая все 32 записи.
 *    Отдельного массива масок нет. В строке подготовительной таблицы ровно 40 слов,
 *    включая нулевое дополнение; шаг строки 320 байтов сохраняет нужное выравнивание.
 * 7. Перенос середины квадрата выполняется после свёртки, перед приведением: снимаются
 *    старшие части коэффициентов 28…39, последняя прибавляется к коэффициенту 40. Это
 *    сохраняет число и заменяет девять переносов внутри цикла тремя векторными группами.
 *    Адреса фиксированы; отдельный проход быстрее переноса внутри свёртки по полной подписи.
 * 8. Модуль квадрата не пересекается с итогом: указатель отмечен __restrict__. Его векторы
 *    явно загружены до повторений, чтобы вставка свёртки не мешала их сохранению в кадре.
 *    В степени модуль лежит в отдельном field; совпадение итога с value допустимо. Читаемые
 *    value и modulus также могут совпадать при отдельном итоге. Девять проходов приведения
 *    разворачиваются по три: это быстрее полной развёртки по замеру.
 * 9. Свёртка выполняется одной вставкой без обращений к стеку. Двенадцать регистров
 *    сохраняют рассылки; при порождении вытесняется коэффициент с наиболее далёким
 *    следующим чтением. Обычные произведения читают второй сомножитель из памяти.
 *    Адреса фиксированы, объявлены чтение 40 слов и запись 72; вход и итог не пересекаются.
 * 10. В обычном произведении term29Avx2 читает модуль прямо из памяти. Векторы первого
 *     сомножителя остаются на интринсиках: их повторные загрузки замедляют полную подпись.
 * 11. Две соседние верхние диагонали свёртки объединены: [a², ab, c², cd] вычисляется
 *     одним vpmuludq, нечётные дорожки удваиваются, пары добавляются в соседние блоки.
 *     Это сокращает число векторных произведений со 189 до 180. Порождатель
 *     tools/math/product29.py проверяет полином каждой дорожки и границы всех команд;
 *     расписание и маски меняются через него. Приведение и договор коэффициентов прежние.
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
				 * @brief Метод четырёх произведений с чтением второго сомножителя из памяти
				 *
				 * @param first  вектор первых сомножителей, младшие 32 разряда каждой дорожки
				 * @param second четыре слова вторых сомножителей по произвольному выравниванию
				 * @return       четыре произведения беззнаковых чисел в 64-разрядных дорожках
				 *
				 * @note Операнд памяти описывает все читаемые байты. Рассылку первого сомножителя
				 *       собиратель вправе использовать повторно, второй читается самой командой
				 *
				 */
				__attribute__((target("avx2"), always_inline)) static inline __m256i term29Avx2(const __m256i first, const uint64_t * second) noexcept {
					// Место четырёх произведений
					__m256i result;
					// Читаем четыре слова без промежуточного вектора в кадре стека
					__asm__("vpmuludq %2, %1, %0" : "=x" (result) : "x" (first), "m" (* reinterpret_cast <const uint64_t (*)[4]> (second)));
					// Выводим произведения в том же порядке дорожек
					return result;
				}
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
							c1 = _mm256_add_epi64(c1, term29Avx2(reducerVector, modulus + 4));
							c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 8))));
							c2 = _mm256_add_epi64(c2, term29Avx2(reducerVector, modulus + 8));
							c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 12))));
							c3 = _mm256_add_epi64(c3, term29Avx2(reducerVector, modulus + 12));
							c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 16))));
							c4 = _mm256_add_epi64(c4, term29Avx2(reducerVector, modulus + 16));
							c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 20))));
							c5 = _mm256_add_epi64(c5, term29Avx2(reducerVector, modulus + 20));
							c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 24))));
							c6 = _mm256_add_epi64(c6, term29Avx2(reducerVector, modulus + 24));
							c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 28))));
							c7 = _mm256_add_epi64(c7, term29Avx2(reducerVector, modulus + 28));
							c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 32))));
							c8 = _mm256_add_epi64(c8, term29Avx2(reducerVector, modulus + 32));
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
							c1 = _mm256_add_epi64(c1, term29Avx2(reducerVector, modulus + 3));
							c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 7))));
							c2 = _mm256_add_epi64(c2, term29Avx2(reducerVector, modulus + 7));
							c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 11))));
							c3 = _mm256_add_epi64(c3, term29Avx2(reducerVector, modulus + 11));
							c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 15))));
							c4 = _mm256_add_epi64(c4, term29Avx2(reducerVector, modulus + 15));
							c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 19))));
							c5 = _mm256_add_epi64(c5, term29Avx2(reducerVector, modulus + 19));
							c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 23))));
							c6 = _mm256_add_epi64(c6, term29Avx2(reducerVector, modulus + 23));
							c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 27))));
							c7 = _mm256_add_epi64(c7, term29Avx2(reducerVector, modulus + 27));
							c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 31))));
							c8 = _mm256_add_epi64(c8, term29Avx2(reducerVector, modulus + 31));
							c9 = _mm256_add_epi64(c9, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 35))));
							c9 = _mm256_add_epi64(c9, term29Avx2(reducerVector, modulus + 35));
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
							c1 = _mm256_add_epi64(c1, term29Avx2(reducerVector, modulus + 2));
							c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 6))));
							c2 = _mm256_add_epi64(c2, term29Avx2(reducerVector, modulus + 6));
							c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 10))));
							c3 = _mm256_add_epi64(c3, term29Avx2(reducerVector, modulus + 10));
							c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 14))));
							c4 = _mm256_add_epi64(c4, term29Avx2(reducerVector, modulus + 14));
							c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 18))));
							c5 = _mm256_add_epi64(c5, term29Avx2(reducerVector, modulus + 18));
							c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 22))));
							c6 = _mm256_add_epi64(c6, term29Avx2(reducerVector, modulus + 22));
							c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 26))));
							c7 = _mm256_add_epi64(c7, term29Avx2(reducerVector, modulus + 26));
							c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 30))));
							c8 = _mm256_add_epi64(c8, term29Avx2(reducerVector, modulus + 30));
							c9 = _mm256_add_epi64(c9, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 34))));
							c9 = _mm256_add_epi64(c9, term29Avx2(reducerVector, modulus + 34));
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
							c1 = _mm256_add_epi64(c1, term29Avx2(reducerVector, modulus + 1));
							c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 5))));
							c2 = _mm256_add_epi64(c2, term29Avx2(reducerVector, modulus + 5));
							c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 9))));
							c3 = _mm256_add_epi64(c3, term29Avx2(reducerVector, modulus + 9));
							c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 13))));
							c4 = _mm256_add_epi64(c4, term29Avx2(reducerVector, modulus + 13));
							c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 17))));
							c5 = _mm256_add_epi64(c5, term29Avx2(reducerVector, modulus + 17));
							c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 21))));
							c6 = _mm256_add_epi64(c6, term29Avx2(reducerVector, modulus + 21));
							c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 25))));
							c7 = _mm256_add_epi64(c7, term29Avx2(reducerVector, modulus + 25));
							c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 29))));
							c8 = _mm256_add_epi64(c8, term29Avx2(reducerVector, modulus + 29));
							c9 = _mm256_add_epi64(c9, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 33))));
							c9 = _mm256_add_epi64(c9, term29Avx2(reducerVector, modulus + 33));
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
				 * @brief Метод симметричной свёртки квадрата на коэффициентах по 29 разрядов
				 *
				 * @param product итог из 72 коэффициентов; не пересекается с value
				 * @param value   исходное число в 40 словах с нулевым дополнением
				 *
				 * @note Коэффициенты ограничены договором файла. Недиагональные произведения
				 *       суммируются один раз и удваиваются перед добавлением диагонали.
				 *       Дополнение за 72 коэффициентами подготавливает вызывающий.
				 *       Расписание и полиномы проверяет tools/math/product29.py
				 *
				 */
				__attribute__((target("avx2"), noinline)) static void product29Avx2(uint64_t * __restrict__ product, const uint64_t * value) noexcept {
					// Порождатель и проверка полиномов: tools/math/product29.py
					// ymm0…11 сохраняют рассылки, ymm13 — диагонали двух соседних блоков
					__asm__(
						// Коэффициенты 0…3
						"vpbroadcastq 0(%[value]), %%ymm0\n\t"
						"vpmuludq 0(%[value]), %%ymm0, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm15, %%ymm12\n\t"
						"vpblendd $3, %%ymm15, %%ymm12, %%ymm14\n\t"
						"vmovdqu 8(%[value]), %%ymm15\n\t"
						"vpermq $160, %%ymm15, %%ymm12\n\t"
						"vpmuludq %%ymm15, %%ymm12, %%ymm13\n\t"
						"vpaddq %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpblendd $51, %%ymm13, %%ymm15, %%ymm13\n\t"
						"vperm2i128 $8, %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vmovdqu %%ymm14, 0(%[product])\n\t"
						// Коэффициенты 4…7
						"vpmuludq 32(%[value]), %%ymm0, %%ymm14\n\t"
						"vpbroadcastq 8(%[value]), %%ymm1\n\t"
						"vpmuludq 24(%[value]), %%ymm1, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpaddq %%ymm14, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 16(%[value]), %%ymm2\n\t"
						"vpmuludq 16(%[value]), %%ymm2, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm15, %%ymm12\n\t"
						"vpblendd $3, %%ymm15, %%ymm12, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vperm2i128 $24, %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vmovdqu %%ymm14, 32(%[product])\n\t"
						// Коэффициенты 8…11
						"vpmuludq 64(%[value]), %%ymm0, %%ymm14\n\t"
						"vpmuludq 56(%[value]), %%ymm1, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 48(%[value]), %%ymm2, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 24(%[value]), %%ymm3\n\t"
						"vpmuludq 40(%[value]), %%ymm3, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpaddq %%ymm14, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 32(%[value]), %%ymm4\n\t"
						"vpmuludq 32(%[value]), %%ymm4, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm15, %%ymm12\n\t"
						"vpblendd $3, %%ymm15, %%ymm12, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vmovdqu 40(%[value]), %%ymm15\n\t"
						"vpermq $160, %%ymm15, %%ymm12\n\t"
						"vpmuludq %%ymm15, %%ymm12, %%ymm13\n\t"
						"vpaddq %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpblendd $51, %%ymm13, %%ymm15, %%ymm13\n\t"
						"vperm2i128 $8, %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vmovdqu %%ymm14, 64(%[product])\n\t"
						// Коэффициенты 12…15
						"vpmuludq 96(%[value]), %%ymm0, %%ymm14\n\t"
						"vpmuludq 88(%[value]), %%ymm1, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 80(%[value]), %%ymm2, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 72(%[value]), %%ymm3, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 64(%[value]), %%ymm4, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 40(%[value]), %%ymm5\n\t"
						"vpmuludq 56(%[value]), %%ymm5, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpaddq %%ymm14, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 48(%[value]), %%ymm6\n\t"
						"vpmuludq 48(%[value]), %%ymm6, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm15, %%ymm12\n\t"
						"vpblendd $3, %%ymm15, %%ymm12, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vperm2i128 $24, %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vmovdqu %%ymm14, 96(%[product])\n\t"
						// Коэффициенты 16…19
						"vpmuludq 128(%[value]), %%ymm0, %%ymm14\n\t"
						"vpmuludq 120(%[value]), %%ymm1, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 112(%[value]), %%ymm2, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 104(%[value]), %%ymm3, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 96(%[value]), %%ymm4, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 88(%[value]), %%ymm5, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 80(%[value]), %%ymm6, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 56(%[value]), %%ymm7\n\t"
						"vpmuludq 72(%[value]), %%ymm7, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpaddq %%ymm14, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 64(%[value]), %%ymm8\n\t"
						"vpmuludq 64(%[value]), %%ymm8, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm15, %%ymm12\n\t"
						"vpblendd $3, %%ymm15, %%ymm12, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vmovdqu 72(%[value]), %%ymm15\n\t"
						"vpermq $160, %%ymm15, %%ymm12\n\t"
						"vpmuludq %%ymm15, %%ymm12, %%ymm13\n\t"
						"vpaddq %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpblendd $51, %%ymm13, %%ymm15, %%ymm13\n\t"
						"vperm2i128 $8, %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vmovdqu %%ymm14, 128(%[product])\n\t"
						// Коэффициенты 20…23
						"vpmuludq 160(%[value]), %%ymm0, %%ymm14\n\t"
						"vpmuludq 152(%[value]), %%ymm1, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 144(%[value]), %%ymm2, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 136(%[value]), %%ymm3, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 128(%[value]), %%ymm4, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 120(%[value]), %%ymm5, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 112(%[value]), %%ymm6, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 104(%[value]), %%ymm7, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 96(%[value]), %%ymm8, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 72(%[value]), %%ymm9\n\t"
						"vpmuludq 88(%[value]), %%ymm9, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpaddq %%ymm14, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 80(%[value]), %%ymm10\n\t"
						"vpmuludq 80(%[value]), %%ymm10, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm15, %%ymm12\n\t"
						"vpblendd $3, %%ymm15, %%ymm12, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vperm2i128 $24, %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vmovdqu %%ymm14, 160(%[product])\n\t"
						// Коэффициенты 24…27
						"vpmuludq 192(%[value]), %%ymm0, %%ymm14\n\t"
						"vpmuludq 184(%[value]), %%ymm1, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 176(%[value]), %%ymm2, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 168(%[value]), %%ymm3, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 160(%[value]), %%ymm4, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 152(%[value]), %%ymm5, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 144(%[value]), %%ymm6, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 136(%[value]), %%ymm7, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 128(%[value]), %%ymm8, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 120(%[value]), %%ymm9, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 112(%[value]), %%ymm10, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 88(%[value]), %%ymm11\n\t"
						"vpmuludq 104(%[value]), %%ymm11, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpaddq %%ymm14, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 96(%[value]), %%ymm11\n\t"
						"vpmuludq 96(%[value]), %%ymm11, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm15, %%ymm12\n\t"
						"vpblendd $3, %%ymm15, %%ymm12, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vmovdqu 104(%[value]), %%ymm15\n\t"
						"vpermq $160, %%ymm15, %%ymm12\n\t"
						"vpmuludq %%ymm15, %%ymm12, %%ymm13\n\t"
						"vpaddq %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpblendd $51, %%ymm13, %%ymm15, %%ymm13\n\t"
						"vperm2i128 $8, %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vmovdqu %%ymm14, 192(%[product])\n\t"
						// Коэффициенты 28…31
						"vpmuludq 224(%[value]), %%ymm0, %%ymm14\n\t"
						"vpmuludq 216(%[value]), %%ymm1, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 208(%[value]), %%ymm2, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 200(%[value]), %%ymm3, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 192(%[value]), %%ymm4, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 184(%[value]), %%ymm5, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 176(%[value]), %%ymm6, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 168(%[value]), %%ymm7, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 160(%[value]), %%ymm8, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 152(%[value]), %%ymm9, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 144(%[value]), %%ymm10, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 88(%[value]), %%ymm10\n\t"
						"vpmuludq 136(%[value]), %%ymm10, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 128(%[value]), %%ymm11, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 104(%[value]), %%ymm11\n\t"
						"vpmuludq 120(%[value]), %%ymm11, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpaddq %%ymm14, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 112(%[value]), %%ymm11\n\t"
						"vpmuludq 112(%[value]), %%ymm11, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm15, %%ymm12\n\t"
						"vpblendd $3, %%ymm15, %%ymm12, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vperm2i128 $24, %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vmovdqu %%ymm14, 224(%[product])\n\t"
						// Коэффициенты 32…35
						"vpmuludq 256(%[value]), %%ymm0, %%ymm14\n\t"
						"vpmuludq 248(%[value]), %%ymm1, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 240(%[value]), %%ymm2, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 232(%[value]), %%ymm3, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 224(%[value]), %%ymm4, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 216(%[value]), %%ymm5, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 208(%[value]), %%ymm6, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 200(%[value]), %%ymm7, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 192(%[value]), %%ymm8, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 184(%[value]), %%ymm9, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 80(%[value]), %%ymm0\n\t"
						"vpmuludq 176(%[value]), %%ymm0, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 168(%[value]), %%ymm10, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 96(%[value]), %%ymm10\n\t"
						"vpmuludq 160(%[value]), %%ymm10, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 104(%[value]), %%ymm10\n\t"
						"vpmuludq 152(%[value]), %%ymm10, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 144(%[value]), %%ymm11, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 120(%[value]), %%ymm11\n\t"
						"vpmuludq 136(%[value]), %%ymm11, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpaddq %%ymm14, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 128(%[value]), %%ymm11\n\t"
						"vpmuludq 128(%[value]), %%ymm11, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm15, %%ymm12\n\t"
						"vpblendd $3, %%ymm15, %%ymm12, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vmovdqu 136(%[value]), %%ymm15\n\t"
						"vpermq $160, %%ymm15, %%ymm12\n\t"
						"vpmuludq %%ymm15, %%ymm12, %%ymm13\n\t"
						"vpaddq %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpblendd $51, %%ymm13, %%ymm15, %%ymm13\n\t"
						"vperm2i128 $8, %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vmovdqu %%ymm14, 256(%[product])\n\t"
						// Коэффициенты 36…39
						"vpmuludq 280(%[value]), %%ymm1, %%ymm14\n\t"
						"vpmuludq 272(%[value]), %%ymm2, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 264(%[value]), %%ymm3, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 256(%[value]), %%ymm4, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 248(%[value]), %%ymm5, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 240(%[value]), %%ymm6, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 232(%[value]), %%ymm7, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 224(%[value]), %%ymm8, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 216(%[value]), %%ymm9, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 208(%[value]), %%ymm0, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 88(%[value]), %%ymm1\n\t"
						"vpmuludq 200(%[value]), %%ymm1, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 96(%[value]), %%ymm2\n\t"
						"vpmuludq 192(%[value]), %%ymm2, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 184(%[value]), %%ymm10, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 112(%[value]), %%ymm3\n\t"
						"vpmuludq 176(%[value]), %%ymm3, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 120(%[value]), %%ymm4\n\t"
						"vpmuludq 168(%[value]), %%ymm4, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 160(%[value]), %%ymm11, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 136(%[value]), %%ymm11\n\t"
						"vpmuludq 152(%[value]), %%ymm11, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpaddq %%ymm14, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 144(%[value]), %%ymm11\n\t"
						"vpmuludq 144(%[value]), %%ymm11, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm15, %%ymm12\n\t"
						"vpblendd $3, %%ymm15, %%ymm12, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vperm2i128 $24, %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vmovdqu %%ymm14, 288(%[product])\n\t"
						// Коэффициенты 40…43
						"vpmuludq 280(%[value]), %%ymm5, %%ymm14\n\t"
						"vpmuludq 272(%[value]), %%ymm6, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 264(%[value]), %%ymm7, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 256(%[value]), %%ymm8, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 248(%[value]), %%ymm9, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 240(%[value]), %%ymm0, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 232(%[value]), %%ymm1, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 224(%[value]), %%ymm2, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 216(%[value]), %%ymm10, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 208(%[value]), %%ymm3, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 200(%[value]), %%ymm4, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 128(%[value]), %%ymm5\n\t"
						"vpmuludq 192(%[value]), %%ymm5, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 136(%[value]), %%ymm6\n\t"
						"vpmuludq 184(%[value]), %%ymm6, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 176(%[value]), %%ymm11, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 152(%[value]), %%ymm7\n\t"
						"vpmuludq 168(%[value]), %%ymm7, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpaddq %%ymm14, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 160(%[value]), %%ymm8\n\t"
						"vpmuludq 160(%[value]), %%ymm8, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm15, %%ymm12\n\t"
						"vpblendd $3, %%ymm15, %%ymm12, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vmovdqu 168(%[value]), %%ymm15\n\t"
						"vpermq $160, %%ymm15, %%ymm12\n\t"
						"vpmuludq %%ymm15, %%ymm12, %%ymm13\n\t"
						"vpaddq %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpblendd $51, %%ymm13, %%ymm15, %%ymm13\n\t"
						"vperm2i128 $8, %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vmovdqu %%ymm14, 320(%[product])\n\t"
						// Коэффициенты 44…47
						"vpmuludq 280(%[value]), %%ymm9, %%ymm14\n\t"
						"vpmuludq 272(%[value]), %%ymm0, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 264(%[value]), %%ymm1, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 256(%[value]), %%ymm2, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 248(%[value]), %%ymm10, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 240(%[value]), %%ymm3, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 232(%[value]), %%ymm4, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 224(%[value]), %%ymm5, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 216(%[value]), %%ymm6, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 208(%[value]), %%ymm11, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 200(%[value]), %%ymm7, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 192(%[value]), %%ymm8, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 168(%[value]), %%ymm9\n\t"
						"vpmuludq 184(%[value]), %%ymm9, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpaddq %%ymm14, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 176(%[value]), %%ymm0\n\t"
						"vpmuludq 176(%[value]), %%ymm0, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm15, %%ymm12\n\t"
						"vpblendd $3, %%ymm15, %%ymm12, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vperm2i128 $24, %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vmovdqu %%ymm14, 352(%[product])\n\t"
						// Коэффициенты 48…51
						"vpmuludq 280(%[value]), %%ymm10, %%ymm14\n\t"
						"vpmuludq 272(%[value]), %%ymm3, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 264(%[value]), %%ymm4, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 256(%[value]), %%ymm5, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 248(%[value]), %%ymm6, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 240(%[value]), %%ymm11, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 232(%[value]), %%ymm7, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 224(%[value]), %%ymm8, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 216(%[value]), %%ymm9, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 208(%[value]), %%ymm0, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 184(%[value]), %%ymm10\n\t"
						"vpmuludq 200(%[value]), %%ymm10, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpaddq %%ymm14, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 192(%[value]), %%ymm1\n\t"
						"vpmuludq 192(%[value]), %%ymm1, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm15, %%ymm12\n\t"
						"vpblendd $3, %%ymm15, %%ymm12, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vmovdqu 200(%[value]), %%ymm15\n\t"
						"vpermq $160, %%ymm15, %%ymm12\n\t"
						"vpmuludq %%ymm15, %%ymm12, %%ymm13\n\t"
						"vpaddq %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpblendd $51, %%ymm13, %%ymm15, %%ymm13\n\t"
						"vperm2i128 $8, %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vmovdqu %%ymm14, 384(%[product])\n\t"
						// Коэффициенты 52…55
						"vpmuludq 280(%[value]), %%ymm6, %%ymm14\n\t"
						"vpmuludq 272(%[value]), %%ymm11, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 264(%[value]), %%ymm7, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 256(%[value]), %%ymm8, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 248(%[value]), %%ymm9, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 240(%[value]), %%ymm0, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 232(%[value]), %%ymm10, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 224(%[value]), %%ymm1, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 200(%[value]), %%ymm2\n\t"
						"vpmuludq 216(%[value]), %%ymm2, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpaddq %%ymm14, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 208(%[value]), %%ymm3\n\t"
						"vpmuludq 208(%[value]), %%ymm3, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm15, %%ymm12\n\t"
						"vpblendd $3, %%ymm15, %%ymm12, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vperm2i128 $24, %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vmovdqu %%ymm14, 416(%[product])\n\t"
						// Коэффициенты 56…59
						"vpmuludq 280(%[value]), %%ymm9, %%ymm14\n\t"
						"vpmuludq 272(%[value]), %%ymm0, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 264(%[value]), %%ymm10, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 256(%[value]), %%ymm1, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 248(%[value]), %%ymm2, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 240(%[value]), %%ymm3, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 216(%[value]), %%ymm4\n\t"
						"vpmuludq 232(%[value]), %%ymm4, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpaddq %%ymm14, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 224(%[value]), %%ymm11\n\t"
						"vpmuludq 224(%[value]), %%ymm11, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm15, %%ymm12\n\t"
						"vpblendd $3, %%ymm15, %%ymm12, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vmovdqu 232(%[value]), %%ymm15\n\t"
						"vpermq $160, %%ymm15, %%ymm12\n\t"
						"vpmuludq %%ymm15, %%ymm12, %%ymm13\n\t"
						"vpaddq %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpblendd $51, %%ymm13, %%ymm15, %%ymm13\n\t"
						"vperm2i128 $8, %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vmovdqu %%ymm14, 448(%[product])\n\t"
						// Коэффициенты 60…63
						"vpmuludq 280(%[value]), %%ymm2, %%ymm14\n\t"
						"vpmuludq 272(%[value]), %%ymm3, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 264(%[value]), %%ymm4, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpmuludq 256(%[value]), %%ymm11, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 232(%[value]), %%ymm5\n\t"
						"vpmuludq 248(%[value]), %%ymm5, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpaddq %%ymm14, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 240(%[value]), %%ymm6\n\t"
						"vpmuludq 240(%[value]), %%ymm6, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm15, %%ymm12\n\t"
						"vpblendd $3, %%ymm15, %%ymm12, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vperm2i128 $24, %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vmovdqu %%ymm14, 480(%[product])\n\t"
						// Коэффициенты 64…67
						"vpmuludq 280(%[value]), %%ymm5, %%ymm14\n\t"
						"vpmuludq 272(%[value]), %%ymm6, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 248(%[value]), %%ymm7\n\t"
						"vpmuludq 264(%[value]), %%ymm7, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vpaddq %%ymm14, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 256(%[value]), %%ymm8\n\t"
						"vpmuludq 256(%[value]), %%ymm8, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm15, %%ymm12\n\t"
						"vpblendd $3, %%ymm15, %%ymm12, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vmovdqu 264(%[value]), %%ymm15\n\t"
						"vpermq $160, %%ymm15, %%ymm12\n\t"
						"vpmuludq %%ymm15, %%ymm12, %%ymm13\n\t"
						"vpaddq %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpblendd $51, %%ymm13, %%ymm15, %%ymm13\n\t"
						"vperm2i128 $8, %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vmovdqu %%ymm14, 512(%[product])\n\t"
						// Коэффициенты 68…71
						"vpbroadcastq 264(%[value]), %%ymm9\n\t"
						"vpmuludq 280(%[value]), %%ymm9, %%ymm14\n\t"
						"vpaddq %%ymm14, %%ymm14, %%ymm14\n\t"
						"vpbroadcastq 272(%[value]), %%ymm0\n\t"
						"vpmuludq 272(%[value]), %%ymm0, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm15, %%ymm12\n\t"
						"vpblendd $3, %%ymm15, %%ymm12, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vperm2i128 $24, %%ymm13, %%ymm13, %%ymm15\n\t"
						"vpaddq %%ymm15, %%ymm14, %%ymm14\n\t"
						"vmovdqu %%ymm14, 544(%[product])\n\t"
						: [output] "=m" (* reinterpret_cast <uint64_t (*)[72]> (product))
						: [product] "r" (product), [value] "r" (value), [input] "m" (* reinterpret_cast <const uint64_t (*)[40]> (value))
						: "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7", "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15"
					);
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
				 *       Модуль не пересекается с итогом; value может совпадать с modulus.
				 *       Итог меньше 2m. Адреса и ветвления не зависят от чисел
				 *
				 */
				__attribute__((target("avx2"))) static void square29Avx2(uint64_t * __restrict__ buffer, uint64_t * result, const uint64_t * value, const uint64_t * __restrict__ modulus, const uint64_t inverse, const size_t repeat) noexcept {
					// Маска коэффициента и нулевой вектор
					const __m256i mask = _mm256_set1_epi64x(0x1FFFFFFF), zero = _mm256_setzero_si256();
					// Сохраняем векторы модуля до всех повторений квадрата
					const __m256i m1 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 1));
					const __m256i m2 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 2));
					const __m256i m3 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 3));
					const __m256i m4 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 4));
					const __m256i m5 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 5));
					const __m256i m6 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 6));
					const __m256i m7 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 7));
					const __m256i m8 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 8));
					const __m256i m9 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 9));
					const __m256i m10 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 10));
					const __m256i m11 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 11));
					const __m256i m12 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 12));
					const __m256i m13 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 13));
					const __m256i m14 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 14));
					const __m256i m15 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 15));
					const __m256i m16 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 16));
					const __m256i m17 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 17));
					const __m256i m18 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 18));
					const __m256i m19 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 19));
					const __m256i m20 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 20));
					const __m256i m21 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 21));
					const __m256i m22 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 22));
					const __m256i m23 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 23));
					const __m256i m24 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 24));
					const __m256i m25 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 25));
					const __m256i m26 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 26));
					const __m256i m27 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 27));
					const __m256i m28 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 28));
					const __m256i m29 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 29));
					const __m256i m30 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 30));
					const __m256i m31 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 31));
					const __m256i m32 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 32));
					const __m256i m33 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 33));
					const __m256i m34 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 34));
					const __m256i m35 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 35));
					// Наращиваем отрицательный обратный множитель до 58 разрядов
					const uint64_t paired = (inverse * (2 + ((modulus[0] + (modulus[1] << 29)) * inverse)));
					// Произведение и младшие коэффициенты находятся в затираемом кадре вызывающего
					uint64_t * product = buffer;
					uint64_t * low = (buffer + 80);
					// Дополнение произведения за старшим значимым коэффициентом
					for(size_t i = 72; i < 80; i++)
						product[i] = 0;
					// Последовательные квадраты окна сохраняют тот же модуль и рабочее место
					for(size_t round = 0; round < repeat; round++){
						// Свёртка отдельно от приведения освобождает регистры её временных значений
						product29Avx2(product, value);
						// Перенос коэффициентов 28…39 ограничивает все последующие суммы приведения
						{
							__m256i previous = zero;
							{
								const __m256i part = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (product + 28));
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(part, 29), 0x93);
								_mm256_storeu_si256(reinterpret_cast <__m256i *> (product + 28), _mm256_add_epi64(_mm256_and_si256(part, mask), _mm256_blend_epi32(high, previous, 3)));
								previous = high;
							}
							{
								const __m256i part = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (product + 32));
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(part, 29), 0x93);
								_mm256_storeu_si256(reinterpret_cast <__m256i *> (product + 32), _mm256_add_epi64(_mm256_and_si256(part, mask), _mm256_blend_epi32(high, previous, 3)));
								previous = high;
							}
							{
								const __m256i part = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (product + 36));
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(part, 29), 0x93);
								_mm256_storeu_si256(reinterpret_cast <__m256i *> (product + 36), _mm256_add_epi64(_mm256_and_si256(part, mask), _mm256_blend_epi32(high, previous, 3)));
								previous = high;
							}
							// Старшая часть коэффициента 39 переходит в коэффициент 40
							product[40] += static_cast <uint64_t> (_mm256_extract_epi64(previous, 0));
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
						#pragma GCC unroll 3
						for(size_t i = 0; i < 36; i += 4){
							// Первая пара множителей определяется младшими 58 разрядами
							{
								const uint64_t packed = ((low[0] + (low[1] << 29)) * paired) & 0x03FFFFFFFFFFFFFFULL;
								// Младший множитель и его обычный перенос
								{
									const uint64_t reducer = (packed & 0x1FFFFFFF);
									const __m256i reducerVector = _mm256_set1_epi64x(reducer);
									low[0] += (reducer * modulus[0]);
									low[1] += (reducer * modulus[1]);
									low[2] += (reducer * modulus[2]);
									low[3] += (reducer * modulus[3]);
									carry = (low[0] >> 29);
									low[1] += carry;
									c1 = _mm256_add_epi64(c1, _mm256_mul_epu32(reducerVector, m4));
									c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(reducerVector, m8));
									c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(reducerVector, m12));
									c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(reducerVector, m16));
									c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(reducerVector, m20));
									c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(reducerVector, m24));
									c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(reducerVector, m28));
									c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(reducerVector, m32));
								}
								// Старший множитель уже известен независимо от предыдущего переноса
								{
									const uint64_t reducer = (packed >> 29);
									const __m256i reducerVector = _mm256_set1_epi64x(reducer);
									low[1] += (reducer * modulus[0]);
									low[2] += (reducer * modulus[1]);
									low[3] += (reducer * modulus[2]);
									carry = (low[1] >> 29);
									low[2] += carry;
									c1 = _mm256_add_epi64(c1, _mm256_mul_epu32(reducerVector, m3));
									c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(reducerVector, m7));
									c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(reducerVector, m11));
									c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(reducerVector, m15));
									c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(reducerVector, m19));
									c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(reducerVector, m23));
									c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(reducerVector, m27));
									c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(reducerVector, m31));
									c9 = _mm256_add_epi64(c9, _mm256_mul_epu32(reducerVector, m35));
								}
							}
							// Вторая пара множителей определяется младшими 58 разрядами
							{
								const uint64_t packed = ((low[2] + (low[3] << 29)) * paired) & 0x03FFFFFFFFFFFFFFULL;
								// Младший множитель и его обычный перенос
								{
									const uint64_t reducer = (packed & 0x1FFFFFFF);
									const __m256i reducerVector = _mm256_set1_epi64x(reducer);
									low[2] += (reducer * modulus[0]);
									low[3] += (reducer * modulus[1]);
									carry = (low[2] >> 29);
									low[3] += carry;
									c1 = _mm256_add_epi64(c1, _mm256_mul_epu32(reducerVector, m2));
									c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(reducerVector, m6));
									c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(reducerVector, m10));
									c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(reducerVector, m14));
									c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(reducerVector, m18));
									c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(reducerVector, m22));
									c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(reducerVector, m26));
									c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(reducerVector, m30));
									c9 = _mm256_add_epi64(c9, _mm256_mul_epu32(reducerVector, m34));
								}
								// Старший множитель уже известен независимо от предыдущего переноса
								{
									const uint64_t reducer = (packed >> 29);
									const __m256i reducerVector = _mm256_set1_epi64x(reducer);
									low[3] += (reducer * modulus[0]);
									carry = (low[3] >> 29);
									c1 = _mm256_add_epi64(c1, _mm256_mul_epu32(reducerVector, m1));
									c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(reducerVector, m5));
									c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(reducerVector, m9));
									c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(reducerVector, m13));
									c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(reducerVector, m17));
									c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(reducerVector, m21));
									c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(reducerVector, m25));
									c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(reducerVector, m29));
									c9 = _mm256_add_epi64(c9, _mm256_mul_epu32(reducerVector, m33));
								}
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
				 *
				 * @note Все записи читаются в одном порядке при любом индексе. Таблица и
				 *       результат выровнены на 32 байта
				 *
				 */
				__attribute__((target("avx2"))) static void choose29Avx2(const uint32_t table[9][32][4], const uint64_t index, uint64_t * result) noexcept {
					// Искомый номер во всех дорожках
					const __m256i wanted = _mm256_set1_epi32(static_cast <int> (index));
					// За проход читаются две соседние записи
					const __m256i step = _mm256_set1_epi32(2);
					// Номера первой пары записей
					__m256i positions = _mm256_set_epi32(1, 1, 1, 1, 0, 0, 0, 0);
					// Девять накопителей охватывают все 36 коэффициентов
					__m256i c0 = _mm256_setzero_si256();
					__m256i c1 = _mm256_setzero_si256();
					__m256i c2 = _mm256_setzero_si256();
					__m256i c3 = _mm256_setzero_si256();
					__m256i c4 = _mm256_setzero_si256();
					__m256i c5 = _mm256_setzero_si256();
					__m256i c6 = _mm256_setzero_si256();
					__m256i c7 = _mm256_setzero_si256();
					__m256i c8 = _mm256_setzero_si256();
					// Порядок чтения всех записей одинаков при любом индексе
					for(size_t i = 0; i < 16; i++){
						// Одна маска обслуживает оба номера во всех блоках
						const __m256i mask = _mm256_cmpeq_epi32(wanted, positions);
						c0 = _mm256_or_si256(c0, _mm256_and_si256(mask, _mm256_load_si256(reinterpret_cast <const __m256i *> (table[0]) + i)));
						c1 = _mm256_or_si256(c1, _mm256_and_si256(mask, _mm256_load_si256(reinterpret_cast <const __m256i *> (table[1]) + i)));
						c2 = _mm256_or_si256(c2, _mm256_and_si256(mask, _mm256_load_si256(reinterpret_cast <const __m256i *> (table[2]) + i)));
						c3 = _mm256_or_si256(c3, _mm256_and_si256(mask, _mm256_load_si256(reinterpret_cast <const __m256i *> (table[3]) + i)));
						c4 = _mm256_or_si256(c4, _mm256_and_si256(mask, _mm256_load_si256(reinterpret_cast <const __m256i *> (table[4]) + i)));
						c5 = _mm256_or_si256(c5, _mm256_and_si256(mask, _mm256_load_si256(reinterpret_cast <const __m256i *> (table[5]) + i)));
						c6 = _mm256_or_si256(c6, _mm256_and_si256(mask, _mm256_load_si256(reinterpret_cast <const __m256i *> (table[6]) + i)));
						c7 = _mm256_or_si256(c7, _mm256_and_si256(mask, _mm256_load_si256(reinterpret_cast <const __m256i *> (table[7]) + i)));
						c8 = _mm256_or_si256(c8, _mm256_and_si256(mask, _mm256_load_si256(reinterpret_cast <const __m256i *> (table[8]) + i)));
						// Переходим к следующей открытой паре номеров
						positions = _mm256_add_epi32(positions, step);
					}
					// Объединяем половины и расширяем четыре коэффициента блока 0
					{
						const __m128i half = _mm_or_si128(_mm256_castsi256_si128(c0), _mm256_extracti128_si256(c0, 1));
						_mm256_store_si256(reinterpret_cast <__m256i *> (result + 0), _mm256_cvtepu32_epi64(half));
					}
					// Объединяем половины и расширяем четыре коэффициента блока 1
					{
						const __m128i half = _mm_or_si128(_mm256_castsi256_si128(c1), _mm256_extracti128_si256(c1, 1));
						_mm256_store_si256(reinterpret_cast <__m256i *> (result + 4), _mm256_cvtepu32_epi64(half));
					}
					// Объединяем половины и расширяем четыре коэффициента блока 2
					{
						const __m128i half = _mm_or_si128(_mm256_castsi256_si128(c2), _mm256_extracti128_si256(c2, 1));
						_mm256_store_si256(reinterpret_cast <__m256i *> (result + 8), _mm256_cvtepu32_epi64(half));
					}
					// Объединяем половины и расширяем четыре коэффициента блока 3
					{
						const __m128i half = _mm_or_si128(_mm256_castsi256_si128(c3), _mm256_extracti128_si256(c3, 1));
						_mm256_store_si256(reinterpret_cast <__m256i *> (result + 12), _mm256_cvtepu32_epi64(half));
					}
					// Объединяем половины и расширяем четыре коэффициента блока 4
					{
						const __m128i half = _mm_or_si128(_mm256_castsi256_si128(c4), _mm256_extracti128_si256(c4, 1));
						_mm256_store_si256(reinterpret_cast <__m256i *> (result + 16), _mm256_cvtepu32_epi64(half));
					}
					// Объединяем половины и расширяем четыре коэффициента блока 5
					{
						const __m128i half = _mm_or_si128(_mm256_castsi256_si128(c5), _mm256_extracti128_si256(c5, 1));
						_mm256_store_si256(reinterpret_cast <__m256i *> (result + 20), _mm256_cvtepu32_epi64(half));
					}
					// Объединяем половины и расширяем четыре коэффициента блока 6
					{
						const __m128i half = _mm_or_si128(_mm256_castsi256_si128(c6), _mm256_extracti128_si256(c6, 1));
						_mm256_store_si256(reinterpret_cast <__m256i *> (result + 24), _mm256_cvtepu32_epi64(half));
					}
					// Объединяем половины и расширяем четыре коэффициента блока 7
					{
						const __m128i half = _mm_or_si128(_mm256_castsi256_si128(c7), _mm256_extracti128_si256(c7, 1));
						_mm256_store_si256(reinterpret_cast <__m256i *> (result + 28), _mm256_cvtepu32_epi64(half));
					}
					// Объединяем половины и расширяем четыре коэффициента блока 8
					{
						const __m128i half = _mm_or_si128(_mm256_castsi256_si128(c8), _mm256_extracti128_si256(c8, 1));
						_mm256_store_si256(reinterpret_cast <__m256i *> (result + 32), _mm256_cvtepu32_epi64(half));
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
				 *       Рабочие массивы затираются перед выходом
				 *
				 */
				[[maybe_unused]] __attribute__((target("avx2"))) static void power16Avx2(const uint64_t * base, const uint64_t * exponent, const uint64_t * modulus, const uint64_t * rr, const uint64_t inverse, uint64_t * result) noexcept {
					// Общий буфер произведения и младших коэффициентов
					alignas(1024) uint64_t scratch[128];
					// Рабочие числа с отдельным выравниванием
					alignas(512) uint64_t field[64], entered[64], square[64], one[64] = {}, adjustment[64] = {}, accumulator[64], chosen[64];
					// По 40 слов на степень, включая нулевое дополнение; шаг строки кратен 64 байтам
					alignas(512) uint64_t table[32][40];
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
					choose29Avx2(columns, window29Avx2(exponent, 1020, 4), accumulator);
					// Перебираем оставшиеся окна по открытому счётчику
					for(size_t position = 1020; position > 0;){
						// Положение следующего окна
						position -= 5;
						// Пять квадратов окна одним вызовом
						square29Avx2(scratch, accumulator, accumulator, field, inverse, 5);
						// Выбираем запись полным перебором таблицы
						choose29Avx2(columns, window29Avx2(exponent, position, 5), chosen);
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
					// Затираем все явно выделенные рабочие массивы
					sys::wipe(scratch, sizeof(scratch));
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
