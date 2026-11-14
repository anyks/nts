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
 *  1. Входы меньше 2m, m < 2^1024; коэффициенты не больше 2^29 + 64, старший - не больше
 *    1024. Четыре слова дополнения нулевые. Произведение переносит старшие части после каждых
 *    четырёх рядов; квадрат - один раз в коэффициентах 28…39 готовой свёртки. Модель
 *    tools/math/power29.py даёт менее 0,688 от 2^64 у произведения и менее 0,922 у квадрата.
 *    Два заключительных прохода оставляют коэффициенты не больше 2^29 + 43 и 2^29 + 59
 *    соответственно. Итог меньше m + 4m^2/R < 2m; старший коэффициент вновь меньше 1024.
 *    Доводка до m выполняется один раз после выхода из области, в обычных словах.
 *  2. Секретный показатель всегда перебирается по 1024 разрядам. Выбор записи читает всю
 *    таблицу в одном порядке; даже смещение внутри строки кеша от показателя не зависит.
 *    Произведение и младшие коэффициенты живут в кадре степени и затираются перед выходом.
 *    Буфер ядра не пересекается с числами, итог может совпадать с входом.
 *  3. Путь выбирается лишь для шестнадцати слов на AVX2 без ADX: ширины, признак машины и
 *    допустимость основания проверяются до вызова. Чужой код в реализации не используется;
 *    сторонняя арифметика служит эталоном результата и скорости.
 *  4. Два множителя приведения получаем сразу: B = 2^29, T = low[0] + B * low[1],
 *    Q = -T / m по модулю B². Младшие и старшие 29 разрядов Q совпадают с двумя
 *    последовательными множителями. Шаг inverse * (2 + m * inverse) наращивает известные
 *    29 разрядов отрицательного обратного до 58. Беззнаковое переполнение при упаковке
 *    и умножении намеренное: остаются лишь младшие 58 разрядов. Скалярные переносы и
 *    договор коэффициентов сохранены; произведение остаётся на одиночном приведении по замеру.
 *  5. Свёртка квадрата вынесена в невстраиваемый метод: её временные векторы не живут
 *    одновременно с состоянием приведения. Диагональные коэффициенты выбираются масками
 *    после произведения; недиагональные суммы удваиваются один раз на четыре коэффициента.
 *  6. Выбор степени держит девять накопителей и одну текущую маску, читая все 32 записи.
 *    Отдельного массива масок нет. В строке подготовительной таблицы ровно 40 слов,
 *    включая нулевое дополнение; шаг строки 320 байтов сохраняет нужное выравнивание.
 *  7. Перенос середины квадрата выполняется после свёртки, перед приведением: снимаются
 *    старшие части коэффициентов 28…39, последняя прибавляется к коэффициенту 40. Это
 *    сохраняет число и заменяет девять переносов внутри цикла тремя векторными группами.
 *    Адреса фиксированы; отдельный проход быстрее переноса внутри свёртки по полной подписи.
 *  8. Модуль квадрата не пересекается с итогом: указатель отмечен __restrict__. Его векторы
 *    явно загружены до повторений, чтобы вставка свёртки не мешала их сохранению в кадре.
 *    В степени модуль лежит в отдельном field; совпадение итога с value допустимо. Читаемые
 *    value и modulus также могут совпадать при отдельном итоге. Девять проходов приведения
 *    разворачиваются по три: это быстрее полной развёртки по замеру.
 *  9. Свёртка выполняется одной вставкой без обращений к стеку. Двенадцать регистров
 *    сохраняют рассылки; при порождении вытесняется коэффициент с наиболее далёким
 *    следующим чтением. Обычные произведения читают второй сомножитель из памяти.
 *    Адреса фиксированы, объявлены чтение 40 слов и запись 72; вход и итог не пересекаются.
 *  10. В обычном произведении term29Avx2 читает модуль прямо из памяти. Векторы первого
 *     сомножителя остаются на интринсиках: их повторные загрузки замедляют полную подпись.
 *  11. Две соседние верхние диагонали свёртки объединены: [a², ab, c², cd] вычисляется
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
/**
 * Объявляем сторожевой макрос заголовка
 */
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
				 * @brief Функция четырёх произведений с чтением второго сомножителя из памяти
				 *
				 * @param first  вектор первых сомножителей, младшие 32 разряда каждой дорожки
				 * @param second четыре слова вторых сомножителей по произвольному выравниванию
				 * @return       четыре произведения беззнаковых чисел в 64-разрядных дорожках
				 *
				 * @note Операнд памяти описывает все читаемые байты. Рассылку первого сомножителя
				 *       собиратель вправе использовать повторно, второй читается самой командой
				 *
				 */
				__attribute__((target("avx2"), always_inline)) static __ANTS_INLINE__ __m256i term29Avx2(const __m256i first, const uint64_t * second) noexcept {
					// Место четырёх произведений
					__m256i result;
					// Читаем четыре слова без промежуточного вектора в кадре стека
					__asm__("vpmuludq %2, %1, %0" : "=x" (result) : "x" (first), "m" (* reinterpret_cast <const uint64_t (*)[4]> (second)));
					// Выводим произведения в том же порядке дорожек
					return result;
				}
				/**
				 * @brief Функция умножения Монтгомери на коэффициентах по 29 разрядов
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
					// Перенос между младшими коэффициентами начинается с нуля
					uint64_t carry = 0;
					// Обнуляем четыре младших коэффициента
					low[0] = low[1] = low[2] = low[3] = 0;
					// Остальные коэффициенты накапливаются в девяти векторах
					__m256i c1 = zero;
					// Накапливаем коэффициенты 8…11 в векторе c2
					__m256i c2 = zero;
					// Накапливаем коэффициенты 12…15 в векторе c3
					__m256i c3 = zero;
					// Накапливаем коэффициенты 16…19 в векторе c4
					__m256i c4 = zero;
					// Накапливаем коэффициенты 20…23 в векторе c5
					__m256i c5 = zero;
					// Накапливаем коэффициенты 24…27 в векторе c6
					__m256i c6 = zero;
					// Накапливаем коэффициенты 28…31 в векторе c7
					__m256i c7 = zero;
					// Накапливаем коэффициенты 32…35 в векторе c8
					__m256i c8 = zero;
					// Накапливаем коэффициенты 36…39 в векторе c9
					__m256i c9 = zero;
					/**
					 * Четыре ряда за проход сохраняют положение коэффициентов внутри векторов
					 */
					for(size_t i = 0; i < 36; i += 4){
						// Частичный перенос не даёт средним коэффициентам переполнить 64 разряда
						const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c3, 29), 0x93);
						// Оставляем младшие разряды c3 и вносим старшие в начало
						c3 = _mm256_add_epi64(_mm256_and_si256(c3, mask), _mm256_blend_epi32(high, zero, 3));
						// Прибавляем старшие разряды c3 к следующей четвёрке
						c4 = _mm256_add_epi64(c4, _mm256_blend_epi32(zero, high, 3));
						// Ряд 1: младший коэффициент становится кратным 2^29
						{
							// Читаем слово 1 ряда второго сомножителя
							const uint64_t word = second[i + 0];
							// Рассылаем слово по всем дорожкам вектора
							const __m256i wordVector = _mm256_set1_epi64x(word);
							// Прибавляем произведение слова к коэффициенту 0
							low[0] += (word * first[0]);
							// Прибавляем произведение слова к коэффициенту 1
							low[1] += (word * first[1]);
							// Прибавляем произведение слова к коэффициенту 2
							low[2] += (word * first[2]);
							// Прибавляем произведение слова к коэффициенту 3
							low[3] += (word * first[3]);
							// Вычисляем множитель приведения коэффициента 0
							const uint64_t reducer = ((low[0] * inverse) & 0x1FFFFFFF);
							// Рассылаем множитель приведения по дорожкам
							const __m256i reducerVector = _mm256_set1_epi64x(reducer);
							// Приводим коэффициент 0 по модулю
							low[0] += (reducer * modulus[0]);
							// Приводим коэффициент 1 по модулю
							low[1] += (reducer * modulus[1]);
							// Приводим коэффициент 2 по модулю
							low[2] += (reducer * modulus[2]);
							// Приводим коэффициент 3 по модулю
							low[3] += (reducer * modulus[3]);
							// Снимаем старшие 29 разрядов коэффициента 0
							carry = (low[0] >> 29);
							// Переносим старшую часть в коэффициент 1
							low[1] += carry;
							// Прибавляем произведения слова к вектору c1
							c1 = _mm256_add_epi64(c1, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 4))));
							// Прибавляем произведения приведения к вектору c1
							c1 = _mm256_add_epi64(c1, term29Avx2(reducerVector, modulus + 4));
							// Прибавляем произведения слова к вектору c2
							c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 8))));
							// Прибавляем произведения приведения к вектору c2
							c2 = _mm256_add_epi64(c2, term29Avx2(reducerVector, modulus + 8));
							// Прибавляем произведения слова к вектору c3
							c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 12))));
							// Прибавляем произведения приведения к вектору c3
							c3 = _mm256_add_epi64(c3, term29Avx2(reducerVector, modulus + 12));
							// Прибавляем произведения слова к вектору c4
							c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 16))));
							// Прибавляем произведения приведения к вектору c4
							c4 = _mm256_add_epi64(c4, term29Avx2(reducerVector, modulus + 16));
							// Прибавляем произведения слова к вектору c5
							c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 20))));
							// Прибавляем произведения приведения к вектору c5
							c5 = _mm256_add_epi64(c5, term29Avx2(reducerVector, modulus + 20));
							// Прибавляем произведения слова к вектору c6
							c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 24))));
							// Прибавляем произведения приведения к вектору c6
							c6 = _mm256_add_epi64(c6, term29Avx2(reducerVector, modulus + 24));
							// Прибавляем произведения слова к вектору c7
							c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 28))));
							// Прибавляем произведения приведения к вектору c7
							c7 = _mm256_add_epi64(c7, term29Avx2(reducerVector, modulus + 28));
							// Прибавляем произведения слова к вектору c8
							c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 32))));
							// Прибавляем произведения приведения к вектору c8
							c8 = _mm256_add_epi64(c8, term29Avx2(reducerVector, modulus + 32));
						}
						// Ряд 2: младший коэффициент становится кратным 2^29
						{
							// Читаем слово 2 ряда второго сомножителя
							const uint64_t word = second[i + 1];
							// Рассылаем слово по всем дорожкам вектора
							const __m256i wordVector = _mm256_set1_epi64x(word);
							// Прибавляем произведение слова к коэффициенту 1
							low[1] += (word * first[0]);
							// Прибавляем произведение слова к коэффициенту 2
							low[2] += (word * first[1]);
							// Прибавляем произведение слова к коэффициенту 3
							low[3] += (word * first[2]);
							// Вычисляем множитель приведения коэффициента 1
							const uint64_t reducer = ((low[1] * inverse) & 0x1FFFFFFF);
							// Рассылаем множитель приведения по дорожкам
							const __m256i reducerVector = _mm256_set1_epi64x(reducer);
							// Приводим коэффициент 1 по модулю
							low[1] += (reducer * modulus[0]);
							// Приводим коэффициент 2 по модулю
							low[2] += (reducer * modulus[1]);
							// Приводим коэффициент 3 по модулю
							low[3] += (reducer * modulus[2]);
							// Снимаем старшие 29 разрядов коэффициента 1
							carry = (low[1] >> 29);
							// Переносим старшую часть в коэффициент 2
							low[2] += carry;
							// Прибавляем произведения слова к вектору c1
							c1 = _mm256_add_epi64(c1, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 3))));
							// Прибавляем произведения приведения к вектору c1
							c1 = _mm256_add_epi64(c1, term29Avx2(reducerVector, modulus + 3));
							// Прибавляем произведения слова к вектору c2
							c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 7))));
							// Прибавляем произведения приведения к вектору c2
							c2 = _mm256_add_epi64(c2, term29Avx2(reducerVector, modulus + 7));
							// Прибавляем произведения слова к вектору c3
							c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 11))));
							// Прибавляем произведения приведения к вектору c3
							c3 = _mm256_add_epi64(c3, term29Avx2(reducerVector, modulus + 11));
							// Прибавляем произведения слова к вектору c4
							c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 15))));
							// Прибавляем произведения приведения к вектору c4
							c4 = _mm256_add_epi64(c4, term29Avx2(reducerVector, modulus + 15));
							// Прибавляем произведения слова к вектору c5
							c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 19))));
							// Прибавляем произведения приведения к вектору c5
							c5 = _mm256_add_epi64(c5, term29Avx2(reducerVector, modulus + 19));
							// Прибавляем произведения слова к вектору c6
							c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 23))));
							// Прибавляем произведения приведения к вектору c6
							c6 = _mm256_add_epi64(c6, term29Avx2(reducerVector, modulus + 23));
							// Прибавляем произведения слова к вектору c7
							c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 27))));
							// Прибавляем произведения приведения к вектору c7
							c7 = _mm256_add_epi64(c7, term29Avx2(reducerVector, modulus + 27));
							// Прибавляем произведения слова к вектору c8
							c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 31))));
							// Прибавляем произведения приведения к вектору c8
							c8 = _mm256_add_epi64(c8, term29Avx2(reducerVector, modulus + 31));
							// Прибавляем произведения слова к вектору c9
							c9 = _mm256_add_epi64(c9, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 35))));
							// Прибавляем произведения приведения к вектору c9
							c9 = _mm256_add_epi64(c9, term29Avx2(reducerVector, modulus + 35));
						}
						// Ряд 3: младший коэффициент становится кратным 2^29
						{
							// Читаем слово 3 ряда второго сомножителя
							const uint64_t word = second[i + 2];
							// Рассылаем слово по всем дорожкам вектора
							const __m256i wordVector = _mm256_set1_epi64x(word);
							// Прибавляем произведение слова к коэффициенту 2
							low[2] += (word * first[0]);
							// Прибавляем произведение слова к коэффициенту 3
							low[3] += (word * first[1]);
							// Вычисляем множитель приведения коэффициента 2
							const uint64_t reducer = ((low[2] * inverse) & 0x1FFFFFFF);
							// Рассылаем множитель приведения по дорожкам
							const __m256i reducerVector = _mm256_set1_epi64x(reducer);
							// Приводим коэффициент 2 по модулю
							low[2] += (reducer * modulus[0]);
							// Приводим коэффициент 3 по модулю
							low[3] += (reducer * modulus[1]);
							// Снимаем старшие 29 разрядов коэффициента 2
							carry = (low[2] >> 29);
							// Переносим старшую часть в коэффициент 3
							low[3] += carry;
							// Прибавляем произведения слова к вектору c1
							c1 = _mm256_add_epi64(c1, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 2))));
							// Прибавляем произведения приведения к вектору c1
							c1 = _mm256_add_epi64(c1, term29Avx2(reducerVector, modulus + 2));
							// Прибавляем произведения слова к вектору c2
							c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 6))));
							// Прибавляем произведения приведения к вектору c2
							c2 = _mm256_add_epi64(c2, term29Avx2(reducerVector, modulus + 6));
							// Прибавляем произведения слова к вектору c3
							c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 10))));
							// Прибавляем произведения приведения к вектору c3
							c3 = _mm256_add_epi64(c3, term29Avx2(reducerVector, modulus + 10));
							// Прибавляем произведения слова к вектору c4
							c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 14))));
							// Прибавляем произведения приведения к вектору c4
							c4 = _mm256_add_epi64(c4, term29Avx2(reducerVector, modulus + 14));
							// Прибавляем произведения слова к вектору c5
							c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 18))));
							// Прибавляем произведения приведения к вектору c5
							c5 = _mm256_add_epi64(c5, term29Avx2(reducerVector, modulus + 18));
							// Прибавляем произведения слова к вектору c6
							c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 22))));
							// Прибавляем произведения приведения к вектору c6
							c6 = _mm256_add_epi64(c6, term29Avx2(reducerVector, modulus + 22));
							// Прибавляем произведения слова к вектору c7
							c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 26))));
							// Прибавляем произведения приведения к вектору c7
							c7 = _mm256_add_epi64(c7, term29Avx2(reducerVector, modulus + 26));
							// Прибавляем произведения слова к вектору c8
							c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 30))));
							// Прибавляем произведения приведения к вектору c8
							c8 = _mm256_add_epi64(c8, term29Avx2(reducerVector, modulus + 30));
							// Прибавляем произведения слова к вектору c9
							c9 = _mm256_add_epi64(c9, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 34))));
							// Прибавляем произведения приведения к вектору c9
							c9 = _mm256_add_epi64(c9, term29Avx2(reducerVector, modulus + 34));
						}
						// Ряд 4: младший коэффициент становится кратным 2^29
						{
							// Читаем слово 4 ряда второго сомножителя
							const uint64_t word = second[i + 3];
							// Рассылаем слово по всем дорожкам вектора
							const __m256i wordVector = _mm256_set1_epi64x(word);
							// Прибавляем произведение слова к коэффициенту 3
							low[3] += (word * first[0]);
							// Вычисляем множитель приведения коэффициента 3
							const uint64_t reducer = ((low[3] * inverse) & 0x1FFFFFFF);
							// Рассылаем множитель приведения по дорожкам
							const __m256i reducerVector = _mm256_set1_epi64x(reducer);
							// Приводим коэффициент 3 по модулю
							low[3] += (reducer * modulus[0]);
							// Снимаем старшие 29 разрядов коэффициента 3
							carry = (low[3] >> 29);
							// Прибавляем произведения слова к вектору c1
							c1 = _mm256_add_epi64(c1, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 1))));
							// Прибавляем произведения приведения к вектору c1
							c1 = _mm256_add_epi64(c1, term29Avx2(reducerVector, modulus + 1));
							// Прибавляем произведения слова к вектору c2
							c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 5))));
							// Прибавляем произведения приведения к вектору c2
							c2 = _mm256_add_epi64(c2, term29Avx2(reducerVector, modulus + 5));
							// Прибавляем произведения слова к вектору c3
							c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 9))));
							// Прибавляем произведения приведения к вектору c3
							c3 = _mm256_add_epi64(c3, term29Avx2(reducerVector, modulus + 9));
							// Прибавляем произведения слова к вектору c4
							c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 13))));
							// Прибавляем произведения приведения к вектору c4
							c4 = _mm256_add_epi64(c4, term29Avx2(reducerVector, modulus + 13));
							// Прибавляем произведения слова к вектору c5
							c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 17))));
							// Прибавляем произведения приведения к вектору c5
							c5 = _mm256_add_epi64(c5, term29Avx2(reducerVector, modulus + 17));
							// Прибавляем произведения слова к вектору c6
							c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 21))));
							// Прибавляем произведения приведения к вектору c6
							c6 = _mm256_add_epi64(c6, term29Avx2(reducerVector, modulus + 21));
							// Прибавляем произведения слова к вектору c7
							c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 25))));
							// Прибавляем произведения приведения к вектору c7
							c7 = _mm256_add_epi64(c7, term29Avx2(reducerVector, modulus + 25));
							// Прибавляем произведения слова к вектору c8
							c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 29))));
							// Прибавляем произведения приведения к вектору c8
							c8 = _mm256_add_epi64(c8, term29Avx2(reducerVector, modulus + 29));
							// Прибавляем произведения слова к вектору c9
							c9 = _mm256_add_epi64(c9, _mm256_mul_epu32(wordVector, _mm256_loadu_si256(reinterpret_cast <const __m256i *> (first + 33))));
							// Прибавляем произведения приведения к вектору c9
							c9 = _mm256_add_epi64(c9, term29Avx2(reducerVector, modulus + 33));
						}
						// Отбрасываем четыре нулевых младших коэффициента
						_mm256_storeu_si256(reinterpret_cast <__m256i *> (low), c1);
						// Возвращаем перенос в младший коэффициент
						low[0] += carry;
						// Сдвигаем накопитель c2 на место c1
						c1 = c2;
						// Сдвигаем накопитель c3 на место c2
						c2 = c3;
						// Сдвигаем накопитель c4 на место c3
						c3 = c4;
						// Сдвигаем накопитель c5 на место c4
						c4 = c5;
						// Сдвигаем накопитель c6 на место c5
						c5 = c6;
						// Сдвигаем накопитель c7 на место c6
						c6 = c7;
						// Сдвигаем накопитель c8 на место c7
						c7 = c8;
						// Сдвигаем накопитель c9 на место c8
						c8 = c9;
						// Освобождаем старший накопитель под новые коэффициенты
						c9 = zero;
					}
					// Собираем четыре младших коэффициента перед переносами
					__m256i c0 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (low));
					// Проводим переносы на один коэффициент: снимаем накопленные старшие части
					{
						// Перенос из предыдущего вектора начинается с нуля
						__m256i previous = zero;
						{
							// Сдвигаем старшие разряды вектора c0 в соседнюю дорожку
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c0, 29), 0x93);
							// Складываем младшие разряды c0 с переносом соседнего вектора
							c0 = _mm256_add_epi64(_mm256_and_si256(c0, mask), _mm256_blend_epi32(high, previous, 3));
							// Запоминаем старшие разряды для следующего вектора
							previous = high;
						}
						{
							// Сдвигаем старшие разряды вектора c1 в соседнюю дорожку
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c1, 29), 0x93);
							// Складываем младшие разряды c1 с переносом соседнего вектора
							c1 = _mm256_add_epi64(_mm256_and_si256(c1, mask), _mm256_blend_epi32(high, previous, 3));
							// Запоминаем старшие разряды для следующего вектора
							previous = high;
						}
						{
							// Сдвигаем старшие разряды вектора c2 в соседнюю дорожку
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c2, 29), 0x93);
							// Складываем младшие разряды c2 с переносом соседнего вектора
							c2 = _mm256_add_epi64(_mm256_and_si256(c2, mask), _mm256_blend_epi32(high, previous, 3));
							// Запоминаем старшие разряды для следующего вектора
							previous = high;
						}
						{
							// Сдвигаем старшие разряды вектора c3 в соседнюю дорожку
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c3, 29), 0x93);
							// Складываем младшие разряды c3 с переносом соседнего вектора
							c3 = _mm256_add_epi64(_mm256_and_si256(c3, mask), _mm256_blend_epi32(high, previous, 3));
							// Запоминаем старшие разряды для следующего вектора
							previous = high;
						}
						{
							// Сдвигаем старшие разряды вектора c4 в соседнюю дорожку
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c4, 29), 0x93);
							// Складываем младшие разряды c4 с переносом соседнего вектора
							c4 = _mm256_add_epi64(_mm256_and_si256(c4, mask), _mm256_blend_epi32(high, previous, 3));
							// Запоминаем старшие разряды для следующего вектора
							previous = high;
						}
						{
							// Сдвигаем старшие разряды вектора c5 в соседнюю дорожку
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c5, 29), 0x93);
							// Складываем младшие разряды c5 с переносом соседнего вектора
							c5 = _mm256_add_epi64(_mm256_and_si256(c5, mask), _mm256_blend_epi32(high, previous, 3));
							// Запоминаем старшие разряды для следующего вектора
							previous = high;
						}
						{
							// Сдвигаем старшие разряды вектора c6 в соседнюю дорожку
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c6, 29), 0x93);
							// Складываем младшие разряды c6 с переносом соседнего вектора
							c6 = _mm256_add_epi64(_mm256_and_si256(c6, mask), _mm256_blend_epi32(high, previous, 3));
							// Запоминаем старшие разряды для следующего вектора
							previous = high;
						}
						{
							// Сдвигаем старшие разряды вектора c7 в соседнюю дорожку
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c7, 29), 0x93);
							// Складываем младшие разряды c7 с переносом соседнего вектора
							c7 = _mm256_add_epi64(_mm256_and_si256(c7, mask), _mm256_blend_epi32(high, previous, 3));
							// Запоминаем старшие разряды для следующего вектора
							previous = high;
						}
						{
							// Сдвигаем старшие разряды вектора c8 в соседнюю дорожку
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c8, 29), 0x93);
							// Складываем младшие разряды c8 с переносом соседнего вектора
							c8 = _mm256_add_epi64(_mm256_and_si256(c8, mask), _mm256_blend_epi32(high, previous, 3));
						}
					}
					// Проводим переносы на один коэффициент: оставляем ограниченную избыточность
					{
						// Перенос из предыдущего вектора начинается с нуля
						__m256i previous = zero;
						{
							// Сдвигаем старшие разряды вектора c0 в соседнюю дорожку
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c0, 29), 0x93);
							// Складываем младшие разряды c0 с переносом соседнего вектора
							c0 = _mm256_add_epi64(_mm256_and_si256(c0, mask), _mm256_blend_epi32(high, previous, 3));
							// Запоминаем старшие разряды для следующего вектора
							previous = high;
						}
						{
							// Сдвигаем старшие разряды вектора c1 в соседнюю дорожку
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c1, 29), 0x93);
							// Складываем младшие разряды c1 с переносом соседнего вектора
							c1 = _mm256_add_epi64(_mm256_and_si256(c1, mask), _mm256_blend_epi32(high, previous, 3));
							// Запоминаем старшие разряды для следующего вектора
							previous = high;
						}
						{
							// Сдвигаем старшие разряды вектора c2 в соседнюю дорожку
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c2, 29), 0x93);
							// Складываем младшие разряды c2 с переносом соседнего вектора
							c2 = _mm256_add_epi64(_mm256_and_si256(c2, mask), _mm256_blend_epi32(high, previous, 3));
							// Запоминаем старшие разряды для следующего вектора
							previous = high;
						}
						{
							// Сдвигаем старшие разряды вектора c3 в соседнюю дорожку
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c3, 29), 0x93);
							// Складываем младшие разряды c3 с переносом соседнего вектора
							c3 = _mm256_add_epi64(_mm256_and_si256(c3, mask), _mm256_blend_epi32(high, previous, 3));
							// Запоминаем старшие разряды для следующего вектора
							previous = high;
						}
						{
							// Сдвигаем старшие разряды вектора c4 в соседнюю дорожку
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c4, 29), 0x93);
							// Складываем младшие разряды c4 с переносом соседнего вектора
							c4 = _mm256_add_epi64(_mm256_and_si256(c4, mask), _mm256_blend_epi32(high, previous, 3));
							// Запоминаем старшие разряды для следующего вектора
							previous = high;
						}
						{
							// Сдвигаем старшие разряды вектора c5 в соседнюю дорожку
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c5, 29), 0x93);
							// Складываем младшие разряды c5 с переносом соседнего вектора
							c5 = _mm256_add_epi64(_mm256_and_si256(c5, mask), _mm256_blend_epi32(high, previous, 3));
							// Запоминаем старшие разряды для следующего вектора
							previous = high;
						}
						{
							// Сдвигаем старшие разряды вектора c6 в соседнюю дорожку
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c6, 29), 0x93);
							// Складываем младшие разряды c6 с переносом соседнего вектора
							c6 = _mm256_add_epi64(_mm256_and_si256(c6, mask), _mm256_blend_epi32(high, previous, 3));
							// Запоминаем старшие разряды для следующего вектора
							previous = high;
						}
						{
							// Сдвигаем старшие разряды вектора c7 в соседнюю дорожку
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c7, 29), 0x93);
							// Складываем младшие разряды c7 с переносом соседнего вектора
							c7 = _mm256_add_epi64(_mm256_and_si256(c7, mask), _mm256_blend_epi32(high, previous, 3));
							// Запоминаем старшие разряды для следующего вектора
							previous = high;
						}
						{
							// Сдвигаем старшие разряды вектора c8 в соседнюю дорожку
							const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c8, 29), 0x93);
							// Складываем младшие разряды c8 с переносом соседнего вектора
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
					/**
					 * Последние четыре коэффициента служат нулевым дополнением для векторных загрузок
					 */
					for(size_t i = 36; i < 40; i++)
						// Зануляем слова нулевого дополнения итога
						result[i] = 0;
					// Завершаем работу с верхними половинами векторных регистров
					_mm256_zeroupper();
				}
				/**
				 * @brief Функция симметричной свёртки квадрата на коэффициентах по 29 разрядов
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
				 * @brief Функция квадрата Монтгомери на коэффициентах по 29 разрядов
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
					// Запоминаем слова модуля 2…5 в векторе m2
					const __m256i m2 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 2));
					// Запоминаем слова модуля 3…6 в векторе m3
					const __m256i m3 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 3));
					// Запоминаем слова модуля 4…7 в векторе m4
					const __m256i m4 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 4));
					// Запоминаем слова модуля 5…8 в векторе m5
					const __m256i m5 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 5));
					// Запоминаем слова модуля 6…9 в векторе m6
					const __m256i m6 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 6));
					// Запоминаем слова модуля 7…10 в векторе m7
					const __m256i m7 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 7));
					// Запоминаем слова модуля 8…11 в векторе m8
					const __m256i m8 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 8));
					// Запоминаем слова модуля 9…12 в векторе m9
					const __m256i m9 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 9));
					// Запоминаем слова модуля 10…13 в векторе m10
					const __m256i m10 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 10));
					// Запоминаем слова модуля 11…14 в векторе m11
					const __m256i m11 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 11));
					// Запоминаем слова модуля 12…15 в векторе m12
					const __m256i m12 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 12));
					// Запоминаем слова модуля 13…16 в векторе m13
					const __m256i m13 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 13));
					// Запоминаем слова модуля 14…17 в векторе m14
					const __m256i m14 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 14));
					// Запоминаем слова модуля 15…18 в векторе m15
					const __m256i m15 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 15));
					// Запоминаем слова модуля 16…19 в векторе m16
					const __m256i m16 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 16));
					// Запоминаем слова модуля 17…20 в векторе m17
					const __m256i m17 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 17));
					// Запоминаем слова модуля 18…21 в векторе m18
					const __m256i m18 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 18));
					// Запоминаем слова модуля 19…22 в векторе m19
					const __m256i m19 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 19));
					// Запоминаем слова модуля 20…23 в векторе m20
					const __m256i m20 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 20));
					// Запоминаем слова модуля 21…24 в векторе m21
					const __m256i m21 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 21));
					// Запоминаем слова модуля 22…25 в векторе m22
					const __m256i m22 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 22));
					// Запоминаем слова модуля 23…26 в векторе m23
					const __m256i m23 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 23));
					// Запоминаем слова модуля 24…27 в векторе m24
					const __m256i m24 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 24));
					// Запоминаем слова модуля 25…28 в векторе m25
					const __m256i m25 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 25));
					// Запоминаем слова модуля 26…29 в векторе m26
					const __m256i m26 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 26));
					// Запоминаем слова модуля 27…30 в векторе m27
					const __m256i m27 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 27));
					// Запоминаем слова модуля 28…31 в векторе m28
					const __m256i m28 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 28));
					// Запоминаем слова модуля 29…32 в векторе m29
					const __m256i m29 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 29));
					// Запоминаем слова модуля 30…33 в векторе m30
					const __m256i m30 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 30));
					// Запоминаем слова модуля 31…34 в векторе m31
					const __m256i m31 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 31));
					// Запоминаем слова модуля 32…35 в векторе m32
					const __m256i m32 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 32));
					// Запоминаем слова модуля 33…36 в векторе m33
					const __m256i m33 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 33));
					// Запоминаем слова модуля 34…37 в векторе m34
					const __m256i m34 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 34));
					// Запоминаем слова модуля 35…38 в векторе m35
					const __m256i m35 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (modulus + 35));
					// Наращиваем отрицательный обратный множитель до 58 разрядов
					const uint64_t paired = (inverse * (2 + ((modulus[0] + (modulus[1] << 29)) * inverse)));
					// Произведение и младшие коэффициенты находятся в затираемом кадре вызывающего
					uint64_t * product = buffer;
					// Младшие коэффициенты занимают конец рабочего буфера
					uint64_t * low = (buffer + 80);
					/**
					 * Дополнение произведения за старшим значимым коэффициентом
					 */
					for(size_t i = 72; i < 80; i++)
						// Зануляем дополнение за старшим значимым коэффициентом
						product[i] = 0;
					/**
					 * Последовательные квадраты окна сохраняют тот же модуль и рабочее место
					 */
					for(size_t round = 0; round < repeat; round++){
						// Свёртка отдельно от приведения освобождает регистры её временных значений
						product29Avx2(product, value);
						// Перенос коэффициентов 28…39 ограничивает все последующие суммы приведения
						{
							// Перенос из предыдущего вектора начинается с нуля
							__m256i previous = zero;
							{
								// Читаем коэффициенты 28…31 произведения
								const __m256i part = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (product + 28));
								// Сдвигаем старшие разряды четвёрки в соседнюю дорожку
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(part, 29), 0x93);
								// Записываем младшие разряды с переносом предыдущей четвёрки
								_mm256_storeu_si256(reinterpret_cast <__m256i *> (product + 28), _mm256_add_epi64(_mm256_and_si256(part, mask), _mm256_blend_epi32(high, previous, 3)));
								// Запоминаем старшие разряды для следующего вектора
								previous = high;
							}
							{
								// Читаем коэффициенты 32…35 произведения
								const __m256i part = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (product + 32));
								// Сдвигаем старшие разряды четвёрки в соседнюю дорожку
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(part, 29), 0x93);
								// Записываем младшие разряды с переносом предыдущей четвёрки
								_mm256_storeu_si256(reinterpret_cast <__m256i *> (product + 32), _mm256_add_epi64(_mm256_and_si256(part, mask), _mm256_blend_epi32(high, previous, 3)));
								// Запоминаем старшие разряды для следующего вектора
								previous = high;
							}
							{
								// Читаем коэффициенты 36…39 произведения
								const __m256i part = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (product + 36));
								// Сдвигаем старшие разряды четвёрки в соседнюю дорожку
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(part, 29), 0x93);
								// Записываем младшие разряды с переносом предыдущей четвёрки
								_mm256_storeu_si256(reinterpret_cast <__m256i *> (product + 36), _mm256_add_epi64(_mm256_and_si256(part, mask), _mm256_blend_epi32(high, previous, 3)));
								// Запоминаем старшие разряды для следующего вектора
								previous = high;
							}
							// Старшая часть коэффициента 39 переходит в коэффициент 40
							product[40] += static_cast <uint64_t> (_mm256_extract_epi64(previous, 0));
						}
						// Младшие четыре коэффициента приводятся цепочкой скалярных переносов
						uint64_t carry = 0;
						/**
						 * Четыре младших коэффициента переносятся в рабочий кадр
						 */
						for(size_t i = 0; i < 4; i++)
							// Копируем коэффициент в рабочий кадр
							low[i] = product[i];
						// Читаем коэффициенты 4…7 произведения в вектор c1
						__m256i c1 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (product + 4));
						// Читаем коэффициенты 8…11 произведения в вектор c2
						__m256i c2 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (product + 8));
						// Читаем коэффициенты 12…15 произведения в вектор c3
						__m256i c3 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (product + 12));
						// Читаем коэффициенты 16…19 произведения в вектор c4
						__m256i c4 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (product + 16));
						// Читаем коэффициенты 20…23 произведения в вектор c5
						__m256i c5 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (product + 20));
						// Читаем коэффициенты 24…27 произведения в вектор c6
						__m256i c6 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (product + 24));
						// Читаем коэффициенты 28…31 произведения в вектор c7
						__m256i c7 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (product + 28));
						// Читаем коэффициенты 32…35 произведения в вектор c8
						__m256i c8 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (product + 32));
						// Читаем коэффициенты 36…39 произведения в вектор c9
						__m256i c9 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (product + 36));
						// Четыре ряда за проход сохраняют положение коэффициентов внутри векторов
						#pragma GCC unroll 3
						/**
						 * Три прохода развёртки покрывают все 36 коэффициентов
						 */
						for(size_t i = 0; i < 36; i += 4){
							// Первая пара множителей определяется младшими 58 разрядами
							{
								// Собираем младшие 58 разрядов для пары множителей
								const uint64_t packed = ((low[0] + (low[1] << 29)) * paired) & 0x03FFFFFFFFFFFFFFULL;
								// Младший множитель и его обычный перенос
								{
									// Младший множитель приведения занимает 29 разрядов
									const uint64_t reducer = (packed & 0x1FFFFFFF);
									// Рассылаем младший множитель по всем дорожкам
									const __m256i reducerVector = _mm256_set1_epi64x(reducer);
									// Приводим коэффициент 0 по модулю
									low[0] += (reducer * modulus[0]);
									// Приводим коэффициент 1 по модулю
									low[1] += (reducer * modulus[1]);
									// Приводим коэффициент 2 по модулю
									low[2] += (reducer * modulus[2]);
									// Приводим коэффициент 3 по модулю
									low[3] += (reducer * modulus[3]);
									// Снимаем старшие 29 разрядов коэффициента 0
									carry = (low[0] >> 29);
									// Переносим старшую часть в коэффициент 1
									low[1] += carry;
									// Прибавляем произведения приведения к вектору c1
									c1 = _mm256_add_epi64(c1, _mm256_mul_epu32(reducerVector, m4));
									// Прибавляем произведения приведения к вектору c2
									c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(reducerVector, m8));
									// Прибавляем произведения приведения к вектору c3
									c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(reducerVector, m12));
									// Прибавляем произведения приведения к вектору c4
									c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(reducerVector, m16));
									// Прибавляем произведения приведения к вектору c5
									c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(reducerVector, m20));
									// Прибавляем произведения приведения к вектору c6
									c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(reducerVector, m24));
									// Прибавляем произведения приведения к вектору c7
									c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(reducerVector, m28));
									// Прибавляем произведения приведения к вектору c8
									c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(reducerVector, m32));
								}
								// Старший множитель уже известен независимо от предыдущего переноса
								{
									// Старший множитель приведения занимает старшие 29 разрядов
									const uint64_t reducer = (packed >> 29);
									// Рассылаем старший множитель по всем дорожкам
									const __m256i reducerVector = _mm256_set1_epi64x(reducer);
									// Приводим коэффициент 1 по модулю
									low[1] += (reducer * modulus[0]);
									// Приводим коэффициент 2 по модулю
									low[2] += (reducer * modulus[1]);
									// Приводим коэффициент 3 по модулю
									low[3] += (reducer * modulus[2]);
									// Снимаем старшие 29 разрядов коэффициента 1
									carry = (low[1] >> 29);
									// Переносим старшую часть в коэффициент 2
									low[2] += carry;
									// Прибавляем произведения приведения к вектору c1
									c1 = _mm256_add_epi64(c1, _mm256_mul_epu32(reducerVector, m3));
									// Прибавляем произведения приведения к вектору c2
									c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(reducerVector, m7));
									// Прибавляем произведения приведения к вектору c3
									c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(reducerVector, m11));
									// Прибавляем произведения приведения к вектору c4
									c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(reducerVector, m15));
									// Прибавляем произведения приведения к вектору c5
									c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(reducerVector, m19));
									// Прибавляем произведения приведения к вектору c6
									c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(reducerVector, m23));
									// Прибавляем произведения приведения к вектору c7
									c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(reducerVector, m27));
									// Прибавляем произведения приведения к вектору c8
									c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(reducerVector, m31));
									// Прибавляем произведения приведения к вектору c9
									c9 = _mm256_add_epi64(c9, _mm256_mul_epu32(reducerVector, m35));
								}
							}
							// Вторая пара множителей определяется младшими 58 разрядами
							{
								// Собираем младшие 58 разрядов для второй пары множителей
								const uint64_t packed = ((low[2] + (low[3] << 29)) * paired) & 0x03FFFFFFFFFFFFFFULL;
								// Младший множитель и его обычный перенос
								{
									// Младший множитель приведения занимает 29 разрядов
									const uint64_t reducer = (packed & 0x1FFFFFFF);
									// Рассылаем младший множитель по всем дорожкам
									const __m256i reducerVector = _mm256_set1_epi64x(reducer);
									// Приводим коэффициент 2 по модулю
									low[2] += (reducer * modulus[0]);
									// Приводим коэффициент 3 по модулю
									low[3] += (reducer * modulus[1]);
									// Снимаем старшие 29 разрядов коэффициента 2
									carry = (low[2] >> 29);
									// Переносим старшую часть в коэффициент 3
									low[3] += carry;
									// Прибавляем произведения приведения к вектору c1
									c1 = _mm256_add_epi64(c1, _mm256_mul_epu32(reducerVector, m2));
									// Прибавляем произведения приведения к вектору c2
									c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(reducerVector, m6));
									// Прибавляем произведения приведения к вектору c3
									c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(reducerVector, m10));
									// Прибавляем произведения приведения к вектору c4
									c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(reducerVector, m14));
									// Прибавляем произведения приведения к вектору c5
									c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(reducerVector, m18));
									// Прибавляем произведения приведения к вектору c6
									c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(reducerVector, m22));
									// Прибавляем произведения приведения к вектору c7
									c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(reducerVector, m26));
									// Прибавляем произведения приведения к вектору c8
									c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(reducerVector, m30));
									// Прибавляем произведения приведения к вектору c9
									c9 = _mm256_add_epi64(c9, _mm256_mul_epu32(reducerVector, m34));
								}
								// Старший множитель уже известен независимо от предыдущего переноса
								{
									// Старший множитель приведения занимает старшие 29 разрядов
									const uint64_t reducer = (packed >> 29);
									// Рассылаем старший множитель по всем дорожкам
									const __m256i reducerVector = _mm256_set1_epi64x(reducer);
									// Приводим коэффициент 3 по модулю
									low[3] += (reducer * modulus[0]);
									// Снимаем старшие 29 разрядов коэффициента 3
									carry = (low[3] >> 29);
									// Прибавляем произведения приведения к вектору c1
									c1 = _mm256_add_epi64(c1, _mm256_mul_epu32(reducerVector, m1));
									// Прибавляем произведения приведения к вектору c2
									c2 = _mm256_add_epi64(c2, _mm256_mul_epu32(reducerVector, m5));
									// Прибавляем произведения приведения к вектору c3
									c3 = _mm256_add_epi64(c3, _mm256_mul_epu32(reducerVector, m9));
									// Прибавляем произведения приведения к вектору c4
									c4 = _mm256_add_epi64(c4, _mm256_mul_epu32(reducerVector, m13));
									// Прибавляем произведения приведения к вектору c5
									c5 = _mm256_add_epi64(c5, _mm256_mul_epu32(reducerVector, m17));
									// Прибавляем произведения приведения к вектору c6
									c6 = _mm256_add_epi64(c6, _mm256_mul_epu32(reducerVector, m21));
									// Прибавляем произведения приведения к вектору c7
									c7 = _mm256_add_epi64(c7, _mm256_mul_epu32(reducerVector, m25));
									// Прибавляем произведения приведения к вектору c8
									c8 = _mm256_add_epi64(c8, _mm256_mul_epu32(reducerVector, m29));
									// Прибавляем произведения приведения к вектору c9
									c9 = _mm256_add_epi64(c9, _mm256_mul_epu32(reducerVector, m33));
								}
							}
							// Отбрасываем четыре нулевых младших коэффициента
							_mm256_storeu_si256(reinterpret_cast <__m256i *> (low), c1);
							// Возвращаем перенос в младший коэффициент
							low[0] += carry;
							// Сдвигаем накопитель c2 на место c1
							c1 = c2;
							// Сдвигаем накопитель c3 на место c2
							c2 = c3;
							// Сдвигаем накопитель c4 на место c3
							c3 = c4;
							// Сдвигаем накопитель c5 на место c4
							c4 = c5;
							// Сдвигаем накопитель c6 на место c5
							c5 = c6;
							// Сдвигаем накопитель c7 на место c6
							c6 = c7;
							// Сдвигаем накопитель c8 на место c7
							c7 = c8;
							// Сдвигаем накопитель c9 на место c8
							c8 = c9;
							// Читаем следующую четвёрку коэффициентов произведения
							c9 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (product + i + 40));
						}
						// Собираем четыре младших коэффициента перед переносами
						__m256i c0 = _mm256_loadu_si256(reinterpret_cast <const __m256i *> (low));
						// Проводим переносы на один коэффициент: снимаем накопленные старшие части
						{
							// Перенос из предыдущего вектора начинается с нуля
							__m256i previous = zero;
							{
								// Сдвигаем старшие разряды вектора c0 в соседнюю дорожку
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c0, 29), 0x93);
								// Складываем младшие разряды c0 с переносом соседнего вектора
								c0 = _mm256_add_epi64(_mm256_and_si256(c0, mask), _mm256_blend_epi32(high, previous, 3));
								// Запоминаем старшие разряды для следующего вектора
								previous = high;
							}
							{
								// Сдвигаем старшие разряды вектора c1 в соседнюю дорожку
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c1, 29), 0x93);
								// Складываем младшие разряды c1 с переносом соседнего вектора
								c1 = _mm256_add_epi64(_mm256_and_si256(c1, mask), _mm256_blend_epi32(high, previous, 3));
								// Запоминаем старшие разряды для следующего вектора
								previous = high;
							}
							{
								// Сдвигаем старшие разряды вектора c2 в соседнюю дорожку
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c2, 29), 0x93);
								// Складываем младшие разряды c2 с переносом соседнего вектора
								c2 = _mm256_add_epi64(_mm256_and_si256(c2, mask), _mm256_blend_epi32(high, previous, 3));
								// Запоминаем старшие разряды для следующего вектора
								previous = high;
							}
							{
								// Сдвигаем старшие разряды вектора c3 в соседнюю дорожку
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c3, 29), 0x93);
								// Складываем младшие разряды c3 с переносом соседнего вектора
								c3 = _mm256_add_epi64(_mm256_and_si256(c3, mask), _mm256_blend_epi32(high, previous, 3));
								// Запоминаем старшие разряды для следующего вектора
								previous = high;
							}
							{
								// Сдвигаем старшие разряды вектора c4 в соседнюю дорожку
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c4, 29), 0x93);
								// Складываем младшие разряды c4 с переносом соседнего вектора
								c4 = _mm256_add_epi64(_mm256_and_si256(c4, mask), _mm256_blend_epi32(high, previous, 3));
								// Запоминаем старшие разряды для следующего вектора
								previous = high;
							}
							{
								// Сдвигаем старшие разряды вектора c5 в соседнюю дорожку
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c5, 29), 0x93);
								// Складываем младшие разряды c5 с переносом соседнего вектора
								c5 = _mm256_add_epi64(_mm256_and_si256(c5, mask), _mm256_blend_epi32(high, previous, 3));
								// Запоминаем старшие разряды для следующего вектора
								previous = high;
							}
							{
								// Сдвигаем старшие разряды вектора c6 в соседнюю дорожку
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c6, 29), 0x93);
								// Складываем младшие разряды c6 с переносом соседнего вектора
								c6 = _mm256_add_epi64(_mm256_and_si256(c6, mask), _mm256_blend_epi32(high, previous, 3));
								// Запоминаем старшие разряды для следующего вектора
								previous = high;
							}
							{
								// Сдвигаем старшие разряды вектора c7 в соседнюю дорожку
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c7, 29), 0x93);
								// Складываем младшие разряды c7 с переносом соседнего вектора
								c7 = _mm256_add_epi64(_mm256_and_si256(c7, mask), _mm256_blend_epi32(high, previous, 3));
								// Запоминаем старшие разряды для следующего вектора
								previous = high;
							}
							{
								// Сдвигаем старшие разряды вектора c8 в соседнюю дорожку
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c8, 29), 0x93);
								// Складываем младшие разряды c8 с переносом соседнего вектора
								c8 = _mm256_add_epi64(_mm256_and_si256(c8, mask), _mm256_blend_epi32(high, previous, 3));
							}
						}
						// Второй перенос сразу записывает готовую четвёрку для следующей свёртки
						// Входы уже прочитаны, поэтому совпадение result и value по-прежнему допустимо
						{
							// Перенос из предыдущего вектора начинается с нуля
							__m256i previous = zero;
							{
								// Сдвигаем старшие разряды вектора c0 в соседнюю дорожку
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c0, 29), 0x93);
								// Складываем младшие разряды c0 с переносом соседнего вектора
								c0 = _mm256_add_epi64(_mm256_and_si256(c0, mask), _mm256_blend_epi32(high, previous, 3));
								// Записываем готовые коэффициенты 0…3 в итог
								_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 0), c0);
								// Запоминаем старшие разряды для следующего вектора
								previous = high;
							}
							{
								// Сдвигаем старшие разряды вектора c1 в соседнюю дорожку
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c1, 29), 0x93);
								// Складываем младшие разряды c1 с переносом соседнего вектора
								c1 = _mm256_add_epi64(_mm256_and_si256(c1, mask), _mm256_blend_epi32(high, previous, 3));
								// Записываем готовые коэффициенты 4…7 в итог
								_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 4), c1);
								// Запоминаем старшие разряды для следующего вектора
								previous = high;
							}
							{
								// Сдвигаем старшие разряды вектора c2 в соседнюю дорожку
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c2, 29), 0x93);
								// Складываем младшие разряды c2 с переносом соседнего вектора
								c2 = _mm256_add_epi64(_mm256_and_si256(c2, mask), _mm256_blend_epi32(high, previous, 3));
								// Записываем готовые коэффициенты 8…11 в итог
								_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 8), c2);
								// Запоминаем старшие разряды для следующего вектора
								previous = high;
							}
							{
								// Сдвигаем старшие разряды вектора c3 в соседнюю дорожку
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c3, 29), 0x93);
								// Складываем младшие разряды c3 с переносом соседнего вектора
								c3 = _mm256_add_epi64(_mm256_and_si256(c3, mask), _mm256_blend_epi32(high, previous, 3));
								// Записываем готовые коэффициенты 12…15 в итог
								_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 12), c3);
								// Запоминаем старшие разряды для следующего вектора
								previous = high;
							}
							{
								// Сдвигаем старшие разряды вектора c4 в соседнюю дорожку
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c4, 29), 0x93);
								// Складываем младшие разряды c4 с переносом соседнего вектора
								c4 = _mm256_add_epi64(_mm256_and_si256(c4, mask), _mm256_blend_epi32(high, previous, 3));
								// Записываем готовые коэффициенты 16…19 в итог
								_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 16), c4);
								// Запоминаем старшие разряды для следующего вектора
								previous = high;
							}
							{
								// Сдвигаем старшие разряды вектора c5 в соседнюю дорожку
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c5, 29), 0x93);
								// Складываем младшие разряды c5 с переносом соседнего вектора
								c5 = _mm256_add_epi64(_mm256_and_si256(c5, mask), _mm256_blend_epi32(high, previous, 3));
								// Записываем готовые коэффициенты 20…23 в итог
								_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 20), c5);
								// Запоминаем старшие разряды для следующего вектора
								previous = high;
							}
							{
								// Сдвигаем старшие разряды вектора c6 в соседнюю дорожку
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c6, 29), 0x93);
								// Складываем младшие разряды c6 с переносом соседнего вектора
								c6 = _mm256_add_epi64(_mm256_and_si256(c6, mask), _mm256_blend_epi32(high, previous, 3));
								// Записываем готовые коэффициенты 24…27 в итог
								_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 24), c6);
								// Запоминаем старшие разряды для следующего вектора
								previous = high;
							}
							{
								// Сдвигаем старшие разряды вектора c7 в соседнюю дорожку
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c7, 29), 0x93);
								// Складываем младшие разряды c7 с переносом соседнего вектора
								c7 = _mm256_add_epi64(_mm256_and_si256(c7, mask), _mm256_blend_epi32(high, previous, 3));
								// Записываем готовые коэффициенты 28…31 в итог
								_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 28), c7);
								// Запоминаем старшие разряды для следующего вектора
								previous = high;
							}
							{
								// Сдвигаем старшие разряды вектора c8 в соседнюю дорожку
								const __m256i high = _mm256_permute4x64_epi64(_mm256_srli_epi64(c8, 29), 0x93);
								// Складываем младшие разряды c8 с переносом соседнего вектора
								c8 = _mm256_add_epi64(_mm256_and_si256(c8, mask), _mm256_blend_epi32(high, previous, 3));
								// Записываем готовые коэффициенты 32…35 в итог
								_mm256_storeu_si256(reinterpret_cast <__m256i *> (result + 32), c8);
							}
						}
						/**
						 * Последние четыре коэффициента служат нулевым дополнением для векторных загрузок
						 */
						for(size_t i = 36; i < 40; i++)
							// Зануляем слова нулевого дополнения итога
							result[i] = 0;
						// Следующий квадрат берёт только что записанный итог
						value = result;
					}
					// Завершаем работу с верхними половинами векторных регистров
					_mm256_zeroupper();
				}
				/**
				 * @brief Функция перевода шестнадцати слов в коэффициенты по 29 разрядов
				 *
				 * @param value  число в шестнадцати словах
				 * @param result место для 40 коэффициентов с нулевым дополнением
				 *
				 */
				static void encode29Avx2(const uint64_t * value, uint64_t * result) noexcept {
					/**
					 * Разбиваем число по открытым положениям разрядов
					 */
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
					/**
					 * Нулевое дополнение для загрузок в конце числа
					 */
					for(size_t i = 36; i < 40; i++)
						// Зануляем четыре слова нулевого дополнения
						result[i] = 0;
				}
				/**
				 * @brief Функция выбора степени полным перебором таблицы
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
					// Накапливаем отобранные коэффициенты блока 1 в векторе c1
					__m256i c1 = _mm256_setzero_si256();
					// Накапливаем отобранные коэффициенты блока 2 в векторе c2
					__m256i c2 = _mm256_setzero_si256();
					// Накапливаем отобранные коэффициенты блока 3 в векторе c3
					__m256i c3 = _mm256_setzero_si256();
					// Накапливаем отобранные коэффициенты блока 4 в векторе c4
					__m256i c4 = _mm256_setzero_si256();
					// Накапливаем отобранные коэффициенты блока 5 в векторе c5
					__m256i c5 = _mm256_setzero_si256();
					// Накапливаем отобранные коэффициенты блока 6 в векторе c6
					__m256i c6 = _mm256_setzero_si256();
					// Накапливаем отобранные коэффициенты блока 7 в векторе c7
					__m256i c7 = _mm256_setzero_si256();
					// Накапливаем отобранные коэффициенты блока 8 в векторе c8
					__m256i c8 = _mm256_setzero_si256();
					/**
					 * Порядок чтения всех записей одинаков при любом индексе
					 */
					for(size_t i = 0; i < 16; i++){
						// Одна маска обслуживает оба номера во всех блоках
						const __m256i mask = _mm256_cmpeq_epi32(wanted, positions);
						// Вносим замаскированную запись в накопитель блока 0
						c0 = _mm256_or_si256(c0, _mm256_and_si256(mask, _mm256_load_si256(reinterpret_cast <const __m256i *> (table[0]) + i)));
						// Вносим замаскированную запись в накопитель блока 1
						c1 = _mm256_or_si256(c1, _mm256_and_si256(mask, _mm256_load_si256(reinterpret_cast <const __m256i *> (table[1]) + i)));
						// Вносим замаскированную запись в накопитель блока 2
						c2 = _mm256_or_si256(c2, _mm256_and_si256(mask, _mm256_load_si256(reinterpret_cast <const __m256i *> (table[2]) + i)));
						// Вносим замаскированную запись в накопитель блока 3
						c3 = _mm256_or_si256(c3, _mm256_and_si256(mask, _mm256_load_si256(reinterpret_cast <const __m256i *> (table[3]) + i)));
						// Вносим замаскированную запись в накопитель блока 4
						c4 = _mm256_or_si256(c4, _mm256_and_si256(mask, _mm256_load_si256(reinterpret_cast <const __m256i *> (table[4]) + i)));
						// Вносим замаскированную запись в накопитель блока 5
						c5 = _mm256_or_si256(c5, _mm256_and_si256(mask, _mm256_load_si256(reinterpret_cast <const __m256i *> (table[5]) + i)));
						// Вносим замаскированную запись в накопитель блока 6
						c6 = _mm256_or_si256(c6, _mm256_and_si256(mask, _mm256_load_si256(reinterpret_cast <const __m256i *> (table[6]) + i)));
						// Вносим замаскированную запись в накопитель блока 7
						c7 = _mm256_or_si256(c7, _mm256_and_si256(mask, _mm256_load_si256(reinterpret_cast <const __m256i *> (table[7]) + i)));
						// Вносим замаскированную запись в накопитель блока 8
						c8 = _mm256_or_si256(c8, _mm256_and_si256(mask, _mm256_load_si256(reinterpret_cast <const __m256i *> (table[8]) + i)));
						// Переходим к следующей открытой паре номеров
						positions = _mm256_add_epi32(positions, step);
					}
					// Объединяем половины и расширяем четыре коэффициента блока 0
					{
						// Объединяем половины накопителя c0
						const __m128i half = _mm_or_si128(_mm256_castsi256_si128(c0), _mm256_extracti128_si256(c0, 1));
						// Расширяем и записываем коэффициенты блока 0
						_mm256_store_si256(reinterpret_cast <__m256i *> (result + 0), _mm256_cvtepu32_epi64(half));
					}
					// Объединяем половины и расширяем четыре коэффициента блока 1
					{
						// Объединяем половины накопителя c1
						const __m128i half = _mm_or_si128(_mm256_castsi256_si128(c1), _mm256_extracti128_si256(c1, 1));
						// Расширяем и записываем коэффициенты блока 1
						_mm256_store_si256(reinterpret_cast <__m256i *> (result + 4), _mm256_cvtepu32_epi64(half));
					}
					// Объединяем половины и расширяем четыре коэффициента блока 2
					{
						// Объединяем половины накопителя c2
						const __m128i half = _mm_or_si128(_mm256_castsi256_si128(c2), _mm256_extracti128_si256(c2, 1));
						// Расширяем и записываем коэффициенты блока 2
						_mm256_store_si256(reinterpret_cast <__m256i *> (result + 8), _mm256_cvtepu32_epi64(half));
					}
					// Объединяем половины и расширяем четыре коэффициента блока 3
					{
						// Объединяем половины накопителя c3
						const __m128i half = _mm_or_si128(_mm256_castsi256_si128(c3), _mm256_extracti128_si256(c3, 1));
						// Расширяем и записываем коэффициенты блока 3
						_mm256_store_si256(reinterpret_cast <__m256i *> (result + 12), _mm256_cvtepu32_epi64(half));
					}
					// Объединяем половины и расширяем четыре коэффициента блока 4
					{
						// Объединяем половины накопителя c4
						const __m128i half = _mm_or_si128(_mm256_castsi256_si128(c4), _mm256_extracti128_si256(c4, 1));
						// Расширяем и записываем коэффициенты блока 4
						_mm256_store_si256(reinterpret_cast <__m256i *> (result + 16), _mm256_cvtepu32_epi64(half));
					}
					// Объединяем половины и расширяем четыре коэффициента блока 5
					{
						// Объединяем половины накопителя c5
						const __m128i half = _mm_or_si128(_mm256_castsi256_si128(c5), _mm256_extracti128_si256(c5, 1));
						// Расширяем и записываем коэффициенты блока 5
						_mm256_store_si256(reinterpret_cast <__m256i *> (result + 20), _mm256_cvtepu32_epi64(half));
					}
					// Объединяем половины и расширяем четыре коэффициента блока 6
					{
						// Объединяем половины накопителя c6
						const __m128i half = _mm_or_si128(_mm256_castsi256_si128(c6), _mm256_extracti128_si256(c6, 1));
						// Расширяем и записываем коэффициенты блока 6
						_mm256_store_si256(reinterpret_cast <__m256i *> (result + 24), _mm256_cvtepu32_epi64(half));
					}
					// Объединяем половины и расширяем четыре коэффициента блока 7
					{
						// Объединяем половины накопителя c7
						const __m128i half = _mm_or_si128(_mm256_castsi256_si128(c7), _mm256_extracti128_si256(c7, 1));
						// Расширяем и записываем коэффициенты блока 7
						_mm256_store_si256(reinterpret_cast <__m256i *> (result + 28), _mm256_cvtepu32_epi64(half));
					}
					// Объединяем половины и расширяем четыре коэффициента блока 8
					{
						// Объединяем половины накопителя c8
						const __m128i half = _mm_or_si128(_mm256_castsi256_si128(c8), _mm256_extracti128_si256(c8, 1));
						// Расширяем и записываем коэффициенты блока 8
						_mm256_store_si256(reinterpret_cast <__m256i *> (result + 32), _mm256_cvtepu32_epi64(half));
					}
					/**
					 * Нулевое дополнение выбранного числа
					 */
					for(size_t i = 36; i < 40; i++)
						// Зануляем четыре слова нулевого дополнения
						result[i] = 0;
					// Завершаем работу с верхними половинами векторных регистров
					_mm256_zeroupper();
				}
				/**
				 * @brief Функция чтения окна показателя по открытому положению
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
				 * @brief Функция степени с фиксированным перебором 1024 разрядов на AVX2
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
					// Размещаем поправку 2^80 по коэффициенту с индексом 2
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
					/**
					 * Чётные записи получаем квадратом, нечётные - умножением на основание
					 */
					for(size_t i = 2; i < 32; i++){
						// Если запись чётная
						if((i % 2) == 0)
							// Возводим половинную запись в квадрат
							square29Avx2(scratch, table[i], table[i / 2], field, inverse, 1);
						// Иначе умножаем предыдущую запись на основание
						else multiply29Avx2(scratch, table[i], table[i - 1], table[1], field, inverse);
					}
					/**
					 * Укладываем коэффициенты по четыре в строку каждого блока
					 */
					for(size_t k = 0; k < 9; k++){
						/**
						 * Перебираем степени окна
						 */
						for(size_t i = 0; i < 32; i++){
							/**
							 * Коэффициенты после переноса помещаются в 32 разряда
							 */
							for(size_t j = 0; j < 4; j++)
								// Укладываем коэффициент блока в 32 разряда строки
								columns[k][i][j] = static_cast <uint32_t> (table[i][(k * 4) + j]);
						}
					}
					// Начинаем с записи первого окна, включая нулевую степень
					choose29Avx2(columns, window29Avx2(exponent, 1020, 4), accumulator);
					/**
					 * Перебираем оставшиеся окна по открытому счётчику
					 */
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
					/**
					 * Обнуляем место для перевода в обычные слова
					 */
					for(size_t i = 0; i < 17; i++)
						// Обнуляем место под семнадцать слов итога
						result[i] = 0;
					// Перенос при окончательной нормализации коэффициентов
					uint64_t carry = 0;
					/**
					 * Собираем число без избыточности в семнадцать слов
					 */
					for(size_t i = 0; i < 36; i++){
						// Нормализованный коэффициент и перенос к следующему
						const uint64_t item = (accumulator[i] + carry), word = (item & 0x1FFFFFFF);
						// Снимаем старшие 29 разрядов нормализованного коэффициента
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
