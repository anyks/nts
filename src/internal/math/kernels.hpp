/**
 * @file kernels.hpp
 * @date 2026-09-21
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
 * @brief Заголовочный файл внутреннего модуля ядер арифметики по модулю известного
 *        числа слов
 *
 * @note Модуль внутренний: он лежит в src и наружному договору библиотеки не
 *       принадлежит. Ядра встраиваются и в арифметику чисел (math/number.cpp), и в
 *       формулы точек кривой (curve/curve.cpp): вызов через границу модуля стоил на
 *       умножении 5 нс из 16 на M4 и 12 из 104 на Эльбрусе, на сложении - треть на M4
 *       и половину на Astra и Эльбрусе, а формула удвоения зовёт восемь умножений и
 *       девять сложений. Замер 21.09.2026
 *
 * @note Число слов заложено в тело шаблонами намеренно: собиратель разворачивает
 *       циклы и держит накопители в регистрах. Пути заведены на четыре и восемь слов -
 *       число слов кривых протокола, прочие ширины идут общим путём в number.cpp
 *
 * @note Сложение, вычитание, условное вычитание модуля и Монтгомери читают входы в
 *       регистры до первой записи и пишут итог одной записью в конце: места входов и
 *       итога вправе совпадать, а при возможном наложении указателей собиратель обязан
 *       ставить всякую загрузку после предыдущей записи, и lcc теряет на этом
 *       параллелизм широкой команды. Замер 21.09.2026 по библиотеке (bench и щуп):
 *       Эльбрус сложение 41 → 33 нс, удвоение точки 1 430 → 1 325; shrink с итогом
 *       отдельным доводом - умножение 103 → 96. Та же запись у полного произведения и
 *       квадрата (накопитель в своём массиве с переносом в итог) пробована и НЕ взята:
 *       у lcc умножение 103 → 126 нс и подпись −10 %, у gcc 12 подпись 16,8 → 12,6
 *       тыс./с из-за срыва встраивания, у clang без разницы при принудительном
 *       встраивании. Свёртка foldminus с копией младшей половины - без выигрыша нигде
 *
 * @note Все ядра встраиваются принудительно (__ANTS_INLINE__): собиратели переставали
 *       встраивать большие тела в формулы точки, и вызов возвращался. Замер 21.09.2026,
 *       подпись ГОСТ по библиотеке: M4 (clang) 62,9 → 70,7 тыс./с, Astra (gcc 12)
 *       16,8 → 18,0, FreeBSD (clang 19) 24,2 → 25,0; вместе с чтением входов наперёд
 *       M4 71,5…73,0, Astra 17,6…18,3, FreeBSD 24,8…25,4
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_MATH_KERNELS__
#define __ANTS_MATH_KERNELS__

/**
 * Стандартные заголовочные файлы
 */
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>
#include <math/number.hpp>
#include <math/wide.hpp>

/**
 * @brief Основное пространство имён
 *
 */
namespace nts {
	/**
	 * @brief Пространство имён арифметики
	 *
	 */
	namespace math {
		/**
		 * @brief Пространство имён ядер арифметики известного числа слов
		 *
		 */
		namespace kernel {
			/**
			 * @brief Метод умножения Монтгомери для модуля известного числа слов
			 *
			 * @param first   первый сомножитель
			 * @param second  второй сомножитель
			 * @param modulus модуль поля
			 * @param factor  множитель приведения по модулю
			 * @param result  место, в которое помещается произведение
			 *
			 * @return        старшее слово переноса произведения
			 *
			 */
			template <size_t WORDS>
			static __ANTS_INLINE__ uint64_t montgomery(const uint64_t * first, const uint64_t * second, const uint64_t * modulus, const uint64_t factor, uint64_t * result) noexcept {
				// Слова накапливаемого произведения
				uint64_t buffer[WORDS + 1] = {};
				// Слова сомножителей и модуля, снятые в регистры до первой записи
				uint64_t a[WORDS], b[WORDS], m[WORDS];
				/**
				 * Выполняем перенос слов сомножителей и модуля в регистры
				 */
				for(size_t i = 0; i < WORDS; i++){
					// Переносим очередное слово первого сомножителя
					a[i] = first[i];
					// Переносим очередное слово второго сомножителя
					b[i] = second[i];
					// Переносим очередное слово модуля
					m[i] = modulus[i];
				}
				/**
				 * Выполняем перебор слов второго сомножителя от младшего к старшему
				 */
				for(size_t i = 0; i < WORDS; i++){
					// Получаем очередное слово второго сомножителя
					const uint64_t word = b[i];
					// Перенос из очередного слова накапливаемого произведения
					uint64_t carry = 0;
					/**
					 * Выполняем умножение первого сомножителя на очередное слово второго
					 */
					for(size_t j = 0; j < WORDS; j++){
						// Складываем накопленное слово с произведением слов и переносом
						const wide_t item = (static_cast <wide_t> (a[j]) * word + buffer[j] + carry);
						// Записываем младшую половину полученного значения
						buffer[j] = static_cast <uint64_t> (item);
						// Запоминаем перенос в следующее слово
						carry = static_cast <uint64_t> (item >> 64);
					}
					// Складываем старшее слово произведения с переносом
					const wide_t item = (static_cast <wide_t> (buffer[WORDS]) + carry);
					// Записываем младшую половину полученного значения
					buffer[WORDS] = static_cast <uint64_t> (item);
					// Запоминаем перенос в дополнительное слово произведения
					const uint64_t extra = static_cast <uint64_t> (item >> 64);
					/**
					 * Выработанный множитель обращает младшее слово накопленного произведения
					 * в ноль: тем приведение по модулю и сводится к сдвигу на слово
					 */
					const uint64_t reducer = (buffer[0] * factor);
					// Складываем младшее слово произведения с произведением множителя на модуль
					const wide_t value = (static_cast <wide_t> (reducer) * m[0] + buffer[0]);
					// Запоминаем перенос из младшего слова произведения
					carry = static_cast <uint64_t> (value >> 64);
					/**
					 * Выполняем приведение произведения по модулю со сдвигом на слово
					 */
					for(size_t j = 1; j < WORDS; j++){
						// Складываем накопленное слово с произведением множителя на модуль
						const wide_t step = (static_cast <wide_t> (reducer) * m[j] + buffer[j] + carry);
						// Записываем младшую половину полученного значения со сдвигом на слово
						buffer[j - 1] = static_cast <uint64_t> (step);
						// Запоминаем перенос в следующее слово
						carry = static_cast <uint64_t> (step >> 64);
					}
					// Складываем старшее слово произведения с переносом
					const wide_t last = (static_cast <wide_t> (buffer[WORDS]) + carry);
					// Записываем младшую половину полученного значения со сдвигом на слово
					buffer[WORDS - 1] = static_cast <uint64_t> (last);
					// Складываем дополнительное слово произведения с переносом
					buffer[WORDS] = static_cast <uint64_t> (extra + (last >> 64));
				}
				/**
				 * Выполняем перебор слов накопленного произведения
				 */
				for(size_t i = 0; i < WORDS; i++)
					// Записываем очередное слово произведения
					result[i] = buffer[i];
				/**
				 * Накопитель не затирается намеренно: умножение зовётся на каждый шаг
				 * арифметики кривой, и затирание здесь стоило двадцатую часть времени;
				 * содержимое накопителя перезаписывается следующим же умножением
				 */
				return buffer[WORDS];
			}
			/**
			 * @brief Метод возведения в квадрат Монтгомери по простому числу кривой P-256
			 *
			 * @details Полное произведение считается сперва целиком: у квадрата всякая пара
			 *          разных слов встречается дважды, и шесть удвоенных произведений вместе с
			 *          четырьмя квадратами слов заменяют шестнадцать произведений. Приведение
			 *          затем идёт словами модуля, как у умножения: множитель приведения есть само
			 *          младшее слово, третье слово модуля не умножается вовсе
			 *
			 * @param value  возводимое число
			 * @param result место, в которое помещается квадрат
			 *
			 * @return       старшее слово переноса квадрата
			 *
			 */
			static __ANTS_INLINE__ uint64_t nist256square(const uint64_t * value, uint64_t * result) noexcept {
				// Слова возводимого числа
				const uint64_t a0 = value[0], a1 = value[1], a2 = value[2], a3 = value[3];
				// Полное произведение в восемь слов
				uint64_t buffer[9] = {};
				// Перенос между словами
				uint64_t carry = 0;
				/**
				 * Выполняем накопление произведений разных слов: a0·a1, a0·a2, a0·a3, a1·a2, a1·a3, a2·a3
				 */
				wide_t item = (static_cast <wide_t> (a0) * a1);
				buffer[1] = static_cast <uint64_t> (item);
				carry = static_cast <uint64_t> (item >> 64);
				item = (static_cast <wide_t> (a0) * a2 + carry);
				buffer[2] = static_cast <uint64_t> (item);
				carry = static_cast <uint64_t> (item >> 64);
				item = (static_cast <wide_t> (a0) * a3 + carry);
				buffer[3] = static_cast <uint64_t> (item);
				buffer[4] = static_cast <uint64_t> (item >> 64);
				item = (static_cast <wide_t> (a1) * a2 + buffer[3]);
				buffer[3] = static_cast <uint64_t> (item);
				carry = static_cast <uint64_t> (item >> 64);
				item = (static_cast <wide_t> (a1) * a3 + buffer[4] + carry);
				buffer[4] = static_cast <uint64_t> (item);
				buffer[5] = static_cast <uint64_t> (item >> 64);
				item = (static_cast <wide_t> (a2) * a3 + buffer[5]);
				buffer[5] = static_cast <uint64_t> (item);
				buffer[6] = static_cast <uint64_t> (item >> 64);
				/**
				 * Удваиваем накопленное: старший разряд седьмого слова уходит в восьмое
				 */
				buffer[7] = (buffer[6] >> 63);
				buffer[6] = ((buffer[6] << 1) | (buffer[5] >> 63));
				buffer[5] = ((buffer[5] << 1) | (buffer[4] >> 63));
				buffer[4] = ((buffer[4] << 1) | (buffer[3] >> 63));
				buffer[3] = ((buffer[3] << 1) | (buffer[2] >> 63));
				buffer[2] = ((buffer[2] << 1) | (buffer[1] >> 63));
				buffer[1] = (buffer[1] << 1);
				/**
				 * Прибавляем квадраты слов по диагонали
				 */
				item = (static_cast <wide_t> (a0) * a0);
				buffer[0] = static_cast <uint64_t> (item);
				carry = nts::math::adc(buffer[1], static_cast <uint64_t> (item >> 64), 0, buffer[1]);
				item = (static_cast <wide_t> (a1) * a1);
				carry = nts::math::adc(buffer[2], static_cast <uint64_t> (item), carry, buffer[2]);
				carry = nts::math::adc(buffer[3], static_cast <uint64_t> (item >> 64), carry, buffer[3]);
				item = (static_cast <wide_t> (a2) * a2);
				carry = nts::math::adc(buffer[4], static_cast <uint64_t> (item), carry, buffer[4]);
				carry = nts::math::adc(buffer[5], static_cast <uint64_t> (item >> 64), carry, buffer[5]);
				item = (static_cast <wide_t> (a3) * a3);
				carry = nts::math::adc(buffer[6], static_cast <uint64_t> (item), carry, buffer[6]);
				carry = nts::math::adc(buffer[7], static_cast <uint64_t> (item >> 64), carry, buffer[7]);
				/**
				 * Выполняем приведение Монтгомери по четырём словам: на всяком шаге младшее
				 * слово обращается в ноль прибавлением произведения множителя на модуль
				 */
				for(size_t i = 0; i < 4; i++){
					// Множитель приведения есть само младшее слово
					const uint64_t reducer = buffer[i];
					// Первое слово модуля из всех единиц: произведение с накопителем даёт перенос в размере множителя
					carry = reducer;
					// Второе слово модуля 2^32 - 1
					item = (static_cast <wide_t> (reducer) * 0xFFFFFFFFULL + buffer[i + 1] + carry);
					buffer[i + 1] = static_cast <uint64_t> (item);
					carry = static_cast <uint64_t> (item >> 64);
					// Третье слово модуля нулевое
					item = (static_cast <wide_t> (buffer[i + 2]) + carry);
					buffer[i + 2] = static_cast <uint64_t> (item);
					carry = static_cast <uint64_t> (item >> 64);
					// Четвёртое слово модуля 2^64 - 2^32 + 1
					item = (static_cast <wide_t> (reducer) * 0xFFFFFFFF00000001ULL + buffer[i + 3] + carry);
					buffer[i + 3] = static_cast <uint64_t> (item);
					carry = static_cast <uint64_t> (item >> 64);
					// Проносим перенос по старшим словам
					for(size_t j = i + 4; j < 9; j++){
						item = (static_cast <wide_t> (buffer[j]) + carry);
						buffer[j] = static_cast <uint64_t> (item);
						carry = static_cast <uint64_t> (item >> 64);
					}
				}
				/**
				 * Выполняем перебор слов приведённого квадрата
				 */
				for(size_t i = 0; i < 4; i++)
					// Записываем очередное слово квадрата
					result[i] = buffer[i + 4];
				// Накопитель не затирается по той же причине, что и у общего умножения
				return buffer[8];
			}
			/**
			 * @brief Метод умножения Монтгомери по простому числу кривой P-256
			 *
			 * @param first  первый сомножитель
			 * @param second второй сомножитель
			 * @param result место, в которое помещается произведение
			 *
			 * @return       старшее слово переноса произведения
			 *
			 */
			static __ANTS_INLINE__ uint64_t nist256(const uint64_t * first, const uint64_t * second, uint64_t * result) noexcept {
				/**
				 * Простое число кривой P-256 в словах, от младшего к старшему, есть
				 * (2^64 - 1, 2^32 - 1, 0, 2^64 - 2^32 + 1), а обратное к его младшему
				 * слову со сменой знака равно единице. Оттого множитель приведения есть
				 * само младшее слово накопителя, произведение множителя на младшее слово
				 * модуля вместе с накопителем даёт ровно перенос в размере множителя,
				 * а третье слово модуля не умножается вовсе: на шаг уходит два умножения
				 * приведения вместо четырёх и ни одного умножения на множитель
				 */
				uint64_t buffer[5] = {};
				// Слова сомножителей, снятые в регистры до первой записи
				uint64_t a[4], b[4];
				/**
				 * Выполняем перенос слов сомножителей в регистры
				 */
				for(size_t i = 0; i < 4; i++){
					// Переносим очередное слово первого сомножителя
					a[i] = first[i];
					// Переносим очередное слово второго сомножителя
					b[i] = second[i];
				}
				/**
				 * Выполняем перебор слов второго сомножителя от младшего к старшему
				 */
				for(size_t i = 0; i < 4; i++){
					// Получаем очередное слово второго сомножителя
					const uint64_t word = b[i];
					// Перенос из очередного слова накапливаемого произведения
					uint64_t carry = 0;
					/**
					 * Выполняем умножение первого сомножителя на очередное слово второго
					 */
					for(size_t j = 0; j < 4; j++){
						// Складываем накопленное слово с произведением слов и переносом
						const wide_t item = (static_cast <wide_t> (a[j]) * word + buffer[j] + carry);
						// Записываем младшую половину полученного значения
						buffer[j] = static_cast <uint64_t> (item);
						// Запоминаем перенос в следующее слово
						carry = static_cast <uint64_t> (item >> 64);
					}
					// Складываем старшее слово произведения с переносом
					const wide_t item = (static_cast <wide_t> (buffer[4]) + carry);
					// Записываем младшую половину полученного значения
					buffer[4] = static_cast <uint64_t> (item);
					// Запоминаем перенос в дополнительное слово произведения
					const uint64_t extra = static_cast <uint64_t> (item >> 64);
					// Множитель приведения есть само младшее слово накопителя
					const uint64_t reducer = buffer[0];
					// Произведение множителя на младшее слово модуля с накопителем даёт перенос в размере множителя
					carry = reducer;
					// Складываем второе слово накопителя с произведением множителя на (2^32 - 1) и переносом
					const wide_t second1 = (static_cast <wide_t> (reducer) * 0xFFFFFFFFULL + buffer[1] + carry);
					// Записываем младшую половину полученного значения со сдвигом на слово
					buffer[0] = static_cast <uint64_t> (second1);
					// Запоминаем перенос в следующее слово
					carry = static_cast <uint64_t> (second1 >> 64);
					// Третье слово модуля нулевое: складываем накопитель лишь с переносом
					const wide_t third = (static_cast <wide_t> (buffer[2]) + carry);
					// Записываем младшую половину полученного значения со сдвигом на слово
					buffer[1] = static_cast <uint64_t> (third);
					// Запоминаем перенос в следующее слово
					carry = static_cast <uint64_t> (third >> 64);
					// Складываем четвёртое слово накопителя с произведением множителя на (2^64 - 2^32 + 1) и переносом
					const wide_t fourth = (static_cast <wide_t> (reducer) * 0xFFFFFFFF00000001ULL + buffer[3] + carry);
					// Записываем младшую половину полученного значения со сдвигом на слово
					buffer[2] = static_cast <uint64_t> (fourth);
					// Запоминаем перенос в следующее слово
					carry = static_cast <uint64_t> (fourth >> 64);
					// Складываем старшее слово произведения с переносом
					const wide_t last = (static_cast <wide_t> (buffer[4]) + carry);
					// Записываем младшую половину полученного значения со сдвигом на слово
					buffer[3] = static_cast <uint64_t> (last);
					// Складываем дополнительное слово произведения с переносом
					buffer[4] = static_cast <uint64_t> (extra + (last >> 64));
				}
				/**
				 * Выполняем перебор слов накопленного произведения
				 */
				for(size_t i = 0; i < 4; i++)
					// Записываем очередное слово произведения
					result[i] = buffer[i];
				// Накопитель не затирается по той же причине, что и у общего умножения
				return buffer[4];
			}
			/**
			 * @brief Метод выбора одного из двух слов наложением маски
			 *
			 * @param mask   маска выбора: все разряды единичны либо все нулевые
			 * @param first  слово, выбираемое при единичной маске
			 * @param second слово, выбираемое при нулевой маске
			 *
			 * @return       выбранное слово
			 *
			 */
			static __ANTS_INLINE__ uint64_t select(const uint64_t mask, const uint64_t first, const uint64_t second) noexcept {
				// Выводим выбранное наложением маски слово
				return (second ^ (mask & (first ^ second)));
			}
			/**
			 * @brief Приведение по модулю после умножения при числе слов, известном собирателю
			 *
			 * @details То же, что lessen, но циклы развёрнуты по WORDS, буфер разности - в WORDS
			 *          слов, и затирается он ровно в WORDS записей. Общий lessen с длиной во время
			 *          выполнения стоил у P-256 больше самого умножения Монтгомери
			 *
			 * @param value   приводимое значение
			 * @param modulus модуль
			 * @param carry   перенос из старшего слова умножения
			 * @param result  место, в которое помещается приведённое значение
			 *
			 * @note Приводимое значение читается в регистры целиком до первой записи итога,
			 *       и итог пишется одной записью в конце: места значения и итога вправе
			 *       совпадать, а собиратель волен не ставить загрузки после записей
			 *
			 */
			template <size_t WORDS>
			static __ANTS_INLINE__ void shrink(const uint64_t * value, const uint64_t * modulus, const uint64_t carry, uint64_t * result) noexcept {
				// Слова приводимого значения, снятые в регистры
				uint64_t item[WORDS];
				// Разность значения с модулем
				uint64_t buffer[WORDS];
				// Заём из очередного слова разности
				uint64_t borrow = 0;
				/**
				 * Выполняем вычитание модуля из значения
				 */
				for(size_t i = 0; i < WORDS; i++){
					// Снимаем очередное слово значения
					item[i] = value[i];
					// Вычитаем очередные слова с заёмом одной командой
					borrow = nts::math::sbb(item[i], modulus[i], borrow, buffer[i]);
				}
				// Модуль вычитается при переносе либо при отсутствии заёма
				const uint64_t mask = (0 - (carry | (borrow ^ 0x01)));
				/**
				 * Выполняем запись итога
				 */
				for(size_t i = 0; i < WORDS; i++)
					// Выбираем очередное слово итога наложением маски
					result[i] = select(mask, buffer[i], item[i]);
				// Буфер не затирается намеренно: его перезаписывает следующее же действие (см. заголовок)
			}
			/**
			 * @brief Метод сложения чисел по модулю известного числа слов
			 *
			 * @param first   первое слагаемое
			 * @param second  второе слагаемое
			 * @param modulus модуль поля
			 * @param result  место, в которое помещается сумма
			 *
			 * @note Число слов заложено в тело постоянной по той же причине, что и у
			 *       умножения: собиратель разворачивает тогда циклы и держит слова в регистрах
			 *
			 */
			template <size_t WORDS>
			static __ANTS_INLINE__ void addition(const uint64_t * first, const uint64_t * second, const uint64_t * modulus, uint64_t * result) noexcept {
				// Сумма слагаемых
				uint64_t sum[WORDS];
				// Перенос из очередного слова суммы
				uint64_t carry = 0;
				/**
				 * Выполняем перебор складываемых слов от младшего к старшему
				 */
				for(size_t i = 0; i < WORDS; i++){
					// Складываем очередные слова с переносом одной командой
					carry = nts::math::adc(first[i], second[i], carry, sum[i]);
				}
				// Итог вычитания модуля из полученной суммы
				uint64_t buffer[WORDS];
				// Заём из старшего слова разности
				uint64_t borrow = 0;
				/**
				 * Выполняем вычитание модуля из полученной суммы
				 */
				for(size_t i = 0; i < WORDS; i++){
					// Вычитаем очередные слова с заёмом одной командой
					borrow = nts::math::sbb(sum[i], modulus[i], borrow, buffer[i]);
				}
				/**
				 * Модуль вычитается, когда сумма его не меньше: либо вычитание прошло без
				 * заёма, либо сумма и без того вышла за разрядность своих слов
				 */
				const uint64_t mask = (0 - (carry | (borrow ^ 0x01)));
				/**
				 * Выполняем запись итога: все чтения слагаемых и модуля уже позади
				 */
				for(size_t i = 0; i < WORDS; i++)
					// Выбираем очередное слово итога наложением маски
					result[i] = select(mask, buffer[i], sum[i]);
				// Буфер не затирается намеренно: его перезаписывает следующее же действие (см. заголовок)
			}
			/**
			 * @brief Метод вычитания чисел по модулю известного числа слов
			 *
			 * @param first   уменьшаемое
			 * @param second  вычитаемое
			 * @param modulus модуль поля
			 * @param result  место, в которое помещается разность
			 *
			 */
			template <size_t WORDS>
			static __ANTS_INLINE__ void subtraction(const uint64_t * first, const uint64_t * second, const uint64_t * modulus, uint64_t * result) noexcept {
				// Разность
				uint64_t difference[WORDS];
				// Заём из очередного слова разности
				uint64_t borrow = 0;
				/**
				 * Выполняем перебор вычитаемых слов от младшего к старшему
				 */
				for(size_t i = 0; i < WORDS; i++){
					// Вычитаем очередные слова с заёмом одной командой
					borrow = nts::math::sbb(first[i], second[i], borrow, difference[i]);
				}
				// Сумма разности с модулем, применяемая при заёме из старшего слова
				uint64_t buffer[WORDS];
				// Перенос из очередного слова суммы
				uint64_t carry = 0;
				/**
				 * Выполняем сложение полученной разности с модулем
				 */
				for(size_t i = 0; i < WORDS; i++){
					// Складываем очередные слова с переносом одной командой
					carry = nts::math::adc(difference[i], modulus[i], carry, buffer[i]);
				}
				/**
				 * Выполняем запись итога: все чтения уменьшаемого, вычитаемого и модуля уже позади
				 */
				for(size_t i = 0; i < WORDS; i++)
					// Выбираем очередное слово итога наложением маски заёма
					result[i] = select(0 - borrow, buffer[i], difference[i]);
				// Буфер не затирается намеренно: его перезаписывает следующее же действие (см. заголовок)
			}
			/**
			 * @brief Метод полного умножения чисел известного числа слов
			 *
			 * @param first  первый сомножитель
			 * @param second второй сомножитель
			 * @param result место, в которое помещается произведение вдвое большего числа слов
			 *
			 */
			template <size_t WORDS>
			static __ANTS_INLINE__ void product(const uint64_t * first, const uint64_t * second, uint64_t * result) noexcept {
				/**
				 * Выполняем обнуление слов произведения
				 */
				for(size_t i = 0; i < (2 * WORDS); i++)
					// Обнуляем очередное слово произведения
					result[i] = 0;
				/**
				 * Выполняем перебор слов второго сомножителя от младшего к старшему
				 */
				for(size_t i = 0; i < WORDS; i++){
					// Получаем очередное слово второго сомножителя
					const uint64_t word = second[i];
					// Перенос в следующее слово произведения
					uint64_t carry = 0;
					/**
					 * Выполняем умножение первого сомножителя на очередное слово второго
					 */
					for(size_t j = 0; j < WORDS; j++){
						// Складываем накопленное слово с произведением слов и переносом
						const wide_t item = (static_cast <wide_t> (first[j]) * word + result[i + j] + carry);
						// Записываем младшую половину полученного значения
						result[i + j] = static_cast <uint64_t> (item);
						// Запоминаем перенос в следующее слово
						carry = static_cast <uint64_t> (item >> 64);
					}
					// Записываем перенос старшим словом строки
					result[i + WORDS] = carry;
				}
			}
			/**
			 * @brief Метод возведения числа известного числа слов в квадрат
			 *
			 * @details Всякая пара разных слов встречается в квадрате дважды: произведения
			 *          разных слов считаются по разу и удваиваются сдвигом, а квадраты слов
			 *          прибавляются по диагонали
			 *
			 * @param value  возводимое число
			 * @param result место, в которое помещается квадрат вдвое большего числа слов
			 *
			 */
			template <size_t WORDS>
			static __ANTS_INLINE__ void squared(const uint64_t * value, uint64_t * result) noexcept {
				/**
				 * Выполняем обнуление слов квадрата
				 */
				for(size_t i = 0; i < (2 * WORDS); i++)
					// Обнуляем очередное слово квадрата
					result[i] = 0;
				/**
				 * Выполняем накопление произведений разных слов
				 */
				for(size_t i = 0; i < WORDS; i++){
					// Перенос в следующее слово квадрата
					uint64_t carry = 0;
					/**
					 * Выполняем умножение очередного слова на все старшие слова
					 */
					for(size_t j = (i + 1); j < WORDS; j++){
						// Складываем накопленное слово с произведением слов и переносом
						const wide_t item = (static_cast <wide_t> (value[i]) * value[j] + result[i + j] + carry);
						// Записываем младшую половину полученного значения
						result[i + j] = static_cast <uint64_t> (item);
						// Запоминаем перенос в следующее слово
						carry = static_cast <uint64_t> (item >> 64);
					}
					// Записываем перенос старшим словом строки
					result[i + WORDS] = carry;
				}
				// Разряд, уходящий при удвоении в следующее слово
				uint64_t carry = 0;
				/**
				 * Выполняем удвоение накопленных произведений сдвигом на разряд
				 */
				for(size_t i = 1; i < (2 * WORDS); i++){
					// Запоминаем сдвигаемое слово
					const uint64_t item = result[i];
					// Записываем удвоенное слово с разрядом из младшего
					result[i] = ((item << 1) | carry);
					// Запоминаем старший разряд слова
					carry = (item >> 63);
				}
				// Перенос прибавления квадратов слов
				carry = 0;
				/**
				 * Выполняем прибавление квадратов слов по диагонали
				 */
				for(size_t i = 0; i < WORDS; i++){
					// Вычисляем квадрат очередного слова
					const wide_t item = (static_cast <wide_t> (value[i]) * value[i]);
					// Прибавляем младшую половину квадрата
					carry = nts::math::adc(result[2 * i], static_cast <uint64_t> (item), carry, result[2 * i]);
					// Прибавляем старшую половину квадрата
					carry = nts::math::adc(result[2 * i + 1], static_cast <uint64_t> (item >> 64), carry, result[2 * i + 1]);
				}
			}
			/**
			 * @brief Метод свёртки произведения по модулю вида 2^(64·слов) - c
			 *
			 * @details Основание разрядной сетки сравнимо с c: старшая половина произведения,
			 *          умноженная на c, прибавляется к младшей, и выход за сетку сворачивается
			 *          ещё раз тем же прибавлением. Итог не превосходит удвоенного модуля, и
			 *          условное вычитание модуля довершает приведение
			 *
			 * @param wide   произведение вдвое большего числа слов, замещаемое ходом свёртки
			 * @param tail   хвост c модуля
			 * @param result место, в которое помещается свёрнутое значение
			 *
			 * @return       перенос из старшего слова свёрнутого значения
			 *
			 */
			template <size_t WORDS>
			static __ANTS_INLINE__ uint64_t foldminus(uint64_t * wide, const uint64_t tail, uint64_t * result) noexcept {
				// Перенос в следующее слово свёртки
				uint64_t carry = 0;
				/**
				 * Выполняем прибавление старшей половины, умноженной на хвост, к младшей
				 */
				for(size_t j = 0; j < WORDS; j++){
					// Складываем слово младшей половины с произведением старшего слова на хвост
					const wide_t item = (static_cast <wide_t> (wide[WORDS + j]) * tail + wide[j] + carry);
					// Записываем младшую половину полученного значения
					wide[j] = static_cast <uint64_t> (item);
					// Запоминаем перенос в следующее слово
					carry = static_cast <uint64_t> (item >> 64);
				}
				// Сворачиваем выход за разрядную сетку тем же прибавлением
				const wide_t item = (static_cast <wide_t> (carry) * tail + wide[0]);
				// Записываем младшее слово свёрнутого значения
				wide[0] = static_cast <uint64_t> (item);
				// Запоминаем перенос в следующее слово
				carry = static_cast <uint64_t> (item >> 64);
				/**
				 * Выполняем пронос переноса по старшим словам
				 */
				for(size_t j = 1; j < WORDS; j++)
					// Прибавляем перенос к очередному слову
					carry = nts::math::adc(wide[j], 0, carry, wide[j]);
				/**
				 * Выполняем перенос свёрнутого значения в итог
				 */
				for(size_t j = 0; j < WORDS; j++)
					// Записываем очередное слово итога
					result[j] = wide[j];
				// Выводим перенос из старшего слова
				return carry;
			}
			/**
			 * @brief Метод свёртки произведения по модулю вида 2^(64·слов - 1) + c
			 *
			 * @details Степень двойки в модуле сравнима с минус c: произведение делится на
			 *          младшую часть ниже этой степени и старшую, старшая умножается на c и
			 *          вычитается. Произведение старшей части на c само выходит за степень, и
			 *          его выход сворачивается тем же порядком со сменой знака: в итоге младшая
			 *          часть прибавляет c, умноженное на выход, и вычитает остаток. Заём
			 *          гасится прибавлением модуля, а условное вычитание довершает приведение
			 *
			 * @param wide    произведение вдвое большего числа слов
			 * @param tail    хвост c модуля
			 * @param modulus слова модуля
			 * @param result  место, в которое помещается приведённое значение
			 *
			 */
			template <size_t WORDS>
			static __ANTS_INLINE__ void foldplus(const uint64_t * wide, const uint64_t tail, const uint64_t * modulus, uint64_t * result) noexcept {
				// Слова модуля, снятые в регистры до первой записи
				uint64_t m[WORDS];
				/**
				 * Выполняем перенос слов модуля в регистры
				 */
				for(size_t j = 0; j < WORDS; j++)
					// Переносим очередное слово модуля
					m[j] = modulus[j];
				// Младшая часть произведения: разряды ниже степени двойки модуля
				uint64_t low[WORDS];
				/**
				 * Выполняем перенос младшей части произведения
				 */
				for(size_t j = 0; j < WORDS; j++)
					// Переносим очередное слово младшей части
					low[j] = wide[j];
				// Снимаем разряд, отвечающий степени двойки модуля
				low[WORDS - 1] &= 0x7FFFFFFFFFFFFFFFULL;
				// Старшая часть произведения: разряды от степени двойки модуля и выше
				uint64_t high[WORDS + 1];
				/**
				 * Выполняем сборку старшей части сдвигом произведения на разряд
				 */
				for(size_t j = 0; j < WORDS; j++)
					// Собираем очередное слово старшей части из двух соседних слов произведения
					high[j] = ((wide[WORDS - 1 + j] >> 63) | (wide[WORDS + j] << 1));
				// Записываем старший разряд произведения
				high[WORDS] = (wide[2 * WORDS - 1] >> 63);
				// Произведение старшей части на хвост
				uint64_t item[WORDS + 1];
				// Перенос в следующее слово произведения
				uint64_t carry = 0;
				/**
				 * Выполняем умножение старшей части на хвост
				 */
				for(size_t j = 0; j <= WORDS; j++){
					// Складываем произведение слова на хвост с переносом
					const wide_t step = (static_cast <wide_t> (high[j]) * tail + carry);
					// Записываем младшую половину полученного значения
					item[j] = static_cast <uint64_t> (step);
					// Запоминаем перенос в следующее слово
					carry = static_cast <uint64_t> (step >> 64);
				}
				/**
				 * Хвост меньше 2^32, оттого произведение старшей части на него не достигает
				 * 2^(64·слов + 33), и его выход за степень двойки модуля умещается в одно слово
				 */
				const uint64_t top = ((item[WORDS - 1] >> 63) | (item[WORDS] << 1));
				// Снимаем разряд, отвечающий степени двойки модуля
				item[WORDS - 1] &= 0x7FFFFFFFFFFFFFFFULL;
				// Собираемое значение: младшая часть с прибавленным произведением выхода на хвост
				uint64_t value[WORDS];
				// Складываем младшее слово с произведением выхода на хвост
				const wide_t step = (static_cast <wide_t> (top) * tail + low[0]);
				// Записываем младшее слово собираемого значения
				value[0] = static_cast <uint64_t> (step);
				// Запоминаем перенос в следующее слово
				carry = static_cast <uint64_t> (step >> 64);
				/**
				 * Выполняем пронос переноса по старшим словам младшей части
				 */
				for(size_t j = 1; j < WORDS; j++)
					// Прибавляем перенос к очередному слову
					carry = nts::math::adc(low[j], 0, carry, value[j]);
				// Заём из старшего слова разности
				uint64_t borrow = 0;
				/**
				 * Выполняем вычитание остатка произведения старшей части на хвост
				 */
				for(size_t j = 0; j < WORDS; j++)
					// Вычитаем очередные слова с заёмом
					borrow = nts::math::sbb(value[j], item[j], borrow, value[j]);
				// Маска заёма: при заёме прибавляется модуль
				const uint64_t mask = (0 - borrow);
				// Перенос прибавления модуля
				carry = 0;
				/**
				 * Выполняем прибавление модуля наложением маски заёма
				 */
				for(size_t j = 0; j < WORDS; j++)
					// Прибавляем очередное слово модуля под маской
					carry = nts::math::adc(value[j], (m[j] & mask), carry, value[j]);
				// Выполняем условное вычитание модуля: значение не превосходит удвоенного модуля
				shrink <WORDS> (value, m, 0, result);
			}
			/**
			 * Ядра на четыре слова для AArch64 на встроенном ассемблере: те же действия, что у
			 * ядер на C++ (полное произведение строками с двумя цепочками переносов, свёртка
			 * старшей половины умножением на хвост, условное вычитание модуля), но с
			 * порядком команд, который собиратель из C++ не выводит. Замер 22.09.2026 на M4
			 * (clang): умножение 11,75 → 10,41 нс, квадрат 10,35 → 9,48, удвоение точки 98 → 88.
			 * Время работы от значений не зависит: ветвлений нет, выбор итога через csel.
			 * Входы читаются до первой записи, оттого места сомножителей и итога вправе
			 * совпадать. Регистр x18 не трогается: у Apple он занят системой
			 */
			#if defined(__aarch64__) && !defined(_MSC_VER)
				/**
				 * Свёртка старшей половины произведения по модулю 2^256 - c и условное вычитание
				 * модуля: общий хвост ядер умножения и квадрата. На входе x11…x14 младшая половина,
				 * x15…x17, x19 старшая; на выходе итог записан по указателю r. Выход первой свёртки
				 * x15 не превосходит c + 1, а c меньше 2^32, оттого вторая свёртка x15·c умещается
				 * в слово и старшей половины не имеет: мутация с её учётом не отличима от
				 * исходного кода, и её нет
				 */
				#define __ANTS_AARCH64_FOLD_SHRINK__ \
					"mul   x20, x15, %[tail]\n\t" "mul   x21, x16, %[tail]\n\t" "mul   x22, x17, %[tail]\n\t" "mul   x23, x19, %[tail]\n\t" \
					"umulh x3, x15, %[tail]\n\t" "umulh x4, x16, %[tail]\n\t" "umulh x5, x17, %[tail]\n\t" "umulh x6, x19, %[tail]\n\t" \
					"adds  x11, x11, x20\n\t" "adcs  x12, x12, x21\n\t" "adcs  x13, x13, x22\n\t" "adcs  x14, x14, x23\n\t" "adc   x15, xzr, xzr\n\t" \
					"adds  x12, x12, x3\n\t" "adcs  x13, x13, x4\n\t" "adcs  x14, x14, x5\n\t" "adc   x15, x15, x6\n\t" \
					"mul   x20, x15, %[tail]\n\t" \
					"adds  x11, x11, x20\n\t" "adcs  x12, x12, xzr\n\t" "adcs  x13, x13, xzr\n\t" "adcs  x14, x14, xzr\n\t" "adc   x15, xzr, xzr\n\t" \
					"ldp   x3, x4, [%[p]]\n\t" "ldp   x5, x6, [%[p], #16]\n\t" \
					"subs  x20, x11, x3\n\t" "sbcs  x21, x12, x4\n\t" "sbcs  x22, x13, x5\n\t" "sbcs  x23, x14, x6\n\t" "sbcs  xzr, x15, xzr\n\t" \
					"csel  x11, x20, x11, cs\n\t" "csel  x12, x21, x12, cs\n\t" "csel  x13, x22, x13, cs\n\t" "csel  x14, x23, x14, cs\n\t" \
					"stp   x11, x12, [%[r]]\n\t" "stp   x13, x14, [%[r], #16]\n\t"
				/**
				 * @brief Метод умножения по модулю вида 2^256 - c на встроенном ассемблере AArch64
				 *
				 * @param first   первый сомножитель
				 * @param second  второй сомножитель
				 * @param tail    хвост c модуля
				 * @param modulus слова модуля
				 * @param result  место, в которое помещается произведение
				 *
				 */
				static __ANTS_INLINE__ void multiplyminus4(const uint64_t * first, const uint64_t * second, const uint64_t tail, const uint64_t * modulus, uint64_t * result) noexcept {
					__asm__ volatile(
						"ldp x3, x4, [%[a]]\n\t" "ldp x5, x6, [%[a], #16]\n\t" "ldp x7, x8, [%[b]]\n\t" "ldp x9, x10, [%[b], #16]\n\t"
						// Строка нулевого слова второго сомножителя
						"mul   x11, x3, x7\n\t" "mul   x12, x4, x7\n\t" "mul   x13, x5, x7\n\t" "mul   x14, x6, x7\n\t"
						"umulh x20, x3, x7\n\t" "umulh x21, x4, x7\n\t" "umulh x22, x5, x7\n\t" "umulh x15, x6, x7\n\t"
						"adds  x12, x12, x20\n\t" "adcs  x13, x13, x21\n\t" "adcs  x14, x14, x22\n\t" "adc   x15, x15, xzr\n\t"
						// Строка первого слова: младшие половины цепочкой, затем старшие
						"mul   x20, x3, x8\n\t" "mul   x21, x4, x8\n\t" "mul   x22, x5, x8\n\t" "mul   x23, x6, x8\n\t"
						"adds  x12, x12, x20\n\t" "adcs  x13, x13, x21\n\t" "adcs  x14, x14, x22\n\t" "adcs  x15, x15, x23\n\t" "adc   x16, xzr, xzr\n\t"
						"umulh x20, x3, x8\n\t" "umulh x21, x4, x8\n\t" "umulh x22, x5, x8\n\t" "umulh x23, x6, x8\n\t"
						"adds  x13, x13, x20\n\t" "adcs  x14, x14, x21\n\t" "adcs  x15, x15, x22\n\t" "adc   x16, x16, x23\n\t"
						// Строка второго слова
						"mul   x20, x3, x9\n\t" "mul   x21, x4, x9\n\t" "mul   x22, x5, x9\n\t" "mul   x23, x6, x9\n\t"
						"adds  x13, x13, x20\n\t" "adcs  x14, x14, x21\n\t" "adcs  x15, x15, x22\n\t" "adcs  x16, x16, x23\n\t" "adc   x17, xzr, xzr\n\t"
						"umulh x20, x3, x9\n\t" "umulh x21, x4, x9\n\t" "umulh x22, x5, x9\n\t" "umulh x23, x6, x9\n\t"
						"adds  x14, x14, x20\n\t" "adcs  x15, x15, x21\n\t" "adcs  x16, x16, x22\n\t" "adc   x17, x17, x23\n\t"
						// Строка третьего слова
						"mul   x20, x3, x10\n\t" "mul   x21, x4, x10\n\t" "mul   x22, x5, x10\n\t" "mul   x23, x6, x10\n\t"
						"adds  x14, x14, x20\n\t" "adcs  x15, x15, x21\n\t" "adcs  x16, x16, x22\n\t" "adcs  x17, x17, x23\n\t" "adc   x19, xzr, xzr\n\t"
						"umulh x20, x3, x10\n\t" "umulh x21, x4, x10\n\t" "umulh x22, x5, x10\n\t" "umulh x23, x6, x10\n\t"
						"adds  x15, x15, x20\n\t" "adcs  x16, x16, x21\n\t" "adcs  x17, x17, x22\n\t" "adc   x19, x19, x23\n\t"
						__ANTS_AARCH64_FOLD_SHRINK__
						: : [a] "r" (first), [b] "r" (second), [tail] "r" (tail), [p] "r" (modulus), [r] "r" (result)
						: "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22", "x23", "cc", "memory"
					);
				}
				/**
				 * @brief Метод возведения в квадрат по модулю вида 2^256 - c на встроенном ассемблере AArch64
				 *
				 * @param value   возводимое число
				 * @param tail    хвост c модуля
				 * @param modulus слова модуля
				 * @param result  место, в которое помещается квадрат
				 *
				 */
				static __ANTS_INLINE__ void squareminus4(const uint64_t * value, const uint64_t tail, const uint64_t * modulus, uint64_t * result) noexcept {
					__asm__ volatile(
						"ldp x3, x4, [%[a]]\n\t" "ldp x5, x6, [%[a], #16]\n\t"
						// Произведения разных слов: a0·a1, a0·a2, a0·a3
						"mul   x12, x3, x4\n\t" "umulh x13, x3, x4\n\t" "mul   x20, x3, x5\n\t" "umulh x14, x3, x5\n\t" "mul   x21, x3, x6\n\t" "umulh x15, x3, x6\n\t"
						"adds  x13, x13, x20\n\t" "adcs  x14, x14, x21\n\t" "adc   x15, x15, xzr\n\t"
						// a1·a2, a1·a3
						"mul   x20, x4, x5\n\t" "umulh x21, x4, x5\n\t" "mul   x22, x4, x6\n\t" "umulh x23, x4, x6\n\t"
						"adds  x14, x14, x20\n\t" "adcs  x15, x15, x21\n\t" "adc   x16, xzr, xzr\n\t"
						"adds  x15, x15, x22\n\t" "adcs  x16, x16, x23\n\t" "adc   x17, xzr, xzr\n\t"
						// a2·a3
						"mul   x20, x5, x6\n\t" "umulh x21, x5, x6\n\t"
						"adds  x16, x16, x20\n\t" "adc   x17, x17, x21\n\t"
						// Удвоение произведений разных слов сдвигом через переносы
						"adds  x12, x12, x12\n\t" "adcs  x13, x13, x13\n\t" "adcs  x14, x14, x14\n\t" "adcs  x15, x15, x15\n\t" "adcs  x16, x16, x16\n\t" "adcs  x17, x17, x17\n\t" "adc   x19, xzr, xzr\n\t"
						// Квадраты слов по диагонали
						"mul   x11, x3, x3\n\t" "umulh x20, x3, x3\n\t" "mul   x21, x4, x4\n\t" "umulh x22, x4, x4\n\t" "mul   x23, x5, x5\n\t" "umulh x7, x5, x5\n\t" "mul   x8, x6, x6\n\t" "umulh x9, x6, x6\n\t"
						"adds  x12, x12, x20\n\t" "adcs  x13, x13, x21\n\t" "adcs  x14, x14, x22\n\t" "adcs  x15, x15, x23\n\t" "adcs  x16, x16, x7\n\t" "adcs  x17, x17, x8\n\t" "adc   x19, x19, x9\n\t"
						__ANTS_AARCH64_FOLD_SHRINK__
						: : [a] "r" (value), [tail] "r" (tail), [p] "r" (modulus), [r] "r" (result)
						: "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22", "x23", "cc", "memory"
					);
				}
				#undef __ANTS_AARCH64_FOLD_SHRINK__
				// Признак наличия ядер на ассемблере для четырёх слов
				#define __ANTS_AARCH64_KERNELS__
			#endif
			/**
			 * Ядра на четыре слова для x86-64 на встроенном ассемблере, только у gcc: его код из
			 * __int128 хуже ручного на треть (Astra, gcc 12: умножение 46 → 31,5 нс, квадрат 38 →
			 * 25,5), а у clang ручной код хуже собранного им самим (FreeBSD, clang 19: 26,6 → 32),
			 * и там остаётся C++. Команды mulx/adx не берутся: их нет у стендов, а без замера
			 * путь не заводится. Произведение считается по одному слову с проносом переноса
			 * (add/adc/adc $0), регистров впритык к пятнадцати: тело разбито на два вставных
			 * блока, между ними накопитель живёт в переменных. Хвост c и указатель на модуль
			 * передаются через структуру, чтобы не занимать регистры. Времени от значений
			 * нет: ветвлений нет, выбор итога через cmov. Входы читаются до первой записи
			 */
			#if defined(__x86_64__) && defined(__GNUC__) && !defined(__clang__) && !defined(_MSC_VER)
				/**
				 * @brief Хвост модуля и его слова для ядер на ассемблере
				 *
				 */
				typedef struct Fold {
					// Хвост c модуля
					uint64_t tail;
					// Слова модуля
					const uint64_t * modulus;
				} fold_t;
				/**
				 * Свёртка старшей половины произведения по модулю 2^256 - c и условное вычитание
				 * модуля: общий хвост ядер умножения и квадрата. Слово переноса первой свёртки не
				 * превосходит c + 1 при c < 2^32, оттого вторая свёртка умещается в слово
				 */
				#define __ANTS_X86_64_FOLD_SHRINK__ \
					"movq %[c4], %%rax\n\t" "mulq 0(%[f])\n\t" "addq %%rax, %[c0]\n\t" "adcq $0, %%rdx\n\t" "movq %%rdx, %[t]\n\t" \
					"movq %[c5], %%rax\n\t" "mulq 0(%[f])\n\t" "addq %[t], %[c1]\n\t" "adcq $0, %%rdx\n\t" "addq %%rax, %[c1]\n\t" "adcq $0, %%rdx\n\t" "movq %%rdx, %[t]\n\t" \
					"movq %[c6], %%rax\n\t" "mulq 0(%[f])\n\t" "addq %[t], %[c2]\n\t" "adcq $0, %%rdx\n\t" "addq %%rax, %[c2]\n\t" "adcq $0, %%rdx\n\t" "movq %%rdx, %[t]\n\t" \
					"movq %[c7], %%rax\n\t" "mulq 0(%[f])\n\t" "addq %[t], %[c3]\n\t" "adcq $0, %%rdx\n\t" "addq %%rax, %[c3]\n\t" "adcq $0, %%rdx\n\t" \
					"movq %%rdx, %%rax\n\t" "mulq 0(%[f])\n\t" \
					"addq %%rax, %[c0]\n\t" "adcq $0, %[c1]\n\t" "adcq $0, %[c2]\n\t" "adcq $0, %[c3]\n\t" \
					"movq $0, %[t]\n\t" "adcq $0, %[t]\n\t" \
					"movq 8(%[f]), %[m]\n\t" \
					"movq %[c0], %[c4]\n\t" "movq %[c1], %[c5]\n\t" "movq %[c2], %[c6]\n\t" "movq %[c3], %[c7]\n\t" \
					"subq 0(%[m]), %[c4]\n\t" "sbbq 8(%[m]), %[c5]\n\t" "sbbq 16(%[m]), %[c6]\n\t" "sbbq 24(%[m]), %[c7]\n\t" "sbbq $0, %[t]\n\t" \
					"cmovncq %[c4], %[c0]\n\t" "cmovncq %[c5], %[c1]\n\t" "cmovncq %[c6], %[c2]\n\t" "cmovncq %[c7], %[c3]\n\t" \
					"movq %[c0], 0(%[r])\n\t" "movq %[c1], 8(%[r])\n\t" "movq %[c2], 16(%[r])\n\t" "movq %[c3], 24(%[r])\n\t"
				/**
				 * @brief Метод свёртки и условного вычитания модуля на ассемблере x86-64
				 *
				 * @param c0 младшие слова произведения, замещаемые итогом
				 * @param c4 старшие слова произведения
				 * @param f  хвост и слова модуля
				 * @param r  место, в которое помещается итог
				 *
				 */
				static __ANTS_INLINE__ void settle4(uint64_t & c0, uint64_t & c1, uint64_t & c2, uint64_t & c3, uint64_t & c4, uint64_t & c5, uint64_t & c6, uint64_t & c7, const fold_t * f, uint64_t * r) noexcept {
					// Слово переноса и указатель на слова модуля
					uint64_t t, m;
					__asm__ volatile(__ANTS_X86_64_FOLD_SHRINK__
						: [c0] "+r" (c0), [c1] "+r" (c1), [c2] "+r" (c2), [c3] "+r" (c3), [c4] "+r" (c4), [c5] "+r" (c5), [c6] "+r" (c6), [c7] "+r" (c7), [t] "=&r" (t), [m] "=&r" (m)
						: [f] "r" (f), [r] "r" (r)
						: "rax", "rdx", "cc", "memory"
					);
				}
				#undef __ANTS_X86_64_FOLD_SHRINK__
				/**
				 * @brief Метод умножения по модулю вида 2^256 - c на встроенном ассемблере x86-64
				 *
				 * @param first   первый сомножитель
				 * @param second  второй сомножитель
				 * @param tail    хвост c модуля
				 * @param modulus слова модуля
				 * @param result  место, в которое помещается произведение
				 *
				 */
				static __ANTS_INLINE__ void multiplyminus4(const uint64_t * first, const uint64_t * second, const uint64_t tail, const uint64_t * modulus, uint64_t * result) noexcept {
					// Хвост и слова модуля
					const fold_t fold = {tail, modulus};
					// Слова полного произведения и слово переноса
					uint64_t c0, c1, c2, c3, c4, c5, c6, c7, t;
					__asm__ volatile(
						// Строка нулевого слова второго сомножителя
						"movq 0(%[a]), %%rax\n\t" "mulq 0(%[b])\n\t" "movq %%rax, %[c0]\n\t" "movq %%rdx, %[c1]\n\t"
						"movq 8(%[a]), %%rax\n\t" "mulq 0(%[b])\n\t" "addq %%rax, %[c1]\n\t" "adcq $0, %%rdx\n\t" "movq %%rdx, %[c2]\n\t"
						"movq 16(%[a]), %%rax\n\t" "mulq 0(%[b])\n\t" "addq %%rax, %[c2]\n\t" "adcq $0, %%rdx\n\t" "movq %%rdx, %[c3]\n\t"
						"movq 24(%[a]), %%rax\n\t" "mulq 0(%[b])\n\t" "addq %%rax, %[c3]\n\t" "adcq $0, %%rdx\n\t" "movq %%rdx, %[c4]\n\t"
						// Строка первого слова
						"movq 0(%[a]), %%rax\n\t" "mulq 8(%[b])\n\t" "addq %%rax, %[c1]\n\t" "adcq $0, %%rdx\n\t" "movq %%rdx, %[t]\n\t"
						"movq 8(%[a]), %%rax\n\t" "mulq 8(%[b])\n\t" "addq %[t], %[c2]\n\t" "adcq $0, %%rdx\n\t" "addq %%rax, %[c2]\n\t" "adcq $0, %%rdx\n\t" "movq %%rdx, %[t]\n\t"
						"movq 16(%[a]), %%rax\n\t" "mulq 8(%[b])\n\t" "addq %[t], %[c3]\n\t" "adcq $0, %%rdx\n\t" "addq %%rax, %[c3]\n\t" "adcq $0, %%rdx\n\t" "movq %%rdx, %[t]\n\t"
						"movq 24(%[a]), %%rax\n\t" "mulq 8(%[b])\n\t" "addq %[t], %[c4]\n\t" "adcq $0, %%rdx\n\t" "addq %%rax, %[c4]\n\t" "adcq $0, %%rdx\n\t" "movq %%rdx, %[c5]\n\t"
						// Строка второго слова
						"movq 0(%[a]), %%rax\n\t" "mulq 16(%[b])\n\t" "addq %%rax, %[c2]\n\t" "adcq $0, %%rdx\n\t" "movq %%rdx, %[t]\n\t"
						"movq 8(%[a]), %%rax\n\t" "mulq 16(%[b])\n\t" "addq %[t], %[c3]\n\t" "adcq $0, %%rdx\n\t" "addq %%rax, %[c3]\n\t" "adcq $0, %%rdx\n\t" "movq %%rdx, %[t]\n\t"
						"movq 16(%[a]), %%rax\n\t" "mulq 16(%[b])\n\t" "addq %[t], %[c4]\n\t" "adcq $0, %%rdx\n\t" "addq %%rax, %[c4]\n\t" "adcq $0, %%rdx\n\t" "movq %%rdx, %[t]\n\t"
						"movq 24(%[a]), %%rax\n\t" "mulq 16(%[b])\n\t" "addq %[t], %[c5]\n\t" "adcq $0, %%rdx\n\t" "addq %%rax, %[c5]\n\t" "adcq $0, %%rdx\n\t" "movq %%rdx, %[c6]\n\t"
						// Строка третьего слова
						"movq 0(%[a]), %%rax\n\t" "mulq 24(%[b])\n\t" "addq %%rax, %[c3]\n\t" "adcq $0, %%rdx\n\t" "movq %%rdx, %[t]\n\t"
						"movq 8(%[a]), %%rax\n\t" "mulq 24(%[b])\n\t" "addq %[t], %[c4]\n\t" "adcq $0, %%rdx\n\t" "addq %%rax, %[c4]\n\t" "adcq $0, %%rdx\n\t" "movq %%rdx, %[t]\n\t"
						"movq 16(%[a]), %%rax\n\t" "mulq 24(%[b])\n\t" "addq %[t], %[c5]\n\t" "adcq $0, %%rdx\n\t" "addq %%rax, %[c5]\n\t" "adcq $0, %%rdx\n\t" "movq %%rdx, %[t]\n\t"
						"movq 24(%[a]), %%rax\n\t" "mulq 24(%[b])\n\t" "addq %[t], %[c6]\n\t" "adcq $0, %%rdx\n\t" "addq %%rax, %[c6]\n\t" "adcq $0, %%rdx\n\t" "movq %%rdx, %[c7]\n\t"
						: [c0] "=&r" (c0), [c1] "=&r" (c1), [c2] "=&r" (c2), [c3] "=&r" (c3), [c4] "=&r" (c4), [c5] "=&r" (c5), [c6] "=&r" (c6), [c7] "=&r" (c7), [t] "=&r" (t)
						: [a] "r" (first), [b] "r" (second)
						: "rax", "rdx", "cc", "memory"
					);
					// Выполняем свёртку и условное вычитание модуля с записью итога
					settle4(c0, c1, c2, c3, c4, c5, c6, c7, &fold, result);
				}
				/**
				 * @brief Метод возведения в квадрат по модулю вида 2^256 - c на встроенном ассемблере x86-64
				 *
				 * @param value   возводимое число
				 * @param tail    хвост c модуля
				 * @param modulus слова модуля
				 * @param result  место, в которое помещается квадрат
				 *
				 */
				static __ANTS_INLINE__ void squareminus4(const uint64_t * value, const uint64_t tail, const uint64_t * modulus, uint64_t * result) noexcept {
					// Хвост и слова модуля
					const fold_t fold = {tail, modulus};
					// Слова полного квадрата и слово переноса
					uint64_t c0, c1, c2, c3, c4, c5, c6, c7, t;
					__asm__ volatile(
						// Произведения разных слов: a0·a1, a0·a2, a0·a3, a1·a2, a1·a3, a2·a3
						"movq 0(%[a]), %%rax\n\t" "mulq 8(%[a])\n\t" "movq %%rax, %[c1]\n\t" "movq %%rdx, %[c2]\n\t"
						"movq 0(%[a]), %%rax\n\t" "mulq 16(%[a])\n\t" "addq %%rax, %[c2]\n\t" "adcq $0, %%rdx\n\t" "movq %%rdx, %[c3]\n\t"
						"movq 0(%[a]), %%rax\n\t" "mulq 24(%[a])\n\t" "addq %%rax, %[c3]\n\t" "adcq $0, %%rdx\n\t" "movq %%rdx, %[c4]\n\t"
						"movq 8(%[a]), %%rax\n\t" "mulq 16(%[a])\n\t" "addq %%rax, %[c3]\n\t" "adcq $0, %%rdx\n\t" "movq %%rdx, %[t]\n\t"
						"movq 8(%[a]), %%rax\n\t" "mulq 24(%[a])\n\t" "addq %[t], %[c4]\n\t" "adcq $0, %%rdx\n\t" "addq %%rax, %[c4]\n\t" "adcq $0, %%rdx\n\t" "movq %%rdx, %[c5]\n\t"
						"movq 16(%[a]), %%rax\n\t" "mulq 24(%[a])\n\t" "addq %%rax, %[c5]\n\t" "adcq $0, %%rdx\n\t" "movq %%rdx, %[c6]\n\t"
						// Удвоение произведений разных слов через переносы
						"addq %[c1], %[c1]\n\t" "adcq %[c2], %[c2]\n\t" "adcq %[c3], %[c3]\n\t" "adcq %[c4], %[c4]\n\t" "adcq %[c5], %[c5]\n\t" "adcq %[c6], %[c6]\n\t" "movq $0, %[c7]\n\t" "adcq $0, %[c7]\n\t"
						// Квадраты слов по диагонали
						"movq 0(%[a]), %%rax\n\t" "mulq %%rax\n\t" "movq %%rax, %[c0]\n\t" "movq %%rdx, %[t]\n\t"
						"movq 8(%[a]), %%rax\n\t" "mulq %%rax\n\t" "addq %[t], %[c1]\n\t" "adcq %%rax, %[c2]\n\t" "adcq $0, %%rdx\n\t" "movq %%rdx, %[t]\n\t"
						"movq 16(%[a]), %%rax\n\t" "mulq %%rax\n\t" "addq %[t], %[c3]\n\t" "adcq %%rax, %[c4]\n\t" "adcq $0, %%rdx\n\t" "movq %%rdx, %[t]\n\t"
						"movq 24(%[a]), %%rax\n\t" "mulq %%rax\n\t" "addq %[t], %[c5]\n\t" "adcq %%rax, %[c6]\n\t" "adcq %%rdx, %[c7]\n\t"
						: [c0] "=&r" (c0), [c1] "=&r" (c1), [c2] "=&r" (c2), [c3] "=&r" (c3), [c4] "=&r" (c4), [c5] "=&r" (c5), [c6] "=&r" (c6), [c7] "=&r" (c7), [t] "=&r" (t)
						: [a] "r" (value)
						: "rax", "rdx", "cc", "memory"
					);
					// Выполняем свёртку и условное вычитание модуля с записью итога
					settle4(c0, c1, c2, c3, c4, c5, c6, c7, &fold, result);
				}
				// Признак наличия ядер на ассемблере для четырёх слов
				#define __ANTS_X86_64_KERNELS__
			#endif
			/**
			 * @brief Метод умножения по модулю вида 2^(64·слов) - c
			 *
			 * @param first   первый сомножитель
			 * @param second  второй сомножитель
			 * @param tail    хвост c модуля
			 * @param modulus слова модуля
			 * @param result  место, в которое помещается произведение
			 *
			 * @note Квадрат считается отдельным ядром squareminus, а не ветвлением здесь:
			 *       lcc сливает обе ветви одного тела в предикатный поток и считает оба
			 *       пути разом - квадрат в библиотеке стоил 157 нс при 70 у ядра порознь
			 *
			 */
			template <size_t WORDS>
			static __ANTS_INLINE__ void multiplyminus(const uint64_t * first, const uint64_t * second, const uint64_t tail, const uint64_t * modulus, uint64_t * result) noexcept {
				#if defined(__ANTS_AARCH64_KERNELS__) || defined(__ANTS_X86_64_KERNELS__)
					// Четыре слова на AArch64 и x86-64 (gcc) идут ядром на встроенном ассемблере
					if constexpr (WORDS == 4){
						// Выполняем умножение ядром на ассемблере
						multiplyminus4(first, second, tail, modulus, result);
						// Выходим из умножения
						return;
					}
				#endif
				// Полное произведение сомножителей
				uint64_t wide[2 * WORDS];
				// Выполняем полное умножение
				product <WORDS> (first, second, wide);
				// Свёрнутое произведение
				uint64_t folded[WORDS];
				// Выполняем свёртку произведения
				const uint64_t carry = foldminus <WORDS> (wide, tail, folded);
				// Выполняем условное вычитание модуля с записью итога
				shrink <WORDS> (folded, modulus, carry, result);
			}
			/**
			 * @brief Метод возведения в квадрат по модулю вида 2^(64·слов) - c
			 *
			 * @param value   возводимое число
			 * @param tail    хвост c модуля
			 * @param modulus слова модуля
			 * @param result  место, в которое помещается квадрат
			 *
			 */
			template <size_t WORDS>
			static __ANTS_INLINE__ void squareminus(const uint64_t * value, const uint64_t tail, const uint64_t * modulus, uint64_t * result) noexcept {
				#if defined(__ANTS_AARCH64_KERNELS__) || defined(__ANTS_X86_64_KERNELS__)
					// Четыре слова на AArch64 и x86-64 (gcc) идут ядром на встроенном ассемблере
					if constexpr (WORDS == 4){
						// Выполняем возведение в квадрат ядром на ассемблере
						squareminus4(value, tail, modulus, result);
						// Выходим из возведения в квадрат
						return;
					}
				#endif
				// Полный квадрат числа
				uint64_t wide[2 * WORDS];
				// Выполняем возведение числа в квадрат
				squared <WORDS> (value, wide);
				// Свёрнутый квадрат
				uint64_t folded[WORDS];
				// Выполняем свёртку квадрата
				const uint64_t carry = foldminus <WORDS> (wide, tail, folded);
				// Выполняем условное вычитание модуля с записью итога
				shrink <WORDS> (folded, modulus, carry, result);
			}
			/**
			 * @brief Метод умножения по модулю вида 2^(64·слов - 1) + c
			 *
			 * @param first   первый сомножитель
			 * @param second  второй сомножитель
			 * @param tail    хвост c модуля
			 * @param modulus слова модуля
			 * @param result  место, в которое помещается произведение
			 *
			 */
			template <size_t WORDS>
			static __ANTS_INLINE__ void multiplyplus(const uint64_t * first, const uint64_t * second, const uint64_t tail, const uint64_t * modulus, uint64_t * result) noexcept {
				// Полное произведение сомножителей
				uint64_t wide[2 * WORDS];
				// Выполняем полное умножение
				product <WORDS> (first, second, wide);
				// Выполняем свёртку произведения по модулю
				foldplus <WORDS> (wide, tail, modulus, result);
			}
			/**
			 * @brief Метод возведения в квадрат по модулю вида 2^(64·слов - 1) + c
			 *
			 * @param value   возводимое число
			 * @param tail    хвост c модуля
			 * @param modulus слова модуля
			 * @param result  место, в которое помещается квадрат
			 *
			 */
			template <size_t WORDS>
			static __ANTS_INLINE__ void squareplus(const uint64_t * value, const uint64_t tail, const uint64_t * modulus, uint64_t * result) noexcept {
				// Полный квадрат числа
				uint64_t wide[2 * WORDS];
				// Выполняем возведение числа в квадрат
				squared <WORDS> (value, wide);
				// Выполняем свёртку квадрата по модулю
				foldplus <WORDS> (wide, tail, modulus, result);
			}
			/**
			 * @brief Метод умножения по модулю ядром, отвечающим виду модуля
			 *
			 * @details Простое число P-256 идёт Монтгомери с заложенными словами, простые
			 *          вида 2^k ± c - прямой свёрткой, прочие - общим Монтгомери. Квадрат
			 *          берётся отдельным методом square: ветвления по совпадению
			 *          сомножителей здесь нет намеренно
			 *
			 * @param layout устройство модуля
			 * @param first  первый сомножитель
			 * @param second второй сомножитель
			 * @param result место, в которое помещается произведение
			 *
			 */
			template <size_t WORDS>
			static __ANTS_INLINE__ void multiply(const Modulus::layout_t & layout, const uint64_t * first, const uint64_t * second, uint64_t * result) noexcept {
				// Выбираем ядро по виду модуля
				switch(static_cast <uint8_t> (layout.form)){
					// Простое число кривой P-256: путь есть лишь на четыре слова
					case static_cast <uint8_t> (Modulus::form_t::NIST): {
						// Произведение до условного вычитания модуля
						uint64_t buffer[WORDS];
						// Перенос из старшего слова произведения
						uint64_t carry = 0;
						// Выполняем умножение ядром P-256 либо общим Монтгомери
						if constexpr (WORDS == 4)
							carry = nist256(first, second, buffer);
						else carry = montgomery <WORDS> (first, second, layout.modulus, layout.factor, buffer);
						// Выполняем условное вычитание модуля с записью итога
						shrink <WORDS> (buffer, layout.modulus, carry, result);
					} break;
					// Простое число вида 2^(64·слов) - c
					case static_cast <uint8_t> (Modulus::form_t::MINUS):
						multiplyminus <WORDS> (first, second, layout.tail, layout.modulus, result);
					break;
					// Простое число вида 2^(64·слов - 1) + c
					case static_cast <uint8_t> (Modulus::form_t::PLUS):
						multiplyplus <WORDS> (first, second, layout.tail, layout.modulus, result);
					break;
					// Произвольный модуль
					default: {
						// Произведение до условного вычитания модуля
						uint64_t buffer[WORDS];
						// Выполняем умножение общим Монтгомери
						const uint64_t carry = montgomery <WORDS> (first, second, layout.modulus, layout.factor, buffer);
						// Выполняем условное вычитание модуля с записью итога
						shrink <WORDS> (buffer, layout.modulus, carry, result);
					}
				}
			}
			/**
			 * @brief Метод возведения в квадрат по модулю ядром, отвечающим виду модуля
			 *
			 * @param layout устройство модуля
			 * @param value  возводимое число
			 * @param result место, в которое помещается квадрат
			 *
			 */
			template <size_t WORDS>
			static __ANTS_INLINE__ void square(const Modulus::layout_t & layout, const uint64_t * value, uint64_t * result) noexcept {
				// Выбираем ядро по виду модуля
				switch(static_cast <uint8_t> (layout.form)){
					// Простое число кривой P-256: путь есть лишь на четыре слова
					case static_cast <uint8_t> (Modulus::form_t::NIST): {
						// Квадрат до условного вычитания модуля
						uint64_t buffer[WORDS];
						// Перенос из старшего слова квадрата
						uint64_t carry = 0;
						// Выполняем возведение в квадрат ядром P-256 либо общим Монтгомери
						if constexpr (WORDS == 4)
							carry = nist256square(value, buffer);
						else carry = montgomery <WORDS> (value, value, layout.modulus, layout.factor, buffer);
						// Выполняем условное вычитание модуля с записью итога
						shrink <WORDS> (buffer, layout.modulus, carry, result);
					} break;
					// Простое число вида 2^(64·слов) - c
					case static_cast <uint8_t> (Modulus::form_t::MINUS):
						squareminus <WORDS> (value, layout.tail, layout.modulus, result);
					break;
					// Простое число вида 2^(64·слов - 1) + c
					case static_cast <uint8_t> (Modulus::form_t::PLUS):
						squareplus <WORDS> (value, layout.tail, layout.modulus, result);
					break;
					// Произвольный модуль: у общего Монтгомери своего квадрата нет
					default: {
						// Квадрат до условного вычитания модуля
						uint64_t buffer[WORDS];
						// Выполняем умножение числа на себя общим Монтгомери
						const uint64_t carry = montgomery <WORDS> (value, value, layout.modulus, layout.factor, buffer);
						// Выполняем условное вычитание модуля с записью итога
						shrink <WORDS> (buffer, layout.modulus, carry, result);
					}
				}
			}
			/**
			 * @brief Метод сложения по модулю ядром известного числа слов
			 *
			 * @param layout устройство модуля
			 * @param first  первое слагаемое
			 * @param second второе слагаемое
			 * @param result место, в которое помещается сумма
			 *
			 */
			template <size_t WORDS>
			static __ANTS_INLINE__ void add(const Modulus::layout_t & layout, const uint64_t * first, const uint64_t * second, uint64_t * result) noexcept {
				// Выполняем сложение развёрнутым ядром
				addition <WORDS> (first, second, layout.modulus, result);
			}
			/**
			 * @brief Метод вычитания по модулю ядром известного числа слов
			 *
			 * @param layout устройство модуля
			 * @param first  уменьшаемое
			 * @param second вычитаемое
			 * @param result место, в которое помещается разность
			 *
			 */
			template <size_t WORDS>
			static __ANTS_INLINE__ void subtract(const Modulus::layout_t & layout, const uint64_t * first, const uint64_t * second, uint64_t * result) noexcept {
				// Выполняем вычитание развёрнутым ядром
				subtraction <WORDS> (first, second, layout.modulus, result);
			}
		};
	};
};

#endif // __ANTS_MATH_KERNELS__
