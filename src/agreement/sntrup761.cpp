/**
 * @file sntrup761.cpp
 * @date 2026-10-04
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
 * @brief Модуль инкапсуляции ключа Streamlined NTRU Prime sntrup761
 *
 * @details Арифметика в Z/4591[x]/(x^761 − x − 1), малые полиномы в {-1,0,1}.
 *          Портировано с эталона OpenSSH sntrup761.c (общественное достояние, SUPERCOP)
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартный заголовочный файл
 */
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/wipe.hpp>
#include <digest/sha2.hpp>
#include <entropy/entropy.hpp>

/**
 * Подключаем заголовочный файл модуля
 */
#include <agreement/sntrup761.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * @brief Служебные объекты модуля
 *
 */
namespace {
	/**
	 * Пространство имён проекта
	 */
	using namespace nts;
	/**
	 * Затирание областей памяти берётся из открытого API библиотеки
	 */
	using nts::sys::wipe;

	/**
	 * Вес малого полинома
	 */
	constexpr size_t W = 286;
	/**
	 * Степень полинома
	 */
	constexpr size_t P = 761;
	/**
	 * Модуль коэффициентов
	 */
	constexpr uint16_t Q = 4591;
	/**
	 * Длина хеша в байтах
	 */
	constexpr size_t HASH_BYTES = 32;
	/**
	 * Длина закодированного полинома Rq
	 */
	constexpr size_t RQ_BYTES = 1158;
	/**
	 * Половина модуля для симметричного представления
	 */
	constexpr int16_t Q12 = (Q - 1) / 2;
	/**
	 * Длина закодированного округлённого полинома
	 */
	constexpr size_t ROUNDED_BYTES = 1007;
	/**
	 * Длина закодированного малого полинома
	 */
	constexpr size_t SMALL_BYTES = (P + 3) / 4;

	/**
	 * Коэффициент по модулю q в [-q12, q12]
	 */
	using fq_t = int16_t;
	/**
	 * Малый коэффициент в {-1, 0, 1}
	 */
	using small_t = int8_t;

	/**
	 * @brief Функция получения маски отрицательного числа
	 *
	 * @param value проверяемое число
	 * @return      -1 если value < 0, иначе 0
	 *
	 */
	static constexpr int32_t __ants_int16_negative_mask__(const int16_t value) noexcept {
		// Возвращаем маску знака: старший бит размножен на все разряды
		return -(static_cast <int32_t> (static_cast <uint16_t> (value) >> 15));
	}
	/**
	 * @brief Функция получения маски ненулевого числа
	 *
	 * @param value проверяемое число
	 * @return      -1 если value != 0, иначе 0
	 *
	 */
	static constexpr int32_t __ants_int16_nonzero_mask__(const int16_t value) noexcept {
		// Приводим число к беззнаковому виду
		const uint32_t word = static_cast <uint32_t> (static_cast <uint16_t> (value));
		// Возвращаем маску ненулевого значения
		return -static_cast <int32_t> ((-word) >> 31);
	}

	/**
	 * Оптимизатор MSVC под ARM64 (14.43) ломает цепочку Барретта ниже: произведение
	 * в двойном слове со сдвигом и вычитанием кратного даёт неверный остаток, и
	 * декапсуляция sntrup761 расходится (проверки Roundtrip/Reuse падают). Оптимизация
	 * функции выключается до исправления собирателя
	 */
	#if defined(_MSC_VER) && defined(_M_ARM64)
		#pragma optimize("", off)
	#endif

	/**
	 * @brief Функция цепочки деления без операции деления: двоичный поиск частного
	 *
	 * @param quotient  частное
	 * @param remainder остаток
	 * @param dividend  делимое
	 * @param divisor   делитель
	 *
	 */
	static __ANTS_INLINE__ void __ants_uint32_divmod_uint14__(uint32_t * quotient, uint16_t * remainder, uint32_t dividend, const uint16_t divisor) noexcept {
		// Предвычисляем масштаб двух в тридцать первой степени на модуль
		uint32_t scale = (0x80000000 / divisor);
		// Обнуляем частное перед накоплением
		(* quotient) = 0;
		// Вычисляем очередную частную часть через верхние биты произведения
		uint32_t qpart = static_cast <uint32_t> ((dividend * static_cast <uint64_t> (scale)) >> 31);
		// Уменьшаем делимое на кратное модулю
		dividend -= qpart * divisor;
		// Прибавляем частную часть к частному
		(* quotient) += qpart;
		// Повторяем уточнение частного для уменьшенного делимого
		qpart = static_cast <uint32_t> ((dividend * static_cast <uint64_t> (scale)) >> 31);
		// Уменьшаем делимое на следующее кратное модулю
		dividend -= qpart * divisor;
		// Прибавляем уточнение к частному
		(* quotient) += qpart;
		// Вычитаем модуль для окончательной коррекции остатка
		dividend -= divisor;
		// Учитываем вычтенный модуль в частном
		(* quotient) += 1;
		// Получаем маску отрицательного остатка
		const uint32_t mask = -(dividend >> 31);
		// Возвращаем модуль обратно при отрицательном остатке
		dividend += mask & static_cast <uint32_t> (divisor);
		// Откатываем лишнюю единицу при отрицательном остатке
		(* quotient) += mask;
		// Записываем скорректированный остаток
		(* remainder) = static_cast <uint16_t> (dividend);
	}

	/**
	 * Возврат оптимизаций MSVC ARM64 после цепочки деления
	 */
	#if defined(_MSC_VER) && defined(_M_ARM64)
		/**
		 * Возвращаем оптимизации MSVC ARM64 после цепочки деления
		 */
		#pragma optimize("", on)
	#endif

	/**
	 * @brief Функция получения остатка uint32 по модулю uint14
	 *
	 * @param value   делимое
	 * @param modulus делитель
	 * @return        остаток
	 *
	 */
	static constexpr uint16_t __ants_uint32_mod_uint14__(const uint32_t value, const uint16_t modulus) noexcept {
		// Место под частное
		uint32_t quotient = 0;
		// Место под остаток
		uint16_t remainder = 0;
		// Получаем частное и остаток деления
		::__ants_uint32_divmod_uint14__(&quotient, &remainder, value, modulus);
		// Возвращаем остаток деления
		return remainder;
	}
	/**
	 * @brief Функция получения остатка int32 по модулю uint14
	 *
	 * @param value   делимое
	 * @param modulus делитель
	 * @return        остаток
	 *
	 */
	static constexpr uint16_t __ants_int32_mod_uint14__(const int32_t value, const uint16_t modulus) noexcept {
		// Приводим знаковое число к беззнаковому виду
		uint32_t magnitude = static_cast <uint32_t> (value);
		// Для отрицательного входа берём его модуль
		if(value < 0)
			// Запоминаем модуль входного числа
			magnitude = static_cast <uint32_t> (-value);
		// Получаем остаток от деления модуля
		uint16_t remainder = ::__ants_uint32_mod_uint14__(magnitude, modulus);
		// Для отрицательного входа переводим остаток в отрицательную область
		if((value < 0) && (remainder != 0))
			// Инвертируем остаток относительно модуля
			remainder = modulus - remainder;
		// Возвращаем итоговый остаток
		return remainder;
	}
	/**
	 * @brief Функция приведения по модулю 3
	 *
	 * @param value приводимое число
	 * @return      число в {-1, 0, 1}
	 *
	 */
	static constexpr small_t __ants_freeze3__(const int16_t value) noexcept {
		// Приводим число по модулю 3 к представителю в диапазоне от минус единицы до единицы
		return static_cast <small_t> (::__ants_int32_mod_uint14__(value + 1, 3) - 1);
	}
	/**
	 * @brief Функция приведения по модулю q
	 *
	 * @param value приводимое число
	 * @return      число в [-q12, q12]
	 *
	 */
	static constexpr fq_t __ants_freeze_q__(const int32_t value) noexcept {
		// Приводим число к симметричному представителю по модулю q
		return static_cast <fq_t> (::__ants_int32_mod_uint14__(value + Q12, Q) - Q12);
	}
	/**
	 * @brief Функция обращения по модулю q
	 *
	 * @param base обращаемое число
	 * @return     обратное число
	 *
	 */
	static __ANTS_INLINE__ fq_t __ants_reciprocal_q__(const fq_t base) noexcept {
		// Начинаем обращение с самого элемента
		fq_t inverse = base;
		/**
		 * Возводим элемент в степень q - 3 последовательным умножением
		 */
		for(int32_t i = 1; i < Q - 2; ++i)
			// Накапливаем произведение с приведением по модулю q
			inverse = ::__ants_freeze_q__(base * static_cast <int32_t> (inverse));
		// Возвращаем обратный элемент
		return inverse;
	}
	/**
	 * @brief Функция сортировки uint32
	 *
	 * @param array сортируемый массив
	 * @param count число элементов
	 *
	 */
	static __ANTS_INLINE__ void __ants_crypto_sort_uint32__(uint32_t * array, const size_t count) noexcept {
		// Короткие массивы сортировать не требуется
		if(count < 2)
			// Завершаем работу сразу
			return;
		// Начинаем с самой маленькой степени двойки
		size_t top = 1;
		/**
		 * Поднимаем степень двойки до половины длины массива
		 */
		while(top < count - top)
			// Удваиваем текущую степень
			top += top;
		/**
		 * Проходим по всем убывающим шагам сетки
		 */
		for(size_t stride = top; stride > 0; stride >>= 1){
			/**
			 * Проходим по элементам с текущим шагом сетки
			 */
			for(size_t i = 0; i + stride < count; ++i){
				// Отбираем пары без пересечения по биту шага
				if((i & stride) == 0){
					// Берём первый элемент пары
					const uint32_t first = array[i];
					// Берём второй элемент пары
					const uint32_t second = array[i + stride];
					// Сравниваем элементы пары между собой
					if(first > second){
						// Переставляем меньший элемент вниз
						array[i] = second;
						// Переставляем больший элемент вверх
						array[i + stride] = first;
					}
				}
			}
			/**
			 * Проходим по вложенным шагам сетки
			 */
			for(size_t inner = top; inner > stride; inner >>= 1){
				/**
				 * Проходим по элементам с вложенным шагом
				 */
				for(size_t i = 0; i + inner < count; ++i){
					// Отбираем пары с установленным битом вложенного шага
					if((i & stride) == 0 && (i & inner) != 0){
						// Берём первый элемент пары
						const uint32_t first = array[i];
						// Берём второй элемент пары
						const uint32_t second = array[i + stride];
						// Сравниваем элементы пары между собой
						if(first > second){
							// Переставляем меньший элемент вниз
							array[i] = second;
							// Переставляем больший элемент вверх
							array[i + stride] = first;
						}
					}
				}
			}
		}
	}
	/**
	 * @brief Функция получения случайного uint32
	 *
	 * @param result место, в которое помещается случайное число
	 * @return       признак успешности
	 *
	 */
	static __ANTS_INLINE__ bool __ants_urandom32__(uint32_t * result) noexcept {
		// Буфер под четыре случайных байта
		uint8_t bytes[4];
		// Заполняем буфер из генератора случайных чисел
		if(!entropy::bytes(bytes, sizeof(bytes)))
			// При сбое энтропии сообщаем об отказе
			return false;
		// Собираем число из четырёх случайных байтов от младшего к старшему
		(* result) = (
			static_cast <uint32_t> (bytes[0]) |
			(static_cast <uint32_t> (bytes[1]) << 8) |
			(static_cast <uint32_t> (bytes[2]) << 16) |
			(static_cast <uint32_t> (bytes[3]) << 24)
		);
		// Сообщаем об успешной выработке числа
		return true;
	}
	/**
	 * @brief Функция построения короткого полинома из списка
	 *
	 * @param out выходной полином
	 * @param in  входной список uint32
	 *
	 */
	static __ANTS_INLINE__ void __ants_build_short__(small_t * out, const uint32_t * in) noexcept {
		// Список пар для сортировки
		uint32_t tags[P];
		/**
		 * Помечаем первые элементы веса чётными метками
		 */
		for(size_t i = 0; i < W; ++i)
			// Сохраняем входное значение с чётной меткой
			tags[i] = in[i] & static_cast <uint32_t> (-2);
		/**
		 * Помечаем остальные элементы нечётными метками
		 */
		for(size_t i = W; i < P; ++i)
			// Сохраняем входное значение с нечётной меткой
			tags[i] = (in[i] & static_cast <uint32_t> (-3)) | 1;
		// Сортируем список меток по возрастанию
		::__ants_crypto_sort_uint32__(tags, P);
		/**
		 * Размечаем коэффициенты по младшим битам меток
		 */
		for(size_t i = 0; i < P; ++i)
			// Извлекаем знак коэффициента из метки
			out[i] = static_cast <small_t> ((tags[i] & 3) - 1);
	}
	/**
	 * @brief Функция выработки случайного короткого полинома
	 *
	 * @param out выходной полином
	 * @return    признак успешности
	 *
	 */
	static __ANTS_INLINE__ bool __ants_random_short__(small_t * out) noexcept {
		// Список случайных значений
		uint32_t tags[P];
		/**
		 * Заполняем список случайными значениями
		 */
		for(size_t i = 0; i < P; ++i){
			// Вырабатываем очередное случайное число
			if(!::__ants_urandom32__(&tags[i]))
				// При сбое энтропии сообщаем об отказе
				return false;
		}
		// Строим короткий полином из отсортированного списка
		::__ants_build_short__(out, tags);
		// Сообщаем об успешной выработке полинома
		return true;
	}
	/**
	 * @brief Функция выработки случайного малого полинома
	 *
	 * @param out выходной полином
	 * @return    признак успешности
	 *
	 */
	static __ANTS_INLINE__ bool __ants_random_small__(small_t * out) noexcept {
		/**
		 * Проходим по всем коэффициентам полинома
		 */
		for(size_t i = 0; i < P; ++i){
			// Место под случайное число
			uint32_t draw;
			// Вырабатываем очередное случайное число
			if(!::__ants_urandom32__(&draw))
				// При сбое энтропии сообщаем об отказе
				return false;
			// Преобразуем случайное число в коэффициент из диапазона от минус единицы до единицы
			out[i] = static_cast <small_t> ((((draw & 0x3fffffff) * 3) >> 30) - 1);
		}
		// Сообщаем об успешной выработке полинома
		return true;
	}
	/**
	 * @brief Функция умножения в кольце R3
	 *
	 * @param result результат
	 * @param first  первый множитель
	 * @param second второй множитель
	 *
	 */
	static __ANTS_INLINE__ void __ants_multiply3__(small_t * result, const small_t * first, const small_t * second) noexcept {
		// Буфер под произведение полной длины
		small_t product[P + P - 1];
		/**
		 * Складываем произведения по возрастанию индекса
		 */
		for(size_t i = 0; i < P; ++i){
			// Накопитель результата
			small_t result = 0;
			/**
			 * Перемножаем коэффициенты с суммой индексов
			 */
			for(size_t j = 0; j <= i; ++j)
				// Накапливаем произведение с приведением по модулю 3
				result = ::__ants_freeze3__(result + first[j] * second[i - j]);
			// Сохраняем коэффициент произведения
			product[i] = result;
		}
		/**
		 * Складываем произведения по убыванию индекса
		 */
		for(size_t i = P; i < P + P - 1; ++i){
			// Накопитель результата
			small_t result = 0;
			/**
			 * Перемножаем коэффициенты с суммой индексов
			 */
			for(size_t j = i - P + 1; j < P; ++j)
				// Накапливаем произведение с приведением по модулю 3
				result = ::__ants_freeze3__(result + first[j] * second[i - j]);
			// Сохраняем коэффициент произведения
			product[i] = result;
		}
		/**
		 * Сворачиваем старшие коэффициенты по модулю кольца
		 */
		for(size_t i = P + P - 2; i >= P; --i){
			// Добавляем старший коэффициент к младшему
			product[i - P] = ::__ants_freeze3__(product[i - P] + product[i]);
			// Добавляем старший коэффициент к следующему
			product[i - P + 1] = ::__ants_freeze3__(product[i - P + 1] + product[i]);
		}
		/**
		 * Копируем результат в выходной полином
		 */
		for(size_t i = 0; i < P; ++i)
			// Копируем коэффициент произведения
			result[i] = product[i];
	}
	/**
	 * @brief Функция обращения в кольце R3
	 *
	 * @param out обратный полином
	 * @param in  входной полином
	 * @return    0 при успехе, -1 при отказе
	 *
	 */
	static __ANTS_INLINE__ int32_t __ants_reciprocal3__(small_t * out, const small_t * in) noexcept {
		// Буферы полиномов расширенной длины
		small_t modulus[P + 1], flipped[P + 1], inverse[P + 1], bezout[P + 1];
		/**
		 * Обнуляем вспомогательный полином
		 */
		for(size_t i = 0; i < P + 1; ++i)
			// Обнуляем очередной коэффициент
			inverse[i] = 0;
		/**
		 * Обнуляем вспомогательный полином
		 */
		for(size_t i = 0; i < P + 1; ++i)
			// Обнуляем очередной коэффициент
			bezout[i] = 0;
		// Единичный коэффициент при нулевой степени
		bezout[0] = 1;
		/**
		 * Обнуляем рабочий полином
		 */
		for(size_t i = 0; i < P; ++i)
			// Обнуляем очередной коэффициент
			modulus[i] = 0;
		// Единичный коэффициент при нулевой степени
		modulus[0] = 1;
		// Записываем коэффициенты модуля кольца
		modulus[P - 1] = modulus[P] = -1;
		/**
		 * Переворачиваем входной полином
		 */
		for(size_t i = 0; i < P; ++i)
			// Копируем коэффициент с обратным индексом
			flipped[P - 1 - i] = in[i];
		// Завершаем полином нулевым коэффициентом
		flipped[P] = 0;
		// Сдвиг разности степеней
		int32_t delta = 1;
		/**
		 * Ведём итерации расширенного алгоритма Евклида
		 */
		for(size_t loop = 0; (loop < ((2 * P) - 1)); ++loop){
			/**
			 * Сдвигаем коэффициенты вспомогательного полинома
			 */
			for(size_t i = P; i > 0; --i)
				// Сдвигаем коэффициент на одну позицию
				inverse[i] = inverse[i - 1];
			// Младший коэффициент сдвига обнуляется
			inverse[0] = 0;
			// Знак ведущего коэффициента
			const int32_t sign = -flipped[0] * modulus[0];
			// Условие перестановки полиномов
			const int32_t swap = ::__ants_int16_negative_mask__(-delta) & ::__ants_int16_nonzero_mask__(flipped[0]);
			// Обновляем сдвиг при перестановке
			delta ^= (swap & (delta ^ -delta));
			// Увеличиваем сдвиг на единицу
			delta += 1;
			/**
			 * Переставляем коэффициенты полиномов по маске
			 */
			for(size_t i = 0; i < P + 1; ++i){
				// Маска перестановки первой пары
				int32_t exchange = swap & (modulus[i] ^ flipped[i]);
				// Применяем маску к первому полиному
				modulus[i] ^= exchange;
				// Применяем маску ко второму полиному
				flipped[i] ^= exchange;
				// Маска перестановки второй пары
				exchange = (swap & (inverse[i] ^ bezout[i]));
				// Применяем маску к первому вспомогательному
				inverse[i] ^= exchange;
				// Применяем маску ко второму вспомогательному
				bezout[i] ^= exchange;
			}
			/**
			 * Вычитаем полиномы с приведением по модулю 3
			 */
			for(size_t i = 0; i < P + 1; ++i)
				// Вычитаем коэффициенты с приведением
				flipped[i] = ::__ants_freeze3__(flipped[i] + sign * modulus[i]);
			/**
			 * Вычитаем вспомогательные полиномы с приведением
			 */
			for(size_t i = 0; i < P + 1; ++i)
				// Вычитаем коэффициенты с приведением
				bezout[i] = ::__ants_freeze3__(bezout[i] + sign * inverse[i]);
			/**
			 * Сдвигаем коэффициенты полинома
			 */
			for(size_t i = 0; i < P; ++i)
				// Сдвигаем коэффициент на одну позицию
				flipped[i] = flipped[i + 1];
			// Старший коэффициент сдвига обнуляется
			flipped[P] = 0;
		}
		// Знак результата обращения
		const int32_t sign = modulus[0];
		/**
		 * Разворачиваем вспомогательный полином
		 */
		for(size_t i = 0; i < P; ++i)
			// Копируем коэффициент с обратным индексом
			out[i] = sign * inverse[P - 1 - i];
		// Возвращаем признак невырожденности
		return ::__ants_int16_nonzero_mask__(delta);
	}
	/**
	 * @brief Функция умножения в кольце Rq на малый полином
	 *
	 * @param result результат
	 * @param first  первый множитель
	 * @param second второй множитель (малый)
	 *
	 */
	static __ANTS_INLINE__ void __ants_multiply_small__(fq_t * result, const fq_t * first, const small_t * second) noexcept {
		// Буфер под произведение полной длины
		fq_t product[P + P - 1];
		/**
		 * Складываем произведения по возрастанию индекса
		 */
		for(size_t i = 0; i < P; ++i){
			// Накопитель результата
			fq_t result = 0;
			/**
			 * Перемножаем коэффициенты с суммой индексов
			 */
			for(size_t j = 0; j <= i; ++j)
				// Накапливаем произведение с приведением по модулю q
				result = ::__ants_freeze_q__(result + first[j] * static_cast <int32_t> (second[i - j]));
			// Сохраняем коэффициент произведения
			product[i] = result;
		}
		/**
		 * Складываем произведения по убыванию индекса
		 */
		for(size_t i = P; i < P + P - 1; ++i){
			// Накопитель результата
			fq_t result = 0;
			/**
			 * Перемножаем коэффициенты с суммой индексов
			 */
			for(size_t j = i - P + 1; j < P; ++j)
				// Накапливаем произведение с приведением по модулю q
				result = ::__ants_freeze_q__(result + first[j] * static_cast <int32_t> (second[i - j]));
			// Сохраняем коэффициент произведения
			product[i] = result;
		}
		/**
		 * Сворачиваем старшие коэффициенты по модулю кольца
		 */
		for(size_t i = P + P - 2; i >= P; --i){
			// Добавляем старший коэффициент к младшему
			product[i - P] = ::__ants_freeze_q__(product[i - P] + product[i]);
			// Добавляем старший коэффициент к следующему
			product[i - P + 1] = ::__ants_freeze_q__(product[i - P + 1] + product[i]);
		}
		/**
		 * Копируем результат в выходной полином
		 */
		for(size_t i = 0; i < P; ++i)
			// Копируем коэффициент произведения
			result[i] = product[i];
	}
	/**
	 * @brief Функция умножения на 3 в кольце Rq
	 *
	 * @param result результат
	 * @param source входной полином
	 *
	 */
	static __ANTS_INLINE__ void __ants_triple__(fq_t * result, const fq_t * source) noexcept {
		/**
		 * Умножаем каждый коэффициент на три
		 */
		for(size_t i = 0; i < P; ++i)
			// Умножаем коэффициент с приведением по модулю q
			result[i] = ::__ants_freeze_q__(3 * source[i]);
	}
	/**
	 * @brief Функция обращения в кольце Rq с умножением на 3
	 *
	 * @param out обратный полином
	 * @param in  входной полином (малый)
	 * @return    0 при успехе, -1 при отказе
	 *
	 */
	static __ANTS_INLINE__ int32_t __ants_triple_reciprocal__(fq_t * out, const small_t * in) noexcept {
		// Буферы полиномов расширенной длины
		fq_t modulus[P + 1], flipped[P + 1], inverse[P + 1], bezout[P + 1];
		/**
		 * Обнуляем вспомогательный полином
		 */
		for(size_t i = 0; i < P + 1; ++i)
			// Обнуляем очередной коэффициент
			inverse[i] = 0;
		/**
		 * Обнуляем вспомогательный полином
		 */
		for(size_t i = 0; i < P + 1; ++i)
			// Обнуляем очередной коэффициент
			bezout[i] = 0;
		// Единичный коэффициент с учётом обратной тройки
		bezout[0] = ::__ants_reciprocal_q__(3);
		/**
		 * Обнуляем рабочий полином
		 */
		for(size_t i = 0; i < P; ++i)
			// Обнуляем очередной коэффициент
			modulus[i] = 0;
		// Единичный коэффициент при нулевой степени
		modulus[0] = 1;
		// Записываем коэффициенты модуля кольца
		modulus[P - 1] = modulus[P] = -1;
		/**
		 * Переворачиваем входной полином
		 */
		for(size_t i = 0; i < P; ++i)
			// Копируем коэффициент с обратным индексом
			flipped[P - 1 - i] = in[i];
		// Завершаем полином нулевым коэффициентом
		flipped[P] = 0;
		// Сдвиг разности степеней
		int32_t delta = 1;
		/**
		 * Ведём итерации расширенного алгоритма Евклида
		 */
		for(size_t loop = 0; (loop < ((2 * P) - 1)); ++loop){
			/**
			 * Сдвигаем коэффициенты вспомогательного полинома
			 */
			for(size_t i = P; i > 0; --i)
				// Сдвигаем коэффициент на одну позицию
				inverse[i] = inverse[i - 1];
			// Младший коэффициент сдвига обнуляется
			inverse[0] = 0;
			// Условие перестановки полиномов
			const int32_t swap = ::__ants_int16_negative_mask__(-delta) & ::__ants_int16_nonzero_mask__(flipped[0]);
			// Обновляем сдвиг при перестановке
			delta ^= (swap & (delta ^ -delta));
			// Увеличиваем сдвиг на единицу
			delta += 1;
			/**
			 * Переставляем коэффициенты полиномов по маске
			 */
			for(size_t i = 0; i < P + 1; ++i){
				// Маска перестановки первой пары
				int32_t exchange = swap & (modulus[i] ^ flipped[i]);
				// Применяем маску к первому полиному
				modulus[i] ^= exchange;
				// Применяем маску ко второму полиному
				flipped[i] ^= exchange;
				// Маска перестановки второй пары
				exchange = (swap & (inverse[i] ^ bezout[i]));
				// Применяем маску к первому вспомогательному
				inverse[i] ^= exchange;
				// Применяем маску ко второму вспомогательному
				bezout[i] ^= exchange;
			}
			// Ведущий коэффициент первого полинома
			const int32_t firstLead = modulus[0];
			// Ведущий коэффициент второго полинома
			const int32_t secondLead = flipped[0];
			/**
			 * Вычитаем полиномы с приведением по модулю q
			 */
			for(size_t i = 0; i < P + 1; ++i)
				// Вычитаем коэффициенты с приведением
				flipped[i] = ::__ants_freeze_q__(firstLead * flipped[i] - secondLead * modulus[i]);
			/**
			 * Вычитаем вспомогательные полиномы с приведением
			 */
			for(size_t i = 0; i < P + 1; ++i)
				// Вычитаем коэффициенты с приведением
				bezout[i] = ::__ants_freeze_q__(firstLead * bezout[i] - secondLead * inverse[i]);
			/**
			 * Сдвигаем коэффициенты полинома
			 */
			for(size_t i = 0; i < P; ++i)
				// Сдвигаем коэффициент на одну позицию
				flipped[i] = flipped[i + 1];
			// Старший коэффициент сдвига обнуляется
			flipped[P] = 0;
		}
		// Масштаб обратного элемента
		const fq_t scale = ::__ants_reciprocal_q__(modulus[0]);
		/**
		 * Разворачиваем вспомогательный полином
		 */
		for(size_t i = 0; i < P; ++i)
			// Копируем коэффициент с масштабированием
			out[i] = ::__ants_freeze_q__(scale * static_cast <int32_t> (inverse[P - 1 - i]));
		// Возвращаем признак невырожденности
		return ::__ants_int16_nonzero_mask__(delta);
	}
	/**
	 * @brief Функция округления полинома
	 *
	 * @param out    округлённый полином
	 * @param source входной полином
	 *
	 */
	static __ANTS_INLINE__ void __ants_round_poly__(fq_t * out, const fq_t * source) noexcept {
		/**
		 * Вычитаем остаток по модулю 3
		 */
		for(size_t i = 0; i < P; ++i)
			// Округляем коэффициент вниз
			out[i] = (source[i] - ::__ants_freeze3__(source[i]));
	}
	/**
	 * @brief Функция проверки веса малого полинома
	 *
	 * @param value проверяемый полином
	 * @return      0 если вес равен W, иначе -1
	 *
	 */
	static __ANTS_INLINE__ int32_t __ants_weight_mask__(const small_t * value) noexcept {
		// Счётчик ненулевых коэффициентов
		int32_t weight = 0;
		/**
		 * Считаем ненулевые коэффициенты
		 */
		for(size_t i = 0; i < P; ++i)
			// Добавляем младший бит коэффициента
			weight += (value[i] & 1);
		// Возвращаем маску несовпадения веса
		return ::__ants_int16_nonzero_mask__(weight - W);
	}
	/**
	 * @brief Функция преобразования из Rq в R3
	 *
	 * @param out    выходной полином R3
	 * @param source входной полином Rq
	 *
	 */
	static __ANTS_INLINE__ void __ants_reduce3__(small_t * out, const fq_t * source) noexcept {
		/**
		 * Приводим коэффициенты по модулю 3
		 */
		for(size_t i = 0; i < P; ++i)
			// Приводим коэффициент к малому виду
			out[i] = ::__ants_freeze3__(source[i]);
	}
	/**
	 * @brief Функция кодирования малого полинома
	 *
	 * @param bytes  выходной буфер
	 * @param source входной полином
	 *
	 */
	static __ANTS_INLINE__ void __ants_encode_small__(uint8_t * bytes, const small_t * source) noexcept {
		/**
		 * Проходим по четвёркам коэффициентов
		 */
		for(size_t i = 0; i < P / 4; ++i){
			// Первый коэффициент пары байт
			uint8_t byte = static_cast <uint8_t> ((* source++) + 1);
			// Второй коэффициент со сдвигом
			byte |= static_cast <uint8_t> (((* source++) + 1) << 2);
			// Третий коэффициент со сдвигом
			byte |= static_cast <uint8_t> (((* source++) + 1) << 4);
			// Четвёртый коэффициент со сдвигом
			byte |= static_cast <uint8_t> (((* source++) + 1) << 6);
			// Выкладываем собранный байт четвёрки коэффициентов
			(* bytes++) = byte;
		}
		// Выкладываем последний непарный коэффициент
		(* bytes++) = static_cast <uint8_t> ((* source++) + 1);
	}
	/**
	 * @brief Функция декодирования малого полинома
	 *
	 * @param target выходной полином
	 * @param bytes  входной буфер
	 *
	 */
	static __ANTS_INLINE__ void __ants_decode_small__(small_t * target, const uint8_t * bytes) noexcept {
		/**
		 * Проходим по четвёркам коэффициентов
		 */
		for(size_t i = 0; i < P / 4; ++i){
			// Читаем очередной байт
			uint8_t byte = *bytes++;
			// Извлекаем первый коэффициент из пары битов
			(* target++) = static_cast <small_t> ((byte & 3) - 1);
			// Переходим к следующей паре битов
			byte >>= 2;
			// Извлекаем второй коэффициент из пары битов
			(* target++) = static_cast <small_t> ((byte & 3) - 1);
			// Переходим к следующей паре битов
			byte >>= 2;
			// Извлекаем третий коэффициент из пары битов
			(* target++) = static_cast <small_t> ((byte & 3) - 1);
			// Переходим к следующей паре битов
			byte >>= 2;
			// Извлекаем четвёртый коэффициент из пары битов
			(* target++) = static_cast <small_t> ((byte & 3) - 1);
		}
		// Извлекаем последний непарный коэффициент
		(* target++) = static_cast <small_t> (((* bytes++) & 3) - 1);
	}
	/**
	 * @brief Функция кодирования массива по модулям
	 *
	 * @param out      выходной буфер
	 * @param residues входной массив
	 * @param moduli   массив модулей
	 * @param size     размер массива
	 *
	 */
	static __ANTS_INLINE__ void __ants_encode_residues__(uint8_t * out, const uint16_t * residues, const uint16_t * moduli, const size_t size) noexcept {
		// Обрабатываем вырожденный случай одиночного модуля
		if(size == 1){
			// Модуль одиночного элемента
			uint16_t modulus = moduli[0];
			// Остаток одиночного элемента
			uint16_t residue = residues[0];
			/**
			 * Выводим байты до полного покрытия модуля
			 */
			while(modulus > 1){
				// Выкладываем очередной байт одиночного остатка
				(* out++) = residue;
				// Сдвигаем остаток на байт вправо
				residue >>= 8;
				// Сдвигаем модуль на байт вправо
				modulus = ((modulus + 255) >> 8);
			}
			// Завершаем обработку вырожденного случая
			return;
		}
		// Индекс текущей пары: живёт между свёрткой и хвостом
		size_t pair = 0;
		// Буфер модулей половинной длины
		uint16_t moduliHalf[(P + 1) / 2];
		// Буфер остатков половинной длины
		uint16_t residuesHalf[(P + 1) / 2];
		/**
		 * Сворачиваем пары остатков и модулей
		 */
		for(pair = 0; (pair < (size - 1)); pair += 2){
			// Модуль первого элемента пары
			const uint32_t pairModulus = moduli[pair];
			// Свёртка модулей пары
			uint32_t modulus = (moduli[pair + 1] * pairModulus);
			// Свёртка остатков пары
			uint32_t residue = (residues[pair] + (residues[pair + 1] * pairModulus));
			/**
			 * Выводим байты до полного покрытия модуля
			 */
			while(modulus >= 16384){
				// Выкладываем очередной байт свёрнутой пары
				(* out++) = residue;
				// Сдвигаем остаток на байт вправо
				residue >>= 8;
				// Сдвигаем модуль на байт вправо
				modulus = ((modulus + 255) >> 8);
			}
			// Сохраняем свёрнутый модуль
			moduliHalf[pair / 2] = modulus;
			// Сохраняем свёрнутый остаток
			residuesHalf[pair / 2] = residue;
		}
		// Переносим хвост нечётной длины
		if(pair < size){
			// Сохраняем неразмеченный модуль
			moduliHalf[pair / 2] = moduli[pair];
			// Сохраняем неразмеченный остаток
			residuesHalf[pair / 2] = residues[pair];
		}
		// Повторяем кодирование для половинной длины
		::__ants_encode_residues__(out, residuesHalf, moduliHalf, (size + 1) / 2);
	}
	/**
	 * @brief Функция декодирования массива по модулям
	 *
	 * @param out    выходной массив
	 * @param bytes  входной буфер
	 * @param moduli массив модулей
	 * @param size   размер массива
	 *
	 */
	static __ANTS_INLINE__ void __ants_decode_residues__(uint16_t * out, const uint8_t * bytes, const uint16_t * moduli, const size_t size) noexcept {
		// Обрабатываем вырожденный случай одиночного модуля
		if(size == 1){
			// Проверяем единичность модуля
			if(moduli[0] == 1)
				// Единичный модуль даёт нулевой остаток
				(* out) = 0;
			// Иначе проверяем вместимость модуля в один байт
			else if(moduli[0] <= 256)
				// Снимаем остаток однобайтового модуля
				(* out) = ::__ants_uint32_mod_uint14__(bytes[0], moduli[0]);
			// Иначе модуль занимает два байта
			else
				// Снимаем остаток двухбайтового модуля
				(* out) = ::__ants_uint32_mod_uint14__(bytes[0] + (static_cast <uint16_t> (bytes[1]) << 8), moduli[0]);
			// Завершаем обработку вырожденного случая
			return;
		}
		// Индекс текущей пары: живёт между свёрткой и хвостом
		size_t pair = 0;
		// Буфер нижних множителей
		uint32_t bottomFactors[P / 2];
		// Буфер нижних остатков
		uint16_t bottomResidues[P / 2];
		// Буфер модулей половинной длины
		uint16_t moduliHalf[(P + 1) / 2];
		// Буфер остатков половинной длины
		uint16_t residuesHalf[(P + 1) / 2];
		/**
		 * Сворачиваем пары модулей нижнего уровня
		 */
		for(pair = 0; (pair < (size - 1)); pair += 2){
			// Свёртка модулей пары
			const uint32_t modulus = (moduli[pair] * static_cast <uint32_t> (moduli[pair + 1]));
			// Модуль пары занимает два байта
			if(modulus > (256 * 16383)){
				// Нижний множитель двухбайтовый
				bottomFactors[pair / 2] = 256 * 256;
				// Нижний остаток из двух байт
				bottomResidues[pair / 2] = (bytes[0] + (256 * bytes[1]));
				// Пропускаем два байта входа
				bytes += 2;
				// Сворачиваем модуль до двух байт
				moduliHalf[pair / 2] = (((modulus + 255) >> 8) + 255) >> 8;
			// Иначе модуль пары занимает один байт
			} else if(modulus >= 16384) {
				// Нижний множитель однобайтовый
				bottomFactors[pair / 2] = 256;
				// Нижний остаток из одного байта
				bottomResidues[pair / 2] = bytes[0];
				// Пропускаем один байт входа
				bytes += 1;
				// Сворачиваем модуль до одного байта
				moduliHalf[pair / 2] = ((modulus + 255) >> 8);
			// Иначе модуль пары укладывается в остаток без нижнего уровня
			} else {
				// Нижний множитель единичный
				bottomFactors[pair / 2] = 1;
				// Нижний остаток отсутствует
				bottomResidues[pair / 2] = 0;
				// Сохраняем модуль без свёртки
				moduliHalf[pair / 2] = modulus;
			}
		}
		// Переносим хвост нечётной длины
		if(pair < size)
			// Сохраняем последний модуль
			moduliHalf[pair / 2] = moduli[pair];
		// Повторяем декодирование для половинной длины
		::__ants_decode_residues__(residuesHalf, bytes, moduliHalf, (size + 1) / 2);
		// Нижний остаток пары
		uint32_t residue = 0;
		// Место под верхнее частное
		uint32_t upperQuotient = 0;
		// Место под верхний остаток
		uint16_t upperRemainder = 0;
		/**
		 * Разворачиваем пары остатков верхнего уровня
		 */
		for(pair = 0; pair < (size - 1); pair += 2){
			// Получаем нижний остаток пары
			residue = bottomResidues[pair / 2];
			// Восстанавливаем остаток пары
			residue += (bottomFactors[pair / 2] * residuesHalf[pair / 2]);
			// Делим восстановленный остаток
			::__ants_uint32_divmod_uint14__(&upperQuotient, &upperRemainder, residue, moduli[pair]);
			// Приводим частное по второму модулю
			upperQuotient = ::__ants_uint32_mod_uint14__(upperQuotient, moduli[pair + 1]);
			// Выкладываем остаток первого элемента пары
			(* out++) = upperRemainder;
			// Выкладываем частное второго элемента пары
			(* out++) = upperQuotient;
		}
		// Переносим хвост нечётной длины
		if(pair < size)
			// Выкладываем хвостовой элемент нечётной длины
			(* out++) = residuesHalf[pair / 2];
	}
	/**
	 * @brief Функция кодирования полинома Rq
	 *
	 * @param bytes  выходной буфер
	 * @param values входной полином
	 *
	 */
	static __ANTS_INLINE__ void __ants_encode_q__(uint8_t * bytes, const fq_t * values) noexcept {
		// Буферы остатков и модулей
		uint16_t residues[P], moduli[P];
		/**
		 * Переводим коэффициенты в беззнаковый вид
		 */
		for(size_t i = 0; i < P; ++i)
			// Сдвигаем коэффициент на половину модуля
			residues[i] = values[i] + Q12;
		/**
		 * Заполняем модули коэффициентов
		 */
		for(size_t i = 0; i < P; ++i)
			// Сохраняем модуль очередного коэффициента
			moduli[i] = Q;
		// Кодируем массив остатков по модулям
		::__ants_encode_residues__(bytes, residues, moduli, P);
	}
	/**
	 * @brief Функция декодирования полинома Rq
	 *
	 * @param values выходной полином
	 * @param bytes  входной буфер
	 *
	 */
	static __ANTS_INLINE__ void __ants_decode_q__(fq_t * values, const uint8_t * bytes) noexcept {
		// Буферы остатков и модулей
		uint16_t residues[P], moduli[P];
		/**
		 * Заполняем модули коэффициентов
		 */
		for(size_t i = 0; i < P; ++i)
			// Сохраняем модуль очередного коэффициента
			moduli[i] = Q;
		// Декодируем массив остатков по модулям
		::__ants_decode_residues__(residues, bytes, moduli, P);
		/**
		 * Возвращаем симметричное представление
		 */
		for(size_t i = 0; i < P; ++i)
			// Сдвигаем коэффициент обратно
			values[i] = static_cast <fq_t> (residues[i]) - Q12;
	}
	/**
	 * @brief Функция кодирования округлённого полинома
	 *
	 * @param bytes  выходной буфер
	 * @param values входной полином
	 *
	 */
	static __ANTS_INLINE__ void __ants_encode_rounded__(uint8_t * bytes, const fq_t * values) noexcept {
		// Буферы остатков и модулей
		uint16_t residues[P], moduli[P];
		/**
		 * Масштабируем коэффициенты на треть модуля
		 */
		for(size_t i = 0; i < P; ++i)
			// Умножаем коэффициент на треть модуля
			residues[i] = ((values[i] + Q12) * 10923) >> 15;
		/**
		 * Заполняем округлённые модули
		 */
		for(size_t i = 0; i < P; ++i)
			// Сохраняем округлённый модуль
			moduli[i] = (Q + 2) / 3;
		// Кодируем округлённый массив по модулям
		::__ants_encode_residues__(bytes, residues, moduli, P);
	}
	/**
	 * @brief Функция декодирования округлённого полинома
	 *
	 * @param values выходной полином
	 * @param bytes  входной буфер
	 *
	 */
	static __ANTS_INLINE__ void __ants_decode_rounded__(fq_t * values, const uint8_t * bytes) noexcept {
		// Буферы остатков и модулей
		uint16_t residues[P], moduli[P];
		/**
		 * Заполняем округлённые модули
		 */
		for(size_t i = 0; i < P; ++i)
			// Сохраняем округлённый модуль
			moduli[i] = (Q + 2) / 3;
		// Декодируем округлённый массив по модулям
		::__ants_decode_residues__(residues, bytes, moduli, P);
		/**
		 * Восстанавливаем коэффициенты из округления
		 */
		for(size_t i = 0; i < P; ++i)
			// Умножаем остаток на три и сдвигаем
			values[i] = residues[i] * 3 - Q12;
	}
	/**
	 * @brief Функция хеширования с префиксом
	 *
	 * @param out    выходной буфер (32 байта)
	 * @param prefix префикс
	 * @param in     входные данные
	 * @param size   размер входных данных
	 *
	 */
	static __ANTS_INLINE__ void __ants_hash_prefix__(uint8_t * out, const uint8_t prefix, const uint8_t * in, const size_t size) noexcept {
		// Буфер под хеш
		uint8_t hash[64];
		// Буфер префикса и входных данных
		uint8_t buffer[SMALL_BYTES + RQ_BYTES + 1];
		// Записываем префикс в начало буфера
		buffer[0] = prefix;
		/**
		 * Копируем входные данные после префикса
		 */
		for(size_t i = 0; i < size; ++i)
			// Копируем очередной байт входа
			buffer[i + 1] = in[i];
		// Инициализируем хеш SHA512
		digest::Sha2 sha(digest::sha_t::SHA512);
		// Обновляем хеш данными буфера
		sha.update(view_t(buffer, size + 1));
		// Завершаем выработку хеша
		sha.finish(hash, sizeof(hash));
		/**
		 * Копируем первые 32 байта хеша
		 */
		for(size_t i = 0; i < 32; ++i)
			// Копируем очередной байт хеша
			out[i] = hash[i];
		// Затираем буфер под хеш
		wipe(hash, sizeof(hash));
		// Затираем буфер входных данных
		wipe(buffer, sizeof(buffer));
	}
	/**
	 * @brief Функция выработки ключей ядра
	 *
	 * @param publicPoly открытый ключ h
	 * @param secret     секретный полином f
	 * @param inverse    обратный к случайному полиному g в R3
	 * @return           признак успешности
	 *
	 */
	static __ANTS_INLINE__ bool __ants_generate_keys__(fq_t * publicPoly, small_t * secret, small_t * inverse) noexcept {
		// Случайный полином g
		small_t random[P];
		// Утроенный обратный 3/f в кольце Rq
		fq_t secretInverse[P];
		/**
		 * Повторяем пока g не обратим в кольце R3
		 */
		for(;;){
			// Вырабатываем случайный малый полином
			if(!::__ants_random_small__(random))
				// Сообщаем об ошибке генерации
				return false;
			// Проверяем обратимость g в кольце R3: найденный обратный сразу сохраняем
			if(::__ants_reciprocal3__(inverse, random) == 0)
				// Полином g обратим - выходим из перебора
				break;
		}
		// Вырабатываем случайный короткий полином
		if(!::__ants_random_short__(secret))
			// Сообщаем об ошибке генерации
			return false;
		// Находим утроенный обратный 3/f в кольце Rq
		::__ants_triple_reciprocal__(secretInverse, secret);
		// Вычисляем открытый ключ h = 3·g/f
		::__ants_multiply_small__(publicPoly, secretInverse, random);
		// Затираем случайный полином g
		wipe(random, sizeof(random));
		// Затираем утроенный обратный 3/f
		wipe(secretInverse, sizeof(secretInverse));
		// Сообщаем об успешной выработке пары
		return true;
	}
	/**
	 * @brief Функция шифрования ядра
	 *
	 * @param cipher     шифртекст
	 * @param input      входной полином
	 * @param publicPoly открытый ключ
	 *
	 */
	static __ANTS_INLINE__ void __ants_encrypt__(fq_t * cipher, const small_t * input, const fq_t * publicPoly) noexcept {
		// Буфер произведения ключа на вход
		fq_t product[P];
		// Умножаем открытый ключ на вход
		::__ants_multiply_small__(product, publicPoly, input);
		// Округляем произведение в шифртекст
		::__ants_round_poly__(cipher, product);
	}
	/**
	 * @brief Функция расшифрования ядра
	 *
	 * @param output  выходной полином
	 * @param cipher  шифртекст
	 * @param secret  секретный полином f
	 * @param inverse обратный к случайному полиному g в R3
	 *
	 */
	static __ANTS_INLINE__ void __ants_decrypt__(small_t * output, const fq_t * cipher, const small_t * secret, const small_t * inverse) noexcept {
		// Буфер произведения шифртекста на f
		fq_t product[P];
		// Буфер утроенного произведения
		fq_t tripled[P];
		// Буфер полинома в кольце R3
		small_t reduced[P];
		// Буфер произведения в кольце R3
		small_t product3[P];
		// Умножаем шифртекст на секретный полином
		::__ants_multiply_small__(product, cipher, secret);
		// Утраиваем произведение в кольце Rq
		::__ants_triple__(tripled, product);
		// Переводим результат в кольцо R3
		::__ants_reduce3__(reduced, tripled);
		// Умножаем на обратный полином в кольце R3
		::__ants_multiply3__(product3, reduced, inverse);
		// Проверяем вес восстановленного полинома
		const int32_t mask = ::__ants_weight_mask__(product3);
		/**
		 * Маскируем коэффициенты по результату проверки веса
		 */
		for(size_t i = 0; i < W; ++i)
			// Снимаем маску с ненулевого коэффициента
			output[i] = ((product3[i] ^ 1) & ~mask) ^ 1;
		/**
		 * Обнуляем хвостовые коэффициенты при несовпадении веса
		 */
		for(size_t i = W; i < P; ++i)
			// Пропускаем коэффициент через маску
			output[i] = product3[i] & ~mask;
		// Затираем произведение шифртекста
		wipe(product, sizeof(product));
		// Затираем утроенное произведение
		wipe(tripled, sizeof(tripled));
		// Затираем полином в кольце R3
		wipe(reduced, sizeof(reduced));
		// Затираем произведение в кольце R3
		wipe(product3, sizeof(product3));
	}
	/**
	 * @brief Функция выработки ключей в закодированном виде
	 *
	 * @param publicKey открытый ключ
	 * @param secretKey секретный ключ
	 * @return          признак успешности
	 *
	 */
	static __ANTS_INLINE__ bool __ants_generate_keys_encoded__(uint8_t * publicKey, uint8_t * secretKey) noexcept {
		// Буфер открытого ключа
		fq_t publicPoly[P];
		// Буферы секретных полиномов
		small_t secret[P], inverse[P];
		// Вырабатываем пару ключей ядра
		if(!::__ants_generate_keys__(publicPoly, secret, inverse))
			// Сообщаем об ошибке генерации
			return false;
		// Кодируем открытый ключ
		::__ants_encode_q__(publicKey, publicPoly);
		// Кодируем секретный полином
		::__ants_encode_small__(secretKey, secret);
		// Сдвигаем буфер за первый полином
		secretKey += SMALL_BYTES;
		// Кодируем обратный полином
		::__ants_encode_small__(secretKey, inverse);
		// Затираем секретный ключ
		wipe(secret, sizeof(secret));
		// Затираем обратный полином
		wipe(inverse, sizeof(inverse));
		// Затираем открытый ключ
		wipe(publicPoly, sizeof(publicPoly));
		// Сообщаем об успешности
		return true;
	}
	/**
	 * @brief Функция шифрования в закодированном виде
	 *
	 * @param cipherOut шифртекст
	 * @param input     входной полином
	 * @param publicKey открытый ключ
	 *
	 */
	static __ANTS_INLINE__ void __ants_encrypt_encoded__(uint8_t * cipherOut, const small_t * input, const uint8_t * publicKey) noexcept {
		// Буфер открытого ключа
		fq_t publicPoly[P];
		// Буфер шифртекста
		fq_t cipherPoly[P];
		// Декодируем открытый ключ
		::__ants_decode_q__(publicPoly, publicKey);
		// Шифруем вход открытым ключом
		::__ants_encrypt__(cipherPoly, input, publicPoly);
		// Кодируем округлённый шифртекст
		::__ants_encode_rounded__(cipherOut, cipherPoly);
		// Затираем открытый ключ
		wipe(publicPoly, sizeof(publicPoly));
		// Затираем шифртекст
		wipe(cipherPoly, sizeof(cipherPoly));
	}
	/**
	 * @brief Функция расшифрования закодированного шифртекста
	 *
	 * @param output    выходной полином
	 * @param cipher    шифртекст
	 * @param secretKey секретный ключ
	 *
	 */
	static __ANTS_INLINE__ void __ants_decrypt_encoded__(small_t * output, const uint8_t * cipher, const uint8_t * secretKey) noexcept {
		// Буфер шифртекста
		fq_t cipherPoly[P];
		// Буферы секретных полиномов
		small_t secret[P], inverse[P];
		// Декодируем секретный полином
		::__ants_decode_small__(secret, secretKey);
		// Сдвигаем буфер за первый полином
		secretKey += SMALL_BYTES;
		// Декодируем обратный полином
		::__ants_decode_small__(inverse, secretKey);
		// Декодируем округлённый шифртекст
		::__ants_decode_rounded__(cipherPoly, cipher);
		// Расшифровываем шифртекст
		::__ants_decrypt__(output, cipherPoly, secret, inverse);
		// Затираем секретный полином
		wipe(secret, sizeof(secret));
		// Затираем обратный полином
		wipe(inverse, sizeof(inverse));
		// Затираем шифртекст
		wipe(cipherPoly, sizeof(cipherPoly));
	}
	/**
	 * @brief Функция вычисления хеша подтверждения
	 *
	 * @param hash  выходной буфер
	 * @param input входной полином (закодированный)
	 * @param cache кэш Hash4(pk)
	 *
	 */
	static __ANTS_INLINE__ void __ants_hash_confirm__(uint8_t * hash, const uint8_t * input, const uint8_t * cache) noexcept {
		// Буфер хеша входа и кэша
		uint8_t buffer[HASH_BYTES * 2];
		// Вычисляем хеш входного полинома
		::__ants_hash_prefix__(buffer, 3, input, SMALL_BYTES);
		/**
		 * Дописываем кэш открытого ключа
		 */
		for(size_t i = 0; i < HASH_BYTES; ++i)
			// Копируем очередной байт кэша
			buffer[HASH_BYTES + i] = cache[i];
		// Вычисляем итоговый хеш подтверждения
		::__ants_hash_prefix__(hash, 2, buffer, sizeof(buffer));
		// Затираем буфер хеша
		wipe(buffer, sizeof(buffer));
	}
	/**
	 * @brief Функция вычисления хеша сессии
	 *
	 * @param key    выходной буфер
	 * @param prefix префикс
	 * @param input  первый вход
	 * @param tail   шифртекст с подтверждением
	 *
	 */
	static __ANTS_INLINE__ void __ants_hash_session__(uint8_t * key, const uint8_t prefix, const uint8_t * input, const uint8_t * tail) noexcept {
		// Буфер хеша входа и шифртекста
		uint8_t buffer[HASH_BYTES + ROUNDED_BYTES + HASH_BYTES];
		// Вычисляем хеш входного полинома
		::__ants_hash_prefix__(buffer, 3, input, SMALL_BYTES);
		/**
		 * Дописываем шифртекст и его хеш
		 */
		for(size_t i = 0; i < ROUNDED_BYTES + HASH_BYTES; ++i)
			// Копируем очередной байт
			buffer[HASH_BYTES + i] = tail[i];
		// Вычисляем итоговый хеш сессии
		::__ants_hash_prefix__(key, prefix, buffer, sizeof(buffer));
		// Затираем буфер хеша
		wipe(buffer, sizeof(buffer));
	}
	/**
	 * @brief Функция сокрытия входа
	 *
	 * @param cipher    шифртекст
	 * @param inputEnc  закодированный вход
	 * @param input     входной полином
	 * @param publicKey открытый ключ
	 * @param cache     кэш Hash4(pk)
	 *
	 */
	static __ANTS_INLINE__ void __ants_hide__(uint8_t * cipher, uint8_t * inputEnc, const small_t * input, const uint8_t * publicKey, const uint8_t * cache) noexcept {
		// Кодируем входной полином
		::__ants_encode_small__(inputEnc, input);
		// Шифруем вход открытым ключом
		::__ants_encrypt_encoded__(cipher, input, publicKey);
		// Сдвигаем буфер за шифртекст
		cipher += ROUNDED_BYTES;
		// Дописываем хеш подтверждения
		::__ants_hash_confirm__(cipher, inputEnc, cache);
	}
	/**
	 * @brief Функция сравнения шифртекстов
	 *
	 * @param first  первый шифртекст
	 * @param second второй шифртекст
	 * @return       0 при совпадении, -1 при различии
	 *
	 */
	static __ANTS_INLINE__ int32_t __ants_diff_mask__(const uint8_t * first, const uint8_t * second) noexcept {
		// Накапливаем различающиеся биты
		uint16_t differentBits = 0;
		// Длина сравниваемой части шифртекста
		size_t size = (ROUNDED_BYTES + HASH_BYTES);
		/**
		 * Складываем различающиеся биты всех байтов
		 */
		while(size-- > 0)
			// Накапливаем различающиеся биты
			differentBits |= ((*first++) ^ (*second++));
		// Возвращаем маску совпадения шифртекстов
		return ((1 & ((differentBits - 1) >> 8)) - 1);
	}
};

/**
 * @brief Функция выработки пары ключей sntrup761
 *
 * @param key    место, в которое помещается открытый ключ длиной SNTRUP761_PUBLIC
 * @param secret место, в которое помещается секретный ключ длиной SNTRUP761_SECRET
 * @return       признак успешности выработки пары ключей
 *
 */
bool nts::agreement::pair(uint8_t * key, uint8_t * secret) noexcept {
	// Проверяем указатели
	if(key == nullptr || secret == nullptr)
		// Отклоняем вызов с нулевыми указателями
		return false;
	// Вырабатываем ключи в закодированном виде
	if(!::__ants_generate_keys_encoded__(key, secret))
		// Сообщаем об ошибке генерации ключей
		return false;
	// Дописываем открытый ключ в секретный
	uint8_t * tail = (secret + 2 * SMALL_BYTES);
	/**
	 * Копируем открытый ключ в хвост секретного
	 */
	for(size_t i = 0; i < RQ_BYTES; ++i)
		// Копируем очередной байт ключа
		(* tail++) = key[i];
	// Дописываем случайное зерно rho
	if(!entropy::bytes(tail, SMALL_BYTES)){
		// Затираем секретный ключ при отказе
		wipe(secret, SNTRUP761_SECRET);
		// Сообщаем об ошибке генерации зерна
		return false;
	}
	// Вычисляем кэш хеша открытого ключа
	tail += SMALL_BYTES;
	// Дописываем кэш Hash4(pk)
	::__ants_hash_prefix__(tail, 4, key, RQ_BYTES);
	// Сообщаем об успешности
	return true;
}
/**
 * @brief Функция инкапсуляции общего секрета sntrup761
 *
 * @param key    открытый ключ встречной стороны длиной SNTRUP761_PUBLIC
 * @param cipher место, в которое помещается шифртекст длиной SNTRUP761_CIPHERTEXT
 * @param shared место, в которое помещается общий секрет длиной SNTRUP761_SHARED
 * @return       признак успешности инкапсуляции
 *
 */
bool nts::agreement::encaps(const view_t & key, uint8_t * cipher, uint8_t * shared) noexcept {
	// Проверяем параметры
	if(key.data == nullptr || key.size != SNTRUP761_PUBLIC || cipher == nullptr || shared == nullptr)
		// Отклоняем вызов с неверными параметрами
		return false;
	// Вырабатываем случайный вход
	small_t input[P];
	// Вырабатываем случайный короткий вход
	if(!::__ants_random_short__(input))
		// Сообщаем об ошибке генерации входа
		return false;
	// Вычисляем кэш Hash4(pk)
	uint8_t cache[HASH_BYTES];
	// Заполняем кэш хешем открытого ключа
	::__ants_hash_prefix__(cache, 4, key.data, RQ_BYTES);
	// Скрываем вход
	uint8_t inputEnc[SMALL_BYTES];
	// Скрываем вход в шифртексте
	::__ants_hide__(cipher, inputEnc, input, key.data, cache);
	// Вычисляем общий секрет
	::__ants_hash_session__(shared, 1, inputEnc, cipher);
	/**
	 * Затираем промежуточные данные
	 */
	wipe(input, sizeof(input));
	wipe(cache, sizeof(cache));
	wipe(inputEnc, sizeof(inputEnc));
	// Сообщаем об успешности
	return true;
}
/**
 * @brief Функция декапсуляции общего секрета sntrup761
 *
 * @param cipher шифртекст длиной SNTRUP761_CIPHERTEXT
 * @param secret секретный ключ длиной SNTRUP761_SECRET
 * @param shared место, в которое помещается общий секрет длиной SNTRUP761_SHARED
 * @return       признак успешности декапсуляции (ложь при подмене шифртекста)
 *
 */
bool nts::agreement::decaps(const view_t & cipher, const view_t & secret, uint8_t * shared) noexcept {
	// Проверяем параметры
	if(cipher.data == nullptr || cipher.size != SNTRUP761_CIPHERTEXT ||
	   secret.data == nullptr || secret.size != SNTRUP761_SECRET || shared == nullptr)
		// Отклоняем вызов с неверными параметрами
		return false;
	// Извлекаем части секретного ключа
	const uint8_t * publicKey = secret.data + 2 * SMALL_BYTES;
	// Извлекаем указатель зерна rho
	const uint8_t * rho = publicKey + RQ_BYTES;
	// Извлекаем указатель кэша
	const uint8_t * cache = rho + SMALL_BYTES;
	// Расшифровываем вход
	small_t input[P];
	// Расшифровываем шифртекст секретным ключом
	::__ants_decrypt_encoded__(input, cipher.data, secret.data);
	// Скрываем вход повторно для проверки
	uint8_t inputEnc[SMALL_BYTES];
	// Буфер повторно скрытого входа
	uint8_t retry[ROUNDED_BYTES + HASH_BYTES];
	// Скрываем вход повторно для проверки
	::__ants_hide__(retry, inputEnc, input, publicKey, cache);
	// Сравниваем шифртексты
	const int32_t mask = ::__ants_diff_mask__(cipher.data, retry);
	/**
	 * При несовпадении подставляем rho вместо input
	 */
	for(size_t i = 0; i < SMALL_BYTES; ++i)
		// Подменяем вход зерном при несовпадении
		inputEnc[i] ^= mask & (inputEnc[i] ^ rho[i]);
	// Вычисляем общий секрет
	::__ants_hash_session__(shared, 1 + mask, inputEnc, cipher.data);
	/**
	 * Затираем промежуточные данные
	 */
	wipe(input, sizeof(input));
	wipe(retry, sizeof(retry));
	wipe(inputEnc, sizeof(inputEnc));
	// Возвращаем признак совпадения шифртекстов
	return mask == 0;
}
