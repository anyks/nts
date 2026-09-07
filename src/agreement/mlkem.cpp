/**
 * @file mlkem.cpp
 * @date 2026-09-07
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
 * @brief Модуль инкапсуляции ключа на решётках ML-KEM по FIPS 203
 *
 * @details Кольцо Z_q[X]/(X^256 + 1) при q = 3329; многочлены держатся массивами в 256
 *          коэффициентов из диапазона [0, q). Умножение идёт в области NTT по алгоритмам
 *          9-12 стандарта с таблицей степеней ζ = 17 в порядке BitRev7. Три набора
 *          параметров различаются размерностью k, параметрами η и разрядностью сжатия
 *
 * @section Намеренные решения
 *
 * 1. Приведение по модулю делается редукцией Барретта с условным вычитанием по маске:
 *    ни ветвления, ни обращения к памяти по секретному значению. Умножения 16-разрядных
 *    коэффициентов держатся в 32 разрядах, переполнения нет.
 *
 * 2. Таблица степеней ζ считается один раз при первом обращении, а не выписывается
 *    числами: так она сверяется с определением стандарта, а не с чьей-то распечаткой.
 *
 * 3. Ключ декапсуляции держится полной записью стандарта dk_PKE || ek || H(ek) || z:
 *    так его выдаёт и принимает всякая иная реализация, а хеш внутри записи позволяет
 *    проверять ключ по разделу 7.3 без пересчёта.
 *
 * 4. Сравнение шифртекстов при декапсуляции и выбор между настоящим и неявно отвергнутым
 *    секретом идут по маске за постоянное время: иначе разница во времени выдавала бы
 *    исход проверки, на чём стоят атаки на решёточные схемы.
 *
 * 5. Вся рабочая память лежит на стеке: у ML-KEM-1024 матрица занимает восемь килобайтов,
 *    и ни один шаг не занимает память кучи, оттого методы не могут ответить нехваткой.
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <agreement/mlkem.hpp>
#include <digest/sha3.hpp>
#include <entropy/entropy.hpp>
#include <sys/wipe.hpp>

/**
 * @brief Служебные объекты модуля
 *
 */
namespace {
	/**
	 * Подписываемся на пространство имён библиотеки
	 */
	using namespace nts;
	/**
	 * Подписываемся на метод затирания памяти
	 */
	using nts::sys::wipe;
	/**
	 * Модуль кольца
	 */
	static constexpr int32_t Q = 3329;
	/**
	 * Число коэффициентов многочлена
	 */
	static constexpr size_t N = 256;
	/**
	 * Наибольшая размерность модуля
	 */
	static constexpr size_t K = 4;
	/**
	 * Длина записи многочлена по двенадцать разрядов на коэффициент
	 */
	static constexpr size_t POLY = 384;
	/**
	 * Длина зерна ρ, σ и хешей
	 */
	static constexpr size_t SEED = 32;
	/**
	 * Обратное к 128 по модулю q: множитель обратного преобразования
	 */
	static constexpr int32_t INVERSE = 3303;
	/**
	 * @brief Многочлен кольца
	 *
	 */
	typedef struct Poly {
		// Коэффициенты многочлена
		int16_t values[N];
	} poly_t;
	/**
	 * @brief Описание набора параметров
	 *
	 */
	typedef struct Sample {
		// Размерность модуля
		size_t k;
		// Параметр η1 выборки секрета
		size_t eta1;
		// Параметр η2 выборки шума
		size_t eta2;
		// Разрядность сжатия вектора u
		size_t du;
		// Разрядность сжатия многочлена v
		size_t dv;
	} sample_t;
	/**
	 * @brief Метод получения описания набора параметров
	 *
	 * @param kem набор параметров
	 *
	 * @return    описание набора либо описание с нулевой размерностью
	 *
	 */
	static sample_t describe(const agreement::kem_t kem) noexcept {
		// Описание набора параметров
		sample_t result = {0, 0, 0, 0, 0};
		/**
		 * Определяем набор параметров
		 */
		switch(static_cast <uint8_t> (kem)){
			// ML-KEM-512
			case static_cast <uint8_t> (agreement::kem_t::MLKEM512):
				// Заполняем описание
				result = {2, 3, 2, 10, 4};
			break;
			// ML-KEM-768
			case static_cast <uint8_t> (agreement::kem_t::MLKEM768):
				// Заполняем описание
				result = {3, 2, 2, 10, 4};
			break;
			// ML-KEM-1024
			case static_cast <uint8_t> (agreement::kem_t::MLKEM1024):
				// Заполняем описание
				result = {4, 2, 2, 11, 5};
			break;
		}
		// Выводим описание набора
		return result;
	}
	/**
	 * @brief Метод приведения числа по модулю q редукцией Барретта
	 *
	 * @param value приводимое число из диапазона [-q·2^15, q·2^15)
	 *
	 * @return      число из диапазона [0, q)
	 *
	 */
	static inline int16_t reduce(const int32_t value) noexcept {
		// Частное по Барретту: 2^26 / q округлённо
		const int32_t quotient = static_cast <int32_t> ((static_cast <int64_t> (value) * 20159) >> 26);
		// Остаток после вычитания произведения частного
		int32_t result = (value - (quotient * Q));
		// Прибавляем модуль, если остаток отрицателен
		result += (Q & (result >> 31));
		// Вычитаем модуль, если остаток не меньше его
		result -= (Q & (((Q - 1) - result) >> 31));
		// Выводим приведённое число
		return static_cast <int16_t> (result);
	}
	/**
	 * @brief Метод умножения двух коэффициентов по модулю q
	 *
	 * @param first  первый множитель
	 * @param second второй множитель
	 *
	 * @return       произведение из диапазона [0, q)
	 *
	 */
	static inline int16_t product(const int32_t first, const int32_t second) noexcept {
		// Выводим приведённое произведение
		return reduce(first * second);
	}
	/**
	 * @brief Таблицы степеней ζ = 17: по BitRev7 для бабочек и нечётные для умножения пар
	 *
	 */
	typedef struct Tables {
		// Степени ζ^BitRev7(i) для бабочек преобразования
		int16_t zetas[128];
		// Степени ζ^(2·BitRev7(2i)+1) для умножения пар коэффициентов: группа i из двух пар с противоположными степенями
		int16_t gammas[64];
		/**
		 * @brief Конструктор: таблицы считаются по определению стандарта
		 *
		 */
		Tables() noexcept {
			/**
			 * Выполняем перебор мест таблиц
			 */
			for(size_t i = 0; i < 128; i++){
				// Обращённая запись места в семь разрядов
				size_t reversed = 0;
				/**
				 * Выполняем обращение разрядов
				 */
				for(size_t bit = 0; bit < 7; bit++)
					// Переносим разряд на зеркальное место
					reversed |= (((i >> bit) & 1) << (6 - bit));
				// Степень ζ, накапливаемая умножением
				int32_t power = 1;
				/**
				 * Выполняем возведение в степень
				 */
				for(size_t j = 0; j < reversed; j++)
					// Умножаем на ζ = 17
					power = product(power, 17);
				// Записываем степень бабочки
				this->zetas[i] = static_cast <int16_t> (power);
				// Если место в пределах таблицы умножения пар
				if(i < 64)
					// Записываем степень ζ^(2·BitRev7(2i)+1) = ζ^(BitRev7(i)+1) пары с номером 2i
					this->gammas[i] = product(power, 17);
			}
		}
	} tables_t;
	/**
	 * @brief Метод получения таблиц степеней ζ
	 *
	 * @return таблицы, заполненные при первом обращении
	 *
	 */
	static const tables_t & tables() noexcept {
		// Таблицы степеней, заполняемые при первом обращении
		static const tables_t result;
		// Выводим таблицы
		return result;
	}
	/**
	 * @brief Метод прямого преобразования NTT многочлена
	 *
	 * @param poly преобразуемый многочлен
	 *
	 */
	static void forward(poly_t & poly) noexcept {
		// Таблица степеней ζ
		const int16_t * table = tables().zetas;
		// Место в таблице степеней
		size_t index = 1;
		/**
		 * Выполняем перебор длин бабочек
		 */
		for(size_t length = 128; length >= 2; length /= 2){
			/**
			 * Выполняем перебор начал участков
			 */
			for(size_t start = 0; start < N; start += (2 * length)){
				// Степень ζ участка
				const int32_t zeta = table[index++];
				/**
				 * Выполняем перебор пар участка
				 */
				for(size_t j = start; j < (start + length); j++){
					// Произведение степени и второго коэффициента пары
					const int32_t t = product(zeta, poly.values[j + length]);
					// Разность пары
					poly.values[j + length] = reduce(poly.values[j] - t);
					// Сумма пары
					poly.values[j] = reduce(poly.values[j] + t);
				}
			}
		}
	}
	/**
	 * @brief Метод обратного преобразования NTT многочлена
	 *
	 * @param poly преобразуемый многочлен
	 *
	 */
	static void inverse(poly_t & poly) noexcept {
		// Таблица степеней ζ
		const int16_t * table = tables().zetas;
		// Место в таблице степеней
		size_t index = 127;
		/**
		 * Выполняем перебор длин бабочек
		 */
		for(size_t length = 2; length <= 128; length *= 2){
			/**
			 * Выполняем перебор начал участков
			 */
			for(size_t start = 0; start < N; start += (2 * length)){
				// Степень ζ участка
				const int32_t zeta = table[index--];
				/**
				 * Выполняем перебор пар участка
				 */
				for(size_t j = start; j < (start + length); j++){
					// Первый коэффициент пары
					const int32_t t = poly.values[j];
					// Сумма пары
					poly.values[j] = reduce(t + poly.values[j + length]);
					// Произведение степени и разности пары
					poly.values[j + length] = product(zeta, poly.values[j + length] - t);
				}
			}
		}
		/**
		 * Выполняем перебор коэффициентов
		 */
		for(size_t i = 0; i < N; i++)
			// Умножаем на обратное к 128
			poly.values[i] = product(poly.values[i], INVERSE);
	}
	/**
	 * @brief Метод умножения двух многочленов в области NTT с накоплением
	 *
	 * @param first  первый множитель
	 * @param second второй множитель
	 * @param result накопитель произведения
	 *
	 */
	static void accumulate(const poly_t & first, const poly_t & second, poly_t & result) noexcept {
		// Таблица степеней умножения пар
		const int16_t * table = tables().gammas;
		/**
		 * Выполняем перебор пар коэффициентов
		 */
		for(size_t i = 0; i < 64; i++){
			// Степень группы: у первой пары прямая, у второй противоположная
			const int32_t gamma = table[i];
			/**
			 * Выполняем перебор двух пар с противоположными степенями
			 */
			for(size_t half = 0; half < 2; half++){
				// Место первой из пары
				const size_t at = (4 * i) + (2 * half);
				// Степень пары: у второй половины противоположная
				const int32_t sign = ((half == 0) ? gamma : (Q - gamma));
				// Коэффициенты первого множителя
				const int32_t a0 = first.values[at], a1 = first.values[at + 1];
				// Коэффициенты второго множителя
				const int32_t b0 = second.values[at], b1 = second.values[at + 1];
				// Произведение старших коэффициентов
				const int32_t high = product(a1, b1);
				// Младший коэффициент произведения
				result.values[at] = reduce(result.values[at] + product(a0, b0) + product(high, sign));
				// Старший коэффициент произведения
				result.values[at + 1] = reduce(result.values[at + 1] + product(a0, b1) + product(a1, b0));
			}
		}
	}
	/**
	 * @brief Метод записи многочлена по двенадцать разрядов на коэффициент
	 *
	 * @param poly   записываемый многочлен
	 * @param result место, в которое помещаются 384 байта записи
	 *
	 */
	static void encode(const poly_t & poly, uint8_t * result) noexcept {
		/**
		 * Выполняем перебор пар коэффициентов
		 */
		for(size_t i = 0; i < (N / 2); i++){
			// Первый коэффициент пары
			const uint16_t first = static_cast <uint16_t> (poly.values[2 * i]);
			// Второй коэффициент пары
			const uint16_t second = static_cast <uint16_t> (poly.values[(2 * i) + 1]);
			// Младшие восемь разрядов первого
			result[3 * i] = static_cast <uint8_t> (first);
			// Старшие четыре разряда первого и младшие четыре второго
			result[(3 * i) + 1] = static_cast <uint8_t> ((first >> 8) | (second << 4));
			// Старшие восемь разрядов второго
			result[(3 * i) + 2] = static_cast <uint8_t> (second >> 4);
		}
	}
	/**
	 * @brief Метод разбора многочлена по двенадцать разрядов на коэффициент
	 *
	 * @param data 384 байта записи
	 * @param poly место, в которое помещается многочлен
	 *
	 * @return     признак того, что всякий коэффициент лежит в диапазоне модуля
	 *
	 */
	static bool decode(const uint8_t * data, poly_t & poly) noexcept {
		// Накопитель признака выхода за модуль
		uint16_t overflow = 0;
		/**
		 * Выполняем перебор пар коэффициентов
		 */
		for(size_t i = 0; i < (N / 2); i++){
			// Первый коэффициент пары
			const uint16_t first = static_cast <uint16_t> (data[3 * i] | ((data[(3 * i) + 1] & 0x0F) << 8));
			// Второй коэффициент пары
			const uint16_t second = static_cast <uint16_t> ((data[(3 * i) + 1] >> 4) | (data[(3 * i) + 2] << 4));
			// Накапливаем признак выхода за модуль
			overflow |= (static_cast <uint16_t> ((Q - 1) - first) >> 15) | (static_cast <uint16_t> ((Q - 1) - second) >> 15);
			// Записываем первый коэффициент
			poly.values[2 * i] = static_cast <int16_t> (first);
			// Записываем второй коэффициент
			poly.values[(2 * i) + 1] = static_cast <int16_t> (second);
		}
		// Выводим признак того, что выхода за модуль не было
		return (overflow == 0);
	}
	/**
	 * @brief Метод сжатия коэффициента до заданной разрядности
	 *
	 * @param value коэффициент из диапазона [0, q)
	 * @param bits  разрядность сжатия
	 *
	 * @return      сжатое значение из диапазона [0, 2^bits)
	 *
	 */
	static inline uint32_t compress(const int32_t value, const size_t bits) noexcept {
		// Округлённое частное (value · 2^bits + q/2) / q: деление на константу собиратель заменяет умножением
		return ((((static_cast <uint32_t> (value) << bits) + (static_cast <uint32_t> (Q) / 2)) / static_cast <uint32_t> (Q)) & ((1u << bits) - 1));
	}
	/**
	 * @brief Метод расширения сжатого значения до коэффициента
	 *
	 * @param value сжатое значение из диапазона [0, 2^bits)
	 * @param bits  разрядность сжатия
	 *
	 * @return      коэффициент из диапазона [0, q)
	 *
	 */
	static inline int16_t decompress(const uint32_t value, const size_t bits) noexcept {
		// Округлённое частное (value · q + 2^(bits-1)) / 2^bits
		return static_cast <int16_t> (((value * static_cast <uint32_t> (Q)) + (1u << (bits - 1))) >> bits);
	}
	/**
	 * @brief Метод записи многочлена со сжатием до заданной разрядности
	 *
	 * @param poly   записываемый многочлен
	 * @param bits   разрядность сжатия
	 * @param result место, в которое помещаются 32·bits байтов записи
	 *
	 */
	static void pack(const poly_t & poly, const size_t bits, uint8_t * result) noexcept {
		// Накопитель разрядов
		uint32_t buffer = 0;
		// Число разрядов в накопителе
		size_t count = 0;
		// Место записи
		size_t offset = 0;
		/**
		 * Выполняем перебор коэффициентов
		 */
		for(size_t i = 0; i < N; i++){
			// Складываем сжатый коэффициент в накопитель
			buffer |= (compress(poly.values[i], bits) << count);
			// Увеличиваем число разрядов
			count += bits;
			/**
			 * Выдаём полные байты накопителя
			 */
			while(count >= 8){
				// Записываем младший байт накопителя
				result[offset++] = static_cast <uint8_t> (buffer);
				// Сдвигаем накопитель
				buffer >>= 8;
				// Уменьшаем число разрядов
				count -= 8;
			}
		}
	}
	/**
	 * @brief Метод разбора многочлена с расширением из заданной разрядности
	 *
	 * @param data 32·bits байтов записи
	 * @param bits разрядность сжатия
	 * @param poly место, в которое помещается многочлен
	 *
	 */
	static void unpack(const uint8_t * data, const size_t bits, poly_t & poly) noexcept {
		// Накопитель разрядов
		uint32_t buffer = 0;
		// Число разрядов в накопителе
		size_t count = 0;
		// Место чтения
		size_t offset = 0;
		/**
		 * Выполняем перебор коэффициентов
		 */
		for(size_t i = 0; i < N; i++){
			/**
			 * Добираем байты в накопитель
			 */
			while(count < bits){
				// Складываем очередной байт в накопитель
				buffer |= (static_cast <uint32_t> (data[offset++]) << count);
				// Увеличиваем число разрядов
				count += 8;
			}
			// Расширяем сжатое значение до коэффициента
			poly.values[i] = decompress(buffer & ((1u << bits) - 1), bits);
			// Сдвигаем накопитель
			buffer >>= bits;
			// Уменьшаем число разрядов
			count -= bits;
		}
	}
	/**
	 * @brief Метод выборки многочлена в области NTT из потока XOF
	 *
	 * @param rho    зерно матрицы
	 * @param row    номер строки
	 * @param column номер столбца
	 * @param poly   место, в которое помещается многочлен
	 *
	 */
	static void sampling(const uint8_t * rho, const uint8_t row, const uint8_t column, poly_t & poly) noexcept {
		// Поток SHAKE128 над ρ || столбец || строка
		digest::keccak_t xof(digest::sha3_t::SHAKE128);
		// Поглощаем зерно
		xof.update(view_t(rho, SEED));
		// Индексы матрицы
		const uint8_t indices[2] = {column, row};
		// Поглощаем индексы
		xof.update(view_t(indices, sizeof(indices)));
		// Число набранных коэффициентов
		size_t count = 0;
		/**
		 * Выполняем выборку до заполнения многочлена
		 */
		while(count < N){
			// Три байта потока
			uint8_t bytes[3];
			// Выжимаем три байта
			xof.squeeze(bytes, sizeof(bytes));
			// Первый претендент
			const uint16_t first = static_cast <uint16_t> (bytes[0] | ((bytes[1] & 0x0F) << 8));
			// Второй претендент
			const uint16_t second = static_cast <uint16_t> ((bytes[1] >> 4) | (bytes[2] << 4));
			// Если первый претендент годен
			if(first < Q)
				// Записываем коэффициент
				poly.values[count++] = static_cast <int16_t> (first);
			// Если второй претендент годен и место есть
			if((second < Q) && (count < N))
				// Записываем коэффициент
				poly.values[count++] = static_cast <int16_t> (second);
		}
	}
	/**
	 * @brief Метод выборки многочлена из центрированного биномиального распределения
	 *
	 * @param sigma зерно выборки
	 * @param nonce номер выборки
	 * @param eta   параметр распределения
	 * @param poly  место, в которое помещается многочлен
	 *
	 */
	static void binomial(const uint8_t * sigma, const uint8_t nonce, const size_t eta, poly_t & poly) noexcept {
		// Байты PRF: 64·η
		uint8_t bytes[64 * 3];
		// Поток SHAKE256 над σ || номер
		digest::keccak_t prf(digest::sha3_t::SHAKE256);
		// Поглощаем зерно
		prf.update(view_t(sigma, SEED));
		// Поглощаем номер
		prf.update(view_t(&nonce, 1));
		// Выжимаем байты
		prf.squeeze(bytes, 64 * eta);
		/**
		 * Выполняем перебор коэффициентов
		 */
		for(size_t i = 0; i < N; i++){
			// Сумма первых η разрядов
			int32_t first = 0;
			// Сумма вторых η разрядов
			int32_t second = 0;
			/**
			 * Выполняем перебор разрядов
			 */
			for(size_t j = 0; j < eta; j++){
				// Место первого разряда
				const size_t at = (2 * i * eta) + j;
				// Прибавляем первый разряд
				first += ((bytes[at / 8] >> (at % 8)) & 1);
				// Прибавляем второй разряд
				second += ((bytes[(at + eta) / 8] >> ((at + eta) % 8)) & 1);
			}
			// Записываем разность сумм по модулю
			poly.values[i] = reduce(first - second);
		}
		// Выполняем затирание байтов PRF
		wipe(bytes, sizeof(bytes));
	}
	/**
	 * @brief Метод хеширования G: SHA3-512
	 *
	 * @param first  первая часть входа
	 * @param second вторая часть входа
	 * @param result место, в которое помещаются 64 байта итога
	 *
	 */
	static void widely(const view_t & first, const view_t & second, uint8_t * result) noexcept {
		// Хеш SHA3-512
		digest::keccak_t hash(digest::sha3_t::SHA3_512);
		// Поглощаем первую часть
		hash.update(first);
		// Поглощаем вторую часть
		hash.update(second);
		// Снимаем итог
		hash.finish(result, 64);
	}
	/**
	 * @brief Метод шифрования K-PKE
	 *
	 * @param sample описание набора
	 * @param key    ключ шифрования: t || ρ
	 * @param message сообщение в 32 байта
	 * @param seed   зерно случайности r
	 * @param cipher место, в которое помещается шифртекст
	 *
	 */
	static void encrypt(const sample_t & sample, const uint8_t * key, const uint8_t * message, const uint8_t * seed, uint8_t * cipher) noexcept {
		// Вектор t в области NTT
		poly_t t[K];
		/**
		 * Выполняем разбор вектора t
		 */
		for(size_t i = 0; i < sample.k; i++)
			// Разбираем многочлен
			decode(key + (i * POLY), t[i]);
		// Зерно матрицы
		const uint8_t * rho = (key + (sample.k * POLY));
		// Вектор r в области NTT
		poly_t r[K];
		/**
		 * Выполняем выборку вектора r
		 */
		for(size_t i = 0; i < sample.k; i++){
			// Выбираем многочлен
			binomial(seed, static_cast <uint8_t> (i), sample.eta1, r[i]);
			// Переводим в область NTT
			forward(r[i]);
		}
		// Вектор u
		poly_t u[K];
		/**
		 * Выполняем вычисление u = A^T r + e1
		 */
		for(size_t i = 0; i < sample.k; i++){
			// Обнуляем накопитель
			::memset(u[i].values, 0, sizeof(u[i].values));
			/**
			 * Выполняем перебор столбцов
			 */
			for(size_t j = 0; j < sample.k; j++){
				// Элемент матрицы A[j][i]: транспонирование
				poly_t a;
				// Выбираем элемент
				sampling(rho, static_cast <uint8_t> (j), static_cast <uint8_t> (i), a);
				// Накапливаем произведение
				accumulate(a, r[j], u[i]);
			}
			// Переводим из области NTT
			inverse(u[i]);
			// Шум e1
			poly_t e;
			// Выбираем шум
			binomial(seed, static_cast <uint8_t> (sample.k + i), sample.eta2, e);
			/**
			 * Выполняем сложение с шумом
			 */
			for(size_t c = 0; c < N; c++)
				// Складываем коэффициенты
				u[i].values[c] = reduce(u[i].values[c] + e.values[c]);
		}
		// Многочлен v
		poly_t v;
		// Обнуляем накопитель
		::memset(v.values, 0, sizeof(v.values));
		/**
		 * Выполняем вычисление t^T r
		 */
		for(size_t i = 0; i < sample.k; i++)
			// Накапливаем произведение
			accumulate(t[i], r[i], v);
		// Переводим из области NTT
		inverse(v);
		// Шум e2
		poly_t e;
		// Выбираем шум
		binomial(seed, static_cast <uint8_t> (2 * sample.k), sample.eta2, e);
		/**
		 * Выполняем сложение с шумом и сообщением
		 */
		for(size_t c = 0; c < N; c++){
			// Разряд сообщения, расширенный до коэффициента
			const int32_t bit = decompress((message[c / 8] >> (c % 8)) & 1, 1);
			// Складываем коэффициенты
			v.values[c] = reduce(v.values[c] + e.values[c] + bit);
		}
		/**
		 * Выполняем запись вектора u со сжатием
		 */
		for(size_t i = 0; i < sample.k; i++)
			// Записываем многочлен
			pack(u[i], sample.du, cipher + (i * 32 * sample.du));
		// Записываем многочлен v со сжатием
		pack(v, sample.dv, cipher + (sample.k * 32 * sample.du));
		// Выполняем затирание секретных промежуточных значений
		wipe(r, sizeof(r));
		// Выполняем затирание вектора u
		wipe(u, sizeof(u));
		// Выполняем затирание многочлена v
		wipe(v.values, sizeof(v.values));
		// Выполняем затирание шума
		wipe(e.values, sizeof(e.values));
	}
	/**
	 * @brief Метод расшифрования K-PKE
	 *
	 * @param sample  описание набора
	 * @param secret  ключ расшифрования: s в области NTT
	 * @param cipher  шифртекст
	 * @param message место, в которое помещаются 32 байта сообщения
	 *
	 */
	static void decrypt(const sample_t & sample, const uint8_t * secret, const uint8_t * cipher, uint8_t * message) noexcept {
		// Многочлен w = v - s^T u
		poly_t w;
		// Обнуляем накопитель
		::memset(w.values, 0, sizeof(w.values));
		/**
		 * Выполняем вычисление s^T NTT(u)
		 */
		for(size_t i = 0; i < sample.k; i++){
			// Многочлен u_i
			poly_t u;
			// Разбираем многочлен с расширением
			unpack(cipher + (i * 32 * sample.du), sample.du, u);
			// Переводим в область NTT
			forward(u);
			// Многочлен s_i
			poly_t s;
			// Разбираем многочлен
			decode(secret + (i * POLY), s);
			// Накапливаем произведение
			accumulate(s, u, w);
			// Выполняем затирание секретного многочлена
			wipe(s.values, sizeof(s.values));
		}
		// Переводим из области NTT
		inverse(w);
		// Многочлен v
		poly_t v;
		// Разбираем многочлен с расширением
		unpack(cipher + (sample.k * 32 * sample.du), sample.dv, v);
		// Обнуляем сообщение
		::memset(message, 0, 32);
		/**
		 * Выполняем сжатие разности до разрядов сообщения
		 */
		for(size_t c = 0; c < N; c++){
			// Разряд сообщения
			const uint32_t bit = compress(reduce(v.values[c] - w.values[c]), 1);
			// Записываем разряд
			message[c / 8] |= static_cast <uint8_t> (bit << (c % 8));
		}
		// Выполняем затирание многочлена w
		wipe(w.values, sizeof(w.values));
	}
};

/**
 * \~russian
 * @brief Метод получения длины ключа инкапсуляции набора
 *
 * @param kem набор параметров
 *
 * @return    длина ключа инкапсуляции в байтах либо нуль
 *
 * \~english
 * @brief Method of the obtaining of the length of the encapsulation key of a set
 *
 * @param kem parameter set
 *
 * @return    length of the encapsulation key in bytes or zero
 *
 * \~
 */
size_t nts::agreement::encapsulation(const kem_t kem) noexcept {
	// Описание набора параметров
	const sample_t sample = describe(kem);
	// Выводим длину: k многочленов и зерно ρ
	return ((sample.k == 0) ? 0 : ((sample.k * POLY) + SEED));
}
/**
 * \~russian
 * @brief Метод получения длины ключа декапсуляции набора
 *
 * @param kem набор параметров
 *
 * @return    длина ключа декапсуляции в байтах либо нуль
 *
 * \~english
 * @brief Method of the obtaining of the length of the decapsulation key of a set
 *
 * @param kem parameter set
 *
 * @return    length of the decapsulation key in bytes or zero
 *
 * \~
 */
size_t nts::agreement::decapsulation(const kem_t kem) noexcept {
	// Описание набора параметров
	const sample_t sample = describe(kem);
	// Выводим длину: k многочленов секрета, ключ инкапсуляции, его хеш и z
	return ((sample.k == 0) ? 0 : ((sample.k * POLY) + encapsulation(kem) + SEED + SEED));
}
/**
 * \~russian
 * @brief Метод получения длины шифртекста набора
 *
 * @param kem набор параметров
 *
 * @return    длина шифртекста в байтах либо нуль
 *
 * \~english
 * @brief Method of the obtaining of the length of the ciphertext of a set
 *
 * @param kem parameter set
 *
 * @return    length of the ciphertext in bytes or zero
 *
 * \~
 */
size_t nts::agreement::ciphertext(const kem_t kem) noexcept {
	// Описание набора параметров
	const sample_t sample = describe(kem);
	// Выводим длину: k сжатых многочленов u и сжатый многочлен v
	return ((sample.k == 0) ? 0 : ((sample.k * 32 * sample.du) + (32 * sample.dv)));
}
/**
 * \~russian
 * @brief Метод проверки ключа инкапсуляции
 *
 * @param kem набор параметров
 * @param key ключ инкапсуляции
 *
 * @return    признак того, что ключ годен
 *
 * \~english
 * @brief Method of the check of an encapsulation key
 *
 * @param kem parameter set
 * @param key encapsulation key
 *
 * @return    sign that the key is valid
 *
 * \~
 */
bool nts::agreement::validate(const kem_t kem, const view_t & key) noexcept {
	// Описание набора параметров
	const sample_t sample = describe(kem);
	// Если набор не установлен либо длина ключа не сходится
	if((sample.k == 0) || (key.data == nullptr) || (key.size != encapsulation(kem)))
		// Выводим отказ проверки
		return false;
	// Признак годности всех многочленов
	bool ok = true;
	/**
	 * Выполняем перебор многочленов ключа
	 */
	for(size_t i = 0; i < sample.k; i++){
		// Многочлен ключа
		poly_t poly;
		// Проверяем коэффициенты многочлена на выход за модуль
		ok = (decode(key.data + (i * POLY), poly) && ok);
	}
	// Выводим признак годности ключа
	return ok;
}
/**
 * \~russian
 * @brief Метод выработки пары ключей из зерна
 *
 * @param kem    набор параметров
 * @param seed   зерно выработки в шестьдесят четыре байта
 * @param key    место, в которое помещается ключ инкапсуляции
 * @param secret место, в которое помещается ключ декапсуляции
 *
 * @return       признак того, что пара ключей выработана
 *
 * \~english
 * @brief Method of the generation of a key pair from a seed
 *
 * @param kem    parameter set
 * @param seed   seed of the generation of sixty four bytes
 * @param key    place into which the encapsulation key is put
 * @param secret place into which the decapsulation key is put
 *
 * @return       sign that the key pair is generated
 *
 * \~
 */
bool nts::agreement::generate(const kem_t kem, const view_t & seed, uint8_t * key, uint8_t * secret) noexcept {
	// Описание набора параметров
	const sample_t sample = describe(kem);
	// Если набор не установлен, зерно не той длины либо места не переданы
	if((sample.k == 0) || (seed.data == nullptr) || (seed.size != MLKEM_SEED) || (key == nullptr) || (secret == nullptr))
		// Выводим отказ выработки
		return false;
	// Размерность модуля как байт
	const uint8_t rank = static_cast <uint8_t> (sample.k);
	// Зёрна ρ и σ: G(d || k)
	uint8_t seeds[64];
	// Вычисляем зёрна
	widely(view_t(seed.data, SEED), view_t(&rank, 1), seeds);
	// Зерно матрицы ρ
	const uint8_t * rho = seeds;
	// Зерно выборки σ
	const uint8_t * sigma = (seeds + SEED);
	// Вектор секрета s в области NTT
	poly_t s[K];
	/**
	 * Выполняем выборку секрета
	 */
	for(size_t i = 0; i < sample.k; i++){
		// Выбираем многочлен
		binomial(sigma, static_cast <uint8_t> (i), sample.eta1, s[i]);
		// Переводим в область NTT
		forward(s[i]);
	}
	// Длина ключа инкапсуляции
	const size_t length = encapsulation(kem);
	/**
	 * Выполняем вычисление t = A s + e
	 */
	for(size_t i = 0; i < sample.k; i++){
		// Многочлен t_i
		poly_t t;
		// Выбираем шум e_i
		binomial(sigma, static_cast <uint8_t> (sample.k + i), sample.eta1, t);
		// Переводим шум в область NTT
		forward(t);
		/**
		 * Выполняем перебор столбцов
		 */
		for(size_t j = 0; j < sample.k; j++){
			// Элемент матрицы A[i][j]
			poly_t a;
			// Выбираем элемент
			sampling(rho, static_cast <uint8_t> (i), static_cast <uint8_t> (j), a);
			// Накапливаем произведение
			accumulate(a, s[j], t);
		}
		// Записываем многочлен t_i в ключ инкапсуляции
		encode(t, key + (i * POLY));
		// Записываем многочлен s_i в ключ декапсуляции
		encode(s[i], secret + (i * POLY));
	}
	// Записываем зерно ρ в ключ инкапсуляции
	::memcpy(key + (sample.k * POLY), rho, SEED);
	// Записываем ключ инкапсуляции в ключ декапсуляции
	::memcpy(secret + (sample.k * POLY), key, length);
	// Записываем хеш ключа инкапсуляции
	digest::sha3(digest::sha3_t::SHA3_256, view_t(key, length), secret + (sample.k * POLY) + length, SEED);
	// Записываем зерно z неявного отказа
	::memcpy(secret + (sample.k * POLY) + length + SEED, seed.data + SEED, SEED);
	// Выполняем затирание секрета
	wipe(s, sizeof(s));
	// Выполняем затирание зёрен
	wipe(seeds, sizeof(seeds));
	// Выводим успешность выработки
	return true;
}
/**
 * \~russian
 * @brief Метод выработки пары ключей на случайном зерне
 *
 * @param kem    набор параметров
 * @param key    место, в которое помещается ключ инкапсуляции
 * @param secret место, в которое помещается ключ декапсуляции
 *
 * @return       признак того, что пара ключей выработана
 *
 * \~english
 * @brief Method of the generation of a key pair on a random seed
 *
 * @param kem    parameter set
 * @param key    place into which the encapsulation key is put
 * @param secret place into which the decapsulation key is put
 *
 * @return       sign that the key pair is generated
 *
 * \~
 */
bool nts::agreement::generate(const kem_t kem, uint8_t * key, uint8_t * secret) noexcept {
	// Зерно выработки
	uint8_t seed[MLKEM_SEED];
	// Если зерно выработать не удалось
	if(!entropy::bytes(seed, sizeof(seed)))
		// Выводим отказ выработки
		return false;
	// Вырабатываем пару ключей из зерна
	const bool result = generate(kem, view_t(seed, sizeof(seed)), key, secret);
	// Выполняем затирание зерна
	wipe(seed, sizeof(seed));
	// Выводим итог выработки
	return result;
}
/**
 * \~russian
 * @brief Метод инкапсуляции на заданном сообщении
 *
 * @param kem     набор параметров
 * @param key     ключ инкапсуляции собеседника
 * @param message случайное сообщение в тридцать два байта
 * @param cipher  место, в которое помещается шифртекст
 * @param shared  место, в которое помещается общий секрет в тридцать два байта
 *
 * @return        признак того, что инкапсуляция выполнена
 *
 * \~english
 * @brief Method of the encapsulation on a given message
 *
 * @param kem     parameter set
 * @param key     encapsulation key of the peer
 * @param message random message of thirty two bytes
 * @param cipher  place into which the ciphertext is put
 * @param shared  place into which the shared secret of thirty two bytes is put
 *
 * @return        sign that the encapsulation is done
 *
 * \~
 */
bool nts::agreement::encapsulate(const kem_t kem, const view_t & key, const view_t & message, uint8_t * cipher, uint8_t * shared) noexcept {
	// Описание набора параметров
	const sample_t sample = describe(kem);
	// Если набор не установлен, сообщение не той длины, места не переданы либо ключ негоден
	if((sample.k == 0) || (message.data == nullptr) || (message.size != MLKEM_MESSAGE) || (cipher == nullptr) || (shared == nullptr) || !validate(kem, key))
		// Выводим отказ инкапсуляции
		return false;
	// Хеш ключа инкапсуляции
	uint8_t hash[SEED];
	// Вычисляем хеш
	digest::sha3(digest::sha3_t::SHA3_256, key, hash, SEED);
	// Секрет и зерно шифрования: G(m || H(ek))
	uint8_t derived[64];
	// Вычисляем секрет и зерно
	widely(message, view_t(hash, SEED), derived);
	// Выполняем шифрование сообщения
	encrypt(sample, key.data, message.data, derived + SEED, cipher);
	// Выдаём общий секрет
	::memcpy(shared, derived, MLKEM_SHARED);
	// Выполняем затирание секрета и зерна
	wipe(derived, sizeof(derived));
	// Выводим успешность инкапсуляции
	return true;
}
/**
 * \~russian
 * @brief Метод инкапсуляции на случайном сообщении
 *
 * @param kem    набор параметров
 * @param key    ключ инкапсуляции собеседника
 * @param cipher место, в которое помещается шифртекст
 * @param shared место, в которое помещается общий секрет в тридцать два байта
 *
 * @return       признак того, что инкапсуляция выполнена
 *
 * \~english
 * @brief Method of the encapsulation on a random message
 *
 * @param kem    parameter set
 * @param key    encapsulation key of the peer
 * @param cipher place into which the ciphertext is put
 * @param shared place into which the shared secret of thirty two bytes is put
 *
 * @return       sign that the encapsulation is done
 *
 * \~
 */
bool nts::agreement::encapsulate(const kem_t kem, const view_t & key, uint8_t * cipher, uint8_t * shared) noexcept {
	// Случайное сообщение
	uint8_t message[MLKEM_MESSAGE];
	// Если сообщение выработать не удалось
	if(!entropy::bytes(message, sizeof(message)))
		// Выводим отказ инкапсуляции
		return false;
	// Выполняем инкапсуляцию на сообщении
	const bool result = encapsulate(kem, key, view_t(message, sizeof(message)), cipher, shared);
	// Выполняем затирание сообщения
	wipe(message, sizeof(message));
	// Выводим итог инкапсуляции
	return result;
}
/**
 * \~russian
 * @brief Метод декапсуляции
 *
 * @param kem    набор параметров
 * @param secret свой ключ декапсуляции
 * @param cipher шифртекст собеседника
 * @param shared место, в которое помещается общий секрет в тридцать два байта
 *
 * @return       признак того, что декапсуляция выполнена
 *
 * \~english
 * @brief Method of the decapsulation
 *
 * @param kem    parameter set
 * @param secret own decapsulation key
 * @param cipher ciphertext of the peer
 * @param shared place into which the shared secret of thirty two bytes is put
 *
 * @return       sign that the decapsulation is done
 *
 * \~
 */
bool nts::agreement::decapsulate(const kem_t kem, const view_t & secret, const view_t & cipher, uint8_t * shared) noexcept {
	// Описание набора параметров
	const sample_t sample = describe(kem);
	// Если набор не установлен, длины не сходятся либо место не передано
	if((sample.k == 0) || (secret.data == nullptr) || (secret.size != decapsulation(kem)) || (cipher.data == nullptr) || (cipher.size != ciphertext(kem)) || (shared == nullptr))
		// Выводим отказ декапсуляции
		return false;
	// Длина ключа инкапсуляции
	const size_t length = encapsulation(kem);
	// Ключ инкапсуляции внутри ключа декапсуляции
	const uint8_t * key = (secret.data + (sample.k * POLY));
	// Хеш ключа инкапсуляции внутри ключа декапсуляции
	const uint8_t * hash = (key + length);
	// Зерно неявного отказа
	const uint8_t * z = (hash + SEED);
	// Пересчитанный хеш ключа инкапсуляции
	uint8_t recomputed[SEED];
	// Вычисляем хеш
	digest::sha3(digest::sha3_t::SHA3_256, view_t(key, length), recomputed, SEED);
	// Накопитель расхождения хешей
	uint8_t mismatch = 0;
	/**
	 * Выполняем сличение хешей за постоянное время
	 */
	for(size_t i = 0; i < SEED; i++)
		// Накапливаем расхождение
		mismatch |= (recomputed[i] ^ hash[i]);
	// Если хеш ключа инкапсуляции не сходится: раздел 7.3 FIPS 203
	if(mismatch != 0)
		// Выводим отказ декапсуляции
		return false;
	// Признак годности секретных многочленов
	bool ok = true;
	/**
	 * Выполняем проверку секретных многочленов на выход за модуль
	 */
	for(size_t i = 0; i < sample.k; i++){
		// Многочлен секрета
		poly_t poly;
		// Проверяем коэффициенты
		ok = (decode(secret.data + (i * POLY), poly) && ok);
		// Выполняем затирание многочлена
		wipe(poly.values, sizeof(poly.values));
	}
	// Если секретные многочлены негодны
	if(!ok || !validate(kem, view_t(key, length)))
		// Выводим отказ декапсуляции
		return false;
	// Расшифрованное сообщение
	uint8_t message[MLKEM_MESSAGE];
	// Выполняем расшифрование
	decrypt(sample, secret.data, cipher.data, message);
	// Секрет и зерно шифрования: G(m' || h)
	uint8_t derived[64];
	// Вычисляем секрет и зерно
	widely(view_t(message, sizeof(message)), view_t(hash, SEED), derived);
	// Неявно отвергнутый секрет: J(z || c)
	uint8_t rejected[MLKEM_SHARED];
	// Поток SHAKE256
	digest::keccak_t j(digest::sha3_t::SHAKE256);
	// Поглощаем зерно
	j.update(view_t(z, SEED));
	// Поглощаем шифртекст
	j.update(cipher);
	// Выжимаем отвергнутый секрет
	j.squeeze(rejected, sizeof(rejected));
	// Пересчитанный шифртекст
	uint8_t recrypted[1568];
	// Выполняем повторное шифрование
	encrypt(sample, key, message, derived + SEED, recrypted);
	// Накопитель расхождения шифртекстов
	uint8_t differ = 0;
	/**
	 * Выполняем сличение шифртекстов за постоянное время
	 */
	for(size_t i = 0; i < cipher.size; i++)
		// Накапливаем расхождение
		differ |= (recrypted[i] ^ cipher.data[i]);
	// Маска выбора: нули при совпадении, единицы при расхождении
	const uint8_t mask = static_cast <uint8_t> (-static_cast <int8_t> ((differ | static_cast <uint8_t> (-differ)) >> 7));
	/**
	 * Выполняем выбор секрета по маске
	 */
	for(size_t i = 0; i < MLKEM_SHARED; i++)
		// Выбираем настоящий либо отвергнутый секрет
		shared[i] = static_cast <uint8_t> ((derived[i] & ~mask) | (rejected[i] & mask));
	// Выполняем затирание сообщения
	wipe(message, sizeof(message));
	// Выполняем затирание секрета и зерна
	wipe(derived, sizeof(derived));
	// Выполняем затирание отвергнутого секрета
	wipe(rejected, sizeof(rejected));
	// Выполняем затирание пересчитанного шифртекста
	wipe(recrypted, sizeof(recrypted));
	// Выводим успешность декапсуляции
	return true;
}
