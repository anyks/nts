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
 *    коэффициентов держатся в 32 разрядах, переполнения нет. Полная редукция берётся
 *    лишь на произведениях и суммах произведений (до трёх слагаемых ниже 2^25 - в её
 *    границах с двумя поправками), а сумма и разность приведённых коэффициентов ниже
 *    удвоенного модуля приводятся одним условным вычитанием (once): бабочки NTT стоили
 *    три редукции на пару, стало по одной, умножение в области NTT - шесть на пару, стало
 *    три (круг 35, 23.09.2026: прямое NTT на M4 1 005 → 584 нс, обратное 465 → 358). Сами
 *    бабочки NTT идут на 16 разрядах умножением Монтгомери (fqmul): степени ζ хранятся в
 *    таблице умноженными на 2^16, произведение выходит в обычной форме, коэффициенты между
 *    слоями держатся со знаком без приведения (семь слоёв поднимают модуль не выше 8q < 2^15),
 *    и лишь на выходе приводятся к [0, q) редукцией Барретта и знаком. Так устроена эталонная
 *    реализация Kyber; арифметика умещается в 32 разряда без 64-разрядного умножения, и
 *    собиратель кладёт бабочки на векторные команды: прямое NTT M4 584 → 151 нс, FreeBSD
 *    3 866 → 1 300 (щуп nttprobe). Умножение в области NTT идёт на подготовленном втором
 *    сомножителе (prepare, круг 36, 23.09.2026): его коэффициенты переводятся в форму
 *    Монтгомери, нечётные места ещё умножаются на ±γ пары, а пары хранятся и местами; тогда
 *    оба коэффициента произведения пар - суммы двух произведений соседних мест, они копятся
 *    в 32-разрядном накопителе по всем слагаемым скалярного произведения (не выше четырёх,
 *    ниже q·2^15) и приводятся один раз редукцией Монтгомери (settle) - вместо трёх редукций
 *    Барретта на пару на каждом слагаемом. На x86-64 накопление - команда pmaddwd, подготовка
 *    и приведение тоже на SSE2 (они есть на всякой x86-64). Скалярное произведение k = 3:
 *    M4 339 → 126 нс, FreeBSD 3 633 → 278; инкапсуляция M4 12,9 → 12,0 мкс, FreeBSD 75,3 → 55,4
 *    (вместе с ядром Keccak круга 36); эталонная реализация Kyber на AVX2 держит тот же
 *    «кэш умножения» с нечётными местами, умноженными на степень пары.
 *
 * 6. Поток SHAKE128 при выборке матрицы выжимается блоками по 168 байтов (56 троек), а не
 *    по три байта; биномиальная выборка считает суммы разрядов масками 0x55 и 0x249249
 *    по байту и по трём байтам, а не разрядом за разрядом. Так же устроены выборки у
 *    OpenSSL (crypto/ml_kem/ml_kem.c: sample_scalar, cbd_2, cbd_3). Щуп kemprobe круга 35:
 *    выборка многочлена матрицы 1 119 → 731 нс, биномиальная 524 → 173 (M4).
 *
 * 7. Сжатие коэффициентов идёт умножением на обратное 2^36/q в 64 разрядах, а не делением на q:
 *    у clang и gcc деление на константу и так обращается в такое умножение, у lcc на Эльбрусе
 *    остаётся делением (упаковка многочлена там стоила 4 326 нс при 930…1 030 на x86). Записи
 *    разрядностей 4, 5, 10 и 11 - всех у наборов FIPS 203 - пишутся и читаются жёсткими узорами
 *    байтов, а побитовый накопитель оставлен прочим разрядностям: узор на M4 13 нс против 155
 *    у накопителя (щуп packprobe круга 36), упаковка многочлена 250 → 64 нс, инкапсуляция
 *    12,0 → 11,2 мкс, раскрытие 15,7 → 14,3.
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
 * Векторные команды SSE2 под умножение в области NTT: на x86-64 они есть всегда
 */
#if defined(__x86_64__) && defined(__SSE2__) && !defined(_MSC_VER)
	#include <emmintrin.h>
	/**
	 * Признак наличия векторного пути умножения
	 */
	#define __ANTS_MLKEM_SSE2__
#endif

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
	 * @brief Метод условного вычитания модуля из значения ниже удвоенного модуля
	 *
	 * @param value приводимое значение из [0, 2q)
	 *
	 * @return      значение из [0, q)
	 *
	 * @note Сумма и разность приведённых коэффициентов не выходят за удвоенный модуль,
	 *       и полная редукция Барретта им не нужна: бабочки NTT стоили три редукции на
	 *       пару коэффициентов, стало по одной на произведение (круг 35, 23.09.2026)
	 */
	static inline int16_t once(const int32_t value) noexcept {
		// Разность с модулем
		const int32_t difference = (value - Q);
		// Выводим разность, если она не отрицательна, иначе само значение
		return static_cast <int16_t> (difference + (Q & (difference >> 31)));
	}
	/**
	 * @brief Таблицы степеней ζ = 17: по BitRev7 для бабочек и нечётные для умножения пар
	 *
	 */
	/**
	 * @brief Метод приведения значения из [0, q) к полуинтервалу (-q/2, q/2]
	 *
	 * @param value приводимое значение
	 *
	 * @return      значение в 16 разрядах со знаком
	 *
	 */
	static inline int16_t centered(const int32_t value) noexcept {
		// Выводим значение, уменьшенное на модуль, если оно выше половины модуля
		return static_cast <int16_t> ((value > (Q / 2)) ? (value - Q) : value);
	}
	/**
	 * @brief Метод редукции Монтгомери 32-разрядного значения
	 *
	 * @param wide приводимое значение, |wide| < q·2^15
	 *
	 * @return     wide·2^(-16) mod q в полуинтервале (-q, q)
	 *
	 * @note Множитель -3327 обращает младшие 16 разрядов в ноль: q·3327 = 169·2^16 - 1,
	 *       оттого разность wide - factor·q делится на 2^16 нацело, а её старшие разряды
	 *       и есть итог. Тем же приведением снимается множитель 2^16 с накопителя
	 *       произведений в области NTT (settle)
	 */
	static inline int16_t montgomery(const int32_t wide) noexcept {
		// Множитель, обращающий младшие 16 разрядов значения в ноль: q^(-1) mod 2^16 = -3327
		const int16_t factor = static_cast <int16_t> (static_cast <uint16_t> (static_cast <int32_t> (static_cast <int16_t> (static_cast <uint16_t> (wide))) * -3327));
		// Выводим старшие 16 разрядов разности значения и произведения множителя на модуль
		return static_cast <int16_t> ((wide - (static_cast <int32_t> (factor) * Q)) >> 16);
	}
	/**
	 * @brief Метод умножения Монтгомери на 16 разрядах
	 *
	 * @param first  первый сомножитель, |first| < 2^15
	 * @param second второй сомножитель, |second| < 2^15
	 *
	 * @return       first·second·2^(-16) mod q в полуинтервале (-q, q)
	 *
	 * @note Так устроены бабочки NTT эталонной реализации Kyber: степень ζ хранится
	 *       умноженной на 2^16, оттого произведение выходит в обычной форме - ζ·x, а вся
	 *       арифметика умещается в 32 разряда без деления и без 64-разрядного умножения,
	 *       и собиратель кладёт бабочки на векторные команды (NEON, SSE2). Щуп nttprobe
	 *       круга 35 (23.09.2026): прямое NTT M4 582 → 150 нс, FreeBSD 3 866 → 1 300
	 */
	static inline int16_t fqmul(const int16_t first, const int16_t second) noexcept {
		// Выводим редукцию Монтгомери полного произведения
		return montgomery(static_cast <int32_t> (first) * second);
	}
	/**
	 * @brief Метод редукции Барретта на 16 разрядах
	 *
	 * @param value приводимое значение
	 *
	 * @return      значение, сравнимое с исходным по модулю q, из [-q/2, q/2]
	 *
	 */
	static inline int16_t barrett(const int16_t value) noexcept {
		// Частное с округлением: 2^26 / q = 20159
		const int16_t quotient = static_cast <int16_t> (((static_cast <int32_t> (value) * 20159) + (1 << 25)) >> 26);
		// Выводим остаток
		return static_cast <int16_t> (value - (static_cast <int32_t> (quotient) * Q));
	}
	/**
	 * @brief Метод приведения значения из (-q, q) к [0, q)
	 *
	 * @param value приводимое значение
	 *
	 * @return      значение из [0, q)
	 *
	 */
	static inline int16_t canonical(const int16_t value) noexcept {
		// Прибавляем модуль под маской знака
		return static_cast <int16_t> (value + (Q & (value >> 15)));
	}
	typedef struct Tables {
		// Степени ζ^BitRev7(i) для бабочек преобразования
		int16_t zetas[128];
		// Скрутки пар: ±γ·2^32 mod q, где γ = ζ^(2·BitRev7(i)+1) степень пары i; у нечётной пары группы знак противоположный
		int16_t twists[128];
		// 2^32 mod q: множитель перевода коэффициента в форму Монтгомери умножением fqmul
		int16_t square;
		// Множители подготовки по местам коэффициентов: на чётных square, на нечётных скрутка пары
		int16_t lanes[N];
		// Степени ζ в форме Монтгомери: ζ·2^16 mod q, приведённые к (-q/2, q/2]
		int16_t montgomery[128];
		// Обратное к 128 в форме Монтгомери: 128^(-1)·2^16 mod q
		int16_t inverse;
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
				// Та же степень в форме Монтгомери
				this->montgomery[i] = centered(reduce(static_cast <int32_t> ((static_cast <int64_t> (power) << 16) % Q)));
				// Если место в пределах таблицы скруток пар
				if(i < 64){
					// Степень пары ζ^(2·BitRev7(2i)+1) = ζ^(BitRev7(i)+1), умноженная на 2^32
					const int16_t twist = centered(reduce(static_cast <int32_t> ((static_cast <int64_t> (product(power, 17)) << 32) % Q)));
					// Записываем скрутку чётной пары группы
					this->twists[2 * i] = twist;
					// Записываем скрутку нечётной пары группы: степень противоположная
					this->twists[(2 * i) + 1] = static_cast <int16_t> (-twist);
				}
			}
			// Обратное к 128 в форме Монтгомери
			this->inverse = centered(reduce(static_cast <int32_t> ((static_cast <int64_t> (INVERSE) << 16) % Q)));
			// Множитель перевода в форму Монтгомери
			this->square = centered(reduce(static_cast <int32_t> ((static_cast <int64_t> (1) << 32) % Q)));
			/**
			 * Выполняем перебор пар коэффициентов
			 */
			for(size_t i = 0; i < N; i += 2){
				// Чётное место: перевод в форму Монтгомери
				this->lanes[i] = this->square;
				// Нечётное место: скрутка пары
				this->lanes[i + 1] = this->twists[i / 2];
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
		// Таблица степеней ζ в форме Монтгомери
		const int16_t * table = tables().montgomery;
		// Коэффициенты многочлена: между слоями держатся со знаком, растут не более чем на q за слой
		int16_t * values = poly.values;
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
				const int16_t zeta = table[index++];
				/**
				 * Выполняем перебор пар участка: одно умножение Монтгомери, сумма и разность
				 * без приведения - семь слоёв поднимают модуль коэффициента не выше 8q < 2^15
				 */
				for(size_t j = start; j < (start + length); j++){
					// Произведение степени и второго коэффициента пары
					const int16_t t = fqmul(zeta, values[j + length]);
					// Разность пары
					values[j + length] = static_cast <int16_t> (values[j] - t);
					// Сумма пары
					values[j] = static_cast <int16_t> (values[j] + t);
				}
			}
		}
		/**
		 * Выполняем приведение коэффициентов к [0, q)
		 */
		for(size_t i = 0; i < N; i++)
			// Приводим коэффициент редукцией Барретта и знаком
			values[i] = canonical(barrett(values[i]));
	}
	/**
	 * @brief Метод обратного преобразования NTT многочлена
	 *
	 * @param poly преобразуемый многочлен
	 *
	 */
	static void inverse(poly_t & poly) noexcept {
		// Таблица степеней ζ в форме Монтгомери
		const tables_t & table = tables();
		// Коэффициенты многочлена
		int16_t * values = poly.values;
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
				const int16_t zeta = table.montgomery[index--];
				/**
				 * Выполняем перебор пар участка: сумма приводится редукцией Барретта,
				 * разность умножается на степень умножением Монтгомери
				 */
				for(size_t j = start; j < (start + length); j++){
					// Первый коэффициент пары
					const int16_t t = values[j];
					// Сумма пары
					values[j] = barrett(static_cast <int16_t> (t + values[j + length]));
					// Произведение степени и разности пары
					values[j + length] = fqmul(zeta, static_cast <int16_t> (values[j + length] - t));
				}
			}
		}
		/**
		 * Выполняем перебор коэффициентов
		 */
		for(size_t i = 0; i < N; i++)
			// Умножаем на обратное к 128 в форме Монтгомери и приводим к [0, q)
			values[i] = canonical(fqmul(values[i], table.inverse));
	}
	/**
	 * @brief Второй сомножитель умножения в области NTT, подготовленный один раз
	 *
	 * @details Умножение пар (a0 + a1·X)·(b0 + b1·X) mod (X² - γ) даёт r0 = a0·b0 + a1·b1·γ и
	 *          r1 = a0·b1 + a1·b0. Коэффициенты второго сомножителя держатся в форме Монтгомери
	 *          (умноженными на 2^16): в массиве twisted нечётные места ещё умножены на ±γ, в
	 *          массиве swapped коэффициенты пары стоят местами. Тогда r0 и r1 - суммы двух
	 *          произведений соседних мест, они копятся в 32 разрядах без приведения по всем
	 *          слагаемым скалярного произведения векторов, и лишь накопитель приводится
	 *          редукцией Монтгомери, снимающей множитель 2^16. На x86-64 сумма двух произведений
	 *          соседних 16-разрядных мест - одна команда pmaddwd
	 */
	typedef struct Twisted {
		// Коэффициенты в форме Монтгомери, нечётные умножены на ±γ: b0·R, b1·γ·R, b2·R, b3·(-γ)·R, …
		int16_t twisted[N];
		// Коэффициенты пар местами в форме Монтгомери: b1·R, b0·R, b3·R, b2·R, …
		int16_t swapped[N];
	} twisted_t;
	/**
	 * @brief Накопитель произведений в области NTT: 32 разряда на коэффициент
	 *
	 * @note Порядок коэффициентов внутри накопителя принадлежит паре методов multiply и
	 *       settle: у векторного пути в каждой восьмёрке сперва идут четыре чётных
	 *       коэффициента, затем четыре нечётных
	 */
	typedef struct Wide {
		// Накопленные произведения
		int32_t values[N];
	} wide_t;
	/**
	 * @brief Метод подготовки второго сомножителя умножения в области NTT
	 *
	 * @param poly   многочлен в области NTT с коэффициентами из [0, q)
	 * @param result место, в которое помещается подготовленный сомножитель
	 *
	 */
	static void prepare(const poly_t & poly, twisted_t & result) noexcept {
		// Таблицы степеней
		const tables_t & table = tables();
		/**
		 * Векторный путь: умножение Монтгомери восьми коэффициентов за шаг
		 */
		#if defined(__ANTS_MLKEM_SSE2__)
			// Множитель q^(-1) mod 2^16 = -3327 и модуль по 16-разрядным местам
			const __m128i factor = _mm_set1_epi16(-3327), modulus = _mm_set1_epi16(static_cast <int16_t> (Q));
			// Множитель перевода в форму Монтгомери по местам
			const __m128i square = _mm_set1_epi16(table.square);
			/**
			 * @brief Умножение Монтгомери восьми пар 16-разрядных значений
			 *
			 * @param first  первые сомножители
			 * @param second вторые сомножители
			 *
			 * @return       произведения, делённые на 2^16, по модулю q в (-q, q)
			 *
			 * @note Младшие 16 разрядов произведения и множителя на модуль равны, оттого
			 *       разность старших половин и есть итог редукции - без заёма
			 */
			auto fqmul = [&factor, &modulus](const __m128i first, const __m128i second) noexcept -> __m128i {
				// Младшие и старшие половины произведений
				const __m128i low = _mm_mullo_epi16(first, second), high = _mm_mulhi_epi16(first, second);
				// Множители, обращающие младшие половины в ноль
				const __m128i zeroing = _mm_mullo_epi16(low, factor);
				// Выводим разность старших половин произведений и множителей на модуль
				return _mm_sub_epi16(high, _mm_mulhi_epi16(zeroing, modulus));
			};
			/**
			 * Выполняем перебор восьмёрок коэффициентов
			 */
			for(size_t i = 0; i < N; i += 8){
				// Коэффициенты многочлена
				const __m128i values = _mm_loadu_si128(reinterpret_cast <const __m128i *> (poly.values + i));
				// Скрученные коэффициенты: множители по местам
				_mm_storeu_si128(reinterpret_cast <__m128i *> (result.twisted + i), fqmul(values, _mm_loadu_si128(reinterpret_cast <const __m128i *> (table.lanes + i))));
				// Коэффициенты пар местами в форме Монтгомери
				_mm_storeu_si128(reinterpret_cast <__m128i *> (result.swapped + i), fqmul(_mm_shufflehi_epi16(_mm_shufflelo_epi16(values, 0xB1), 0xB1), square));
			}
		/**
		 * Переносимый путь
		 */
		#else
			/**
			 * Выполняем перебор пар коэффициентов
			 */
			for(size_t i = 0; i < N; i += 2){
				// Чётный и нечётный коэффициенты пары в форме Монтгомери
				const int16_t even = fqmul(poly.values[i], table.square), odd = fqmul(poly.values[i + 1], table.square);
				// Чётное место скрученного массива: коэффициент как есть
				result.twisted[i] = even;
				// Нечётное место скрученного массива: коэффициент, умноженный на степень пары
				result.twisted[i + 1] = fqmul(poly.values[i + 1], table.twists[i / 2]);
				// Переставленные коэффициенты пары
				result.swapped[i] = odd;
				result.swapped[i + 1] = even;
			}
		#endif
	}
	/**
	 * @brief Метод умножения многочлена на подготовленный сомножитель с накоплением
	 *
	 * @param first  первый сомножитель с коэффициентами из [0, q)
	 * @param second подготовленный второй сомножитель
	 * @param result накопитель произведений
	 *
	 * @note Слагаемое накопителя ниже 2·q² < 2^25, а слагаемых у скалярного произведения
	 *       не больше четырёх (размерность модуля): накопитель остаётся ниже q·2^15,
	 *       в границах редукции Монтгомери
	 */
	static void multiply(const poly_t & first, const twisted_t & second, wide_t & result) noexcept {
		/**
		 * Векторный путь: восемь коэффициентов за шаг, суммы произведений соседних мест командой pmaddwd
		 */
		#if defined(__ANTS_MLKEM_SSE2__)
			/**
			 * Выполняем перебор восьмёрок коэффициентов
			 */
			for(size_t i = 0; i < N; i += 8){
				// Коэффициенты первого сомножителя
				const __m128i a = _mm_loadu_si128(reinterpret_cast <const __m128i *> (first.values + i));
				// Скрученные и переставленные коэффициенты второго
				const __m128i twisted = _mm_loadu_si128(reinterpret_cast <const __m128i *> (second.twisted + i));
				const __m128i swapped = _mm_loadu_si128(reinterpret_cast <const __m128i *> (second.swapped + i));
				// Накопители чётных и нечётных коэффициентов восьмёрки
				__m128i * even = reinterpret_cast <__m128i *> (result.values + i);
				__m128i * odd = reinterpret_cast <__m128i *> (result.values + i + 4);
				// Складываем суммы произведений соседних мест с накопителями
				_mm_storeu_si128(even, _mm_add_epi32(_mm_loadu_si128(even), _mm_madd_epi16(a, twisted)));
				_mm_storeu_si128(odd, _mm_add_epi32(_mm_loadu_si128(odd), _mm_madd_epi16(a, swapped)));
			}
		/**
		 * Переносимый путь
		 */
		#else
			/**
			 * Выполняем перебор пар коэффициентов
			 */
			for(size_t i = 0; i < N; i += 2){
				// Коэффициенты первого сомножителя
				const int32_t a0 = first.values[i], a1 = first.values[i + 1];
				// Чётный коэффициент произведения: a0·b0 + a1·b1·γ
				result.values[i] += ((a0 * second.twisted[i]) + (a1 * second.twisted[i + 1]));
				// Нечётный коэффициент произведения: a0·b1 + a1·b0
				result.values[i + 1] += ((a0 * second.swapped[i]) + (a1 * second.swapped[i + 1]));
			}
		#endif
	}
	/**
	 * @brief Метод приведения накопителя произведений к многочлену
	 *
	 * @param wide   накопитель произведений
	 * @param result место, в которое помещается многочлен с коэффициентами из [0, q)
	 *
	 */
	static void settle(const wide_t & wide, poly_t & result) noexcept {
		/**
		 * Векторный путь: редукция Монтгомери четырёх 32-разрядных значений за шаг
		 */
		#if defined(__ANTS_MLKEM_SSE2__)
			// Множитель q^(-1) mod 2^16 = -3327 в младших половинах 32-разрядных мест, старшие половины нули
			const __m128i factor = _mm_set1_epi32(0x0000F301);
			// Модуль в младших половинах мест
			const __m128i modulus = _mm_set1_epi32(Q);
			/**
			 * @brief Редукция Монтгомери четырёх значений с приведением к [0, q)
			 *
			 * @param value четыре 32-разрядных значения
			 *
			 * @return      четыре значения из [0, q) в 32-разрядных местах
			 *
			 */
			auto reduce = [&factor, &modulus](const __m128i value) noexcept -> __m128i {
				// Младшие 16 разрядов значения на множитель: старшие половины мест обнуляются нулём множителя
				const __m128i low = _mm_mullo_epi16(value, factor);
				// Разность значения и произведения множителя на модуль, делённая на 2^16
				__m128i reduced = _mm_srai_epi32(_mm_sub_epi32(value, _mm_madd_epi16(low, modulus)), 16);
				// Прибавляем модуль под маской знака
				reduced = _mm_add_epi32(reduced, _mm_and_si128(_mm_srai_epi32(reduced, 31), modulus));
				// Выводим приведённые значения
				return reduced;
			};
			/**
			 * Выполняем перебор восьмёрок коэффициентов
			 */
			for(size_t i = 0; i < N; i += 8){
				// Приведённые чётные и нечётные коэффициенты восьмёрки
				const __m128i even = reduce(_mm_loadu_si128(reinterpret_cast <const __m128i *> (wide.values + i)));
				const __m128i odd = reduce(_mm_loadu_si128(reinterpret_cast <const __m128i *> (wide.values + i + 4)));
				// Переплетаем чётные и нечётные в 16-разрядные места: старшие половины чётных пусты
				_mm_storeu_si128(reinterpret_cast <__m128i *> (result.values + i), _mm_or_si128(even, _mm_slli_epi32(odd, 16)));
			}
		/**
		 * Переносимый путь
		 */
		#else
			/**
			 * Выполняем перебор коэффициентов
			 */
			for(size_t i = 0; i < N; i++)
				// Приводим накопленное значение редукцией Монтгомери и знаком
				result.values[i] = canonical(montgomery(wide.values[i]));
		#endif
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
		// Числитель округлённого частного value·2^bits + q/2: ниже 2^23 при bits ≤ 11
		const uint32_t numerator = ((static_cast <uint32_t> (value) << bits) + (static_cast <uint32_t> (Q) / 2));
		/**
		 * Частное умножением на обратное: 2^36/q, округлённое вверх, есть 20642679, его избыток над
		 * 2^36/q равен 1655/2^36, и частное точно при числителе ниже 2^36/1655 (щуп packprobe круга 36
		 * сличил с делением все value < q при bits от 1 до 11); деление на q у lcc остаётся делением
		 */
		return (static_cast <uint32_t> ((static_cast <uint64_t> (numerator) * 20642679ULL) >> 36) & ((1u << bits) - 1));
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
	 * @note Разрядности наборов FIPS 203 - 10 и 11 у вектора u, 4 и 5 у многочлена v - пишутся
	 *       жёсткими узорами байтов: четыре коэффициента в пять байтов, восемь в одиннадцать,
	 *       два в один, восемь в пять. Побитовый накопитель оставлен для прочих разрядностей:
	 *       он стоил на многочлене 155 нс на M4 против 13 у узора (щуп packprobe круга 36)
	 */
	static void pack(const poly_t & poly, const size_t bits, uint8_t * result) noexcept {
		// Сжатые коэффициенты
		uint16_t values[N];
		/**
		 * Выполняем сжатие коэффициентов
		 */
		for(size_t i = 0; i < N; i++)
			// Сжимаем коэффициент
			values[i] = static_cast <uint16_t> (compress(poly.values[i], bits));
		/**
		 * Определяем разрядность сжатия
		 */
		switch(bits){
			// Четыре разряда: два коэффициента в байт
			case 4: {
				/**
				 * Выполняем перебор пар коэффициентов
				 */
				for(size_t i = 0; i < N; i += 2)
					// Записываем байт
					result[i / 2] = static_cast <uint8_t> (values[i] | (values[i + 1] << 4));
			} break;
			// Пять разрядов: восемь коэффициентов в пять байтов
			case 5: {
				/**
				 * Выполняем перебор восьмёрок коэффициентов
				 */
				for(size_t i = 0; i < N; i += 8, result += 5){
					// Коэффициенты восьмёрки
					const uint16_t * v = (values + i);
					// Записываем байты узора
					result[0] = static_cast <uint8_t> (v[0] | (v[1] << 5));
					result[1] = static_cast <uint8_t> ((v[1] >> 3) | (v[2] << 2) | (v[3] << 7));
					result[2] = static_cast <uint8_t> ((v[3] >> 1) | (v[4] << 4));
					result[3] = static_cast <uint8_t> ((v[4] >> 4) | (v[5] << 1) | (v[6] << 6));
					result[4] = static_cast <uint8_t> ((v[6] >> 2) | (v[7] << 3));
				}
			} break;
			// Десять разрядов: четыре коэффициента в пять байтов
			case 10: {
				/**
				 * Выполняем перебор четвёрок коэффициентов
				 */
				for(size_t i = 0; i < N; i += 4, result += 5){
					// Коэффициенты четвёрки
					const uint16_t * v = (values + i);
					// Записываем байты узора
					result[0] = static_cast <uint8_t> (v[0]);
					result[1] = static_cast <uint8_t> ((v[0] >> 8) | (v[1] << 2));
					result[2] = static_cast <uint8_t> ((v[1] >> 6) | (v[2] << 4));
					result[3] = static_cast <uint8_t> ((v[2] >> 4) | (v[3] << 6));
					result[4] = static_cast <uint8_t> (v[3] >> 2);
				}
			} break;
			// Одиннадцать разрядов: восемь коэффициентов в одиннадцать байтов
			case 11: {
				/**
				 * Выполняем перебор восьмёрок коэффициентов
				 */
				for(size_t i = 0; i < N; i += 8, result += 11){
					// Коэффициенты восьмёрки
					const uint16_t * v = (values + i);
					// Записываем байты узора
					result[0] = static_cast <uint8_t> (v[0]);
					result[1] = static_cast <uint8_t> ((v[0] >> 8) | (v[1] << 3));
					result[2] = static_cast <uint8_t> ((v[1] >> 5) | (v[2] << 6));
					result[3] = static_cast <uint8_t> (v[2] >> 2);
					result[4] = static_cast <uint8_t> ((v[2] >> 10) | (v[3] << 1));
					result[5] = static_cast <uint8_t> ((v[3] >> 7) | (v[4] << 4));
					result[6] = static_cast <uint8_t> ((v[4] >> 4) | (v[5] << 7));
					result[7] = static_cast <uint8_t> (v[5] >> 1);
					result[8] = static_cast <uint8_t> ((v[5] >> 9) | (v[6] << 2));
					result[9] = static_cast <uint8_t> ((v[6] >> 6) | (v[7] << 5));
					result[10] = static_cast <uint8_t> (v[7] >> 3);
				}
			} break;
			// Прочие разрядности: побитовый накопитель
			default: {
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
					buffer |= (static_cast <uint32_t> (values[i]) << count);
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
		}
	}
	/**
	 * @brief Метод разбора многочлена с расширением из заданной разрядности
	 *
	 * @param data 32·bits байтов записи
	 * @param bits разрядность сжатия
	 * @param poly место, в которое помещается многочлен
	 *
	 * @note Узоры байтов зеркальны узорам записи; побитовый накопитель - для прочих разрядностей
	 */
	static void unpack(const uint8_t * data, const size_t bits, poly_t & poly) noexcept {
		// Сжатые коэффициенты
		uint16_t values[N];
		/**
		 * Определяем разрядность сжатия
		 */
		switch(bits){
			// Четыре разряда: байт на два коэффициента
			case 4: {
				/**
				 * Выполняем перебор пар коэффициентов
				 */
				for(size_t i = 0; i < N; i += 2){
					// Читаем коэффициенты байта
					values[i] = static_cast <uint16_t> (data[i / 2] & 0x0F);
					values[i + 1] = static_cast <uint16_t> (data[i / 2] >> 4);
				}
			} break;
			// Пять разрядов: пять байтов на восемь коэффициентов
			case 5: {
				/**
				 * Выполняем перебор восьмёрок коэффициентов
				 */
				for(size_t i = 0; i < N; i += 8, data += 5){
					// Коэффициенты восьмёрки
					uint16_t * v = (values + i);
					// Читаем коэффициенты узора
					v[0] = static_cast <uint16_t> (data[0] & 0x1F);
					v[1] = static_cast <uint16_t> (((data[0] >> 5) | (data[1] << 3)) & 0x1F);
					v[2] = static_cast <uint16_t> ((data[1] >> 2) & 0x1F);
					v[3] = static_cast <uint16_t> (((data[1] >> 7) | (data[2] << 1)) & 0x1F);
					v[4] = static_cast <uint16_t> (((data[2] >> 4) | (data[3] << 4)) & 0x1F);
					v[5] = static_cast <uint16_t> ((data[3] >> 1) & 0x1F);
					v[6] = static_cast <uint16_t> (((data[3] >> 6) | (data[4] << 2)) & 0x1F);
					v[7] = static_cast <uint16_t> (data[4] >> 3);
				}
			} break;
			// Десять разрядов: пять байтов на четыре коэффициента
			case 10: {
				/**
				 * Выполняем перебор четвёрок коэффициентов
				 */
				for(size_t i = 0; i < N; i += 4, data += 5){
					// Коэффициенты четвёрки
					uint16_t * v = (values + i);
					// Читаем коэффициенты узора
					v[0] = static_cast <uint16_t> ((data[0] | (data[1] << 8)) & 0x3FF);
					v[1] = static_cast <uint16_t> (((data[1] >> 2) | (data[2] << 6)) & 0x3FF);
					v[2] = static_cast <uint16_t> (((data[2] >> 4) | (data[3] << 4)) & 0x3FF);
					v[3] = static_cast <uint16_t> (((data[3] >> 6) | (data[4] << 2)) & 0x3FF);
				}
			} break;
			// Одиннадцать разрядов: одиннадцать байтов на восемь коэффициентов
			case 11: {
				/**
				 * Выполняем перебор восьмёрок коэффициентов
				 */
				for(size_t i = 0; i < N; i += 8, data += 11){
					// Коэффициенты восьмёрки
					uint16_t * v = (values + i);
					// Читаем коэффициенты узора
					v[0] = static_cast <uint16_t> ((data[0] | (data[1] << 8)) & 0x7FF);
					v[1] = static_cast <uint16_t> (((data[1] >> 3) | (data[2] << 5)) & 0x7FF);
					v[2] = static_cast <uint16_t> (((data[2] >> 6) | (data[3] << 2) | (data[4] << 10)) & 0x7FF);
					v[3] = static_cast <uint16_t> (((data[4] >> 1) | (data[5] << 7)) & 0x7FF);
					v[4] = static_cast <uint16_t> (((data[5] >> 4) | (data[6] << 4)) & 0x7FF);
					v[5] = static_cast <uint16_t> (((data[6] >> 7) | (data[7] << 1) | (data[8] << 9)) & 0x7FF);
					v[6] = static_cast <uint16_t> (((data[8] >> 2) | (data[9] << 6)) & 0x7FF);
					v[7] = static_cast <uint16_t> (((data[9] >> 5) | (data[10] << 3)) & 0x7FF);
				}
			} break;
			// Прочие разрядности: побитовый накопитель
			default: {
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
					// Читаем сжатое значение
					values[i] = static_cast <uint16_t> (buffer & ((1u << bits) - 1));
					// Сдвигаем накопитель
					buffer >>= bits;
					// Уменьшаем число разрядов
					count -= bits;
				}
			}
		}
		/**
		 * Выполняем расширение коэффициентов
		 */
		for(size_t i = 0; i < N; i++)
			// Расширяем сжатое значение до коэффициента
			poly.values[i] = decompress(values[i], bits);
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
		 * Поток выжимается блоками SHAKE128 по 168 байтов - 56 троек: выжимание по три
		 * байта стоило вызов на тройку, а блок кратен тройке, и тройки не рвутся по краям
		 */
		uint8_t block[168];
		/**
		 * Выполняем выборку до заполнения многочлена
		 */
		while(count < N){
			// Выжимаем блок потока
			xof.squeeze(block, sizeof(block));
			/**
			 * Выполняем перебор троек байтов блока
			 */
			for(size_t at = 0; (at < sizeof(block)) && (count < N); at += 3){
				// Первый претендент
				const uint16_t first = static_cast <uint16_t> (block[at] | ((block[at + 1] & 0x0F) << 8));
				// Второй претендент
				const uint16_t second = static_cast <uint16_t> ((block[at + 1] >> 4) | (block[at + 2] << 4));
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
		// Байты псевдослучайного потока: 64·η байтов
		uint8_t bytes[64 * 3];
		// Функция переменного выхода потока
		digest::keccak_t prf(digest::sha3_t::SHAKE256);
		// Поглощаем затравку
		prf.update(view_t(sigma, SEED));
		// Поглощаем порядковый номер
		prf.update(view_t(&nonce, 1));
		// Выжимаем поток
		prf.squeeze(bytes, 64 * eta);
		// Если η равно двум
		if(eta == 2){
			/**
			 * Каждый байт даёт два коэффициента: суммы пар разрядов считаются разом маской
			 * 0x55 - сложение разряда с соседом даёт двухразрядные суммы в каждой четвёрке.
			 * Прежний ход по разряду стоил 524 нс на многочлен на M4 (круг 35, 23.09.2026)
			 */
			for(size_t i = 0; i < (N / 2); i++){
				// Очередной байт потока
				const uint32_t byte = bytes[i];
				// Суммы соседних разрядов по парам: по два разряда на пару
				const uint32_t sums = ((byte & 0x55) + ((byte >> 1) & 0x55));
				// Первый коэффициент: разность сумм первой и второй пары
				poly.values[2 * i] = once(static_cast <int32_t> (sums & 3) - static_cast <int32_t> ((sums >> 2) & 3) + Q);
				// Второй коэффициент: разность сумм третьей и четвёртой пары
				poly.values[(2 * i) + 1] = once(static_cast <int32_t> ((sums >> 4) & 3) - static_cast <int32_t> ((sums >> 6) & 3) + Q);
			}
		// Если η равно трём: три байта дают четыре коэффициента
		} else {
			/**
			 * Каждые три байта - 24 разряда - дают четыре коэффициента по шести разрядам:
			 * суммы троек разрядов считаются разом маской 0x249249
			 */
			for(size_t i = 0; i < (N / 4); i++){
				// Очередные три байта потока одним словом
				const uint32_t word = (static_cast <uint32_t> (bytes[3 * i]) | (static_cast <uint32_t> (bytes[(3 * i) + 1]) << 8) | (static_cast <uint32_t> (bytes[(3 * i) + 2]) << 16));
				// Суммы троек разрядов: по три разряда на тройку
				const uint32_t sums = ((word & 0x00249249) + ((word >> 1) & 0x00249249) + ((word >> 2) & 0x00249249));
				/**
				 * Выполняем перебор четырёх коэффициентов слова
				 */
				for(size_t j = 0; j < 4; j++){
					// Сумма первой тройки разрядов
					const int32_t first = static_cast <int32_t> ((sums >> (6 * j)) & 7);
					// Сумма второй тройки разрядов
					const int32_t second = static_cast <int32_t> ((sums >> ((6 * j) + 3)) & 7);
					// Коэффициент: разность сумм
					poly.values[(4 * i) + j] = once((first - second) + Q);
				}
			}
		}
		// Выполняем затирание байтов потока
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
		// Вектор r в области NTT, подготовленный к умножению
		twisted_t r[K];
		/**
		 * Выполняем выборку вектора r
		 */
		for(size_t i = 0; i < sample.k; i++){
			// Многочлен r_i
			poly_t poly;
			// Выбираем многочлен
			binomial(seed, static_cast <uint8_t> (i), sample.eta1, poly);
			// Переводим в область NTT
			forward(poly);
			// Готовим к умножению
			prepare(poly, r[i]);
			// Выполняем затирание многочлена
			wipe(poly.values, sizeof(poly.values));
		}
		// Вектор u
		poly_t u[K];
		/**
		 * Выполняем вычисление u = A^T r + e1
		 */
		for(size_t i = 0; i < sample.k; i++){
			// Накопитель произведений
			wide_t wide;
			// Обнуляем накопитель
			::memset(wide.values, 0, sizeof(wide.values));
			/**
			 * Выполняем перебор столбцов
			 */
			for(size_t j = 0; j < sample.k; j++){
				// Элемент матрицы A[j][i]: транспонирование
				poly_t a;
				// Выбираем элемент
				sampling(rho, static_cast <uint8_t> (j), static_cast <uint8_t> (i), a);
				// Накапливаем произведение
				multiply(a, r[j], wide);
			}
			// Приводим накопитель
			settle(wide, u[i]);
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
				u[i].values[c] = once(u[i].values[c] + e.values[c]);
			// Выполняем затирание шума: вместе с u и матрицей он раскрывает r
			wipe(e.values, sizeof(e.values));
		}
		// Накопитель произведений t^T r
		wide_t wide;
		// Обнуляем накопитель
		::memset(wide.values, 0, sizeof(wide.values));
		/**
		 * Выполняем вычисление t^T r
		 */
		for(size_t i = 0; i < sample.k; i++)
			// Накапливаем произведение
			multiply(t[i], r[i], wide);
		// Многочлен v
		poly_t v;
		// Приводим накопитель
		settle(wide, v);
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
		// Накопитель произведений s^T NTT(u)
		wide_t wide;
		// Обнуляем накопитель
		::memset(wide.values, 0, sizeof(wide.values));
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
			// Многочлен u_i, подготовленный к умножению: готовится он, открытый, а не секрет
			twisted_t prepared;
			// Готовим к умножению
			prepare(u, prepared);
			// Многочлен s_i
			poly_t s;
			// Разбираем многочлен
			decode(secret + (i * POLY), s);
			// Накапливаем произведение
			multiply(s, prepared, wide);
			// Выполняем затирание секретного многочлена
			wipe(s.values, sizeof(s.values));
		}
		// Многочлен w = v - s^T u
		poly_t w;
		// Приводим накопитель
		settle(wide, w);
		// Переводим из области NTT
		inverse(w);
		// Выполняем затирание накопителя: он раскрывает секрет
		wipe(wide.values, sizeof(wide.values));
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
	// Секрет, подготовленный к умножению
	twisted_t prepared[K];
	/**
	 * Выполняем выборку секрета
	 */
	for(size_t i = 0; i < sample.k; i++){
		// Выбираем многочлен
		binomial(sigma, static_cast <uint8_t> (i), sample.eta1, s[i]);
		// Переводим в область NTT
		forward(s[i]);
		// Готовим к умножению
		prepare(s[i], prepared[i]);
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
		// Накопитель произведений строки
		wide_t wide;
		// Обнуляем накопитель
		::memset(wide.values, 0, sizeof(wide.values));
		/**
		 * Выполняем перебор столбцов
		 */
		for(size_t j = 0; j < sample.k; j++){
			// Элемент матрицы A[i][j]
			poly_t a;
			// Выбираем элемент
			sampling(rho, static_cast <uint8_t> (i), static_cast <uint8_t> (j), a);
			// Накапливаем произведение
			multiply(a, prepared[j], wide);
		}
		// Произведение строки на секрет
		poly_t product;
		// Приводим накопитель
		settle(wide, product);
		/**
		 * Выполняем сложение произведения с шумом
		 */
		for(size_t c = 0; c < N; c++)
			// Складываем коэффициенты
			t.values[c] = once(t.values[c] + product.values[c]);
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
	// Выполняем затирание подготовленного секрета
	wipe(prepared, sizeof(prepared));
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
