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
 *  1. Приведение по модулю делается редукцией Барретта с условным вычитанием по маске:
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
 *  6. Поток SHAKE128 при выборке матрицы выжимается блоками по 168 байтов (56 троек), а не
 *    по три байта; биномиальная выборка считает суммы разрядов масками 0x55 и 0x249249
 *    по байту и по трём байтам, а не разрядом за разрядом. Так же устроены выборки у
 *    OpenSSL (crypto/ml_kem/ml_kem.c: sample_scalar, cbd_2, cbd_3). Щуп kemprobe круга 35:
 *    выборка многочлена матрицы 1 119 → 731 нс, биномиальная 524 → 173 (M4).
 *
 *  7. Сжатие коэффициентов идёт умножением на обратное 2^36/q в 64 разрядах, а не делением на q:
 *    у clang и gcc деление на константу и так обращается в такое умножение, у lcc на Эльбрусе
 *    остаётся делением (упаковка многочлена там стоила 4 326 нс при 930…1 030 на x86). Записи
 *    разрядностей 4, 5, 10 и 11 - всех у наборов FIPS 203 - пишутся и читаются жёсткими узорами
 *    байтов, а побитовый накопитель оставлен прочим разрядностям: узор на M4 13 нс против 155
 *    у накопителя (щуп packprobe круга 36), упаковка многочлена 250 → 64 нс, инкапсуляция
 *    12,0 → 11,2 мкс, раскрытие 15,7 → 14,3.
 *
 *  8. Прямое и обратное NTT идут на векторной прослойке (vec_t и v-функции: SSE2 на x86-64,
 *    пакетные команды Эльбруса __builtin_e2k_qp* с набором команд 5 и старше; та же прослойка
 *    держит подготовку, умножение и приведение решения 1): слои с длиной от 8 - целыми
 *    векторами по восемь коэффициентов, слои длины 4 и 2 - шестнадцатью коэффициентами за шаг с
 *    перестановками 64-разрядных половин и пар двойных слов (степени ζ этих слоёв заготовлены по
 *    местам векторов: forward4, forward2, inverse4, inverse2), редукция Барретта на местах с тем
 *    же округлением, что у скалярной ((старшая половина произведения + 512) >> 10). Итог побитово
 *    равен переносимому пути: щуп nttcheck (круг 36, 23.09.2026) сличил хеш итогов NTT, умножения
 *    и упаковки на 200 многочленах с краями между M4, x86 и Эльбрусом - у lcc 9 402 → 2 249 нс на
 *    прямое NTT и 8 981 → 2 250 на обратное (скалярные бабочки он не векторизует), ML-KEM-768 там
 *    110 / 125 / 177 → 62,6 / 70,6 / 94,8 мкс; числа x86 - CONFORMANCE.md, круг 36. Переносимый путь
 *    остаётся у прочих: на M4 clang кладёт скалярные бабочки на NEON сам (151 нс).
 *
 *  2. Таблица степеней ζ считается один раз при первом обращении, а не выписывается
 *    числами: так она сверяется с определением стандарта, а не с чьей-то распечаткой.
 *
 *  3. Ключ декапсуляции держится полной записью стандарта dk_PKE || ek || H(ek) || z:
 *    так его выдаёт и принимает всякая иная реализация, а хеш внутри записи позволяет
 *    проверять ключ по разделу 7.3 без пересчёта.
 *
 *  4. Сравнение шифртекстов при декапсуляции и выбор между настоящим и неявно отвергнутым
 *    секретом идут по маске за постоянное время: иначе разница во времени выдавала бы
 *    исход проверки, на чём стоят атаки на решёточные схемы.
 *
 *  5. Вся рабочая память лежит на стеке: у ML-KEM-1024 матрица занимает восемь килобайтов,
 *    и ни один шаг не занимает память кучи, оттого методы не могут ответить нехваткой.
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартный заголовочный файл
 */
#include <cstring>

/**
 * @brief Векторные команды под арифметику NTT: SSE2 на x86-64 (есть на всякой x86-64) и пакетные
 *        команды Эльбруса с набором команд 5 и старше (128-разрядные регистры, восемь мест по 16
 *        разрядов); обе ветви идут через одну прослойку (vec_t и v-функции ниже)
 *
 * @note Собиратель Microsoft Visual C++ признаков наборов команд не объявляет, но команды
 *       основания набора - SSE2 у x86-64 и NEON у ARM64 - доступны ему без ключей сборки,
 *       потому стена открывается признаком архитектуры вместо признака набора
 *
 */
#if ((defined(__x86_64__) && defined(__SSE2__)) || defined(__ANTS_MSVC_X64__)) && !defined(ANTS_NO_MACHINE)
	/**
	 * Системный заголовочный файл
	 */
	#include <emmintrin.h>

	/**
	 * Признаки векторного пути: команды SSE2
	 */
	#define __ANTS_MLKEM_SSE2__
	/**
	 * Признак общего векторного пути
	 */
	#define __ANTS_MLKEM_VECTOR__
/**
 * Ветвь пакетных команд Эльбруса с набором команд 5 и старше
 */
#elif defined(__e2k__) && defined(__iset__) && (__iset__ >= 5) && !defined(ANTS_NO_MACHINE)
	/**
	 * Признаки векторного пути: пакетные команды Эльбруса
	 */
	#define __ANTS_MLKEM_E2K__
	/**
	 * Признак общего векторного пути
	 */
	#define __ANTS_MLKEM_VECTOR__
/**
 * Ветвь NEON на ARM64: расширение вечно доступно на этой архитектуре
 */
#elif ((defined(__aarch64__) && defined(__ARM_NEON)) || defined(__ANTS_MSVC_ARM64__)) && !defined(ANTS_NO_MACHINE)
	/**
	 * Системный заголовочный файл
	 */
	#include <arm_neon.h>

	/**
	 * Признаки векторного пути: команды NEON
	 */
	#define __ANTS_MLKEM_NEON__
	/**
	 * Признак общего векторного пути
	 */
	#define __ANTS_MLKEM_VECTOR__
#endif

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/wipe.hpp>
#include <digest/sha3.hpp>
#include <entropy/entropy.hpp>
#include <internal/digest/keccak.hpp>

/**
 * На x86-64 с командами Keccak-x4 нужен опрос признаков машины
 */
#if defined(__ANTS_KECCAK_X4__) && defined(__x86_64__)
	/**
	 * Подключаем заголовочный файл проекта
	 */
	#include <sys/machine.hpp>
#endif

/**
 * Подключаем заголовочный файл модуля
 */
#include <agreement/mlkem.hpp>

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
	 * Наибольшая размерность модуля
	 */
	static constexpr size_t K = 4;
	/**
	 * Число коэффициентов многочлена
	 */
	static constexpr size_t N = 256;
	/**
	 * Длина зерна ρ, σ и хешей
	 */
	static constexpr size_t SEED = 32;
	/**
	 * Модуль кольца
	 */
	static constexpr int32_t Q = 3329;
	/**
	 * Длина записи многочлена по двенадцать разрядов на коэффициент
	 */
	static constexpr size_t POLY = 384;
	/**
	 * Обратное к 128 по модулю q: множитель обратного преобразования
	 */
	static constexpr int32_t INVERSE = 3303;

	/**
	 * Векторная прослойка: восемь 16-разрядных либо четыре 32-разрядных места в одном регистре
	 */
	#if defined(__ANTS_MLKEM_SSE2__)
		/**
		 * Создаём тип вектора в 128 разрядов
		 */
		using vec_t = __m128i;

		/**
		 * @brief Функция загрузки выровненного 128-разрядного вектора из памяти
		 *
		 * @param data адрес выровненных под вектор слов
		 * @return     собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t loadVector(const void * data) noexcept {
			// Загружаем вектор одним обращением к выровненной памяти
			return _mm_load_si128(reinterpret_cast <const __m128i *> (data));
		}
		/**
		 * @brief Функция записи 128-разрядного вектора в память выровненным сохранением
		 *
		 * @param result место записи вектора
		 * @param value  передаваемое значение
		 *
		 */
		static __ANTS_INLINE__ void storeVector(void * result, const vec_t value) noexcept {
			// Записываем вектор одним обращением к выровненной памяти
			_mm_store_si128(reinterpret_cast <__m128i *> (result), value);
		}
		/**
		 * @brief Функция заполнения всех 16-разрядных мест вектора одним значением
		 *
		 * @param value передаваемое значение
		 * @return      собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t broadcast16(const int16_t value) noexcept {
			// Заполняем значением все 16-разрядные места
			return _mm_set1_epi16(value);
		}
		/**
		 * @brief Функция заполнения всех 32-разрядных мест вектора одним значением
		 *
		 * @param value передаваемое значение
		 * @return      собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t broadcast32(const int32_t value) noexcept {
			// Заполняем значением все 32-разрядные места
			return _mm_set1_epi32(value);
		}
		/**
		 * @brief Функция умножения 16-разрядных мест с младшими половинами произведений
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t multiplyLow16(const vec_t first, const vec_t second) noexcept {
			// Умножаем места и берём младшие половины произведений
			return _mm_mullo_epi16(first, second);
		}
		/**
		 * @brief Функция умножения 16-разрядных мест со старшими половинами произведений
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t multiplyHigh16(const vec_t first, const vec_t second) noexcept {
			// Умножаем места и берём старшие половины произведений
			return _mm_mulhi_epi16(first, second);
		}
		/**
		 * @brief Функция суммирования произведений соседних 16-разрядных мест в 32-разрядные
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t multiplySum16(const vec_t first, const vec_t second) noexcept {
			// Считаем суммы произведений соседних мест в 32 разрядах
			return _mm_madd_epi16(first, second);
		}
		/**
		 * @brief Функция сложения 16-разрядных мест двух векторов
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t add16(const vec_t first, const vec_t second) noexcept {
			// Складываем 16-разрядные места
			return _mm_add_epi16(first, second);
		}
		/**
		 * @brief Функция вычитания 16-разрядных мест двух векторов
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t subtract16(const vec_t first, const vec_t second) noexcept {
			// Вычитаем 16-разрядные места
			return _mm_sub_epi16(first, second);
		}
		/**
		 * @brief Функция сложения 32-разрядных мест двух векторов
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t add32(const vec_t first, const vec_t second) noexcept {
			// Складываем 32-разрядные места
			return _mm_add_epi32(first, second);
		}
		/**
		 * @brief Функция вычитания 32-разрядных мест двух векторов
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t subtract32(const vec_t first, const vec_t second) noexcept {
			// Вычитаем 32-разрядные места
			return _mm_sub_epi32(first, second);
		}
		/**
		 * @brief Функция арифметического сдвига 16-разрядных мест вправо
		 *
		 * @param value передаваемое значение
		 * @param count число разрядов сдвига
		 * @return      собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t shiftRight16(const vec_t value, const int count) noexcept {
			// Сдвигаем 16-разрядные места вправо на заданные разряды
			return _mm_srai_epi16(value, count);
		}
		/**
		 * @brief Функция арифметического сдвига 32-разрядных мест вправо
		 *
		 * @param value передаваемое значение
		 * @param count число разрядов сдвига
		 * @return      собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t shiftRight32(const vec_t value, const int count) noexcept {
			// Сдвигаем 32-разрядные места вправо на заданные разряды
			return _mm_srai_epi32(value, count);
		}
		/**
		 * @brief Функция поразрядного умножения маски на вектор
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t maskBits(const vec_t first, const vec_t second) noexcept {
			// Накладываем маску поразрядным умножением
			return _mm_and_si128(first, second);
		}
		/**
		 * @brief Функция перестановки соседних 16-разрядных слов в каждом 32-разрядном месте
		 *
		 * @param value передаваемое значение
		 * @return      собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t swapHalves16(const vec_t value) noexcept {
			// Меняем местами соседние 16-разрядные слова каждого 32-разрядного места
			return _mm_shufflehi_epi16(_mm_shufflelo_epi16(value, 0xB1), 0xB1);
		}
		/**
		 * @brief Функция сборки младших 64-разрядных половин двух векторов рядом
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t takeLow64(const vec_t first, const vec_t second) noexcept {
			// Ставим младшие 64-разрядные половины двух векторов рядом
			return _mm_unpacklo_epi64(first, second);
		}
		/**
		 * @brief Функция сборки старших 64-разрядных половин двух векторов рядом
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t takeHigh64(const vec_t first, const vec_t second) noexcept {
			// Ставим старшие 64-разрядные половины двух векторов рядом
			return _mm_unpackhi_epi64(first, second);
		}
		/**
		 * @brief Функция переплетения младших пар 32-разрядных мест двух векторов
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t interleaveLow32(const vec_t first, const vec_t second) noexcept {
			// Переплетаем младшие пары 32-разрядных мест
			return _mm_unpacklo_epi32(first, second);
		}
		/**
		 * @brief Функция переплетения старших пар 32-разрядных мест двух векторов
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t interleaveHigh32(const vec_t first, const vec_t second) noexcept {
			// Переплетаем старшие пары 32-разрядных мест
			return _mm_unpackhi_epi32(first, second);
		}
		/**
		 * @brief Функция перестановки чётных 32-разрядных мест вперёд и нечётных назад
		 *
		 * @param value передаваемое значение
		 * @return      собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t evenOdd32(const vec_t value) noexcept {
			// Ставим чётные 32-разрядные места вперёд, нечётные назад
			return _mm_shuffle_epi32(value, 0xD8);
		}
		/**
		 * @brief Функция переплетения младших половин 32-разрядных мест в 16-разрядные слова
		 *
		 * @param even вектор чётных мест
		 * @param odd  вектор нечётных мест
		 * @return     собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t interleave16(const vec_t even, const vec_t odd) noexcept {
			// Собираем младшие половины 32-разрядных мест в 16-разрядные слова
			return _mm_or_si128(even, _mm_slli_epi32(odd, 16));
		}
	/**
	 * Ветвь векторной прослойки Эльбруса: тот же тип вектора и пакетные команды
	 */
	#elif defined(__ANTS_MLKEM_E2K__)
		/**
		 * Создаём тип вектора в 128 разрядов: тот же тип, что __v2di заголовков lcc
		 */
		typedef long long vec_t __attribute__ ((__vector_size__ (16)));

		/**
		 * @brief Функция загрузки выровненного 128-разрядного вектора из памяти
		 *
		 * @param data адрес выровненных под вектор слов
		 * @return     собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t loadVector(const void * data) noexcept {
			// Загружаем вектор одним обращением к выровненной памяти
			return (* reinterpret_cast <const vec_t *> (data));
		}
		/**
		 * @brief Функция записи 128-разрядного вектора в память выровненным сохранением
		 *
		 * @param result место записи вектора
		 * @param value  передаваемое значение
		 *
		 */
		static __ANTS_INLINE__ void storeVector(void * result, const vec_t value) noexcept {
			// Записываем вектор одним обращением к выровненной памяти
			(* reinterpret_cast <vec_t *> (result)) = value;
		}
		/**
		 * @brief Функция сборки вектора из двух 64-разрядных слов
		 *
		 * @return собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t packWords(const uint64_t high, const uint64_t low) noexcept {
			// Вектор из двух 64-разрядных слов: старшее и младшее
			return __builtin_e2k_qppackdl(high, low);
		}
		/**
		 * @brief Функция заполнения всех 16-разрядных мест вектора одним значением
		 *
		 * @param value передаваемое значение
		 * @return      собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t broadcast16(const int16_t value) noexcept {
			// Раскладываем значение по всем 16-разрядным словам числа
			const uint64_t word = (static_cast <uint64_t> (static_cast <uint16_t> (value)) * 0x0001000100010001ULL);
			// Собираем вектор из двух одинаковых слов
			return packWords(word, word);
		}
		/**
		 * @brief Функция заполнения всех 32-разрядных мест вектора одним значением
		 *
		 * @param value передаваемое значение
		 * @return      собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t broadcast32(const int32_t value) noexcept {
			// Раскладываем значение по двум 32-разрядным словам числа
			const uint64_t word = (static_cast <uint64_t> (static_cast <uint32_t> (value)) * 0x0000000100000001ULL);
			// Собираем вектор из двух одинаковых слов
			return packWords(word, word);
		}
		/**
		 * @brief Функция умножения 16-разрядных мест с младшими половинами произведений
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t multiplyLow16(const vec_t first, const vec_t second) noexcept {
			// Умножаем места и берём младшие половины произведений
			return __builtin_e2k_qpmullh(first, second);
		}
		/**
		 * @brief Функция умножения 16-разрядных мест со старшими половинами произведений
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t multiplyHigh16(const vec_t first, const vec_t second) noexcept {
			// Умножаем места и берём старшие половины произведений
			return __builtin_e2k_qpmulhh(first, second);
		}
		/**
		 * @brief Функция суммирования произведений соседних 16-разрядных мест в 32-разрядные
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t multiplySum16(const vec_t first, const vec_t second) noexcept {
			// Считаем суммы произведений соседних мест в 32 разрядах
			return __builtin_e2k_qpmaddh(first, second);
		}
		/**
		 * @brief Функция сложения 16-разрядных мест двух векторов
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t add16(const vec_t first, const vec_t second) noexcept {
			// Складываем 16-разрядные места
			return __builtin_e2k_qpaddh(first, second);
		}
		/**
		 * @brief Функция вычитания 16-разрядных мест двух векторов
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t subtract16(const vec_t first, const vec_t second) noexcept {
			// Вычитаем 16-разрядные места
			return __builtin_e2k_qpsubh(first, second);
		}
		/**
		 * @brief Функция сложения 32-разрядных мест двух векторов
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t add32(const vec_t first, const vec_t second) noexcept {
			// Складываем 32-разрядные места
			return __builtin_e2k_qpaddw(first, second);
		}
		/**
		 * @brief Функция вычитания 32-разрядных мест двух векторов
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t subtract32(const vec_t first, const vec_t second) noexcept {
			// Вычитаем 32-разрядные места
			return __builtin_e2k_qpsubw(first, second);
		}
		/**
		 * @brief Функция арифметического сдвига 16-разрядных мест вправо
		 *
		 * @param value передаваемое значение
		 * @param count число разрядов сдвига
		 * @return      собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t shiftRight16(const vec_t value, const int count) noexcept {
			// Сдвигаем 16-разрядные места вправо на заданные разряды
			return __builtin_e2k_qpsrah(value, count);
		}
		/**
		 * @brief Функция арифметического сдвига 32-разрядных мест вправо
		 *
		 * @param value передаваемое значение
		 * @param count число разрядов сдвига
		 * @return      собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t shiftRight32(const vec_t value, const int count) noexcept {
			// Сдвигаем 32-разрядные места вправо на заданные разряды
			return __builtin_e2k_qpsraw(value, count);
		}
		/**
		 * @brief Функция поразрядного умножения маски на вектор
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t maskBits(const vec_t first, const vec_t second) noexcept {
			// Накладываем маску поразрядным умножением
			return __builtin_e2k_qpand(first, second);
		}
		/**
		 * @brief Функция перестановки соседних 16-разрядных слов в каждом 32-разрядном месте
		 *
		 * @param value передаваемое значение
		 * @return      собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t swapHalves16(const vec_t value) noexcept {
			// Меняем местами соседние 16-разрядные слова каждого 32-разрядного места
			return __builtin_e2k_qppermb(value, value, packWords(0x0d0c0f0e09080b0aULL, 0x0504070601000302ULL));
		}
		/**
		 * @brief Функция сборки младших 64-разрядных половин двух векторов рядом
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t takeLow64(const vec_t first, const vec_t second) noexcept {
			// Ставим младшие 64-разрядные половины двух векторов рядом
			return __builtin_e2k_qppermb(second, first, packWords(0x1716151413121110ULL, 0x0706050403020100ULL));
		}
		/**
		 * @brief Функция сборки старших 64-разрядных половин двух векторов рядом
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t takeHigh64(const vec_t first, const vec_t second) noexcept {
			// Ставим старшие 64-разрядные половины двух векторов рядом
			return __builtin_e2k_qppermb(second, first, packWords(0x1f1e1d1c1b1a1918ULL, 0x0f0e0d0c0b0a0908ULL));
		}
		/**
		 * @brief Функция переплетения младших пар 32-разрядных мест двух векторов
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t interleaveLow32(const vec_t first, const vec_t second) noexcept {
			// Переплетаем младшие пары 32-разрядных мест
			return __builtin_e2k_qppermb(second, first, packWords(0x1716151407060504ULL, 0x1312111003020100ULL));
		}
		/**
		 * @brief Функция переплетения старших пар 32-разрядных мест двух векторов
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t interleaveHigh32(const vec_t first, const vec_t second) noexcept {
			// Переплетаем старшие пары 32-разрядных мест
			return __builtin_e2k_qppermb(second, first, packWords(0x1f1e1d1c0f0e0d0cULL, 0x1b1a19180b0a0908ULL));
		}
		/**
		 * @brief Функция перестановки чётных 32-разрядных мест вперёд и нечётных назад
		 *
		 * @param value передаваемое значение
		 * @return      собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t evenOdd32(const vec_t value) noexcept {
			// Ставим чётные 32-разрядные места вперёд, нечётные назад
			return __builtin_e2k_qppermb(value, value, packWords(0x0f0e0d0c07060504ULL, 0x0b0a090803020100ULL));
		}
		/**
		 * @brief Функция переплетения младших половин 32-разрядных мест в 16-разрядные слова
		 *
		 * @param even вектор чётных мест
		 * @param odd  вектор нечётных мест
		 * @return     собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t interleave16(const vec_t even, const vec_t odd) noexcept {
			// Собираем младшие половины 32-разрядных мест в 16-разрядные слова
			return __builtin_e2k_qppermb(odd, even, packWords(0x1d1c0d0c19180908ULL, 0x1514050411100100ULL));
		}
	/**
	 * Ветвь векторной прослойки NEON: те же операции над 128-разрядными векторами,
	 * результат каждой сводится к раскладке SSE2 по местам
	 */
	#elif defined(__ANTS_MLKEM_NEON__)
		/**
		 * Создаём тип вектора в 128 разрядов: восемь 16-разрядных мест
		 */
		using vec_t = int16x8_t;

		/**
		 * @brief Функция загрузки выровненного 128-разрядного вектора из памяти
		 *
		 * @param data адрес выровненных под вектор слов
		 * @return     собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t loadVector(const void * data) noexcept {
			// Загружаем вектор одним обращением к выровненной памяти
			return vld1q_s16(reinterpret_cast <const int16_t *> (data));
		}
		/**
		 * @brief Функция записи 128-разрядного вектора в память выровненным сохранением
		 *
		 * @param result место записи вектора
		 * @param value  передаваемое значение
		 *
		 */
		static __ANTS_INLINE__ void storeVector(void * result, const vec_t value) noexcept {
			// Записываем вектор одним обращением к выровненной памяти
			vst1q_s16(reinterpret_cast <int16_t *> (result), value);
		}
		/**
		 * @brief Функция заполнения всех 16-разрядных мест вектора одним значением
		 *
		 * @param value передаваемое значение
		 * @return      собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t broadcast16(const int16_t value) noexcept {
			// Заполняем значением все 16-разрядные места
			return vdupq_n_s16(value);
		}
		/**
		 * @brief Функция заполнения всех 32-разрядных мест вектора одним значением
		 *
		 * @param value передаваемое значение
		 * @return      собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t broadcast32(const int32_t value) noexcept {
			// Заполняем значением все 32-разрядные места
			return vreinterpretq_s16_s32(vdupq_n_s32(value));
		}
		/**
		 * @brief Функция умножения 16-разрядных мест с младшими половинами произведений
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t multiplyLow16(const vec_t first, const vec_t second) noexcept {
			// Умножаем места и берём младшие половины произведений
			return vmulq_s16(first, second);
		}
		/**
		 * @brief Функция умножения 16-разрядных мест со старшими половинами произведений
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t multiplyHigh16(const vec_t first, const vec_t second) noexcept {
			// Произведения младших половин вектора в 32 разрядах
			const int32x4_t low = vmull_s16(vget_low_s16(first), vget_low_s16(second));
			// Произведения старших половин вектора в 32 разрядах
			const int32x4_t high = vmull_s16(vget_high_s16(first), vget_high_s16(second));
			// Выводим старшие половины сужением произведений
			return vcombine_s16(vshrn_n_s32(low, 16), vshrn_n_s32(high, 16));
		}
		/**
		 * @brief Функция суммирования произведений соседних 16-разрядных мест в 32-разрядные
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t multiplySum16(const vec_t first, const vec_t second) noexcept {
			// Произведения младших половин вектора в 32 разрядах
			const int32x4_t low = vmull_s16(vget_low_s16(first), vget_low_s16(second));
			// Произведения старших половин вектора в 32 разрядах
			const int32x4_t high = vmull_s16(vget_high_s16(first), vget_high_s16(second));
			// Выводим суммы соседних произведений половин вектора
			return vreinterpretq_s16_s32(vcombine_s32(vpadd_s32(vget_low_s32(low), vget_high_s32(low)), vpadd_s32(vget_low_s32(high), vget_high_s32(high))));
		}
		/**
		 * @brief Функция сложения 16-разрядных мест двух векторов
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t add16(const vec_t first, const vec_t second) noexcept {
			// Складываем 16-разрядные места
			return vaddq_s16(first, second);
		}
		/**
		 * @brief Функция вычитания 16-разрядных мест двух векторов
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t subtract16(const vec_t first, const vec_t second) noexcept {
			// Вычитаем 16-разрядные места
			return vsubq_s16(first, second);
		}
		/**
		 * @brief Функция сложения 32-разрядных мест двух векторов
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t add32(const vec_t first, const vec_t second) noexcept {
			// Складываем 32-разрядные места
			return vreinterpretq_s16_s32(vaddq_s32(vreinterpretq_s32_s16(first), vreinterpretq_s32_s16(second)));
		}
		/**
		 * @brief Функция вычитания 32-разрядных мест двух векторов
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t subtract32(const vec_t first, const vec_t second) noexcept {
			// Вычитаем 32-разрядные места
			return vreinterpretq_s16_s32(vsubq_s32(vreinterpretq_s32_s16(first), vreinterpretq_s32_s16(second)));
		}
		/**
		 * @brief Функция арифметического сдвига 16-разрядных мест вправо
		 *
		 * @param value передаваемое значение
		 * @param count число разрядов сдвига
		 * @return      собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t shiftRight16(const vec_t value, const int count) noexcept {
			// Сдвигаем 16-разрядные места вправо на заданные разряды
			return vshlq_s16(value, vdupq_n_s16(-count));
		}
		/**
		 * @brief Функция арифметического сдвига 32-разрядных мест вправо
		 *
		 * @param value передаваемое значение
		 * @param count число разрядов сдвига
		 * @return      собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t shiftRight32(const vec_t value, const int count) noexcept {
			// Сдвигаем 32-разрядные места вправо на заданные разряды
			return vreinterpretq_s16_s32(vshlq_s32(vreinterpretq_s32_s16(value), vdupq_n_s32(-count)));
		}
		/**
		 * @brief Функция поразрядного умножения маски на вектор
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t maskBits(const vec_t first, const vec_t second) noexcept {
			// Накладываем маску поразрядным умножением
			return vandq_s16(first, second);
		}
		/**
		 * @brief Функция перестановки соседних 16-разрядных слов в каждом 32-разрядном месте
		 *
		 * @param value передаваемое значение
		 * @return      собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t swapHalves16(const vec_t value) noexcept {
			// Меняем местами соседние 16-разрядные слова каждого 32-разрядного места
			return vrev32q_s16(value);
		}
		/**
		 * @brief Функция сборки младших 64-разрядных половин двух векторов рядом
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t takeLow64(const vec_t first, const vec_t second) noexcept {
			// В старшую половину первого ставим младшую половину второго
			return vreinterpretq_s16_u64(vsetq_lane_u64(vgetq_lane_u64(vreinterpretq_u64_s16(second), 0), vreinterpretq_u64_s16(first), 1));
		}
		/**
		 * @brief Функция сборки старших 64-разрядных половин двух векторов рядом
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t takeHigh64(const vec_t first, const vec_t second) noexcept {
			// В младшую половину второго ставим старшую половину первого
			return vreinterpretq_s16_u64(vsetq_lane_u64(vgetq_lane_u64(vreinterpretq_u64_s16(first), 1), vreinterpretq_u64_s16(second), 0));
		}
		/**
		 * @brief Функция переплетения младших пар 32-разрядных мест двух векторов
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t interleaveLow32(const vec_t first, const vec_t second) noexcept {
			// Переплетаем младшие пары мест командой почленного чередования
			return vreinterpretq_s16_s32(vzip1q_s32(vreinterpretq_s32_s16(first), vreinterpretq_s32_s16(second)));
		}
		/**
		 * @brief Функция переплетения старших пар 32-разрядных мест двух векторов
		 *
		 * @param first  первый вектор
		 * @param second второй вектор
		 * @return       собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t interleaveHigh32(const vec_t first, const vec_t second) noexcept {
			// Переплетаем старшие пары мест командой почленного чередования
			return vreinterpretq_s16_s32(vzip2q_s32(vreinterpretq_s32_s16(first), vreinterpretq_s32_s16(second)));
		}
		/**
		 * @brief Функция перестановки чётных 32-разрядных мест вперёд и нечётных назад
		 *
		 * @param value передаваемое значение
		 * @return      собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t evenOdd32(const vec_t value) noexcept {
			/**
			 * Номера байтов мест 0, 2, 1, 3 по порядку: таблица читается загрузкой, потому что
			 * собиратель Microsoft Visual C++ не принимает инициализацию вектора списком
			 */
			static const uint8_t INDICES[16] = {0, 1, 2, 3, 8, 9, 10, 11, 4, 5, 6, 7, 12, 13, 14, 15};
			// Выводим перестановку байтов таблицей
			return vreinterpretq_s16_u8(vqtbl1q_u8(vreinterpretq_u8_s16(value), vld1q_u8(INDICES)));
		}
		/**
		 * @brief Функция переплетения младших половин 32-разрядных мест двух векторов
		 *        в 16-разрядные слова: старшие половины мест пусты
		 *
		 * @param even вектор чётных мест
		 * @param odd  вектор нечётных мест
		 * @return     собранный вектор
		 *
		 */
		static __ANTS_INLINE__ vec_t interleave16(const vec_t even, const vec_t odd) noexcept {
			// Ставим нечётные места сдвигом поверх чётных
			return vreinterpretq_s16_s32(vorrq_s32(vreinterpretq_s32_s16(even), vshlq_n_s32(vreinterpretq_s32_s16(odd), 16)));
		}
	#endif

	/**
	 * Векторная арифметика кольца поверх прослойки
	 */
	#if defined(__ANTS_MLKEM_VECTOR__)
		/**
		 * @brief Функция умножения Монтгомери восьми пар 16-разрядных значений
		 *
		 * @note Младшие 16 разрядов произведения и множителя на модуль равны, оттого разность
		 *       старших половин и есть итог редукции - без заёма (тот же приём у эталонной
		 *       реализации Kyber на AVX2)
		 *
		 * @param first  первые сомножители
		 * @param second вторые сомножители
		 * @return       произведения, делённые на 2^16, по модулю q в (-q, q)
		 *
		 */
		static __ANTS_INLINE__ vec_t multiplyMontgomery(const vec_t first, const vec_t second) noexcept {
			// Младшие и старшие половины произведений
			const vec_t low = multiplyLow16(first, second), high = multiplyHigh16(first, second);
			// Множители, обращающие младшие половины в ноль: q^(-1) mod 2^16 = -3327
			const vec_t zeroing = multiplyLow16(low, broadcast16(-3327));
			// Выводим разность старших половин произведений и множителей на модуль
			return subtract16(high, multiplyHigh16(zeroing, broadcast16(static_cast <int16_t> (Q))));
		}
		/**
		 * @brief Функция редукции Барретта восьми 16-разрядных значений
		 *
		 * @note Частное ((value·20159) + 2^25) >> 26 берётся как (старшие 16 разрядов
		 *       произведения + 512) >> 10: вложенные округления вниз с целыми делителями
		 *       дают то же, что одно
		 *
		 * @param value приводимые значения
		 * @return      значения из [-q/2, q/2], те же, что у скалярной barrett
		 *
		 */
		static __ANTS_INLINE__ vec_t reduceBarrett(const vec_t value) noexcept {
			// Частное с округлением
			const vec_t quotient = shiftRight16(add16(multiplyHigh16(value, broadcast16(20159)), broadcast16(512)), 10);
			// Выводим остаток
			return subtract16(value, multiplyLow16(quotient, broadcast16(static_cast <int16_t> (Q))));
		}
		/**
		 * @brief Функция приведения восьми значений из (-q, q) к [0, q)
		 *
		 * @param value приводимые значения
		 * @return      значения из [0, q)
		 *
		 */
		static __ANTS_INLINE__ vec_t reduceCanonical(const vec_t value) noexcept {
			// Прибавляем модуль под маской знака
			return add16(value, maskBits(shiftRight16(value, 15), broadcast16(static_cast <int16_t> (Q))));
		}
	#endif

	/**
	 * @brief Структура многочлена кольца
	 *
	 */
	typedef struct Poly {
		// Коэффициенты многочлена: выровнены под векторные загрузки
		alignas(16) int16_t values[N];
	} poly_t;
	/**
	 * @brief Структура слота кеша развёрнутой матрицы
	 *
	 * @details Матрица A выводится из публичного зерна ρ ключа инкапсуляции и секрета
	 *          не содержит, поэтому её разворот держится по одному слоту на поток:
	 *          повторные шифрования того же ключа берут готовые многочлены вместо
	 *          новых выборок SHAKE128. Элемент A[x][y] лежит на месте (x * K) + y -
	 *          шаг K постоянен при любой размерности, и слот большего набора годится
	 *          меньшему без перезаполнения.
	 *
	 */
	typedef struct Matrix {
		// Зерно развёрнутой матрицы
		uint8_t seed[SEED];
		// Размерность, до которой развёрнута матрица
		size_t dimension;
		// Многочлены матрицы: элемент A[x][y] на месте (x * K) + y
		poly_t items[K * K];
	} matrix_t;
	/**
	 * @brief Структура описания набора параметров
	 *
	 */
	typedef struct Sample {
		// Параметр η1 выборки секрета
		size_t eta1 = 0;
		// Параметр η2 выборки шума
		size_t eta2 = 0;
		// Разрядность сжатия вектора u
		size_t compressU = 0;
		// Разрядность сжатия многочлена v
		size_t compressV = 0;
		// Размерность модуля: число многочленов в векторе
		size_t dimension = 0;
	} sample_t;

	/**
	 * @brief Функция получения описания набора параметров
	 *
	 * @param kem набор параметров
	 * @return    описание набора либо описание с нулевой размерностью
	 *
	 */
	static __ANTS_INLINE__ sample_t describe(const agreement::kem_t kem) noexcept {
		// Описание набора параметров
		sample_t result = {0, 0, 0, 0, 0};
		/**
		 * Определяем набор параметров
		 */
		switch(static_cast <uint8_t> (kem)){
			// ML-KEM-512
			case static_cast <uint8_t> (agreement::kem_t::MLKEM512):
				// Размерность k, η1, η2, сжатия u и v
				result = {3, 2, 10, 4, 2};
			break;
			// ML-KEM-768
			case static_cast <uint8_t> (agreement::kem_t::MLKEM768):
				// Размерность k, η1, η2, сжатия u и v
				result = {2, 2, 10, 4, 3};
			break;
			// ML-KEM-1024
			case static_cast <uint8_t> (agreement::kem_t::MLKEM1024):
				// Размерность k, η1, η2, сжатия u и v
				result = {2, 2, 11, 5, 4};
			break;
		}
		// Выводим описание набора
		return result;
	}
	/**
	 * @brief Функция приведения числа по модулю q редукцией Барретта
	 *
	 * @param value приводимое число из диапазона [-q·2^15, q·2^15)
	 * @return      число из диапазона [0, q)
	 *
	 */
	static __ANTS_INLINE__ int16_t reduce(const int32_t value) noexcept {
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
	 * @brief Функция умножения двух коэффициентов по модулю q
	 *
	 * @param first  первый множитель
	 * @param second второй множитель
	 * @return       произведение из диапазона [0, q)
	 *
	 */
	static __ANTS_INLINE__ int16_t product(const int32_t first, const int32_t second) noexcept {
		// Выводим приведённое произведение
		return reduce(first * second);
	}
	/**
	 * @brief Функция условного вычитания модуля из значения ниже удвоенного модуля
	 *
	 * @note Сумма и разность приведённых коэффициентов не выходят за удвоенный модуль,
	 *       и полная редукция Барретта им не нужна: бабочки NTT стоили три редукции на
	 *       пару коэффициентов, стало по одной на произведение (круг 35, 23.09.2026)
	 *
	 * @param value приводимое значение из [0, 2q)
	 * @return      значение из [0, q)
	 *
	 */
	static __ANTS_INLINE__ int16_t once(const int32_t value) noexcept {
		// Разность с модулем
		const int32_t difference = (value - Q);
		// Выводим разность, если она не отрицательна, иначе само значение
		return static_cast <int16_t> (difference + (Q & (difference >> 31)));
	}
	/**
	 * @brief Функция приведения значения из [0, q) к полуинтервалу (-q/2, q/2]
	 *
	 * @param value приводимое значение
	 * @return      значение в 16 разрядах со знаком
	 *
	 */
	static __ANTS_INLINE__ int16_t centered(const int32_t value) noexcept {
		// Выводим значение, уменьшенное на модуль, если оно выше половины модуля
		return static_cast <int16_t> ((value > (Q / 2)) ? (value - Q) : value);
	}

	/**
	 * Скалярная арифметика Монтгомери и Барретта нужна лишь переносимому пути
	 */
	#if !defined(__ANTS_MLKEM_VECTOR__)
		/**
		 * @brief Функция редукции Монтгомери 32-разрядного значения
		 *
		 * @note Множитель -3327 обращает младшие 16 разрядов в ноль: q·3327 = 169·2^16 - 1,
		 *       оттого разность wide - factor·q делится на 2^16 нацело, а её старшие разряды
		 *       и есть итог. Тем же приведением снимается множитель 2^16 с накопителя
		 *       произведений в области NTT (settle)
		 *
		 * @param wide приводимое значение, |wide| < q·2^15
		 * @return     wide·2^(-16) mod q в полуинтервале (-q, q)
		 *
		 */
		static __ANTS_INLINE__ int16_t montgomery(const int32_t wide) noexcept {
			// Множитель, обращающий младшие 16 разрядов значения в ноль: q^(-1) mod 2^16 = -3327
			const int16_t factor = static_cast <int16_t> (static_cast <uint16_t> (static_cast <int32_t> (static_cast <int16_t> (static_cast <uint16_t> (wide))) * -3327));
			// Выводим старшие 16 разрядов разности значения и произведения множителя на модуль
			return static_cast <int16_t> ((wide - (static_cast <int32_t> (factor) * Q)) >> 16);
		}
		/**
		 * @brief Функция умножения Монтгомери на 16 разрядах
		 *
		 * @note Так устроены бабочки NTT эталонной реализации Kyber: степень ζ хранится
		 *       умноженной на 2^16, оттого произведение выходит в обычной форме - ζ·x, а вся
		 *       арифметика умещается в 32 разряда без деления и без 64-разрядного умножения,
		 *       и собиратель кладёт бабочки на векторные команды (NEON, SSE2). Щуп nttprobe
		 *       круга 35 (23.09.2026): прямое NTT M4 582 → 150 нс, FreeBSD 3 866 → 1 300
		 *
		 * @param first  первый сомножитель, |first| < 2^15
		 * @param second второй сомножитель, |second| < 2^15
		 * @return       first·second·2^(-16) mod q в полуинтервале (-q, q)
		 *
		 */
		static __ANTS_INLINE__ int16_t fqmul(const int16_t first, const int16_t second) noexcept {
			// Выводим редукцию Монтгомери полного произведения
			return montgomery(static_cast <int32_t> (first) * second);
		}
		/**
		 * @brief Функция редукции Барретта на 16 разрядах
		 *
		 * @param value приводимое значение
		 * @return      значение, сравнимое с исходным по модулю q, из [-q/2, q/2]
		 *
		 */
		static __ANTS_INLINE__ int16_t barrett(const int16_t value) noexcept {
			// Частное с округлением: 2^26 / q = 20159
			const int16_t quotient = static_cast <int16_t> (((static_cast <int32_t> (value) * 20159) + (1 << 25)) >> 26);
			// Выводим остаток
			return static_cast <int16_t> (value - (static_cast <int32_t> (quotient) * Q));
		}
		/**
		 * @brief Функция приведения значения из (-q, q) к [0, q)
		 *
		 * @param value приводимое значение
		 * @return      значение из [0, q)
		 *
		 */
		static __ANTS_INLINE__ int16_t canonical(const int16_t value) noexcept {
			// Прибавляем модуль под маской знака
			return static_cast <int16_t> (value + (Q & (value >> 15)));
		}
	#endif
	/**
	 * @brief Структура таблиц степеней ζ = 17: по BitRev7 для бабочек и нечётные для умножения пар
	 *
	 */
	typedef struct Tables {
		// 2^32 mod q: множитель перевода коэффициента в форму Монтгомери умножением fqmul
		int16_t square;
		// Обратное к 128 в форме Монтгомери: 128^(-1)·2^16 mod q
		int16_t inverse;
		// Степени ζ^BitRev7(i) для бабочек преобразования
		int16_t zetas[128];
		// Скрутки пар: ±γ·2^32 mod q, где γ = ζ^(2·BitRev7(i)+1) степень пары i; у нечётной пары группы знак противоположный
		int16_t twists[128];
		// Степени ζ в форме Монтгомери: ζ·2^16 mod q, приведённые к (-q/2, q/2]
		int16_t montgomery[128];
		// Множители подготовки по местам коэффициентов: на чётных square, на нечётных скрутка пары
		alignas(16) int16_t lanes[N];
		// Степени ζ слоёв длины 4 и 2 по местам векторов: прямое преобразование (по восемь мест на шестнадцать коэффициентов)
		alignas(16) int16_t forward4[N / 2];
		alignas(16) int16_t forward2[N / 2];
		// То же для обратного преобразования: порядок степеней обратный
		alignas(16) int16_t inverse4[N / 2];
		alignas(16) int16_t inverse2[N / 2];
		/**
		 * @brief Конструктор: таблицы считаются по определению стандарта
		 *
		 */
		explicit Tables() noexcept {
			/**
			 * Перебираем места таблиц
			 */
			for(size_t i = 0; i < 128; i++){
				// Обращённая запись места в семь разрядов
				size_t reversed = 0;
				/**
				 * Обращаем разряды места зеркально
				 */
				for(size_t bit = 0; bit < 7; bit++)
					// Переносим разряд на зеркальное место
					reversed |= (((i >> bit) & 1) << (6 - bit));
				// Степень ζ, накапливаемая умножением
				int32_t power = 1;
				/**
				 * Возводим ζ = 17 в степень обращённого места
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
			 * Перебираем пары коэффициентов
			 */
			for(size_t i = 0; i < N; i += 2){
				// Чётное место: перевод в форму Монтгомери
				this->lanes[i] = this->square;
				// Нечётное место: скрутка пары
				this->lanes[i + 1] = this->twists[i / 2];
			}
			/**
			 * Перебираем шестнадцатки коэффициентов: слои длины 4 и 2 идут парами векторов
			 */
			for(size_t k = 0; k < (N / 16); k++){
				/**
				 * Перебираем места вектора
				 */
				for(size_t lane = 0; lane < 8; lane++){
					// Слой длины 4: участок из восьми коэффициентов, по два участка на шаг
					this->forward4[(8 * k) + lane] = this->montgomery[32 + (2 * k) + (lane / 4)];
					// То же для обратного преобразования: порядок степеней обратный
					this->inverse4[(8 * k) + lane] = this->montgomery[63 - (2 * k) - (lane / 4)];
					// Слой длины 2: участок из четырёх коэффициентов, по четыре участка на шаг
					this->forward2[(8 * k) + lane] = this->montgomery[64 + (4 * k) + (lane / 2)];
					// То же для обратного преобразования: порядок степеней обратный
					this->inverse2[(8 * k) + lane] = this->montgomery[127 - (4 * k) - (lane / 2)];
				}
			}
		}
	} tables_t;

	/**
	 * @brief Функция получения таблиц степеней ζ
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
	 * @brief Функция прямого преобразования NTT многочлена
	 *
	 * @param poly преобразуемый многочлен
	 *
	 */
	static void forward(poly_t & poly) noexcept {
		/**
		 * Векторный путь: слои с длиной от 128 до 8 идут целыми векторами, слои длины 4 и 2 -
		 * шестнадцатью коэффициентами за шаг с перестановками половин и пар двойных слов
		 */
		#if defined(__ANTS_MLKEM_VECTOR__)
			// Место в таблице степеней
			size_t index = 1;
			// Коэффициенты многочлена
			int16_t * values = poly.values;
			// Таблицы степеней
			const tables_t & table = tables();
			/**
			 * Перебираем длины бабочек от 128 до 8
			 */
			for(size_t length = 128; length >= 8; length /= 2){
				/**
				 * Перебираем начала участков
				 */
				for(size_t start = 0; start < N; start += (2 * length)){
					// Степень ζ участка по всем местам
					const vec_t zeta = broadcast16(table.montgomery[index++]);
					/**
					 * Перебираем восьмёрки пар участка
					 */
					for(size_t j = start; j < (start + length); j += 8){
						// Произведение степени ζ на вторые коэффициенты пар
						const vec_t product = multiplyMontgomery(loadVector(values + j + length), zeta);
						// Первые коэффициенты пар
						const vec_t first = loadVector(values + j);
						// Разности пар уходят на вторые половины участков
						storeVector(values + j + length, subtract16(first, product));
						// Суммы пар остаются на первых половинах
						storeVector(values + j, add16(first, product));
					}
				}
			}
			/**
			 * Перебираем шестнадцатки коэффициентов: слои длины 4 и 2 и приведение
			 */
			for(size_t i = 0, m = 0; i < N; i += 16, m += 8){
				// Младший и старший векторы по восемь коэффициентов
				const vec_t lower = loadVector(values + i), upper = loadVector(values + i + 8);
				// Слой длины 4: младшие четвёрки обоих векторов против старших
				vec_t low = takeLow64(lower, upper), high = takeHigh64(lower, upper);
				// Произведения степеней и старших четвёрок
				vec_t product = multiplyMontgomery(high, loadVector(table.forward4 + m));
				// Разности пар - в старшие четвёрки
				high = subtract16(low, product);
				// Суммы пар - в младшие четвёрки
				low = add16(low, product);
				// Обратно в порядок коэффициентов, затем чётные пары двойных слов вперёд
				const vec_t swappedLow = evenOdd32(takeLow64(low, high)), swappedHigh = evenOdd32(takeHigh64(low, high));
				// Слой длины 2: первые пары четвёрок против вторых
				low = takeLow64(swappedLow, swappedHigh);
				// Старшие четвёрки - во второй вектор
				high = takeHigh64(swappedLow, swappedHigh);
				// Произведения степеней и вторых пар
				product = multiplyMontgomery(high, loadVector(table.forward2 + m));
				// Разности пар - в старшие четвёрки
				high = subtract16(low, product);
				// Суммы пар - в младшие четвёрки
				low = add16(low, product);
				// Обратно в порядок коэффициентов с приведением к [0, q)
				storeVector(values + i, reduceCanonical(reduceBarrett(interleaveLow32(low, high))));
				storeVector(values + i + 8, reduceCanonical(reduceBarrett(interleaveHigh32(low, high))));
			}
		/**
		 * Переносимый путь
		 */
		#else
			// Место в таблице степеней
			size_t index = 1;
			// Коэффициенты многочлена: между слоями держатся со знаком, растут не более чем на q за слой
			int16_t * values = poly.values;
			// Таблица степеней ζ в форме Монтгомери
			const int16_t * table = tables().montgomery;
			/**
			 * Перебираем длины бабочек
			 */
			for(size_t length = 128; length >= 2; length /= 2){
				/**
				 * Перебираем начала участков
				 */
				for(size_t start = 0; start < N; start += (2 * length)){
					// Степень ζ участка
					const int16_t zeta = table[index++];
					/**
					 * Перебираем пары участка: одно умножение Монтгомери, сумма и разность
					 * без приведения - семь слоёв поднимают модуль коэффициента не выше 8q < 2^15
					 */
					for(size_t j = start; j < (start + length); j++){
						// Произведение степени и второго коэффициента пары
						const int16_t product = fqmul(zeta, values[j + length]);
						// Разность пары
						values[j + length] = static_cast <int16_t> (values[j] - product);
						// Сумма пары
						values[j] = static_cast <int16_t> (values[j] + product);
					}
				}
			}
			/**
			 * Приводим коэффициенты к [0, q)
			 */
			for(size_t i = 0; i < N; i++)
				// Приводим коэффициент редукцией Барретта и знаком
				values[i] = canonical(barrett(values[i]));
		#endif
	}
	/**
	 * @brief Функция обратного преобразования NTT многочлена
	 *
	 * @param poly преобразуемый многочлен
	 *
	 */
	static void inverse(poly_t & poly) noexcept {
		/**
		 * Векторный путь: слои длины 2 и 4 шестнадцатью коэффициентами за шаг с перестановками,
		 * слои с длиной от 8 до 128 целыми векторами
		 */
		#if defined(__ANTS_MLKEM_VECTOR__)
			// Коэффициенты многочлена
			int16_t * values = poly.values;
			// Таблицы степеней
			const tables_t & table = tables();
			/**
			 * Перебираем шестнадцатки коэффициентов: слои длины 2 и 4
			 */
			for(size_t i = 0, m = 0; i < N; i += 16, m += 8){
				// Два вектора по восемь коэффициентов, чётные пары двойных слов вперёд
				const vec_t swappedLower = evenOdd32(loadVector(values + i)), swappedUpper = evenOdd32(loadVector(values + i + 8));
				// Слой длины 2: первые пары четвёрок против вторых
				vec_t low = takeLow64(swappedLower, swappedUpper), high = takeHigh64(swappedLower, swappedUpper);
				// Первые коэффициенты пар
				vec_t first = low;
				// Сумма пар с редукцией Барретта
				low = reduceBarrett(add16(first, high));
				// Произведения степеней и разностей пар
				high = multiplyMontgomery(subtract16(high, first), loadVector(table.inverse2 + m));
				// Обратно в порядок коэффициентов переплетением половин
				const vec_t interleavedLow = interleaveLow32(low, high), interleavedHigh = interleaveHigh32(low, high);
				// Слой длины 4: младшие четвёрки против старших
				low = takeLow64(interleavedLow, interleavedHigh);
				// Старшие четвёрки против младших
				high = takeHigh64(interleavedLow, interleavedHigh);
				// Первые коэффициенты пар
				first = low;
				// Сумма пар с редукцией Барретта
				low = reduceBarrett(add16(first, high));
				// Произведения степеней и разностей пар
				high = multiplyMontgomery(subtract16(high, first), loadVector(table.inverse4 + m));
				// Раскладываем половины на места коэффициентов
				storeVector(values + i, takeLow64(low, high));
				storeVector(values + i + 8, takeHigh64(low, high));
			}
			// Место в таблице степеней после слоёв длины 2 и 4
			size_t index = 31;
			/**
			 * Перебираем длины бабочек от 8 до 128
			 */
			for(size_t length = 8; length <= 128; length *= 2){
				/**
				 * Перебираем начала участков
				 */
				for(size_t start = 0; start < N; start += (2 * length)){
					// Степень ζ участка по всем местам
					const vec_t zeta = broadcast16(table.montgomery[index--]);
					/**
					 * Перебираем восьмёрки пар участка
					 */
					for(size_t j = start; j < (start + length); j += 8){
						// Первые и вторые коэффициенты пар
						const vec_t first = loadVector(values + j), second = loadVector(values + j + length);
						// Суммы пар с редукцией
						storeVector(values + j, reduceBarrett(add16(first, second)));
						// Произведения степени и разностей пар
						storeVector(values + j + length, multiplyMontgomery(subtract16(second, first), zeta));
					}
				}
			}
			// Обратное к 128 в форме Монтгомери по всем местам
			const vec_t scale = broadcast16(table.inverse);
			/**
			 * Перебираем восьмёрки коэффициентов
			 */
			for(size_t i = 0; i < N; i += 8)
				// Умножаем на обратное к 128 и приводим к [0, q)
				storeVector(values + i, reduceCanonical(multiplyMontgomery(loadVector(values + i), scale)));
		/**
		 * Переносимый путь
		 */
		#else
			// Место в таблице степеней
			size_t index = 127;
			// Коэффициенты многочлена
			int16_t * values = poly.values;
			// Таблица степеней ζ в форме Монтгомери
			const tables_t & table = tables();
			/**
			 * Перебираем длины бабочек
			 */
			for(size_t length = 2; length <= 128; length *= 2){
				/**
				 * Перебираем начала участков
				 */
				for(size_t start = 0; start < N; start += (2 * length)){
					// Степень ζ участка
					const int16_t zeta = table.montgomery[index--];
					/**
					 * Перебираем пары участка: сумма приводится редукцией Барретта,
					 * разность умножается на степень умножением Монтгомери
					 */
					for(size_t j = start; j < (start + length); j++){
						// Первый коэффициент пары
						const int16_t first = values[j];
						// Сумма пары
						values[j] = barrett(static_cast <int16_t> (first + values[j + length]));
						// Произведение степени и разности пары
						values[j + length] = fqmul(zeta, static_cast <int16_t> (values[j + length] - first));
					}
				}
			}
			/**
			 * Перебираем коэффициенты
			 */
			for(size_t i = 0; i < N; i++)
			// Умножаем на обратное к 128 в форме Монтгомери и приводим к [0, q)
			values[i] = canonical(fqmul(values[i], table.inverse));
		#endif
	}

	/**
	 * @brief Структура второго сомножителя умножения в области NTT, подготовленный один раз
	 *
	 * @details Умножение пар (a0 + a1·X)·(b0 + b1·X) mod (X² - γ) даёт r0 = a0·b0 + a1·b1·γ и
	 *          r1 = a0·b1 + a1·b0. Коэффициенты второго сомножителя держатся в форме Монтгомери
	 *          (умноженными на 2^16): в массиве twisted нечётные места ещё умножены на ±γ, в
	 *          массиве swapped коэффициенты пары стоят местами. Тогда r0 и r1 - суммы двух
	 *          произведений соседних мест, они копятся в 32 разрядах без приведения по всем
	 *          слагаемым скалярного произведения векторов, и лишь накопитель приводится
	 *          редукцией Монтгомери, снимающей множитель 2^16. На x86-64 сумма двух произведений
	 *          соседних 16-разрядных мест - одна команда pmaddwd.
	 *
	 */
	typedef struct Twisted {
		// Коэффициенты в форме Монтгомери, нечётные умножены на ±γ: b0·R, b1·γ·R, b2·R, b3·(-γ)·R, …
		alignas(16) int16_t twisted[N];
		// Коэффициенты пар местами в форме Монтгомери: b1·R, b0·R, b3·R, b2·R, …
		alignas(16) int16_t swapped[N];
	} twisted_t;
	/**
	 * @brief Структура накопителя произведений в области NTT: 32 разряда на коэффициент
	 *
	 * @note Порядок коэффициентов внутри накопителя принадлежит паре методов multiply и
	 *       settle: у векторного пути в каждой восьмёрке сперва идут четыре чётных
	 *       коэффициента, затем четыре нечётных
	 *
	 */
	typedef struct Wide {
		// Накопленные произведения
		alignas(16) int32_t values[N];
	} wide_t;

	/**
	 * @brief Функция подготовки второго сомножителя умножения в области NTT
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
		#if defined(__ANTS_MLKEM_VECTOR__)
			// Множитель перевода в форму Монтгомери по местам
			const vec_t square = broadcast16(table.square);
			/**
			 * Перебираем восьмёрки коэффициентов
			 */
			for(size_t i = 0; i < N; i += 8){
				// Коэффициенты многочлена
				const vec_t values = loadVector(poly.values + i);
				// Скрученные коэффициенты: множители по местам
				storeVector(result.twisted + i, multiplyMontgomery(values, loadVector(table.lanes + i)));
				// Коэффициенты пар местами в форме Монтгомери
				storeVector(result.swapped + i, multiplyMontgomery(swapHalves16(values), square));
			}
		/**
		 * Переносимый путь
		 */
		#else
			/**
			 * Перебираем пары коэффициентов
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
				// Чётное место переставленной пары
				result.swapped[i + 1] = even;
			}
		#endif
	}
	/**
	 * @brief Функция умножения многочлена на подготовленный сомножитель с накоплением
	 *
	 * @note Слагаемое накопителя ниже 2·q² < 2^25, а слагаемых у скалярного произведения
	 *       не больше четырёх (размерность модуля): накопитель остаётся ниже q·2^15,
	 *       в границах редукции Монтгомери
	 *
	 * @param first  первый сомножитель с коэффициентами из [0, q)
	 * @param second подготовленный второй сомножитель
	 * @param result накопитель произведений
	 *
	 */
	static void multiply(const poly_t & first, const twisted_t & second, wide_t & result) noexcept {
		/**
		 * Векторный путь: восемь коэффициентов за шаг, суммы произведений соседних мест одной командой (pmaddwd, qpmaddh)
		 */
		#if defined(__ANTS_MLKEM_VECTOR__)
			/**
			 * Перебираем восьмёрки коэффициентов
			 */
			for(size_t i = 0; i < N; i += 8){
				// Коэффициенты первого сомножителя
				const vec_t factor = loadVector(first.values + i);
				// Накопители чётных и нечётных коэффициентов восьмёрки
				int32_t * even = (result.values + i), * odd = (result.values + i + 4);
				// Складываем суммы произведений соседних мест с накопителями
				storeVector(even, add32(loadVector(even), multiplySum16(factor, loadVector(second.twisted + i))));
				storeVector(odd, add32(loadVector(odd), multiplySum16(factor, loadVector(second.swapped + i))));
			}
		/**
		 * Переносимый путь
		 */
		#else
			/**
			 * Перебираем пары коэффициентов
			 */
			for(size_t i = 0; i < N; i += 2){
				// Коэффициенты первого сомножителя
				const int32_t factor0 = first.values[i], factor1 = first.values[i + 1];
				// Чётный коэффициент произведения: factor0·b0 + factor1·b1·γ
				result.values[i] += ((factor0 * second.twisted[i]) + (factor1 * second.twisted[i + 1]));
				// Нечётный коэффициент произведения: factor0·b1 + factor1·b0
				result.values[i + 1] += ((factor0 * second.swapped[i]) + (factor1 * second.swapped[i + 1]));
			}
		#endif
	}
	/**
	 * @brief Функция приведения накопителя произведений к многочлену
	 *
	 * @param wide   накопитель произведений
	 * @param result место, в которое помещается многочлен с коэффициентами из [0, q)
	 *
	 */
	static void settle(const wide_t & wide, poly_t & result) noexcept {
		/**
		 * Векторный путь: редукция Монтгомери четырёх 32-разрядных значений за шаг
		 */
		#if defined(__ANTS_MLKEM_VECTOR__)
			// Множитель q^(-1) mod 2^16 = -3327 в младших половинах 32-разрядных мест, старшие половины нули
			const vec_t factor = broadcast32(0x0000F301);
			// Модуль в младших половинах мест
			const vec_t modulus = broadcast32(Q);
			/**
			 * @brief Редукция Монтгомери четырёх значений с приведением к [0, q)
			 *
			 * @param value четыре 32-разрядных значения
			 * @return      четыре значения из [0, q) в 32-разрядных местах
			 *
			 */
			auto reduce = [&factor, &modulus](const vec_t value) noexcept -> vec_t {
				// Младшие 16 разрядов значения на множитель: старшие половины мест обнуляются нулём множителя
				const vec_t low = multiplyLow16(value, factor);
				// Разность значения и произведения множителя на модуль, делённая на 2^16
				vec_t reduced = shiftRight32(subtract32(value, multiplySum16(low, modulus)), 16);
				// Прибавляем модуль под маской знака
				reduced = add32(reduced, maskBits(shiftRight32(reduced, 31), modulus));
				// Выводим приведённые значения
				return reduced;
			};
			/**
			 * Перебираем восьмёрки коэффициентов
			 */
			for(size_t i = 0; i < N; i += 8){
				// Приведённые чётные и нечётные коэффициенты восьмёрки
				const vec_t even = reduce(loadVector(wide.values + i)), odd = reduce(loadVector(wide.values + i + 4));
				// Переплетаем чётные и нечётные в 16-разрядные места
				storeVector(result.values + i, interleave16(even, odd));
			}
		/**
		 * Переносимый путь
		 */
		#else
			/**
			 * Перебираем коэффициенты
			 */
			for(size_t i = 0; i < N; i++)
				// Приводим накопленное значение редукцией Монтгомери и знаком
				result.values[i] = canonical(montgomery(wide.values[i]));
		#endif
	}
	/**
	 * @brief Функция записи многочлена по двенадцать разрядов на коэффициент
	 *
	 * @param poly   записываемый многочлен
	 * @param result место, в которое помещаются 384 байта записи
	 *
	 */
	static void encode(const poly_t & poly, uint8_t * result) noexcept {
		/**
		 * Перебираем пары коэффициентов
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
	 * @brief Функция разбора многочлена по двенадцать разрядов на коэффициент
	 *
	 * @param data 384 байта записи
	 * @param poly место, в которое помещается многочлен
	 * @return     признак того, что всякий коэффициент лежит в диапазоне модуля
	 *
	 */
	static bool decode(const uint8_t * data, poly_t & poly) noexcept {
		// Накопитель признака выхода за модуль
		uint16_t overflow = 0;
		/**
		 * Перебираем пары коэффициентов
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
	 * @brief Функция сжатия коэффициента до заданной разрядности
	 *
	 * @param value коэффициент из диапазона [0, q)
	 * @param bits  разрядность сжатия
	 * @return      сжатое значение из диапазона [0, 2^bits)
	 *
	 */
	static __ANTS_INLINE__ uint32_t compress(const int32_t value, const size_t bits) noexcept {
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
	 * @brief Функция расширения сжатого значения до коэффициента
	 *
	 * @param value сжатое значение из диапазона [0, 2^bits)
	 * @param bits  разрядность сжатия
	 * @return      коэффициент из диапазона [0, q)
	 *
	 */
	static __ANTS_INLINE__ int16_t decompress(const uint32_t value, const size_t bits) noexcept {
		// Округлённое частное (value · q + 2^(bits-1)) / 2^bits
		return static_cast <int16_t> (((value * static_cast <uint32_t> (Q)) + (1u << (bits - 1))) >> bits);
	}
	/**
	 * @brief Функция записи многочлена со сжатием до заданной разрядности
	 *
	 * @note Разрядности наборов FIPS 203 - 10 и 11 у вектора u, 4 и 5 у многочлена v - пишутся
	 *       жёсткими узорами байтов: четыре коэффициента в пять байтов, восемь в одиннадцать,
	 *       два в один, восемь в пять. Побитовый накопитель оставлен для прочих разрядностей:
	 *       он стоил на многочлене 155 нс на M4 против 13 у узора (щуп packprobe круга 36)
	 *
	 * @param poly   записываемый многочлен
	 * @param bits   разрядность сжатия
	 * @param result место, в которое помещаются 32·bits байтов записи
	 *
	 */
	static void pack(const poly_t & poly, const size_t bits, uint8_t * result) noexcept {
		// Сжатые коэффициенты
		uint16_t values[N];
		/**
		 * Сжимаем коэффициенты
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
				 * Перебираем пары коэффициентов
				 */
				for(size_t i = 0; i < N; i += 2)
					// Записываем байт
					result[i / 2] = static_cast <uint8_t> (values[i] | (values[i + 1] << 4));
			} break;
			// Пять разрядов: восемь коэффициентов в пять байтов
			case 5: {
				/**
				 * Перебираем восьмёрки коэффициентов
				 */
				for(size_t i = 0; i < N; i += 8, result += 5){
					// Коэффициенты восьмёрки
					const uint16_t * words = (values + i);
					// Записываем байты узора
					result[0] = static_cast <uint8_t> (words[0] | (words[1] << 5));
					// Записываем второй байт узора
					result[1] = static_cast <uint8_t> ((words[1] >> 3) | (words[2] << 2) | (words[3] << 7));
					// Записываем третий байт узора
					result[2] = static_cast <uint8_t> ((words[3] >> 1) | (words[4] << 4));
					// Записываем четвёртый байт узора
					result[3] = static_cast <uint8_t> ((words[4] >> 4) | (words[5] << 1) | (words[6] << 6));
					// Записываем пятый байт узора
					result[4] = static_cast <uint8_t> ((words[6] >> 2) | (words[7] << 3));
				}
			} break;
			// Десять разрядов: четыре коэффициента в пять байтов
			case 10: {
				/**
				 * Перебираем четвёрки коэффициентов
				 */
				for(size_t i = 0; i < N; i += 4, result += 5){
					// Коэффициенты четвёрки
					const uint16_t * words = (values + i);
					// Записываем байты узора
					result[0] = static_cast <uint8_t> (words[0]);
					// Записываем второй байт узора
					result[1] = static_cast <uint8_t> ((words[0] >> 8) | (words[1] << 2));
					// Записываем третий байт узора
					result[2] = static_cast <uint8_t> ((words[1] >> 6) | (words[2] << 4));
					// Записываем четвёртый байт узора
					result[3] = static_cast <uint8_t> ((words[2] >> 4) | (words[3] << 6));
					// Записываем пятый байт узора
					result[4] = static_cast <uint8_t> (words[3] >> 2);
				}
			} break;
			// Одиннадцать разрядов: восемь коэффициентов в одиннадцать байтов
			case 11: {
				/**
				 * Перебираем восьмёрки коэффициентов
				 */
				for(size_t i = 0; i < N; i += 8, result += 11){
					// Коэффициенты восьмёрки
					const uint16_t * words = (values + i);
					// Записываем байты узора
					result[0] = static_cast <uint8_t> (words[0]);
					// Записываем второй байт узора
					result[1] = static_cast <uint8_t> ((words[0] >> 8) | (words[1] << 3));
					// Записываем третий байт узора
					result[2] = static_cast <uint8_t> ((words[1] >> 5) | (words[2] << 6));
					// Записываем четвёртый байт узора
					result[3] = static_cast <uint8_t> (words[2] >> 2);
					// Записываем пятый байт узора
					result[4] = static_cast <uint8_t> ((words[2] >> 10) | (words[3] << 1));
					// Записываем шестой байт узора
					result[5] = static_cast <uint8_t> ((words[3] >> 7) | (words[4] << 4));
					// Записываем седьмой байт узора
					result[6] = static_cast <uint8_t> ((words[4] >> 4) | (words[5] << 7));
					// Записываем восьмой байт узора
					result[7] = static_cast <uint8_t> (words[5] >> 1);
					// Записываем девятый байт узора
					result[8] = static_cast <uint8_t> ((words[5] >> 9) | (words[6] << 2));
					// Записываем десятый байт узора
					result[9] = static_cast <uint8_t> ((words[6] >> 6) | (words[7] << 5));
					// Записываем одиннадцатый байт узора
					result[10] = static_cast <uint8_t> (words[7] >> 3);
				}
			} break;
			// Прочие разрядности: побитовый накопитель
			default: {
				// Число разрядов в накопителе
				size_t count = 0;
				// Место записи
				size_t offset = 0;
				// Накопитель разрядов
				uint32_t buffer = 0;
				/**
				 * Перебираем коэффициенты
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
	 * @brief Функция разбора многочлена с расширением из заданной разрядности
	 *
	 * @note Узоры байтов зеркальны узорам записи; побитовый накопитель - для прочих разрядностей
	 *
	 * @param data 32·bits байтов записи
	 * @param bits разрядность сжатия
	 * @param poly место, в которое помещается многочлен
	 *
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
				 * Перебираем пары коэффициентов
				 */
				for(size_t i = 0; i < N; i += 2){
					// Читаем коэффициенты байта
					values[i] = static_cast <uint16_t> (data[i / 2] & 0x0F);
					// Второй коэффициент: старшие четыре разряда байта
					values[i + 1] = static_cast <uint16_t> (data[i / 2] >> 4);
				}
			} break;
			// Пять разрядов: пять байтов на восемь коэффициентов
			case 5: {
				/**
				 * Перебираем восьмёрки коэффициентов
				 */
				for(size_t i = 0; i < N; i += 8, data += 5){
					// Коэффициенты восьмёрки
					uint16_t * target = (values + i);
					// Читаем коэффициенты узора
					target[0] = static_cast <uint16_t> (data[0] & 0x1F);
					// Читаем второй коэффициент узора
					target[1] = static_cast <uint16_t> (((data[0] >> 5) | (data[1] << 3)) & 0x1F);
					// Читаем третий коэффициент узора
					target[2] = static_cast <uint16_t> ((data[1] >> 2) & 0x1F);
					// Читаем четвёртый коэффициент узора
					target[3] = static_cast <uint16_t> (((data[1] >> 7) | (data[2] << 1)) & 0x1F);
					// Читаем пятый коэффициент узора
					target[4] = static_cast <uint16_t> (((data[2] >> 4) | (data[3] << 4)) & 0x1F);
					// Читаем шестой коэффициент узора
					target[5] = static_cast <uint16_t> ((data[3] >> 1) & 0x1F);
					// Читаем седьмой коэффициент узора
					target[6] = static_cast <uint16_t> (((data[3] >> 6) | (data[4] << 2)) & 0x1F);
					// Читаем восьмой коэффициент узора
					target[7] = static_cast <uint16_t> (data[4] >> 3);
				}
			} break;
			// Десять разрядов: пять байтов на четыре коэффициента
			case 10: {
				/**
				 * Перебираем четвёрки коэффициентов
				 */
				for(size_t i = 0; i < N; i += 4, data += 5){
					// Коэффициенты четвёрки
					uint16_t * target = (values + i);
					// Читаем коэффициенты узора
					target[0] = static_cast <uint16_t> ((data[0] | (data[1] << 8)) & 0x3FF);
					// Читаем второй коэффициент узора
					target[1] = static_cast <uint16_t> (((data[1] >> 2) | (data[2] << 6)) & 0x3FF);
					// Читаем третий коэффициент узора
					target[2] = static_cast <uint16_t> (((data[2] >> 4) | (data[3] << 4)) & 0x3FF);
					// Читаем четвёртый коэффициент узора
					target[3] = static_cast <uint16_t> (((data[3] >> 6) | (data[4] << 2)) & 0x3FF);
				}
			} break;
			// Одиннадцать разрядов: одиннадцать байтов на восемь коэффициентов
			case 11: {
				/**
				 * Перебираем восьмёрки коэффициентов
				 */
				for(size_t i = 0; i < N; i += 8, data += 11){
					// Коэффициенты восьмёрки
					uint16_t * target = (values + i);
					// Читаем коэффициенты узора
					target[0] = static_cast <uint16_t> ((data[0] | (data[1] << 8)) & 0x7FF);
					// Читаем второй коэффициент узора
					target[1] = static_cast <uint16_t> (((data[1] >> 3) | (data[2] << 5)) & 0x7FF);
					// Читаем третий коэффициент узора
					target[2] = static_cast <uint16_t> (((data[2] >> 6) | (data[3] << 2) | (data[4] << 10)) & 0x7FF);
					// Читаем четвёртый коэффициент узора
					target[3] = static_cast <uint16_t> (((data[4] >> 1) | (data[5] << 7)) & 0x7FF);
					// Читаем пятый коэффициент узора
					target[4] = static_cast <uint16_t> (((data[5] >> 4) | (data[6] << 4)) & 0x7FF);
					// Читаем шестой коэффициент узора
					target[5] = static_cast <uint16_t> (((data[6] >> 7) | (data[7] << 1) | (data[8] << 9)) & 0x7FF);
					// Читаем седьмой коэффициент узора
					target[6] = static_cast <uint16_t> (((data[8] >> 2) | (data[9] << 6)) & 0x7FF);
					// Читаем восьмой коэффициент узора
					target[7] = static_cast <uint16_t> (((data[9] >> 5) | (data[10] << 3)) & 0x7FF);
				}
			} break;
			// Прочие разрядности: побитовый накопитель
			default: {
				// Число разрядов в накопителе
				size_t count = 0;
				// Место чтения
				size_t offset = 0;
				// Накопитель разрядов
				uint32_t buffer = 0;
				/**
				 * Перебираем коэффициенты
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
		 * Расширяем сжатые значения до коэффициентов
		 */
		for(size_t i = 0; i < N; i++)
			// Расширяем сжатое значение до коэффициента
			poly.values[i] = decompress(values[i], bits);
	}
	/**
	 * Опрос готовности параллельного ядра Keccak-x4
	 */
	#if defined(__ANTS_KECCAK_X4__)
		/**
		 * @brief Функция чтения 64-разрядного слова из байтов от младшего
		 *
		 * @param data байты слова
		 * @return     слово
		 *
		 */
		static __ANTS_INLINE__ uint64_t wordLoad(const uint8_t * data) noexcept {
			// Слово из восьми байтов
			uint64_t word = 0;
			/**
			 * Перебираем байты слова
			 */
			for(size_t i = 0; i < 8; i++)
				// Складываем очередной байт в слово
				word |= (static_cast <uint64_t> (data[i]) << (i * 8));
			// Выводим слово
			return word;
		}
		/**
		 * @brief Функция записи 64-разрядного слова байтами от младшего
		 *
		 * @param word   слово
		 * @param result место, в которое помещаются байты слова
		 *
		 */
		static __ANTS_INLINE__ void wordStore(const uint64_t word, uint8_t * result) noexcept {
			/**
			 * Перебираем байты слова
			 */
			for(size_t i = 0; i < 8; i++)
				// Записываем очередной байт слова
				result[i] = static_cast <uint8_t> (word >> (i * 8));
		}
		/**
		 * @brief Функция проверки готовности параллельного ядра губок
		 *
		 * @note Ядро несёт векторные команды: на ARM64 они входят в архитектуру, на x86-64
		 *       спрашивается AVX2 у машины на исполнении
		 *
		 * @return признак готовности ядра четырёх состояний
		 *
		 */
		static __ANTS_INLINE__ bool sponges4() noexcept {
			/**
			 * Если архитектура x86-64
			 */
			#if defined(__x86_64__)
				// Выводим признак AVX2: на x86-64 команды могут отсутствовать у машины
				return machine::has(machine::feature_t::AVX2);
			/**
			 * Прочие архитектуры с параллельным ядром готовы всегда
			 */
			#else
				// Выводим готовность параллельного ядра
				return true;
			#endif
		}
	#endif

	/**
	 * @brief Функция выборки многочлена матрицы из зерна
	 *
	 * @param rho    зерно развёрнутой матрицы
	 * @param row    номер строки элемента матрицы
	 * @param column номер столбца элемента матрицы
	 * @param poly   место, в которое помещается выбранный многочлен
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
		 * Выбираем байты до заполнения многочлена
		 */
		while(count < N){
			// Выжимаем блок потока
			xof.squeeze(block, sizeof(block));
			/**
			 * Перебираем тройки байтов блока
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
	 * Параллельная выборка четырёх многочленов матрицы губками Keccak-x4
	 */
	#if defined(__ANTS_KECCAK_X4__)
		/**
		 * @brief Функция параллельной выборки четырёх элементов матрицы
		 *
		 * @details Четыре губки SHAKE128 переставляются разом параллельным ядром: каждая губка
		 *          поглощает зерно с парой индексов и выжимает блоки по 168 байтов, пока каждая
		 *          не наберёт 256 коэффициентов - закончившие раньше выжимают лишние блоки впустую,
		 *          чтобы перестановки шли общие.
		 *
		 * @param rho     зерно матрицы
		 * @param indices пары индексов четырёх губок: зерно || первый || второй
		 * @param polys   место, в которое помещаются многочлены
		 *
		 */
		static void sampling4(const uint8_t * rho, const uint8_t indices[4][2], poly_t * polys) noexcept {
			// Состояния четырёх губок
			uint64_t states[4][25];
			// Обнуляем состояния
			::memset(states, 0, sizeof(states));
			/**
			 * Поглощаем зерно и индексы каждой губкой: слова 0…3 - зерно, слово 4 - пара индексов
			 */
			for(size_t k = 0; k < 4; k++){
				/**
				 * Перебираем слова зерна
				 */
				for(size_t i = 0; i < (SEED / 8); i++)
					// Складываем очередное слово зерна
					states[k][i] ^= wordLoad(rho + (i * 8));
				// Складываем пару индексов матрицы
				states[k][SEED / 8] ^= (indices[k][0] | (static_cast <uint64_t> (indices[k][1]) << 8));
			}
			/**
			 * Дополняем домен функций переменного выхода: байт 0x1F на смещении тридцать четыре и разряд 0x80 в последнем байте скорости 168
			 */
			for(size_t k = 0; k < 4; k++){
				// Байт начала дополнения
				states[k][34 / 8] ^= (0x1FULL << ((34 % 8) * 8));
				// Разряд окончания дополнения
				states[k][(168 - 1) / 8] ^= (0x80ULL << (((168 - 1) % 8) * 8));
			}
			// Переставляем четыре состояния губок
			digest::kernel::keccak4(states);
			// Число набранных коэффициентов каждой губки
			size_t counts[4] = {0, 0, 0, 0};
			// Блоки выжимания
			uint8_t blocks[4][168];
			/**
			 * Выжимаем блоки и разбираем тройки, пока какая-то губка не набрала многочлен
			 */
			while((counts[0] < N) || (counts[1] < N) || (counts[2] < N) || (counts[3] < N)){
				/**
				 * Выжимаем блок каждой губкой
				 */
				for(size_t k = 0; k < 4; k++)
					/**
					 * Перебираем слова блока
					 */
					for(size_t i = 0; i < (168 / 8); i++)
						// Записываем очередное слово блока
						wordStore(states[k][i], blocks[k] + (i * 8));
				// Переставляем четыре состояния губок
				digest::kernel::keccak4(states);
				/**
				 * Разбираем тройки байтов блока каждой губкой
				 */
				for(size_t k = 0; k < 4; k++){
					/**
					 * Перебираем тройки блока
					 */
					for(size_t at = 0; (at < sizeof(blocks[k])) && (counts[k] < N); at += 3){
						// Первый претендент
						const uint16_t first = static_cast <uint16_t> (blocks[k][at] | ((blocks[k][at + 1] & 0x0F) << 8));
						// Второй претендент
						const uint16_t second = static_cast <uint16_t> ((blocks[k][at + 1] >> 4) | (blocks[k][at + 2] << 4));
						// Если первый претендент годен
						if(first < Q)
							// Записываем коэффициент
							polys[k].values[counts[k]++] = static_cast <int16_t> (first);
						// Если второй претендент годен и место есть
						if((second < Q) && (counts[k] < N))
							// Записываем коэффициент
							polys[k].values[counts[k]++] = static_cast <int16_t> (second);
					}
				}
			}
			// Затираем состояния губок
			wipe(states, sizeof(states));
			// Затираем блоки губок
			wipe(blocks, sizeof(blocks));
		}
	#endif

	/**
	 * @brief Функция разбора байтов потока в многочлен биномиального распределения
	 *
	 * @param stream байты псевдослучайного потока
	 * @param eta    параметр распределения
	 * @param poly   место, в которое помещается многочлен
	 *
	 */
	static void binomialParse(const uint8_t * stream, const size_t eta, poly_t & poly) noexcept {
		// Если η равно двум
		if(eta == 2){
			/**
			 * Каждый байт даёт два коэффициента: суммы пар разрядов считаются разом маской
			 * 0x55 - сложение разряда с соседом даёт двухразрядные суммы в каждой четвёрке.
			 * Прежний ход по разряду стоил 524 нс на многочлен на M4 (круг 35, 23.09.2026)
			 */
			for(size_t i = 0; i < (N / 2); i++){
				// Очередной байт потока
				const uint32_t byte = stream[i];
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
				const uint32_t word = (static_cast <uint32_t> (stream[3 * i]) | (static_cast <uint32_t> (stream[(3 * i) + 1]) << 8) | (static_cast <uint32_t> (stream[(3 * i) + 2]) << 16));
				// Суммы троек разрядов: по три разряда на тройку
				const uint32_t sums = ((word & 0x00249249) + ((word >> 1) & 0x00249249) + ((word >> 2) & 0x00249249));
				/**
				 * Перебираем четыре коэффициента слова
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
	}
	/**
	 * @brief Функция выборки многочлена из центрированного биномиального распределения
	 *
	 * @param sigma зерно выборки
	 * @param nonce номер выборки
	 * @param eta   параметр распределения
	 * @param poly  место, в которое помещается многочлен
	 *
	 */
	static __ANTS_INLINE__ void binomial(const uint8_t * sigma, const uint8_t nonce, const size_t eta, poly_t & poly) noexcept {
		// Байты псевдослучайного потока: 64·η байтов
		uint8_t stream[64 * 3];
		// Функция переменного выхода потока
		digest::keccak_t prf(digest::sha3_t::SHAKE256);
		// Поглощаем затравку
		prf.update(view_t(sigma, SEED));
		// Поглощаем порядковый номер
		prf.update(view_t(&nonce, 1));
		// Выжимаем поток
		prf.squeeze(stream, 64 * eta);
		// Разбираем поток в многочлен
		binomialParse(stream, eta, poly);
		// Затираем байты потока выборки
		wipe(stream, sizeof(stream));
	}

	/**
	 * Параллельная биномиальная выборка четырёх шумов губками Keccak-x4
	 */
	#if defined(__ANTS_KECCAK_X4__)
		/**
		 * @brief Функция параллельной выборки четырёх многочленов из центрированного биномиального распределения
		 *
		 * @details Четыре губки SHAKE256 переставляются разом параллельным ядром: каждая губка
		 *          поглощает зерно со своим номером и выжимает 64·η байтов потока.
		 *
		 * @param sigma  зерно выборки
		 * @param nonces номера четырёх выборок
		 * @param eta    параметр распределения
		 * @param polys  место, в которое помещаются многочлены
		 *
		 */
		static void binomial4(const uint8_t * sigma, const uint8_t * nonces, const size_t eta, poly_t * polys) noexcept {
			// Состояния четырёх губок
			uint64_t states[4][25];
			// Обнуляем состояния
			::memset(states, 0, sizeof(states));
			/**
			 * Поглощаем зерно и номер каждой губкой: слова 0…3 - зерно, младший байт слова 4 - номер
			 */
			for(size_t k = 0; k < 4; k++){
				/**
				 * Перебираем слова зерна
				 */
				for(size_t i = 0; i < (SEED / 8); i++)
					// Складываем очередное слово зерна
					states[k][i] ^= wordLoad(sigma + (i * 8));
				// Складываем номер выборки
				states[k][SEED / 8] ^= nonces[k];
			}
			/**
			 * Дополняем домен функций переменного выхода: байт 0x1F на смещении тридцать три и разряд 0x80 в последнем байте скорости 136
			 */
			for(size_t k = 0; k < 4; k++){
				// Байт начала дополнения
				states[k][33 / 8] ^= (0x1FULL << ((33 % 8) * 8));
				// Разряд окончания дополнения
				states[k][(136 - 1) / 8] ^= (0x80ULL << (((136 - 1) % 8) * 8));
			}
			// Переставляем четыре состояния губок
			digest::kernel::keccak4(states);
			// Байты потоков: 64·η байтов каждой губки
			uint8_t streams[4][64 * 3];
			/**
			 * Выжимаем первый блок каждой губкой
			 */
			for(size_t k = 0; k < 4; k++)
				/**
				 * Перебираем слова блока
				 */
				for(size_t i = 0; i < (136 / 8); i++)
					// Записываем очередное слово блока
					wordStore(states[k][i], streams[k] + (i * 8));
			// Если η равно трём: поток длиннее блока, дожимаем хвосты
			if(eta == 3){
				// Переставляем четыре состояния губок
				digest::kernel::keccak4(states);
				/**
				 * Выжимаем хвосты потоков
				 */
				for(size_t k = 0; k < 4; k++)
					/**
					 * Перебираем слова хвоста
					 */
					for(size_t i = 0; i < 7; i++)
						// Записываем очередное слово хвоста
						wordStore(states[k][i], streams[k] + 136 + (i * 8));
			}
			/**
			 * Разбираем потоки в многочлены
			 */
			for(size_t k = 0; k < 4; k++)
				// Разбираем поток губки
				binomialParse(streams[k], eta, polys[k]);
			// Затираем состояния губок
			wipe(states, sizeof(states));
			// Затираем потоки выборки
			wipe(streams, sizeof(streams));
		}
	#endif

	/**
	 * @brief Функция хеширования G: SHA3-512
	 *
	 * @param first  первая часть входа
	 * @param second вторая часть входа
	 * @param result место, в которое помещаются 64 байта итога
	 *
	 */
	static __ANTS_INLINE__ void widely(const view_t & first, const view_t & second, uint8_t * result) noexcept {
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
	 * @brief Функция получения развёрнутой матрицы набора
	 *
	 * @details При совпадении зерна и достаточной размерности слот отдаётся как есть,
	 *          иначе строки разворачиваются заново выборками SHAKE128: скалярными либо
	 *          параллельным ядром, как и до кеша.
	 *
	 * @param sample описание набора
	 * @param rho    зерно матрицы
	 * @return       место k² многочленов матрицы A по строкам
	 *
	 */
	static const poly_t * expanded(const sample_t & sample, const uint8_t * rho) noexcept {
		// Слот кеша матрицы потока
		static thread_local matrix_t cache;
		// Если матрица того же зерна развёрнута до нужной размерности
		if((cache.dimension >= sample.dimension) && (::memcmp(cache.seed, rho, SEED) == 0))
			// Выводим развёрнутую матрицу
			return cache.items;
		/**
		 * Если параллельное ядро губок готово, строки выбираются четырьмя губками разом:
		 * у набора меньшей ширины лишний поток каждой четвёрки пишется в запасной слот строки полной ширины
		 */
		#if defined(__ANTS_KECCAK_X4__)
			// Если параллельное ядро губок готово
			if(sponges4()){
				/**
				 * Разворачиваем строки матрицы
				 */
				for(size_t x = 0; x < sample.dimension; x++){
					// Пары индексов губок: столбец y и строка x
					uint8_t indices[K][2];
					/**
					 * Заполняем пары индексов
					 */
					for(size_t y = 0; y < K; y++){
						// Первый индекс пары
						indices[y][0] = static_cast <uint8_t> (y);
						// Второй индекс пары
						indices[y][1] = static_cast <uint8_t> (x);
					}
					// Выбираем строку из четырёх многочленов разом
					sampling4(rho, indices, cache.items + (x * K));
				}
				// Запоминаем зерно развёрнутой матрицы
				::memcpy(cache.seed, rho, SEED);
				// Запоминаем размерность разворота
				cache.dimension = sample.dimension;
				// Выводим развёрнутую матрицу
				return cache.items;
			}
		#endif
		/**
		 * Разворачиваем строки матрицы по одному элементу
		 */
		for(size_t x = 0; x < sample.dimension; x++){
			/**
			 * Перебираем столбцы строки
			 */
			for(size_t y = 0; y < sample.dimension; y++)
				// Выбираем элемент матрицы
				sampling(rho, static_cast <uint8_t> (x), static_cast <uint8_t> (y), cache.items[(x * K) + y]);
		}
		// Запоминаем зерно развёрнутой матрицы
		::memcpy(cache.seed, rho, SEED);
		// Запоминаем размерность разворота
		cache.dimension = sample.dimension;
		// Выводим развёрнутую матрицу
		return cache.items;
	}
	/**
	 * @brief Функция шифрования K-PKE
	 *
	 * @param sample  описание набора
	 * @param key     ключ шифрования: t || ρ
	 * @param message сообщение в 32 байта
	 * @param seed    зерно случайности r
	 * @param cipher  место, в которое помещается шифртекст
	 *
	 */
	static void encrypt(const sample_t & sample, const uint8_t * key, const uint8_t * message, const uint8_t * seed, uint8_t * cipher) noexcept {
		// Вектор t в области NTT
		poly_t t[K];
		/**
		 * Разбираем запись вектора t
		 */
		for(size_t i = 0; i < sample.dimension; i++)
			// Разбираем многочлен
			decode(key + (i * POLY), t[i]);
		// Зерно матрицы
		const uint8_t * rho = (key + (sample.dimension * POLY));
		// Вектор r в области NTT, подготовленный к умножению
		twisted_t r[K];
		// Многочлены вектора r
		poly_t random[K];
		/**
		 * Выбираем вектор r
		 */
		#if defined(__ANTS_KECCAK_X4__)
			// Если параллельное ядро губок готово: четыре многочлена выбираются разом, лишние у неполной четвёрки отбрасываются
			if(::sponges4()){
				// Номера выборок вектора
				const uint8_t nonces[K] = {0, 1, 2, 3};
				// Выбираем четыре многочлена разом
				::binomial4(seed, nonces, sample.eta1, random);
			// Иначе многочлены вектора r выбираются по одному губкой
			} else {
		#endif
			/**
			 * Перебираем места вектора
			 */
			for(size_t i = 0; i < sample.dimension; i++)
				// Выбираем многочлен
				::binomial(seed, static_cast <uint8_t> (i), sample.eta1, random[i]);
		/**
		 * Замыкаем ветвь параллельного выбора
		 */
		#if defined(__ANTS_KECCAK_X4__)
			}
		#endif
		/**
		 * Переводим вектор r в область NTT и готовим к умножению
		 */
		for(size_t i = 0; i < sample.dimension; i++){
			// Переводим в область NTT
			::forward(random[i]);
			// Готовим к умножению
			::prepare(random[i], r[i]);
			// Затираем многочлен
			wipe(random[i].values, sizeof(random[i].values));
		}
		// Вектор шума e1
		poly_t noise[K];
		/**
		 * Выбираем вектор шума e1
		 */
		#if defined(__ANTS_KECCAK_X4__)
			// Если параллельное ядро губок готово: четыре многочлена выбираются разом, лишние у неполной четвёрки отбрасываются
			if(::sponges4()){
				// Номера выборок шума
				const uint8_t nonces[K] = {static_cast <uint8_t> (sample.dimension), static_cast <uint8_t> (sample.dimension + 1), static_cast <uint8_t> (sample.dimension + 2), static_cast <uint8_t> (sample.dimension + 3)};
				// Выбираем четыре многочлена разом
				::binomial4(seed, nonces, sample.eta2, noise);
			// Иначе шумы e1 выбираются по одному губкой
			} else {
		#endif
			/**
			 * Перебираем места вектора
			 */
			for(size_t i = 0; i < sample.dimension; i++)
				// Выбираем шум
				::binomial(seed, static_cast <uint8_t> (sample.dimension + i), sample.eta2, noise[i]);
		/**
		 * Замыкаем ветвь параллельного выбора
		 */
		#if defined(__ANTS_KECCAK_X4__)
			}
		#endif
		// Вектор u
		poly_t u[K];
		// Развёрнутая матрица A: строка i произведения берёт элементы A[j][i]
		const poly_t * matrix = expanded(sample, rho);
		/**
		 * Вычисляем u = A^T r + e1
		 */
		for(size_t i = 0; i < sample.dimension; i++){
			// Накопитель произведений
			wide_t wide;
			// Обнуляем накопитель
			::memset(wide.values, 0, sizeof(wide.values));
			/**
			 * Перебираем столбцы
			 */
			for(size_t j = 0; j < sample.dimension; j++)
				// Накапливаем произведение элемента A[j][i] на r[j]
				multiply(matrix[(j * K) + i], r[j], wide);
			// Приводим накопитель
			settle(wide, u[i]);
			// Переводим из области NTT
			inverse(u[i]);
			/**
			 * Складываем с шумом
			 */
			for(size_t c = 0; c < N; c++)
				// Складываем коэффициенты
				u[i].values[c] = once(u[i].values[c] + noise[i].values[c]);
			// Затираем шум: вместе с u и матрицей он раскрывает r
			wipe(noise[i].values, sizeof(noise[i].values));
		}
		// Накопитель произведений t^T r
		wide_t wide;
		// Обнуляем накопитель
		::memset(wide.values, 0, sizeof(wide.values));
		/**
		 * Вычисляем t^T r
		 */
		for(size_t i = 0; i < sample.dimension; i++)
			// Накапливаем произведение
			multiply(t[i], r[i], wide);
		// Многочлен shared
		poly_t shared;
		// Приводим накопитель
		settle(wide, shared);
		// Переводим из области NTT
		inverse(shared);
		// Шум e2
		poly_t error;
		// Выбираем шум
		binomial(seed, static_cast <uint8_t> (2 * sample.dimension), sample.eta2, error);
		/**
		 * Складываем с шумом и сообщением
		 */
		for(size_t c = 0; c < N; c++){
			// Разряд сообщения, расширенный до коэффициента
			const int32_t bit = decompress((message[c / 8] >> (c % 8)) & 1, 1);
			// Складываем коэффициенты
			shared.values[c] = reduce(shared.values[c] + error.values[c] + bit);
		}
		/**
		 * Записываем вектор u со сжатием
		 */
		for(size_t i = 0; i < sample.dimension; i++)
			// Записываем многочлен
			pack(u[i], sample.compressU, cipher + (i * 32 * sample.compressU));
		// Записываем многочлен shared со сжатием
		pack(shared, sample.compressV, cipher + (sample.dimension * 32 * sample.compressU));
		// Затираем секретные промежуточные значения
		wipe(r, sizeof(r));
		// Затираем вектор u
		wipe(u, sizeof(u));
		// Затираем многочлен shared
		wipe(shared.values, sizeof(shared.values));
		// Затираем многочлен шума
		wipe(error.values, sizeof(error.values));
	}
	/**
	 * @brief Функция расшифрования K-PKE
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
		 * Вычисляем s^T NTT(u)
		 */
		for(size_t i = 0; i < sample.dimension; i++){
			// Многочлен u_i
			poly_t decoded;
			// Разбираем многочлен с расширением
			unpack(cipher + (i * 32 * sample.compressU), sample.compressU, decoded);
			// Переводим в область NTT
			forward(decoded);
			// Открытый многочлен u_i, подготовленный к умножению
			twisted_t prepared;
			// Готовим к умножению
			prepare(decoded, prepared);
			// Многочлен s_i
			poly_t secretPoly;
			// Разбираем многочлен
			decode(secret + (i * POLY), secretPoly);
			// Накапливаем произведение
			multiply(secretPoly, prepared, wide);
			// Затираем секретный многочлен secretPoly
			wipe(secretPoly.values, sizeof(secretPoly.values));
		}
		// Многочлен разности shared и s^T NTT(u)
		poly_t candidate;
		// Приводим накопитель
		settle(wide, candidate);
		// Переводим из области NTT
		inverse(candidate);
		// Затираем накопитель: он раскрывает секрет
		wipe(wide.values, sizeof(wide.values));
		// Многочлен shared
		poly_t shared;
		// Разбираем многочлен с расширением
		unpack(cipher + (sample.dimension * 32 * sample.compressU), sample.compressV, shared);
		// Обнуляем сообщение
		::memset(message, 0, 32);
		/**
		 * Сжимаем разность до разрядов сообщения
		 */
		for(size_t c = 0; c < N; c++){
			// Разряд сообщения
			const uint32_t bit = compress(reduce(shared.values[c] - candidate.values[c]), 1);
			// Записываем разряд
			message[c / 8] |= static_cast <uint8_t> (bit << (c % 8));
		}
		// Затираем многочлен candidate
		wipe(candidate.values, sizeof(candidate.values));
	}
};

/**
 * @brief Функция получения длины ключа инкапсуляции набора
 *
 * @param kem набор параметров
 * @return    длина ключа инкапсуляции в байтах либо нуль
 *
 */
size_t nts::agreement::encapsulation(const kem_t kem) noexcept {
	// Описание набора параметров
	const sample_t sample = ::describe(kem);
	// Выводим длину: k многочленов и зерно ρ
	return ((sample.dimension == 0) ? 0 : ((sample.dimension * POLY) + SEED));
}
/**
 * @brief Функция получения длины ключа декапсуляции набора
 *
 * @param kem набор параметров
 * @return    длина ключа декапсуляции в байтах либо нуль
 *
 */
size_t nts::agreement::decapsulation(const kem_t kem) noexcept {
	// Описание набора параметров
	const sample_t sample = ::describe(kem);
	// Выводим длину: k многочленов секрета, ключ инкапсуляции, его хеш и z
	return ((sample.dimension == 0) ? 0 : ((sample.dimension * POLY) + encapsulation(kem) + SEED + SEED));
}
/**
 * @brief Функция получения длины шифртекста набора
 *
 * @param kem набор параметров
 * @return    длина шифртекста в байтах либо нуль
 *
 */
size_t nts::agreement::ciphertext(const kem_t kem) noexcept {
	// Описание набора параметров
	const sample_t sample = ::describe(kem);
	// Выводим длину: k сжатых многочленов u и сжатый многочлен v
	return ((sample.dimension == 0) ? 0 : ((sample.dimension * 32 * sample.compressU) + (32 * sample.compressV)));
}
/**
 * @brief Функция проверки ключа инкапсуляции
 *
 * @param kem набор параметров
 * @param key ключ инкапсуляции
 * @return    признак того, что ключ годен
 *
 */
bool nts::agreement::validate(const kem_t kem, const view_t & key) noexcept {
	// Описание набора параметров
	const sample_t sample = ::describe(kem);
	// Если набор не установлен либо длина ключа не сходится
	if((sample.dimension == 0) || (key.data == nullptr) || (key.size != encapsulation(kem)))
		// Выводим отказ проверки
		return false;
	// Признак годности всех многочленов
	bool ok = true;
	/**
	 * Перебираем многочлены ключа
	 */
	for(size_t i = 0; i < sample.dimension; i++){
		// Многочлен ключа
		poly_t poly;
		// Проверяем коэффициенты многочлена на выход за модуль
		ok = (::decode(key.data + (i * POLY), poly) && ok);
	}
	// Выводим признак годности ключа
	return ok;
}
/**
 * @brief Функция выработки пары ключей из зерна
 *
 * @param kem    набор параметров
 * @param seed   зерно выработки в шестьдесят четыре байта
 * @param key    место, в которое помещается ключ инкапсуляции
 * @param secret место, в которое помещается ключ декапсуляции
 * @return       признак того, что пара ключей выработана
 *
 */
bool nts::agreement::generate(const kem_t kem, const view_t & seed, uint8_t * key, uint8_t * secret) noexcept {
	// Описание набора параметров
	const sample_t sample = ::describe(kem);
	// Если набор не установлен, зерно не той длины либо места не переданы
	if((sample.dimension == 0) || (seed.data == nullptr) || (seed.size != MLKEM_SEED) || (key == nullptr) || (secret == nullptr))
		// Выводим отказ выработки
		return false;
	// Размерность модуля байтом для хеша G(d || k)
	const uint8_t rank = static_cast <uint8_t> (sample.dimension);
	// Зёрна ρ и σ: G(d || k)
	uint8_t seeds[64];
	// Вычисляем зёрна
	::widely(view_t(seed.data, SEED), view_t(&rank, 1), seeds);
	// Зерно матрицы ρ
	const uint8_t * rho = seeds;
	// Зерно выборки σ
	const uint8_t * sigma = (seeds + SEED);
	// Вектор секрета s в области NTT
	poly_t s[K];
	// Секрет, подготовленный к умножению
	twisted_t prepared[K];
	/**
	 * Выбираем секрет
	 */
	#if defined(__ANTS_KECCAK_X4__)
		// Если параллельное ядро губок готово: четыре многочлена выбираются разом, лишние у неполной четвёрки отбрасываются
		if(::sponges4()){
			// Номера выборок секрета
			const uint8_t nonces[K] = {0, 1, 2, 3};
			// Выбираем четыре многочлена разом
			::binomial4(sigma, nonces, sample.eta1, s);
		// Иначе многочлены секрета выбираются по одному губкой
		} else {
	#endif
		/**
		 * Перебираем места вектора
		 */
		for(size_t i = 0; i < sample.dimension; i++)
			// Выбираем многочлен
			::binomial(sigma, static_cast <uint8_t> (i), sample.eta1, s[i]);
	/**
	 * Замыкаем ветвь параллельного выбора
	 */
	#if defined(__ANTS_KECCAK_X4__)
		}
	#endif
	/**
	 * Переводим секрет в область NTT и готовим к умножению
	 */
	for(size_t i = 0; i < sample.dimension; i++){
		// Переводим в область NTT
		::forward(s[i]);
		// Готовим к умножению
		::prepare(s[i], prepared[i]);
	}
	// Вектор шума e
	poly_t noises[K];
	/**
	 * Выбираем вектор шума
	 */
	#if defined(__ANTS_KECCAK_X4__)
		// Если параллельное ядро губок готово: четыре многочлена выбираются разом, лишние у неполной четвёрки отбрасываются
		if(::sponges4()){
			// Номера выборок шума
			const uint8_t nonces[K] = {static_cast <uint8_t> (sample.dimension), static_cast <uint8_t> (sample.dimension + 1), static_cast <uint8_t> (sample.dimension + 2), static_cast <uint8_t> (sample.dimension + 3)};
			// Выбираем четыре многочлена разом
			::binomial4(sigma, nonces, sample.eta1, noises);
		// Иначе шумы выбираются по одному губкой
		} else {
	#endif
		/**
		 * Перебираем места вектора
		 */
		for(size_t i = 0; i < sample.dimension; i++)
			// Выбираем шум
			::binomial(sigma, static_cast <uint8_t> (sample.dimension + i), sample.eta1, noises[i]);
	/**
	 * Замыкаем ветвь параллельного выбора
	 */
	#if defined(__ANTS_KECCAK_X4__)
		}
	#endif
	// Длина ключа инкапсуляции
	const size_t length = encapsulation(kem);
	// Развёрнутая матрица A: строка i произведения берёт элементы A[i][j]
	const poly_t * matrix = ::expanded(sample, rho);
	/**
	 * Вычисляем t = A s + e
	 */
	for(size_t i = 0; i < sample.dimension; i++){
		// Многочлен t_i: шум e_i в области NTT
		poly_t noise = noises[i];
		// Переводим шум в область NTT
		::forward(noise);
		// Накопитель произведений строки
		wide_t wide;
		// Обнуляем накопитель
		::memset(wide.values, 0, sizeof(wide.values));
		/**
		 * Перебираем столбцы
		 */
		for(size_t j = 0; j < sample.dimension; j++)
			// Накапливаем произведение элемента A[i][j] на s[j]
			::multiply(matrix[(i * K) + j], prepared[j], wide);
		// Произведение строки на секрет
		poly_t product;
		// Приводим накопитель
		::settle(wide, product);
		/**
		 * Складываем произведение с шумом
		 */
		for(size_t c = 0; c < N; c++)
			// Складываем коэффициенты
			noise.values[c] = ::once(noise.values[c] + product.values[c]);
		// Записываем многочлен t_i в ключ инкапсуляции
		::encode(noise, key + (i * POLY));
		// Записываем многочлен s_i в ключ декапсуляции
		::encode(s[i], secret + (i * POLY));
		// Затираем многочлен шума
		::wipe(noises[i].values, sizeof(noises[i].values));
	}
	// Записываем зерно ρ в ключ инкапсуляции
	::memcpy(key + (sample.dimension * POLY), rho, SEED);
	// Записываем ключ инкапсуляции в ключ декапсуляции
	::memcpy(secret + (sample.dimension * POLY), key, length);
	// Записываем хеш ключа инкапсуляции
	digest::sha3(digest::sha3_t::SHA3_256, view_t(key, length), secret + (sample.dimension * POLY) + length, SEED);
	// Записываем зерно z неявного отказа
	::memcpy(secret + (sample.dimension * POLY) + length + SEED, seed.data + SEED, SEED);
	// Затираем секрет
	::wipe(s, sizeof(s));
	// Затираем подготовленный секрет
	::wipe(prepared, sizeof(prepared));
	// Затираем зёрна выборки
	::wipe(seeds, sizeof(seeds));
	// Выводим успешность выработки
	return true;
}
/**
 * @brief Функция выработки пары ключей на случайном зерне
 *
 * @param kem    набор параметров
 * @param key    место, в которое помещается ключ инкапсуляции
 * @param secret место, в которое помещается ключ декапсуляции
 * @return       признак того, что пара ключей выработана
 *
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
	// Затираем зерно выработки с зерном отказа
	::wipe(seed, sizeof(seed));
	// Выводим итог выработки
	return result;
}
/**
 * @brief Функция инкапсуляции на заданном сообщении
 *
 * @param kem     набор параметров
 * @param key     ключ инкапсуляции собеседника
 * @param message случайное сообщение в тридцать два байта
 * @param cipher  место, в которое помещается шифртекст
 * @param shared  место, в которое помещается общий секрет в тридцать два байта
 * @return        признак того, что инкапсуляция выполнена
 *
 */
bool nts::agreement::encapsulate(const kem_t kem, const view_t & key, const view_t & message, uint8_t * cipher, uint8_t * shared) noexcept {
	// Описание набора параметров
	const sample_t sample = ::describe(kem);
	// Если набор не установлен, сообщение не той длины, места не переданы либо ключ негоден
	if((sample.dimension == 0) || (message.data == nullptr) || (message.size != MLKEM_MESSAGE) || (cipher == nullptr) || (shared == nullptr) || !validate(kem, key))
		// Выводим отказ инкапсуляции
		return false;
	// Хеш ключа инкапсуляции
	uint8_t hash[SEED];
	// Вычисляем хеш
	digest::sha3(digest::sha3_t::SHA3_256, key, hash, SEED);
	// Секрет и зерно шифрования: G(m || H(ek))
	uint8_t derived[64];
	// Вычисляем секрет и зерно
	::widely(message, view_t(hash, SEED), derived);
	// Шифруем сообщение
	::encrypt(sample, key.data, message.data, derived + SEED, cipher);
	// Выдаём общий секрет
	::memcpy(shared, derived, MLKEM_SHARED);
	// Затираем секрет и зерно
	::wipe(derived, sizeof(derived));
	// Выводим успешность инкапсуляции
	return true;
}
/**
 * @brief Функция инкапсуляции на случайном сообщении
 *
 * @param kem    набор параметров
 * @param key    ключ инкапсуляции собеседника
 * @param cipher место, в которое помещается шифртекст
 * @param shared место, в которое помещается общий секрет в тридцать два байта
 * @return       признак того, что инкапсуляция выполнена
 *
 */
bool nts::agreement::encapsulate(const kem_t kem, const view_t & key, uint8_t * cipher, uint8_t * shared) noexcept {
	// Случайное сообщение
	uint8_t message[MLKEM_MESSAGE];
	// Если сообщение выработать не удалось
	if(!entropy::bytes(message, sizeof(message)))
		// Выводим отказ инкапсуляции
		return false;
	// Инкапсулируем сообщение
	const bool result = encapsulate(kem, key, view_t(message, sizeof(message)), cipher, shared);
	// Затираем сообщение
	::wipe(message, sizeof(message));
	// Выводим итог инкапсуляции
	return result;
}
/**
 * @brief Функция декапсуляции
 *
 * @param kem    набор параметров
 * @param secret свой ключ декапсуляции
 * @param cipher шифртекст собеседника
 * @param shared место, в которое помещается общий секрет в тридцать два байта
 * @return       признак того, что декапсуляция выполнена
 *
 */
bool nts::agreement::decapsulate(const kem_t kem, const view_t & secret, const view_t & cipher, uint8_t * shared) noexcept {
	// Описание набора параметров
	const sample_t sample = ::describe(kem);
	// Если набор не установлен, длины не сходятся либо место не передано
	if((sample.dimension == 0) || (secret.data == nullptr) || (secret.size != decapsulation(kem)) ||
	   (cipher.data == nullptr) || (cipher.size != ciphertext(kem)) || (shared == nullptr))
		// Выводим отказ декапсуляции
		return false;
	// Длина ключа инкапсуляции
	const size_t length = encapsulation(kem);
	// Ключ инкапсуляции внутри ключа декапсуляции
	const uint8_t * key = (secret.data + (sample.dimension * POLY));
	// Хеш ключа инкапсуляции внутри ключа декапсуляции
	const uint8_t * hash = (key + length);
	// Зерно неявного отказа
	const uint8_t * rejection = (hash + SEED);
	// Пересчитанный хеш ключа инкапсуляции
	uint8_t recomputed[SEED];
	// Вычисляем хеш
	digest::sha3(digest::sha3_t::SHA3_256, view_t(key, length), recomputed, SEED);
	// Накопитель расхождения хешей
	uint8_t mismatch = 0;
	/**
	 * Сличаем хеши за постоянное время
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
	 * Проверяем секретные многочлены на выход за модуль
	 */
	for(size_t i = 0; i < sample.dimension; i++){
		// Многочлен секрета
		poly_t poly;
		// Проверяем коэффициенты
		ok = (::decode(secret.data + (i * POLY), poly) && ok);
		// Затираем многочлен
		::wipe(poly.values, sizeof(poly.values));
	}
	// Если секретные многочлены негодны
	if(!ok || !validate(kem, view_t(key, length)))
		// Выводим отказ декапсуляции
		return false;
	// Расшифрованное сообщение
	uint8_t message[MLKEM_MESSAGE];
	// Расшифровываем шифртекст в сообщение
	::decrypt(sample, secret.data, cipher.data, message);
	// Секрет и зерно шифрования: G(m' || h)
	uint8_t derived[64];
	// Вычисляем секрет и зерно
	::widely(view_t(message, sizeof(message)), view_t(hash, SEED), derived);
	// Неявно отвергнутый секрет: J(z || c)
	uint8_t rejected[MLKEM_SHARED];
	// Поток SHAKE256
	digest::keccak_t sponge(digest::sha3_t::SHAKE256);
	// Поглощаем зерно
	sponge.update(view_t(rejection, SEED));
	// Поглощаем шифртекст
	sponge.update(cipher);
	// Выжимаем отвергнутый секрет
	sponge.squeeze(rejected, sizeof(rejected));
	// Пересчитанный шифртекст
	uint8_t recrypted[1568];
	// Шифруем повторно для сличения шифртекстов
	::encrypt(sample, key, message, derived + SEED, recrypted);
	// Накопитель расхождения шифртекстов
	uint8_t differ = 0;
	/**
	 * Сличаем шифртексты за постоянное время
	 */
	for(size_t i = 0; i < cipher.size; i++)
		// Накапливаем расхождение
		differ |= (recrypted[i] ^ cipher.data[i]);
	// Маска выбора: нули при совпадении, единицы при расхождении
	const uint8_t mask = static_cast <uint8_t> (-static_cast <int8_t> ((differ | static_cast <uint8_t> (-differ)) >> 7));
	/**
	 * Выбираем секрет по маске
	 */
	for(size_t i = 0; i < MLKEM_SHARED; i++)
		// Выбираем настоящий либо отвергнутый секрет
		shared[i] = static_cast <uint8_t> ((derived[i] & ~mask) | (rejected[i] & mask));
	// Затираем сообщение
	::wipe(message, sizeof(message));
	// Затираем секрет и зерно
	::wipe(derived, sizeof(derived));
	// Затираем отвергнутый секрет
	::wipe(rejected, sizeof(rejected));
	// Затираем пересчитанный шифртекст
	::wipe(recrypted, sizeof(recrypted));
	// Выводим успешность декапсуляции
	return true;
}
