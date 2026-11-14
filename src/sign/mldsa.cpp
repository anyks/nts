/**
 * @file mldsa.cpp
 * @date 2026-10-03
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
 * @brief Модуль электронной подписи ML-DSA по FIPS 204
 *
 * @details Кольцо Z_q[X]/(X^256 + 1) при q = 2^23 − 2^13 + 1 = 8 380 417.
 *          Многочлены держатся массивами в 256 коэффициентов из 32 разрядов,
 *          произведения в области NTT с примитивным корнем ζ = 1753 из единицы
 *          степени 256 (негациклическое умножение, ζ^128 ≡ −1). Отбор коэффициентов
 *          и вызов - потоки SHAKE128/SHAKE256, кодировки ключей и подписи - по
 *          разделу 7 FIPS 204.
 *
 * @section Намеренные решения
 *  1. Арифметика поля - на приведении Монтгомери с QINV = q⁻¹ mod 2^32, вычисленным
 *    при сборке, как и MONT = 2^32 mod q: произведение 32-разрядных коэффициентов
 *    держится в 64 разрядах (2^23 · 2^23 < 2^46). Таблицы степеней ζ и обратных к
 *    ним считаются один раз при первом обращении и сличаются с определением
 *    стандарта, а не с чужой распечаткой; в таблице - степени в форме Монтгомери,
 *    итог умножения в области выходит в обычной форме без лишних переводов.
 *  2. Потоки выборки выжимаются блоками, а не по одному значению: отклоняющая
 *    выборка матрицы - блоками по три байта, выборка ±1 вызова - по одному байту
 *    на позицию, знаки первые восемь байтов. Числа коэффициентов на блок кратны
 *    блоку SHAKE, чтобы тройки и пары не рвались по краям.
 *  3. Проверки границ подписи (‖z‖∞, ‖resultEven‖∞, ‖c·productEven‖∞ и вес подсказки) идут без
 *    ветвлений по секретному значению там, где значение секретно: сравнение
 *    зерна вызова при проверке - по маске за постоянное время; выбор между
 *    принятием и отказом при выработке - тоже, и перезаписываемые части рабочей
 *    памяти затираются на каждой попытке.
 *  4. Запись ключа подписи - форма стандарта ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ productEven без
 *    перекладки при установке: выработка подписи распаковывает s1, s2 и productEven в
 *    области NTT на каждый вызов, а матрица строится из ρ заново - так запись
 *    читается и пишется всякой иной реализацией. Вся рабочая память на стеке:
 *    у ML-DSA-87 матрица занимает 56 килобайтов в области NTT, и ни один шаг не
 *    занимает память кучи, оттого методы не могут ответить нехваткой.
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
#include <sign/mldsa.hpp>
#include <digest/sha3.hpp>
#include <entropy/entropy.hpp>
#include <sys/wipe.hpp>
#include <internal/digest/keccak.hpp>
/**
 * На x86-64 с командами Keccak-x4 нужен опрос признаков машины
 */
#if defined(__ANTS_KECCAK_X4__) && defined(__x86_64__)
	#include <sys/machine.hpp>
#endif
/**
 * Векторные команды под арифметику NTT: SSE2 на x86-64 (есть на всякой x86-64) и NEON
 * на ARM64 (вечно доступно на этой архитектуре) - четыре 32-разрядных места в одном
 * регистре, обе ветви идут через одну прослойку (vec_t и v-функции ниже); Эльбрусу
 * остаётся переносимый путь без векторных слоёв
 *
 * @note Собиратель Microsoft Visual C++ признаков наборов команд не объявляет, но команды
 *       основания набора - SSE2 у x86-64 и NEON у ARM64 - доступны ему без ключей сборки,
 *       потому стена открывается признаком архитектуры вместо признака набора
 *
 */
#if ((defined(__x86_64__) && defined(__SSE2__)) || defined(__ANTS_MSVC_X64__)) && !defined(ANTS_NO_MACHINE)
	#include <emmintrin.h>
	/**
	 * Признаки векторного пути: команды SSE2
	 */
	#define __ANTS_MLDSA_SSE2__
	/**
	 * Признак общего векторного пути
	 */
	#define __ANTS_MLDSA_VECTOR__
/**
 * Ветвь NEON на ARM64
 */
#elif ((defined(__aarch64__) && defined(__ARM_NEON)) || defined(__ANTS_MSVC_ARM64__)) && !defined(ANTS_NO_MACHINE)
	#include <arm_neon.h>
	/**
	 * Признаки векторного пути: команды NEON
	 */
	#define __ANTS_MLDSA_NEON__
	/**
	 * Признак общего векторного пути
	 */
	#define __ANTS_MLDSA_VECTOR__
#endif
/**
 * Опрос машины нужен ветви SSE2 для развилки векторных слоёв на исполнении
 */
#if defined(__ANTS_MLDSA_SSE2__)
	#include <sys/machine.hpp>
#endif

/**
 * Пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Служебные объекты модуля
 *
 */
namespace {
	/**
	 * @brief Число коэффициентов многочлена кольца
	 *
	 */
	static constexpr size_t N = 256;
	/**
	 * @brief Модуль кольца: q = 2^23 − 2^13 + 1
	 *
	 */
	static constexpr uint32_t Q = 8380417;

	/**
	 * @brief Функция вычисления обратного по модулю 2^32 шагами Ньютона при сборке
	 *
	 * @param value нечётное значение
	 * @return      обратное value⁻¹ mod 2^32
	 *
	 */
	static constexpr uint32_t invert32(const uint32_t value) noexcept {
		// Шаг Ньютона удваивает верные разряды: x·(2 − a·x) сходится к a⁻¹
		uint32_t result = value;
		// Шесть шагов Ньютона дают 32 верных разряда обратного
		/**
		 * Удваиваем верные разряды обратного на каждом шаге
		 */
		for(size_t i = 0; i < 6; i++)
			// Домножаем на ошибку шага Ньютона
			result *= (2 - value * result);
		// Выводим обратное по модулю 2^32
		return result;
	}

	/**
	 * @brief Обратный множитель приведения Монтгомери: q⁻¹ mod 2^32
	 *
	 */
	static constexpr uint32_t QINV = invert32(Q);

	/**
	 * @brief Единица в форме Монтгомери: 2^32 mod q
	 *
	 */
	static constexpr uint32_t MONT = ((static_cast <uint64_t> (1) << 32) % Q);

	static_assert((static_cast <uint64_t> (Q) * QINV) % (static_cast <uint64_t> (1) << 32) == 1, "QINV должен быть обратным к q по модулю 2^32");

	/**
	 * @brief Функция приведения Монтгомери
	 *
	 * @param value значение меньше q · 2^32
	 * @return      приведённое value · 2⁻³² mod q в [−q, q]
	 *
	 */
	static constexpr int32_t reduce(const int64_t value) noexcept {
		// Младшие 32 разряда произведения на q⁻¹ mod 2^32 обращают значение в кратное q
		const int64_t word = static_cast <int32_t> (static_cast <uint32_t> (static_cast <uint64_t> (value) * QINV));
		// Выводим приведённое значение: вычитаем кратное q и снимаем масштаб 2^32
		return static_cast <int32_t> ((value - (word * static_cast <int64_t> (Q))) >> 32);
	}
	/**
	 * @brief Функция умножения коэффициентов по модулю с приведением Монтгомери
	 *
	 * @param first  первый сомножитель
	 * @param second второй сомножитель
	 * @return       произведение по модулю в форме Монтгомери при second в ней
	 *
	 */
	static constexpr int32_t multiply(const int32_t first, const int32_t second) noexcept {
		// Выводим произведение с приведением Монтгомери
		return reduce(static_cast <int64_t> (first) * second);
	}
	/**
	 * @brief Функция вычисления обратного по простому модулю q возведением в степень при сборке
	 *
	 * @param value значение отличное от нуля по модулю
	 * @return      обратное value⁻¹ mod q по малой теореме Ферма: value^(q − 2) mod q
	 *
	 */
	static constexpr uint32_t invertQ(const uint32_t value) noexcept {
		// Накопитель степени и основание в квадрате
		uint64_t result = 1, base = value;
		// Показатель q − 2 из малой теоремы Ферма
		uint64_t power = (Q - 2);
		/**
		 * Разбираем показатель по разрядам справа налево
		 */
		while(power != 0){
			// Если разряд показателя единичный
			if((power & 1) != 0)
				// Взнос основания в итог на единичном разряде показателя
				result = ((result * base) % Q);
			// Основание возводится в квадрат на каждом разряде
			base = ((base * base) % Q);
			// Переходим к следующему разряду показателя
			power >>= 1;
		}
		// Выводим обратное по модулю q
		return static_cast <uint32_t> (result);
	}

	static_assert((static_cast <uint64_t> (invertQ(1753)) * 1753) % Q == 1, "обращение по модулю q обязано быть верным");

	/**
	 * @brief Таблицы степеней корня NTT, считаются один раз при первом обращении
	 *
	 */
	struct Zetas {
		// Степени ζ = 1753 в порядке битового переворота восьми разрядов, в форме Монтгомери
		uint32_t forward[N];
		// Множитель 2^56 mod q: снимает масштаб 256 обратного NTT и перевод 2⁻³² произведений
		uint32_t factor;
		/**
		 * Хвостовые таблицы нужны лишь векторному пути: слои длины 2 и 1 идут сплавленным
		 * проходом по восьмёркам коэффициентов, и степени лежат в порядке мест этого прохода
		 */
		#if defined(__ANTS_MLDSA_VECTOR__)
			// Степени слоя длины 2 прямого NTT: по четыре на восьмёрку коэффициентов
			uint32_t onward2[N / 2] = {};
			// Степени слоя длины 1 прямого NTT
			uint32_t onward1[N / 2] = {};
			// Степени слоя длины 2 обратного NTT: задом наперёд со знаком минус
			uint32_t back2[N / 2] = {};
			// Степени слоя длины 1 обратного NTT
			uint32_t back1[N / 2] = {};
		#endif
		/**
		 * @brief Метод вычисления таблиц из определения стандарта
		 *
		 * @details ζ = 1753 примитивен из единицы степени 512 (ζ^256 ≡ −1 по q);
		 *          степени записываются в порядке битового переворота восьми разрядов,
		 *          прямое и обратное NTT читают одну таблицу вперёд и назад
		 *
		 */
		constexpr Zetas() noexcept : forward{}, factor(0) {
			/**
			 * Степени по порядку битового переворота, в форме Монтгомери
			 */
			for(size_t i = 0; i < N; i++){
				// Показатель степени: битовый переворот индекса
				size_t power = 0;
				/**
				 * Обращаем разряды индекса зеркально
				 */
				for(size_t bit = 0; bit < 8; bit++)
					// Переносим разряды индекса в обратном порядке
					power |= (((i >> bit) & 1) << (7 - bit));
				// Степень корня возведением
				uint64_t value = 1;
				/**
				 * Возводим 1753 в степень показателя
				 */
				for(size_t j = 0; j < power; j++)
					// Возводим 1753 в степень показателя
					value = ((value * 1753) % Q);
				// Степень записывается в форме Монтгомери умножением на 2^32
				forward[i] = static_cast <uint32_t> ((value << 32) % Q);
			}
			// Множитель 2^56 mod q = 41 978
			uint64_t scale = 1;
			/**
			 * Удваиваем накопитель по модулю 56 раз
			 */
			for(size_t i = 0; i < 56; i++)
				// Удваиваем накопитель по модулю на каждом из 56 разрядов
				scale = ((scale << 1) % Q);
			// Запоминаем множитель 2^56 mod q
			factor = static_cast <uint32_t> (scale);
			/**
			 * Заполняем хвостовые таблицы векторного пути: по четыре степени на восьмёрку коэффициентов
			 */
			#if defined(__ANTS_MLDSA_VECTOR__)
				/**
				 * Перебираем восьмёрки коэффициентов
				 */
				for(size_t k = 0; k < (N / 8); k++){
					/**
					 * Перебираем места восьмёрки
					 */
					for(size_t lane = 0; lane < 4; lane++){
						// Слой длины 2 прямого NTT: пара соседних участков делит степень
						this->onward2[(4 * k) + lane] = this->forward[64 + (2 * k) + (lane / 2)];
						// Слой длины 1 прямого NTT: четыре последовательных участка
						this->onward1[(4 * k) + lane] = this->forward[128 + (4 * k) + lane];
						// Слой длины 2 обратного NTT: степени задом наперёд со знаком минус
						this->back2[(4 * k) + lane] = (Q - this->forward[127 - (2 * k) - (lane / 2)]);
						// Слой длины 1 обратного NTT
						this->back1[(4 * k) + lane] = (Q - this->forward[255 - (4 * k) - lane]);
					}
				}
			#endif
		}
	};

	/**
	 * Таблицы степеней корня, порождаются один раз на процесс
	 */
	static constexpr Zetas ZETAS;

	static_assert((static_cast <uint64_t> (ZETAS.factor) * 256) % Q == ((static_cast <uint64_t> (MONT) * MONT) % Q), "итоговый масштаб обратного NTT должен быть 2^56 mod q");

	/**
	 * Векторная прослойка над четырьмя 32-разрядными местами одного регистра
	 */
	#if defined(__ANTS_MLDSA_VECTOR__)
		/**
		 * Ветвь SSE2: вектор в 128 разрядов
		 */
		#if defined(__ANTS_MLDSA_SSE2__)
			// Вектор в 128 разрядов
			typedef __m128i vec_t;
			/**
			 * @brief Функция загрузки вектора коэффициентов
			 *
			 * @param data место четырёх коэффициентов
			 * @return     вектор четырёх коэффициентов
			 *
			 */
			static __ANTS_INLINE__ vec_t loadVector(const void * data) noexcept {
				// Выводим вектор четырёх коэффициентов
				return _mm_loadu_si128(reinterpret_cast <const __m128i *> (data));
			}
			/**
			 * @brief Функция записи вектора коэффициентов
			 *
			 * @param result место четырёх коэффициентов
			 * @param value  записываемый вектор
			 *
			 */
			static __ANTS_INLINE__ void storeVector(void * result, const vec_t value) noexcept {
				// Записываем вектор четырёх коэффициентов
				_mm_storeu_si128(reinterpret_cast <__m128i *> (result), value);
			}
			/**
			 * @brief Функция заполнения всех мест одним значением
			 *
			 * @param value значение всех мест
			 * @return      вектор с заполненными местами
			 *
			 */
			static constexpr vec_t broadcast32(const int32_t value) noexcept {
				// Выводим вектор с заполненными местами
				return _mm_set1_epi32(value);
			}
			/**
			 * @brief Функция суммирования векторов
			 *
			 * @param first  первое слагаемое
			 * @param second второе слагаемое
			 * @return       суммы мест
			 *
			 */
			static constexpr vec_t add32(const vec_t first, const vec_t second) noexcept {
				// Выводим суммы мест
				return _mm_add_epi32(first, second);
			}
			/**
			 * @brief Функция вычитания векторов
			 *
			 * @param first  уменьшаемое
			 * @param second вычитаемое
			 * @return       разности мест
			 *
			 */
			static constexpr vec_t subtract32(const vec_t first, const vec_t second) noexcept {
				// Выводим разности мест
				return _mm_sub_epi32(first, second);
			}
			/**
			 * @brief Функция знакового произведения чётных мест двух векторов
			 *
			 * @details SSE2 умеет умножать беззнаковые чётные места в 64 разряда: знаковое
			 *          произведение выходит вычитанием поправки 2³²·(sₐ·uᵦ + sᵦ·uₐ), где
			 *          s - знаковый разряд, а u - беззнаковый вид места.
			 *
			 * @param first  первый сомножитель
			 * @param second второй сомножитель
			 * @return       произведения чётных мест в 64-разрядных половинах
			 *
			 */
			static constexpr vec_t multiplyEven64(const vec_t first, const vec_t second) noexcept {
				// Нулевой вектор для расширения слов
				const vec_t zero = _mm_setzero_si128();
				// Беззнаковые произведения чётных мест
				const vec_t product = _mm_mul_epu32(first, second);
				// Поправка знака мест: знаковые маски заведуют чужими сомножителями
				const vec_t sign = _mm_add_epi32(_mm_and_si128(_mm_srai_epi32(first, 31), second), _mm_and_si128(_mm_srai_epi32(second, 31), first));
				// Поправка чётных мест в старшие слова 64-разрядных половин
				const vec_t even = _mm_shuffle_epi32(sign, 0x08);
				// Выводим знаковые произведения
				return _mm_sub_epi64(product, _mm_slli_epi64(_mm_unpacklo_epi32(even, zero), 32));
			}
			/**
			 * @brief Функция знакового произведения нечётных мест двух векторов
			 *
			 * @param first  первый сомножитель
			 * @param second второй сомножитель
			 * @return       произведения нечётных мест в 64-разрядных половинах
			 *
			 */
			static constexpr vec_t multiplyOdd64(const vec_t first, const vec_t second) noexcept {
				// Нечётные места на чётных позициях
				const vec_t low = _mm_shuffle_epi32(first, 0x31);
				// То же для второго сомножителя
				const vec_t high = _mm_shuffle_epi32(second, 0x31);
				// Выводим произведения чётных позиций переставленных векторов
				return multiplyEven64(low, high);
			}
			/**
			 * @brief Функция умножения Монтгомери четырёх пар мест
			 *
			 * @details Произведение мест - 64 разряда, множитель q⁻¹ mod 2³² обращает младшее
			 *          слово произведения в кратное q, старшее слово разности произведения
			 *          с этим кратным и есть итог в [−q, q]. Младшие слова и множители
			 *          перелагаются на чётные позиции перестановками 0x08 и 0x10 - их и
			 *          берут произведения vmuls.
			 *
			 * @param first  первый сомножитель
			 * @param second второй сомножитель
			 * @return       произведения мест с приведением Монтгомери
			 *
			 */
			static __ANTS_INLINE__ vec_t multiplyMontgomery(const vec_t first, const vec_t second) noexcept {
				// Произведения чётных мест
				const vec_t productEven = multiplyEven64(first, second);
				// Произведения нечётных мест
				const vec_t productOdd = multiplyOdd64(first, second);
				// Множитель q⁻¹ mod 2³² по всем местам
				const vec_t inverse = broadcast32(static_cast <int32_t> (QINV));
				// Модуль q по всем местам
				const vec_t modulus = broadcast32(static_cast <int32_t> (Q));
				// Младшие слова чётных произведений на чётных позициях
				const vec_t lowEven = _mm_shuffle_epi32(_mm_shuffle_epi32(productEven, 0x08), 0x10);
				// Младшие слова нечётных произведений
				const vec_t lowOdd = _mm_shuffle_epi32(_mm_shuffle_epi32(productOdd, 0x08), 0x10);
				// Множители, обращающие младшие слова чётных произведений в кратные q
				const vec_t factorEven = multiplyEven64(lowEven, inverse);
				// Множители нечётных произведений
				const vec_t factorOdd = multiplyEven64(lowOdd, inverse);
				// Кратные q чётных мест: младшие слова множителей на чётных позициях
				const vec_t multipleEven = multiplyEven64(_mm_shuffle_epi32(_mm_shuffle_epi32(factorEven, 0x08), 0x10), modulus);
				// Кратные q нечётных мест
				const vec_t multipleOdd = multiplyEven64(_mm_shuffle_epi32(_mm_shuffle_epi32(factorOdd, 0x08), 0x10), modulus);
				// Разности чётных произведений с кратными q: старшие слова и есть итог
				const vec_t resultEven = _mm_sub_epi64(productEven, multipleEven);
				// Разности нечётных произведений
				const vec_t resultOdd = _mm_sub_epi64(productOdd, multipleOdd);
				// Собираем чётные и нечётные итоги в порядок мест
				return _mm_unpacklo_epi32(_mm_shuffle_epi32(resultEven, 0x0D), _mm_shuffle_epi32(resultOdd, 0x0D));
			}
			/**
			 * @brief Функция сборки младших половин двух векторов
			 *
			 * @param first  первый вектор
			 * @param second второй вектор
			 * @return       вектор [a0 a1 b0 b1]
			 *
			 */
			static constexpr vec_t takeLow64(const vec_t first, const vec_t second) noexcept {
				// Выводим младшие половины рядом
				return _mm_unpacklo_epi64(first, second);
			}
			/**
			 * @brief Функция сборки старших половин двух векторов
			 *
			 * @param first  первый вектор
			 * @param second второй вектор
			 * @return       вектор [a2 a3 b2 b3]
			 *
			 */
			static constexpr vec_t takeHigh64(const vec_t first, const vec_t second) noexcept {
				// Выводим старшие половины рядом
				return _mm_unpackhi_epi64(first, second);
			}
			/**
			 * @brief Функция сборки чётных мест двух векторов
			 *
			 * @param first  первый вектор
			 * @param second второй вектор
			 * @return       вектор [a0 a2 b0 b2]
			 *
			 */
			static constexpr vec_t takeEven32(const vec_t first, const vec_t second) noexcept {
				// Выводим чётные места вперёд
				return takeLow64(_mm_shuffle_epi32(first, 0xD8), _mm_shuffle_epi32(second, 0xD8));
			}
			/**
			 * @brief Функция сборки нечётных мест двух векторов
			 *
			 * @param first  первый вектор
			 * @param second второй вектор
			 * @return       вектор [a1 a3 b1 b3]
			 *
			 */
			static constexpr vec_t takeOdd32(const vec_t first, const vec_t second) noexcept {
				// Выводим нечётные места вперёд
				return takeHigh64(_mm_shuffle_epi32(first, 0xD8), _mm_shuffle_epi32(second, 0xD8));
			}
			/**
			 * @brief Функция переплетения младших пар мест двух векторов
			 *
			 * @param first  первый вектор
			 * @param second второй вектор
			 * @return       вектор [a0 b0 a1 b1]
			 *
			 */
			static constexpr vec_t interleaveLow32(const vec_t first, const vec_t second) noexcept {
				// Выводим переплетение младших пар
				return _mm_unpacklo_epi32(first, second);
			}
			/**
			 * @brief Функция переплетения старших пар мест двух векторов
			 *
			 * @param first  первый вектор
			 * @param second второй вектор
			 * @return       вектор [a2 b2 a3 b3]
			 *
			 */
			static constexpr vec_t interleaveHigh32(const vec_t first, const vec_t second) noexcept {
				// Выводим переплетение старших пар
				return _mm_unpackhi_epi32(first, second);
			}
		/**
		 * Ветвь NEON: те же операции над 128-разрядными векторами ARM64
		 */
		#elif defined(__ANTS_MLDSA_NEON__)
			/**
			 * @brief Вектор в 128 разрядов: четыре 32-разрядных места (NEON)
			 *
			 */
			typedef int32x4_t vec_t;
			/**
			 * @brief Функция загрузки вектора коэффициентов
			 *
			 * @param data место четырёх коэффициентов
			 * @return     вектор четырёх коэффициентов
			 *
			 */
			static __ANTS_INLINE__ vec_t loadVector(const void * data) noexcept {
				// Выводим вектор четырёх коэффициентов
				return vld1q_s32(static_cast <const int32_t *> (data));
			}
			/**
			 * @brief Функция записи вектора коэффициентов
			 *
			 * @param result место четырёх коэффициентов
			 * @param value  записываемый вектор
			 *
			 */
			static __ANTS_INLINE__ void storeVector(void * result, const vec_t value) noexcept {
				// Записываем вектор четырёх коэффициентов
				vst1q_s32(static_cast <int32_t *> (result), value);
			}
			/**
			 * @brief Функция заполнения всех мест одним значением
			 *
			 * @param value значение всех мест
			 * @return      вектор с заполненными местами
			 *
			 */
			static constexpr vec_t broadcast32(const int32_t value) noexcept {
				// Выводим вектор с заполненными местами
				return vdupq_n_s32(value);
			}
			/**
			 * @brief Функция суммирования векторов
			 *
			 * @param first  первое слагаемое
			 * @param second второе слагаемое
			 * @return       суммы мест
			 *
			 */
			static constexpr vec_t add32(const vec_t first, const vec_t second) noexcept {
				// Выводим суммы мест
				return vaddq_s32(first, second);
			}
			/**
			 * @brief Функция вычитания векторов
			 *
			 * @param first  уменьшаемое
			 * @param second вычитаемое
			 * @return       разности мест
			 *
			 */
			static constexpr vec_t subtract32(const vec_t first, const vec_t second) noexcept {
				// Выводим разности мест
				return vsubq_s32(first, second);
			}
			/**
			 * @brief Функция умножения Монтгомери четырёх пар мест
			 *
			 * @details Произведение мест - 64 разряда, множитель q⁻¹ mod 2³² обращает младшее
			 *          слово произведения в кратное q, старшее слово разности произведения
			 *          с этим кратным и есть итог в [−q, q].
			 *
			 * @param first  первый сомножитель
			 * @param second второй сомножитель
			 * @return       произведения мест с приведением Монтгомери
			 *
			 */
			static __ANTS_INLINE__ vec_t multiplyMontgomery(const vec_t first, const vec_t second) noexcept {
				// Произведения чётных мест
				const int64x2_t productEven = vmull_s32(vget_low_s32(first), vget_low_s32(second));
				// Произведения нечётных мест
				const int64x2_t productOdd = vmull_high_s32(first, second);
				// Младшие слова чётных произведений
				const int32x2_t lowEven = vmovn_s64(productEven);
				// Младшие слова нечётных произведений
				const int32x2_t lowOdd = vmovn_s64(productOdd);
				// Множители, обращающие младшие слова чётных произведений в кратные q: младшие 32 разряда произведения
				const int32x2_t factorEven = vmul_s32(lowEven, vdup_n_s32(static_cast <int32_t> (QINV)));
				// Множители нечётных произведений
				const int32x2_t factorOdd = vmul_s32(lowOdd, vdup_n_s32(static_cast <int32_t> (QINV)));
				// Разности чётных произведений с кратными q: старшие слова и есть итог
				const int64x2_t resultEven = vsubq_s64(productEven, vmull_s32(factorEven, vdup_n_s32(static_cast <int32_t> (Q))));
				// Разности нечётных произведений
				const int64x2_t resultOdd = vsubq_s64(productOdd, vmull_s32(factorOdd, vdup_n_s32(static_cast <int32_t> (Q))));
				// Собираем чётные и нечётные итоги в порядок мест
				return vcombine_s32(vshrn_n_s64(resultEven, 32), vshrn_n_s64(resultOdd, 32));
			}
			/**
			 * @brief Функция сборки младших половин двух векторов
			 *
			 * @param first  первый вектор
			 * @param second второй вектор
			 * @return       вектор [a0 a1 b0 b1]
			 *
			 */
			static constexpr vec_t takeLow64(const vec_t first, const vec_t second) noexcept {
				// Выводим младшие половины рядом
				return vcombine_s32(vget_low_s32(first), vget_low_s32(second));
			}
			/**
			 * @brief Функция сборки старших половин двух векторов
			 *
			 * @param first  первый вектор
			 * @param second второй вектор
			 * @return       вектор [a2 a3 b2 b3]
			 *
			 */
			static constexpr vec_t takeHigh64(const vec_t first, const vec_t second) noexcept {
				// Выводим старшие половины рядом
				return vcombine_s32(vget_high_s32(first), vget_high_s32(second));
			}
			/**
			 * @brief Функция сборки чётных мест двух векторов
			 *
			 * @param first  первый вектор
			 * @param second второй вектор
			 * @return       вектор [a0 a2 b0 b2]
			 *
			 */
			static constexpr vec_t takeEven32(const vec_t first, const vec_t second) noexcept {
				// Выводим чётные места вперёд
				return vuzp1q_s32(first, second);
			}
			/**
			 * @brief Функция сборки нечётных мест двух векторов
			 *
			 * @param first  первый вектор
			 * @param second второй вектор
			 * @return       вектор [a1 a3 b1 b3]
			 *
			 */
			static constexpr vec_t takeOdd32(const vec_t first, const vec_t second) noexcept {
				// Выводим нечётные места вперёд
				return vuzp2q_s32(first, second);
			}
			/**
			 * @brief Функция переплетения младших пар мест двух векторов
			 *
			 * @param first  первый вектор
			 * @param second второй вектор
			 * @return       вектор [a0 b0 a1 b1]
			 *
			 */
			static constexpr vec_t interleaveLow32(const vec_t first, const vec_t second) noexcept {
				// Выводим переплетение младших пар
				return vzip1q_s32(first, second);
			}
			/**
			 * @brief Функция переплетения старших пар мест двух векторов
			 *
			 * @param first  первый вектор
			 * @param second второй вектор
			 * @return       вектор [a2 b2 a3 b3]
			 *
			 */
			static constexpr vec_t interleaveHigh32(const vec_t first, const vec_t second) noexcept {
				// Выводим переплетение старших пар
				return vzip2q_s32(first, second);
			}
		#endif
	#endif

	/**
	 * @brief Функция проверки готовности векторных слоёв NTT машине
	 *
	 * @return признак того, что векторные команды машина исполняет честно
	 *
	 * @details Ветвь SSE2 многословнее переносимой: под чистой эмуляцией CPU каждая
	 *          команда стоит одинаково дорого, и слои проигрывают переносимым -
	 *          эмулируемые машины уходят на переносимый путь по отсутствию заявки AVX,
	 *          которой умолчательная модель QEMU не несёт, а всякое настоящее железо
	 *          x86-64 несёт с 2011 года; прочие ветви векторного пути вечно готовы.
	 *
	 */
	static bool vectors() noexcept {
		/**
		 * Готовность ветви SSE2 выясняется по заявке AVX машины
		 */
		#if defined(__ANTS_MLDSA_SSE2__)
			// Выводим готовность по заявке AVX: умолчательная модель QEMU не заявляет его, а всякое настоящее железо x86-64 заявляет
			return machine::has(machine::feature_t::AVX);
		/**
		 * Прочие ветви векторного пути вечно готовы
		 */
		#else
			// Выводим вечную готовность прочих ветвей
			return true;
		#endif
	}

	/**
	 * Векторное тело существует лишь на векторном пути
	 */
	#if defined(__ANTS_MLDSA_VECTOR__)
		/**
		 * @brief Функция прямого NTT многочлена векторными слоями
		 *
		 * @details Слои длины от 128 до 4 идут целыми векторами внутри участков, слои
		 *          длины 2 и 1 - одним сплавленным проходом по восьмёркам коэффициентов
		 *          с перестановками половин и чётных мест.
		 *
		 * @param poly многочлен, переводится в область NTT на месте
		 *
		 */
		static void forwardVector(int32_t * poly) noexcept {
			// Таблица степеней в векторном чтении
			const int32_t * table = reinterpret_cast <const int32_t *> (ZETAS.forward);
			// Место в таблице степеней
			size_t index = 0;
			/**
			 * Перебираем слои длины от 128 до 4
			 */
			for(size_t length = (N / 2); length >= 4; length >>= 1){
				/**
				 * Перебираем начала участков
				 */
				for(size_t start = 0; start < N; start += (2 * length)){
					// Степень слоя по всем местам
					const vec_t zeta = broadcast32(table[++index]);
					/**
					 * Перебираем четвёрки пар участка
					 */
					for(size_t j = start; j < (start + length); j += 4){
						// Произведение степени и вторых коэффициентов пар
						const vec_t product = multiplyMontgomery(loadVector(poly + j + length), zeta);
						// Первые коэффициенты пар
						const vec_t first = loadVector(poly + j);
						// Разности и суммы пар
						storeVector(poly + j + length, subtract32(first, product));
						storeVector(poly + j, add32(first, product));
					}
				}
			}
			/**
			 * Сплавленный проход по восьмёркам коэффициентов: слои длины 2 и 1
			 */
			for(size_t i = 0, m = 0; i < N; i += 8, m += 4){
				// Первый вектор четырёх коэффициентов
				const vec_t first = loadVector(poly + i);
				// Второй вектор четырёх коэффициентов
				const vec_t second = loadVector(poly + i + 4);
				// Слой длины 2: первые пары четвёрок против вторых
				vec_t low = takeLow64(first, second);
				// Старшие половины двух векторов
				vec_t high = takeHigh64(first, second);
				// Произведения степеней и вторых пар
				vec_t product = multiplyMontgomery(high, loadVector(ZETAS.onward2 + m));
				// Разности пар
				high = subtract32(low, product);
				// Суммы пар
				low = add32(low, product);
				// Порядок памяти восьмёрки: младшие половины
				const vec_t memoryLow = takeLow64(low, high);
				// Порядок памяти восьмёрки: старшие половины
				const vec_t memoryHigh = takeHigh64(low, high);
				// Чётные места восьмёрки
				const vec_t even = takeEven32(memoryLow, memoryHigh);
				// Нечётные места восьмёрки
				const vec_t odd = takeOdd32(memoryLow, memoryHigh);
				// Слой длины 1: произведения степеней и нечётных мест
				product = multiplyMontgomery(odd, loadVector(ZETAS.onward1 + m));
				// Суммы чётных мест
				low = add32(even, product);
				// Разности чётных мест
				high = subtract32(even, product);
				// Записываем младшую половину восьмёрки в порядок коэффициентов
				storeVector(poly + i, interleaveLow32(low, high));
				// Записываем старшую половину восьмёрки
				storeVector(poly + i + 4, interleaveHigh32(low, high));
			}
		}
	#endif
	/**
	 * @brief Функция прямого NTT многочлена переносимыми слоями
	 *
	 * @param poly многочлен, переводится в область NTT на месте
	 *
	 */
	static __ANTS_INLINE__ void forwardPortable(int32_t * poly) noexcept {
		// Позиция степени в таблице
		size_t index = 0;
		/**
		 * Слои уменьшающейся длины: бабочка Кули-Тьюки без переноса между слоями
		 */
		for(size_t length = (N / 2); length > 0; length >>= 1){
			/**
			 * Перебираем начала участков
			 */
			for(size_t start = 0; start < N; start += (2 * length)){
				// Степень слоя
				const int32_t zeta = static_cast <int32_t> (ZETAS.forward[++index]);
				/**
				 * Перебираем пары участка
				 */
				for(size_t i = start; i < (start + length); i++){
					// Произведение пары на степень слоя
					const int32_t term = multiply(zeta, poly[i + length]);
					// Бабочка Кули-Тьюки: нижняя половина пары теряет произведение
					poly[i + length] = (poly[i] - term);
					// Верхняя половина пары наращивается произведением
					poly[i] += term;
				}
			}
		}
	}
	/**
	 * @brief Функция прямого NTT многочлена
	 *
	 * @param poly многочлен, переводится в область NTT на месте
	 *
	 * @details Векторные слои идут, когда машина исполняет их честно: под чистой
	 *          эмуляцией CPU векторные команды стоят как скалярные, и многословные
	 *          слои проигрывают переносимым
	 *
	 */
	static __ANTS_INLINE__ void forward(int32_t * poly) noexcept {
		/**
		 * Векторные слои идут лишь готовой машине
		 */
		#if defined(__ANTS_MLDSA_VECTOR__)
			// Если векторные слои готовы машине
			if(vectors()){
				// Переводим векторными слоями
				forwardVector(poly);
				// Векторные слои перевели многочлен
				return;
			}
		#endif
		// Переводим переносимыми слоями
		forwardPortable(poly);
	}

	/**
	 * Векторное тело существует лишь на векторном пути
	 */
	#if defined(__ANTS_MLDSA_VECTOR__)
		/**
		 * @brief Функция обратного NTT многочлена векторными слоями
		 *
		 * @details Слои длины 1 и 2 идут одним сплавленным проходом по восьмёркам
		 *          коэффициентов, слои длины от 4 до 128 - целыми векторами внутри
		 *          участков, итоговый масштаб снимается векторным умножением
		 *
		 * @param poly многочлен из области NTT, переводится в обычную форму на месте
		 *
		 */
		static void backwardVector(int32_t * poly) noexcept {
			// Таблица степеней в векторном чтении
			const int32_t * table = reinterpret_cast <const int32_t *> (ZETAS.forward);
			// Место в таблице степеней после хвостовых слоёв
			size_t index = 64;
			/**
			 * Сплавленный проход по восьмёркам коэффициентов: слои длины 1 и 2
			 */
			for(size_t i = 0, m = 0; i < N; i += 8, m += 4){
				// Первый вектор четырёх коэффициентов
				const vec_t lower = loadVector(poly + i);
				// Второй вектор четырёх коэффициентов
				const vec_t upper = loadVector(poly + i + 4);
				// Слой длины 1: чётные места восьмёрки
				const vec_t even = takeEven32(lower, upper);
				// Нечётные места восьмёрки
				const vec_t odd = takeOdd32(lower, upper);
				// Суммы пар
				vec_t sum = add32(even, odd);
				// Разности пар
				const vec_t difference = subtract32(even, odd);
				// Произведения разностей на степени слоя
				vec_t product = multiplyMontgomery(difference, loadVector(ZETAS.back1 + m));
				// Порядок памяти восьмёрки: младшая половина вперемежку
				vec_t low = interleaveLow32(sum, product);
				// Старшая половина восьмёрки
				vec_t high = interleaveHigh32(sum, product);
				// Слой длины 2: первые пары четвёрок
				const vec_t first = takeLow64(low, high);
				// Вторые пары четвёрок
				const vec_t second = takeHigh64(low, high);
				// Суммы пар слоя
				sum = add32(first, second);
				// Разности пар слоя
				const vec_t spread = subtract32(first, second);
				// Произведения разностей на степени слоя
				product = multiplyMontgomery(spread, loadVector(ZETAS.back2 + m));
				// Записываем младшую половину восьмёрки в порядок коэффициентов
				storeVector(poly + i, takeLow64(sum, product));
				// Записываем старшую половину восьмёрки
				storeVector(poly + i + 4, takeHigh64(sum, product));
			}
			/**
			 * Перебираем слои длины от 4 до 128
			 */
			for(size_t length = 4; length < N; length <<= 1){
				/**
				 * Перебираем начала участков
				 */
				for(size_t start = 0; start < N; start += (2 * length)){
					// Степень слоя задом наперёд со знаком минус
					const vec_t zeta = broadcast32(static_cast <int32_t> (Q) - table[--index]);
					/**
					 * Перебираем четвёрки пар участка
					 */
					for(size_t j = start; j < (start + length); j += 4){
						// Пара коэффициентов
						const vec_t first = loadVector(poly + j), second = loadVector(poly + j + length);
						// Бабочка Джентльмена-Санда: сумма вперёд, разность к степени
						storeVector(poly + j, add32(first, second));
						storeVector(poly + j + length, multiplyMontgomery(subtract32(first, second), zeta));
					}
				}
			}
			// Итоговый масштаб 2^56 по всем коэффициентам
			const vec_t scale = broadcast32(static_cast <int32_t> (ZETAS.factor));
			/**
			 * Перебираем четвёрки коэффициентов
			 */
			for(size_t i = 0; i < N; i += 4)
				// Коэффициент снимает масштаб 256 и переводит произведение из формы Монтгомери
				storeVector(poly + i, multiplyMontgomery(loadVector(poly + i), scale));
		}
	#endif
	/**
	 * @brief Функция обратного NTT многочлена переносимыми слоями
	 *
	 * @details Прямая таблица степеней читается задом наперёд: степень 1753^(256−k)
	 *          есть −1753^(−k), и знак обращает разность бабочки; множитель 2^56
	 *          снимает масштаб 256 обратного NTT и перевод 2⁻³² произведений.
	 *
	 * @param poly многочлен из области NTT, переводится в обычную форму на месте
	 *
	 */
	static __ANTS_INLINE__ void backwardPortable(int32_t * poly) noexcept {
		// Позиция степени в таблице
		size_t index = N;
		/**
		 * Слои возрастающей длины: бабочка Джентльмена-Санда
		 */
		for(size_t length = 1; length < N; length <<= 1){
			/**
			 * Перебираем начала участков
			 */
			for(size_t start = 0; start < N; start += (2 * length)){
				// Степень слоя из прямой таблицы задом наперёд
				const int32_t zeta = (static_cast <int32_t> (Q) - static_cast <int32_t> (ZETAS.forward[--index]));
				/**
				 * Перебираем пары участка
				 */
				for(size_t i = start; i < (start + length); i++){
					// Сумма пары и произведение разности на степень слоя
					const int32_t term = poly[i];
					// Бабочка Джентльмена-Санда: верхняя половина пары есть сумма
					poly[i] = (term + poly[i + length]);
					// Нижняя половина пары есть разность
					poly[i + length] = (term - poly[i + length]);
					// Разность приводится к степени слоя
					poly[i + length] = multiply(zeta, poly[i + length]);
				}
			}
		}
		/**
		 * Итоговый масштаб 2^56: 256⁻¹ с переводом произведений из формы 2⁻³² в обычную
		 */
		for(size_t i = 0; i < N; i++)
			// Коэффициент снимает масштаб 256 и переводит произведение из формы Монтгомери
			poly[i] = multiply(static_cast <int32_t> (ZETAS.factor), poly[i]);
	}
	/**
	 * @brief Функция обратного NTT многочлена
	 *
	 * @details Векторные слои идут, когда машина исполняет их честно: под чистой
	 *          эмуляцией CPU векторные команды стоят как скалярные, и многословные
	 *          слои проигрывают переносимым.
	 *
	 * @param poly многочлен из области NTT, переводится в обычную форму на месте
	 *
	 */
	static __ANTS_INLINE__ void backward(int32_t * poly) noexcept {
		/**
		 * Векторные слои идут лишь готовой машине
		 */
		#if defined(__ANTS_MLDSA_VECTOR__)
			// Если векторные слои готовы машине
			if(vectors()){
				// Переводим векторными слоями
				backwardVector(poly);
				// Векторные слои перевели многочлен
				return;
			}
		#endif
		// Переводим переносимыми слоями
		backwardPortable(poly);
	}

	/**
	 * Векторное тело существует лишь на векторном пути
	 */
	#if defined(__ANTS_MLDSA_VECTOR__)
		/**
		 * @brief Функция произведения многочленов векторными слоями
		 *
		 * @param first  первый сомножитель в области
		 * @param second второй сомножитель в области
		 * @param result произведение в области
		 *
		 */
		static __ANTS_INLINE__ void pointwiseVector(const int32_t * first, const int32_t * second, int32_t * result) noexcept {
			/**
			 * Перебираем четвёрки коэффициентов
			 */
			for(size_t i = 0; i < N; i += 4)
				// Произведение коэффициентов в области NTT
				storeVector(result + i, multiplyMontgomery(loadVector(first + i), loadVector(second + i)));
		}
	#endif

	/**
	 * @brief Функция произведения многочленов переносимыми слоями
	 *
	 * @param first  первый сомножитель в области
	 * @param second второй сомножитель в области
	 * @param result произведение в области
	 *
	 */
	static __ANTS_INLINE__ void pointwisePortable(const int32_t * first, const int32_t * second, int32_t * result) noexcept {
		/**
		 * Перебираем коэффициенты
		 */
		for(size_t i = 0; i < N; i++)
			// Произведение коэффициентов в области NTT
			result[i] = multiply(first[i], second[i]);
	}
	/**
	 * @brief Функция произведения многочленов в области NTT по коэффициентам
	 *
	 * @details Векторные слои идут, когда машина исполняет их честно: под чистой
	 *          эмуляцией CPU векторные команды стоят как скалярные, и многословные
	 *          слои проигрывают переносимым.
	 *
	 * @param first  первый сомножитель в области
	 * @param second второй сомножитель в области
	 * @param result произведение в области
	 *
	 */
	static __ANTS_INLINE__ void pointwise(const int32_t * first, const int32_t * second, int32_t * result) noexcept {
		/**
		 * Векторные слои идут лишь готовой машине
		 */
		#if defined(__ANTS_MLDSA_VECTOR__)
			// Если векторные слои готовы машине
			if(vectors()){
				// Перемножаем векторными слоями
				pointwiseVector(first, second, result);
				// Векторные слои перемножили многочлены
				return;
			}
		#endif
		// Перемножаем переносимыми слоями
		pointwisePortable(first, second, result);
	}

	/**
	 * @brief Функция нормализации коэффициентов многочлена к [0, q)
	 *
	 * @details Выход обратного NTT уже в обычной форме: дополнительное приведение
	 *          Монтгомери здесь неуместно, оно масштабировало бы значения на 2⁻³².
	 *
	 * @param poly многочлен, нормализуется на месте
	 *
	 */
	static __ANTS_INLINE__ void reduceAll(int32_t * poly) noexcept {
		/**
		 * Приводим коэффициенты к [0, q)
		 */
		for(size_t i = 0; i < N; i++){
			// Остаток по модулю со знаком делимого
			const int32_t value = (poly[i] % static_cast <int32_t> (Q));
			// Отрицательный остаток переводится в [0, q) прибавлением модуля
			poly[i] = (value + ((value >> 31) & static_cast <int32_t> (Q)));
		}
	}
	/**
	 * @brief Функция суммы многочленов по коэффициентам
	 *
	 * @param first  первое слагаемое
	 * @param second второе слагаемое
	 * @param result сумма
	 *
	 */
	static __ANTS_INLINE__ void add(const int32_t * first, const int32_t * second, int32_t * result) noexcept {
		/**
		 * Складываем коэффициенты
		 */
		for(size_t i = 0; i < N; i++)
			// Сумма коэффициентов
			result[i] = (first[i] + second[i]);
	}
	/**
	 * @brief Функция разности многочленов по коэффициентам
	 *
	 * @param first  уменьшаемое
	 * @param second вычитаемое
	 * @param result разность
	 *
	 */
	static __ANTS_INLINE__ void subtract(const int32_t * first, const int32_t * second, int32_t * result) noexcept {
		/**
		 * Вычитаем коэффициенты
		 */
		for(size_t i = 0; i < N; i++)
			// Разность коэффициентов
			result[i] = (first[i] - second[i]);
	}

	/**
	 * @brief Параметры наборов стандарта (раздел 4 FIPS 204)
	 *
	 */
	struct Params {
		// Число строк матрицы
		uint8_t rows = 0;
		// Число столбцов матрицы
		uint8_t columns = 0;
		// Граница коэффициентов секрета η
		uint8_t eta = 0;
		// Число единиц вызова τ
		uint8_t tau = 0;
		// Порог отклонения β = τ · η
		uint16_t beta = 0;
		// Граница маски γ1
		uint32_t gamma1 = 0;
		// Граница младших частей γ2
		uint32_t gamma2 = 0;
		// Верхний вес подсказки ω
		uint8_t omega = 0;
		// Размер зерна вызова c~ в байтах (λ/4)
		uint8_t challenge = 0;
	};

	/**
	 * @brief Функция получения параметров набора
	 *
	 * @param set набор параметров
	 * @return    параметры набора, нули у несуществующего набора
	 *
	 */
	static constexpr Params params(const sign::Mldsa::set_t set) noexcept {
		/**
		 * Определяем набор параметров
		 */
		switch(set){
			// Параметры ML-DSA-44 из раздела 4 FIPS 204
			case sign::Mldsa::set_t::DSA44: return {4, 4, 2, 39, 78, (1u << 17), ((Q - 1) / 88), 80, 32};
			// Параметры ML-DSA-65 из раздела 4 FIPS 204
			case sign::Mldsa::set_t::DSA65: return {6, 5, 4, 49, 196, (1u << 19), ((Q - 1) / 32), 55, 48};
			// Параметры ML-DSA-87 из раздела 4 FIPS 204
			case sign::Mldsa::set_t::DSA87: return {8, 7, 2, 60, 120, (1u << 19), ((Q - 1) / 32), 75, 64};
			// Несуществующий набор выдаёт нулевые параметры
			default: return {0, 0, 0, 0, 0, 0, 0, 0, 0};
		}
	}

	/**
	 * Поглощение и выжимание словами нужно лишь параллельному ядру губок Keccak
	 */
	#if defined(__ANTS_KECCAK_X4__)
		/**
		 * @brief Функция чтения 64-разрядного слова байтами от младшего
		 *
		 * @param data место, из которого читаются байты слова
		 * @return     слово из восьми байтов
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
	#endif
	
	/**
	 * Опрос готовности параллельного ядра Keccak-x4
	 */
	#if defined(__ANTS_KECCAK_X4__)
		/**
		 * @brief Функция проверки готовности параллельного ядра губок
		 *
		 * @return признак готовности ядра четырёх состояний
		 *
		 * @note Ядро несёт векторные команды: на ARM64 они входят в архитектуру, на x86-64
		 *       спрашивается AVX2 у машины на исполнении
		 *
		 */
		static __ANTS_INLINE__ bool sponges4() noexcept {
			/**
			 * Признак AVX2 опрашиваем только на x86-64, где команды есть
			 */
			#if defined(__x86_64__)
				// Выводим признак команд AVX2 машины
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
	 * Параллельный разворот зёрен губками Keccak-x4
	 */
	#if defined(__ANTS_KECCAK_X4__)
		/**
		 * @brief Функция параллельной выборки четырёх многочленов матрицы в области NTT
		 *
		 * @details Четыре губки SHAKE128 переставляются разом параллельным ядром: каждая губка
		 *          поглощает зерно с парой индексов и выжимает блоки по 168 байтов, пока каждая
		 *          не наберёт 256 коэффициентов - закончившие раньше выжимают лишние блоки впустую,
		 *          чтобы перестановки шли общие (та же дисциплина, что у выборки матрицы ML-KEM).
		 *          Перестановка к следующему блоку выполняется лишь когда блок понадобился:
		 *          после последней выжимки губки лишней перестановки нет.
		 *
		 * @param rho     зерно матрицы ρ
		 * @param indices пары индексов четырёх губок: ρ ‖ столбец ‖ строка
		 * @param outs    места, в которые помещаются четыре многочлена
		 *
		 */
		static void expandA4(const uint8_t * rho, const uint8_t indices[4][2], int32_t * const outs[4]) noexcept {
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
				for(size_t i = 0; i < 4; i++)
					// Складываем очередное слово зерна
					states[k][i] ^= wordLoad(rho + (i * 8));
				// Складываем пару индексов матрицы
				states[k][4] ^= (indices[k][0] | (static_cast <uint64_t> (indices[k][1]) << 8));
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
			// Перестановка четырёх состояний
			digest::kernel::keccak4(states);
			// Число набранных коэффициентов каждой губки
			size_t counts[4] = {0, 0, 0, 0};
			// Блоки выжимания
			uint8_t blocks[4][168];
			// Признак первой выжимки: состояние уже переставлено после поглощения
			bool initial = true;
			/**
			 * Выжимаем блоки и разбираем тройки, пока какая-то губка не набрала многочлен
			 */
			while((counts[0] < N) || (counts[1] < N) || (counts[2] < N) || (counts[3] < N)){
				// Перестановка к следующему блоку выполняется лишь когда блок понадобился: после последней выжимки губки лишней перестановки нет
				if(!initial)
					// Перестановка четырёх состояний
					digest::kernel::keccak4(states);
				// Снимаем признак первой выжимки
				initial = false;
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
				/**
				 * Разбираем тройки байтов блока каждой губкой
				 */
				for(size_t k = 0; k < 4; k++){
					/**
					 * Перебираем тройки блока
					 */
					for(size_t i = 0; (i < sizeof(blocks[k])) && (counts[k] < N); i += 3){
						// Коэффициент из трёх байтов, 23 разряда без старшего разряда третьего байта
						const uint32_t value = ((static_cast <uint32_t> (blocks[k][i])) | (static_cast <uint32_t> (blocks[k][i + 1]) << 8) | ((static_cast <uint32_t> (blocks[k][i + 2]) & 0x7F) << 16));
						// Коэффициент меньше модуля принимается в многочлен
						if(value < Q)
							// Записываем коэффициент
							outs[k][counts[k]++] = static_cast <int32_t> (value);
					}
				}
			}
			// Затирание состояний
			sys::wipe(states, sizeof(states));
			// Затирание блоков
			sys::wipe(blocks, sizeof(blocks));
		}
	#endif
	/**
	 * @brief Функция отклоняющей выборки многочлена матрицы в области NTT
	 *
	 * @param rho    зерно матрицы ρ
	 * @param row    строка матрицы
	 * @param column столбец матрицы
	 * @param poly   многочлен в области NTT
	 *
	 */
	static void expandA(const uint8_t * rho, const uint8_t row, const uint8_t column, int32_t * poly) noexcept {
		// Поток SHAKE128 над ρ ‖ столбец ‖ строка
		digest::keccak_t xof(digest::sha3_t::SHAKE128);
		// Подаём зерно матрицы в поток
		xof.update(view_t(rho, 32));
		// Индексы многочлена: столбец, затем строка
		const uint8_t indices[2] = {column, row};
		// Подаём индексы в поток
		xof.update(view_t(indices, sizeof(indices)));
		// Число набранных коэффициентов
		size_t count = 0;
		// Поток выжимается блоками по 168 байтов (56 троек): тройки не рвутся по краям
		uint8_t block[168];
		/**
		 * Выбираем блоки потока до заполнения многочлена
		 */
		while(count < N){
			// Выжимаем очередной блок
			if(!xof.squeeze(block, sizeof(block))){
				// Отказ выжимания обнуляет счёт и обрывает выборку
				count = 0;
				// Выходим из перебора при отказе потока
				break;
			}
			/**
			 * Разбираем тройки байтов: старший разряд третьего байта обнуляется, коэффициент берётся, пока меньше q
			 */
			for(size_t i = 0; (i < sizeof(block)) && (count < N); i += 3){
				// Коэффициент из трёх байтов младшим байтом вперёд, 23 разряда
				const uint32_t value = ((static_cast <uint32_t> (block[i])) | (static_cast <uint32_t> (block[i + 1]) << 8) | ((static_cast <uint32_t> (block[i + 2]) & 0x7F) << 16));
				// Коэффициент из 23 разрядов без отклонения, если меньше модуля
				if(value < Q)
					// Коэффициент меньше модуля принимается в многочлен
					poly[count++] = static_cast <int32_t> (value);
			}
		}
		// Затираем рабочий блок потока
		sys::wipe(block, sizeof(block));
		// Счёт набранных коэффициентов не выводится наружу
		(void) count;
	}
	/**
	 * @brief Функция выборки матрицы целиком: четыре губки параллельным ядром, хвост по одной
	 *
	 * @param rho     зерно матрицы ρ
	 * @param rows    число строк матрицы k
	 * @param columns число столбцов матрицы l
	 * @param stride  шаг строки приёмника в многочленах: у плоского буфера l, у массива полной ширины - наибольшая размерность
	 * @param matrix  место, в которое помещаются многочлены матрицы строками подряд
	 *
	 */
	static void matrixExpand(const uint8_t * rho, const size_t rows, const size_t columns, const size_t stride, int32_t * const matrix) noexcept {
		/**
		 * Параллельный разворот матрицы губками Keccak-x4
		 */
		#if defined(__ANTS_KECCAK_X4__)
			// Если параллельное ядро губок готово
			if(sponges4()){
				// Число многочленов матрицы
				const size_t total = rows * columns;
				// Линейная позиция многочлена: строка за строкой
				size_t index = 0;
				/**
				 * Перебираем четвёрки многочленов плашмя: порядок многочленов тот же, что у перебора строками, но хвост одиночных губок короче
				 */
				for(; (index + 4) <= total; index += 4){
					// Пары индексов губок: зерно || столбец || строка
					uint8_t indices[4][2];
					// Места четырёх многочленов
					int32_t * outs[4];
					/**
					 * Заполняем пары индексов и места
					 */
					for(size_t j = 0; j < 4; j++){
						// Линейная позиция многочлена четвёрки
						const size_t linear = index + j;
						// Первый индекс пары - столбец
						indices[j][0] = static_cast <uint8_t> (linear % columns);
						// Второй индекс пары - строка
						indices[j][1] = static_cast <uint8_t> (linear / columns);
						// Место многочлена в приёмнике с шагом строки stride
						outs[j] = (matrix + (((linear / columns) * stride) + (linear % columns)) * N);
					}
					// Выбираем четыре многочлена разом
					expandA4(rho, indices, outs);
				}
				/**
				 * Перебираем хвостовые многочлены
				 */
				for(; index < total; index++)
					// Выбираем многочлен одной губкой
					expandA(rho, static_cast <uint8_t> (index / columns), static_cast <uint8_t> (index % columns), matrix + (((index / columns) * stride) + (index % columns)) * N);
				// Матрица развёрнута губками четвёрками
				return;
			}
		#endif
		/**
		 * Перебираем строки матрицы
		 */
		for(size_t row = 0; row < rows; row++)
			/**
			 * Перебираем столбцы матрицы
			 */
			for(size_t column = 0; column < columns; column++)
				// Многочлен матрицы из зерна ρ
				expandA(rho, static_cast <uint8_t> (row), static_cast <uint8_t> (column), matrix + (((row * stride) + column) * N));
	}
	/**
	 * @brief Функция выборки многочлена секрета с коэффициентами из [−η, η]
	 *
	 * @param rhoprime зерно ρ′
	 * @param nonce    номер многочлена в векторе
	 * @param eta      граница коэффициентов η
	 * @param poly     многочлен секрета
	 *
	 */
	static void expandS(const uint8_t * rhoprime, const uint16_t nonce, const uint8_t eta, int32_t * poly) noexcept {
		// Поток SHAKE256 над ρ′ ‖ номер многочлена младшим байтом вперёд
		digest::keccak_t xof(digest::sha3_t::SHAKE256);
		// Подаём зерно секрета в поток
		xof.update(view_t(rhoprime, 64));
		// Номер многочлена двумя байтами младшим вперёд
		const uint8_t suffix[2] = {static_cast <uint8_t> (nonce & 0xFF), static_cast <uint8_t> (nonce >> 8)};
		// Подаём номер в поток
		xof.update(view_t(suffix, sizeof(suffix)));
		// Число набранных коэффициентов
		size_t count = 0;
		// Поток выжимается блоками по 136 байтов (68 полубайтовых пар при η = 2 и 34 при η = 4)
		uint8_t block[136];
		/**
		 * Выбираем блоки потока до заполнения многочлена
		 */
		while(count < N){
			// Отказ выжимания обнуляет счёт и обрывает выборку
			if(!xof.squeeze(block, sizeof(block))){
				// Выходим из перебора при отказе потока
				count = 0;
				break;
			}
			/**
			 * Разбираем полубайты без ветвления по данным: коэффициент пишется всегда, счётчик растёт лишь у принятых полубайтов; при η = 2 коэффициент с отклонением остатка от деления на пять, при η = 4 - с отклонением от четырёх
			 */
			if(eta == 2){
				/**
				 * Перебираем байты блока
				 */
				for(size_t i = 0; (i < sizeof(block)) && (count < N); i++){
					/**
					 * Перебираем полубайты байта
					 */
					for(size_t half = 0; (half < 2) && (count < N); half++){
						// Полубайт: младший, затем старший
						const uint32_t value = ((half == 0) ? (block[i] & 0x0F) : (block[i] >> 4));
						// Признак принятия полубайта: полубайт 15 отклоняется
						const size_t accept = (value < 15) ? 1 : 0;
						// Остаток от деления полубайта на пять - магическим умножением
						const uint32_t remainder = (value - (5 * ((value * 205) >> 10)));
						// Коэффициент из [−2, 2] пишется на текущее место
						poly[count] = (2 - static_cast <int32_t> (remainder));
						// Счётчик растёт лишь у принятого полубайта
						count += accept;
					}
				}
			/**
			 * Разбираем блоки при границе η = 4
			 */
			} else {
				/**
				 * Перебираем байты блока
				 */
				for(size_t i = 0; (i < sizeof(block)) && (count < N); i++){
					/**
					 * Перебираем полубайты байта
					 */
					for(size_t half = 0; (half < 2) && (count < N); half++){
						// Полубайт: младший, затем старший
						const uint32_t value = ((half == 0) ? (block[i] & 0x0F) : (block[i] >> 4));
						// Признак принятия полубайта: полубайты от девяти отклоняются
						const size_t accept = (value < 9) ? 1 : 0;
						// Коэффициент из [−4, 4] пишется на текущее место
						poly[count] = (4 - static_cast <int32_t> (value));
						// Счётчик растёт лишь у принятого полубайта
						count += accept;
					}
				}
			}
		}
		// Затираем рабочий блок потока
		sys::wipe(block, sizeof(block));
	}

	/**
	 * Параллельная выборка секретов доступна при параллельном ядре губок Keccak
	 */
	#if defined(__ANTS_KECCAK_X4__)
		/**
		 * @brief Функция параллельной выборки четырёх многочленов секрета
		 *
		 * @details Четыре губки SHAKE256 переставляются разом параллельным ядром: каждая губка
		 *          поглощает зерно ρ′ с номером многочлена и выжимает блоки по 136 байтов,
		 *          пока каждая не наберёт 256 коэффициентов - закончившие раньше выжимают лишние
		 *          блоки впустую, чтобы перестановки шли общие; перестановка к следующему
		 *          блоку выполняется лишь когда блок понадобился (та же дисциплина, что
		 *          у выборки матрицы)
		 *
		 * @param rhoprime зерно ρ′
		 * @param nonces   номера четырёх многочленов в векторе
		 * @param eta      граница коэффициентов η
		 * @param outs     места, в которые помещаются четыре многочлена
		 *
		 */
		static void expandS4(const uint8_t * rhoprime, const uint16_t nonces[4], const uint8_t eta, int32_t * const outs[4]) noexcept {
			// Состояния четырёх губок
			uint64_t states[4][25];
			// Обнуляем состояния
			::memset(states, 0, sizeof(states));
			/**
			 * Поглощаем зерно и номер каждой губкой: слова 0…7 - зерно, слово 8 - номер двумя байтами
			 */
			for(size_t k = 0; k < 4; k++){
				/**
				 * Перебираем слова зерна
				 */
				for(size_t i = 0; i < 8; i++)
					// Складываем очередное слово зерна
					states[k][i] ^= wordLoad(rhoprime + (i * 8));
				// Складываем номер многочлена младшим байтом вперёд
				states[k][8] ^= (static_cast <uint64_t> (nonces[k] & 0xFF) | (static_cast <uint64_t> (nonces[k] >> 8) << 8));
			}
			/**
			 * Дополняем домен функций переменного выхода: байт 0x1F на смещении шестьдесят шесть и разряд 0x80 в последнем байте скорости 136
			 */
			for(size_t k = 0; k < 4; k++){
				// Байт начала дополнения
				states[k][66 / 8] ^= (0x1FULL << ((66 % 8) * 8));
				// Разряд окончания дополнения
				states[k][(136 - 1) / 8] ^= (0x80ULL << (((136 - 1) % 8) * 8));
			}
			// Перестановка четырёх состояний
			digest::kernel::keccak4(states);
			// Число набранных коэффициентов каждой губки
			size_t counts[4] = {0, 0, 0, 0};
			// Блоки выжимания
			uint8_t blocks[4][136];
			// Признак первой выжимки: состояние уже переставлено после поглощения
			bool initial = true;
			/**
			 * Выжимаем блоки и разбираем полубайты, пока какая-то губка не набрала многочлен
			 */
			while((counts[0] < N) || (counts[1] < N) || (counts[2] < N) || (counts[3] < N)){
				// Перестановка к следующему блоку выполняется лишь когда блок понадобился: после последней выжимки губки лишней перестановки нет
				if(!initial)
					// Перестановка четырёх состояний
					digest::kernel::keccak4(states);
				// Снимаем признак первой выжимки
				initial = false;
				/**
				 * Выжимаем блок каждой губкой
				 */
				for(size_t k = 0; k < 4; k++)
					/**
					 * Перебираем слова блока
					 */
					for(size_t i = 0; i < (136 / 8); i++)
						// Записываем очередное слово блока
						wordStore(states[k][i], blocks[k] + (i * 8));
				/**
				 * Разбираем полубайты блока каждой губкой без ветвления по данным: коэффициент пишется всегда, счётчик растёт лишь у принятых полубайтов
				 */
				for(size_t k = 0; k < 4; k++){
					/**
					 * Разбираем полубайты при границе η = 2
					 */
					if(eta == 2){
						/**
						 * Перебираем байты блока
						 */
						for(size_t i = 0; (i < sizeof(blocks[k])) && (counts[k] < N); i++){
							/**
							 * Перебираем полубайты байта
							 */
							for(size_t half = 0; (half < 2) && (counts[k] < N); half++){
								// Полубайт: младший, затем старший
								const uint32_t value = ((half == 0) ? (blocks[k][i] & 0x0F) : (blocks[k][i] >> 4));
								// Признак принятия полубайта: полубайт 15 отклоняется
								const size_t accept = (value < 15) ? 1 : 0;
								// Остаток от деления полубайта на пять - магическим умножением
								const uint32_t remainder = (value - (5 * ((value * 205) >> 10)));
								// Коэффициент из [−2, 2] пишется на текущее место
								outs[k][counts[k]] = (2 - static_cast <int32_t> (remainder));
								// Счётчик растёт лишь у принятого полубайта
								counts[k] += accept;
							}
						}
					/**
					 * Разбираем блоки при границе η = 4
					 */
					} else {
						/**
						 * Перебираем байты блока
						 */
						for(size_t i = 0; (i < sizeof(blocks[k])) && (counts[k] < N); i++){
							/**
							 * Перебираем полубайты байта
							 */
							for(size_t half = 0; (half < 2) && (counts[k] < N); half++){
								// Полубайт: младший, затем старший
								const uint32_t value = ((half == 0) ? (blocks[k][i] & 0x0F) : (blocks[k][i] >> 4));
								// Признак принятия полубайта: полубайты от девяти отклоняются
								const size_t accept = (value < 9) ? 1 : 0;
								// Коэффициент из [−4, 4] пишется на текущее место
								outs[k][counts[k]] = (4 - static_cast <int32_t> (value));
								// Счётчик растёт лишь у принятого полубайта
								counts[k] += accept;
							}
						}
					}
				}
			}
			// Затирание состояний
			sys::wipe(states, sizeof(states));
			// Затирание блоков
			sys::wipe(blocks, sizeof(blocks));
		}
	#endif

	/**
	 * @brief Функция выборки векторов секрета s1 и s2 из зерна ρ′
	 *
	 * @details При готовом параллельном ядре губки многочлены выбираются плашмя по четыре,
	 *          неполная четвёрка доезжает запасным буфером; иначе многочлены выбираются
	 *          порознь по одному
	 *
	 * @param rhoprime зерно ρ′
	 * @param lengthS1 длина вектора s1
	 * @param lengthS2 длина вектора s2
	 * @param eta      граница коэффициентов η
	 * @param s1       вектор секрета s1
	 * @param s2       вектор секрета s2
	 *
	 */
	static void expandSecrets(const uint8_t * rhoprime, const size_t lengthS1, const size_t lengthS2, const uint8_t eta, int32_t s1[7][N], int32_t s2[8][N]) noexcept {
		/**
		 * Если параллельное ядро губок готово, секреты выбираются четвёрками губок
		 */
		#if defined(__ANTS_KECCAK_X4__)
			// Если параллельное ядро губок готово
			if(sponges4()){
				// Места всех многочленов секрета: сначала s1, затем s2
				int32_t * outs[15];
				// Число многочленов секрета
				const size_t count = lengthS1 + lengthS2;
				/**
				 * Перебираем многочлены s1
				 */
				for(size_t i = 0; i < lengthS1; i++)
					// Место многочлена s1
					outs[i] = s1[i];
				/**
				 * Перебираем многочлены s2
				 */
				for(size_t i = 0; i < lengthS2; i++)
					// Место многочлена s2
					outs[lengthS1 + i] = s2[i];
				// Запасной буфер неполной четвёрки
				int32_t idle[N];
				/**
				 * Перебираем четвёрки многочленов плашмя
				 */
				for(size_t index = 0; index < count; index += 4){
					// Номера четырёх губок
					uint16_t nonces[4];
					// Места четырёх многочленов
					int32_t * group[4];
					/**
					 * Заполняем номера и места: губки за пределом реальных многочленов пишут в запасной буфер
					 */
					for(size_t j = 0; j < 4; j++){
						// Номер губки: реальный или невозможный у холостой
						nonces[j] = static_cast <uint16_t> (((index + j) < count) ? (index + j) : 0xFFFF);
						// Место многочлена или запасной буфер
						group[j] = (((index + j) < count) ? outs[index + j] : idle);
					}
					// Выбираем четыре многочлена разом
					expandS4(rhoprime, nonces, eta, group);
				}
				// Затираем запасной буфер
				sys::wipe(idle, sizeof(idle));
				// Секреты выбраны губками четвёрками
				return;
			}
		#endif
		/**
		 * Перебираем многочлены s1
		 */
		for(size_t i = 0; i < lengthS1; i++)
			// Многочлен секрета s1 из зерна ρ′
			expandS(rhoprime, static_cast <uint16_t> (i), eta, s1[i]);
		/**
		 * Перебираем многочлены s2
		 */
		for(size_t i = 0; i < lengthS2; i++)
			// Многочлен секрета s2 из зерна ρ′
			expandS(rhoprime, static_cast <uint16_t> (lengthS1 + i), eta, s2[i]);
	}
	/**
	 * @brief Функция выборки маски подписи с коэффициентами из (−γ1, γ1]
	 *
	 * @param rhodbl зерно ρ″
	 * @param nonce  номер многочлена: κ · l + позиция
	 * @param gamma1 граница маски γ1
	 * @param poly   многочлен маски
	 *
	 */
	static void expandMask(const uint8_t * rhodbl, const uint16_t nonce, const uint32_t gamma1, int32_t * poly) noexcept {
		// Поток SHAKE256 над ρ″ ‖ номер многочлена младшим байтом вперёд
		digest::keccak_t xof(digest::sha3_t::SHAKE256);
		// Подаём зерно маски в поток
		xof.update(view_t(rhodbl, 64));
		// Номер многочлена двумя байтами младшим вперёд
		const uint8_t suffix[2] = {static_cast <uint8_t> (nonce & 0xFF), static_cast <uint8_t> (nonce >> 8)};
		// Подаём номер в поток
		xof.update(view_t(suffix, sizeof(suffix)));
		// Число набранных коэффициентов
		size_t count = 0;
		// Если граница маски γ1 = 2^17
		if(gamma1 == (1u << 17)){
			// Поток выжимается блоками по 144 байта (16 девяток по четыре коэффициента на 18 разрядов)
			uint8_t block[144];
			/**
			 * Выбираем блоки потока до заполнения многочлена
			 */
			while(count < N){
				// Отказ выжимания обнуляет счёт и обрывает выборку
				if(!xof.squeeze(block, sizeof(block))){
					// Выходим из перебора при отказе потока
					count = 0;
					break;
				}
				/**
				 * Перебираем девятки байтов блока
				 */
				for(size_t i = 0; (i < sizeof(block)) && (count < N); i += 9){
					// Девять байтов дают четыре коэффициента по 18 разрядов подряд
					const uint64_t window = ((static_cast <uint64_t> (block[i])) | (static_cast <uint64_t> (block[i + 1]) << 8) | (static_cast <uint64_t> (block[i + 2]) << 16) | (static_cast <uint64_t> (block[i + 3]) << 24) | (static_cast <uint64_t> (block[i + 4]) << 32) | (static_cast <uint64_t> (block[i + 5]) << 40) | (static_cast <uint64_t> (block[i + 6]) << 48) | (static_cast <uint64_t> (block[i + 7]) << 56));
					// Первый коэффициент из младших 18 разрядов окна
					poly[count++] = static_cast <int32_t> (gamma1 - (static_cast <uint32_t> (window & 0x3FFFF)));
					// Второй коэффициент из следующих 18 разрядов
					poly[count++] = static_cast <int32_t> (gamma1 - (static_cast <uint32_t> ((window >> 18) & 0x3FFFF)));
					// Третий коэффициент из следующих 18 разрядов
					poly[count++] = static_cast <int32_t> (gamma1 - (static_cast <uint32_t> ((window >> 36) & 0x3FFFF)));
					// Четвёртый коэффициент добирает девятый байт
					poly[count++] = static_cast <int32_t> (gamma1 - (static_cast <uint32_t> (((window >> 54) | (static_cast <uint64_t> (block[i + 8]) << 10)) & 0x3FFFF)));
				}
			}
			// Затираем рабочий блок потока
			sys::wipe(block, sizeof(block));
		} else {
			// Поток выжимается блоками по 160 байтов (64 пятёрки на две по 20 разрядов)
			uint8_t block[160];
			/**
			 * Выбираем блоки потока до заполнения многочлена
			 */
			while(count < N){
				// Отказ выжимания обнуляет счёт и обрывает выборку
				if(!xof.squeeze(block, sizeof(block))){
					// Выходим из перебора при отказе потока
					count = 0;
					break;
				}
				/**
				 * Перебираем пятёрки байтов блока
				 */
				for(size_t i = 0; (i < sizeof(block)) && (count + 1 < N); i += 5){
					// Пять байтов дают два коэффициента по 20 разрядов
					const uint64_t window = ((static_cast <uint64_t> (block[i])) | (static_cast <uint64_t> (block[i + 1]) << 8) | (static_cast <uint64_t> (block[i + 2]) << 16) | (static_cast <uint64_t> (block[i + 3]) << 24) | (static_cast <uint64_t> (block[i + 4]) << 32));
					// Первый коэффициент из младших 20 разрядов окна
					poly[count++] = static_cast <int32_t> (gamma1 - (static_cast <uint32_t> (window & 0xFFFFF)));
					// Второй коэффициент из старших 20 разрядов
					poly[count++] = static_cast <int32_t> (gamma1 - (static_cast <uint32_t> ((window >> 20) & 0xFFFFF)));
				}
			}
			// Затираем рабочий блок потока
			sys::wipe(block, sizeof(block));
		}
		// Счёт набранных коэффициентов не выводится наружу
		(void) count;
	}
	/**
	 * @brief Функция выборки вызова из шара с τ единицами
	 *
	 * @param seed зерно вызова c~
	 * @param size размер зерна в байтах (λ/4)
	 * @param tau  число единиц вызова τ
	 * @param poly многочлен вызова с τ коэффициентами ±1
	 *
	 */
	static void sampleInBall(const uint8_t * seed, const size_t size, const uint8_t tau, int32_t * poly) noexcept {
		// Поток SHAKE256 над зерном вызова
		digest::keccak_t xof(digest::sha3_t::SHAKE256);
		// Подаём зерно вызова в поток
		xof.update(view_t(seed, size));
		// Знаки первых восьми байтов потока
		uint8_t signs[8];
		// Выжимаем восемь байтов знаков
		(void) xof.squeeze(signs, sizeof(signs));
		// Накопитель разрядов знаков
		uint64_t bits = 0;
		/**
		 * Собираем знаки восьми байтов в слово
		 */
		for(size_t i = 0; i < sizeof(signs); i++)
			// Разряды знаков собираются в слово младшим байтом вперёд
			bits |= (static_cast <uint64_t> (signs[i]) << (8 * i));
		/**
		 * Обнуляем многочлен вызова
		 */
		for(size_t i = 0; i < N; i++)
			// Коэффициент вызова обнуляется
			poly[i] = 0;
		// Отсчёт позиций единиц от N − τ к старшим (алгоритм 29 FIPS 204)
		size_t scan = (N - tau);
		// Буфер дочитки потока
		uint8_t buffer[32];
		// Позиция чтения буфера: сразу за границей, буфер пуст
		size_t used = sizeof(buffer);
		/**
		 * Выбираем позиции единиц вызова
		 */
		while(scan < N){
			// Дочитываем поток порциями
			if(used == sizeof(buffer)){
				// Выжимаем очередную порцию потока
				(void) xof.squeeze(buffer, sizeof(buffer));
				// Чтение буфера с начала
				used = 0;
			}
			// Позиция из очередного байта, отклоняется большая текущей
			// Позиция из очередного байта потока
			const size_t drawn = buffer[used++];
			// Если позиция не выше текущей, она принимается
			if(drawn <= scan){
				// Переносим прежнее значение и пишем единицу со знаком
				poly[scan] = poly[drawn];
				// Единица со знаком очередного разряда встаёт на выбранную позицию
				poly[drawn] = (((bits & 1) != 0) ? -1 : 1);
				// Снимаем использованный разряд знака
				bits >>= 1;
				// Переходим к следующей позиции
				scan++;
			}
		}
		// Затираем рабочие значения выбора
		sys::wipe(signs, sizeof(signs));
		// Затираем буфер дочитки
		sys::wipe(buffer, sizeof(buffer));
	}
	/**
	 * @brief Функция разложения коэффициента на старшую и младшую части
	 *
	 * @param value  коэффициент в [0, q)
	 * @param gamma2 граница младшей части γ2
	 * @param low    младшая часть из (−γ2, γ2]
	 * @return       старшая часть из [0, (q − 1)/(2γ2) − 1]
	 *
	 */
	static int32_t decompose(const int32_t value, const uint32_t gamma2, int32_t & low) noexcept {
		// Старшая часть округлением к ближайшему кратному 2γ2
		int32_t high = ((value + 127) >> 7);
		// Если граница младшей части γ2 = (q − 1)/32
		if(gamma2 == ((Q - 1) / 32)){
			// (q − 1)/32: точное умножение на 2^10/γ2 с округлением, старшая часть в [0, 15]
			high = (((high * 1025) + (1 << 21)) >> 22);
			// Обрезка до четырёх разрядов
			high &= 15;
		} else {
			// (q − 1)/88: точное умножение на 2^12/γ2 с округлением, старшая часть в [0, 43] с обращением 44 в 0
			high = (((high * 11275) + (1 << 23)) >> 24);
			// Обращение 44 в 0 без ветвления
			high ^= (((43 - high) >> 31) & high);
		}
		// Младшая часть в (−γ2, γ2] с обращением края модуля
		low = (value - (high * static_cast <int32_t> (2 * gamma2)));
		// Край модуля обращается без ветвления
		low -= ((((static_cast <int32_t> (Q) - 1) / 2 - low) >> 31) & static_cast <int32_t> (Q));
		// Выводим старшую часть
		return high;
	}
	/**
	 * @brief Функция округления коэффициента на два разряда: productOdd = (t + 2^12) >> 13, productEven = t − productOdd · 2^13
	 *
	 * @param value коэффициент в [0, q)
	 * @param low   младшая часть productEven из (−2^12, 2^12]
	 * @return      старшая часть productOdd из [0, 2^10)
	 *
	 */
	static __ANTS_INLINE__ int32_t power2round(const int32_t value, int32_t & low) noexcept {
		// Старшая часть округлением вверх к 2^13
		const int32_t high = ((value + ((1 << 12) - 1)) >> 13);
		// Младшая часть вычитанием старшей
		low = (value - (high << 13));
		// Выводим старшую часть
		return high;
	}
	/**
	 * @brief Функция применения подсказки к коэффициенту
	 *
	 * @param value коэффициент w′ в [0, q)
	 * @param hint  бит подсказки
	 * @return      скорректированная старшая часть из [0, (q − 1)/(2γ2) − 1]
	 *
	 */
	static __ANTS_INLINE__ int32_t useHint(const int32_t value, const uint32_t hint, const uint32_t gamma2) noexcept {
		// Младшая часть разложения
		int32_t low = 0;
		// Разложение коэффициента на части
		const int32_t high = decompose(value, gamma2, low);
		// Если бит подсказки нулевой
		if(hint == 0)
			// Без подсказки старшая часть не меняется
			return high;
		// Если граница младшей части γ2 = (q − 1)/32
		if(gamma2 == ((Q - 1) / 32))
			// Подсказка сдвигает старшую часть по знаку младшей, кольцо из 16
			return ((low > 0) ? ((high + 1) & 15) : ((high - 1) & 15));
		// Подсказка сдвигает старшую часть по знаку младшей, кольцо из 44
		return ((low > 0) ? ((high == 43) ? 0 : (high + 1)) : ((high == 0) ? 43 : (high - 1)));
	}
	/**
	 * @brief Функция записи многочлена разрядностью bits на коэффициент
	 *
	 * @param poly   многочлен со значениями из [0, 2^bits)
	 * @param bits   разрядность коэффициента
	 * @param result место записи
	 *
	 */
	static __ANTS_INLINE__ void bitpack(const uint32_t * poly, const size_t bits, uint8_t * result) noexcept {
		// Накопитель разрядов
		uint64_t window = 0;
		// Число занятых разрядов окна
		size_t used = 0;
		/**
		 * Вдвигаем коэффициенты в окно
		 */
		for(size_t i = 0; i < N; i++){
			// Коэффициент вдвигается в окно на свободное место
			window |= (static_cast <uint64_t> (poly[i]) << used);
			// Считаем занятые разряды
			used += bits;
			/**
			 * Выдаём полные байты окна
			 */
			while(used >= 8){
				// Младший байт окна уходит в запись
				*result++ = static_cast <uint8_t> (window);
				// Окно сдвигается на выданный байт
				window >>= 8;
				// Считаем оставшиеся разряды
				used -= 8;
			}
		}
	}
	/**
	 * @brief Функция чтения многочлена разрядностью bits на коэффициент
	 *
	 * @param data запись
	 * @param bits разрядность коэффициента
	 * @param poly многочлен со значениями из [0, 2^bits)
	 *
	 */
	static __ANTS_INLINE__ void bitunpack(const uint8_t * data, const size_t bits, uint32_t * poly) noexcept {
		// Накопитель разрядов окна
		uint64_t window = 0;
		// Число разрядов в окне
		size_t used = 0;
		/**
		 * Перебираем коэффициенты
		 */
		for(size_t i = 0; i < N; i++){
			/**
			 * Добираем байты записи в окно
			 */
			while(used < bits){
				// Байт записи вдвигается в окно
				window |= (static_cast <uint64_t> (*data++) << used);
				// Считаем набранные разряды
				used += 8;
			}
			// Коэффициент снимается маской разрядности
			poly[i] = static_cast <uint32_t> (window & ((static_cast <uint64_t> (1) << bits) - 1));
			// Окно сдвигается на снятые разряды
			window >>= bits;
			// Считаем оставшиеся разряды
			used -= bits;
		}
	}
	/**
	 * @brief Функция записи многочлена productOdd разрядностью 10 на коэффициент
	 *
	 * @param poly   многочлен productOdd
	 * @param result место записи, 320 байтов
	 *
	 */
	static __ANTS_INLINE__ void packT1(const int32_t * poly, uint8_t * result) noexcept {
		// Рабочий многочлен беззнаковых коэффициентов
		uint32_t work[N];
		/**
		 * Переводим коэффициенты в беззнаковую форму
		 */
		for(size_t i = 0; i < N; i++)
			// Коэффициент в беззнаковую форму
			work[i] = static_cast <uint32_t> (poly[i]);
		// Записываем по 10 разрядов на коэффициент
		bitpack(work, 10, result);
		// Затираем рабочий многочлен
		sys::wipe(work, sizeof(work));
	}
	/**
	 * @brief Функция чтения многочлена productOdd разрядностью 10 на коэффициент
	 *
	 * @param data запись productOdd, 320 байтов
	 * @param poly многочлен productOdd
	 *
	 */
	static __ANTS_INLINE__ void unpackT1(const uint8_t * data, int32_t * poly) noexcept {
		// Рабочий многочлен беззнаковых коэффициентов
		uint32_t work[N];
		// Читаем по 10 разрядов на коэффициент
		bitunpack(data, 10, work);
		/**
		 * Переводим коэффициенты в знаковую форму
		 */
		for(size_t i = 0; i < N; i++)
			// Коэффициент в знаковую форму
			poly[i] = static_cast <int32_t> (work[i]);
		// Затираем рабочий многочлен
		sys::wipe(work, sizeof(work));
	}
	/**
	 * @brief Функция записи многочлена productEven разрядностью 13 на коэффициент
	 *
	 * @param poly   многочлен productEven с коэффициентами из (−2^12, 2^12]
	 * @param result место записи, 416 байтов
	 *
	 */
	static __ANTS_INLINE__ void packT0(const int32_t * poly, uint8_t * result) noexcept {
		// Рабочий многочлен беззнаковых коэффициентов
		uint32_t work[N];
		/**
		 * Переводим коэффициенты в беззнаковую форму
		 */
		for(size_t i = 0; i < N; i++)
			// Коэффициент из (−2^12, 2^12] в беззнаковую форму 2^12 − productEven
			work[i] = static_cast <uint32_t> ((1 << 12) - poly[i]);
		// Записываем по 13 разрядов на коэффициент
		bitpack(work, 13, result);
		// Затираем рабочий многочлен
		sys::wipe(work, sizeof(work));
	}
	/**
	 * @brief Функция чтения многочлена productEven разрядностью 13 на коэффициент
	 *
	 * @param data запись productEven, 416 байтов
	 * @param poly многочлен productEven
	 *
	 */
	static __ANTS_INLINE__ void unpackT0(const uint8_t * data, int32_t * poly) noexcept {
		// Рабочий многочлен беззнаковых коэффициентов
		uint32_t work[N];
		// Читаем по 13 разрядов на коэффициент
		bitunpack(data, 13, work);
		/**
		 * Переводим коэффициенты в знаковую форму
		 */
		for(size_t i = 0; i < N; i++)
			// Коэффициент обратно в (−2^12, 2^12]
			poly[i] = static_cast <int32_t> ((1 << 12) - work[i]);
		// Затираем рабочий многочлен
		sys::wipe(work, sizeof(work));
	}
	/**
	 * @brief Функция записи многочлена секрета разрядностью 3 либо 4 на коэффициент
	 *
	 * @param poly   многочлен секрета с коэффициентами из [−η, η]
	 * @param eta    граница коэффициентов η
	 * @param result место записи
	 *
	 */
	static __ANTS_INLINE__ void packS(const int32_t * poly, const uint8_t eta, uint8_t * result) noexcept {
		// Рабочий многочлен беззнаковых коэффициентов
		uint32_t work[N];
		/**
		 * Переводим коэффициенты в беззнаковую форму
		 */
		for(size_t i = 0; i < N; i++)
			// Коэффициент из [−η, η] в беззнаковую форму η − s
			work[i] = static_cast <uint32_t> (eta - poly[i]);
		// Записываем по 3 либо 4 разряда на коэффициент
		bitpack(work, ((eta == 2) ? 3 : 4), result);
		// Затираем рабочий многочлен
		sys::wipe(work, sizeof(work));
	}
	/**
	 * @brief Функция чтения многочлена секрета
	 *
	 * @param data запись секрета
	 * @param eta  граница коэффициентов η
	 * @param poly многочлен секрета
	 * @return     признак кода записи за границей 2η (гнилая запись ключа)
	 *
	 */
	static __ANTS_INLINE__ uint32_t unpackS(const uint8_t * data, const uint8_t eta, int32_t * poly) noexcept {
		// Признак гнилой записи: коды выше 2η из выборки стандарта не выходят
		uint32_t reject = 0;
		// Рабочий многочлен беззнаковых коэффициентов
		uint32_t work[N];
		// Читаем по 3 либо 4 разряда на коэффициент
		bitunpack(data, ((eta == 2) ? 3 : 4), work);
		/**
		 * Разбираем коды коэффициентов
		 */
		for(size_t i = 0; i < N; i++){
			// Код выше 2η отмечает гнилую запись
			reject |= static_cast <uint32_t> ((work[i] > (2u * eta)) ? 1 : 0);
			// Коэффициент обратно в [−η, η]
			poly[i] = static_cast <int32_t> (eta - work[i]);
		}
		// Затираем рабочий многочлен
		sys::wipe(work, sizeof(work));
		// Выводим признак гнилой записи
		return reject;
	}
	/**
	 * @brief Функция записи многочлена ответа z
	 *
	 * @param poly   многочлен ответа с коэффициентами из (−γ1, γ1]
	 * @param gamma1 граница маски γ1
	 * @param result место записи
	 *
	 */
	static __ANTS_INLINE__ void packZ(const int32_t * poly, const uint32_t gamma1, uint8_t * result) noexcept {
		// Рабочий многочлен беззнаковых коэффициентов
		uint32_t work[N];
		/**
		 * Переводим коэффициенты в беззнаковую форму
		 */
		for(size_t i = 0; i < N; i++)
			// Коэффициент из (−γ1, γ1] в беззнаковую форму γ1 − z
			work[i] = static_cast <uint32_t> (gamma1 - poly[i]);
		// Записываем по 18 либо 20 разрядов на коэффициент
		bitpack(work, ((gamma1 == (1u << 17)) ? 18 : 20), result);
		// Затираем рабочий многочлен
		sys::wipe(work, sizeof(work));
	}
	/**
	 * @brief Функция чтения многочлена ответа z
	 *
	 * @param data   запись ответа
	 * @param gamma1 граница маски γ1
	 * @param poly   многочлен ответа
	 *
	 */
	static __ANTS_INLINE__ void unpackZ(const uint8_t * data, const uint32_t gamma1, int32_t * poly) noexcept {
		// Рабочий многочлен беззнаковых коэффициентов
		uint32_t work[N];
		// Читаем по 18 либо 20 разрядов на коэффициент
		bitunpack(data, ((gamma1 == (1u << 17)) ? 18 : 20), work);
		/**
		 * Переводим коэффициенты в знаковую форму
		 */
		for(size_t i = 0; i < N; i++)
			// Коэффициент обратно в (−γ1, γ1]
			poly[i] = static_cast <int32_t> (gamma1 - work[i]);
		// Затираем рабочий многочлен
		sys::wipe(work, sizeof(work));
	}
	/**
	 * @brief Функция кодировки старших частей lowOdd для зерна вызова
	 *
	 * @param poly   многочлен старших частей
	 * @param gamma2 граница младших частей γ2
	 * @param result место записи
	 *
	 */
	static __ANTS_INLINE__ void encodeW1(const int32_t * poly, const uint32_t gamma2, uint8_t * result) noexcept {
		// Рабочий многочлен беззнаковых коэффициентов
		uint32_t work[N];
		/**
		 * Переводим коэффициенты в беззнаковую форму
		 */
		for(size_t i = 0; i < N; i++)
			// Старшая часть в беззнаковую форму
			work[i] = static_cast <uint32_t> (poly[i]);
		// Записываем по 4 либо 6 разрядов на коэффициент
		bitpack(work, ((gamma2 == ((Q - 1) / 32)) ? 4 : 6), result);
		// Затираем рабочий многочлен
		sys::wipe(work, sizeof(work));
	}
	/**
	 * @brief Функция проверки границы коэффициентов многочлена
	 *
	 * @param poly  многочлен со значениями со знаком
	 * @param bound граница модулей коэффициентов (превышение при равенстве)
	 * @return      ненольное значение, если модуль какого-то коэффициента не меньше границы
	 *
	 */
	static __ANTS_INLINE__ uint32_t overflow(const int32_t * poly, const int32_t bound) noexcept {
		// Накопитель признака превышения
		uint32_t result = 0;
		/**
		 * Перебираем коэффициенты
		 */
		for(size_t i = 0; i < N; i++){
			// Модуль коэффициента без ветвления
			const int32_t mask = (poly[i] >> 31);
			// Модуль коэффициента из маски знака
			const int32_t absolute = ((poly[i] ^ mask) - mask);
			// Превышение границы модулем без ветвления
			result |= static_cast <uint32_t> (((bound - 1) - absolute) >> 31);
		}
		// Выводим признак превышения
		return (result & 1);
	}
	/**
	 * @brief Функция сложения вектора многочленов матрицы с вектором в области NTT
	 *
	 * @param matrix  матрица A в области NTT: rows строк по columns многочленов
	 * @param vector  вектор y из columns многочленов в области NTT
	 * @param rows    строки матрицы
	 * @param columns столбцы матрицы
	 * @param result  вектор из rows многочленов в области NTT
	 *
	 */
	static __ANTS_INLINE__ void matrixVector(const int32_t * matrix, const int32_t * vector, const uint8_t rows, const uint8_t columns, int32_t * result) noexcept {
		/**
		 * Перебираем строки результата
		 */
		for(size_t row = 0; row < rows; row++){
			// Первое произведение строки
			pointwise(matrix + ((row * columns) * N), vector, result + (row * N));
			/**
			 * Остальные слагаемые строки накапливаются
			 */
			for(size_t column = 1; column < columns; column++){
				// Рабочий многочлен произведения
				int32_t term[N];
				// Произведение столбца строки на многочлен вектора
				pointwise(matrix + (((row * columns) + column) * N), vector + (column * N), term);
				// Накопление произведения в строке итога
				add(result + (row * N), term, result + (row * N));
				// Затираем рабочий многочлен
				sys::wipe(term, sizeof(term));
			}
		}
	}
	/**
	 * @brief Функция выработки ключа из зерна ξ (раздел 6.1 FIPS 204)
	 *
	 * @param p      параметры набора
	 * @param seed   зерно ξ, тридцать два байта
	 * @param key    место для записи ключа проверки ρ ‖ productOdd
	 * @param secret место для записи ключа подписи ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ productEven
	 *
	 */
	static void keygen(const Params & setup, const uint8_t * seed, uint8_t * key, uint8_t * secret) noexcept {
		// Расширение зерна: (ρ, ρ′, K) = H(ξ ‖ k ‖ l, 128)
		uint8_t expanded[128];
		{
			// Поток SHAKE256 над ξ ‖ k ‖ l
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			// Подаём зерно ξ в поток
			xof.update(view_t(seed, 32));
			// Размерности матрицы двумя байтами
			const uint8_t dimensions[2] = {setup.rows, setup.columns};
			// Подаём размерности в поток
			xof.update(view_t(dimensions, sizeof(dimensions)));
			// Выжимаем 128 байтов расширения зерна
			(void) xof.squeeze(expanded, sizeof(expanded));
		}
		// Зерно матрицы ρ
		const uint8_t * rho = expanded;
		// Зерно секретов ρ′
		const uint8_t * rhoprime = (expanded + 32);
		// Ключ случайности K
		const uint8_t * kappa = (expanded + 96);
		// Матрица A в области NTT и секретные векторы s1, s2
		int32_t matrix[8][7][N];
		// Матрица из зерна ρ: четыре губки разом, хвост по одной
		matrixExpand(rho, setup.rows, setup.columns, 7, &matrix[0][0][0]);
		// Секретные векторы s1 и s2
		int32_t s1[7][N], s2[8][N];
		// Секреты из зерна ρ′
		expandSecrets(rhoprime, setup.columns, setup.rows, setup.eta, s1, s2);
		// t = NTT⁻¹(A ∘ NTT(s1)) + s2 по строкам матрицы
		int32_t t[8][N];
		{
			// Образ секрета в области NTT
			int32_t domain[7][N];
			/**
			 * Переводим многочлены секрета в область NTT
			 */
			for(size_t i = 0; i < setup.columns; i++){
				// Копия многочлена секрета для перевода в область
				::memcpy(domain[i], s1[i], sizeof(domain[i]));
				// Многочлен секрета в области NTT
				forward(domain[i]);
			}
			/**
			 * Вычисляем строки t произведением матрицы на секрет
			 */
			for(size_t row = 0; row < setup.rows; row++){
				// Первое произведение строки матрицы
				pointwise(matrix[row][0], domain[0], t[row]);
				/**
				 * Перебираем столбцы строки
				 */
				for(size_t column = 1; column < setup.columns; column++){
					// Рабочий многочлен произведения
					int32_t term[N];
					// Произведение столбца строки на многочлен секрета
					pointwise(matrix[row][column], domain[column], term);
					// Накопление произведения в строке t
					add(t[row], term, t[row]);
					// Затираем рабочий многочлен
					sys::wipe(term, sizeof(term));
				}
				// Строка t в обычную форму
				backward(t[row]);
				// Строка t дополняется секретом s2
				add(t[row], s2[row], t[row]);
				// Коэффициенты строки t к [0, q)
				reduceAll(t[row]);
			}
			// Затираем образ секрета в области NTT
			sys::wipe(domain, sizeof(domain));
		}
		// Разложение t на старшую и младшую части, запись ключа проверки
		int32_t productEven[8][N];
		::memcpy(key, rho, 32);
		/**
		 * Раскладываем строки t на части
		 */
		for(size_t row = 0; row < setup.rows; row++){
			/**
			 * Раскладываем коэффициенты строки
			 */
			for(size_t i = 0; i < N; i++)
				// Коэффициент t раскладывается на productOdd и productEven
				t[row][i] = power2round(t[row][i], productEven[row][i]);
			// Записываем строку productOdd в ключ проверки
			packT1(t[row], (key + 32 + (row * 320)));
		}
		// Трассировка открытого ключа: tr = H(ρ ‖ productOdd, 64)
		uint8_t trace[64];
		{
			// Поток SHAKE256 над ключом проверки
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			// Подаём запись ρ ‖ productOdd в поток
			xof.update(view_t(key, (32 + (setup.rows * 320))));
			// Выжимаем трассировку ключа проверки
			(void) xof.squeeze(trace, sizeof(trace));
		}
		// Позиция записи ключа подписи
		uint8_t * out = secret;
		// Записываем зерно матрицы ρ
		::memcpy(out, rho, 32);
		// Продвигаем позицию записи
		out += 32;
		// Записываем ключ случайности K
		::memcpy(out, kappa, 32);
		// Продвигаем позицию записи
		out += 32;
		// Записываем трассировку ключа проверки
		::memcpy(out, trace, 64);
		// Продвигаем позицию записи
		out += 64;
		/**
		 * Записываем многочлены s1
		 */
		for(size_t i = 0; i < setup.columns; i++){
			// Записываем многочлен секрета s1
			packS(s1[i], setup.eta, out);
			// Продвигаем позицию записи на размер записи секрета
			out += ((setup.eta == 2) ? 96 : 128);
		}
		/**
		 * Записываем многочлены s2
		 */
		for(size_t i = 0; i < setup.rows; i++){
			// Записываем многочлен секрета s2
			packS(s2[i], setup.eta, out);
			// Продвигаем позицию записи на размер записи секрета
			out += ((setup.eta == 2) ? 96 : 128);
		}
		/**
		 * Записываем строки productEven
		 */
		for(size_t row = 0; row < setup.rows; row++){
			// Записываем строку младших частей productEven
			packT0(productEven[row], out);
			// Продвигаем позицию записи на 416 байтов
			out += 416;
		}
		// Затираем расширение зерна
		sys::wipe(expanded, sizeof(expanded));
		// Затираем матрицу
		sys::wipe(matrix, sizeof(matrix));
		// Затираем секрет s1
		sys::wipe(s1, sizeof(s1));
		// Затираем секрет s2
		sys::wipe(s2, sizeof(s2));
		// Затираем вектор t
		sys::wipe(t, sizeof(t));
		// Затираем младшие части productEven
		sys::wipe(productEven, sizeof(productEven));
		// Затираем трассировку
		sys::wipe(trace, sizeof(trace));
	}

	/**
	 * @brief Функция выработки подписи (раздел 6.2 FIPS 204)
	 *
	 * @param p       параметры набора
	 * @param secret  запись ключа подписи ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ productEven
	 * @param rnd     случайность подписи, тридцать два байта
	 * @param message подписываемое сообщение
	 * @param context контекст подписи
	 * @param result  место для записи подписи c~ ‖ z ‖ h
	 *
	 */
	static void signing(const Params & setup, const uint8_t * secret, const uint8_t * rnd, const view_t & message, const view_t & context, uint8_t * result) noexcept {
		// Зерно матрицы ρ из записи ключа
		const uint8_t * rho = secret;
		// Ключ случайности K из записи ключа
		const uint8_t * kappa = (secret + 32);
		// Трассировка ключа проверки из записи ключа
		const uint8_t * trace = (secret + 64);
		// Вычисляемое сообщение μ = H(tr ‖ 0x00 ‖ длина контекста ‖ контекст ‖ сообщение, 64)
		uint8_t mu[64];
		{
			// Поток SHAKE256 над представлением сообщения
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			// Подаём трассировку в поток
			xof.update(view_t(trace, 64));
			// Приставка: нулевой байт и длина контекста
			const uint8_t prefix[2] = {0, static_cast <uint8_t> (context.size)};
			// Подаём приставку в поток
			xof.update(view_t(prefix, sizeof(prefix)));
			// Подаём контекст в поток
			xof.update(context);
			// Подаём сообщение в поток
			xof.update(message);
			// Выжимаем вычисляемое сообщение μ
			(void) xof.squeeze(mu, sizeof(mu));
		}
		// Случайность маски: ρ″ = H(K ‖ rnd ‖ μ, 64)
		uint8_t rhodbl[64];
		{
			// Поток SHAKE256 над случайностью маски
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			// Подаём ключ K в поток
			xof.update(view_t(kappa, 32));
			// Подаём случайность подписи в поток
			xof.update(view_t(rnd, 32));
			// Подаём вычисляемое сообщение в поток
			xof.update(view_t(mu, sizeof(mu)));
			// Выжимаем зерно маски ρ″
			(void) xof.squeeze(rhodbl, sizeof(rhodbl));
		}
		// Позиция записи секретов в ключе подписи
		const uint8_t * packed = (secret + 128);
		// Секретные векторы s1, s2 и младшие части productEven
		int32_t s1[7][N], s2[8][N], productEven[8][N];
		/**
		 * Читаем многочлены s1
		 */
		for(size_t i = 0; i < setup.columns; i++){
			// Читаем многочлен секрета s1
			(void) unpackS(packed, setup.eta, s1[i]);
			// Продвигаем позицию чтения на размер записи секрета
			packed += ((setup.eta == 2) ? 96 : 128);
			// Многочлен s1 в область NTT
			forward(s1[i]);
		}
		/**
		 * Читаем многочлены s2
		 */
		for(size_t i = 0; i < setup.rows; i++){
			// Читаем многочлен секрета s2
			(void) unpackS(packed, setup.eta, s2[i]);
			// Продвигаем позицию чтения на размер записи секрета
			packed += ((setup.eta == 2) ? 96 : 128);
			// Многочлен s2 в область NTT
			forward(s2[i]);
		}
		/**
		 * Читаем строки productEven
		 */
		for(size_t i = 0; i < setup.rows; i++){
			// Читаем строку младших частей productEven
			unpackT0(packed, productEven[i]);
			// Продвигаем позицию чтения на 416 байтов
			packed += 416;
			// Многочлен productEven в область NTT
			forward(productEven[i]);
		}
		// Матрица A в области NTT строится заново из ρ (укладка строк подряд по l многочленов)
		int32_t matrix[8 * 7 * N];
		// Матрица из зерна ρ: четыре губки разом, хвост по одной
		matrixExpand(rho, setup.rows, setup.columns, setup.columns, matrix);
		// Счётчик попыток подписи
		uint16_t attempt = 0;
		// Признак готовности подписи
		uint32_t ready = 0;
		/**
		 * Пробуем подпись, пока попытка не примется
		 */
		while(ready == 0){
			// Маска y из l многочленов в обычной форме и её образ в области NTT
			int32_t y[7][N], domain[7][N];
			/**
			 * Выбираем многочлены маски y
			 */
			for(size_t i = 0; i < setup.columns; i++){
				// Многочлен маски y из зерна ρ″ с номером попытки
				expandMask(rhodbl, static_cast <uint16_t> ((attempt * setup.columns) + i), setup.gamma1, y[i]);
				// Копия маски для перевода в область
				::memcpy(domain[i], y[i], sizeof(domain[i]));
				// Многочлен маски в области NTT
				forward(domain[i]);
			}
			// w = NTT⁻¹(A ∘ NTT(y)) по строкам матрицы
			int32_t w[8][N];
			// Произведение матрицы на маску в области NTT
			matrixVector(matrix, domain[0], setup.rows, setup.columns, w[0]);
			/**
			 * Переводим строки w в обычную форму
			 */
			for(size_t row = 0; row < setup.rows; row++){
				// Строка w в обычную форму
				backward(w[row]);
				// Коэффициенты строки w к [0, q)
				reduceAll(w[row]);
			}
			// Зерно вызова c~
			uint8_t challenge[64];
			// Размер записи старших частей на многочлен
			size_t w1size = 0;
			{
				// Записи старших частей по строкам
				uint8_t encoded[8][192];
				/**
				 * Записываем старшие части строк
				 */
				for(size_t row = 0; row < setup.rows; row++){
					// Младшая часть разложения и многочлен старших частей
					int32_t low = 0, lowOdd[N];
					/**
					 * Раскладываем коэффициенты строки w
					 */
					for(size_t i = 0; i < N; i++)
						// Коэффициент w раскладывается, старшая часть в lowOdd
						lowOdd[i] = decompose(w[row][i], setup.gamma2, low);
					// Записываем старшие части строки
					encodeW1(lowOdd, setup.gamma2, encoded[row]);
					// Затираем многочлен старших частей
					sys::wipe(lowOdd, sizeof(lowOdd));
				}
				// Запись короче при γ2 = (q − 1)/32: 128 байтов вместо 192
				w1size = ((setup.gamma2 == ((Q - 1) / 32)) ? 128 : 192);
				// Поток SHAKE256 над μ и записями старших частей
				digest::keccak_t xof(digest::sha3_t::SHAKE256);
				// Подаём вычисляемое сообщение в поток
				xof.update(view_t(mu, sizeof(mu)));
				/**
				 * Подаём записи старших частей в поток
				 */
				for(size_t row = 0; row < setup.rows; row++)
					// Подаём запись старших частей строки в поток
					xof.update(view_t(encoded[row], w1size));
				// Выжимаем зерно вызова
				(void) xof.squeeze(challenge, setup.challenge);
				// Затираем записи старших частей
				sys::wipe(encoded, sizeof(encoded));
			}
			// Вызов c из шара
			int32_t c[N];
			// Многочлен вызова из шара по зерну c~
			sampleInBall(challenge, setup.challenge, setup.tau, c);
			// Вызов в область NTT
			forward(c);
			// z = y + c·s1 в свободной форме: суммы малы и в приведении не нуждаются
			int32_t z[7][N];
			/**
			 * Вычисляем многочлены ответа z
			 */
			for(size_t i = 0; i < setup.columns; i++){
				// Рабочий многочлен произведения
				int32_t term[N];
				// Произведение вызова на многочлен секрета s1
				pointwise(c, s1[i], term);
				// Произведение в обычную форму
				backward(term);
				// Ответ z есть сумма маски и произведения
				add(y[i], term, z[i]);
				// Затираем рабочий многочлен
				sys::wipe(term, sizeof(term));
			}
			// Накопитель отказа попытки
			uint32_t reject = 0;
			/**
			 * Проверяем границу ответа z
			 */
			for(size_t i = 0; i < setup.columns; i++)
				// Превышение границы ответом отклоняет попытку
				reject |= overflow(z[i], static_cast <int32_t> (setup.gamma1 - setup.beta));
			// Многочлены подсказки по строкам
			int32_t hints[8][N];
			// Младшие части resultEven по строкам
			int32_t resultEven[8][N];
			/**
			 * Вычисляем подсказки по строкам
			 */
			for(size_t row = 0; row < setup.rows; row++){
				// Рабочие многочлены произведений
				int32_t term[N], ct0[N];
				// Произведение вызова на многочлен секрета s2
				pointwise(c, s2[row], term);
				// Произведение c·s2 в обычную форму
				backward(term);
				// Произведение вызова на младшие части productEven
				pointwise(c, productEven[row], ct0);
				// Произведение c·productEven в обычную форму
				backward(ct0);
				// Превышение границы произведением c·productEven отклоняет попытку
				reject |= overflow(ct0, static_cast <int32_t> (setup.gamma2));
				/**
				 * Разлагаем разность и сумму по коэффициентам
				 */
				for(size_t i = 0; i < N; i++){
					// Разность w − c·s2 в записи модуля и её разложение
					const int32_t value = ((((w[row][i] - term[i]) % static_cast <int32_t> (Q)) + Q) % static_cast <int32_t> (Q));
					// Младшая часть разложения разности
					int32_t low = 0;
					// Старшая часть разности w − c·s2
					const int32_t high1 = decompose(value, setup.gamma2, low);
					// Младшая часть разности в resultEven
					resultEven[row][i] = low;
					// Подсказка: старшая часть меняется от добавления c·productEven
					const int32_t corrected = ((((value + ct0[i]) % static_cast <int32_t> (Q)) + Q) % static_cast <int32_t> (Q));
					// Младшая часть разложения суммы
					int32_t low2 = 0;
					// Старшая часть суммы с произведением c·productEven
					const int32_t high2 = decompose(corrected, setup.gamma2, low2);
					// Подсказка выставляется при смене старшей части
					hints[row][i] = ((high1 != high2) ? 1 : 0);
				}
				// Затираем произведение c·s2
				sys::wipe(term, sizeof(term));
				// Затираем произведение c·productEven
				sys::wipe(ct0, sizeof(ct0));
			}
			/**
			 * Отказ по границе ‖resultEven‖∞ ≥ γ2 − β
			 */
			for(size_t row = 0; row < setup.rows; row++)
				// Превышение границы младшими частями отклоняет попытку
				reject |= overflow(resultEven[row], static_cast <int32_t> (setup.gamma2 - setup.beta));
			// Вес подсказки: число единиц по всем строкам
			uint32_t weight = 0;
			/**
			 * Считаем вес подсказки по строкам
			 */
			for(size_t row = 0; row < setup.rows; row++){
				// Вес строки подсказки
				uint32_t rowweight = 0;
				/**
				 * Считаем единицы строки подсказки
				 */
				for(size_t i = 0; i < N; i++)
					// Единица подсказки в вес строки
					rowweight += static_cast <uint32_t> (hints[row][i]);
				// Вес строки в общий вес
				weight += rowweight;
			}
			// Вес выше ω отклоняет попытку
			reject |= static_cast <uint32_t> ((weight > setup.omega) ? 1 : 0);
			// Если отказа нет, записываем подпись
			if(reject == 0){
				// Позиция записи подписи
				uint8_t * out = result;
				// Записываем зерно вызова c~
				::memcpy(out, challenge, setup.challenge);
				// Продвигаем позицию записи на размер зерна
				out += setup.challenge;
				/**
				 * Записываем многочлены ответа z
				 */
				for(size_t i = 0; i < setup.columns; i++){
					// Записываем многочлен ответа z
					packZ(z[i], setup.gamma1, out);
					// Продвигаем позицию записи на размер записи ответа
					out += ((setup.gamma1 == (1u << 17)) ? 576 : 640);
				}
				// Позиция индекса в записи подсказки
				size_t position = 0;
				/**
				 * Записываем индексы единиц подсказки
				 */
				for(size_t row = 0; row < setup.rows; row++){
					/**
					 * Перебираем позиции единиц строки
					 */
					for(size_t i = 0; i < N; i++){
						// Если подсказка на позиции выставлена
						if(hints[row][i] != 0){
							if(position < setup.omega)
								// Индекс единицы в запись подсказки
								out[position] = static_cast <uint8_t> (i);
							// Считаем единицы подсказки
							position++;
						}
					}
					// Если строка не последняя, счётчик единиц в запись
					if(row + 1 < setup.rows)
						// Счётчик единиц строки в запись подсказки
						out[setup.omega + row] = static_cast <uint8_t> (position);
				}
				/**
				 * Незаполненные индексы и последний счётчик
				 */
				for(size_t i = position; i < setup.omega; i++)
					// Незаполненные индексы обнуляются
					out[i] = 0;
				// Последний счётчик единиц в запись подсказки
				out[setup.omega + (setup.rows - 1)] = static_cast <uint8_t> (position);
				// Подпись готова: выходим из перебора попыток
				ready = 1;
			}
			// Затираем маску y
			sys::wipe(y, sizeof(y));
			// Затираем образ маски в области NTT
			sys::wipe(domain, sizeof(domain));
			// Затираем вектор w
			sys::wipe(w, sizeof(w));
			// Затираем вызов c
			sys::wipe(c, sizeof(c));
			// Затираем ответ z
			sys::wipe(z, sizeof(z));
			// Затираем младшие части resultEven
			sys::wipe(resultEven, sizeof(resultEven));
			// Затираем подсказку
			sys::wipe(hints, sizeof(hints));
			// Считаем попытку
			attempt++;
		}
		// Затираем вычисляемое сообщение μ
		sys::wipe(mu, sizeof(mu));
		// Затираем зерно маски ρ″
		sys::wipe(rhodbl, sizeof(rhodbl));
		// Затираем секрет s1
		sys::wipe(s1, sizeof(s1));
		// Затираем секрет s2
		sys::wipe(s2, sizeof(s2));
		// Затираем младшие части productEven
		sys::wipe(productEven, sizeof(productEven));
		// Затираем матрицу
		sys::wipe(matrix, sizeof(matrix));
	}
	/**
	 * @brief Функция проверки подписи (раздел 6.3 FIPS 204)
	 *
	 * @param p         параметры набора
	 * @param key       запись ключа проверки ρ ‖ productOdd
	 * @param message   подписанное сообщение
	 * @param context   контекст подписи
	 * @param signature проверяемая подпись c~ ‖ z ‖ h
	 * @return          признак того, что подпись сошлась
	 *
	 */
	static bool checking(const Params & setup, const uint8_t * key, const view_t & message, const view_t & context, const uint8_t * signature) noexcept {
		// Зерно матрицы ρ из записи ключа
		const uint8_t * rho = key;
		// Трассировка ключа проверки: tr = H(ρ ‖ productOdd, 64)
		uint8_t trace[64];
		{
			// Поток SHAKE256 над ключом проверки
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			// Подаём запись ρ ‖ productOdd в поток
			xof.update(view_t(key, (32 + (setup.rows * 320))));
			// Выжимаем трассировку ключа проверки
			(void) xof.squeeze(trace, sizeof(trace));
		}
		// Вычисляемое сообщение μ = H(tr ‖ 0x00 ‖ длина контекста ‖ контекст ‖ сообщение, 64)
		uint8_t mu[64];
		{
			// Поток SHAKE256 над представлением сообщения
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			// Подаём трассировку в поток
			xof.update(view_t(trace, sizeof(trace)));
			// Приставка: нулевой байт и длина контекста
			const uint8_t prefix[2] = {0, static_cast <uint8_t> (context.size)};
			// Подаём приставку в поток
			xof.update(view_t(prefix, sizeof(prefix)));
			// Подаём контекст в поток
			xof.update(context);
			// Подаём сообщение в поток
			xof.update(message);
			// Выжимаем вычисляемое сообщение μ
			(void) xof.squeeze(mu, sizeof(mu));
		}
		// Зерно вызова c~ из записи подписи
		const uint8_t * challenge = signature;
		// Позиция записи ответа в подписи
		const uint8_t * packed = (signature + setup.challenge);
		// Многочлены ответа z
		int32_t z[7][N];
		// Накопитель отказа проверки
		uint32_t reject = 0;
		/**
		 * Читаем многочлены ответа z
		 */
		for(size_t i = 0; i < setup.columns; i++){
			// Читаем многочлен ответа z
			unpackZ(packed, setup.gamma1, z[i]);
			// Продвигаем позицию чтения на размер записи ответа
			packed += ((setup.gamma1 == (1u << 17)) ? 576 : 640);
			// Ответ за границей γ1 − β отвергается
			reject |= overflow(z[i], static_cast <int32_t> (setup.gamma1 - setup.beta));
			// Многочлен z в область NTT
			forward(z[i]);
		}
		// Запись индексов и счётчиков подсказки
		const uint8_t * indices = packed;
		// Многочлены подсказки по строкам
		int32_t hints[8][N];
		// Позиция индекса в записи подсказки
		size_t position = 0;
		// Признак гнилой записи подсказки
		uint32_t malformed = 0;
		/**
		 * Разбираем подсказку по строкам
		 */
		for(size_t row = 0; row < setup.rows; row++){
			/**
			 * Обнуляем строку подсказки
			 */
			for(size_t i = 0; i < N; i++)
				// Коэффициент подсказки обнуляется
				hints[row][i] = 0;
			// Предел индексов многочлена: накопленный счётчик
			const size_t bound = ((row + 1 < setup.rows) ? indices[setup.omega + row] : indices[setup.omega + (setup.rows - 1)]);
			// Последний принятый индекс строки
			size_t last = 0;
			/**
			 * Разбираем индексы единиц строки
			 */
			for(size_t j = position; j < bound; j++){
				// Индексы обязаны возрастать и не превышать ω
				if(j >= setup.omega){
					// Индекс за пределом ω гнилит запись
					malformed = 1;
					// Обрываем разбор строки при гнилой записи
					break;
				}
				// Очередной индекс единицы
				const uint8_t index = indices[j];
				// Если индекс не возрастает, запись гнилая
				if((j > position) && (index <= last))
					// Индексы обязаны строго возрастать
					malformed = 1;
				// Запоминаем последний индекс
				last = index;
				// Единица подсказки на позиции индекса
				hints[row][index] = 1;
			}
			// Позиция следующей строки по счётчику
			position = bound;
		}
		/**
		 * Остаток индексов обязан быть нулевым
		 */
		for(size_t j = position; j < setup.omega; j++)
			// Ненулевой остаток индексов гнилит запись
			malformed |= static_cast <uint32_t> (indices[j]);
		// Гнилая подсказка отклоняет подпись
		reject |= malformed;
		// Вызов c из шара
		int32_t c[N];
		// Многочлен вызова из шара по зерну c~
		sampleInBall(challenge, setup.challenge, setup.tau, c);
		// Вызов в область NTT
		forward(c);
		// w′ = NTT⁻¹(A ∘ NTT(z) − c ∘ NTT(productOdd · 2^13)) по строкам матрицы
		int32_t w[8][N];
		{
			// Матрица из ρ ключа (укладка строк подряд по l многочленов)
			int32_t matrix[8 * 7 * N];
			// Многочлены матрицы из зерна ρ: плашмя четвёрками губок, хвост по одной
			matrixExpand(rho, setup.rows, setup.columns, setup.columns, matrix);
			// Произведение матрицы на ответ в области NTT
			matrixVector(matrix, z[0], setup.rows, setup.columns, w[0]);
			// Затираем матрицу
			sys::wipe(matrix, sizeof(matrix));
		}
		/**
		 * Вычитаем вызов из строк произведения
		 */
		for(size_t row = 0; row < setup.rows; row++){
			// Рабочий многочлен productOdd
			int32_t term[N];
			// Читаем строку productOdd из ключа проверки
			unpackT1((key + 32 + (row * 320)), term);
			/**
			 * productOdd · 2^13 простым масштабом коэффициентов перед переходом в область
			 */
			for(size_t i = 0; i < N; i++)
				// Коэффициент productOdd масштабируется на 2^13
				term[i] <<= 13;
			// Многочлен productOdd в область NTT
			forward(term);
			// Произведение вызова на productOdd в области
			int32_t product[N];
			// Произведение вызова на многочлен productOdd
			pointwise(c, term, product);
			// Вычитание произведения из строки w′
			subtract(w[row], product, w[row]);
			// Строка w′ в обычную форму
			backward(w[row]);
			// Коэффициенты строки w′ к [0, q)
			reduceAll(w[row]);
			// Затираем рабочий многочлен productOdd
			sys::wipe(term, sizeof(term));
			// Затираем произведение
			sys::wipe(product, sizeof(product));
		}
		// Ожидаемое зерно вызова
		uint8_t expected[64];
		// Размер записи старших частей на многочлен
		size_t w1size = 0;
		{
			// Записи старших частей по строкам
			uint8_t encoded[8][192];
			/**
			 * Применяем подсказку к строкам w′
			 */
			for(size_t row = 0; row < setup.rows; row++){
				/**
				 * Применяем подсказку к коэффициентам
				 */
				for(size_t i = 0; i < N; i++)
					// Коэффициент w′ с применённой подсказкой
					w[row][i] = useHint(w[row][i], static_cast <uint32_t> (hints[row][i]), setup.gamma2);
				// Записываем старшие части строки
				encodeW1(w[row], setup.gamma2, encoded[row]);
			}
			// Запись короче при γ2 = (q − 1)/32: 128 байтов вместо 192
			w1size = ((setup.gamma2 == ((Q - 1) / 32)) ? 128 : 192);
			// Поток SHAKE256 над μ и записями старших частей
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			// Подаём вычисляемое сообщение в поток
			xof.update(view_t(mu, sizeof(mu)));
			/**
			 * Подаём записи старших частей в поток
			 */
			for(size_t row = 0; row < setup.rows; row++)
				// Подаём запись старших частей строки в поток
				xof.update(view_t(encoded[row], w1size));
			// Выжимаем ожидаемое зерно вызова
			(void) xof.squeeze(expected, setup.challenge);
			// Затираем записи старших частей
			sys::wipe(encoded, sizeof(encoded));
		}
		// Накопитель расхождения зёрен
		uint8_t difference = 0;
		/**
		 * Сличаем байты зёрен вызова
		 */
		for(size_t i = 0; i < setup.challenge; i++)
			// Расхождение байтов зёрен в накопитель
			difference |= static_cast <uint8_t> (expected[i] ^ challenge[i]);
		// Затираем трассировку
		sys::wipe(trace, sizeof(trace));
		// Затираем вычисляемое сообщение μ
		sys::wipe(mu, sizeof(mu));
		// Затираем ответ z
		sys::wipe(z, sizeof(z));
		// Затираем вызов c
		sys::wipe(c, sizeof(c));
		// Затираем вектор w′
		sys::wipe(w, sizeof(w));
		// Затираем подсказку
		sys::wipe(hints, sizeof(hints));
		// Затираем ожидаемое зерно
		sys::wipe(expected, sizeof(expected));
		// Подпись сошлась при отсутствии отказа и расхождения
		return ((reject == 0) && (difference == 0));
	}
	/**
	 * @brief Функция проверки подлинности записи ключа подписи и вывода ключа проверки
	 *
	 * @details Раздел 6.1 FIPS 204 вычисляется из ρ и распакованных s1, s2:
	 *          t = NTT⁻¹(A ∘ NTT(s1)) + s2, далее productOdd = Power2Round(t) и
	 *          tr′ = H(ρ ‖ productOdd) сличается с записанной трассировкой.
	 *
	 * @param p      параметры набора
	 * @param secret запись ключа подписи ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ productEven
	 * @param key    место для записи ключа проверки ρ ‖ productOdd (при подлинной записи)
	 * @return       признак того, что трассировка tr сошлась с пересчитанной из частей записи
	 *
	 */
	static bool consistent(const Params & setup, const uint8_t * secret, uint8_t * key) noexcept {
		// Зерно матрицы ρ из записи ключа
		const uint8_t * rho = secret;
		// Записанная трассировка ключа проверки
		const uint8_t * trace = (secret + 64);
		// Позиция записи секретов в ключе подписи
		const uint8_t * packed = (secret + 128);
		// Распаковка секретных векторов из записи с контролем кодов за границей 2η
		uint32_t malformed = 0;
		// Секретные векторы s1 и s2
		int32_t s1[7][N], s2[8][N];
		/**
		 * Читаем многочлены s1
		 */
		for(size_t i = 0; i < setup.columns; i++){
			// Читаем многочлен секрета s1 с контролем кодов
			malformed |= unpackS(packed, setup.eta, s1[i]);
			// Продвигаем позицию чтения на размер записи секрета
			packed += ((setup.eta == 2) ? 96 : 128);
		}
		/**
		 * Читаем многочлены s2
		 */
		for(size_t i = 0; i < setup.rows; i++){
			// Читаем многочлен секрета s2 с контролем кодов
			malformed |= unpackS(packed, setup.eta, s2[i]);
			// Продвигаем позицию чтения на размер записи секрета
			packed += ((setup.eta == 2) ? 96 : 128);
		}
		// t = NTT⁻¹(A ∘ NTT(s1)) + s2 по строкам матрицы из ρ записи
		int32_t t[8][N];
		{
			// Образ секрета в области NTT и многочлен матрицы
			int32_t domain[7][N], expanded[N];
			/**
			 * Переводим многочлены секрета в область NTT
			 */
			for(size_t i = 0; i < setup.columns; i++){
				// Копия многочлена секрета для перевода в область
				::memcpy(domain[i], s1[i], sizeof(domain[i]));
				// Многочлен секрета в области NTT
				forward(domain[i]);
			}
			/**
			 * Вычисляем строки t произведением матрицы на секрет
			 */
			for(size_t row = 0; row < setup.rows; row++){
				// Первый многочлен строки матрицы из зерна ρ
				expandA(rho, static_cast <uint8_t> (row), 0, expanded);
				// Первое произведение строки матрицы
				pointwise(expanded, domain[0], t[row]);
				/**
				 * Перебираем столбцы строки
				 */
				for(size_t column = 1; column < setup.columns; column++){
					// Многочлен столбца строки матрицы из зерна ρ
					expandA(rho, static_cast <uint8_t> (row), static_cast <uint8_t> (column), expanded);
					// Рабочий многочлен произведения
					int32_t term[N];
					// Произведение столбца строки на многочлен секрета
					pointwise(expanded, domain[column], term);
					// Накопление произведения в строке t
					add(t[row], term, t[row]);
					// Затираем рабочий многочлен
					sys::wipe(term, sizeof(term));
				}
				// Строка t в обычную форму
				backward(t[row]);
				// Строка t дополняется секретом s2
				add(t[row], s2[row], t[row]);
				// Коэффициенты строки t к [0, q)
				reduceAll(t[row]);
			}
			// Затираем образ секрета в области NTT
			sys::wipe(domain, sizeof(domain));
			// Затираем многочлен матрицы
			sys::wipe(expanded, sizeof(expanded));
		}
		// Ключ проверки ρ ‖ productOdd и трассировка tr′ = H(ρ ‖ productOdd)
		uint8_t expected[64];
		{
			// Младшие части разложения строки
			int32_t productEven[N];
			// Записываем зерно матрицы в ключ проверки
			::memcpy(key, rho, 32);
			/**
			 * Раскладываем строки t на части
			 */
			for(size_t row = 0; row < setup.rows; row++){
				/**
				 * Раскладываем коэффициенты строки
				 */
				for(size_t i = 0; i < N; i++)
					// Коэффициент t раскладывается на productOdd и productEven
					t[row][i] = power2round(t[row][i], productEven[i]);
				// Записываем строку productOdd в ключ проверки
				packT1(t[row], (key + 32 + (row * 320)));
			}
			// Затираем младшие части
			sys::wipe(productEven, sizeof(productEven));
			// Поток SHAKE256 над ключом проверки
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			// Подаём запись ρ ‖ productOdd в поток
			xof.update(view_t(key, (32 + (setup.rows * 320))));
			// Выжимаем пересчитанную трассировку
			(void) xof.squeeze(expected, sizeof(expected));
		}
		// Сличаем трассировку с записанной, гнилая запись отвергается
		const bool result = ((malformed == 0) && (::memcmp(expected, trace, sizeof(expected)) == 0));
		// Затираем секрет s1
		sys::wipe(s1, sizeof(s1));
		// Затираем секрет s2
		sys::wipe(s2, sizeof(s2));
		// Затираем вектор t
		sys::wipe(t, sizeof(t));
		// Затираем пересчитанную трассировку
		sys::wipe(expected, sizeof(expected));
		// Выводим признак подлинности записи
		return result;
	}

};

/**
 * @brief Метод получения набора параметров ключа
 *
 * @return набор параметров ключа, NONE без ключа
 *
 */
sign::Mldsa::set_t sign::Mldsa::set() const noexcept {
	// Если ключ не установлен, набора нет
	if(!this->_secret && !this->_public)
		// Выводим отказ: без ключа набора нет
		return set_t::NONE;
	// Выводим набор параметров ключа
	return this->_set;
}

/**
 * @brief Метод получения размера подписи
 *
 * @return размер подписи в байтах, ноль без ключа
 *
 */
size_t sign::Mldsa::size() const noexcept {
	// Если ключ не установлен, размера нет
	if(!this->_secret && !this->_public)
		// Выводим отказ: без ключа размера нет
		return 0;
	// Выводим размер подписи набора
	return signatureSize(this->_set);
}
/**
 * @brief Метод получения верхнего предела длины подписи в записанном виде
 *
 * @return верхний предел длины подписи в байтах, ноль без ключа
 *
 */
size_t sign::Mldsa::limit() const noexcept {
	// Если ключ не установлен, предела нет
	if(!this->_secret && !this->_public)
		// Выводим отказ: без ключа предела нет
		return 0;
	// Выводим предел длины подписи набора
	return signatureSize(this->_set);
}
/**
 * @brief Метод сброса состояния модуля
 *
 */
void sign::Mldsa::clear() noexcept {
	// Затираем запись ключа подписи
	sys::wipe(this->_key, sizeof(this->_key));
	// Затираем запись ключа проверки подписи
	sys::wipe(this->_pkey, sizeof(this->_pkey));
	// Признак ключа подписи сброшен
	this->_secret = false;
	// Признак ключа проверки сброшен
	this->_public = false;
	// Набор параметров сброшен
	this->_set = set_t::NONE;
}
/**
 * @brief Метод получения размера ключа подписи набора в байтах
 *
 * @param set набор параметров
 * @return    размер ключа подписи в байтах, ноль у несуществующего набора
 *
 */
size_t sign::Mldsa::secretSize(const set_t set) noexcept {
	/**
	 * Определяем размер ключа подписи набора
	 */
	switch(set){
		// Размер ключа подписи ML-DSA-44
		case set_t::DSA44: return 2560;
		// Размер ключа подписи ML-DSA-65
		case set_t::DSA65: return 4032;
		// Размер ключа подписи ML-DSA-87
		case set_t::DSA87: return 4896;
		// Несуществующий набор выдаёт ноль
		default: return 0;
	}
}
/**
 * @brief Метод получения размера ключа проверки набора в байтах
 *
 * @param set набор параметров
 * @return    размер ключа проверки в байтах, ноль у несуществующего набора
 *
 */
size_t sign::Mldsa::publicSize(const set_t set) noexcept {
	/**
	 * Определяем размер ключа проверки набора
	 */
	switch(set){
		// Размер ключа проверки ML-DSA-44
		case set_t::DSA44: return 1312;
		// Размер ключа проверки ML-DSA-65
		case set_t::DSA65: return 1952;
		// Размер ключа проверки ML-DSA-87
		case set_t::DSA87: return 2592;
		// Несуществующий набор выдаёт ноль
		default: return 0;
	}
}
/**
 * @brief Метод получения размера подписи набора в байтах
 *
 * @param set набор параметров
 * @return    размер подписи в байтах, ноль у несуществующего набора
 *
 */
size_t sign::Mldsa::signatureSize(const set_t set) noexcept {
	/**
	 * Определяем размер подписи набора
	 */
	switch(set){
		// Размер подписи ML-DSA-44
		case set_t::DSA44: return 2420;
		// Размер подписи ML-DSA-65
		case set_t::DSA65: return 3309;
		// Размер подписи ML-DSA-87
		case set_t::DSA87: return 4627;
		// Несуществующий набор выдаёт ноль
		default: return 0;
	}
}
/**
 * @brief Метод порождения долговременного ключа подписи из зерна
 *
 * @param set    набор параметров
 * @param seed   зерно выработки ξ длиной в тридцать два байта
 * @param key    место, в которое помещается ключ проверки ρ ‖ productOdd
 * @param secret место, в которое помещается ключ подписи ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ productEven
 * @return       признак успешности порождения ключа
 *
 */
bool sign::Mldsa::generate(const set_t set, const view_t & seed, uint8_t * key, uint8_t * secret) noexcept {
	// Результат работы
	bool result = false;
	// Параметры набора существуют и зерно верной длины
	const Params setup = params(set);
	// Если набор существует и зерно верной длины
	if((setup.rows != 0) && (seed.size == SEED_SIZE)){
		// Вырабатываем ключ из зерна
		keygen(setup, static_cast <const uint8_t *> (seed.data), key, secret);
		// Ключ проверки в состояние модуля
		::memcpy(this->_pkey, key, publicSize(set));
		// Ключ подписи в состояние модуля
		::memcpy(this->_key, secret, secretSize(set));
		// Запоминаем набор параметров
		this->_set = set;
		// Отмечаем установку ключа подписи
		this->_secret = true;
		// Отмечаем установку ключа проверки
		this->_public = true;
		// Порождение удалось
		result = true;
	}
	// Выводим признак успешности
	return result;
}
/**
 * @brief Метод порождения долговременного ключа подписи из источника случайности
 *
 * @param set    набор параметров
 * @param key    место, в которое помещается ключ проверки ρ ‖ productOdd
 * @param secret место, в которое помещается ключ подписи ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ productEven
 * @return       признак успешности порождения ключа
 *
 */
bool sign::Mldsa::generate(const set_t set, uint8_t * key, uint8_t * secret) noexcept {
	// Результат работы
	bool result = false;
	// Параметры набора существуют
	if(params(set).rows != 0){
		// Зерно из источника случайности
		uint8_t seed[SEED_SIZE];
		// Если источник случайности выдал зерно
		if(entropy::bytes(seed, sizeof(seed))){
			// Вырабатываем ключ из зерна
			// Вырабатываем ключ из зерна
			keygen(params(set), seed, key, secret);
			// Ключ проверки в состояние модуля
			::memcpy(this->_pkey, key, publicSize(set));
			// Ключ подписи в состояние модуля
			::memcpy(this->_key, secret, secretSize(set));
			// Запоминаем набор параметров
			this->_set = set;
			// Отмечаем установку ключа подписи
			this->_secret = true;
			// Отмечаем установку ключа проверки
			this->_public = true;
			// Порождение удалось
			result = true;
		} else
			// Источник отказал: состояние сброшено
			this->clear();
		// Затираем зерно
		sys::wipe(seed, sizeof(seed));
	}
	// Выводим признак успешности
	return result;
}
/**
 * @brief Метод установки ключа подписи
 *
 * @param set    набор параметров ключа
 * @param secret запись ключа подписи ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ productEven по набору
 * @return       признак успешности установки ключа подписи
 *
 */
bool sign::Mldsa::secret(const set_t set, const view_t & secret) noexcept {
	// Результат работы
	bool result = false;
	// Параметры набора существуют и запись верной длины
	const Params setup = params(set);
	// Если набор существует и запись верной длины
	if((setup.rows != 0) && (secret.size == secretSize(set))){
		// Подлинность записи проверяется пересчётом трассировки из её частей
		uint8_t check[2592];
		// Пересчёт трассировки из частей записи
		result = consistent(setup, static_cast <const uint8_t *> (secret.data), check);
		// Если запись подлинная, ключи в состояние модуля
		if(result){
			// Ключ подписи в состояние модуля
			::memcpy(this->_key, secret.data, secretSize(set));
			// Выведенный ключ проверки в состояние модуля
			::memcpy(this->_pkey, check, publicSize(set));
			// Запоминаем набор параметров
			this->_set = set;
			// Отмечаем установку ключа подписи
			this->_secret = true;
			// Отмечаем установку ключа проверки
			this->_public = true;
		}
		// Затираем выведенный ключ
		sys::wipe(check, sizeof(check));
	}
	// Выводим признак успешности
	return result;
}
/**
 * @brief Метод установки ключа проверки подписи
 *
 * @param set набор параметров ключа
 * @param key запись ключа проверки ρ ‖ productOdd по набору
 * @return    признак успешности установки ключа проверки подписи
 *
 */
bool sign::Mldsa::key(const set_t set, const view_t & key) noexcept {
	// Результат работы
	bool result = false;
	// Параметры набора существуют и запись верной длины
	if((params(set).rows != 0) && (key.size == publicSize(set))){
		// Если ключ подписи установлен, поданный обязан совпасть с выведенным
		if(this->_secret && (this->_set == set)){
			if(::memcmp(this->_pkey, key.data, publicSize(set)) == 0)
				// Поданный ключ совпал с выведенным: установка удалась
				result = true;
		} else {
			// Запись ключа проверки в состояние модуля
			::memcpy(this->_pkey, key.data, publicSize(set));
			// Запоминаем набор параметров
			this->_set = set;
			// Отмечаем установку ключа проверки
			this->_public = true;
			// Установка удалась
			result = true;
		}
	}
	// Выводим признак успешности
	return result;
}
/**
 * @brief Метод получения ключа проверки подписи
 *
 * @param result место, в которое записывается ключ проверки ρ ‖ productOdd по набору
 * @param size   размер места, не меньше размера ключа проверки набора
 * @return       признак успешности получения ключа проверки подписи
 *
 */
bool sign::Mldsa::key(uint8_t * result, const size_t size) const noexcept {
	// Результат работы
	bool outcome = false;
	// Ключ проверки установлен и места хватает
	if(this->_public && (size >= publicSize(this->_set))){
		// Ключ проверки в приёмник
		::memcpy(result, this->_pkey, publicSize(this->_set));
		// Получение удалось
		outcome = true;
	}
	// Выводим признак успешности
	return outcome;
}
/**
 * @brief Метод выработки подписи со случайностью от источника
 *
 * @param message подписываемое сообщение целиком
 * @param context контекст подписи, до 255 байтов, в TLS пустой
 * @param result  место, в которое помещается подпись c~ ‖ z ‖ h по набору
 * @return        признак успешности выработки подписи
 *
 */
bool sign::Mldsa::make(const view_t & message, const view_t & context, uint8_t * result) const noexcept {
	// Результат работы
	bool outcome = false;
	// Ключ подписи установлен и контекст допустимой длины
	if(this->_secret && (context.size <= 255)){
		// Случайность подписи из источника
		uint8_t rnd[SEED_SIZE];
		// Если источник случайности выдал случайность подписи
		if(entropy::bytes(rnd, sizeof(rnd))){
			// Выработка подписи из случайности источника
			signing(params(this->_set), this->_key, rnd, message, context, result);
			// Выработка удалась
			outcome = true;
		}
		// Затираем случайность
		sys::wipe(rnd, sizeof(rnd));
	}
	// Выводим признак успешности
	return outcome;
}
/**
 * @brief Метод выработки подписи с заданной случайностью
 *
 * @param rnd     случайность подписи длиной в тридцать два байта
 * @param message подписываемое сообщение целиком
 * @param context контекст подписи, до 255 байтов, в TLS пустой
 * @param result  место, в которое помещается подпись c~ ‖ z ‖ h по набору
 * @return        признак успешности выработки подписи
 *
 */
bool sign::Mldsa::make(const view_t & rnd, const view_t & message, const view_t & context, uint8_t * result) const noexcept {
	// Результат работы
	bool outcome = false;
	// Ключ подписи установлен, случайность и контекст допустимой длины
	if(this->_secret && (rnd.size == SEED_SIZE) && (context.size <= 255)){
		// Выработка подписи из заданной случайности
		signing(params(this->_set), this->_key, static_cast <const uint8_t *> (rnd.data), message, context, result);
		// Выработка удалась
		outcome = true;
	}
	// Выводим признак успешности
	return outcome;
}
/**
 * @brief Метод проверки подписи
 *
 * @param message   подписанное сообщение целиком
 * @param context   контекст подписи, до 255 байтов, в TLS пустой
 * @param signature проверяемая подпись c~ ‖ z ‖ h по набору
 * @return          признак того, что подпись сошлась
 *
 */
bool sign::Mldsa::check(const view_t & message, const view_t & context, const view_t & signature) const noexcept {
	// Результат работы
	bool result = false;
	// Ключ проверки установлен, подпись и контекст допустимой длины
	if(this->_public && (signature.size == signatureSize(this->_set)) && (context.size <= 255)){
		// Проверка подписи по ключу проверки
		result = checking(params(this->_set), this->_pkey, message, context, static_cast <const uint8_t *> (signature.data));
	}
	// Выводим признак успешности
	return result;
}

/**
 * @brief Конструктор
 *
 */
sign::Mldsa::Mldsa() noexcept :
 _set(set_t::NONE), _secret(false), _public(false) {}

/**
 * @brief Деструктор
 *
 */
sign::Mldsa::~Mldsa() noexcept {
	// Затираем запись ключа подписи
	sys::wipe(this->_key, sizeof(this->_key));
	// Затираем запись ключа проверки подписи
	sys::wipe(this->_pkey, sizeof(this->_pkey));
}
