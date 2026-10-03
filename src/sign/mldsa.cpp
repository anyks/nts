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
 * 1. Арифметика поля - на приведении Монтгомери с QINV = q⁻¹ mod 2^32, вычисленным
 *    при сборке, как и MONT = 2^32 mod q: произведение 32-разрядных коэффициентов
 *    держится в 64 разрядах (2^23 · 2^23 < 2^46). Таблицы степеней ζ и обратных к
 *    ним считаются один раз при первом обращении и сличаются с определением
 *    стандарта, а не с чужой распечаткой; в таблице - степени в форме Монтгомери,
 *    итог умножения в области выходит в обычной форме без лишних переводов.
 * 2. Потоки выборки выжимаются блоками, а не по одному значению: отклоняющая
 *    выборка матрицы - блоками по три байта, выборка ±1 вызова - по одному байту
 *    на позицию, знаки первые восемь байтов. Числа коэффициентов на блок кратны
 *    блоку SHAKE, чтобы тройки и пары не рвались по краям.
 * 3. Проверки границ подписи (‖z‖∞, ‖r0‖∞, ‖c·t0‖∞ и вес подсказки) идут без
 *    ветвлений по секретному значению там, где значение секретно: сравнение
 *    зерна вызова при проверке - по маске за постоянное время; выбор между
 *    принятием и отказом при выработке - тоже, и перезаписываемые части рабочей
 *    памяти затираются на каждой попытке.
 * 4. Запись ключа подписи - форма стандарта ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0 без
 *    перекладки при установке: выработка подписи распаковывает s1, s2 и t0 в
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

/**
 * @brief Служебные объекты модуля
 *
 */
namespace {
	/**
	 * Пространство имён библиотеки
	 */
	using namespace nts;

	/**
	 * @brief Модуль кольца: q = 2^23 − 2^13 + 1
	 *
	 */
	static constexpr uint32_t Q = 8380417;

	/**
	 * @brief Число коэффициентов многочлена кольца
	 *
	 */
	static constexpr size_t N = 256;

	/**
	 * @brief Вычисление обратного по модулю 2^32 шагами Ньютона при сборке
	 *
	 * @param value нечётное значение
	 *
	 * @return      обратное value⁻¹ mod 2^32
	 *
	 */
	static constexpr uint32_t invert32(const uint32_t value) noexcept {
		// Шаг Ньютона удваивает верные разряды: x·(2 − a·x) сходится к a⁻¹
		uint32_t result = value;
		for(size_t i = 0; i < 6; i++)
			result *= (2 - value * result);
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
	 * @brief Метод приведения Монтгомери
	 *
	 * @param value значение меньше q · 2^32
	 *
	 * @return      приведённое value · 2⁻³² mod q в [−q, q]
	 *
	 */
	static inline int32_t reduce(const int64_t value) noexcept {
		// Младшие 32 разряда произведения на q⁻¹ mod 2^32 обращают значение в кратное q
		const int64_t word = static_cast <int32_t> (static_cast <uint32_t> (static_cast <uint64_t> (value) * QINV));
		return static_cast <int32_t> ((value - (word * static_cast <int64_t> (Q))) >> 32);
	}

	/**
	 * @brief Метод умножения коэффициентов по модулю с приведением Монтгомери
	 *
	 * @param first  первый сомножитель
	 * @param second второй сомножитель
	 *
	 * @return       произведение по модулю в форме Монтгомери при second в ней
	 *
	 */
	static inline int32_t multiply(const int32_t first, const int32_t second) noexcept {
		return reduce(static_cast <int64_t> (first) * second);
	}

	/**
	 * @brief Вычисление обратного по простому модулю q возведением в степень при сборке
	 *
	 * @param value значение отличное от нуля по модулю
	 *
	 * @return      обратное value⁻¹ mod q по малой теореме Ферма: value^(q − 2) mod q
	 *
	 */
	static constexpr uint32_t invertQ(const uint32_t value) noexcept {
		uint64_t result = 1, base = value;
		uint64_t power = (Q - 2);
		while(power != 0){
			if((power & 1) != 0)
				result = ((result * base) % Q);
			base = ((base * base) % Q);
			power >>= 1;
		}
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
		 * @brief Метод вычисления таблиц из определения стандарта
		 *
		 * @details ζ = 1753 примитивен из единицы степени 512 (ζ^256 ≡ −1 по q);
		 *          степени записываются в порядке битового переворота восьми разрядов,
		 *          прямое и обратное NTT читают одну таблицу вперёд и назад
		 *
		 */
		constexpr Zetas() noexcept : forward{}, factor(0) {
			// Степени по порядку битового переворота, в форме Монтгомери
			for(size_t i = 0; i < N; i++){
				// Показатель степени: битовый переворот индекса
				size_t power = 0;
				for(size_t bit = 0; bit < 8; bit++)
					power |= (((i >> bit) & 1) << (7 - bit));
				// Степень корня возведением
				uint64_t value = 1;
				for(size_t j = 0; j < power; j++)
					value = ((value * 1753) % Q);
				forward[i] = static_cast <uint32_t> ((value << 32) % Q);
			}
			// Множитель 2^56 mod q = 41 978
			uint64_t scale = 1;
			for(size_t i = 0; i < 56; i++)
				scale = ((scale << 1) % Q);
			factor = static_cast <uint32_t> (scale);
		}
	};

	/**
	 * Таблицы степеней корня, порождаются один раз на процесс
	 */
	static constexpr Zetas ZETAS;

	static_assert((static_cast <uint64_t> (ZETAS.factor) * 256) % Q == ((static_cast <uint64_t> (MONT) * MONT) % Q), "итоговый масштаб обратного NTT должен быть 2^56 mod q");

	/**
	 * @brief Метод прямого NTT многочлена
	 *
	 * @param poly многочлен, переводится в область NTT на месте
	 *
	 */
	static void forward(int32_t * poly) noexcept {
		// Позиция степени в таблице
		size_t index = 0;
		// Слои уменьшающейся длины: бабочка Кули-Тьюки без переноса между слоями
		for(size_t length = (N / 2); length > 0; length >>= 1){
			for(size_t start = 0; start < N; start += (2 * length)){
				// Степень слоя
				const int32_t zeta = static_cast <int32_t> (ZETAS.forward[++index]);
				for(size_t i = start; i < (start + length); i++){
					// Произведение пары на степень слоя
					const int32_t term = multiply(zeta, poly[i + length]);
					poly[i + length] = (poly[i] - term);
					poly[i] += term;
				}
			}
		}
	}

	/**
	 * @brief Метод обратного NTT многочлена
	 *
	 * @param poly многочлен из области NTT, переводится в обычную форму на месте
	 *
	 * @details Прямая таблица степеней читается задом наперёд: степень 1753^(256−k)
	 *          есть −1753^(−k), и знак обращает разность бабочки; множитель 2^56
	 *          снимает масштаб 256 обратного NTT и перевод 2⁻³² произведений
	 *
	 */
	static void backward(int32_t * poly) noexcept {
		// Позиция степени в таблице
		size_t index = N;
		// Слои возрастающей длины: бабочка Джентльмена-Санда
		for(size_t length = 1; length < N; length <<= 1){
			for(size_t start = 0; start < N; start += (2 * length)){
				// Степень слоя из прямой таблицы задом наперёд
				const int32_t zeta = (static_cast <int32_t> (Q) - static_cast <int32_t> (ZETAS.forward[--index]));
				for(size_t i = start; i < (start + length); i++){
					// Сумма пары и произведение разности на степень слоя
					const int32_t term = poly[i];
					poly[i] = (term + poly[i + length]);
					poly[i + length] = (term - poly[i + length]);
					poly[i + length] = multiply(zeta, poly[i + length]);
				}
			}
		}
		// Итоговый масштаб 2^56: 256⁻¹ с переводом произведений из формы 2⁻³² в обычную
		for(size_t i = 0; i < N; i++)
			poly[i] = multiply(static_cast <int32_t> (ZETAS.factor), poly[i]);
	}

	/**
	 * @brief Метод произведения многочленов в области NTT по коэффициентам
	 *
	 * @param first  первый сомножитель в области
	 * @param second второй сомножитель в области
	 * @param result произведение в области
	 *
	 */
	static void pointwise(const int32_t * first, const int32_t * second, int32_t * result) noexcept {
		for(size_t i = 0; i < N; i++)
			result[i] = multiply(first[i], second[i]);
	}

	/**
	 * @brief Метод нормализации коэффициентов многочлена к [0, q)
	 *
	 * @param poly многочлен, нормализуется на месте
	 *
	 * @details Выход обратного NTT уже в обычной форме: дополнительное приведение
	 *          Монтгомери здесь неуместно, оно масштабировало бы значения на 2⁻³²
	 *
	 */
	static void reduceAll(int32_t * poly) noexcept {
		for(size_t i = 0; i < N; i++){
			const int32_t value = (poly[i] % static_cast <int32_t> (Q));
			poly[i] = (value + ((value >> 31) & static_cast <int32_t> (Q)));
		}
	}

	/**
	 * @brief Метод суммы многочленов по коэффициентам
	 *
	 * @param first  первое слагаемое
	 * @param second второе слагаемое
	 * @param result сумма
	 *
	 */
	static void add(const int32_t * first, const int32_t * second, int32_t * result) noexcept {
		for(size_t i = 0; i < N; i++)
			result[i] = (first[i] + second[i]);
	}

	/**
	 * @brief Метод разности многочленов по коэффициентам
	 *
	 * @param first  уменьшаемое
	 * @param second вычитаемое
	 * @param result разность
	 *
	 */
	static void subtract(const int32_t * first, const int32_t * second, int32_t * result) noexcept {
		for(size_t i = 0; i < N; i++)
			result[i] = (first[i] - second[i]);
	}

	/**
	 * @brief Параметры наборов стандарта (раздел 4 FIPS 204)
	 *
	 */
	struct Params {
		// Размерность матрицы: строки k
		uint8_t k;
		// Размерность матрицы: столбцы l
		uint8_t l;
		// Граница коэффициентов секрета η
		uint8_t eta;
		// Число единиц вызова τ
		uint8_t tau;
		// Порог отклонения β = τ · η
		uint16_t beta;
		// Граница маски γ1
		uint32_t gamma1;
		// Граница младших частей γ2
		uint32_t gamma2;
		// Верхний вес подсказки ω
		uint8_t omega;
		// Размер зерна вызова c~ в байтах (λ/4)
		uint8_t challenge;
	};

	/**
	 * @brief Метод получения параметров набора
	 *
	 * @param set набор параметров
	 *
	 * @return    параметры набора, нули у несуществующего набора
	 *
	 */
	static Params params(const sign::Mldsa::set_t set) noexcept {
		switch(set){
			case sign::Mldsa::set_t::DSA44: return {4, 4, 2, 39, 78, (1u << 17), ((Q - 1) / 88), 80, 32};
			case sign::Mldsa::set_t::DSA65: return {6, 5, 4, 49, 196, (1u << 19), ((Q - 1) / 32), 55, 48};
			case sign::Mldsa::set_t::DSA87: return {8, 7, 2, 60, 120, (1u << 19), ((Q - 1) / 32), 75, 64};
			default: return {0, 0, 0, 0, 0, 0, 0, 0, 0};
		}
	}

	/**
	 * @brief Метод отклоняющей выборки многочлена матрицы в области NTT
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
		xof.update(view_t(rho, 32));
		const uint8_t indices[2] = {column, row};
		xof.update(view_t(indices, sizeof(indices)));
		// Число набранных коэффициентов
		size_t count = 0;
		// Поток выжимается блоками по 168 байтов (56 троек): тройки не рвутся по краям
		uint8_t block[168];
		while(count < N){
			// Выжимаем очередной блок
			if(!xof.squeeze(block, sizeof(block))){
				count = 0;
				break;
			}
			// Разбираем тройки байтов: старший разряд третьего байта обнуляется, коэффициент берётся, пока меньше q
			for(size_t i = 0; (i < sizeof(block)) && (count < N); i += 3){
				const uint32_t value = ((static_cast <uint32_t> (block[i])) | (static_cast <uint32_t> (block[i + 1]) << 8) | ((static_cast <uint32_t> (block[i + 2]) & 0x7F) << 16));
				// Коэффициент из 23 разрядов без отклонения, если меньше модуля
				if(value < Q)
					poly[count++] = static_cast <int32_t> (value);
			}
		}
		// Затираем рабочий блок потока
		sys::wipe(block, sizeof(block));
		(void) count;
	}

	/**
	 * @brief Метод выборки многочлена секрета с коэффициентами из [−η, η]
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
		xof.update(view_t(rhoprime, 64));
		const uint8_t suffix[2] = {static_cast <uint8_t> (nonce & 0xFF), static_cast <uint8_t> (nonce >> 8)};
		xof.update(view_t(suffix, sizeof(suffix)));
		// Число набранных коэффициентов
		size_t count = 0;
		// Поток выжимается блоками по 136 байтов (68 полубайтовых пар при η = 2 и 34 при η = 4)
		uint8_t block[136];
		while(count < N){
			if(!xof.squeeze(block, sizeof(block))){
				count = 0;
				break;
			}
			// Разбираем полубайты: при η = 2 коэффициент из mod 5 с отклонением 15, при η = 4 - с отклонением от девяти
			for(size_t i = 0; (i < sizeof(block)) && (count < N); i++){
				for(size_t half = 0; (half < 2) && (count < N); half++){
					const uint32_t value = ((half == 0) ? (block[i] & 0x0F) : (block[i] >> 4));
					if(eta == 2){
						// Коэффициент равномерный из [−2, 2]: 2 − (value mod 5), полубайт 15 отклоняется
						if(value < 15)
							poly[count++] = (2 - static_cast <int32_t> (value % 5));
					} else if(value < 9){
						// Коэффициент равномерный из [−4, 4]: 4 − value
						poly[count++] = (4 - static_cast <int32_t> (value));
					}
				}
			}
		}
		// Затираем рабочий блок потока
		sys::wipe(block, sizeof(block));
	}

	/**
	 * @brief Метод выборки маски подписи с коэффициентами из (−γ1, γ1]
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
		xof.update(view_t(rhodbl, 64));
		const uint8_t suffix[2] = {static_cast <uint8_t> (nonce & 0xFF), static_cast <uint8_t> (nonce >> 8)};
		xof.update(view_t(suffix, sizeof(suffix)));
		// Число набранных коэффициентов
		size_t count = 0;
		if(gamma1 == (1u << 17)){
			// Поток выжимается блоками по 144 байта (16 девяток по четыре коэффициента на 18 разрядов)
			uint8_t block[144];
			while(count < N){
				if(!xof.squeeze(block, sizeof(block))){
					count = 0;
					break;
				}
				for(size_t i = 0; (i < sizeof(block)) && (count < N); i += 9){
					// Девять байтов дают четыре коэффициента по 18 разрядов подряд
					const uint64_t window = ((static_cast <uint64_t> (block[i])) | (static_cast <uint64_t> (block[i + 1]) << 8) | (static_cast <uint64_t> (block[i + 2]) << 16) | (static_cast <uint64_t> (block[i + 3]) << 24) | (static_cast <uint64_t> (block[i + 4]) << 32) | (static_cast <uint64_t> (block[i + 5]) << 40) | (static_cast <uint64_t> (block[i + 6]) << 48) | (static_cast <uint64_t> (block[i + 7]) << 56));
					poly[count++] = static_cast <int32_t> (gamma1 - (static_cast <uint32_t> (window & 0x3FFFF)));
					poly[count++] = static_cast <int32_t> (gamma1 - (static_cast <uint32_t> ((window >> 18) & 0x3FFFF)));
					poly[count++] = static_cast <int32_t> (gamma1 - (static_cast <uint32_t> ((window >> 36) & 0x3FFFF)));
					poly[count++] = static_cast <int32_t> (gamma1 - (static_cast <uint32_t> (((window >> 54) | (static_cast <uint64_t> (block[i + 8]) << 10)) & 0x3FFFF)));
				}
			}
			sys::wipe(block, sizeof(block));
		} else {
			// Поток выжимается блоками по 160 байтов (64 пятёрки на две по 20 разрядов)
			uint8_t block[160];
			while(count < N){
				if(!xof.squeeze(block, sizeof(block))){
					count = 0;
					break;
				}
				for(size_t i = 0; (i < sizeof(block)) && (count + 1 < N); i += 5){
					// Пять байтов дают два коэффициента по 20 разрядов
					const uint64_t window = ((static_cast <uint64_t> (block[i])) | (static_cast <uint64_t> (block[i + 1]) << 8) | (static_cast <uint64_t> (block[i + 2]) << 16) | (static_cast <uint64_t> (block[i + 3]) << 24) | (static_cast <uint64_t> (block[i + 4]) << 32));
					poly[count++] = static_cast <int32_t> (gamma1 - (static_cast <uint32_t> (window & 0xFFFFF)));
					poly[count++] = static_cast <int32_t> (gamma1 - (static_cast <uint32_t> ((window >> 20) & 0xFFFFF)));
				}
			}
			sys::wipe(block, sizeof(block));
		}
		(void) count;
	}

	/**
	 * @brief Метод выборки вызова из шара с τ единицами
	 *
	 * @param seed  зерно вызова c~
	 * @param size  размер зерна в байтах (λ/4)
	 * @param tau   число единиц вызова τ
	 * @param poly  многочлен вызова с τ коэффициентами ±1
	 *
	 */
	static void sampleInBall(const uint8_t * seed, const size_t size, const uint8_t tau, int32_t * poly) noexcept {
		// Поток SHAKE256 над зерном вызова
		digest::keccak_t xof(digest::sha3_t::SHAKE256);
		xof.update(view_t(seed, size));
		// Знаки первых восьми байтов потока
		uint8_t signs[8];
		(void) xof.squeeze(signs, sizeof(signs));
		uint64_t bits = 0;
		for(size_t i = 0; i < sizeof(signs); i++)
			bits |= (static_cast <uint64_t> (signs[i]) << (8 * i));
		// Обнуляем многочлен вызова
		for(size_t i = 0; i < N; i++)
			poly[i] = 0;
		// Позиции единиц выбираются от индекса N − τ к старшим (алгоритм 29 FIPS 204)
		size_t i = (N - tau);
		uint8_t buffer[32];
		size_t used = sizeof(buffer);
		while(i < N){
			// Дочитываем поток порциями
			if(used == sizeof(buffer)){
				(void) xof.squeeze(buffer, sizeof(buffer));
				used = 0;
			}
			// Позиция из очередного байта, отклоняется большая текущей
			const size_t j = buffer[used++];
			if(j <= i){
				// Переносим прежнее значение и пишем единицу со знаком
				poly[i] = poly[j];
				poly[j] = (((bits & 1) != 0) ? -1 : 1);
				bits >>= 1;
				i++;
			}
		}
		// Затираем рабочие значения выбора
		sys::wipe(signs, sizeof(signs));
		sys::wipe(buffer, sizeof(buffer));
	}

	/**
	 * @brief Метод разложения коэффициента на старшую и младшую части
	 *
	 * @param value  коэффициент в [0, q)
	 * @param gamma2 граница младшей части γ2
	 * @param low    младшая часть из (−γ2, γ2]
	 *
	 * @return       старшая часть из [0, (q − 1)/(2γ2) − 1]
	 *
	 */
	static int32_t decompose(const int32_t value, const uint32_t gamma2, int32_t & low) noexcept {
		// Старшая часть округлением к ближайшему кратному 2γ2
		int32_t high = ((value + 127) >> 7);
		if(gamma2 == ((Q - 1) / 32)){
			// (q − 1)/32: точное умножение на 2^10/γ2 с округлением, старшая часть в [0, 15]
			high = (((high * 1025) + (1 << 21)) >> 22);
			high &= 15;
		} else {
			// (q − 1)/88: точное умножение на 2^12/γ2 с округлением, старшая часть в [0, 43] с обращением 44 в 0
			high = (((high * 11275) + (1 << 23)) >> 24);
			high ^= (((43 - high) >> 31) & high);
		}
		// Младшая часть в (−γ2, γ2] с обращением края модуля
		low = (value - (high * static_cast <int32_t> (2 * gamma2)));
		low -= ((((static_cast <int32_t> (Q) - 1) / 2 - low) >> 31) & static_cast <int32_t> (Q));
		return high;
	}

	/**
	 * @brief Метод округления коэффициента на два разряда: t1 = (t + 2^12) >> 13, t0 = t − t1 · 2^13
	 *
	 * @param value коэффициент в [0, q)
	 * @param low   младшая часть t0 из (−2^12, 2^12]
	 *
	 * @return      старшая часть t1 из [0, 2^10)
	 *
	 */
	static int32_t power2round(const int32_t value, int32_t & low) noexcept {
		const int32_t high = ((value + ((1 << 12) - 1)) >> 13);
		low = (value - (high << 13));
		return high;
	}

	/**
	 * @brief Метод применения подсказки к коэффициенту
	 *
	 * @param value коэффициент w′ в [0, q)
	 * @param hint  бит подсказки
	 *
	 * @return      скорректированная старшая часть из [0, (q − 1)/(2γ2) − 1]
	 *
	 */
	static int32_t useHint(const int32_t value, const uint32_t hint, const uint32_t gamma2) noexcept {
		int32_t low = 0;
		const int32_t high = decompose(value, gamma2, low);
		if(hint == 0)
			return high;
		if(gamma2 == ((Q - 1) / 32))
			return ((low > 0) ? ((high + 1) & 15) : ((high - 1) & 15));
		return ((low > 0) ? ((high == 43) ? 0 : (high + 1)) : ((high == 0) ? 43 : (high - 1)));
	}

	/**
	 * @brief Метод записи многочлена разрядностью bits на коэффициент
	 *
	 * @param poly   многочлен со значениями из [0, 2^bits)
	 * @param bits   разрядность коэффициента
	 * @param result место записи
	 *
	 */
	static void bitpack(const uint32_t * poly, const size_t bits, uint8_t * result) noexcept {
		// Накопитель разрядов
		uint64_t window = 0;
		size_t used = 0;
		for(size_t i = 0; i < N; i++){
			window |= (static_cast <uint64_t> (poly[i]) << used);
			used += bits;
			while(used >= 8){
				*result++ = static_cast <uint8_t> (window);
				window >>= 8;
				used -= 8;
			}
		}
	}

	/**
	 * @brief Метод чтения многочлена разрядностью bits на коэффициент
	 *
	 * @param data запись
	 * @param bits разрядность коэффициента
	 * @param poly многочлен со значениями из [0, 2^bits)
	 *
	 */
	static void bitunpack(const uint8_t * data, const size_t bits, uint32_t * poly) noexcept {
		uint64_t window = 0;
		size_t used = 0;
		for(size_t i = 0; i < N; i++){
			while(used < bits){
				window |= (static_cast <uint64_t> (*data++) << used);
				used += 8;
			}
			poly[i] = static_cast <uint32_t> (window & ((static_cast <uint64_t> (1) << bits) - 1));
			window >>= bits;
			used -= bits;
		}
	}

	/**
	 * @brief Метод записи многочлена t1 разрядностью 10 на коэффициент
	 *
	 * @param poly   многочлен t1
	 * @param result место записи, 320 байтов
	 *
	 */
	static void packT1(const int32_t * poly, uint8_t * result) noexcept {
		uint32_t work[N];
		for(size_t i = 0; i < N; i++)
			work[i] = static_cast <uint32_t> (poly[i]);
		bitpack(work, 10, result);
		sys::wipe(work, sizeof(work));
	}

	/**
	 * @brief Метод чтения многочлена t1 разрядностью 10 на коэффициент
	 *
	 * @param data запись t1, 320 байтов
	 * @param poly многочлен t1
	 *
	 */
	static void unpackT1(const uint8_t * data, int32_t * poly) noexcept {
		uint32_t work[N];
		bitunpack(data, 10, work);
		for(size_t i = 0; i < N; i++)
			poly[i] = static_cast <int32_t> (work[i]);
		sys::wipe(work, sizeof(work));
	}

	/**
	 * @brief Метод записи многочлена t0 разрядностью 13 на коэффициент
	 *
	 * @param poly   многочлен t0 с коэффициентами из (−2^12, 2^12]
	 * @param result место записи, 416 байтов
	 *
	 */
	static void packT0(const int32_t * poly, uint8_t * result) noexcept {
		uint32_t work[N];
		for(size_t i = 0; i < N; i++)
			work[i] = static_cast <uint32_t> ((1 << 12) - poly[i]);
		bitpack(work, 13, result);
		sys::wipe(work, sizeof(work));
	}

	/**
	 * @brief Метод чтения многочлена t0 разрядностью 13 на коэффициент
	 *
	 * @param data запись t0, 416 байтов
	 * @param poly многочлен t0
	 *
	 */
	static void unpackT0(const uint8_t * data, int32_t * poly) noexcept {
		uint32_t work[N];
		bitunpack(data, 13, work);
		for(size_t i = 0; i < N; i++)
			poly[i] = static_cast <int32_t> ((1 << 12) - work[i]);
		sys::wipe(work, sizeof(work));
	}

	/**
	 * @brief Метод записи многочлена секрета разрядностью 3 либо 4 на коэффициент
	 *
	 * @param poly   многочлен секрета с коэффициентами из [−η, η]
	 * @param eta    граница коэффициентов η
	 * @param result место записи
	 *
	 */
	static void packS(const int32_t * poly, const uint8_t eta, uint8_t * result) noexcept {
		uint32_t work[N];
		for(size_t i = 0; i < N; i++)
			work[i] = static_cast <uint32_t> (eta - poly[i]);
		bitpack(work, ((eta == 2) ? 3 : 4), result);
		sys::wipe(work, sizeof(work));
	}

	/**
	 * @brief Метод чтения многочлена секрета
	 *
	 * @param data запись секрета
	 * @param eta  граница коэффициентов η
	 * @param poly многочлен секрета
	 *
	 * @return     признак кода записи за границей 2η (гнилая запись ключа)
	 *
	 */
	static uint32_t unpackS(const uint8_t * data, const uint8_t eta, int32_t * poly) noexcept {
		// Признак гнилой записи: коды выше 2η из выборки стандарта не выходят
		uint32_t reject = 0;
		uint32_t work[N];
		bitunpack(data, ((eta == 2) ? 3 : 4), work);
		for(size_t i = 0; i < N; i++){
			reject |= static_cast <uint32_t> ((work[i] > (2u * eta)) ? 1 : 0);
			poly[i] = static_cast <int32_t> (eta - work[i]);
		}
		sys::wipe(work, sizeof(work));
		// Выводим признак гнилой записи
		return reject;
	}

	/**
	 * @brief Метод записи многочлена ответа z
	 *
	 * @param poly   многочлен ответа с коэффициентами из (−γ1, γ1]
	 * @param gamma1 граница маски γ1
	 * @param result место записи
	 *
	 */
	static void packZ(const int32_t * poly, const uint32_t gamma1, uint8_t * result) noexcept {
		uint32_t work[N];
		for(size_t i = 0; i < N; i++)
			work[i] = static_cast <uint32_t> (gamma1 - poly[i]);
		bitpack(work, ((gamma1 == (1u << 17)) ? 18 : 20), result);
		sys::wipe(work, sizeof(work));
	}

	/**
	 * @brief Метод чтения многочлена ответа z
	 *
	 * @param data   запись ответа
	 * @param gamma1 граница маски γ1
	 * @param poly   многочлен ответа
	 *
	 */
	static void unpackZ(const uint8_t * data, const uint32_t gamma1, int32_t * poly) noexcept {
		uint32_t work[N];
		bitunpack(data, ((gamma1 == (1u << 17)) ? 18 : 20), work);
		for(size_t i = 0; i < N; i++)
			poly[i] = static_cast <int32_t> (gamma1 - work[i]);
		sys::wipe(work, sizeof(work));
	}

	/**
	 * @brief Метод кодировки старших частей w1 для зерна вызова
	 *
	 * @param poly   многочлен старших частей
	 * @param gamma2 граница младших частей γ2
	 * @param result место записи
	 *
	 */
	static void encodeW1(const int32_t * poly, const uint32_t gamma2, uint8_t * result) noexcept {
		uint32_t work[N];
		for(size_t i = 0; i < N; i++)
			work[i] = static_cast <uint32_t> (poly[i]);
		bitpack(work, ((gamma2 == ((Q - 1) / 32)) ? 4 : 6), result);
		sys::wipe(work, sizeof(work));
	}

	/**
	 * @brief Метод проверки границы коэффициентов многочлена
	 *
	 * @param poly  многочлен со значениями со знаком
	 * @param bound граница модулей коэффициентов (превышение при равенстве)
	 *
	 * @return      ненольное значение, если модуль какого-то коэффициента не меньше границы
	 *
	 */
	static uint32_t overflow(const int32_t * poly, const int32_t bound) noexcept {
		uint32_t result = 0;
		for(size_t i = 0; i < N; i++){
			// Модуль коэффициента без ветвления
			const int32_t mask = (poly[i] >> 31);
			const int32_t absolute = ((poly[i] ^ mask) - mask);
			result |= static_cast <uint32_t> (((bound - 1) - absolute) >> 31);
		}
		return (result & 1);
	}

	/**
	 * @brief Метод сложения вектора многочленов матрицы с вектором в области NTT
	 *
	 * @param matrix матрица A в области NTT: k строк по l многочленов
	 * @param vector вектор y из l многочленов в области NTT
	 * @param k      строки матрицы
	 * @param l      столбцы матрицы
	 * @param result вектор из k многочленов в области NTT
	 *
	 */
	static void matrixVector(const int32_t * matrix, const int32_t * vector, const uint8_t k, const uint8_t l, int32_t * result) noexcept {
		for(size_t row = 0; row < k; row++){
			// Первое произведение строки
			pointwise(matrix + ((row * l) * N), vector, result + (row * N));
			// Остальные слагаемые строки накапливаются
			for(size_t column = 1; column < l; column++){
				int32_t term[N];
				pointwise(matrix + (((row * l) + column) * N), vector + (column * N), term);
				add(result + (row * N), term, result + (row * N));
				sys::wipe(term, sizeof(term));
			}
		}
	}

	/**
	 * @brief Метод выработки ключа из зерна ξ (раздел 6.1 FIPS 204)
	 *
	 * @param p      параметры набора
	 * @param xi     зерно ξ, тридцать два байта
	 * @param key    место для записи ключа проверки ρ ‖ t1
	 * @param secret место для записи ключа подписи ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0
	 *
	 */
	static void keygen(const Params & p, const uint8_t * xi, uint8_t * key, uint8_t * secret) noexcept {
		// Расширение зерна: (ρ, ρ′, K) = H(ξ ‖ k ‖ l, 128)
		uint8_t expanded[128];
		{
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			xof.update(view_t(xi, 32));
			const uint8_t dimensions[2] = {p.k, p.l};
			xof.update(view_t(dimensions, sizeof(dimensions)));
			(void) xof.squeeze(expanded, sizeof(expanded));
		}
		const uint8_t * rho = expanded;
		const uint8_t * rhoprime = (expanded + 32);
		const uint8_t * kappa = (expanded + 96);
		// Матрица A в области NTT и секретные векторы s1, s2
		int32_t matrix[8][7][N];
		for(size_t row = 0; row < p.k; row++)
			for(size_t column = 0; column < p.l; column++)
				expandA(rho, static_cast <uint8_t> (row), static_cast <uint8_t> (column), matrix[row][column]);
		int32_t s1[7][N], s2[8][N];
		for(size_t i = 0; i < p.l; i++)
			expandS(rhoprime, static_cast <uint16_t> (i), p.eta, s1[i]);
		for(size_t i = 0; i < p.k; i++)
			expandS(rhoprime, static_cast <uint16_t> (p.l + i), p.eta, s2[i]);
		// t = NTT⁻¹(A ∘ NTT(s1)) + s2 по строкам матрицы
		int32_t t[8][N];
		{
			int32_t domain[7][N];
			for(size_t i = 0; i < p.l; i++){
				::memcpy(domain[i], s1[i], sizeof(domain[i]));
				forward(domain[i]);
			}
			for(size_t row = 0; row < p.k; row++){
				pointwise(matrix[row][0], domain[0], t[row]);
				for(size_t column = 1; column < p.l; column++){
					int32_t term[N];
					pointwise(matrix[row][column], domain[column], term);
					add(t[row], term, t[row]);
					sys::wipe(term, sizeof(term));
				}
				backward(t[row]);
				add(t[row], s2[row], t[row]);
				reduceAll(t[row]);
			}
			sys::wipe(domain, sizeof(domain));
		}
		// Разложение t на старшую и младшую части, запись ключа проверки
		int32_t t0[8][N];
		::memcpy(key, rho, 32);
		for(size_t row = 0; row < p.k; row++){
			for(size_t i = 0; i < N; i++)
				t[row][i] = power2round(t[row][i], t0[row][i]);
			packT1(t[row], (key + 32 + (row * 320)));
		}
		// Трассировка открытого ключа: tr = H(ρ ‖ t1, 64)
		uint8_t trace[64];
		{
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			xof.update(view_t(key, (32 + (p.k * 320))));
			(void) xof.squeeze(trace, sizeof(trace));
		}
		// Запись ключа подписи: ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0
		uint8_t * out = secret;
		::memcpy(out, rho, 32);
		out += 32;
		::memcpy(out, kappa, 32);
		out += 32;
		::memcpy(out, trace, 64);
		out += 64;
		for(size_t i = 0; i < p.l; i++){
			packS(s1[i], p.eta, out);
			out += ((p.eta == 2) ? 96 : 128);
		}
		for(size_t i = 0; i < p.k; i++){
			packS(s2[i], p.eta, out);
			out += ((p.eta == 2) ? 96 : 128);
		}
		for(size_t row = 0; row < p.k; row++){
			packT0(t0[row], out);
			out += 416;
		}
		// Затираем рабочие значения секрета
		sys::wipe(expanded, sizeof(expanded));
		sys::wipe(matrix, sizeof(matrix));
		sys::wipe(s1, sizeof(s1));
		sys::wipe(s2, sizeof(s2));
		sys::wipe(t, sizeof(t));
		sys::wipe(t0, sizeof(t0));
		sys::wipe(trace, sizeof(trace));
	}

	/**
	 * @brief Метод выработки подписи (раздел 6.2 FIPS 204)
	 *
	 * @param p       параметры набора
	 * @param secret  запись ключа подписи ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0
	 * @param rnd     случайность подписи, тридцать два байта
	 * @param message подписываемое сообщение
	 * @param context контекст подписи
	 * @param result  место для записи подписи c~ ‖ z ‖ h
	 *
	 */
	static void signing(const Params & p, const uint8_t * secret, const uint8_t * rnd, const view_t & message, const view_t & context, uint8_t * result) noexcept {
		const uint8_t * rho = secret;
		const uint8_t * kappa = (secret + 32);
		const uint8_t * trace = (secret + 64);
		// Вычисляемое сообщение μ = H(tr ‖ 0x00 ‖ длина контекста ‖ контекст ‖ сообщение, 64)
		uint8_t mu[64];
		{
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			xof.update(view_t(trace, 64));
			const uint8_t prefix[2] = {0, static_cast <uint8_t> (context.size)};
			xof.update(view_t(prefix, sizeof(prefix)));
			xof.update(context);
			xof.update(message);
			(void) xof.squeeze(mu, sizeof(mu));
		}
		// Случайность маски: ρ″ = H(K ‖ rnd ‖ μ, 64)
		uint8_t rhodbl[64];
		{
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			xof.update(view_t(kappa, 32));
			xof.update(view_t(rnd, 32));
			xof.update(view_t(mu, sizeof(mu)));
			(void) xof.squeeze(rhodbl, sizeof(rhodbl));
		}
		// Распаковка секретов в область NTT
		const uint8_t * packed = (secret + 128);
		int32_t s1[7][N], s2[8][N], t0[8][N];
		for(size_t i = 0; i < p.l; i++){
			(void) unpackS(packed, p.eta, s1[i]);
			packed += ((p.eta == 2) ? 96 : 128);
			forward(s1[i]);
		}
		for(size_t i = 0; i < p.k; i++){
			(void) unpackS(packed, p.eta, s2[i]);
			packed += ((p.eta == 2) ? 96 : 128);
			forward(s2[i]);
		}
		for(size_t i = 0; i < p.k; i++){
			unpackT0(packed, t0[i]);
			packed += 416;
			forward(t0[i]);
		}
		// Матрица A в области NTT строится заново из ρ (укладка строк подряд по l многочленов)
		int32_t matrix[8 * 7 * N];
		for(size_t row = 0; row < p.k; row++)
			for(size_t column = 0; column < p.l; column++)
				expandA(rho, static_cast <uint8_t> (row), static_cast <uint8_t> (column), matrix + (((row * p.l) + column) * N));
		// Счётчик попыток подписи
		uint16_t attempt = 0;
		// Признак готовности подписи
		uint32_t ready = 0;
		while(ready == 0){
			// Маска y из l многочленов в обычной форме и её образ в области NTT
			int32_t y[7][N], domain[7][N];
			for(size_t i = 0; i < p.l; i++){
				expandMask(rhodbl, static_cast <uint16_t> ((attempt * p.l) + i), p.gamma1, y[i]);
				::memcpy(domain[i], y[i], sizeof(domain[i]));
				forward(domain[i]);
			}
			// w = NTT⁻¹(A ∘ NTT(y)) по строкам матрицы
			int32_t w[8][N];
			matrixVector(matrix, domain[0], p.k, p.l, w[0]);
			for(size_t row = 0; row < p.k; row++){
				backward(w[row]);
				reduceAll(w[row]);
			}
			// Старшие части w и зерно вызова c~ = H(μ ‖ w1Encode(w1), λ/4): w сохраняется
			uint8_t challenge[64];
			size_t w1size = 0;
			{
				uint8_t encoded[8][192];
				for(size_t row = 0; row < p.k; row++){
					int32_t low = 0, w1[N];
					for(size_t i = 0; i < N; i++)
						w1[i] = decompose(w[row][i], p.gamma2, low);
					encodeW1(w1, p.gamma2, encoded[row]);
					sys::wipe(w1, sizeof(w1));
				}
				w1size = ((p.gamma2 == ((Q - 1) / 32)) ? 128 : 192);
				digest::keccak_t xof(digest::sha3_t::SHAKE256);
				xof.update(view_t(mu, sizeof(mu)));
				for(size_t row = 0; row < p.k; row++)
					xof.update(view_t(encoded[row], w1size));
				(void) xof.squeeze(challenge, p.challenge);
				sys::wipe(encoded, sizeof(encoded));
			}
			// Вызов c из шара
			int32_t c[N];
			sampleInBall(challenge, p.challenge, p.tau, c);
			forward(c);
			// z = y + c·s1 в свободной форме: суммы малы и в приведении не нуждаются
			int32_t z[7][N];
			for(size_t i = 0; i < p.l; i++){
				int32_t term[N];
				pointwise(c, s1[i], term);
				backward(term);
				add(y[i], term, z[i]);
				sys::wipe(term, sizeof(term));
			}
			// Отказ по границе ‖z‖∞ ≥ γ1 − β
			uint32_t reject = 0;
			for(size_t i = 0; i < p.l; i++)
				reject |= overflow(z[i], static_cast <int32_t> (p.gamma1 - p.beta));
			// Младшие части r0, произведение c·t0 и подсказка одним проходом по строкам
			int32_t hints[8][N];
			int32_t r0[8][N];
			for(size_t row = 0; row < p.k; row++){
				int32_t term[N], ct0[N];
				pointwise(c, s2[row], term);
				backward(term);
				pointwise(c, t0[row], ct0);
				backward(ct0);
				// Отказ по границе ‖c·t0‖∞ ≥ γ2
				reject |= overflow(ct0, static_cast <int32_t> (p.gamma2));
				for(size_t i = 0; i < N; i++){
					// Разность w − c·s2 в записи модуля и её разложение
					const int32_t value = ((((w[row][i] - term[i]) % static_cast <int32_t> (Q)) + Q) % static_cast <int32_t> (Q));
					int32_t low = 0;
					const int32_t high1 = decompose(value, p.gamma2, low);
					r0[row][i] = low;
					// Подсказка: старшая часть меняется от добавления c·t0
					const int32_t corrected = ((((value + ct0[i]) % static_cast <int32_t> (Q)) + Q) % static_cast <int32_t> (Q));
					int32_t low2 = 0;
					const int32_t high2 = decompose(corrected, p.gamma2, low2);
					hints[row][i] = ((high1 != high2) ? 1 : 0);
				}
				sys::wipe(term, sizeof(term));
				sys::wipe(ct0, sizeof(ct0));
			}
			// Отказ по границе ‖r0‖∞ ≥ γ2 − β
			for(size_t row = 0; row < p.k; row++)
				reject |= overflow(r0[row], static_cast <int32_t> (p.gamma2 - p.beta));
			// Отказ по весу подсказки
			uint32_t weight = 0;
			for(size_t row = 0; row < p.k; row++){
				uint32_t rowweight = 0;
				for(size_t i = 0; i < N; i++)
					rowweight += static_cast <uint32_t> (hints[row][i]);
				weight += rowweight;
			}
			reject |= static_cast <uint32_t> ((weight > p.omega) ? 1 : 0);
			if(reject == 0){
				// Запись подписи: c~ ‖ z ‖ h
				uint8_t * out = result;
				::memcpy(out, challenge, p.challenge);
				out += p.challenge;
				for(size_t i = 0; i < p.l; i++){
					packZ(z[i], p.gamma1, out);
					out += ((p.gamma1 == (1u << 17)) ? 576 : 640);
				}
				// Подсказка: индексы единиц по порядку, затем счётчики по многочленам
				size_t position = 0;
				for(size_t row = 0; row < p.k; row++){
					for(size_t i = 0; i < N; i++){
						if(hints[row][i] != 0){
							if(position < p.omega)
								out[position] = static_cast <uint8_t> (i);
							position++;
						}
					}
					if(row + 1 < p.k)
						out[p.omega + row] = static_cast <uint8_t> (position);
				}
				// Незаполненные индексы и последний счётчик
				for(size_t i = position; i < p.omega; i++)
					out[i] = 0;
				out[p.omega + (p.k - 1)] = static_cast <uint8_t> (position);
				ready = 1;
			}
			// Затираем значения попытки перед следующей
			sys::wipe(y, sizeof(y));
			sys::wipe(domain, sizeof(domain));
			sys::wipe(w, sizeof(w));
			sys::wipe(c, sizeof(c));
			sys::wipe(z, sizeof(z));
			sys::wipe(r0, sizeof(r0));
			sys::wipe(hints, sizeof(hints));
			attempt++;
		}
		// Затираем рабочие значения секрета
		sys::wipe(mu, sizeof(mu));
		sys::wipe(rhodbl, sizeof(rhodbl));
		sys::wipe(s1, sizeof(s1));
		sys::wipe(s2, sizeof(s2));
		sys::wipe(t0, sizeof(t0));
		sys::wipe(matrix, sizeof(matrix));
	}

	/**
	 * @brief Метод проверки подписи (раздел 6.3 FIPS 204)
	 *
	 * @param p         параметры набора
	 * @param key       запись ключа проверки ρ ‖ t1
	 * @param message   подписанное сообщение
	 * @param context   контекст подписи
	 * @param signature проверяемая подпись c~ ‖ z ‖ h
	 *
	 * @return          признак того, что подпись сошлась
	 *
	 */
	static bool checking(const Params & p, const uint8_t * key, const view_t & message, const view_t & context, const uint8_t * signature) noexcept {
		const uint8_t * rho = key;
		// Трассировка ключа проверки: tr = H(ρ ‖ t1, 64)
		uint8_t trace[64];
		{
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			xof.update(view_t(key, (32 + (p.k * 320))));
			(void) xof.squeeze(trace, sizeof(trace));
		}
		// Вычисляемое сообщение μ = H(tr ‖ 0x00 ‖ длина контекста ‖ контекст ‖ сообщение, 64)
		uint8_t mu[64];
		{
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			xof.update(view_t(trace, sizeof(trace)));
			const uint8_t prefix[2] = {0, static_cast <uint8_t> (context.size)};
			xof.update(view_t(prefix, sizeof(prefix)));
			xof.update(context);
			xof.update(message);
			(void) xof.squeeze(mu, sizeof(mu));
		}
		// Разбор подписи: c~, z и подсказка
		const uint8_t * challenge = signature;
		const uint8_t * packed = (signature + p.challenge);
		int32_t z[7][N];
		uint32_t reject = 0;
		for(size_t i = 0; i < p.l; i++){
			unpackZ(packed, p.gamma1, z[i]);
			packed += ((p.gamma1 == (1u << 17)) ? 576 : 640);
			// Ответ за границей γ1 − β отвергается
			reject |= overflow(z[i], static_cast <int32_t> (p.gamma1 - p.beta));
			forward(z[i]);
		}
		// Разбор подсказки: индексы и счётчики
		const uint8_t * indices = packed;
		int32_t hints[8][N];
		size_t position = 0;
		uint32_t malformed = 0;
		for(size_t row = 0; row < p.k; row++){
			for(size_t i = 0; i < N; i++)
				hints[row][i] = 0;
			// Предел индексов многочлена: накопленный счётчик
			const size_t bound = ((row + 1 < p.k) ? indices[p.omega + row] : indices[p.omega + (p.k - 1)]);
			size_t last = 0;
			for(size_t j = position; j < bound; j++){
				// Индексы обязаны возрастать и не превышать ω
				if(j >= p.omega){
					malformed = 1;
					break;
				}
				const uint8_t index = indices[j];
				if((j > position) && (index <= last))
					malformed = 1;
				last = index;
				hints[row][index] = 1;
			}
			position = bound;
		}
		// Остаток индексов обязан быть нулевым
		for(size_t j = position; j < p.omega; j++)
			malformed |= static_cast <uint32_t> (indices[j]);
		reject |= malformed;
		// Вызов c из шара
		int32_t c[N];
		sampleInBall(challenge, p.challenge, p.tau, c);
		forward(c);
		// w′ = NTT⁻¹(A ∘ NTT(z) − c ∘ NTT(t1 · 2^13)) по строкам матрицы
		int32_t w[8][N];
		{
			// Матрица из ρ ключа (укладка строк подряд по l многочленов)
			int32_t matrix[8 * 7 * N];
			for(size_t row = 0; row < p.k; row++)
				for(size_t column = 0; column < p.l; column++)
					expandA(rho, static_cast <uint8_t> (row), static_cast <uint8_t> (column), matrix + (((row * p.l) + column) * N));
			matrixVector(matrix, z[0], p.k, p.l, w[0]);
			sys::wipe(matrix, sizeof(matrix));
		}
		for(size_t row = 0; row < p.k; row++){
			int32_t term[N];
			unpackT1((key + 32 + (row * 320)), term);
			// t1 · 2^13 простым масштабом коэффициентов перед переходом в область
			for(size_t i = 0; i < N; i++)
				term[i] <<= 13;
			forward(term);
			// Вычитание c ∘ NTT(t1 · 2^13) из произведения матрицы в области NTT
			int32_t product[N];
			pointwise(c, term, product);
			subtract(w[row], product, w[row]);
			backward(w[row]);
			reduceAll(w[row]);
			sys::wipe(term, sizeof(term));
			sys::wipe(product, sizeof(product));
		}
		// Старшие части по подсказке и зерно вызова заново
		uint8_t expected[64];
		size_t w1size = 0;
		{
			uint8_t encoded[8][192];
			for(size_t row = 0; row < p.k; row++){
				for(size_t i = 0; i < N; i++)
					w[row][i] = useHint(w[row][i], static_cast <uint32_t> (hints[row][i]), p.gamma2);
				encodeW1(w[row], p.gamma2, encoded[row]);
			}
			w1size = ((p.gamma2 == ((Q - 1) / 32)) ? 128 : 192);
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			xof.update(view_t(mu, sizeof(mu)));
			for(size_t row = 0; row < p.k; row++)
				xof.update(view_t(encoded[row], w1size));
			(void) xof.squeeze(expected, p.challenge);
			sys::wipe(encoded, sizeof(encoded));
		}
		// Сравнение зерна вызова за постоянное время
		uint8_t difference = 0;
		for(size_t i = 0; i < p.challenge; i++)
			difference |= static_cast <uint8_t> (expected[i] ^ challenge[i]);
		// Затираем рабочие значения
		sys::wipe(trace, sizeof(trace));
		sys::wipe(mu, sizeof(mu));
		sys::wipe(z, sizeof(z));
		sys::wipe(c, sizeof(c));
		sys::wipe(w, sizeof(w));
		sys::wipe(hints, sizeof(hints));
		sys::wipe(expected, sizeof(expected));
		return ((reject == 0) && (difference == 0));
	}

	/**
	 * @brief Метод проверки подлинности записи ключа подписи и вывода ключа проверки
	 *
	 * @param p      параметры набора
	 * @param secret запись ключа подписи ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0
	 * @param key    место для записи ключа проверки ρ ‖ t1 (при подлинной записи)
	 *
	 * @return       признак того, что трассировка tr сошлась с пересчитанной из частей записи
	 *
	 * @details Раздел 6.1 FIPS 204 вычисляется из ρ и распакованных s1, s2:
	 *          t = NTT⁻¹(A ∘ NTT(s1)) + s2, далее t1 = Power2Round(t) и
	 *          tr′ = H(ρ ‖ t1) сличается с записанной трассировкой
	 *
	 */
	static bool consistent(const Params & p, const uint8_t * secret, uint8_t * key) noexcept {
		const uint8_t * rho = secret;
		const uint8_t * trace = (secret + 64);
		const uint8_t * packed = (secret + 128);
		// Распаковка секретных векторов из записи с контролем кодов за границей 2η
		uint32_t malformed = 0;
		int32_t s1[7][N], s2[8][N];
		for(size_t i = 0; i < p.l; i++){
			malformed |= unpackS(packed, p.eta, s1[i]);
			packed += ((p.eta == 2) ? 96 : 128);
		}
		for(size_t i = 0; i < p.k; i++){
			malformed |= unpackS(packed, p.eta, s2[i]);
			packed += ((p.eta == 2) ? 96 : 128);
		}
		// t = NTT⁻¹(A ∘ NTT(s1)) + s2 по строкам матрицы из ρ записи
		int32_t t[8][N];
		{
			int32_t domain[7][N], expanded[N];
			for(size_t i = 0; i < p.l; i++){
				::memcpy(domain[i], s1[i], sizeof(domain[i]));
				forward(domain[i]);
			}
			for(size_t row = 0; row < p.k; row++){
				expandA(rho, static_cast <uint8_t> (row), 0, expanded);
				pointwise(expanded, domain[0], t[row]);
				for(size_t column = 1; column < p.l; column++){
					expandA(rho, static_cast <uint8_t> (row), static_cast <uint8_t> (column), expanded);
					int32_t term[N];
					pointwise(expanded, domain[column], term);
					add(t[row], term, t[row]);
					sys::wipe(term, sizeof(term));
				}
				backward(t[row]);
				add(t[row], s2[row], t[row]);
				reduceAll(t[row]);
			}
			sys::wipe(domain, sizeof(domain));
			sys::wipe(expanded, sizeof(expanded));
		}
		// Ключ проверки ρ ‖ t1 и трассировка tr′ = H(ρ ‖ t1)
		uint8_t expected[64];
		{
			int32_t t0[N];
			::memcpy(key, rho, 32);
			for(size_t row = 0; row < p.k; row++){
				for(size_t i = 0; i < N; i++)
					t[row][i] = power2round(t[row][i], t0[i]);
				packT1(t[row], (key + 32 + (row * 320)));
			}
			sys::wipe(t0, sizeof(t0));
			digest::keccak_t xof(digest::sha3_t::SHAKE256);
			xof.update(view_t(key, (32 + (p.k * 320))));
			(void) xof.squeeze(expected, sizeof(expected));
		}
		// Сличаем трассировку с записанной, гнилая запись отвергается
		const bool result = ((malformed == 0) && (::memcmp(expected, trace, sizeof(expected)) == 0));
		// Затираем рабочие значения секрета
		sys::wipe(s1, sizeof(s1));
		sys::wipe(s2, sizeof(s2));
		sys::wipe(t, sizeof(t));
		sys::wipe(expected, sizeof(expected));
		return result;
	}

};

/**
 * Пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Метод получения набора параметров ключа
 *
 * @return набор параметров ключа, NONE без ключа
 *
 */
sign::Mldsa::set_t sign::Mldsa::set() const noexcept {
	// Если ключ не установлен, набора нет
	if(!this->_secret && !this->_public)
		return set_t::NONE;
	// Возвращаем набор параметров ключа
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
		return 0;
	// Возвращаем размер подписи набора
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
		return 0;
	// Подпись уходит наружу записью постоянной длины по набору
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
	// Сбрасываем признаки ключей и набор
	this->_secret = false;
	this->_public = false;
	this->_set = set_t::NONE;
}

/**
 * @brief Метод получения размера ключа подписи набора в байтах
 *
 * @param set набор параметров
 *
 * @return    размер ключа подписи в байтах, ноль у несуществующего набора
 *
 */
size_t sign::Mldsa::secretSize(const set_t set) noexcept {
	switch(set){
		case set_t::DSA44: return 2560;
		case set_t::DSA65: return 4032;
		case set_t::DSA87: return 4896;
		default: return 0;
	}
}

/**
 * @brief Метод получения размера ключа проверки набора в байтах
 *
 * @param set набор параметров
 *
 * @return    размер ключа проверки в байтах, ноль у несуществующего набора
 *
 */
size_t sign::Mldsa::publicSize(const set_t set) noexcept {
	switch(set){
		case set_t::DSA44: return 1312;
		case set_t::DSA65: return 1952;
		case set_t::DSA87: return 2592;
		default: return 0;
	}
}

/**
 * @brief Метод получения размера подписи набора в байтах
 *
 * @param set набор параметров
 *
 * @return    размер подписи в байтах, ноль у несуществующего набора
 *
 */
size_t sign::Mldsa::signatureSize(const set_t set) noexcept {
	switch(set){
		case set_t::DSA44: return 2420;
		case set_t::DSA65: return 3309;
		case set_t::DSA87: return 4627;
		default: return 0;
	}
}

/**
 * @brief Метод порождения долговременного ключа подписи из зерна
 *
 * @param set    набор параметров
 * @param seed   зерно выработки ξ длиной в тридцать два байта
 * @param key    место, в которое помещается ключ проверки ρ ‖ t1
 * @param secret место, в которое помещается ключ подписи ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0
 *
 * @return       признак успешности порождения ключа
 *
 */
bool sign::Mldsa::generate(const set_t set, const view_t & seed, uint8_t * key, uint8_t * secret) noexcept {
	// Результат работы
	bool result = false;
	// Параметры набора существуют и зерно верной длины
	const Params p = params(set);
	if((p.k != 0) && (seed.size == SEED_SIZE)){
		// Вырабатываем ключ из зерна
		keygen(p, static_cast <const uint8_t *> (seed.data), key, secret);
		// Записываем ключи в состояние модуля
		::memcpy(this->_pkey, key, publicSize(set));
		::memcpy(this->_key, secret, secretSize(set));
		this->_set = set;
		this->_secret = true;
		this->_public = true;
		result = true;
	}
	// Выводим признак успешности
	return result;
}

/**
 * @brief Метод порождения долговременного ключа подписи из источника случайности
 *
 * @param set    набор параметров
 * @param key    место, в которое помещается ключ проверки ρ ‖ t1
 * @param secret место, в которое помещается ключ подписи ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0
 *
 * @return       признак успешности порождения ключа
 *
 */
bool sign::Mldsa::generate(const set_t set, uint8_t * key, uint8_t * secret) noexcept {
	// Результат работы
	bool result = false;
	// Параметры набора существуют
	if(params(set).k != 0){
		// Зерно из источника случайности
		uint8_t xi[SEED_SIZE];
		if(entropy::bytes(xi, sizeof(xi))){
			// Вырабатываем ключ из зерна
			keygen(params(set), xi, key, secret);
			// Записываем ключи в состояние модуля
			::memcpy(this->_pkey, key, publicSize(set));
			::memcpy(this->_key, secret, secretSize(set));
			this->_set = set;
			this->_secret = true;
			this->_public = true;
			result = true;
		} else
			// Источник отказал: состояние сброшено
			this->clear();
		// Затираем зерно
		sys::wipe(xi, sizeof(xi));
	}
	// Выводим признак успешности
	return result;
}

/**
 * @brief Метод установки ключа подписи
 *
 * @param set    набор параметров ключа
 * @param secret запись ключа подписи ρ ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0 по набору
 *
 * @return       признак успешности установки ключа подписи
 *
 */
bool sign::Mldsa::secret(const set_t set, const view_t & secret) noexcept {
	// Результат работы
	bool result = false;
	// Параметры набора существуют и запись верной длины
	const Params p = params(set);
	if((p.k != 0) && (secret.size == secretSize(set))){
		// Подлинность записи проверяется пересчётом трассировки из её частей
		uint8_t check[2592];
		result = consistent(p, static_cast <const uint8_t *> (secret.data), check);
		if(result){
			::memcpy(this->_key, secret.data, secretSize(set));
			::memcpy(this->_pkey, check, publicSize(set));
			this->_set = set;
			this->_secret = true;
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
 * @param key запись ключа проверки ρ ‖ t1 по набору
 *
 * @return    признак успешности установки ключа проверки подписи
 *
 */
bool sign::Mldsa::key(const set_t set, const view_t & key) noexcept {
	// Результат работы
	bool result = false;
	// Параметры набора существуют и запись верной длины
	if((params(set).k != 0) && (key.size == publicSize(set))){
		// Если ключ подписи установлен, поданный обязан совпасть с выведенным
		if(this->_secret && (this->_set == set)){
			if(::memcmp(this->_pkey, key.data, publicSize(set)) == 0)
				result = true;
		} else {
			// Иначе устанавливаем ключ проверки
			::memcpy(this->_pkey, key.data, publicSize(set));
			this->_set = set;
			this->_public = true;
			result = true;
		}
	}
	// Выводим признак успешности
	return result;
}

/**
 * @brief Метод получения ключа проверки подписи
 *
 * @param result место, в которое записывается ключ проверки ρ ‖ t1 по набору
 * @param size   размер места, не меньше размера ключа проверки набора
 *
 * @return       признак успешности получения ключа проверки подписи
 *
 */
bool sign::Mldsa::key(uint8_t * result, const size_t size) const noexcept {
	// Результат работы
	bool outcome = false;
	// Ключ проверки установлен и места хватает
	if(this->_public && (size >= publicSize(this->_set))){
		// Выводим ключ проверки
		::memcpy(result, this->_pkey, publicSize(this->_set));
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
 *
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
		if(entropy::bytes(rnd, sizeof(rnd))){
			// Вырабатываем подпись
			signing(params(this->_set), this->_key, rnd, message, context, result);
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
 *
 * @return        признак успешности выработки подписи
 *
 */
bool sign::Mldsa::make(const view_t & rnd, const view_t & message, const view_t & context, uint8_t * result) const noexcept {
	// Результат работы
	bool outcome = false;
	// Ключ подписи установлен, случайность и контекст допустимой длины
	if(this->_secret && (rnd.size == SEED_SIZE) && (context.size <= 255)){
		// Вырабатываем подпись
		signing(params(this->_set), this->_key, static_cast <const uint8_t *> (rnd.data), message, context, result);
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
 *
 * @return          признак того, что подпись сошлась
 *
 */
bool sign::Mldsa::check(const view_t & message, const view_t & context, const view_t & signature) const noexcept {
	// Результат работы
	bool result = false;
	// Ключ проверки установлен, подпись и контекст допустимой длины
	if(this->_public && (signature.size == signatureSize(this->_set)) && (context.size <= 255)){
		// Проверяем подпись
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
