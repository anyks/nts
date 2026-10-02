/**
 * @file sha3.cpp
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
 * @brief Модуль хеширования SHA-3 и функций переменного выхода SHAKE по FIPS 202
 *
 * @details Губка над перестановкой Keccak-f[1600]: состояние в двадцать пять полос по
 *          64 разряда, полосы читаются и пишутся от младшего байта. Скорость хешей
 *          1600 − 2·длина итога разрядов, у SHAKE128 - 1344, у SHAKE256 - 1088 разрядов.
 *          Дополнение хешей начинается байтом 0x06, функций переменного выхода - 0x1F, и
 *          в обоих случаях оканчивается разрядом 0x80 в последнем байте блока
 *
 * @section Намеренные решения
 *
 * 1. Перестановка расписана по шагам θ, ρ, π, χ, ι, но развёрнута по полосам: двадцать
 *    пять полос лежат в именованных переменных, сдвиги ρ и обход π выписаны подстановкой,
 *    а не таблицами. Прежняя запись циклами с таблицами сдвигов читалась против FIPS 202
 *    построчно, и clang разворачивал её сам (M4 148 нс на перестановку, FreeBSD clang 19
 *    738), а gcc 12 - нет: на Astra она стоила 1 568 нс против 737 у развёрнутой (щуп
 *    keccakprobe, круг 35, 23.09.2026). Ассемблер OpenSSL там же около 540 нс, на M4 126.
 *
 * 2. Поглощение и выжимание идут через одно состояние без отдельного накопителя блока:
 *    байты сообщения складываются в полосы по смещению, оттого память под блок не
 *    занимается, а число байтов в незавершённом блоке хранится счётчиком. Целые полосы
 *    идут словами по восемь байтов, по байту - лишь хвосты и начало с невыровненного
 *    смещения: побайтовый ход стоил на блоке SHAKE128 больше самой перестановки
 *    (M4: поглощение 358 нс при перестановке 148, выжимание 235; Astra 1 813 и 1 935 при
 *    1 568). Целые блоки с начала блока идут прямым циклом по полосам без проверок
 *    смещения на каждой (как SHA3_absorb OpenSSL): M4 инкапсуляция ML-KEM-768 11,2 → 10,8 мкс
 *    (круг 36, 23.09.2026).
 *    Функция переменного выхода в ML-KEM выжимается блоками по 168 байтов.
 *
 * 3. После первого выжимания поглощение отвергается: губка FIPS 202 не двусторонняя,
 *    и продолжение поглощения после выжимания дало бы итог, не описанный стандартом.
 *
 * 4. На x86-64 у gcc и clang перестановка идёт ядром на встроенном ассемблере
 *    (src/internal/digest/keccak.hpp, порождается сценарием tools/digest/keccak.py, который
 *    сличает порождённый список команд с эталонной перестановкой до выдачи текста): полосы
 *    в двух накопителях памяти, чётности θ в регистрах, строки по одной, шесть полос хранятся
 *    инвертированными (дополнение полос), оттого χ обходится одним not на строку. Собранная
 *    из C++ перестановка на четырнадцати регистрах не умещается: gcc 12 и clang 19 давали на
 *    стендах x86 689…742 нс, ядро - 606…615 (FreeBSD clang 19 705 → 615, Astra gcc 12 741 → 612,
 *    MinGW gcc 16 689 → 606; круг 36, 23.09.2026), SHA3-256 ключа ML-KEM в 1 184 байта 5,6…6,0 мкс
 *    при 5,2…5,4 у ассемблера OpenSSL. На AArch64 с командами SHA-3 (FEAT_SHA3: eor3, rax1, xar,
 *    bcax; признак __ARM_FEATURE_SHA3 - у clang на процессорах Apple задан сам, у gcc и clang под
 *    Linux появляется от -march=armv8.2-a+sha3, как у MGM с __ARM_FEATURE_AES) - второе ядро того
 *    же порождателя: полосы в младших половинах v0…v31, все круги развёрнуты, чётности двумя eor3
 *    на столбец, слагаемые θ одним rax1, сложение с D и сдвиг ρ одним xar по циклу подстановки π,
 *    χ одним bcax на полосу, итоги χ ложатся в свободные регистры без копий (1 682 команды). M4:
 *    перестановка 145 → 126,6 нс при 125,8 у ассемблера OpenSSL под ARMv8, SHA3-256 ключа ML-KEM
 *    1 354 → 1 186 при 1 298, инкапсуляция ML-KEM-768 10,8 → 9,9 мкс. На Эльбрусе lcc и так кладёт
 *    развёртку в регистры (421 нс), там и у прочих собирателей остаётся переносимая перестановка.
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
#include <digest/sha3.hpp>
#include <sys/wipe.hpp>
#include <internal/digest/keccak.hpp>

/**
 * @brief Служебные объекты модуля
 *
 */
namespace {
	/**
	 * Число кругов перестановки Keccak-f[1600]
	 */
	static constexpr size_t ROUNDS = 24;
	/**
	 * Константы шага ι по кругам
	 */
	static const uint64_t IOTA[ROUNDS] = {
		0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL, 0x8000000080008000ULL,
		0x000000000000808BULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
		0x000000000000008AULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
		0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
		0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800AULL, 0x800000008000000AULL,
		0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
	};
	/**
	 * Круговой сдвиг нужен лишь переносимой перестановке
	 */
	#if !defined(__ANTS_KECCAK_X86_64__) && !defined(__ANTS_KECCAK_AARCH64__)
		/**
		 * @brief Метод кругового сдвига полосы влево
		 *
		 * @param lane  сдвигаемая полоса
		 * @param count число разрядов сдвига
		 *
		 * @return      сдвинутая полоса
		 *
		 */
		static inline uint64_t spin(const uint64_t lane, const size_t count) noexcept {
			// Выводим круговой сдвиг полосы
			return ((lane << count) | (lane >> (64 - count)));
		}
	#endif
	/**
	 * @brief Метод чтения полосы из восьми байтов от младшего
	 *
	 * @param data читаемые байты
	 *
	 * @return     полоса
	 *
	 * @note Собиратель сворачивает сборку из байтов в одну загрузку на машинах с младшим
	 *       байтом вперёд; на прочих запись верна по определению раздела 3.1.2 FIPS 202
	 */
	static inline uint64_t word(const uint8_t * data) noexcept {
		/**
		 * На машинах с младшим байтом вперёд полоса лежит в памяти как есть, и копия
		 * восьми байтов обращается в одну загрузку у clang и gcc. У lcc на Эльбрусе memcpy
		 * остаётся вызовом: поглощение блока SHAKE128 там стоило 947 нс против 743 при
		 * сборке из байтов (круг 35, 23.09.2026), оттого e2k идёт сборкой
		 */
		#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) && !defined(__e2k__)
			// Полоса
			uint64_t lane = 0;
			// Копируем байты полосы
			::memcpy(&lane, data, sizeof(lane));
			// Выводим полосу
			return lane;
		#else
			// Собираем полосу из байтов от младшего к старшему
			return (
				static_cast <uint64_t> (data[0]) | (static_cast <uint64_t> (data[1]) << 8) |
				(static_cast <uint64_t> (data[2]) << 16) | (static_cast <uint64_t> (data[3]) << 24) |
				(static_cast <uint64_t> (data[4]) << 32) | (static_cast <uint64_t> (data[5]) << 40) |
				(static_cast <uint64_t> (data[6]) << 48) | (static_cast <uint64_t> (data[7]) << 56)
			);
		#endif
	}
	/**
	 * @brief Метод записи полосы восемью байтами от младшего
	 *
	 * @param lane   записываемая полоса
	 * @param result место, в которое помещаются байты
	 *
	 */
	static inline void bytes(const uint64_t lane, uint8_t * result) noexcept {
		#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) && !defined(__e2k__)
			// Копируем полосу как есть: младший байт вперёд
			::memcpy(result, &lane, sizeof(lane));
		#else
			/**
			 * Выполняем запись байтов полосы от младшего к старшему
			 */
			for(size_t i = 0; i < 8; i++)
				// Записываем очередной байт полосы
				result[i] = static_cast <uint8_t> (lane >> (i * 8));
		#endif
	}
};

/**
 * @brief Метод перестановки состояния Keccak-f[1600]
 *
 */
void nts::digest::Keccak::permute() noexcept {
	/**
	 * Ядро на ассемблере x86-64 либо на командах SHA-3 AArch64 (решение 4)
	 */
	#if defined(__ANTS_KECCAK_X86_64__) || defined(__ANTS_KECCAK_AARCH64__)
		// Выполняем перестановку ядром на ассемблере
		kernel::keccak(this->_state, IOTA);
	/**
	 * Переносимая перестановка
	 */
	#else
		// Полосы состояния в переменных: a[x + 5y], x - столбец, y - строка (раздел 3.1.2 FIPS 202)
		uint64_t a00 = this->_state[0], a01 = this->_state[1], a02 = this->_state[2], a03 = this->_state[3], a04 = this->_state[4], a05 = this->_state[5], a06 = this->_state[6], a07 = this->_state[7], a08 = this->_state[8], a09 = this->_state[9], a10 = this->_state[10], a11 = this->_state[11], a12 = this->_state[12], a13 = this->_state[13], a14 = this->_state[14], a15 = this->_state[15], a16 = this->_state[16], a17 = this->_state[17], a18 = this->_state[18], a19 = this->_state[19], a20 = this->_state[20], a21 = this->_state[21], a22 = this->_state[22], a23 = this->_state[23], a24 = this->_state[24];
		// Полосы после шагов ρ и π
		uint64_t b00, b01, b02, b03, b04, b05, b06, b07, b08, b09, b10, b11, b12, b13, b14, b15, b16, b17, b18, b19, b20, b21, b22, b23, b24;
		/**
		 * Выполняем перебор кругов перестановки
		 */
		for(size_t round = 0; round < ROUNDS; round++){
			// Шаг θ: чётность каждого столбца
			const uint64_t c0 = (a00 ^ a05 ^ a10 ^ a15 ^ a20), c1 = (a01 ^ a06 ^ a11 ^ a16 ^ a21), c2 = (a02 ^ a07 ^ a12 ^ a17 ^ a22), c3 = (a03 ^ a08 ^ a13 ^ a18 ^ a23), c4 = (a04 ^ a09 ^ a14 ^ a19 ^ a24);
			// Шаг θ: слагаемое столбца из чётностей соседей
			const uint64_t d0 = (c4 ^ spin(c1, 1)), d1 = (c0 ^ spin(c2, 1)), d2 = (c1 ^ spin(c3, 1)), d3 = (c2 ^ spin(c4, 1)), d4 = (c3 ^ spin(c0, 1));
			// Шаг θ: сложение слагаемого с каждой полосой столбца
			a00 ^= d0; a05 ^= d0; a10 ^= d0; a15 ^= d0; a20 ^= d0;
			a01 ^= d1; a06 ^= d1; a11 ^= d1; a16 ^= d1; a21 ^= d1;
			a02 ^= d2; a07 ^= d2; a12 ^= d2; a17 ^= d2; a22 ^= d2;
			a03 ^= d3; a08 ^= d3; a13 ^= d3; a18 ^= d3; a23 ^= d3;
			a04 ^= d4; a09 ^= d4; a14 ^= d4; a19 ^= d4; a24 ^= d4;
			/**
			 * Шаги ρ и π: полоса (x, y) сдвигается на своё число разрядов и переносится на
			 * место (y, 2x + 3y mod 5) - подстановка выписана по разделам 3.2.2 и 3.2.3
			 */
			b00 = a00; b10 = spin(a01, 1); b20 = spin(a02, 62); b05 = spin(a03, 28); b15 = spin(a04, 27);
			b16 = spin(a05, 36); b01 = spin(a06, 44); b11 = spin(a07, 6); b21 = spin(a08, 55); b06 = spin(a09, 20);
			b07 = spin(a10, 3); b17 = spin(a11, 10); b02 = spin(a12, 43); b12 = spin(a13, 25); b22 = spin(a14, 39);
			b23 = spin(a15, 41); b08 = spin(a16, 45); b18 = spin(a17, 15); b03 = spin(a18, 21); b13 = spin(a19, 8);
			b14 = spin(a20, 18); b24 = spin(a21, 2); b09 = spin(a22, 61); b19 = spin(a23, 56); b04 = spin(a24, 14);
			// Шаг χ: нелинейное смешение полос каждой строки с двумя соседями по строке
			a00 = (b00 ^ ((~b01) & b02)); a01 = (b01 ^ ((~b02) & b03)); a02 = (b02 ^ ((~b03) & b04)); a03 = (b03 ^ ((~b04) & b00)); a04 = (b04 ^ ((~b00) & b01));
			a05 = (b05 ^ ((~b06) & b07)); a06 = (b06 ^ ((~b07) & b08)); a07 = (b07 ^ ((~b08) & b09)); a08 = (b08 ^ ((~b09) & b05)); a09 = (b09 ^ ((~b05) & b06));
			a10 = (b10 ^ ((~b11) & b12)); a11 = (b11 ^ ((~b12) & b13)); a12 = (b12 ^ ((~b13) & b14)); a13 = (b13 ^ ((~b14) & b10)); a14 = (b14 ^ ((~b10) & b11));
			a15 = (b15 ^ ((~b16) & b17)); a16 = (b16 ^ ((~b17) & b18)); a17 = (b17 ^ ((~b18) & b19)); a18 = (b18 ^ ((~b19) & b15)); a19 = (b19 ^ ((~b15) & b16));
			a20 = (b20 ^ ((~b21) & b22)); a21 = (b21 ^ ((~b22) & b23)); a22 = (b22 ^ ((~b23) & b24)); a23 = (b23 ^ ((~b24) & b20)); a24 = (b24 ^ ((~b20) & b21));
			// Шаг ι: сложение константы круга с первой полосой
			a00 ^= IOTA[round];
		}
		/**
		 * Выполняем запись полос в состояние
		 */
		this->_state[0] = a00;
		this->_state[1] = a01;
		this->_state[2] = a02;
		this->_state[3] = a03;
		this->_state[4] = a04;
		this->_state[5] = a05;
		this->_state[6] = a06;
		this->_state[7] = a07;
		this->_state[8] = a08;
		this->_state[9] = a09;
		this->_state[10] = a10;
		this->_state[11] = a11;
		this->_state[12] = a12;
		this->_state[13] = a13;
		this->_state[14] = a14;
		this->_state[15] = a15;
		this->_state[16] = a16;
		this->_state[17] = a17;
		this->_state[18] = a18;
		this->_state[19] = a19;
		this->_state[20] = a20;
		this->_state[21] = a21;
		this->_state[22] = a22;
		this->_state[23] = a23;
		this->_state[24] = a24;
	#endif
}
/**
 * @brief Метод дополнения сообщения и перехода к выжиманию
 *
 */
void nts::digest::Keccak::seal() noexcept {
	// Байт начала дополнения по разновидности: 0x06 у хешей, 0x1F у функций переменного выхода
	const uint8_t opening = (((this->_type == sha3_t::SHAKE128) || (this->_type == sha3_t::SHAKE256)) ? 0x1F : 0x06);
	// Складываем байт начала дополнения с полосой по смещению незавершённого блока
	this->_state[this->_size / 8] ^= (static_cast <uint64_t> (opening) << ((this->_size % 8) * 8));
	// Складываем разряд окончания дополнения с последней полосой блока
	this->_state[(this->_rate - 1) / 8] ^= (static_cast <uint64_t> (0x80) << (((this->_rate - 1) % 8) * 8));
	// Выполняем перестановку состояния
	this->permute();
	// Сбрасываем счётчик выжатых из блока байтов
	this->_size = 0;
	// Запоминаем, что выжимание итога началось
	this->_squeezing = true;
}
/**
 * \~russian
 * @brief Метод получения разновидности преобразования
 *
 * @return разновидность преобразования
 *
 * \~english
 * @brief Method of the obtaining of the kind of the transformation
 *
 * @return kind of the transformation
 *
 * \~
 */
nts::digest::sha3_t nts::digest::Keccak::type() const noexcept {
	// Выводим разновидность преобразования
	return this->_type;
}
/**
 * \~russian
 * @brief Метод получения скорости преобразования
 *
 * @return число байтов, поглощаемых за одну перестановку
 *
 * \~english
 * @brief Method of the obtaining of the rate of the transformation
 *
 * @return number of the bytes absorbed per one permutation
 *
 * \~
 */
size_t nts::digest::Keccak::block() const noexcept {
	// Выводим скорость преобразования
	return this->_rate;
}
/**
 * \~russian
 * @brief Метод сброса преобразования в начальное состояние
 *
 * @param type разновидность преобразования
 *
 * \~english
 * @brief Method of the reset of the transformation to the initial state
 *
 * @param type kind of the transformation
 *
 * \~
 */
void nts::digest::Keccak::reset(const sha3_t type) noexcept {
	// Запоминаем разновидность преобразования
	this->_type = type;
	// Запоминаем скорость разновидности
	this->_rate = rate(type);
	// Сбрасываем счётчик байтов незавершённого блока
	this->_size = 0;
	// Сбрасываем признак выжимания
	this->_squeezing = false;
	// Обнуляем состояние губки
	::memset(this->_state, 0, sizeof(this->_state));
}
/**
 * \~russian
 * @brief Метод поглощения куска сообщения
 *
 * @param data кусок сообщения
 *
 * @return     признак того, что кусок поглощён: после выжимания поглощение отвергается
 *
 * \~english
 * @brief Method of the absorption of a piece of the message
 *
 * @param data piece of the message
 *
 * @return     sign that the piece is absorbed: after a squeezing the absorption is refused
 *
 * \~
 */
bool nts::digest::Keccak::update(const view_t & data) noexcept {
	// Если разновидность не установлена либо выжимание уже началось
	if((this->_rate == 0) || this->_squeezing)
		// Выводим отказ поглощения
		return false;
	// Если кусок сообщения пуст
	if((data.data == nullptr) || (data.size == 0))
		// Выводим успешность поглощения пустого куска
		return (data.size == 0);
	// Очередной байт куска сообщения и число оставшихся байтов
	const uint8_t * bytes = data.data;
	size_t left = data.size;
	/**
	 * Выполняем поглощение целых блоков с начала блока: полосы складываются прямым
	 * циклом без проверок смещения - так же устроен SHA3_absorb OpenSSL
	 */
	while((this->_size == 0) && (left >= this->_rate)){
		/**
		 * Выполняем перебор полос блока
		 */
		for(size_t i = 0; i < (this->_rate / 8); i++)
			// Складываем полосу сообщения с полосой состояния
			this->_state[i] ^= word(bytes + (i * 8));
		// Выполняем перестановку состояния
		this->permute();
		// Сдвигаем байты сообщения на блок
		bytes += this->_rate;
		left -= this->_rate;
	}
	/**
	 * Выполняем поглощение остатка куска сообщения
	 */
	while(left > 0){
		// Если смещение в блоке выровнено по полосе и осталось не меньше полосы
		if(((this->_size % 8) == 0) && (left >= 8)){
			// Складываем целую полосу сообщения с полосой состояния
			this->_state[this->_size / 8] ^= word(bytes);
			// Сдвигаем байты сообщения на полосу
			bytes += 8;
			left -= 8;
			this->_size += 8;
		// Иначе складываем байт сообщения с полосой по смещению незавершённого блока
		} else {
			// Складываем байт сообщения с полосой по смещению незавершённого блока
			this->_state[this->_size / 8] ^= (static_cast <uint64_t> (* bytes) << ((this->_size % 8) * 8));
			// Сдвигаем байты сообщения на байт
			bytes++;
			left--;
			this->_size++;
		}
		// Если блок заполнен
		if(this->_size == this->_rate){
			// Выполняем перестановку состояния
			this->permute();
			// Сбрасываем счётчик байтов незавершённого блока
			this->_size = 0;
		}
	}
	// Выводим успешность поглощения
	return true;
}
/**
 * \~russian
 * @brief Метод выжимания куска итога функции переменного выхода
 *
 * @param result место, в которое помещается кусок итога
 * @param size   длина куска итога в байтах
 *
 * @return       признак того, что кусок выжат: у хешей выжимание отвергается
 *
 * \~english
 * @brief Method of the squeezing of a piece of the result of an extendable-output function
 *
 * @param result place into which the piece of the result is put
 * @param size   length of the piece of the result in bytes
 *
 * @return       sign that the piece is squeezed: at the hashes the squeezing is refused
 *
 * \~
 */
bool nts::digest::Keccak::squeeze(uint8_t * result, const size_t size) noexcept {
	// Если разновидность не функция переменного выхода
	if((this->_type != sha3_t::SHAKE128) && (this->_type != sha3_t::SHAKE256))
		// Выводим отказ выжимания
		return false;
	// Если место под кусок итога не передано
	if((result == nullptr) && (size > 0))
		// Выводим отказ выжимания
		return false;
	// Если выжимание ещё не началось
	if(!this->_squeezing)
		// Выполняем дополнение сообщения и переход к выжиманию
		this->seal();
	// Число оставшихся байтов куска итога
	size_t left = size;
	/**
	 * Выполняем выжимание целых блоков от края блока: полосы выдаются прямым циклом
	 */
	while((this->_size == this->_rate) && (left >= this->_rate)){
		// Выполняем перестановку состояния
		this->permute();
		/**
		 * Выполняем перебор полос блока
		 */
		for(size_t i = 0; i < (this->_rate / 8); i++)
			// Выдаём полосу итога
			bytes(this->_state[i], result + (i * 8));
		// Сдвигаем место итога на блок
		result += this->_rate;
		left -= this->_rate;
	}
	/**
	 * Выполняем выжимание остатка куска итога
	 */
	while(left > 0){
		// Если блок выжат целиком
		if(this->_size == this->_rate){
			// Выполняем перестановку состояния
			this->permute();
			// Сбрасываем счётчик выжатых из блока байтов
			this->_size = 0;
		}
		// Если смещение в блоке выровнено по полосе и осталось не меньше полосы
		if(((this->_size % 8) == 0) && (left >= 8)){
			// Выдаём целую полосу итога
			bytes(this->_state[this->_size / 8], result);
			// Сдвигаем место итога на полосу
			result += 8;
			left -= 8;
			this->_size += 8;
		// Иначе выдаём байт полосы по смещению выжатых байтов
		} else {
			// Выдаём байт полосы по смещению выжатых байтов
			(* result) = static_cast <uint8_t> (this->_state[this->_size / 8] >> ((this->_size % 8) * 8));
			// Сдвигаем место итога на байт
			result++;
			left--;
			this->_size++;
		}
	}
	// Выводим успешность выжимания
	return true;
}
/**
 * \~russian
 * @brief Метод снятия итога хеша
 *
 * @param result место, в которое помещается итог
 * @param size   длина места в байтах: у хешей ровно длина разновидности, у функций переменного выхода любая
 *
 * @return       признак того, что итог снят; повторное снятие отвергается
 *
 * \~english
 * @brief Method of the taking of the result of the hash
 *
 * @param result place into which the result is put
 * @param size   length of the place in bytes: at the hashes exactly the length of the kind, at the extendable-output functions any
 *
 * @return       sign that the result is taken; a repeated taking is refused
 *
 * \~
 */
bool nts::digest::Keccak::finish(uint8_t * result, const size_t size) noexcept {
	// Если разновидность не установлена, итог уже снят либо место не передано
	if((this->_rate == 0) || this->_squeezing || (result == nullptr) || (size == 0))
		// Выводим отказ снятия итога
		return false;
	// Если разновидность - функция переменного выхода
	if((this->_type == sha3_t::SHAKE128) || (this->_type == sha3_t::SHAKE256))
		// Выжимаем итог запрошенной длины
		return this->squeeze(result, size);
	// Если длина места не сходится с длиной разновидности
	if(size != length(this->_type))
		// Выводим отказ снятия итога
		return false;
	// Выполняем дополнение сообщения и переход к выжиманию
	this->seal();
	/**
	 * Выполняем перебор целых полос итога: итог хеша целиком лежит в первом блоке
	 */
	for(size_t i = 0; (i + 8) <= size; i += 8)
		// Выдаём целую полосу итога
		bytes(this->_state[i / 8], result + i);
	/**
	 * Выполняем перебор байтов хвоста итога: у SHA3-224 итог в 28 байтов на полосы не делится
	 */
	for(size_t i = (size - (size % 8)); i < size; i++)
		// Выдаём байт полосы по смещению
		result[i] = static_cast <uint8_t> (this->_state[i / 8] >> ((i % 8) * 8));
	// Выводим успешность снятия итога
	return true;
}
/**
 * \~russian
 * @brief Конструктор
 *
 * @param type разновидность преобразования
 *
 * \~english
 * @brief Constructor
 *
 * @param type kind of the transformation
 *
 * \~
 */
nts::digest::Keccak::Keccak(const sha3_t type) noexcept : _type(sha3_t::NONE), _squeezing(false), _size(0), _rate(0) {
	// Выполняем сброс преобразования
	this->reset(type);
}
/**
 * \~russian
 * @brief Деструктор: состояние затирается
 *
 * \~english
 * @brief Destructor: the state is wiped
 *
 * \~
 */
nts::digest::Keccak::~Keccak() noexcept {
	// Выполняем затирание состояния губки
	sys::wipe(this->_state, sizeof(this->_state));
}
/**
 * \~russian
 * @brief Метод получения длины итога разновидности
 *
 * @param type разновидность преобразования
 *
 * @return     длина итога хеша в байтах либо нуль у функций переменного выхода
 *
 * \~english
 * @brief Method of the obtaining of the length of the result of a kind
 *
 * @param type kind of the transformation
 *
 * @return     length of the result of the hash in bytes or zero at the extendable-output functions
 *
 * \~
 */
size_t nts::digest::length(const sha3_t type) noexcept {
	/**
	 * Определяем разновидность преобразования
	 */
	switch(static_cast <uint8_t> (type)){
		// Хеши: длина итога равна значению перечисления
		case static_cast <uint8_t> (sha3_t::SHA3_224):
		case static_cast <uint8_t> (sha3_t::SHA3_256):
		case static_cast <uint8_t> (sha3_t::SHA3_384):
		case static_cast <uint8_t> (sha3_t::SHA3_512):
			// Выводим длину итога
			return static_cast <size_t> (type);
	}
	// Выводим отсутствие заданной длины итога
	return 0;
}
/**
 * \~russian
 * @brief Метод получения скорости разновидности
 *
 * @param type разновидность преобразования
 *
 * @return     число байтов, поглощаемых или выдаваемых за одну перестановку, либо нуль
 *
 * \~english
 * @brief Method of the obtaining of the rate of a kind
 *
 * @param type kind of the transformation
 *
 * @return     number of the bytes absorbed or squeezed per one permutation or zero
 *
 * \~
 */
size_t nts::digest::rate(const sha3_t type) noexcept {
	/**
	 * Определяем разновидность преобразования
	 */
	switch(static_cast <uint8_t> (type)){
		// Хеши: скорость есть размер состояния без удвоенной длины итога
		case static_cast <uint8_t> (sha3_t::SHA3_224):
		case static_cast <uint8_t> (sha3_t::SHA3_256):
		case static_cast <uint8_t> (sha3_t::SHA3_384):
		case static_cast <uint8_t> (sha3_t::SHA3_512):
			// Выводим скорость хеша
			return (SHA3_STATE - (static_cast <size_t> (type) * 2));
		// SHAKE128: скорость 1344 разряда
		case static_cast <uint8_t> (sha3_t::SHAKE128):
			// Выводим скорость функции переменного выхода
			return 168;
		// SHAKE256: скорость 1088 разрядов
		case static_cast <uint8_t> (sha3_t::SHAKE256):
			// Выводим скорость функции переменного выхода
			return 136;
	}
	// Выводим отсутствие скорости
	return 0;
}
/**
 * \~russian
 * @brief Метод хеширования сообщения за один вызов
 *
 * @param type   разновидность преобразования
 * @param data   сообщение
 * @param result место, в которое помещается итог
 * @param size   длина итога в байтах: у хешей ровно длина разновидности, у функций переменного выхода любая
 *
 * @return       признак того, что итог вычислен
 *
 * \~english
 * @brief Method of the hashing of a message by one call
 *
 * @param type   kind of the transformation
 * @param data   message
 * @param result place into which the result is put
 * @param size   length of the result in bytes: at the hashes exactly the length of the kind, at the extendable-output functions any
 *
 * @return       sign that the result is computed
 *
 * \~
 */
bool nts::digest::sha3(const sha3_t type, const view_t & data, uint8_t * result, const size_t size) noexcept {
	// Преобразование заданной разновидности
	keccak_t keccak(type);
	// Если сообщение поглотить не удалось
	if(!keccak.update(data))
		// Выводим отказ хеширования
		return false;
	// Выводим итог снятия хеша
	return keccak.finish(result, size);
}
