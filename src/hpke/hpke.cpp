/**
 * @file hpke.cpp
 * @date 2026-09-06
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
 * @brief Реализация модуля гибридного шифрования с открытым ключом HPKE по RFC 9180
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Намеренные решения
 *
 * 1. Меченые извлечение и растяжение (LabeledExtract и LabeledExpand раздела 4 RFC 9180)
 *    складываются по частям потоковой имитовставкой `digest::mac_t`, а не склейкой
 *    «HPKE-v1» || suite_id || label || данные в один буфер: у растяжения по разделу 2.3
 *    RFC 5869 итог HMAC берётся по частям T(i-1) || info || i тем же способом. Оттого на
 *    ключевом пути модуль не выделяет память вовсе, и нехватка памяти возможна лишь в
 *    накопителях `vector` наружных обёрток, где она перехватывается и отдаётся кодом MEMORY.
 *
 * 2. Порядковый номер хранится числом в шестьдесят четыре разряда. Раздел 5.2 RFC 9180
 *    велит останавливать переписку при номере 2^(8·Nn) − 1, то есть 2^96 − 1 при Nn = 12;
 *    модуль останавливается раньше — при номере 2^64 − 1 — что строже стандарта и ни одно
 *    законное сообщение не отвергает: столько сообщений по одному состоянию не пошлёт никто.
 *
 * 3. Секретный ключ пары хранится в том виде, в каком его выдало DeriveKeyPair либо задал
 *    потребитель, без зажима разрядов: зажим по разделу 5 RFC 7748 выполняет сама функция
 *    X25519 при каждом употреблении, а вектора приложения A RFC 9180 сличают незажатый вид.
 *
 * 4. Открытый ключ получателя на принадлежность кривой не проверяется: раздел 7.1.4 RFC 9180
 *    велит лишь отвергать нулевое общее значение, и это делает `agreement::x25519`, отдавая
 *    отказ, который здесь обращается в код ENCAPSULATION.
 */

/**
 * Стандартные заголовочные файлы
 */
#include <new>
#include <vector>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <hpke/hpke.hpp>
#include <agreement/x25519.hpp>
#include <agreement/x448.hpp>
#include <agreement/ecdhe.hpp>
#include <agreement/mlkem.hpp>
#include <curve/parameters.hpp>
#include <digest/hash.hpp>
#include <digest/hmac.hpp>
#include <digest/sha3.hpp>
#include <entropy/entropy.hpp>
#include <cipher/gcm.hpp>
#include <cipher/mode.hpp>
#include <internal/digest/keccak.hpp>
#include <cipher/chachapoly.hpp>
#include <sys/wipe.hpp>

/**
 * Подписываемся на стандартное пространство имён
 */
using namespace std;

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
	 * Пространство имён модуля
	 */
	using namespace nts::hpke;

	/**
	 * Помощник стирания памяти
	 */
	using nts::sys::wipe;

	/**
	 * Метка издания протокола: раздел 4 RFC 9180
	 */
	static const char * VERSION = "HPKE-v1";
	/**
	 * Длина опознавателя способа инкапсуляции: «KEM» и два байта номера
	 */
	static constexpr size_t KEM_STAMP = 5;
	// Наименьшая длина заранее разделённого ключа в байтах (раздел 9.5 RFC 9180)
	static constexpr size_t PSK_LEAST = 32;
	/**
	 * Длина опознавателя набора: «HPKE» и три номера по два байта
	 */
	static constexpr size_t SUITE_STAMP = 10;
	/**
	 * Длина привязки расписания ключей: режим и два хеша
	 */
	static constexpr size_t SCHEDULE_SIZE = (1 + (2 * HASH_SIZE));
	/**
	 * Наибольшая длина привязки способа инкапсуляции у новых способов:
	 * инкапсулированный ключ и два открытых ключа по KEM_CIPHER
	 */
	static constexpr size_t BINDING_FULL = (3 * KEM_CIPHER);
	/**
	 * Наибольшая длина зерна выработки пары ключей гибридного способа:
	 * зерно ML-KEM и зерно отбора скаляра группы (128 байтов у P-256)
	 */
	static constexpr size_t SEED_FULL = (64 + 128);
	/**
	 * Наибольшая длина скаляра кривой NIST в байтах: 66 у P-521
	 */
	static constexpr size_t SCALAR_SIZE = 66;
	/**
	 * Длина зерна выработки пары ключей чистого ML-KEM в байтах
	 */
	static constexpr size_t MLKEM_SEED_SIZE = 64;
	/**
	 * Длина зерна выработки пары ключей гибридного способа в байтах
	 */
	static constexpr size_t HYBRID_SEED_SIZE = 32;
	/**
	 * Длина случайного сообщения инкапсуляции ML-KEM в байтах
	 */
	static constexpr size_t MLKEM_MESSAGE_SIZE = 32;
	/**
	 * Длина общего значения ML-KEM в байтах
	 */
	static constexpr size_t MLKEM_SHARED_SIZE = 32;
	/**
	 * Число кругов перестановки Keccak-f[1600]
	 */
	static constexpr size_t KECCAK_ROUNDS = 24;
	/**
	 * Константы шага ι по кругам перестановки Keccak-f[1600]
	 */
	static const uint64_t KECCAK_IOTA[KECCAK_ROUNDS] = {
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
	 * @brief Метод перестановки состояния Keccak-p[1600] с заданным числом кругов
	 *
	 * @param state  состояние в двадцать пять полос по 64 разряда
	 * @param rounds число кругов: 24 у Keccak-f[1600], 12 у Keccak-p[1600, 12] TurboSHAKE
	 *
	 * @details У ядра на ассемблере круги идут от конца таблицы констант: двенадцать
	 *          кругов TurboSHAKE - это последние двенадцать кругов Keccak-f[1600]
	 *
	 */
	static void permute(uint64_t * state, const size_t rounds) noexcept {
		/**
		 * Ядро на ассемблере x86-64 либо на командах SHA-3 AArch64
		 */
		#if defined(__ANTS_KECCAK_X86_64__) || defined(__ANTS_KECCAK_AARCH64__)
			// Выполняем перестановку ядром от конца таблицы констант
			digest::kernel::keccak(state, KECCAK_IOTA + (KECCAK_ROUNDS - rounds));
		/**
		 * Переносимая перестановка
		 */
		#else
			// Полосы состояния в переменных: a[x + 5y], x - столбец, y - строка (раздел 3.1.2 FIPS 202)
			uint64_t a00 = state[0], a01 = state[1], a02 = state[2], a03 = state[3], a04 = state[4], a05 = state[5], a06 = state[6], a07 = state[7], a08 = state[8], a09 = state[9], a10 = state[10], a11 = state[11], a12 = state[12], a13 = state[13], a14 = state[14], a15 = state[15], a16 = state[16], a17 = state[17], a18 = state[18], a19 = state[19], a20 = state[20], a21 = state[21], a22 = state[22], a23 = state[23], a24 = state[24];
			// Полосы после шагов ρ и π
			uint64_t b00, b01, b02, b03, b04, b05, b06, b07, b08, b09, b10, b11, b12, b13, b14, b15, b16, b17, b18, b19, b20, b21, b22, b23, b24;
			/**
			 * Выполняем перебор кругов перестановки от конца таблицы констант
			 */
			for(size_t round = (KECCAK_ROUNDS - rounds); round < KECCAK_ROUNDS; round++){
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
				a00 ^= KECCAK_IOTA[round];
			}
			/**
			 * Выполняем запись полос в состояние
			 */
			state[0] = a00;
			state[1] = a01;
			state[2] = a02;
			state[3] = a03;
			state[4] = a04;
			state[5] = a05;
			state[6] = a06;
			state[7] = a07;
			state[8] = a08;
			state[9] = a09;
			state[10] = a10;
			state[11] = a11;
			state[12] = a12;
			state[13] = a13;
			state[14] = a14;
			state[15] = a15;
			state[16] = a16;
			state[17] = a17;
			state[18] = a18;
			state[19] = a19;
			state[20] = a20;
			state[21] = a21;
			state[22] = a22;
			state[23] = a23;
			state[24] = a24;
		#endif
	}
	/**
	 * @brief Метод выработки функцией семейства SHAKE с заданным числом кругов
	 *
	 * @param kdf      функция выработки ключа
	 * @param pieces   просмотры кусков сообщения по порядку
	 * @param count    число кусков
	 * @param result   место под материал
	 * @param size     длина материала в байтах
	 *
	 * @details Функция Derive раздела 5 draft-ietf-hpke-pq: SHAKE(ikm) с выжиманием L
	 *          байтов; у TurboSHAKE перестановка Keccak-p[1600, 12] по RFC 9861, байт
	 *          дополнения у обеих 0x1F
	 *
	 */
	static void xof(const kdf_t kdf, const view_t * pieces, const size_t count, uint8_t * result, const size_t size) noexcept {
		// Скорость губки: 168 байтов у SHAKE128, 136 у SHAKE256
		const size_t rate = (((kdf == kdf_t::SHAKE128) || (kdf == kdf_t::TURBOSHAKE128)) ? 168 : 136);
		// Число кругов перестановки: 24 у SHAKE, 12 у TurboSHAKE
		const size_t rounds = (((kdf == kdf_t::SHAKE128) || (kdf == kdf_t::SHAKE256)) ? 24 : 12);
		// Состояние губки: двадцать пять полос по 64 разряда
		uint64_t state[25];
		// Обнуляем состояние губки
		::memset(state, 0, sizeof(state));
		// Число байтов незавершённого блока
		size_t filled = 0;
		/**
		 * Выполняем поглощение кусков сообщения
		 */
		for(size_t i = 0; i < count; i++){
			// Очередной байт куска и число оставшихся байтов
			const uint8_t * bytes = pieces[i].data;
			size_t left = pieces[i].size;
			// Если кусок пуст
			if((bytes == nullptr) || (left == 0))
				// Переходим к следующему куску
				continue;
			/**
			 * Выполняем поглощение куска сообщения
			 */
			while(left > 0){
				// Если блок заполнен
				if(filled == rate){
					// Выполняем перестановку состояния
					permute(state, rounds);
					// Сбрасываем счётчик байтов незавершённого блока
					filled = 0;
				}
				// Длина поглощаемой части
				const size_t part = (((rate - filled) < left) ? (rate - filled) : left);
				/**
				 * Выполняем поглощение части куска по байтам
				 */
				for(size_t j = 0; j < part; j++)
					// Складываем байт сообщения с полосой по смещению незавершённого блока
					state[(filled + j) / 8] ^= (static_cast <uint64_t> (bytes[j]) << (((filled + j) % 8) * 8));
				// Сдвигаем счётчик байтов незавершённого блока
				filled += part;
				// Сдвигаем байты сообщения на часть
				bytes += part;
				left -= part;
			}
		}
		// Складываем байт начала дополнения 0x1F с полосой по смещению незавершённого блока
		state[filled / 8] ^= (static_cast <uint64_t> (0x1F) << ((filled % 8) * 8));
		// Складываем разряд окончания дополнения с последней полосой блока
		state[(rate - 1) / 8] ^= (static_cast <uint64_t> (0x80) << (((rate - 1) % 8) * 8));
		// Выполняем перестановку состояния
		permute(state, rounds);
		// Число выжатых из блока байтов
		size_t offset = 0;
		// Число оставшихся байтов итога
		size_t left = size;
		/**
		 * Выполняем выжимание итога
		 */
		while(left > 0){
			// Если блок выжат целиком
			if(offset == rate){
				// Выполняем перестановку состояния
				permute(state, rounds);
				// Сбрасываем счётчик выжатых из блока байтов
				offset = 0;
			}
			// Длина выжимаемой части
			const size_t part = (((rate - offset) < left) ? (rate - offset) : left);
			/**
			 * Выполняем выжимание части итога по байтам
			 */
			for(size_t j = 0; j < part; j++)
				// Выдаём байт полосы по смещению выжатых байтов
				result[j] = static_cast <uint8_t> (state[(offset + j) / 8] >> (((offset + j) % 8) * 8));
			// Сдвигаем счётчик выжатых байтов
			offset += part;
			// Сдвигаем место итога на часть
			result += part;
			left -= part;
		}
		// Стираем состояние губки
		wipe(state, sizeof(state));
	}

	/**
	 * @brief Метод выбора алгоритма хеширования функции выработки ключа
	 *
	 * @param kdf функция выработки ключа
	 * @return    алгоритм хеширования либо NONE
	 *
	 */
	static digest::hash_t hashing(const kdf_t kdf) noexcept {
		/**
		 * Определяем функцию выработки ключа
		 */
		switch(static_cast <uint16_t> (kdf)){
			// HKDF-SHA256
			case static_cast <uint16_t> (kdf_t::HKDF_SHA256):
				// Выводим SHA-256
				return digest::hash_t::SHA256;
			// HKDF-SHA384
			case static_cast <uint16_t> (kdf_t::HKDF_SHA384):
				// Выводим SHA-384
				return digest::hash_t::SHA384;
			// HKDF-SHA512
			case static_cast <uint16_t> (kdf_t::HKDF_SHA512):
				// Выводим SHA-512
				return digest::hash_t::SHA512;
		}
		// Выводим отсутствие алгоритма
		return digest::hash_t::NONE;
	}
	/**
	 * @brief Метод проверки признака одноступенчатой функции выработки ключа
	 *
	 * @param kdf функция выработки ключа
	 * @return    признак того, что функция одноступенчатая (раздел 5 draft-ietf-hpke-pq)
	 *
	 */
	static bool onestage(const kdf_t kdf) noexcept {
		// Выводим признак одноступенчатых функций SHAKE и TurboSHAKE
		return ((kdf == kdf_t::SHAKE128) || (kdf == kdf_t::SHAKE256) || (kdf == kdf_t::TURBOSHAKE128) || (kdf == kdf_t::TURBOSHAKE256));
	}
	/**
	 * @brief Метод записи двухбайтового номера старшим байтом вперёд
	 *
	 * @param value  номер
	 * @param result место под два байта
	 *
	 */
	static void inscribe(const uint16_t value, uint8_t * result) noexcept {
		// Записываем старший байт
		result[0] = static_cast <uint8_t> (value >> 8);
		// Записываем младший байт
		result[1] = static_cast <uint8_t> (value);
	}
	/**
	 * @brief Метод составления опознавателя способа инкапсуляции
	 *
	 * @param kem    способ инкапсуляции ключа
	 * @param result место под опознаватель длиной KEM_STAMP
	 *
	 * @details Значение suite_id раздела 4.1 RFC 9180 для функций способа инкапсуляции
	 *
	 */
	static void stamp(const kem_t kem, uint8_t * result) noexcept {
		// Записываем метку «KEM»
		::memcpy(result, "KEM", 3);
		// Записываем номер способа
		inscribe(static_cast <uint16_t> (kem), result + 3);
	}
	/**
	 * @brief Метод составления опознавателя набора алгоритмов
	 *
	 * @param suite  набор алгоритмов
	 * @param result место под опознаватель длиной SUITE_STAMP
	 *
	 * @details Значение suite_id раздела 5.1 RFC 9180 для расписания ключей
	 *
	 */
	static void stamp(const suite_t & suite, uint8_t * result) noexcept {
		// Записываем метку «HPKE»
		::memcpy(result, "HPKE", 4);
		// Записываем номер способа инкапсуляции
		inscribe(static_cast <uint16_t> (suite.kem), result + 4);
		// Записываем номер функции выработки ключа
		inscribe(static_cast <uint16_t> (suite.kdf), result + 6);
		// Записываем номер шифра
		inscribe(static_cast <uint16_t> (suite.aead), result + 8);
	}
	/**
	 * @brief Метод меченого извлечения ключа
	 *
	 * @param hash     алгоритм хеширования
	 * @param salt     соль: пустая заменяется нулями в длину хеша
	 * @param suite    просмотр опознавателя набора либо способа инкапсуляции
	 * @param label    метка извлечения
	 * @param material исходный ключевой материал, вправе быть пустым
	 * @param result   место под извлечённый ключ в длину хеша
	 * @return         признак успешности извлечения
	 *
	 * @details Функция LabeledExtract раздела 4 RFC 9180: Extract(salt, «HPKE-v1» || suite_id || label || ikm)
	 *
	 */
	static bool absorb(const digest::hash_t hash, const view_t & salt, const view_t & suite, const char * label, const view_t & material, uint8_t * result) noexcept {
		// Длина хеша
		const size_t length = digest::length(hash);
		// Нулевая соль в длину хеша: раздел 2.2 RFC 5869
		uint8_t zeros[HASH_SIZE];
		// Обнуляем нулевую соль
		::memset(zeros, 0, sizeof(zeros));
		// Объект имитовставки
		digest::mac_t mac;
		// Заводим имитовставку на соли
		if(!mac.start(hash, ((salt.size > 0) ? salt : view_t(zeros, length))))
			// Выводим отказ извлечения
			return false;
		// Подаём метку издания
		mac.update(view_t(reinterpret_cast <const uint8_t *> (VERSION), ::strlen(VERSION)));
		// Подаём опознаватель набора
		mac.update(suite);
		// Подаём метку извлечения
		mac.update(view_t(reinterpret_cast <const uint8_t *> (label), ::strlen(label)));
		// Если материал не пуст
		if(material.size > 0)
			// Подаём материал
			mac.update(material);
		// Выводим итог имитовставки
		return mac.finish(result, length);
	}
	/**
	 * @brief Метод меченого растяжения ключа
	 *
	 * @param hash   алгоритм хеширования
	 * @param key    псевдослучайный ключ в длину хеша
	 * @param suite  просмотр опознавателя набора либо способа инкапсуляции
	 * @param label  метка растяжения
	 * @param info   привязка растяжения, вправе быть пустой
	 * @param result место под материал
	 * @param size   длина материала, от одного байта до 255 длин хеша
	 * @return       признак успешности растяжения
	 *
	 * @details Функция LabeledExpand раздела 4 RFC 9180: Expand(prk, I2OSP(L, 2) || «HPKE-v1» ||
	 *          suite_id || label || info, L); растяжение идёт по разделу 2.3 RFC 5869 частями
	 *          T(i) = HMAC(prk, T(i-1) || info' || i) без склейки привязки в один буфер
	 *
	 */
	static bool unfold(const digest::hash_t hash, const view_t & key, const view_t & suite, const char * label, const view_t & info, uint8_t * result, const size_t size) noexcept {
		// Длина хеша
		const size_t length = digest::length(hash);
		// Если длина материала недопустима
		if((size == 0) || (size > (255 * length)))
			// Выводим отказ растяжения
			return false;
		// Двухбайтовая запись длины материала
		uint8_t width[2];
		// Записываем длину материала
		inscribe(static_cast <uint16_t> (size), width);
		// Предыдущий блок растяжения
		uint8_t previous[HASH_SIZE];
		// Число выданных байтов
		size_t offset = 0;
		// Номер блока растяжения
		uint8_t counter = 0;
		// Объект имитовставки
		digest::mac_t mac;
		// Заводим имитовставку на ключе
		if(!mac.start(hash, key))
			// Выводим отказ растяжения
			return false;
		/**
		 * Выполняем выработку блоков растяжения
		 */
		while(offset < size){
			// Увеличиваем номер блока
			counter++;
			// Если блок не первый
			if(offset > 0){
				// Перезаводим имитовставку на том же ключе
				if(!mac.restart()){
					// Стираем предыдущий блок
					wipe(previous, sizeof(previous));
					// Выводим отказ растяжения
					return false;
				}
				// Подаём предыдущий блок
				mac.update(view_t(previous, length));
			}
			// Подаём длину материала
			mac.update(view_t(width, sizeof(width)));
			// Подаём метку издания
			mac.update(view_t(reinterpret_cast <const uint8_t *> (VERSION), ::strlen(VERSION)));
			// Подаём опознаватель набора
			mac.update(suite);
			// Подаём метку растяжения
			mac.update(view_t(reinterpret_cast <const uint8_t *> (label), ::strlen(label)));
			// Если привязка не пуста
			if(info.size > 0)
				// Подаём привязку
				mac.update(info);
			// Подаём номер блока
			mac.update(view_t(&counter, 1));
			// Вырабатываем блок
			if(!mac.finish(previous, length)){
				// Стираем предыдущий блок
				wipe(previous, sizeof(previous));
				// Стираем выданный материал
				wipe(result, offset);
				// Выводим отказ растяжения
				return false;
			}
			// Длина выдаваемой части блока
			const size_t part = (((size - offset) < length) ? (size - offset) : length);
			// Копируем часть блока в материал
			::memcpy(result + offset, previous, part);
			// Сдвигаем число выданных байтов
			offset += part;
		}
		// Стираем предыдущий блок
		wipe(previous, sizeof(previous));
		// Выводим успех растяжения
		return true;
	}
	/**
	 * @brief Метод выработки одноступенчатой функцией с заданным числом кругов
	 *
	 * @param kdf     функция выработки ключа
	 * @param suite   просмотр опознавателя набора либо способа инкапсуляции
	 * @param label   метка выработки
	 * @param context привязка выработки, вправе быть пустой
	 * @param material исходный ключевой материал, вправе быть пустым
	 * @param result  место под материал
	 * @param size    длина материала в байтах
	 * @return        признак успешности выработки
	 *
	 * @details Функция LabeledDerive раздела 4.4 draft-ietf-hpke-hpke: выжимание из
	 *          ikm ‖ «HPKE-v1» ‖ suite_id ‖ lengthPrefixed(label) ‖ I2OSP(L, 2) ‖ context
	 *          губкой функции; у TurboSHAKE перестановка Keccak-p[1600, 12] вместо
	 *          Keccak-f[1600] (24 круга) по RFC 9861, байт дополнения у обеих 0x1F
	 *
	 */
	static bool labeled(const kdf_t kdf, const view_t & suite, const char * label, const view_t & context, const view_t & material, uint8_t * result, const size_t size) noexcept {
		// Если функция не одноступенчатая либо места под итог нет
		if(!onestage(kdf) || ((result == nullptr) && (size > 0)))
			// Выводим отказ выработки
			return false;
		// Двухбайтовые записи длин: метки и материала
		uint8_t width[2], extent[2];
		// Куски сообщения губки по порядку: материал, метка издания, опознаватель
		// набора, длина метки, метка, длина материала, привязка
		view_t pieces[7];
		// Число кусков
		size_t count = 0;
		// Подаём материал
		pieces[count++] = material;
		// Подаём метку издания
		pieces[count++] = view_t(reinterpret_cast <const uint8_t *> (VERSION), ::strlen(VERSION));
		// Подаём опознаватель набора
		pieces[count++] = suite;
		// Записываем длину метки
		inscribe(static_cast <uint16_t> (::strlen(label)), width);
		// Подаём длину метки
		pieces[count++] = view_t(width, sizeof(width));
		// Подаём метку выработки
		pieces[count++] = view_t(reinterpret_cast <const uint8_t *> (label), ::strlen(label));
		// Записываем длину материала
		inscribe(static_cast <uint16_t> (size), extent);
		// Подаём длину материала
		pieces[count++] = view_t(extent, sizeof(extent));
		// Подаём привязку
		pieces[count++] = context;
		// Выжимаем материал
		xof(kdf, pieces, count, result, size);
		// Выводим успех выработки
		return true;
	}
	/**
	 * @brief Метод разворота записи области байтов
	 *
	 * @param source переносимая область
	 * @param result место, в которое переносится область
	 * @param size   размер области в байтах
	 *
	 */
	static void reverse(const uint8_t * source, uint8_t * result, const size_t size) noexcept {
		/**
		 * Выполняем перебор байтов переносимой области
		 */
		for(size_t i = 0; i < size; i++)
			// Переносим очередной байт с конца области
			result[i] = source[size - i - 1];
	}
	/**
	 * @brief Метод извлечения функции выработки ключа способа инкапсуляции
	 *
	 * @param kem способ инкапсуляции ключа
	 * @return    функция выработки ключа либо NONE
	 *
	 * @details У способов Диффи-Хеллмана функция своя у каждого способа (раздел 7.1
	 *          RFC 9180); у чистого ML-KEM и гибридов выработка ключей идёт SHAKE256
	 *          (разделы 3 и 4 draft-ietf-hpke-pq), а общее значение готово само по себе
	 *
	 */
	static kdf_t derivation(const kem_t kem) noexcept {
		/**
		 * Определяем способ инкапсуляции
		 */
		switch(static_cast <uint16_t> (kem)){
			// DHKEM(P-256, HKDF-SHA256)
			case static_cast <uint16_t> (kem_t::P256_HKDF_SHA256):
				// Выводим HKDF-SHA256
				return kdf_t::HKDF_SHA256;
			// DHKEM(P-384, HKDF-SHA384)
			case static_cast <uint16_t> (kem_t::P384_HKDF_SHA384):
				// Выводим HKDF-SHA384
				return kdf_t::HKDF_SHA384;
			// DHKEM(P-521, HKDF-SHA512)
			case static_cast <uint16_t> (kem_t::P521_HKDF_SHA512):
				// Выводим HKDF-SHA512
				return kdf_t::HKDF_SHA512;
			// DHKEM(X25519, HKDF-SHA256)
			case static_cast <uint16_t> (kem_t::X25519_HKDF_SHA256):
				// Выводим HKDF-SHA256
				return kdf_t::HKDF_SHA256;
			// DHKEM(X448, HKDF-SHA512)
			case static_cast <uint16_t> (kem_t::X448_HKDF_SHA512):
				// Выводим HKDF-SHA512
				return kdf_t::HKDF_SHA512;
			// Чистый ML-KEM и гибриды: выработка ключей на SHAKE256
			case static_cast <uint16_t> (kem_t::MLKEM512):
			case static_cast <uint16_t> (kem_t::MLKEM768):
			case static_cast <uint16_t> (kem_t::MLKEM1024):
			case static_cast <uint16_t> (kem_t::MLKEM768_P256):
			case static_cast <uint16_t> (kem_t::MLKEM1024_P384):
			case static_cast <uint16_t> (kem_t::MLKEM768_X25519):
				// Выводим SHAKE256
				return kdf_t::SHAKE256;
		}
		// Выводим отсутствие функции
		return kdf_t::NONE;
	}
	/**
	 * @brief Метод извлечения опознавателя кривой способа инкапсуляции
	 *
	 * @param kem способ инкапсуляции ключа
	 * @return    опознаватель набора параметров кривой либо nullptr
	 *
	 */
	static const char * curveoid(const kem_t kem) noexcept {
		/**
		 * Определяем способ инкапсуляции
		 */
		switch(static_cast <uint16_t> (kem)){
			// P-256
			case static_cast <uint16_t> (kem_t::P256_HKDF_SHA256):
			case static_cast <uint16_t> (kem_t::MLKEM768_P256):
				// Выводим опознаватель secp256r1
				return "1.2.840.10045.3.1.7";
			// P-384
			case static_cast <uint16_t> (kem_t::P384_HKDF_SHA384):
			case static_cast <uint16_t> (kem_t::MLKEM1024_P384):
				// Выводим опознаватель secp384r1
				return "1.3.132.0.34";
			// P-521
			case static_cast <uint16_t> (kem_t::P521_HKDF_SHA512):
				// Выводим опознаватель secp521r1
				return "1.3.132.0.35";
		}
		// Выводим отсутствие кривой
		return nullptr;
	}
	/**
	 * @brief Метод извлечения набора параметров ML-KEM способа инкапсуляции
	 *
	 * @param kem способ инкапсуляции ключа
	 * @return    набор параметров ML-KEM либо NONE
	 *
	 */
	static agreement::kem_t mlkemset(const kem_t kem) noexcept {
		/**
		 * Определяем способ инкапсуляции
		 */
		switch(static_cast <uint16_t> (kem)){
			// ML-KEM-512
			case static_cast <uint16_t> (kem_t::MLKEM512):
				// Выводим набор ML-KEM-512
				return agreement::kem_t::MLKEM512;
			// ML-KEM-768
			case static_cast <uint16_t> (kem_t::MLKEM768):
			case static_cast <uint16_t> (kem_t::MLKEM768_P256):
			case static_cast <uint16_t> (kem_t::MLKEM768_X25519):
				// Выводим набор ML-KEM-768
				return agreement::kem_t::MLKEM768;
			// ML-KEM-1024
			case static_cast <uint16_t> (kem_t::MLKEM1024):
			case static_cast <uint16_t> (kem_t::MLKEM1024_P384):
				// Выводим набор ML-KEM-1024
				return agreement::kem_t::MLKEM1024;
		}
		// Выводим отсутствие набора
		return agreement::kem_t::NONE;
	}
	/**
	 * @brief Метод извлечения длины зерна традиционной составляющей гибрида
	 *
	 * @param kem способ инкапсуляции ключа
	 * @return    длина зерна в байтах либо ноль у негибридного способа
	 *
	 * @details Значения Nseed групп раздела 3.1 draft-irtf-cfrg-concrete-hybrid-kems:
	 *          128 у P-256 (четыре куска отбора по 32 байта), 48 у P-384, 32 у Curve25519
	 *
	 */
	static size_t tradition(const kem_t kem) noexcept {
		/**
		 * Определяем способ инкапсуляции
		 */
		switch(static_cast <uint16_t> (kem)){
			// Гибрид с P-256
			case static_cast <uint16_t> (kem_t::MLKEM768_P256):
				// Выводим длину зерна P-256
				return 128;
			// Гибрид с P-384
			case static_cast <uint16_t> (kem_t::MLKEM1024_P384):
				// Выводим длину зерна P-384
				return 48;
			// Гибрид с Curve25519
			case static_cast <uint16_t> (kem_t::MLKEM768_X25519):
				// Выводим длину зерна Curve25519
				return 32;
		}
		// Выводим отсутствие зерна
		return 0;
	}
	/**
	 * @brief Метод извлечения метки гибридного способа
	 *
	 * @param kem способ инкапсуляции ключа
	 * @return    метка способа для сочетателя C2PRI
	 *
	 * @details Метки раздела 4 draft-irtf-cfrg-concrete-hybrid-kems: у X-Wing метка
	 *          «\.//^\» (hex 5C2E2F2F5E5C)
	 *
	 */
	static const uint8_t * hybridlabel(const kem_t kem) noexcept {
		// Метка гибрида ML-KEM-768 и P-256
		static const uint8_t LABEL_P256[] = "MLKEM768-P256";
		// Метка гибрида ML-KEM-1024 и P-384
		static const uint8_t LABEL_P384[] = "MLKEM1024-P384";
		// Метка гибрида ML-KEM-768 и X25519 (X-Wing)
		static const uint8_t LABEL_X25519[] = "\\.//^\\";
		/**
		 * Определяем способ инкапсуляции
		 */
		switch(static_cast <uint16_t> (kem)){
			// Гибрид с P-256
			case static_cast <uint16_t> (kem_t::MLKEM768_P256):
				// Выводим метку
				return LABEL_P256;
			// Гибрид с P-384
			case static_cast <uint16_t> (kem_t::MLKEM1024_P384):
				// Выводим метку
				return LABEL_P384;
			// Гибрид с Curve25519
			case static_cast <uint16_t> (kem_t::MLKEM768_X25519):
				// Выводим метку
				return LABEL_X25519;
		}
		// Выводим пустую метку
		return reinterpret_cast <const uint8_t *> ("");
	}
	/**
	 * @brief Метод извлечения длины метки гибридного способа
	 *
	 * @param kem способ инкапсуляции ключа
	 * @return    длина метки в байтах
	 *
	 */
	static size_t hybridmark(const kem_t kem) noexcept {
		/**
		 * Определяем способ инкапсуляции
		 */
		switch(static_cast <uint16_t> (kem)){
			// Гибрид с P-256: «MLKEM768-P256»
			case static_cast <uint16_t> (kem_t::MLKEM768_P256):
				// Выводим длину метки
				return 13;
			// Гибрид с P-384: «MLKEM1024-P384»
			case static_cast <uint16_t> (kem_t::MLKEM1024_P384):
				// Выводим длину метки
				return 14;
			// Гибрид с Curve25519: «\.//^\»
			case static_cast <uint16_t> (kem_t::MLKEM768_X25519):
				// Выводим длину метки
				return 6;
		}
		// Выводим пустую длину
		return 0;
	}

	/**
	 * @brief Метод проверки признака способа Диффи-Хеллмана
	 *
	 * @param kem способ инкапсуляции ключа
	 * @return    признак того, что способ есть DHKEM
	 *
	 */
	static bool diffie(const kem_t kem) noexcept {
		// Выводим признак способов Диффи-Хеллмана
		return ((kem == kem_t::P256_HKDF_SHA256) || (kem == kem_t::P384_HKDF_SHA384) || (kem == kem_t::P521_HKDF_SHA512) || (kem == kem_t::X25519_HKDF_SHA256) || (kem == kem_t::X448_HKDF_SHA512));
	}
	/**
	 * @brief Метод проверки признака чистого ML-KEM
	 *
	 * @param kem способ инкапсуляции ключа
	 * @return    признак того, что способ есть чистый ML-KEM
	 *
	 */
	static bool puremlkem(const kem_t kem) noexcept {
		// Выводим признак чистого ML-KEM
		return ((kem == kem_t::MLKEM512) || (kem == kem_t::MLKEM768) || (kem == kem_t::MLKEM1024));
	}
	/**
	 * @brief Метод проверки признака гибридного способа
	 *
	 * @param kem способ инкапсуляции ключа
	 * @return    признак того, что способ есть гибрид ML-KEM и группы
	 *
	 */
	static bool hybrid(const kem_t kem) noexcept {
		// Выводим признак гибридного способа
		return ((kem == kem_t::MLKEM768_P256) || (kem == kem_t::MLKEM1024_P384) || (kem == kem_t::MLKEM768_X25519));
	}
	/**
	 * @brief Метод извлечения длины общего значения способа инкапсуляции
	 *
	 * @param kem способ инкапсуляции ключа
	 * @return    длина общего значения в байтах (Nsecret)
	 *
	 * @details У способов Диффи-Хеллмана общее значение длиной в размер кривой, у чистого
	 *          ML-KEM и гибридов - тридцать два байта (таблицы 2 и 3 draft-ietf-hpke-pq)
	 *
	 */
	static size_t nsecret(const kem_t kem) noexcept {
		// У чистого ML-KEM и гибридов общее значение в тридцать два байта
		if(puremlkem(kem) || hybrid(kem))
			// Выводим длину общего значения
			return 32;
		// У способов Диффи-Хеллмана общее значение длиной в размер кривой
		return secret(kem);
	}


	/**
	 * @brief Метод выработки общего значения способа Диффи-Хеллмана
	 *
	 * @param kem     способ инкапсуляции ключа
	 * @param dh      просмотр общих значений Диффи-Хеллмана: одно либо два
	 * @param binding просмотр привязки способа инкапсуляции: инкапсулированный ключ и открытые ключи
	 * @param result  место под общее значение длиной Nsecret способа
	 * @return        признак успешности выработки
	 *
	 * @details Функция ExtractAndExpand раздела 4.5 draft-ietf-hpke-hpke для способа:
	 *          у двухступенчатой функции способа - eae_prk = LabeledExtract("", "eae_prk", dh),
	 *          shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret);
	 *          у одноступенчатой - LabeledDerive(dh, "shared_secret", kem_context, Nsecret)
	 *
	 */
	static bool combine(const kem_t kem, const view_t & dh, const view_t & binding, uint8_t * result) noexcept {
		// Опознаватель способа инкапсуляции
		uint8_t suite[KEM_STAMP];
		// Составляем опознаватель способа
		stamp(kem, suite);
		// Функция выработки ключа способа
		const kdf_t kdf = derivation(kem);
		// Длина общего значения способа
		const size_t size = nsecret(kem);
		// Если функция одноступенчатая
		if(onestage(kdf))
			// Вырабатываем общее значение выжиманием
			return labeled(kdf, view_t(suite, sizeof(suite)), "shared_secret", binding, dh, result, size);
		// Алгоритм хеширования функции способа
		const digest::hash_t hash = hashing(kdf);
		// Псевдослучайный ключ извлечения
		uint8_t prk[HASH_SIZE];
		// Извлекаем ключ из общих значений
		if(!absorb(hash, view_t(), view_t(suite, sizeof(suite)), "eae_prk", dh, prk)){
			// Стираем ключ извлечения
			wipe(prk, sizeof(prk));
			// Выводим отказ выработки
			return false;
		}
		// Растягиваем ключ в общее значение
		const bool status = unfold(hash, view_t(prk, digest::length(hash)), view_t(suite, sizeof(suite)), "shared_secret", binding, result, size);
		// Стираем ключ извлечения
		wipe(prk, sizeof(prk));
		// Выводим итог выработки
		return status;
	}
	/**
	 * @brief Метод выработки пары ключей способа Диффи-Хеллмана из исходного материала
	 *
	 * @param kem      способ инкапсуляции ключа
	 * @param material исходный ключевой материал
	 * @param secret   место под секретный ключ длиной secret(kem)
	 * @param point    место под открытый ключ длиной length(kem)
	 * @return         признак успешности выработки
	 *
	 * @details Функция DeriveKeyPair раздела 7.1.3 draft-ietf-hpke-hpke: у кривых NIST -
	 *          отбор кандидатов LabeledDerive/LabeledExpand(ikm, "candidate", I2OSP(counter, 1),
	 *          Nsk) до 0 < sk < order; у X25519 и X448 - вывод ключа меткой «sk»
	 *
	 */
	static bool expand(const kem_t kem, const view_t & material, uint8_t * secret, uint8_t * point) noexcept {
		// Опознаватель способа инкапсуляции
		uint8_t suite[KEM_STAMP];
		// Составляем опознаватель способа
		stamp(kem, suite);
		// Функция выработки ключа способа
		const kdf_t kdf = derivation(kem);
		// Длина секретного ключа способа
		const size_t size = nts::hpke::secret(kem);
		/**
		 * Определяем способ инкапсуляции
		 */
		switch(static_cast <uint16_t> (kem)){
			// DHKEM(X25519, HKDF-SHA256)
			case static_cast <uint16_t> (kem_t::X25519_HKDF_SHA256): {
				// Секретный ключ
				uint8_t key[X25519_SIZE];
				// Признак успешности выработки
				bool status = false;
				// Если функция одноступенчатая
				if(onestage(kdf))
					// Вырабатываем ключ выжиманием
					status = labeled(kdf, view_t(suite, sizeof(suite)), "sk", view_t(), material, key, sizeof(key));
				else {
					// Псевдослучайный ключ извлечения
					uint8_t prk[HASH_SIZE];
					// Извлекаем ключ из материала
					status = absorb(digest::hash_t::SHA256, view_t(), view_t(suite, sizeof(suite)), "dkp_prk", material, prk);
					// Растягиваем ключ в секретный ключ
					status = (status && unfold(digest::hash_t::SHA256, view_t(prk, digest::length(digest::hash_t::SHA256)), view_t(suite, sizeof(suite)), "sk", view_t(), key, sizeof(key)));
					// Стираем ключ извлечения
					wipe(prk, sizeof(prk));
				}
				// Вычисляем открытый ключ
				status = (status && agreement::x25519(view_t(key, sizeof(key)), point));
				// Копируем секретный ключ
				if(status)
					// Переносим ключ
					::memcpy(secret, key, sizeof(key));
				// Стираем ключ
				wipe(key, sizeof(key));
				// Выводим итог выработки
				return status;
			}
			// DHKEM(X448, HKDF-SHA512)
			case static_cast <uint16_t> (kem_t::X448_HKDF_SHA512): {
				// Секретный ключ
				uint8_t key[agreement::X448_SIZE];
				// Признак успешности выработки
				bool status = false;
				// Если функция одноступенчатая
				if(onestage(kdf))
					// Вырабатываем ключ выжиманием
					status = labeled(kdf, view_t(suite, sizeof(suite)), "sk", view_t(), material, key, sizeof(key));
				else {
					// Псевдослучайный ключ извлечения
					uint8_t prk[HASH_SIZE];
					// Извлекаем ключ из материала
					status = absorb(digest::hash_t::SHA512, view_t(), view_t(suite, sizeof(suite)), "dkp_prk", material, prk);
					// Растягиваем ключ в секретный ключ
					status = (status && unfold(digest::hash_t::SHA512, view_t(prk, digest::length(digest::hash_t::SHA512)), view_t(suite, sizeof(suite)), "sk", view_t(), key, sizeof(key)));
					// Стираем ключ извлечения
					wipe(prk, sizeof(prk));
				}
				// Вычисляем открытый ключ
				status = (status && agreement::x448(view_t(key, sizeof(key)), point));
				// Копируем секретный ключ
				if(status)
					// Переносим ключ
					::memcpy(secret, key, sizeof(key));
				// Стираем ключ
				wipe(key, sizeof(key));
				// Выводим итог выработки
				return status;
			}
			// DHKEM кривых NIST
			case static_cast <uint16_t> (kem_t::P256_HKDF_SHA256):
			case static_cast <uint16_t> (kem_t::P384_HKDF_SHA384):
			case static_cast <uint16_t> (kem_t::P521_HKDF_SHA512): {
				// Кривая
				curve::curve_t curve;
				// Если параметры кривой не найдены
				if(!curve::parameters(curveoid(kem), curve))
					// Выводим отказ выработки
					return false;
				// Арифметика порядка подгруппы точек кривой
				const math::modulus_t & order = curve.order();
				// Маска старшего байта кандидата: 0xFF у P-256 и P-384, 0x01 у P-521
				const uint8_t bitmask = ((kem == kem_t::P521_HKDF_SHA512) ? 0x01 : 0xFF);
				// Кандидат в секретный ключ
				uint8_t candidate[SCALAR_SIZE];
				// Признак успешности выработки
				bool status = false;
				// Псевдослучайный ключ извлечения
				uint8_t prk[HASH_SIZE];
				// Признак извлечения ключа
				bool keyed = false;
				// Если функция двухступенчатая: извлекаем ключ из материала один раз
				if(!onestage(kdf))
					// Извлекаем ключ из материала
					keyed = absorb(hashing(kdf), view_t(), view_t(suite, sizeof(suite)), "dkp_prk", material, prk);
				/**
				 * Выполняем отбор кандидата в секретный ключ
				 */
				for(size_t counter = 0; !status && (counter <= 255); counter++){
					// Номер кандидата
					const uint8_t number = static_cast <uint8_t> (counter);
					// Если функция одноступенчатая
					if(onestage(kdf))
						// Вырабатываем кандидата выжиманием
						status = labeled(kdf, view_t(suite, sizeof(suite)), "candidate", view_t(&number, sizeof(number)), material, candidate, size);
					// Иначе растягиваем кандидата из извлечённого ключа
					else
						// Вырабатываем кандидата растяжением
						status = (keyed && unfold(hashing(kdf), view_t(prk, digest::length(hashing(kdf))), view_t(suite, sizeof(suite)), "candidate", view_t(&number, sizeof(number)), candidate, size));
					// Если кандидат не выработан
					if(!status)
						// Прерываем отбор
						break;
					// Накладываем маску старшего байта
					candidate[0] &= bitmask;
					// Число кандидата
					math::number_t value;
					// Разбираем кандидата: ноль и число не меньше порядка отвергаются
					if(order.load(view_t(candidate, size), value) && !order.zero(value)){
						// Открытый ключ
						curve::point_t opened;
						// Выполняем умножение образующей точки на секретный ключ
						curve.product(value, opened);
						// Координаты открытого ключа старшим байтом вперёд
						uint8_t first[math::NUMBER_SIZE], second[math::NUMBER_SIZE];
						// Записываем координаты открытого ключа
						status = curve.coordinates(opened, first, second, size);
						// Складываем открытый ключ в несжатом виде
						if(status){
							// Записываем признак несжатой точки
							point[0] = 0x04;
							// Записываем первую координату
							::memcpy(point + 1, first, size);
							// Записываем вторую координату
							::memcpy(point + 1 + size, second, size);
							// Переносим секретный ключ
							::memcpy(secret, candidate, size);
						}
						// Стираем координаты
						wipe(first, sizeof(first));
						wipe(second, sizeof(second));
						// Стираем точку
						wipe(&opened, sizeof(opened));
					// Кандидат не годится: продолжаем отбор
					} else
						// Сбрасываем признак
						status = false;
					// Стираем число кандидата
					wipe(value.words, sizeof(value.words));
				}
				// Стираем кандидата
				wipe(candidate, sizeof(candidate));
				// Стираем ключ извлечения
				wipe(prk, sizeof(prk));
				// Выводим итог выработки
				return status;
			}
		}
		// Выводим отказ выработки
		return false;
	}
	/**
	 * @brief Метод выработки общего значения Диффи-Хеллмана кривой NIST
	 *
	 * @param kem    способ инкапсуляции ключа
	 * @param secret секретный ключ своей стороны старшим байтом вперёд
	 * @param peer   открытый ключ встречной стороны в несжатом виде
	 * @param result место под общее значение длиной в размер кривой
	 * @return       признак успешности выработки
	 *
	 * @details Открытый ключ проверяется на принадлежность кривой разбором точки, а
	 *          кратная точка — на обращение в ноль: обе проверки выполняет `agreement::ecdhe`
	 *
	 */
	static bool exchange(const kem_t kem, const view_t & secret, const view_t & peer, uint8_t * result) noexcept {
		// Кривая
		curve::curve_t curve;
		// Если параметры кривой не найдены либо точка не в несжатом виде
		if(!curve::parameters(curveoid(kem), curve) || (peer.data == nullptr) || (peer.size != (1 + (2 * curve.size()))) || (peer.data[0] != 0x04))
			// Выводим отказ выработки
			return false;
		// Размер записи координаты кривой
		const size_t size = curve.size();
		// Секретный ключ младшим байтом вперёд
		uint8_t scalar[SCALAR_SIZE];
		// Переводим секретный ключ в запись младшим байтом вперёд
		reverse(secret.data, scalar, size);
		// Точка младшим байтом вперёд
		uint8_t raw[math::NUMBER_SIZE * 2];
		// Переводим координаты точки в запись младшим байтом вперёд
		reverse(peer.data + 1, raw, size);
		reverse(peer.data + 1 + size, raw + size, size);
		// Общее значение младшим байтом вперёд
		uint8_t little[math::NUMBER_SIZE];
		// Вырабатываем общее значение
		const bool status = agreement::ecdhe(curve, view_t(scalar, size), view_t(raw, size * 2), little);
		// Переводим общее значение в запись старшим байтом вперёд
		if(status)
			// Переводим запись
			reverse(little, result, size);
		// Стираем записи
		wipe(scalar, sizeof(scalar));
		wipe(raw, sizeof(raw));
		wipe(little, sizeof(little));
		// Выводим итог выработки
		return status;
	}
	/**
	 * @brief Метод выработки открытого ключа кривой NIST по секретному ключу
	 *
	 * @param kem    способ инкапсуляции ключа
	 * @param secret секретный ключ старшим байтом вперёд
	 * @param point  место под открытый ключ в несжатом виде
	 * @return       признак успешности выработки
	 *
	 */
	static bool publish(const kem_t kem, const view_t & secret, uint8_t * point) noexcept {
		// Кривая
		curve::curve_t curve;
		// Если параметры кривой не найдены
		if(!curve::parameters(curveoid(kem), curve))
			// Выводим отказ выработки
			return false;
		// Размер записи координаты кривой
		const size_t size = curve.size();
		// Арифметика порядка подгруппы точек кривой
		const math::modulus_t & order = curve.order();
		// Число секретного ключа
		math::number_t value;
		// Разбираем секретный ключ: ноль и число не меньше порядка отвергаются
		bool status = (order.load(secret, value) && !order.zero(value));
		// Если секретный ключ годен
		if(status){
			// Открытый ключ
			curve::point_t opened;
			// Выполняем умножение образующей точки на секретный ключ
			curve.product(value, opened);
			// Координаты открытого ключа старшим байтом вперёд
			uint8_t first[math::NUMBER_SIZE], second[math::NUMBER_SIZE];
			// Записываем координаты открытого ключа
			status = curve.coordinates(opened, first, second, size);
			// Складываем открытый ключ в несжатом виде
			if(status){
				// Записываем признак несжатой точки
				point[0] = 0x04;
				// Записываем первую координату
				::memcpy(point + 1, first, size);
				// Записываем вторую координату
				::memcpy(point + 1 + size, second, size);
			}
			// Стираем координаты
			wipe(first, sizeof(first));
			wipe(second, sizeof(second));
			// Стираем точку
			wipe(&opened, sizeof(opened));
		}
		// Стираем число секретного ключа
		wipe(value.words, sizeof(value.words));
		// Выводим итог выработки
		return status;
	}
	/**
	 * @brief Метод выработки пары ключей чистого ML-KEM из зерна
	 *
	 * @param kem    способ инкапсуляции ключа
	 * @param seed   зерно в шестьдесят четыре байта
	 * @param point  место под ключ инкапсуляции
	 * @return       признак успешности выработки
	 *
	 * @details Функция expandDecapsKey раздела 3 draft-ietf-hpke-pq: KeyGen_internal(d, z)
	 *          FIPS 203; секретным ключом способа служит само зерно
	 *
	 */
	static bool expandmlkem(const kem_t kem, const view_t & seed, uint8_t * point) noexcept {
		// Набор параметров ML-KEM
		const agreement::kem_t set = mlkemset(kem);
		// Ключ декапсуляции полной записью стандарта: dk_PKE ‖ ek ‖ H(ek) ‖ z
		uint8_t expanded[2400];
		// Вырабатываем пару ключей из зерна
		const bool status = agreement::generate(set, seed, point, expanded);
		// Стираем ключ декапсуляции
		wipe(expanded, sizeof(expanded));
		// Выводим итог выработки
		return status;
	}
	/**
	 * @brief Метод отбора скаляра кривой NIST из зерна
	 *
	 * @param kem    способ инкапсуляции ключа
	 * @param seed   зерно отбора длиной Nseed группы
	 * @param result место под скаляр длиной в размер кривой старшим байтом вперёд
	 * @return       признак успешности отбора
	 *
	 * @details Функция RandomScalar раздела 3.1.1 draft-irtf-cfrg-concrete-hybrid-kems:
	 *          отбор кусков зерна по Nscalar байтов до 0 < sk < order
	 *
	 */
	static bool pick(const kem_t kem, const view_t & seed, uint8_t * result) noexcept {
		// Кривая
		curve::curve_t curve;
		// Если параметры кривой не найдены
		if(!curve::parameters(curveoid(kem), curve))
			// Выводим отказ отбора
			return false;
		// Размер записи координаты кривой
		const size_t size = curve.size();
		// Арифметика порядка подгруппы точек кривой
		const math::modulus_t & order = curve.order();
		// Признак успешности отбора
		bool status = false;
		/**
		 * Выполняем отбор скаляра кусками зерна по размеру кривой
		 */
		for(size_t at = 0; !status && ((at + size) <= seed.size); at += size){
			// Число куска
			math::number_t value;
			// Разбираем кусок: ноль и число не меньше порядка отвергаются
			if(order.load(view_t(seed.data + at, size), value) && !order.zero(value))
				// Записываем скаляр старшим байтом вперёд
				status = order.store(value, result, size);
			// Стираем число куска
			wipe(value.words, sizeof(value.words));
		}
		// Выводим итог отбора
		return status;
	}
	/**
	 * @brief Метод выработки составляющих гибридного способа из зерна
	 *
	 * @param kem    способ инкапсуляции ключа
	 * @param seed   зерно в тридцать два байта
	 * @param pq     место под зерно ML-KEM в шестьдесят четыре байта
	 * @param trad   место под зерно традиционной составляющей
	 * @return       признак успешности выработки
	 *
	 * @details Функция expandDecapsKeyG раздела 5.1.1 draft-irtf-cfrg-hybrid-kems:
	 *          seed_full = SHAKE256(seed, 64 + Nseed группы), разрез на зерно ML-KEM
	 *          и зерно группы
	 *
	 */
	static bool spread(const kem_t kem, const view_t & seed, uint8_t * pq, uint8_t * trad) noexcept {
		// Длина зерна традиционной составляющей
		const size_t size = tradition(kem);
		// Зерно целиком
		uint8_t full[SEED_FULL];
		// Вырабатываем зерно выжиманием SHAKE256
		xof(kdf_t::SHAKE256, &seed, 1, full, MLKEM_SEED_SIZE + size);
		// Разрезаем зерно: впереди зерно ML-KEM
		::memcpy(pq, full, MLKEM_SEED_SIZE);
		// Затем зерно группы
		::memcpy(trad, full + MLKEM_SEED_SIZE, size);
		// Стираем зерно целиком
		wipe(full, sizeof(full));
		// Выводим успех
		return true;
	}
	/**
	 * @brief Метод выработки общего значения гибридного способа
	 *
	 * @param kem    способ инкапсуляции ключа
	 * @param ssPQ   общее значение ML-KEM
	 * @param ssT    общее значение традиционной составляющей
	 * @param ctT    шифртекст традиционной составляющей (точка)
	 * @param ekT    открытый ключ традиционной составляющей получателя
	 * @param result место под общее значение в тридцать два байта
	 *
	 * @details Функция C2PRICombiner раздела 5.1.3 draft-irtf-cfrg-hybrid-kems:
	 *          SHA3-256(ss_PQ ‖ ss_T ‖ ct_T ‖ ek_T ‖ Label)
	 *
	 */
	static void fuse(const kem_t kem, const view_t & ssPQ, const view_t & ssT, const view_t & ctT, const view_t & ekT, uint8_t * result) noexcept {
		// Объект губки
		digest::keccak_t hash(digest::sha3_t::SHA3_256);
		// Подаём общее значение ML-KEM
		hash.update(ssPQ);
		// Подаём общее значение традиционной составляющей
		hash.update(ssT);
		// Подаём шифртекст традиционной составляющей
		hash.update(ctT);
		// Подаём открытый ключ традиционной составляющей получателя
		hash.update(ekT);
		// Подаём метку способа
		hash.update(view_t(hybridlabel(kem), hybridmark(kem)));
		// Снимаем итог
		(void) hash.finish(result, MLKEM_SHARED_SIZE);
	}
	/**
	 * @brief Метод проверки допустимости режима работы
	 *
	 * @param mode режим работы
	 * @return     признак того, что режим известен
	 *
	 */
	static bool admissible(const regime_t mode) noexcept {
		/**
		 * Определяем режим работы
		 */
		switch(static_cast <uint8_t> (mode)){
			// Известные режимы
			case static_cast <uint8_t> (regime_t::BASE):
			case static_cast <uint8_t> (regime_t::PSK):
			case static_cast <uint8_t> (regime_t::AUTH):
			case static_cast <uint8_t> (regime_t::AUTH_PSK):
				// Выводим допустимость
				return true;
		}
		// Выводим недопустимость
		return false;
	}
	/**
	 * @brief Метод проверки признака подлинности отправителя у режима
	 *
	 * @param mode режим работы
	 * @return     признак того, что режим требует ключ отправителя
	 *
	 */
	static bool demanding(const regime_t mode) noexcept {
		// Выводим признак режимов AUTH и AUTH_PSK
		return ((mode == regime_t::AUTH) || (mode == regime_t::AUTH_PSK));
	}
	/**
	 * @brief Метод проверки признака заранее разделённого ключа у режима
	 *
	 * @param mode режим работы
	 * @return     признак того, что режим требует заранее разделённый ключ
	 *
	 */
	static bool preshared(const regime_t mode) noexcept {
		// Выводим признак режимов PSK и AUTH_PSK
		return ((mode == regime_t::PSK) || (mode == regime_t::AUTH_PSK));
	}
}

/**
 * @brief Конструктор пустого набора
 *
 */
nts::hpke::Suite::Suite() noexcept : kem(kem_t::NONE), kdf(kdf_t::NONE), aead(aead_t::NONE) {}
/**
 * @brief Конструктор набора
 *
 * @param kem  способ инкапсуляции ключа
 * @param kdf  функция выработки ключа
 * @param aead шифр с проверкой подлинности
 *
 */
nts::hpke::Suite::Suite(const kem_t kem, const kdf_t kdf, const aead_t aead) noexcept : kem(kem), kdf(kdf), aead(aead) {}
/**
 * @brief Конструктор пустого ключа
 *
 */
nts::hpke::Shared::Shared() noexcept : key(), identity() {}
/**
 * @brief Конструктор ключа
 *
 * @param key      просмотр заранее разделённого ключа
 * @param identity просмотр опознавателя ключа
 *
 */
nts::hpke::Shared::Shared(const view_t & key, const view_t & identity) noexcept : key(key), identity(identity) {}
/**
 * @brief Метод извлечения длины хеша функции выработки ключа
 *
 * @param kdf функция выработки ключа
 * @return    длина хеша в байтах либо ноль у неизвестной функции
 *
 */
size_t nts::hpke::length(const kdf_t kdf) noexcept {
	// Если функция одноступенчатая: Nh таблицы 1 draft-ietf-hpke-pq
	if(onestage(kdf))
		// Выводим длину: 32 у SHAKE128 и TurboSHAKE128, 64 у SHAKE256 и TurboSHAKE256
		return (((kdf == kdf_t::SHAKE128) || (kdf == kdf_t::TURBOSHAKE128)) ? 32 : 64);
	// Выводим длину хеша алгоритма функции
	return digest::length(hashing(kdf));
}
/**
 * @brief Метод извлечения длины открытого ключа способа инкапсуляции
 *
 * @param kem способ инкапсуляции ключа
 * @return    длина открытого ключа в байтах либо ноль у неизвестного способа
 *
 */
size_t nts::hpke::length(const kem_t kem) noexcept {
	/**
	 * Определяем способ инкапсуляции
	 */
	switch(static_cast <uint16_t> (kem)){
		// DHKEM(P-256, HKDF-SHA256): несжатая точка
		case static_cast <uint16_t> (kem_t::P256_HKDF_SHA256):
			// Выводим длину ключа
			return 65;
		// DHKEM(P-384, HKDF-SHA384): несжатая точка
		case static_cast <uint16_t> (kem_t::P384_HKDF_SHA384):
			// Выводим длину ключа
			return 97;
		// DHKEM(P-521, HKDF-SHA512): несжатая точка
		case static_cast <uint16_t> (kem_t::P521_HKDF_SHA512):
			// Выводим длину ключа
			return 133;
		// DHKEM(X25519, HKDF-SHA256)
		case static_cast <uint16_t> (kem_t::X25519_HKDF_SHA256):
			// Выводим длину ключа
			return 32;
		// DHKEM(X448, HKDF-SHA512)
		case static_cast <uint16_t> (kem_t::X448_HKDF_SHA512):
			// Выводим длину ключа
			return 56;
		// ML-KEM-512
		case static_cast <uint16_t> (kem_t::MLKEM512):
			// Выводим длину ключа инкапсуляции
			return 800;
		// ML-KEM-768
		case static_cast <uint16_t> (kem_t::MLKEM768):
			// Выводим длину ключа инкапсуляции
			return 1184;
		// ML-KEM-1024
		case static_cast <uint16_t> (kem_t::MLKEM1024):
			// Выводим длину ключа инкапсуляции
			return 1568;
		// Гибрид ML-KEM-768 и P-256
		case static_cast <uint16_t> (kem_t::MLKEM768_P256):
			// Выводим длину ключа
			return 1249;
		// Гибрид ML-KEM-1024 и P-384
		case static_cast <uint16_t> (kem_t::MLKEM1024_P384):
			// Выводим длину ключа
			return 1665;
		// Гибрид ML-KEM-768 и X25519
		case static_cast <uint16_t> (kem_t::MLKEM768_X25519):
			// Выводим длину ключа
			return 1216;
	}
	// Выводим отсутствие ключа
	return 0;
}
/**
 * @brief Метод извлечения длины секретного ключа способа инкапсуляции
 *
 * @param kem способ инкапсуляции ключа
 * @return    длина секретного ключа в байтах либо ноль у неизвестного способа
 *
 */
size_t nts::hpke::secret(const kem_t kem) noexcept {
	/**
	 * Определяем способ инкапсуляции
	 */
	switch(static_cast <uint16_t> (kem)){
		// DHKEM(P-256, HKDF-SHA256)
		case static_cast <uint16_t> (kem_t::P256_HKDF_SHA256):
			// Выводим длину скаляра
			return 32;
		// DHKEM(P-384, HKDF-SHA384)
		case static_cast <uint16_t> (kem_t::P384_HKDF_SHA384):
			// Выводим длину скаляра
			return 48;
		// DHKEM(P-521, HKDF-SHA512)
		case static_cast <uint16_t> (kem_t::P521_HKDF_SHA512):
			// Выводим длину скаляра
			return 66;
		// DHKEM(X25519, HKDF-SHA256)
		case static_cast <uint16_t> (kem_t::X25519_HKDF_SHA256):
			// Выводим длину ключа
			return 32;
		// DHKEM(X448, HKDF-SHA512)
		case static_cast <uint16_t> (kem_t::X448_HKDF_SHA512):
			// Выводим длину ключа
			return 56;
		// Чистый ML-KEM: секретный ключ - зерно в шестьдесят четыре байта
		case static_cast <uint16_t> (kem_t::MLKEM512):
		case static_cast <uint16_t> (kem_t::MLKEM768):
		case static_cast <uint16_t> (kem_t::MLKEM1024):
			// Выводим длину зерна
			return 64;
		// Гибриды: секретный ключ - зерно в тридцать два байта
		case static_cast <uint16_t> (kem_t::MLKEM768_P256):
		case static_cast <uint16_t> (kem_t::MLKEM1024_P384):
		case static_cast <uint16_t> (kem_t::MLKEM768_X25519):
			// Выводим длину зерна
			return 32;
	}
	// Выводим отсутствие ключа
	return 0;
}
/**
 * @brief Метод извлечения длины инкапсулированного ключа способа инкапсуляции
 *
 * @param kem способ инкапсуляции ключа
 * @return    длина инкапсулированного ключа в байтах либо ноль у неизвестного способа
 *
 */
size_t nts::hpke::overhead(const kem_t kem) noexcept {
	/**
	 * Определяем способ инкапсуляции
	 */
	switch(static_cast <uint16_t> (kem)){
		// У способов Диффи-Хеллмана инкапсулированный ключ - открытый ключ мимолётной пары
		case static_cast <uint16_t> (kem_t::P256_HKDF_SHA256):
		case static_cast <uint16_t> (kem_t::P384_HKDF_SHA384):
		case static_cast <uint16_t> (kem_t::P521_HKDF_SHA512):
		case static_cast <uint16_t> (kem_t::X25519_HKDF_SHA256):
		case static_cast <uint16_t> (kem_t::X448_HKDF_SHA512):
			// Выводим длину открытого ключа
			return length(kem);
		// ML-KEM-512
		case static_cast <uint16_t> (kem_t::MLKEM512):
			// Выводим длину шифртекста
			return 768;
		// ML-KEM-768
		case static_cast <uint16_t> (kem_t::MLKEM768):
			// Выводим длину шифртекста
			return 1088;
		// ML-KEM-1024
		case static_cast <uint16_t> (kem_t::MLKEM1024):
			// Выводим длину шифртекста
			return 1568;
		// Гибрид ML-KEM-768 и P-256
		case static_cast <uint16_t> (kem_t::MLKEM768_P256):
			// Выводим длину шифртекста
			return 1153;
		// Гибрид ML-KEM-1024 и P-384
		case static_cast <uint16_t> (kem_t::MLKEM1024_P384):
			// Выводим длину шифртекста
			return 1665;
		// Гибрид ML-KEM-768 и X25519
		case static_cast <uint16_t> (kem_t::MLKEM768_X25519):
			// Выводим длину шифртекста
			return 1120;
	}
	// Выводим отсутствие длины
	return 0;
}
/**
 * @brief Метод извлечения длины исходного материала выработки пары ключей
 *
 * @param kem способ инкапсуляции ключа
 * @return    наименьшая длина исходного материала в байтах либо ноль у неизвестного способа
 *
 */
size_t nts::hpke::material(const kem_t kem) noexcept {
	// У чистого ML-KEM материал - зерно в шестьдесят четыре байта
	if(puremlkem(kem))
		// Выводим длину зерна
		return MLKEM_SEED_SIZE;
	// У гибридов материал - зерно в тридцать два байта
	if(hybrid(kem))
		// Выводим длину зерна
		return HYBRID_SEED_SIZE;
	// У способов Диффи-Хеллмана материал не короче секретного ключа (раздел 7.1.3 RFC 9180)
	return secret(kem);
}
/**
 * @brief Метод проверки признака подлинности отправителя у способа инкапсуляции
 *
 * @param kem способ инкапсуляции ключа
 * @return    признак того, что способ поддерживает режимы AUTH и AUTH_PSK
 *
 */
bool nts::hpke::authenticated(const kem_t kem) noexcept {
	// Выводим признак способов Диффи-Хеллмана: раздел 7.2 draft-ietf-hpke-pq
	return diffie(kem);
}
/**
 * @brief Метод извлечения длины ключа шифра
 *
 * @param aead шифр с проверкой подлинности
 * @return     длина ключа в байтах, ноль у набора только для экспорта и у неизвестного шифра
 *
 */
size_t nts::hpke::length(const aead_t aead) noexcept {
	/**
	 * Определяем шифр
	 */
	switch(static_cast <uint16_t> (aead)){
		// AES-128-GCM
		case static_cast <uint16_t> (aead_t::AES_128_GCM):
			// Выводим шестнадцать байтов
			return 16;
		// AES-256-GCM и ChaCha20-Poly1305
		case static_cast <uint16_t> (aead_t::AES_256_GCM):
		case static_cast <uint16_t> (aead_t::CHACHA20_POLY1305):
			// Выводим тридцать два байта
			return 32;
	}
	// Выводим отсутствие ключа
	return 0;
}
/**
 * @brief Метод извлечения длины метки подлинности шифра
 *
 * @param aead шифр с проверкой подлинности
 * @return     длина метки в байтах, ноль у набора только для экспорта и у неизвестного шифра
 *
 */
size_t nts::hpke::overhead(const aead_t aead) noexcept {
	/**
	 * Определяем шифр
	 */
	switch(static_cast <uint16_t> (aead)){
		// Шифры с меткой в шестнадцать байтов
		case static_cast <uint16_t> (aead_t::AES_128_GCM):
		case static_cast <uint16_t> (aead_t::AES_256_GCM):
		case static_cast <uint16_t> (aead_t::CHACHA20_POLY1305):
			// Выводим длину метки
			return TAG_SIZE;
	}
	// Выводим отсутствие метки
	return 0;
}
/**
 * @brief Метод проверки поддержки набора алгоритмов
 *
 * @param suite набор алгоритмов
 * @return      признак того, что все три алгоритма набора поддерживаются
 *
 */
bool nts::hpke::supported(const suite_t & suite) noexcept {
	// Если способ инкапсуляции не поддерживается
	if(length(suite.kem) == 0)
		// Выводим отсутствие поддержки
		return false;
	// Если функция выработки ключа не поддерживается
	if((hashing(suite.kdf) == digest::hash_t::NONE) && !onestage(suite.kdf))
		// Выводим отсутствие поддержки
		return false;
	// Выводим признак поддержки шифра
	return ((suite.aead == aead_t::EXPORT_ONLY) || (overhead(suite.aead) > 0));
}
/**
 * @brief Метод проверки готовности пары ключей
 *
 * @return признак того, что пара ключей установлена
 *
 */
bool nts::hpke::Key::ready() const noexcept {
	// Выводим признак установленного способа
	return (this->_kem != kem_t::NONE);
}
/**
 * @brief Метод извлечения способа инкапсуляции ключа
 *
 * @return способ инкапсуляции ключа
 *
 */
nts::hpke::kem_t nts::hpke::Key::kem() const noexcept {
	// Выводим способ инкапсуляции
	return this->_kem;
}
/**
 * @brief Метод извлечения секретного ключа
 *
 * @return просмотр секретного ключа либо пустой просмотр у неготовой пары
 *
 */
nts::view_t nts::hpke::Key::secret() const noexcept {
	// Выводим просмотр секретного ключа готовой пары
	return (this->ready() ? view_t(this->_secret, this->_secretSize) : view_t());
}
/**
 * @brief Метод извлечения открытого ключа
 *
 * @return просмотр открытого ключа либо пустой просмотр у неготовой пары
 *
 */
nts::view_t nts::hpke::Key::point() const noexcept {
	// Выводим просмотр открытого ключа готовой пары
	return (this->ready() ? view_t(this->_point, this->_pointSize) : view_t());
}
/**
 * @brief Метод выработки пары ключей из случайных байтов
 *
 * @param kem способ инкапсуляции ключа
 * @return    причина отказа либо NONE
 *
 */
nts::hpke::error_t nts::hpke::Key::generate(const kem_t kem) noexcept {
	// Стираем прежнюю пару
	this->clear();
	// Если способ инкапсуляции не поддерживается
	if(length(kem) == 0)
		// Выводим отказ набора
		return error_t::SUITE;
	// Длина секретного ключа способа
	const size_t size = hpke::secret(kem);
	// Зерно выработки пары ключей
	uint8_t seed[KEM_SEED];
	// Признак успешности выработки
	bool status = false;
	/**
	 * Определяем способ инкапсуляции
	 */
	switch(static_cast <uint16_t> (kem)){
		// DHKEM(X25519, HKDF-SHA256)
		case static_cast <uint16_t> (kem_t::X25519_HKDF_SHA256):
			// Вырабатываем пару ключей из случайных байтов
			status = agreement::generate(this->_secret, this->_point);
			break;
		// DHKEM(X448, HKDF-SHA512)
		case static_cast <uint16_t> (kem_t::X448_HKDF_SHA512):
			// Вырабатываем секретный ключ из случайных байтов и вычисляем открытый
			status = (entropy::bytes(this->_secret, size) && agreement::x448(view_t(this->_secret, size), this->_point));
			break;
		// DHKEM кривых NIST
		case static_cast <uint16_t> (kem_t::P256_HKDF_SHA256):
		case static_cast <uint16_t> (kem_t::P384_HKDF_SHA384):
		case static_cast <uint16_t> (kem_t::P521_HKDF_SHA512): {
			// Кривая
			curve::curve_t curve;
			// Если параметры кривой не найдены
			if(!curve::parameters(curveoid(kem), curve))
				break;
			// Секретный ключ и точка младшим байтом вперёд
			uint8_t scalar[SCALAR_SIZE], raw[math::NUMBER_SIZE * 2];
			// Вырабатываем пару ключей кривой
			status = agreement::generate(curve, scalar, raw);
			// Переводим ключи в запись старшим байтом вперёд
			if(status){
				// Переводим секретный ключ
				reverse(scalar, this->_secret, size);
				// Складываем открытый ключ в несжатом виде
				this->_point[0] = 0x04;
				reverse(raw, this->_point + 1, size);
				reverse(raw + size, this->_point + 1 + size, size);
			}
			// Стираем записи
			wipe(scalar, sizeof(scalar));
			wipe(raw, sizeof(raw));
			break;
		}
		// Чистый ML-KEM
		case static_cast <uint16_t> (kem_t::MLKEM512):
		case static_cast <uint16_t> (kem_t::MLKEM768):
		case static_cast <uint16_t> (kem_t::MLKEM1024):
			// Вырабатываем зерно из случайных байтов и пару ключей из зерна
			status = (entropy::bytes(seed, MLKEM_SEED_SIZE) && expandmlkem(kem, view_t(seed, MLKEM_SEED_SIZE), this->_point));
			// Переносим зерно в секретный ключ
			if(status)
				// Копируем зерно
				::memcpy(this->_secret, seed, MLKEM_SEED_SIZE);
			break;
		// Гибридные способы
		case static_cast <uint16_t> (kem_t::MLKEM768_P256):
		case static_cast <uint16_t> (kem_t::MLKEM1024_P384):
		case static_cast <uint16_t> (kem_t::MLKEM768_X25519):
			// Вырабатываем зерно из случайных байтов и пару ключей из зерна
			status = (entropy::bytes(seed, HYBRID_SEED_SIZE) && this->grown(kem, view_t(seed, HYBRID_SEED_SIZE)));
			break;
	}
	// Стираем зерно
	wipe(seed, sizeof(seed));
	// Если выработка не удалась
	if(!status){
		// Стираем пару
		this->clear();
		// Выводим отказ источника случайных значений
		return error_t::ENTROPY;
	}
	// Запоминаем длины ключей
	this->_secretSize = static_cast <uint16_t> (size);
	this->_pointSize = static_cast <uint16_t> (length(kem));
	// Запоминаем способ инкапсуляции
	this->_kem = kem;
	// Выводим успех
	return error_t::NONE;
}
/**
 * @brief Метод выработки пары ключей из исходного материала
 *
 * @param kem      способ инкапсуляции ключа
 * @param material исходный ключевой материал длиной не короче ключа
 * @return         причина отказа либо NONE
 *
 */
nts::hpke::error_t nts::hpke::Key::derive(const kem_t kem, const view_t & material) noexcept {
	// Стираем прежнюю пару
	this->clear();
	// Если способ инкапсуляции не поддерживается
	if(length(kem) == 0)
		// Выводим отказ набора
		return error_t::SUITE;
	// Если материал короче наименьшей длины способа: раздел 7.1.3 RFC 9180 и разделы 3 и 4 draft-ietf-hpke-pq
	if((material.data == nullptr) || (material.size < hpke::material(kem)))
		// Выводим отказ ключа
		return error_t::KEY;
	// Длина секретного ключа способа
	const size_t size = hpke::secret(kem);
	// Признак успешности выработки
	bool status = false;
	// Если способ Диффи-Хеллмана
	if(diffie(kem))
		// Вырабатываем пару ключей способа из материала
		status = expand(kem, material, this->_secret, this->_point);
	// Если способ чистый ML-KEM
	else if(puremlkem(kem)){
		// Зерно выработки пары ключей
		uint8_t seed[MLKEM_SEED_SIZE];
		// Опознаватель способа инкапсуляции
		uint8_t suite[KEM_STAMP];
		// Составляем опознаватель способа
		stamp(kem, suite);
		// Вырабатываем зерно меченой выработкой
		status = labeled(derivation(kem), view_t(suite, sizeof(suite)), "DeriveKeyPair", view_t(), material, seed, sizeof(seed));
		// Вырабатываем пару ключей из зерна
		status = (status && expandmlkem(kem, view_t(seed, sizeof(seed)), this->_point));
		// Переносим зерно в секретный ключ
		if(status)
			// Копируем зерно
			::memcpy(this->_secret, seed, sizeof(seed));
		// Стираем зерно
		wipe(seed, sizeof(seed));
	// Если способ гибридный
	} else if(hybrid(kem)){
		// Зерно выработки пары ключей
		uint8_t seed[HYBRID_SEED_SIZE];
		// Опознаватель способа инкапсуляции
		uint8_t suite[KEM_STAMP];
		// Составляем опознаватель способа
		stamp(kem, suite);
		// Вырабатываем зерно меченой выработкой
		status = labeled(derivation(kem), view_t(suite, sizeof(suite)), "DeriveKeyPair", view_t(), material, seed, sizeof(seed));
		// Вырабатываем пару ключей из зерна
		status = (status && this->grown(kem, view_t(seed, sizeof(seed))));
		// Стираем зерно
		wipe(seed, sizeof(seed));
	}
	// Если выработка не удалась
	if(!status){
		// Стираем пару
		this->clear();
		// Выводим отказ ключа
		return error_t::KEY;
	}
	// Запоминаем длины ключей
	this->_secretSize = static_cast <uint16_t> (size);
	this->_pointSize = static_cast <uint16_t> (length(kem));
	// Запоминаем способ инкапсуляции
	this->_kem = kem;
	// Выводим успех
	return error_t::NONE;
}
/**
 * @brief Метод установки пары ключей по секретному ключу
 *
 * @param kem    способ инкапсуляции ключа
 * @param secret секретный ключ длиной в тридцать два байта
 * @return       причина отказа либо NONE
 *
 */
nts::hpke::error_t nts::hpke::Key::set(const kem_t kem, const view_t & secret) noexcept {
	// Стираем прежнюю пару
	this->clear();
	// Если способ инкапсуляции не поддерживается
	if(length(kem) == 0)
		// Выводим отказ набора
		return error_t::SUITE;
	// Длина секретного ключа способа
	const size_t size = hpke::secret(kem);
	// Если секретный ключ записан неверной длиной
	if((secret.data == nullptr) || (secret.size != size))
		// Выводим отказ ключа
		return error_t::KEY;
	// Признак успешности выработки
	bool status = false;
	/**
	 * Определяем способ инкапсуляции
	 */
	switch(static_cast <uint16_t> (kem)){
		// DHKEM(X25519, HKDF-SHA256)
		case static_cast <uint16_t> (kem_t::X25519_HKDF_SHA256):
			// Вычисляем открытый ключ
			status = agreement::x25519(secret, this->_point);
			break;
		// DHKEM(X448, HKDF-SHA512)
		case static_cast <uint16_t> (kem_t::X448_HKDF_SHA512):
			// Вычисляем открытый ключ
			status = agreement::x448(secret, this->_point);
			break;
		// DHKEM кривых NIST
		case static_cast <uint16_t> (kem_t::P256_HKDF_SHA256):
		case static_cast <uint16_t> (kem_t::P384_HKDF_SHA384):
		case static_cast <uint16_t> (kem_t::P521_HKDF_SHA512):
			// Вычисляем открытый ключ с проверкой скаляра
			status = publish(kem, secret, this->_point);
			break;
		// Чистый ML-KEM
		case static_cast <uint16_t> (kem_t::MLKEM512):
		case static_cast <uint16_t> (kem_t::MLKEM768):
		case static_cast <uint16_t> (kem_t::MLKEM1024):
			// Вырабатываем открытый ключ из зерна
			status = expandmlkem(kem, secret, this->_point);
			break;
		// Гибридные способы
		case static_cast <uint16_t> (kem_t::MLKEM768_P256):
		case static_cast <uint16_t> (kem_t::MLKEM1024_P384):
		case static_cast <uint16_t> (kem_t::MLKEM768_X25519):
			// Вырабатываем пару ключей из зерна
			status = this->grown(kem, secret);
			break;
	}
	// Если выработка не удалась
	if(!status){
		// Стираем пару
		this->clear();
		// Выводим отказ ключа
		return error_t::KEY;
	}
	// Копируем секретный ключ
	::memcpy(this->_secret, secret.data, size);
	// Запоминаем длины ключей
	this->_secretSize = static_cast <uint16_t> (size);
	this->_pointSize = static_cast <uint16_t> (length(kem));
	// Запоминаем способ инкапсуляции
	this->_kem = kem;
	// Выводим успех
	return error_t::NONE;
}
/**
 * @brief Метод выработки пары ключей гибридного способа из зерна
 *
 * @param kem  способ инкапсуляции ключа
 * @param seed зерно в тридцать два байта
 * @return     признак успешности выработки
 *
 */
bool nts::hpke::Key::grown(const kem_t kem, const view_t & seed) noexcept {
	// Зёрна составляющих: ML-KEM и группы
	uint8_t pq[MLKEM_SEED_SIZE], trad[128];
	// Растягиваем зерно в зёрна составляющих
	bool status = spread(kem, seed, pq, trad);
	// Если зёрна выработаны
	if(status){
		// Набор параметров ML-KEM
		const agreement::kem_t set = mlkemset(kem);
		// Вырабатываем открытый ключ ML-KEM из зерна
		status = expandmlkem(kem, view_t(pq, sizeof(pq)), this->_point);
		// Если способ с группой Curve25519
		if(status && (kem == kem_t::MLKEM768_X25519))
			// Вычисляем открытый ключ X25519 из зерна как скаляра
			status = agreement::x25519(view_t(trad, X25519_SIZE), this->_point + agreement::encapsulation(set));
		// Если способ с кривой NIST
		else if(status){
			// Скаляр группы
			uint8_t scalar[SCALAR_SIZE];
			// Отбираем скаляр из зерна
			status = pick(kem, view_t(trad, tradition(kem)), scalar);
			// Вычисляем открытый ключ по скаляру
			status = (status && publish(kem, view_t(scalar, ((kem == kem_t::MLKEM768_P256) ? 32 : 48)), this->_point + agreement::encapsulation(set)));
			// Стираем скаляр
			wipe(scalar, sizeof(scalar));
		}
	}
	// Стираем зёрна
	wipe(pq, sizeof(pq));
	wipe(trad, sizeof(trad));
	// Выводим итог выработки
	return status;
}
/**
 * @brief Метод стирания пары ключей
 *
 */
void nts::hpke::Key::clear() noexcept {
	// Сбрасываем способ инкапсуляции
	this->_kem = kem_t::NONE;
	// Сбрасываем длины ключей
	this->_secretSize = 0;
	this->_pointSize = 0;
	// Стираем секретный ключ
	wipe(this->_secret, sizeof(this->_secret));
	// Стираем открытый ключ
	wipe(this->_point, sizeof(this->_point));
}
/**
 * @brief Конструктор пустой пары ключей
 *
 */
nts::hpke::Key::Key() noexcept : _kem(kem_t::NONE), _secretSize(0), _pointSize(0) {
	// Обнуляем секретный ключ
	::memset(this->_secret, 0, sizeof(this->_secret));
	// Обнуляем открытый ключ
	::memset(this->_point, 0, sizeof(this->_point));
}
/**
 * @brief Деструктор: стирает секретный ключ
 *
 */
nts::hpke::Key::~Key() noexcept {
	// Стираем пару
	this->clear();
}
/**
 * @brief Метод установки состояния по общему значению
 *
 * @param suite  набор алгоритмов
 * @param mode   режим работы
 * @param shared общее значение способа инкапсуляции
 * @param info   привязка к применению
 * @param psk    заранее разделённый ключ с опознавателем
 * @param sender признак стороны отправителя
 * @return       причина отказа либо NONE
 *
 * @details Функция KeySchedule раздела 5.1 RFC 9180
 *
 */
nts::hpke::error_t nts::hpke::Context::setup(const suite_t & suite, const regime_t mode, const view_t & shared, const view_t & info, const shared_t & psk, const bool sender) noexcept {
	// Стираем прежнее состояние
	this->clear();
	// Если набор не поддерживается
	if(!supported(suite))
		// Выводим отказ набора
		return error_t::SUITE;
	// Если режим неизвестен
	if(!admissible(mode))
		// Выводим отказ режима
		return error_t::MODE;
	// Признак заданного ключа
	const bool keyed = (psk.key.size > 0);
	// Признак заданного опознавателя
	const bool named = (psk.identity.size > 0);
	// Если ключ и опознаватель заданы порознь: раздел 5.1 RFC 9180
	if(keyed != named)
		// Выводим отказ ключа
		return error_t::PSK;
	// Если наличие ключа не отвечает режиму: раздел 5.1 RFC 9180
	if(keyed != preshared(mode))
		// Выводим отказ ключа
		return error_t::PSK;
	// Если просмотры заданы длиной без места
	if((keyed && ((psk.key.data == nullptr) || (psk.identity.data == nullptr))) || ((info.size > 0) && (info.data == nullptr)))
		// Выводим отказ довода
		return error_t::ARGUMENT;
	// Раздел 9.5 RFC 9180: заранее разделённый ключ обязан нести не меньше 32 байтов энтропии - короче 32 байтов он отвергается
	if(keyed && (psk.key.size < PSK_LEAST))
		// Выводим отказ ключа
		return error_t::PSK;
	// Опознаватель набора
	uint8_t identifier[SUITE_STAMP];
	// Составляем опознаватель набора
	stamp(suite, identifier);
	// Просмотр опознавателя набора
	const view_t label(identifier, sizeof(identifier));
	// Признак успешности выработки
	bool status = true;
	// Если функция выработки ключа одноступенчатая
	if(onestage(suite.kdf)){
		/**
		 * Функция CombineSecrets_OneStage раздела 5.1 draft-ietf-hpke-hpke: секреты -
		 * lengthPrefixed(psk) ‖ lengthPrefixed(shared_secret), привязка - режим ‖
		 * lengthPrefixed(psk_id) ‖ lengthPrefixed(info), а секрет расписания длиной
		 * Nk + Nn + Nh разрезается на ключ шифра, начальное заполнение и секрет экспорта
		 */
		// Длина хеша функции выработки ключа
		const size_t width = hpke::length(suite.kdf);
		// Длина ключа шифра
		const size_t keysize = ((suite.aead != aead_t::EXPORT_ONLY) ? hpke::length(suite.aead) : 0);
		// Длина начального заполнения
		const size_t noncesize = ((suite.aead != aead_t::EXPORT_ONLY) ? NONCE_SIZE : 0);
		// Двухбайтовая запись длины
		uint8_t span[2];
		// Куски секретов: длина ключа, ключ, длина общего значения, общее значение
		view_t secrets[4];
		// Записываем длину заранее разделённого ключа
		inscribe(static_cast <uint16_t> (psk.key.size), span);
		// Подаём длину ключа
		secrets[0] = view_t(span, sizeof(span));
		// Подаём ключ
		secrets[1] = psk.key;
		// Куски привязки: режим, длина опознавателя, опознаватель, длина привязки к применению, привязка
		view_t binding[5];
		// Записываем режим
		binding[0] = view_t(reinterpret_cast <const uint8_t *> (&mode), 1);
		// Секрет расписания целиком
		uint8_t secret[KEY_SIZE + NONCE_SIZE + HASH_SIZE];
		// Двухбайтовая запись длины общего значения
		uint8_t span2[2];
		// Записываем длину общего значения
		inscribe(static_cast <uint16_t> (shared.size), span2);
		// Подаём длину общего значения
		secrets[2] = view_t(span2, sizeof(span2));
		// Подаём общее значение
		secrets[3] = shared;
		// Двухбайтовая запись длины опознавателя
		uint8_t span3[2];
		// Записываем длину опознавателя
		inscribe(static_cast <uint16_t> (psk.identity.size), span3);
		// Подаём длину опознавателя
		binding[1] = view_t(span3, sizeof(span3));
		// Подаём опознаватель
		binding[2] = psk.identity;
		// Двухбайтовая запись длины привязки к применению
		uint8_t span4[2];
		// Записываем длину привязки к применению
		inscribe(static_cast <uint16_t> (info.size), span4);
		// Подаём длину привязки к применению
		binding[3] = view_t(span4, sizeof(span4));
		// Подаём привязку к применению
		binding[4] = info;
		// Складываем секреты и привязку во временные накопители
		uint8_t pooled[(2 + KEM_SHARED) + (2 + KEM_SHARED)];
		uint8_t bound[1 + (2 + 255) + (2 + 255)];
		// Смещение в накопителе
		size_t at = 0;
		/**
		 * Выполняем перенос секретов в накопитель
		 */
		for(size_t i = 0; i < 4; i++){
			// Переносим кусок
			::memcpy(pooled + at, secrets[i].data, secrets[i].size);
			// Сдвигаем смещение
			at += secrets[i].size;
		}
		// Число байтов секретов
		const size_t pooledsize = at;
		// Сбрасываем смещение
		at = 0;
		/**
		 * Выполняем перенос привязки в накопитель
		 */
		for(size_t i = 0; i < 5; i++){
			// Переносим кусок
			::memcpy(bound + at, binding[i].data, binding[i].size);
			// Сдвигаем смещение
			at += binding[i].size;
		}
		// Вырабатываем секрет расписания целиком меченой выработкой
		status = labeled(suite.kdf, label, "secret", view_t(bound, at), view_t(pooled, pooledsize), secret, keysize + noncesize + width);
		// Стираем накопители
		wipe(pooled, sizeof(pooled));
		wipe(bound, sizeof(bound));
		// Если набор шифрует
		if(suite.aead != aead_t::EXPORT_ONLY){
			// Переносим ключ шифра
			::memcpy(this->_key, secret, keysize);
			// Переносим начальное заполнение
			::memcpy(this->_nonce, secret + keysize, noncesize);
		}
		// Переносим секрет экспорта
		::memcpy(this->_exporter, secret + keysize + noncesize, width);
		// Стираем секрет расписания
		wipe(secret, sizeof(secret));
	// Если функция выработки ключа двухступенчатая
	} else {
		// Алгоритм хеширования функции выработки ключа
		const digest::hash_t hash = hashing(suite.kdf);
		// Длина хеша
		const size_t length = digest::length(hash);
		// Привязка расписания ключей: режим, хеш опознавателя ключа, хеш привязки к применению
		uint8_t schedule[SCHEDULE_SIZE];
		// Записываем режим
		schedule[0] = static_cast <uint8_t> (mode);
		// Секрет расписания
		uint8_t secret[HASH_SIZE];
		// Вырабатываем хеш опознавателя ключа
		status = absorb(hash, view_t(), label, "psk_id_hash", psk.identity, schedule + 1);
		// Вырабатываем хеш привязки к применению
		status = (status && absorb(hash, view_t(), label, "info_hash", info, schedule + 1 + length));
		// Вырабатываем секрет расписания на общем значении
		status = (status && absorb(hash, shared, label, "secret", psk.key, secret));
		// Просмотр секрета расписания
		const view_t prk(secret, length);
		// Просмотр привязки расписания
		const view_t binding(schedule, 1 + (2 * length));
		// Если набор шифрует
		if(suite.aead != aead_t::EXPORT_ONLY){
			// Вырабатываем ключ шифра
			status = (status && unfold(hash, prk, label, "key", binding, this->_key, hpke::length(suite.aead)));
			// Вырабатываем начальное заполнение
			status = (status && unfold(hash, prk, label, "base_nonce", binding, this->_nonce, NONCE_SIZE));
		}
		// Вырабатываем секрет экспорта
		status = (status && unfold(hash, prk, label, "exp", binding, this->_exporter, length));
		// Стираем секрет расписания
		wipe(secret, sizeof(secret));
		// Стираем привязку расписания
		wipe(schedule, sizeof(schedule));
	}
	// Если набор шифрует AES
	if(status && ((suite.aead == aead_t::AES_128_GCM) || (suite.aead == aead_t::AES_256_GCM)))
		// Разворачиваем ключ шифра
		status = this->_aes.key(view_t(this->_key, hpke::length(suite.aead)));
	// Если выработка не удалась
	if(!status){
		// Стираем состояние
		this->clear();
		// Выводим отказ набора
		return error_t::SUITE;
	}
	// Запоминаем набор
	this->_suite = suite;
	// Запоминаем сторону
	this->_sender = sender;
	// Устанавливаем признак готовности
	this->_ready = true;
	// Выводим успех
	return error_t::NONE;
}
/**
 * @brief Метод выработки начального заполнения сообщения
 *
 * @param result место под начальное заполнение длиной NONCE_SIZE
 *
 * @details Функция ComputeNonce раздела 5.2 RFC 9180: base_nonce XOR I2OSP(seq, Nn)
 *
 */
void nts::hpke::Context::mask(uint8_t * result) const noexcept {
	// Копируем начальное заполнение
	::memcpy(result, this->_nonce, NONCE_SIZE);
	/**
	 * Выполняем наложение порядкового номера на младшие восемь байтов
	 */
	for(size_t i = 0; i < sizeof(uint64_t); i++)
		// Накладываем байт номера старшим байтом вперёд
		result[NONCE_SIZE - 1 - i] ^= static_cast <uint8_t> (this->_sequence >> (8 * i));
}
/**
 * @brief Метод проверки готовности состояния
 *
 * @return признак того, что состояние установлено
 *
 */
bool nts::hpke::Context::ready() const noexcept {
	// Выводим признак готовности
	return this->_ready;
}
/**
 * @brief Метод извлечения набора алгоритмов
 *
 * @return набор алгоритмов состояния
 *
 */
const nts::hpke::suite_t & nts::hpke::Context::suite() const noexcept {
	// Выводим набор
	return this->_suite;
}
/**
 * @brief Метод извлечения порядкового номера следующего сообщения
 *
 * @return порядковый номер следующего сообщения
 *
 */
uint64_t nts::hpke::Context::sequence() const noexcept {
	// Выводим порядковый номер
	return this->_sequence;
}
/**
 * @brief Метод установки порядкового номера следующего сообщения
 *
 * @param sequence порядковый номер следующего сообщения
 * @return         причина отказа либо NONE
 *
 */
nts::hpke::error_t nts::hpke::Context::sequence(const uint64_t sequence) noexcept {
	// Если состояние не установлено
	if(!this->_ready)
		// Выводим отказ готовности
		return error_t::READY;
	// Устанавливаем порядковый номер
	this->_sequence = sequence;
	// Выводим успех
	return error_t::NONE;
}
/**
 * @brief Метод зашифрования сообщения
 *
 * @param associated связанные данные, вправе быть пустыми
 * @param source     открытый текст, вправе быть пустым
 * @param result     место под шифртекст с меткой подлинности длиной source.size + TAG_SIZE
 * @return           причина отказа либо NONE
 *
 * @details Функция ContextS.Seal раздела 5.2 RFC 9180
 *
 */
nts::hpke::error_t nts::hpke::Context::seal(const view_t & associated, const view_t & source, uint8_t * result) noexcept {
	// Если состояние не установлено
	if(!this->_ready)
		// Выводим отказ готовности
		return error_t::READY;
	// Если сторона не отправитель либо набор не шифрует
	if(!this->_sender || (this->_suite.aead == aead_t::EXPORT_ONLY))
		// Выводим отказ шифрования
		return error_t::AEAD;
	// Если места под итог нет либо просмотры заданы длиной без места
	if((result == nullptr) || ((source.size > 0) && (source.data == nullptr)) || ((associated.size > 0) && (associated.data == nullptr)))
		// Выводим отказ довода
		return error_t::ARGUMENT;
	// Если порядковые номера исчерпаны
	if(this->_sequence == UINT64_MAX)
		// Выводим отказ порядкового номера
		return error_t::SEQUENCE;
	// Начальное заполнение сообщения
	uint8_t nonce[NONCE_SIZE];
	// Вырабатываем начальное заполнение
	this->mask(nonce);
	// Признак успешности зашифрования
	bool status = false;
	// Если набор шифрует ChaCha20-Poly1305
	if(this->_suite.aead == aead_t::CHACHA20_POLY1305){
		// Объект шифра
		cipher::chachapoly_t aead;
		// Заводим шифр на ключе и начальном заполнении
		status = aead.start(view_t(this->_key, hpke::length(this->_suite.aead)), view_t(nonce, sizeof(nonce)));
		// Зашифровываем сообщение
		status = (status && aead.encrypt(associated, source, result, result + source.size));
	// Если набор шифрует AES-GCM
	} else {
		// Объект режима
		cipher::gcm_t aead;
		// Заводим режим на развёрнутом ключе и начальном заполнении
		status = aead.start(cipher::block_t(this->_aes), view_t(nonce, sizeof(nonce)), TAG_SIZE);
		// Зашифровываем сообщение
		status = (status && aead.encrypt(associated, source, result, result + source.size));
	}
	// Стираем начальное заполнение
	wipe(nonce, sizeof(nonce));
	// Если зашифрование не удалось
	if(!status){
		// Стираем место под итог
		wipe(result, source.size + TAG_SIZE);
		// Выводим отказ шифрования
		return error_t::AEAD;
	}
	// Увеличиваем порядковый номер
	this->_sequence++;
	// Выводим успех
	return error_t::NONE;
}
/**
 * @brief Метод зашифрования сообщения в накопитель
 *
 * @param associated связанные данные, вправе быть пустыми
 * @param source     открытый текст, вправе быть пустым
 * @param result     накопитель шифртекста с меткой подлинности
 * @return           причина отказа либо NONE
 *
 */
nts::hpke::error_t nts::hpke::Context::seal(const view_t & associated, const view_t & source, vector <uint8_t> & result) noexcept {
	/**
	 * Накопитель растёт под шифртекст с меткой: нехватка памяти отдаётся кодом
	 */
	try {
		// Отводим место под шифртекст с меткой
		result.resize(source.size + TAG_SIZE);
	// Если память выделить не удалось
	} catch(const bad_alloc &) {
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Зашифровываем сообщение в накопитель
	const error_t status = this->seal(associated, source, result.data());
	// Если зашифрование не удалось
	if(status != error_t::NONE)
		// Очищаем накопитель
		result.clear();
	// Выводим итог зашифрования
	return status;
}
/**
 * @brief Метод расшифрования сообщения
 *
 * @param associated связанные данные, вправе быть пустыми
 * @param source     шифртекст с меткой подлинности длиной не короче TAG_SIZE
 * @param result     место под открытый текст длиной source.size - TAG_SIZE
 * @return           причина отказа либо NONE
 *
 * @details Функция ContextR.Open раздела 5.2 RFC 9180
 *
 */
nts::hpke::error_t nts::hpke::Context::open(const view_t & associated, const view_t & source, uint8_t * result) noexcept {
	// Если состояние не установлено
	if(!this->_ready)
		// Выводим отказ готовности
		return error_t::READY;
	// Если сторона не получатель либо набор не шифрует
	if(this->_sender || (this->_suite.aead == aead_t::EXPORT_ONLY))
		// Выводим отказ шифрования
		return error_t::AEAD;
	// Если шифртекст короче метки либо просмотры заданы длиной без места
	if((source.data == nullptr) || (source.size < TAG_SIZE) || ((associated.size > 0) && (associated.data == nullptr)))
		// Выводим отказ довода
		return error_t::ARGUMENT;
	// Длина открытого текста
	const size_t size = (source.size - TAG_SIZE);
	// Если места под открытый текст нет
	if((size > 0) && (result == nullptr))
		// Выводим отказ довода
		return error_t::ARGUMENT;
	// Если порядковые номера исчерпаны
	if(this->_sequence == UINT64_MAX)
		// Выводим отказ порядкового номера
		return error_t::SEQUENCE;
	// Начальное заполнение сообщения
	uint8_t nonce[NONCE_SIZE];
	// Вырабатываем начальное заполнение
	this->mask(nonce);
	// Просмотр шифртекста без метки
	const view_t sealed(source.data, size);
	// Просмотр метки подлинности
	const view_t tag(source.data + size, TAG_SIZE);
	// Признак успешности расшифрования
	bool status = false;
	// Если набор шифрует ChaCha20-Poly1305
	if(this->_suite.aead == aead_t::CHACHA20_POLY1305){
		// Объект шифра
		cipher::chachapoly_t aead;
		// Заводим шифр на ключе и начальном заполнении
		status = aead.start(view_t(this->_key, hpke::length(this->_suite.aead)), view_t(nonce, sizeof(nonce)));
		// Расшифровываем сообщение
		status = (status && aead.decrypt(associated, sealed, result, tag));
	// Если набор шифрует AES-GCM
	} else {
		// Объект режима
		cipher::gcm_t aead;
		// Заводим режим на развёрнутом ключе и начальном заполнении
		status = aead.start(cipher::block_t(this->_aes), view_t(nonce, sizeof(nonce)), TAG_SIZE);
		// Расшифровываем сообщение
		status = (status && aead.decrypt(associated, sealed, result, tag));
	}
	// Стираем начальное заполнение
	wipe(nonce, sizeof(nonce));
	// Если подлинность не сошлась
	if(!status){
		// Стираем место под открытый текст
		wipe(result, size);
		// Выводим отказ подлинности
		return error_t::OPEN;
	}
	// Увеличиваем порядковый номер
	this->_sequence++;
	// Выводим успех
	return error_t::NONE;
}
/**
 * @brief Метод расшифрования сообщения в накопитель
 *
 * @param associated связанные данные, вправе быть пустыми
 * @param source     шифртекст с меткой подлинности длиной не короче TAG_SIZE
 * @param result     накопитель открытого текста
 * @return           причина отказа либо NONE
 *
 */
nts::hpke::error_t nts::hpke::Context::open(const view_t & associated, const view_t & source, vector <uint8_t> & result) noexcept {
	// Если шифртекст короче метки
	if((source.data == nullptr) || (source.size < TAG_SIZE))
		// Выводим отказ довода
		return error_t::ARGUMENT;
	/**
	 * Накопитель растёт под открытый текст: нехватка памяти отдаётся кодом
	 */
	try {
		// Отводим место под открытый текст
		result.resize(source.size - TAG_SIZE);
	// Если память выделить не удалось
	} catch(const bad_alloc &) {
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Расшифровываем сообщение в накопитель
	const error_t status = this->open(associated, source, result.data());
	// Если расшифрование не удалось
	if(status != error_t::NONE)
		// Очищаем накопитель
		result.clear();
	// Выводим итог расшифрования
	return status;
}
/**
 * @brief Метод выработки секрета экспорта
 *
 * @param context привязка секрета, вправе быть пустой
 * @param result  место под секрет
 * @param size    длина секрета в байтах, не больше 255 длин хеша функции выработки ключа
 * @return        причина отказа либо NONE
 *
 * @details Функция Context.Export раздела 5.3 RFC 9180
 *
 */
nts::hpke::error_t nts::hpke::Context::exporter(const view_t & context, uint8_t * result, const size_t size) const noexcept {
	// Если состояние не установлено
	if(!this->_ready)
		// Выводим отказ готовности
		return error_t::READY;
	// Длина хеша функции выработки ключа
	const size_t length = hpke::length(this->_suite.kdf);
	// Если длина секрета недопустима
	if((size == 0) || (size > (255 * length)))
		// Выводим отказ длины
		return error_t::LENGTH;
	// Если места под секрет нет либо привязка задана длиной без места
	if((result == nullptr) || ((context.size > 0) && (context.data == nullptr)))
		// Выводим отказ довода
		return error_t::ARGUMENT;
	// Опознаватель набора
	uint8_t identifier[SUITE_STAMP];
	// Составляем опознаватель набора
	stamp(this->_suite, identifier);
	// Растягиваем секрет экспорта
	if(!unfold(hashing(this->_suite.kdf), view_t(this->_exporter, length), view_t(identifier, sizeof(identifier)), "sec", context, result, size)){
		// Стираем место под секрет
		wipe(result, size);
		// Выводим отказ набора
		return error_t::SUITE;
	}
	// Выводим успех
	return error_t::NONE;
}
/**
 * @brief Метод стирания состояния
 *
 */
void nts::hpke::Context::clear() noexcept {
	// Сбрасываем признак готовности
	this->_ready = false;
	// Сбрасываем сторону
	this->_sender = false;
	// Сбрасываем набор
	this->_suite = suite_t();
	// Сбрасываем порядковый номер
	this->_sequence = 0;
	// Стираем ключ шифра
	wipe(this->_key, sizeof(this->_key));
	// Стираем начальное заполнение
	wipe(this->_nonce, sizeof(this->_nonce));
	// Стираем секрет экспорта
	wipe(this->_exporter, sizeof(this->_exporter));
	// Стираем развёрнутый ключ шифра
	this->_aes.clear();
}
/**
 * @brief Конструктор пустого состояния
 *
 */
nts::hpke::Context::Context() noexcept : _ready(false), _sender(false), _suite(), _sequence(0) {
	// Обнуляем ключ шифра
	::memset(this->_key, 0, sizeof(this->_key));
	// Обнуляем начальное заполнение
	::memset(this->_nonce, 0, sizeof(this->_nonce));
	// Обнуляем секрет экспорта
	::memset(this->_exporter, 0, sizeof(this->_exporter));
}
/**
 * @brief Деструктор: стирает ключи
 *
 */
nts::hpke::Context::~Context() noexcept {
	// Стираем состояние
	this->clear();
}
/**
 * @brief Метод инкапсуляции ключа
 *
 * @param ephemeral     мимолётная пара ключей отправителя
 * @param point         открытый ключ получателя длиной X25519_SIZE
 * @param authenticator пара ключей отправителя для подлинности либо nullptr
 * @param shared        место под общее значение длиной X25519_SIZE
 * @param result        место под инкапсулированный ключ длиной X25519_SIZE
 * @return              причина отказа либо NONE
 *
 * @details Функции Encap и AuthEncap раздела 7.1.1 RFC 9180
 *
 */
nts::hpke::error_t nts::hpke::encapsulate(const key_t & ephemeral, const view_t & point, const key_t * authenticator, uint8_t * shared, uint8_t * result) noexcept {
	// Если мимолётная пара не готова
	if(!ephemeral.ready())
		// Выводим отказ ключа
		return error_t::KEY;
	// Способ инкапсуляции
	const kem_t kem = ephemeral.kem();
	// Если пара отправителя задана и не готова либо способ её не поддерживает
	if((authenticator != nullptr) && (!authenticator->ready() || (authenticator->kem() != kem) || !authenticated(kem)))
		// Выводим отказ ключа
		return error_t::KEY;
	// Если открытый ключ получателя записан неверной длиной
	if((point.data == nullptr) || (point.size != length(kem)))
		// Выводим отказ ключа
		return error_t::KEY;
	// Если места под итог нет
	if((shared == nullptr) || (result == nullptr))
		// Выводим отказ довода
		return error_t::ARGUMENT;
	// Признак успешности выработки
	bool status = false;
	// Если способ Диффи-Хеллмана
	if(diffie(kem)){
		// Размер общего значения кривой
		const size_t size = hpke::secret(kem);
		// Общие значения Диффи-Хеллмана: мимолётное и отправителя
		uint8_t dh[2 * SCALAR_SIZE];
		/**
		 * Определяем способ инкапсуляции
		 */
		switch(static_cast <uint16_t> (kem)){
			// DHKEM(X25519, HKDF-SHA256)
			case static_cast <uint16_t> (kem_t::X25519_HKDF_SHA256):
				// Вырабатываем мимолётное общее значение
				status = agreement::x25519(ephemeral.secret(), point, dh);
				// Если подлинность отправителя требуется
				if(status && (authenticator != nullptr))
					// Вырабатываем общее значение отправителя
					status = agreement::x25519(authenticator->secret(), point, dh + size);
				break;
			// DHKEM(X448, HKDF-SHA512)
			case static_cast <uint16_t> (kem_t::X448_HKDF_SHA512):
				// Вырабатываем мимолётное общее значение
				status = agreement::x448(ephemeral.secret(), point, dh);
				// Если подлинность отправителя требуется
				if(status && (authenticator != nullptr))
					// Вырабатываем общее значение отправителя
					status = agreement::x448(authenticator->secret(), point, dh + size);
				break;
			// DHKEM кривых NIST
			default:
				// Вырабатываем мимолётное общее значение
				status = exchange(kem, ephemeral.secret(), point, dh);
				// Если подлинность отправителя требуется
				if(status && (authenticator != nullptr))
					// Вырабатываем общее значение отправителя
					status = exchange(kem, authenticator->secret(), point, dh + size);
				break;
		}
		// Если общие значения выработаны
		if(status){
			// Привязка способа инкапсуляции: инкапсулированный ключ, ключ получателя, ключ отправителя
			uint8_t binding[BINDING_FULL];
			// Записываем инкапсулированный ключ
			::memcpy(binding, ephemeral.point().data, ephemeral.point().size);
			// Записываем ключ получателя
			::memcpy(binding + ephemeral.point().size, point.data, point.size);
			// Если подлинность отправителя требуется
			if(authenticator != nullptr)
				// Записываем ключ отправителя
				::memcpy(binding + ephemeral.point().size + point.size, authenticator->point().data, authenticator->point().size);
			// Длина занятой части общих значений
			const size_t width = ((authenticator != nullptr) ? (2 * size) : size);
			// Вырабатываем общее значение
			status = combine(kem, view_t(dh, width), view_t(binding, ephemeral.point().size + point.size + ((authenticator != nullptr) ? authenticator->point().size : 0)), shared);
			// Стираем привязку
			wipe(binding, sizeof(binding));
		}
		// Стираем общие значения
		wipe(dh, sizeof(dh));
		// Если выработка удалась
		if(status)
			// Копируем инкапсулированный ключ
			::memcpy(result, ephemeral.point().data, ephemeral.point().size);
	// Если способ чистый ML-KEM
	} else if(puremlkem(kem)){
		// Набор параметров ML-KEM
		const agreement::kem_t set = mlkemset(kem);
		// Если ключ инкапсуляции негоден: раздел 3 draft-ietf-hpke-pq
		if(!agreement::validate(set, point))
			// Выводим отказ инкапсуляции
			return error_t::ENCAPSULATION;
		// Инкапсулируем ключ на мимолётном зерне как сообщении
		status = agreement::encapsulate(set, point, view_t(ephemeral.secret().data, MLKEM_MESSAGE_SIZE), result, shared);
	// Если способ гибридный
	} else if(hybrid(kem)){
		// Набор параметров ML-KEM
		const agreement::kem_t set = mlkemset(kem);
		// Длина ключа инкапсуляции ML-KEM
		const size_t pksize = agreement::encapsulation(set);
		// Длина шифртекста ML-KEM
		const size_t ctsize = agreement::ciphertext(set);
		// Если ключ инкапсуляции негоден
		if(!agreement::validate(set, view_t(point.data, pksize)))
			// Выводим отказ инкапсуляции
			return error_t::ENCAPSULATION;
		// Общие значения составляющих
		uint8_t ssPQ[MLKEM_SHARED_SIZE], ssT[SCALAR_SIZE];
		// Инкапсулируем ключ ML-KEM на мимолётном зерне как сообщении
		status = agreement::encapsulate(set, view_t(point.data, pksize), view_t(ephemeral.secret().data, MLKEM_MESSAGE_SIZE), result, ssPQ);
		// Если способ с группой Curve25519
		if(status && (kem == kem_t::MLKEM768_X25519)){
			// Мимолётный скаляр: зерно традиционной составляющей из зерна пары
			uint8_t scalar[X25519_SIZE];
			// Копируем скаляр из зерна мимолётной пары
			::memcpy(scalar, ephemeral.secret().data + MLKEM_MESSAGE_SIZE, sizeof(scalar));
			// Вырабатываем мимолётный открытый ключ
			status = agreement::x25519(view_t(scalar, sizeof(scalar)), result + ctsize);
			// Вырабатываем общее значение традиционной составляющей
			status = (status && agreement::x25519(view_t(scalar, sizeof(scalar)), view_t(point.data + pksize, X25519_SIZE), ssT));
			// Стираем скаляр
			wipe(scalar, sizeof(scalar));
		// Если способ с кривой NIST
		} else if(status){
			// Размер кривой
			const size_t size = (((kem == kem_t::MLKEM768_P256)) ? 32 : 48);
			// Мимолётный скаляр: зерно традиционной составляющей из зерна пары
			uint8_t scalar[SCALAR_SIZE];
			// Отбираем скаляр из зерна мимолётной пары
			status = pick(kem, view_t(ephemeral.secret().data + MLKEM_MESSAGE_SIZE, tradition(kem)), scalar);
			// Вырабатываем мимолётный открытый ключ
			status = (status && publish(kem, view_t(scalar, size), result + ctsize));
			// Вырабатываем общее значение традиционной составляющей
			status = (status && exchange(kem, view_t(scalar, size), view_t(point.data + pksize, 1 + (2 * size)), ssT));
			// Стираем скаляр
			wipe(scalar, sizeof(scalar));
		}
		// Если составляющие выработаны
		if(status){
			// Длина традиционной части ключа и шифртекста
			const size_t tsize = ((kem == kem_t::MLKEM768_X25519) ? X25519_SIZE : (1 + (2 * ((kem == kem_t::MLKEM768_P256) ? 32 : 48))));
			// Вырабатываем общее значение сочетателем C2PRI
			fuse(kem, view_t(ssPQ, sizeof(ssPQ)), view_t(ssT, ((kem == kem_t::MLKEM768_X25519) ? X25519_SIZE : ((kem == kem_t::MLKEM768_P256) ? 32 : 48))), view_t(result + ctsize, tsize), view_t(point.data + pksize, tsize), shared);
		}
		// Стираем общие значения
		wipe(ssPQ, sizeof(ssPQ));
		wipe(ssT, sizeof(ssT));
	}
	// Если выработка не удалась
	if(!status){
		// Стираем место под общее значение
		wipe(shared, nsecret(kem));
		// Выводим отказ инкапсуляции
		return error_t::ENCAPSULATION;
	}
	// Выводим успех
	return error_t::NONE;
}
/**
 * @brief Метод декапсуляции ключа
 *
 * @param own           пара ключей получателя
 * @param enc           инкапсулированный ключ длиной X25519_SIZE
 * @param authenticator открытый ключ отправителя для подлинности либо пустой просмотр
 * @param shared        место под общее значение длиной X25519_SIZE
 * @return              причина отказа либо NONE
 *
 * @details Функции Decap и AuthDecap раздела 7.1.1 RFC 9180
 *
 */
nts::hpke::error_t nts::hpke::decapsulate(const key_t & own, const view_t & enc, const view_t & authenticator, uint8_t * shared) noexcept {
	// Если пара получателя не готова
	if(!own.ready())
		// Выводим отказ ключа
		return error_t::KEY;
	// Способ инкапсуляции
	const kem_t kem = own.kem();
	// Если инкапсулированный ключ записан неверной длиной
	if((enc.data == nullptr) || (enc.size != overhead(kem)))
		// Выводим отказ инкапсуляции
		return error_t::ENCAPSULATION;
	// Признак подлинности отправителя
	const bool authenticated = (authenticator.size > 0);
	// Если открытый ключ отправителя записан неверной длиной либо способ его не поддерживает
	if(authenticated && ((authenticator.data == nullptr) || (authenticator.size != length(kem)) || !hpke::authenticated(kem)))
		// Выводим отказ ключа
		return error_t::KEY;
	// Если места под итог нет
	if(shared == nullptr)
		// Выводим отказ довода
		return error_t::ARGUMENT;
	// Признак успешности выработки
	bool status = false;
	// Если способ Диффи-Хеллмана
	if(diffie(kem)){
		// Размер общего значения кривой
		const size_t size = hpke::secret(kem);
		// Общие значения Диффи-Хеллмана: мимолётное и отправителя
		uint8_t dh[2 * SCALAR_SIZE];
		/**
		 * Определяем способ инкапсуляции
		 */
		switch(static_cast <uint16_t> (kem)){
			// DHKEM(X25519, HKDF-SHA256)
			case static_cast <uint16_t> (kem_t::X25519_HKDF_SHA256):
				// Вырабатываем мимолётное общее значение
				status = agreement::x25519(own.secret(), enc, dh);
				// Если подлинность отправителя требуется
				if(status && authenticated)
					// Вырабатываем общее значение отправителя
					status = agreement::x25519(own.secret(), authenticator, dh + size);
				break;
			// DHKEM(X448, HKDF-SHA512)
			case static_cast <uint16_t> (kem_t::X448_HKDF_SHA512):
				// Вырабатываем мимолётное общее значение
				status = agreement::x448(own.secret(), enc, dh);
				// Если подлинность отправителя требуется
				if(status && authenticated)
					// Вырабатываем общее значение отправителя
					status = agreement::x448(own.secret(), authenticator, dh + size);
				break;
			// DHKEM кривых NIST
			default:
				// Вырабатываем мимолётное общее значение
				status = exchange(kem, own.secret(), enc, dh);
				// Если подлинность отправителя требуется
				if(status && authenticated)
					// Вырабатываем общее значение отправителя
					status = exchange(kem, own.secret(), authenticator, dh + size);
				break;
		}
		// Если общие значения выработаны
		if(status){
			// Привязка способа инкапсуляции: инкапсулированный ключ, ключ получателя, ключ отправителя
			uint8_t binding[BINDING_FULL];
			// Записываем инкапсулированный ключ
			::memcpy(binding, enc.data, enc.size);
			// Записываем ключ получателя
			::memcpy(binding + enc.size, own.point().data, own.point().size);
			// Если подлинность отправителя требуется
			if(authenticated)
				// Записываем ключ отправителя
				::memcpy(binding + enc.size + own.point().size, authenticator.data, authenticator.size);
			// Длина занятой части общих значений
			const size_t width = (authenticated ? (2 * size) : size);
			// Вырабатываем общее значение
			status = combine(kem, view_t(dh, width), view_t(binding, enc.size + own.point().size + (authenticated ? authenticator.size : 0)), shared);
			// Стираем привязку
			wipe(binding, sizeof(binding));
		}
		// Стираем общие значения
		wipe(dh, sizeof(dh));
	// Если способ чистый ML-KEM
	} else if(puremlkem(kem)){
		// Набор параметров ML-KEM
		const agreement::kem_t set = mlkemset(kem);
		// Ключ декапсуляции полной записью стандарта из зерна
		uint8_t expanded[2400];
		// Открытый ключ из зерна
		uint8_t opened[KEM_PUBLIC];
		// Разворачиваем зерно в ключ декапсуляции
		status = agreement::generate(set, own.secret(), opened, expanded);
		// Декапсулируем ключ
		status = (status && agreement::decapsulate(set, view_t(expanded, agreement::decapsulation(set)), enc, shared));
		// Стираем ключ декапсуляции и открытый ключ
		wipe(expanded, sizeof(expanded));
		wipe(opened, sizeof(opened));
	// Если способ гибридный
	} else if(hybrid(kem)){
		// Набор параметров ML-KEM
		const agreement::kem_t set = mlkemset(kem);
		// Длина ключа инкапсуляции ML-KEM
		const size_t pksize = agreement::encapsulation(set);
		// Длина шифртекста ML-KEM
		const size_t ctsize = agreement::ciphertext(set);
		// Зёрна составляющих из зерна пары
		uint8_t pq[MLKEM_SEED_SIZE], trad[128];
		// Растягиваем зерно пары в зёрна составляющих
		status = spread(kem, own.secret(), pq, trad);
		// Ключ декапсуляции полной записью стандарта из зерна
		uint8_t expanded[2400];
		// Открытый ключ ML-KEM из зерна
		uint8_t opened[1568];
		// Разворачиваем зерно ML-KEM в ключ декапсуляции
		status = (status && agreement::generate(set, view_t(pq, sizeof(pq)), opened, expanded));
		// Общие значения составляющих
		uint8_t ssPQ[MLKEM_SHARED_SIZE], ssT[SCALAR_SIZE];
		// Декапсулируем ключ ML-KEM
		status = (status && agreement::decapsulate(set, view_t(expanded, agreement::decapsulation(set)), view_t(enc.data, ctsize), ssPQ));
		// Если способ с группой Curve25519
		if(status && (kem == kem_t::MLKEM768_X25519))
			// Вырабатываем общее значение традиционной составляющей
			status = agreement::x25519(view_t(trad, X25519_SIZE), view_t(enc.data + ctsize, X25519_SIZE), ssT);
		// Если способ с кривой NIST
		else if(status){
			// Размер кривой
			const size_t size = ((kem == kem_t::MLKEM768_P256) ? 32 : 48);
			// Скаляр группы
			uint8_t scalar[SCALAR_SIZE];
			// Отбираем скаляр из зерна
			status = pick(kem, view_t(trad, tradition(kem)), scalar);
			// Вырабатываем общее значение традиционной составляющей
			status = (status && exchange(kem, view_t(scalar, size), view_t(enc.data + ctsize, 1 + (2 * size)), ssT));
			// Стираем скаляр
			wipe(scalar, sizeof(scalar));
		}
		// Если составляющие выработаны
		if(status){
			// Длина традиционной части ключа и шифртекста
			const size_t tsize = ((kem == kem_t::MLKEM768_X25519) ? X25519_SIZE : (1 + (2 * ((kem == kem_t::MLKEM768_P256) ? 32 : 48))));
			// Вырабатываем общее значение сочетателем C2PRI
			fuse(kem, view_t(ssPQ, sizeof(ssPQ)), view_t(ssT, ((kem == kem_t::MLKEM768_X25519) ? X25519_SIZE : ((kem == kem_t::MLKEM768_P256) ? 32 : 48))), view_t(enc.data + ctsize, tsize), view_t(own.point().data + pksize, tsize), shared);
		}
		// Стираем зёрна, ключи и общие значения
		wipe(pq, sizeof(pq));
		wipe(trad, sizeof(trad));
		wipe(expanded, sizeof(expanded));
		wipe(opened, sizeof(opened));
		wipe(ssPQ, sizeof(ssPQ));
		wipe(ssT, sizeof(ssT));
	}
	// Если выработка не удалась
	if(!status){
		// Стираем место под общее значение
		wipe(shared, nsecret(kem));
		// Выводим отказ инкапсуляции
		return error_t::ENCAPSULATION;
	}
	// Выводим успех
	return error_t::NONE;
}
/**
 * @brief Метод установки состояния отправителя по заданной мимолётной паре
 *
 * @param suite         набор алгоритмов
 * @param mode          режим работы
 * @param point         открытый ключ получателя длиной X25519_SIZE
 * @param info          привязка к применению, вправе быть пустой
 * @param psk           заранее разделённый ключ с опознавателем: непустой в режимах PSK и AUTH_PSK
 * @param authenticator пара ключей отправителя: задана в режимах AUTH и AUTH_PSK, иначе nullptr
 * @param ephemeral     мимолётная пара ключей отправителя
 * @param enc           место под инкапсулированный ключ длиной X25519_SIZE
 * @param context       состояние связи отправителя
 * @return              причина отказа либо NONE
 *
 * @details Функции SetupBaseS, SetupPSKS, SetupAuthS и SetupAuthPSKS раздела 5.1 RFC 9180
 *
 */
nts::hpke::error_t nts::hpke::sender(const suite_t & suite, const regime_t mode, const view_t & point, const view_t & info, const shared_t & psk, const key_t * authenticator, const key_t & ephemeral, uint8_t * enc, context_t & context) noexcept {
	// Стираем прежнее состояние
	context.clear();
	// Если набор не поддерживается
	if(!supported(suite))
		// Выводим отказ набора
		return error_t::SUITE;
	// Если режим неизвестен
	if(!admissible(mode))
		// Выводим отказ режима
		return error_t::MODE;
	// Если наличие пары отправителя не отвечает режиму
	if((authenticator != nullptr) != demanding(mode))
		// Выводим отказ ключа
		return error_t::KEY;
	// Если режим требует подлинности, а способ её не поддерживает: раздел 7.2 draft-ietf-hpke-pq
	if(demanding(mode) && !hpke::authenticated(suite.kem))
		// Выводим отказ режима
		return error_t::MODE;
	// Если мимолётная пара не отвечает набору
	if(!ephemeral.ready() || (ephemeral.kem() != suite.kem))
		// Выводим отказ ключа
		return error_t::KEY;
	// Если места под инкапсулированный ключ нет
	if(enc == nullptr)
		// Выводим отказ довода
		return error_t::ARGUMENT;
	// Общее значение способа инкапсуляции
	uint8_t shared[KEM_SHARED];
	// Инкапсулируем ключ
	error_t status = encapsulate(ephemeral, point, authenticator, shared, enc);
	// Если инкапсуляция удалась
	if(status == error_t::NONE)
		// Устанавливаем состояние отправителя
		status = context.setup(suite, mode, view_t(shared, nsecret(suite.kem)), info, psk, true);
	// Стираем общее значение
	wipe(shared, sizeof(shared));
	// Если установка не удалась
	if(status != error_t::NONE)
		// Стираем инкапсулированный ключ
		wipe(enc, overhead(suite.kem));
	// Выводим итог установки
	return status;
}
/**
 * @brief Метод установки состояния отправителя
 *
 * @param suite         набор алгоритмов
 * @param mode          режим работы
 * @param point         открытый ключ получателя длиной X25519_SIZE
 * @param info          привязка к применению, вправе быть пустой
 * @param psk           заранее разделённый ключ с опознавателем: непустой в режимах PSK и AUTH_PSK
 * @param authenticator пара ключей отправителя: задана в режимах AUTH и AUTH_PSK, иначе nullptr
 * @param enc           место под инкапсулированный ключ длиной X25519_SIZE
 * @param context       состояние связи отправителя
 * @return              причина отказа либо NONE
 *
 */
nts::hpke::error_t nts::hpke::sender(const suite_t & suite, const regime_t mode, const view_t & point, const view_t & info, const shared_t & psk, const key_t * authenticator, uint8_t * enc, context_t & context) noexcept {
	// Стираем прежнее состояние
	context.clear();
	// Если набор не поддерживается
	if(!supported(suite))
		// Выводим отказ набора
		return error_t::SUITE;
	// Мимолётная пара ключей
	key_t ephemeral;
	// Вырабатываем мимолётную пару
	const error_t status = ephemeral.generate(suite.kem);
	// Если выработка не удалась
	if(status != error_t::NONE)
		// Выводим отказ выработки
		return status;
	// Выводим итог установки по мимолётной паре
	return sender(suite, mode, point, info, psk, authenticator, ephemeral, enc, context);
}
/**
 * @brief Метод установки состояния получателя
 *
 * @param suite         набор алгоритмов
 * @param mode          режим работы
 * @param own           пара ключей получателя
 * @param enc           инкапсулированный ключ длиной X25519_SIZE
 * @param info          привязка к применению, вправе быть пустой
 * @param psk           заранее разделённый ключ с опознавателем: непустой в режимах PSK и AUTH_PSK
 * @param authenticator открытый ключ отправителя: задан в режимах AUTH и AUTH_PSK, иначе пустой просмотр
 * @param context       состояние связи получателя
 * @return              причина отказа либо NONE
 *
 * @details Функции SetupBaseR, SetupPSKR, SetupAuthR и SetupAuthPSKR раздела 5.1 RFC 9180
 *
 */
nts::hpke::error_t nts::hpke::recipient(const suite_t & suite, const regime_t mode, const key_t & own, const view_t & enc, const view_t & info, const shared_t & psk, const view_t & authenticator, context_t & context) noexcept {
	// Стираем прежнее состояние
	context.clear();
	// Если набор не поддерживается
	if(!supported(suite))
		// Выводим отказ набора
		return error_t::SUITE;
	// Если режим неизвестен
	if(!admissible(mode))
		// Выводим отказ режима
		return error_t::MODE;
	// Если наличие ключа отправителя не отвечает режиму
	if((authenticator.size > 0) != demanding(mode))
		// Выводим отказ ключа
		return error_t::KEY;
	// Если режим требует подлинности, а способ её не поддерживает: раздел 7.2 draft-ietf-hpke-pq
	if(demanding(mode) && !hpke::authenticated(suite.kem))
		// Выводим отказ режима
		return error_t::MODE;
	// Если пара получателя не отвечает набору
	if(!own.ready() || (own.kem() != suite.kem))
		// Выводим отказ ключа
		return error_t::KEY;
	// Общее значение способа инкапсуляции
	uint8_t shared[KEM_SHARED];
	// Декапсулируем ключ
	error_t status = decapsulate(own, enc, authenticator, shared);
	// Если декапсуляция удалась
	if(status == error_t::NONE)
		// Устанавливаем состояние получателя
		status = context.setup(suite, mode, view_t(shared, nsecret(suite.kem)), info, psk, false);
	// Стираем общее значение
	wipe(shared, sizeof(shared));
	// Выводим итог установки
	return status;
}
/**
 * @brief Метод зашифрования одного сообщения
 *
 * @param suite         набор алгоритмов
 * @param mode          режим работы
 * @param point         открытый ключ получателя длиной X25519_SIZE
 * @param info          привязка к применению, вправе быть пустой
 * @param psk           заранее разделённый ключ с опознавателем по режиму
 * @param authenticator пара ключей отправителя по режиму либо nullptr
 * @param associated    связанные данные, вправе быть пустыми
 * @param source        открытый текст, вправе быть пустым
 * @param enc           накопитель инкапсулированного ключа
 * @param result        накопитель шифртекста с меткой подлинности
 * @return              причина отказа либо NONE
 *
 * @details Одношаговая обёртка Seal раздела 6.1 RFC 9180
 *
 */
nts::hpke::error_t nts::hpke::seal(const suite_t & suite, const regime_t mode, const view_t & point, const view_t & info, const shared_t & psk, const key_t * authenticator, const view_t & associated, const view_t & source, vector <uint8_t> & enc, vector <uint8_t> & result) noexcept {
	// Очищаем накопитель шифртекста
	result.clear();
	/**
	 * Накопитель растёт под инкапсулированный ключ: нехватка памяти отдаётся кодом
	 */
	try {
		// Отводим место под инкапсулированный ключ
		enc.resize(overhead(suite.kem));
	// Если память выделить не удалось
	} catch(const bad_alloc &) {
		// Очищаем накопитель
		enc.clear();
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Состояние отправителя
	context_t context;
	// Устанавливаем состояние отправителя
	error_t status = sender(suite, mode, point, info, psk, authenticator, enc.data(), context);
	// Если состояние установлено
	if(status == error_t::NONE)
		// Зашифровываем сообщение
		status = context.seal(associated, source, result);
	// Если зашифрование не удалось
	if(status != error_t::NONE)
		// Очищаем накопитель инкапсулированного ключа
		enc.clear();
	// Выводим итог зашифрования
	return status;
}
/**
 * @brief Метод расшифрования одного сообщения
 *
 * @param suite         набор алгоритмов
 * @param mode          режим работы
 * @param own           пара ключей получателя
 * @param enc           инкапсулированный ключ длиной X25519_SIZE
 * @param info          привязка к применению, вправе быть пустой
 * @param psk           заранее разделённый ключ с опознавателем по режиму
 * @param authenticator открытый ключ отправителя по режиму либо пустой просмотр
 * @param associated    связанные данные, вправе быть пустыми
 * @param source        шифртекст с меткой подлинности
 * @param result        накопитель открытого текста
 * @return              причина отказа либо NONE
 *
 * @details Одношаговая обёртка Open раздела 6.1 RFC 9180
 *
 */
nts::hpke::error_t nts::hpke::open(const suite_t & suite, const regime_t mode, const key_t & own, const view_t & enc, const view_t & info, const shared_t & psk, const view_t & authenticator, const view_t & associated, const view_t & source, vector <uint8_t> & result) noexcept {
	// Очищаем накопитель открытого текста
	result.clear();
	// Состояние получателя
	context_t context;
	// Устанавливаем состояние получателя
	const error_t status = recipient(suite, mode, own, enc, info, psk, authenticator, context);
	// Если состояние не установлено
	if(status != error_t::NONE)
		// Выводим отказ установки
		return status;
	// Выводим итог расшифрования
	return context.open(associated, source, result);
}
/**
 * @brief Метод выработки секрета экспорта отправителем за один шаг
 *
 * @param suite         набор алгоритмов
 * @param mode          режим работы
 * @param point         открытый ключ получателя длиной X25519_SIZE
 * @param info          привязка к применению, вправе быть пустой
 * @param psk           заранее разделённый ключ с опознавателем по режиму
 * @param authenticator пара ключей отправителя по режиму либо nullptr
 * @param context       привязка секрета, вправе быть пустой
 * @param size          длина секрета в байтах
 * @param enc           накопитель инкапсулированного ключа
 * @param result        накопитель секрета
 * @return              причина отказа либо NONE
 *
 * @details Одношаговая обёртка SendExport раздела 6.2 RFC 9180
 *
 */
nts::hpke::error_t nts::hpke::dispatch(const suite_t & suite, const regime_t mode, const view_t & point, const view_t & info, const shared_t & psk, const key_t * authenticator, const view_t & context, const size_t size, vector <uint8_t> & enc, vector <uint8_t> & result) noexcept {
	// Очищаем накопитель секрета
	result.clear();
	/**
	 * Накопители растут под инкапсулированный ключ и секрет: нехватка памяти отдаётся кодом
	 */
	try {
		// Отводим место под инкапсулированный ключ
		enc.resize(overhead(suite.kem));
		// Отводим место под секрет
		result.resize(size);
	// Если память выделить не удалось
	} catch(const bad_alloc &) {
		// Очищаем накопитель инкапсулированного ключа
		enc.clear();
		// Очищаем накопитель секрета
		result.clear();
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Состояние отправителя
	context_t state;
	// Устанавливаем состояние отправителя
	error_t status = sender(suite, mode, point, info, psk, authenticator, enc.data(), state);
	// Если состояние установлено
	if(status == error_t::NONE)
		// Вырабатываем секрет экспорта
		status = state.exporter(context, result.data(), size);
	// Если выработка не удалась
	if(status != error_t::NONE){
		// Очищаем накопитель инкапсулированного ключа
		enc.clear();
		// Очищаем накопитель секрета
		result.clear();
	}
	// Выводим итог выработки
	return status;
}
/**
 * @brief Метод выработки секрета экспорта получателем за один шаг
 *
 * @param suite         набор алгоритмов
 * @param mode          режим работы
 * @param own           пара ключей получателя
 * @param enc           инкапсулированный ключ длиной X25519_SIZE
 * @param info          привязка к применению, вправе быть пустой
 * @param psk           заранее разделённый ключ с опознавателем по режиму
 * @param authenticator открытый ключ отправителя по режиму либо пустой просмотр
 * @param context       привязка секрета, вправе быть пустой
 * @param size          длина секрета в байтах
 * @param result        накопитель секрета
 * @return              причина отказа либо NONE
 *
 * @details Одношаговая обёртка ReceiveExport раздела 6.2 RFC 9180
 *
 */
nts::hpke::error_t nts::hpke::receive(const suite_t & suite, const regime_t mode, const key_t & own, const view_t & enc, const view_t & info, const shared_t & psk, const view_t & authenticator, const view_t & context, const size_t size, vector <uint8_t> & result) noexcept {
	// Очищаем накопитель секрета
	result.clear();
	// Состояние получателя
	context_t state;
	// Устанавливаем состояние получателя
	error_t status = recipient(suite, mode, own, enc, info, psk, authenticator, state);
	// Если состояние не установлено
	if(status != error_t::NONE)
		// Выводим отказ установки
		return status;
	/**
	 * Накопитель растёт под секрет: нехватка памяти отдаётся кодом
	 */
	try {
		// Отводим место под секрет
		result.resize(size);
	// Если память выделить не удалось
	} catch(const bad_alloc &) {
		// Очищаем накопитель
		result.clear();
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Вырабатываем секрет экспорта
	status = state.exporter(context, result.data(), size);
	// Если выработка не удалась
	if(status != error_t::NONE)
		// Очищаем накопитель
		result.clear();
	// Выводим итог выработки
	return status;
}
