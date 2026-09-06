/**
 * @file sha2.cpp
 * @date 2026-09-04
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
 * @brief Модуль хеширования SHA-2 по FIPS 180-4
 *
 * @details Два преобразования: SHA-256 над словами в 32 разряда с блоком в 64 байта
 *          (64 круга) и SHA-512 над словами в 64 разряда с блоком в 128 байтов
 *          (80 кругов). SHA-224 и SHA-384 - те же преобразования с иным начальным
 *          значением и усечённым итогом. Слова читаются и пишутся от старшего байта.
 *          На ARM64 оба преобразования идут машинными командами расширений SHA2 и
 *          SHA512 (ARMv8.2) с выбором на исполнении; переносимый путь остаётся
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <digest/sha2.hpp>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/machine.hpp>
#include <sys/wipe.hpp>

/**
 * Если сборка ведётся под ARM64
 */
#if defined(__aarch64__) && !defined(ANTS_NO_MACHINE)
	/**
	 * Подключаем заголовочный файл команд ARM
	 */
	#include <arm_neon.h>

	/**
	 * Если расширение уже разрешено ключами сборки
	 */
	#if defined(__ARM_FEATURE_SHA2)
		/**
		 * Атрибут цели не нужен
		 */
		#define __ANTS_SHA256_TARGET__
	/**
	 * Если собиратель clang
	 */
	#elif defined(__clang__)
		/**
		 * Разрешаем команды расширения одной функции
		 */
		#define __ANTS_SHA256_TARGET__ __attribute__((target("crypto")))
	/**
	 * Если собиратель GCC
	 */
	#else
		/**
		 * Разрешаем команды расширения одной функции
		 */
		#define __ANTS_SHA256_TARGET__ __attribute__((target("+crypto")))
	#endif

	/**
	 * Объявляем наличие ветви команд SHA-256
	 */
	#define __ANTS_SHA256_ARM__ 1

	/**
	 * Если расширение SHA-512 уже разрешено ключами сборки
	 */
	#if defined(__ARM_FEATURE_SHA512)
		/**
		 * Атрибут цели не нужен
		 */
		#define __ANTS_SHA512_TARGET__
	/**
	 * Если собиратель clang
	 */
	#elif defined(__clang__)
		/**
		 * Разрешаем команды расширения одной функции: SHA-512 идёт в составе sha3
		 */
		#define __ANTS_SHA512_TARGET__ __attribute__((target("sha3")))
	/**
	 * Если собиратель GCC
	 */
	#else
		/**
		 * Разрешаем команды расширения одной функции: SHA-512 идёт в составе sha3
		 */
		#define __ANTS_SHA512_TARGET__ __attribute__((target("+sha3")))
	#endif

	/**
	 * Объявляем наличие ветви команд SHA-512
	 */
	#define __ANTS_SHA512_ARM__ 1
#endif

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * @brief Внутренние служебные объекты
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
	using namespace nts::digest;

	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;

	/**
	 * @brief Круговые постоянные SHA-224 и SHA-256
	 *
	 * @details Первые 32 разряда дробных частей кубических корней первых 64 простых
	 *          чисел, раздел 4.2.2 FIPS 180-4
	 *
	 */
	static constexpr uint32_t K256[64] = {
		0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
		0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
		0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
		0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
		0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
		0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
		0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
		0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
	};

	/**
	 * @brief Круговые постоянные SHA-384 и SHA-512
	 *
	 * @details Первые 64 разряда дробных частей кубических корней первых 80 простых
	 *          чисел, раздел 4.2.3 FIPS 180-4
	 *
	 */
	static constexpr uint64_t K512[80] = {
		0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL, 0xB5C0FBCFEC4D3B2FULL, 0xE9B5DBA58189DBBCULL,
		0x3956C25BF348B538ULL, 0x59F111F1B605D019ULL, 0x923F82A4AF194F9BULL, 0xAB1C5ED5DA6D8118ULL,
		0xD807AA98A3030242ULL, 0x12835B0145706FBEULL, 0x243185BE4EE4B28CULL, 0x550C7DC3D5FFB4E2ULL,
		0x72BE5D74F27B896FULL, 0x80DEB1FE3B1696B1ULL, 0x9BDC06A725C71235ULL, 0xC19BF174CF692694ULL,
		0xE49B69C19EF14AD2ULL, 0xEFBE4786384F25E3ULL, 0x0FC19DC68B8CD5B5ULL, 0x240CA1CC77AC9C65ULL,
		0x2DE92C6F592B0275ULL, 0x4A7484AA6EA6E483ULL, 0x5CB0A9DCBD41FBD4ULL, 0x76F988DA831153B5ULL,
		0x983E5152EE66DFABULL, 0xA831C66D2DB43210ULL, 0xB00327C898FB213FULL, 0xBF597FC7BEEF0EE4ULL,
		0xC6E00BF33DA88FC2ULL, 0xD5A79147930AA725ULL, 0x06CA6351E003826FULL, 0x142929670A0E6E70ULL,
		0x27B70A8546D22FFCULL, 0x2E1B21385C26C926ULL, 0x4D2C6DFC5AC42AEDULL, 0x53380D139D95B3DFULL,
		0x650A73548BAF63DEULL, 0x766A0ABB3C77B2A8ULL, 0x81C2C92E47EDAEE6ULL, 0x92722C851482353BULL,
		0xA2BFE8A14CF10364ULL, 0xA81A664BBC423001ULL, 0xC24B8B70D0F89791ULL, 0xC76C51A30654BE30ULL,
		0xD192E819D6EF5218ULL, 0xD69906245565A910ULL, 0xF40E35855771202AULL, 0x106AA07032BBD1B8ULL,
		0x19A4C116B8D2D0C8ULL, 0x1E376C085141AB53ULL, 0x2748774CDF8EEB99ULL, 0x34B0BCB5E19B48A8ULL,
		0x391C0CB3C5C95A63ULL, 0x4ED8AA4AE3418ACBULL, 0x5B9CCA4F7763E373ULL, 0x682E6FF3D6B2B8A3ULL,
		0x748F82EE5DEFB2FCULL, 0x78A5636F43172F60ULL, 0x84C87814A1F0AB72ULL, 0x8CC702081A6439ECULL,
		0x90BEFFFA23631E28ULL, 0xA4506CEBDE82BDE9ULL, 0xBEF9A3F7B2C67915ULL, 0xC67178F2E372532BULL,
		0xCA273ECEEA26619CULL, 0xD186B8C721C0C207ULL, 0xEADA7DD6CDE0EB1EULL, 0xF57D4F7FEE6ED178ULL,
		0x06F067AA72176FBAULL, 0x0A637DC5A2C898A6ULL, 0x113F9804BEF90DAEULL, 0x1B710B35131C471BULL,
		0x28DB77F523047D84ULL, 0x32CAAB7B40C72493ULL, 0x3C9EBE0A15C9BEBCULL, 0x431D67C49C100D4CULL,
		0x4CC5D4BECB3E42B6ULL, 0x597F299CFC657E2AULL, 0x5FCB6FAB3AD6FAECULL, 0x6C44198C4A475817ULL
	};

	/**
	 * @brief Начальные значения хеша SHA-224
	 *
	 * @details Раздел 5.3.2 FIPS 180-4
	 *
	 */
	static constexpr uint32_t H224[8] = {
		0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939, 0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4
	};

	/**
	 * @brief Начальные значения хеша SHA-256
	 *
	 * @details Раздел 5.3.3 FIPS 180-4
	 *
	 */
	static constexpr uint32_t H256[8] = {
		0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
	};

	/**
	 * @brief Начальные значения хеша SHA-384
	 *
	 * @details Раздел 5.3.4 FIPS 180-4
	 *
	 */
	static constexpr uint64_t H384[8] = {
		0xCBBB9D5DC1059ED8ULL, 0x629A292A367CD507ULL, 0x9159015A3070DD17ULL, 0x152FECD8F70E5939ULL,
		0x67332667FFC00B31ULL, 0x8EB44A8768581511ULL, 0xDB0C2E0D64F98FA7ULL, 0x47B5481DBEFA4FA4ULL
	};

	/**
	 * @brief Начальные значения хеша SHA-512
	 *
	 * @details Раздел 5.3.5 FIPS 180-4
	 *
	 */
	static constexpr uint64_t H512[8] = {
		0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL, 0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
		0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL, 0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
	};

	/**
	 * @brief Метод кругового сдвига слова в 32 разряда вправо
	 *
	 * @param value сдвигаемое слово
	 * @param count число разрядов сдвига
	 *
	 * @return      сдвинутое слово
	 *
	 */
	static __ANTS_INLINE__ uint32_t rotr(const uint32_t value, const unsigned count) noexcept {
		// Выводим слово, сдвинутое по кругу
		return ((value >> count) | (value << (32 - count)));
	}

	/**
	 * @brief Метод кругового сдвига слова в 64 разряда вправо
	 *
	 * @param value сдвигаемое слово
	 * @param count число разрядов сдвига
	 *
	 * @return      сдвинутое слово
	 *
	 */
	static __ANTS_INLINE__ uint64_t rotr(const uint64_t value, const unsigned count) noexcept {
		// Выводим слово, сдвинутое по кругу
		return ((value >> count) | (value << (64 - count)));
	}

	/**
	 * @brief Метод чтения слова в 32 разряда от старшего байта
	 *
	 * @param data читаемые байты
	 *
	 * @return     прочитанное слово
	 *
	 */
	static __ANTS_INLINE__ uint32_t load32(const uint8_t * data) noexcept {
		// Выводим слово, собранное от старшего байта
		return ((static_cast <uint32_t> (data[0]) << 24) | (static_cast <uint32_t> (data[1]) << 16) |
		        (static_cast <uint32_t> (data[2]) << 8) | static_cast <uint32_t> (data[3]));
	}

	/**
	 * @brief Метод чтения слова в 64 разряда от старшего байта
	 *
	 * @param data читаемые байты
	 *
	 * @return     прочитанное слово
	 *
	 */
	static __ANTS_INLINE__ uint64_t load64(const uint8_t * data) noexcept {
		// Выводим слово, собранное из двух половин от старшего байта
		return ((static_cast <uint64_t> (load32(data)) << 32) | static_cast <uint64_t> (load32(data + 4)));
	}

	/**
	 * @brief Метод записи слова в 32 разряда от старшего байта
	 *
	 * @param value записываемое слово
	 * @param data  место, в которое записываются байты
	 *
	 */
	static __ANTS_INLINE__ void store32(const uint32_t value, uint8_t * data) noexcept {
		// Записываем старший байт слова
		data[0] = static_cast <uint8_t> (value >> 24);
		// Записываем второй байт слова
		data[1] = static_cast <uint8_t> (value >> 16);
		// Записываем третий байт слова
		data[2] = static_cast <uint8_t> (value >> 8);
		// Записываем младший байт слова
		data[3] = static_cast <uint8_t> (value);
	}

	/**
	 * @brief Метод записи слова в 64 разряда от старшего байта
	 *
	 * @param value записываемое слово
	 * @param data  место, в которое записываются байты
	 *
	 */
	static __ANTS_INLINE__ void store64(const uint64_t value, uint8_t * data) noexcept {
		// Записываем старшую половину слова
		store32(static_cast <uint32_t> (value >> 32), data);
		// Записываем младшую половину слова
		store32(static_cast <uint32_t> (value), data + 4);
	}

	/**
	 * @brief Метод одного круга преобразования SHA-512 без сдвига переменных
	 *
	 * @details Раздел 6.4.2 FIPS 180-4: переменные d и h заменяются итогом круга,
	 *          остальные не трогаются - сдвиг делает вызывающий переименованием
	 *
	 * @param a первая рабочая переменная
	 * @param b вторая рабочая переменная
	 * @param c третья рабочая переменная
	 * @param d четвёртая рабочая переменная: заменяется суммой с первым временным значением
	 * @param e пятая рабочая переменная
	 * @param f шестая рабочая переменная
	 * @param g седьмая рабочая переменная
	 * @param h восьмая рабочая переменная: заменяется суммой временных значений
	 * @param k круговая постоянная
	 * @param w слово расписания круга
	 *
	 */
	static __ANTS_INLINE__ void round512(const uint64_t a, const uint64_t b, const uint64_t c, uint64_t & d, const uint64_t e, const uint64_t f, const uint64_t g, uint64_t & h, const uint64_t k, const uint64_t w) noexcept {
		// Большая сигма первая от переменной e
		const uint64_t s1 = (rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41));
		// Функция выбора по переменной e
		const uint64_t ch = ((e & f) ^ ((~e) & g));
		// Первое временное значение круга
		const uint64_t t1 = (h + s1 + ch + k + w);
		// Большая сигма нулевая от переменной a
		const uint64_t s0 = (rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39));
		// Функция большинства по переменным a, b, c
		const uint64_t maj = ((a & b) ^ (a & c) ^ (b & c));
		// Складываем новое значение переменной e на месте d
		d += t1;
		// Складываем новое значение переменной a на месте h
		h = (t1 + s0 + maj);
	}

/**
 * Если есть ветвь команд SHA-256 расширения ARMv8
 */
#if defined(__ANTS_SHA256_ARM__)
	/**
	 * @brief Метод разбора блока в 64 байта командами SHA256H, SHA256H2, SHA256SU0 и SHA256SU1
	 *
	 * @param block разбираемый блок сообщения
	 * @param hash  значение хеша, в которое складывается итог блока
	 *
	 */
	static __ANTS_SHA256_TARGET__ void compressArm(const uint8_t * block, uint64_t * hash) noexcept {
		// Значение хеша словами в 32 разряда
		uint32_t words[8];
		/**
		 * Выполняем перенос значения хеша в слова
		 */
		for(size_t i = 0; i < 8; i++)
			// Переносим очередное слово
			words[i] = static_cast <uint32_t> (hash[i]);
		// Половины состояния: abcd и efgh
		uint32x4_t abcd = vld1q_u32(words), efgh = vld1q_u32(words + 4);
		// Сохранённые половины для сложения в конце
		const uint32x4_t abcd0 = abcd, efgh0 = efgh;
		// Четвёрки слов сообщения от старшего байта
		uint32x4_t m0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block)));
		// Четвёрки слов сообщения от старшего байта
		uint32x4_t m1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 16)));
		// Четвёрки слов сообщения от старшего байта
		uint32x4_t m2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 32)));
		// Четвёрки слов сообщения от старшего байта
		uint32x4_t m3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 48)));
		/**
		 * Выполняем шестнадцать четвёрок кругов: по четыре круга на команду
		 */
		for(size_t i = 0; i < 16; i++){
			// Слова расписания, сложенные с постоянными четырёх кругов
			const uint32x4_t t = vaddq_u32(m0, vld1q_u32(K256 + (i * 4)));
			// Сохранённая половина abcd
			const uint32x4_t saved = abcd;
			// Выполняем четыре круга над половиной abcd
			abcd = vsha256hq_u32(abcd, efgh, t);
			// Выполняем четыре круга над половиной efgh
			efgh = vsha256h2q_u32(efgh, saved, t);
			// Если расписание ещё расширяется
			if(i < 12)
				// Складываем следующую четвёрку слов расписания
				m0 = vsha256su1q_u32(vsha256su0q_u32(m0, m1), m2, m3);
			// Сдвигаем четвёрки слов по кругу
			const uint32x4_t shifted = m0;
			// Сдвигаем четвёрки слов по кругу
			m0 = m1;
			// Сдвигаем четвёрки слов по кругу
			m1 = m2;
			// Сдвигаем четвёрки слов по кругу
			m2 = m3;
			// Сдвигаем четвёрки слов по кругу
			m3 = shifted;
		}
		// Складываем итог с прежним значением хеша
		abcd = vaddq_u32(abcd, abcd0);
		// Складываем итог с прежним значением хеша
		efgh = vaddq_u32(efgh, efgh0);
		// Записываем половину abcd
		vst1q_u32(words, abcd);
		// Записываем половину efgh
		vst1q_u32(words + 4, efgh);
		/**
		 * Выполняем перенос слов в значение хеша
		 */
		for(size_t i = 0; i < 8; i++)
			// Переносим очередное слово
			hash[i] = words[i];
	}
#endif

	/**
	 * @brief Метод разбора блока в 64 байта преобразованием SHA-256
	 *
	 * @details Раздел 6.2.2 FIPS 180-4: расписание из 64 слов и 64 круга
	 *
	 * @param block разбираемый блок сообщения
	 * @param hash  значение хеша, в которое складывается итог блока
	 *
	 */
	static void compress256(const uint8_t * block, uint64_t * hash) noexcept {
/**
 * Если есть ветвь команд SHA-256 расширения ARMv8
 */
#if defined(__ANTS_SHA256_ARM__)
		// Если машина хеширует командами
		if(machine::has(machine::feature_t::SHA256)){
			// Выполняем разбор блока командами
			compressArm(block, hash);
			// Выходим из метода
			return;
		}
#endif
		// Расписание слов сообщения
		uint32_t w[64];
		/**
		 * Выполняем чтение шестнадцати слов блока
		 */
		for(size_t i = 0; i < 16; i++)
			// Читаем очередное слово блока от старшего байта
			w[i] = load32(block + (i * 4));
		/**
		 * Выполняем расширение расписания до 64 слов
		 */
		for(size_t i = 16; i < 64; i++){
			// Малая сигма нулевая от слова пятнадцатью позициями раньше
			const uint32_t s0 = (rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3));
			// Малая сигма первая от слова двумя позициями раньше
			const uint32_t s1 = (rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10));
			// Складываем очередное слово расписания
			w[i] = (w[i - 16] + s0 + w[i - 7] + s1);
		}
		// Рабочие переменные круга
		uint32_t a = static_cast <uint32_t> (hash[0]), b = static_cast <uint32_t> (hash[1]);
		// Рабочие переменные круга
		uint32_t c = static_cast <uint32_t> (hash[2]), d = static_cast <uint32_t> (hash[3]);
		// Рабочие переменные круга
		uint32_t e = static_cast <uint32_t> (hash[4]), f = static_cast <uint32_t> (hash[5]);
		// Рабочие переменные круга
		uint32_t g = static_cast <uint32_t> (hash[6]), h = static_cast <uint32_t> (hash[7]);
		/**
		 * Выполняем 64 круга преобразования
		 */
		for(size_t i = 0; i < 64; i++){
			// Большая сигма первая от переменной e
			const uint32_t s1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25));
			// Функция выбора по переменной e
			const uint32_t ch = ((e & f) ^ ((~e) & g));
			// Первое временное значение круга
			const uint32_t t1 = (h + s1 + ch + K256[i] + w[i]);
			// Большая сигма нулевая от переменной a
			const uint32_t s0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22));
			// Функция большинства по переменным a, b, c
			const uint32_t maj = ((a & b) ^ (a & c) ^ (b & c));
			// Второе временное значение круга
			const uint32_t t2 = (s0 + maj);
			// Сдвигаем рабочие переменные
			h = g;
			// Сдвигаем рабочие переменные
			g = f;
			// Сдвигаем рабочие переменные
			f = e;
			// Складываем новое значение переменной e
			e = (d + t1);
			// Сдвигаем рабочие переменные
			d = c;
			// Сдвигаем рабочие переменные
			c = b;
			// Сдвигаем рабочие переменные
			b = a;
			// Складываем новое значение переменной a
			a = (t1 + t2);
		}
		// Складываем итог круга с прежним значением хеша
		hash[0] = static_cast <uint32_t> (static_cast <uint32_t> (hash[0]) + a);
		// Складываем итог круга с прежним значением хеша
		hash[1] = static_cast <uint32_t> (static_cast <uint32_t> (hash[1]) + b);
		// Складываем итог круга с прежним значением хеша
		hash[2] = static_cast <uint32_t> (static_cast <uint32_t> (hash[2]) + c);
		// Складываем итог круга с прежним значением хеша
		hash[3] = static_cast <uint32_t> (static_cast <uint32_t> (hash[3]) + d);
		// Складываем итог круга с прежним значением хеша
		hash[4] = static_cast <uint32_t> (static_cast <uint32_t> (hash[4]) + e);
		// Складываем итог круга с прежним значением хеша
		hash[5] = static_cast <uint32_t> (static_cast <uint32_t> (hash[5]) + f);
		// Складываем итог круга с прежним значением хеша
		hash[6] = static_cast <uint32_t> (static_cast <uint32_t> (hash[6]) + g);
		// Складываем итог круга с прежним значением хеша
		hash[7] = static_cast <uint32_t> (static_cast <uint32_t> (hash[7]) + h);
	}

/**
 * Если есть ветвь команд SHA-512 расширения ARMv8.2
 */
#if defined(__ANTS_SHA512_ARM__)
	/**
	 * @brief Два круга SHA-512 командами SHA512H, SHA512H2, SHA512SU0 и SHA512SU1
	 *
	 * @details Состояние лежит четырьмя парами слов: ab, cd, ef и gh. Команды
	 *          считают два круга разом, и роли пар за два круга сдвигаются по
	 *          кругу: пара-цель принимает новые a и b, а пара на две раньше
	 *          складывается с промежутком. Внутри макроса допустимы лишь блочные
	 *          пояснения: строчные срезали бы продолжение строки
	 *
	 * @param t      пара-цель: заменяется итогом двух кругов
	 * @param p1     пара на одну раньше цели
	 * @param p2     пара на две раньше цели: складывается с промежутком
	 * @param p3     пара на три раньше цели
	 * @param m      пара слов расписания текущих кругов: расширяется на два круга вперёд
	 * @param k      номер первой из двух постоянных
	 * @param n      пара слов расписания, следующая за текущей
	 * @param f      пара слов расписания на семь пар дальше
	 * @param e1     пара слов расписания на четыре пары дальше
	 * @param e2     пара слов расписания на пять пар дальше
	 * @param extend признак того, что расписание ещё расширяется
	 *
	 */
	#define __ANTS_SHA512_STEP__(t, p1, p2, p3, m, k, n, f, e1, e2, extend) { \
		/* Слова расписания, сложенные с постоянными двух кругов */ \
		const uint64x2_t sum = vaddq_u64(m, vld1q_u64(K512 + (k))); \
		/* Сумма с переставленными половинами, сложенная с парой-целью */ \
		const uint64x2_t mixed = vaddq_u64(vextq_u64(sum, sum, 1), t); \
		/* Промежуток двух кругов: сигма и выбор над парами fg и de */ \
		const uint64x2_t mid = vsha512hq_u64(mixed, vextq_u64(p1, t, 1), vextq_u64(p2, p1, 1)); \
		/* Новая пара-цель: сигма и большинство над парами ab и cd */ \
		t = vsha512h2q_u64(mid, p2, p3); \
		/* Пара на две раньше складывается с промежутком */ \
		p2 = vaddq_u64(p2, mid); \
		/* Если расписание ещё расширяется */ \
		if(extend) \
			/* Складываем пару слов расписания на восемь пар вперёд */ \
			m = vsha512su1q_u64(vsha512su0q_u64(m, n), f, vextq_u64(e1, e2, 1)); \
	}

	/**
	 * @brief Метод чтения пары слов сообщения от старшего байта в вектор
	 *
	 * @param data читаемые шестнадцать байтов
	 *
	 * @return     пара слов
	 *
	 */
	static __ANTS_INLINE__ __ANTS_SHA512_TARGET__ uint64x2_t pair(const uint8_t * data) noexcept {
		// Выводим пару слов с обращённым порядком байтов внутри каждого слова
		return vreinterpretq_u64_u8(vrev64q_u8(vld1q_u8(data)));
	}
	/**
	 * @brief Метод разбора блока в 128 байтов командами SHA-512 расширения ARMv8.2
	 *
	 * @details Восемь пар слов расписания и четыре пары состояния; 80 кругов идут
	 *          пятью проходами по восемь шагов в два круга, и роли пар состояния за
	 *          восемь шагов дважды обходят круг, возвращаясь на места. На последнем
	 *          проходе расписание не расширяется
	 *
	 * @param block разбираемый блок сообщения
	 * @param hash  значение хеша, в которое складывается итог блока
	 *
	 */
	static __ANTS_SHA512_TARGET__ void compressArm512(const uint8_t * block, uint64_t * hash) noexcept {
		// Пары состояния: ab, cd, ef и gh
		uint64x2_t ab = vld1q_u64(hash), cd = vld1q_u64(hash + 2);
		// Пары состояния: ab, cd, ef и gh
		uint64x2_t ef = vld1q_u64(hash + 4), gh = vld1q_u64(hash + 6);
		// Сохранённые пары для сложения в конце
		const uint64x2_t ab0 = ab, cd0 = cd, ef0 = ef, gh0 = gh;
		// Пары слов расписания
		uint64x2_t m0 = pair(block), m1 = pair(block + 16), m2 = pair(block + 32), m3 = pair(block + 48);
		// Пары слов расписания
		uint64x2_t m4 = pair(block + 64), m5 = pair(block + 80), m6 = pair(block + 96), m7 = pair(block + 112);
		/**
		 * Выполняем пять проходов по шестнадцать кругов
		 */
		for(size_t i = 0; i < 5; i++){
			// Признак того, что расписание ещё расширяется
			const bool extend = (i < 4);
			// Номер первой постоянной прохода
			const size_t k = (i * 16);
			// Круги первый и второй прохода
			__ANTS_SHA512_STEP__(gh, ef, cd, ab, m0, k, m1, m7, m4, m5, extend)
			// Круги третий и четвёртый прохода
			__ANTS_SHA512_STEP__(ef, cd, ab, gh, m1, k + 2, m2, m0, m5, m6, extend)
			// Круги пятый и шестой прохода
			__ANTS_SHA512_STEP__(cd, ab, gh, ef, m2, k + 4, m3, m1, m6, m7, extend)
			// Круги седьмой и восьмой прохода
			__ANTS_SHA512_STEP__(ab, gh, ef, cd, m3, k + 6, m4, m2, m7, m0, extend)
			// Круги девятый и десятый прохода
			__ANTS_SHA512_STEP__(gh, ef, cd, ab, m4, k + 8, m5, m3, m0, m1, extend)
			// Круги одиннадцатый и двенадцатый прохода
			__ANTS_SHA512_STEP__(ef, cd, ab, gh, m5, k + 10, m6, m4, m1, m2, extend)
			// Круги тринадцатый и четырнадцатый прохода
			__ANTS_SHA512_STEP__(cd, ab, gh, ef, m6, k + 12, m7, m5, m2, m3, extend)
			// Круги пятнадцатый и шестнадцатый прохода
			__ANTS_SHA512_STEP__(ab, gh, ef, cd, m7, k + 14, m0, m6, m3, m4, extend)
		}
		// Складываем итог с прежним значением хеша
		vst1q_u64(hash, vaddq_u64(ab, ab0));
		// Складываем итог с прежним значением хеша
		vst1q_u64(hash + 2, vaddq_u64(cd, cd0));
		// Складываем итог с прежним значением хеша
		vst1q_u64(hash + 4, vaddq_u64(ef, ef0));
		// Складываем итог с прежним значением хеша
		vst1q_u64(hash + 6, vaddq_u64(gh, gh0));
	}
#endif

	/**
	 * @brief Метод разбора блока в 128 байтов преобразованием SHA-512
	 *
	 * @details Раздел 6.4.2 FIPS 180-4: расписание из 80 слов и 80 кругов
	 *
	 * @param block разбираемый блок сообщения
	 * @param hash  значение хеша, в которое складывается итог блока
	 *
	 */
	static void compress512(const uint8_t * block, uint64_t * hash) noexcept {
/**
 * Если есть ветвь команд SHA-512 расширения ARMv8.2
 */
#if defined(__ANTS_SHA512_ARM__)
		// Если машина хеширует командами
		if(machine::has(machine::feature_t::SHA512)){
			// Выполняем разбор блока командами
			compressArm512(block, hash);
			// Выходим из метода
			return;
		}
#endif
		// Расписание слов сообщения
		uint64_t w[80];
		/**
		 * Выполняем чтение шестнадцати слов блока
		 */
		for(size_t i = 0; i < 16; i++)
			// Читаем очередное слово блока от старшего байта
			w[i] = load64(block + (i * 8));
		/**
		 * Выполняем расширение расписания до 80 слов
		 */
		for(size_t i = 16; i < 80; i++){
			// Малая сигма нулевая от слова пятнадцатью позициями раньше
			const uint64_t s0 = (rotr(w[i - 15], 1) ^ rotr(w[i - 15], 8) ^ (w[i - 15] >> 7));
			// Малая сигма первая от слова двумя позициями раньше
			const uint64_t s1 = (rotr(w[i - 2], 19) ^ rotr(w[i - 2], 61) ^ (w[i - 2] >> 6));
			// Складываем очередное слово расписания
			w[i] = (w[i - 16] + s0 + w[i - 7] + s1);
		}
		// Рабочие переменные круга
		uint64_t a = hash[0], b = hash[1], c = hash[2], d = hash[3];
		// Рабочие переменные круга
		uint64_t e = hash[4], f = hash[5], g = hash[6], h = hash[7];
		/**
		 * Выполняем 80 кругов преобразования восьмёрками: круг кладёт итог прямо в
		 * переменные d и h, а сдвиг остальных заменён кольцевым переименованием -
		 * за восемь кругов имена возвращаются на места
		 */
		for(size_t i = 0; i < 80; i += 8){
			// Первый круг восьмёрки
			round512(a, b, c, d, e, f, g, h, K512[i], w[i]);
			// Второй круг восьмёрки
			round512(h, a, b, c, d, e, f, g, K512[i + 1], w[i + 1]);
			// Третий круг восьмёрки
			round512(g, h, a, b, c, d, e, f, K512[i + 2], w[i + 2]);
			// Четвёртый круг восьмёрки
			round512(f, g, h, a, b, c, d, e, K512[i + 3], w[i + 3]);
			// Пятый круг восьмёрки
			round512(e, f, g, h, a, b, c, d, K512[i + 4], w[i + 4]);
			// Шестой круг восьмёрки
			round512(d, e, f, g, h, a, b, c, K512[i + 5], w[i + 5]);
			// Седьмой круг восьмёрки
			round512(c, d, e, f, g, h, a, b, K512[i + 6], w[i + 6]);
			// Восьмой круг восьмёрки
			round512(b, c, d, e, f, g, h, a, K512[i + 7], w[i + 7]);
		}
		// Складываем итог круга с прежним значением хеша
		hash[0] += a;
		// Складываем итог круга с прежним значением хеша
		hash[1] += b;
		// Складываем итог круга с прежним значением хеша
		hash[2] += c;
		// Складываем итог круга с прежним значением хеша
		hash[3] += d;
		// Складываем итог круга с прежним значением хеша
		hash[4] += e;
		// Складываем итог круга с прежним значением хеша
		hash[5] += f;
		// Складываем итог круга с прежним значением хеша
		hash[6] += g;
		// Складываем итог круга с прежним значением хеша
		hash[7] += h;
	}
};

/**
 * @brief Метод разбора блока сообщения
 *
 * @param block разбираемый блок: накопитель либо сам кусок сообщения
 *
 */
void nts::digest::Sha2::compress(const uint8_t * block) noexcept {
	// Если хеш вырабатывается над словами в 64 разряда
	if(this->block() == 128)
		// Выполняем разбор блока преобразованием SHA-512
		compress512(block, this->_hash);
	// Иначе хеш вырабатывается над словами в 32 разряда
	else compress256(block, this->_hash);
}
/**
 * @brief Метод получения разновидности вырабатываемого хеша
 *
 * @return разновидность вырабатываемого хеша
 *
 */
nts::digest::sha_t nts::digest::Sha2::type() const noexcept {
	// Выводим разновидность вырабатываемого хеша
	return this->_type;
}
/**
 * @brief Метод получения размера блока сообщения
 *
 * @return размер блока в байтах: 64 либо 128
 *
 */
size_t nts::digest::Sha2::block() const noexcept {
	// Выводим размер блока по разновидности хеша
	return (((this->_type == sha_t::SHA384) || (this->_type == sha_t::SHA512)) ? 128 : 64);
}
/**
 * @brief Метод сброса состояния хеширования
 *
 * @param type разновидность вырабатываемого хеша
 *
 */
void nts::digest::Sha2::reset(const sha_t type) noexcept {
	// Запоминаем разновидность вырабатываемого хеша
	this->_type = type;
	// Сбрасываем признак снятого хеша
	this->_finished = false;
	// Сбрасываем число байтов незавершённого блока
	this->_size = 0;
	// Сбрасываем младшую часть числа разобранных байтов
	this->_count[0] = 0;
	// Сбрасываем старшую часть числа разобранных байтов
	this->_count[1] = 0;
	/**
	 * Выполняем установку начального значения хеша по разновидности
	 */
	switch(static_cast <uint8_t> (type)){
		// Если вырабатывается хеш длиной 224 разряда
		case static_cast <uint8_t> (sha_t::SHA224): {
			/**
			 * Выполняем перенос начальных значений
			 */
			for(size_t i = 0; i < 8; i++)
				// Переносим очередное начальное значение
				this->_hash[i] = H224[i];
		} break;
		// Если вырабатывается хеш длиной 256 разрядов
		case static_cast <uint8_t> (sha_t::SHA256): {
			/**
			 * Выполняем перенос начальных значений
			 */
			for(size_t i = 0; i < 8; i++)
				// Переносим очередное начальное значение
				this->_hash[i] = H256[i];
		} break;
		// Если вырабатывается хеш длиной 384 разряда
		case static_cast <uint8_t> (sha_t::SHA384): {
			/**
			 * Выполняем перенос начальных значений
			 */
			for(size_t i = 0; i < 8; i++)
				// Переносим очередное начальное значение
				this->_hash[i] = H384[i];
		} break;
		// Если вырабатывается хеш длиной 512 разрядов
		case static_cast <uint8_t> (sha_t::SHA512): {
			/**
			 * Выполняем перенос начальных значений
			 */
			for(size_t i = 0; i < 8; i++)
				// Переносим очередное начальное значение
				this->_hash[i] = H512[i];
		} break;
		// Если разновидность хеша не установлена
		default: {
			// Выполняем затирание значения хеша
			wipe(this->_hash, sizeof(this->_hash));
			// Считаем хеш снятым: вырабатывать нечего
			this->_finished = true;
		}
	}
	// Выполняем затирание накопителя незавершённого блока
	wipe(this->_block, sizeof(this->_block));
}
/**
 * @brief Метод подачи куска сообщения
 *
 * @param data подаваемый кусок сообщения
 *
 */
void nts::digest::Sha2::update(const view_t & data) noexcept {
	// Если хеш уже снят либо кусок сообщения пуст
	if(this->_finished || (data.data == nullptr) || (data.size == 0))
		// Выходим из метода
		return;
	// Размер блока сообщения
	const size_t width = this->block();
	// Число ещё не разобранных байтов куска
	size_t left = data.size;
	// Позиция чтения куска
	const uint8_t * cursor = data.data;
	// Прежнее значение младшей части числа разобранных байтов
	const uint64_t before = this->_count[0];
	// Считаем поданные байты в младшей части
	this->_count[0] += static_cast <uint64_t> (data.size);
	// Если младшая часть переполнилась
	if(this->_count[0] < before)
		// Переносим единицу в старшую часть
		this->_count[1]++;
	// Если в накопителе есть незавершённый блок
	if(this->_size > 0){
		// Число байтов, которых накопителю не хватает до целого блока
		const size_t needed = (width - this->_size);
		// Число байтов, переносимых в накопитель из куска
		const size_t taken = ((left < needed) ? left : needed);
		/**
		 * Выполняем перенос байтов куска в накопитель
		 */
		for(size_t i = 0; i < taken; i++)
			// Переносим очередной байт куска
			this->_block[this->_size + i] = cursor[i];
		// Считаем перенесённые байты
		this->_size += taken;
		// Сдвигаем позицию чтения куска
		cursor += taken;
		// Уменьшаем число не разобранных байтов
		left -= taken;
		// Если блок набрался целиком
		if(this->_size == width){
			// Выполняем разбор накопленного блока
			this->compress(this->_block);
			// Сбрасываем число байтов незавершённого блока
			this->_size = 0;
		// Иначе весь кусок ушёл в накопитель, и блок ещё не полон
		} else return;
	}
	/**
	 * Выполняем разбор целых блоков куска прямо из него: слова читаются побайтно,
	 * оттого выравнивание куска значения не имеет
	 */
	while(left >= width){
		// Выполняем разбор очередного блока куска
		this->compress(cursor);
		// Сдвигаем позицию чтения куска
		cursor += width;
		// Уменьшаем число не разобранных байтов
		left -= width;
	}
	/**
	 * Выполняем перенос хвоста куска в накопитель
	 */
	for(size_t i = 0; i < left; i++)
		// Переносим очередной байт хвоста
		this->_block[i] = cursor[i];
	// Запоминаем число байтов незавершённого блока
	this->_size = left;
}
/**
 * @brief Метод снятия выработанного хеша
 *
 * @param result место, в которое записывается хеш
 * @param size   размер места в байтах, не меньше длины хеша
 *
 * @return       признак успешности снятия хеша
 *
 */
bool nts::digest::Sha2::finish(uint8_t * result, const size_t size) noexcept {
	// Длина вырабатываемого хеша в байтах
	const size_t length = static_cast <size_t> (this->_type);
	// Если хеш уже снят, либо места под него нет, либо оно мало
	if(this->_finished || (result == nullptr) || (size < length))
		// Выводим отказ снятия хеша
		return false;
	// Размер блока сообщения
	const size_t width = this->block();
	// Размер поля длины сообщения в хвосте: 8 байтов у блока в 64 и 16 у блока в 128
	const size_t field = (width / 8);
	// Число разобранных разрядов сообщения: младшая часть
	const uint64_t low = (this->_count[0] << 3);
	// Число разобранных разрядов сообщения: старшая часть
	const uint64_t high = ((this->_count[1] << 3) | (this->_count[0] >> 61));
	// Записываем байт-отделитель за последним байтом сообщения
	this->_block[this->_size++] = 0x80;
	// Если места под поле длины в этом блоке не осталось
	if(this->_size > (width - field)){
		/**
		 * Выполняем дополнение блока нулями до конца
		 */
		for(size_t i = this->_size; i < width; i++)
			// Записываем очередной нулевой байт
			this->_block[i] = 0;
		// Выполняем разбор дополненного блока
		this->compress(this->_block);
		// Сбрасываем число байтов незавершённого блока
		this->_size = 0;
	}
	/**
	 * Выполняем дополнение блока нулями до поля длины
	 */
	for(size_t i = this->_size; i < (width - field); i++)
		// Записываем очередной нулевой байт
		this->_block[i] = 0;
	// Если поле длины занимает шестнадцать байтов
	if(field == 16)
		// Записываем старшую часть длины сообщения
		store64(high, this->_block + (width - 16));
	// Записываем младшую часть длины сообщения
	store64(low, this->_block + (width - 8));
	// Выполняем разбор последнего блока
	this->compress(this->_block);
	// Если хеш вырабатывается над словами в 64 разряда
	if(width == 128){
		/**
		 * Выполняем запись слов хеша от старшего байта в пределах длины хеша
		 */
		for(size_t i = 0; (i * 8) < length; i++)
			// Записываем очередное слово хеша
			store64(this->_hash[i], result + (i * 8));
	// Иначе хеш вырабатывается над словами в 32 разряда
	} else {
		/**
		 * Выполняем запись слов хеша от старшего байта в пределах длины хеша
		 */
		for(size_t i = 0; (i * 4) < length; i++)
			// Записываем очередное слово хеша
			store32(static_cast <uint32_t> (this->_hash[i]), result + (i * 4));
	}
	// Выполняем затирание значения хеша
	wipe(this->_hash, sizeof(this->_hash));
	// Выполняем затирание накопителя незавершённого блока
	wipe(this->_block, sizeof(this->_block));
	// Сбрасываем число байтов незавершённого блока
	this->_size = 0;
	// Запоминаем, что хеш снят
	this->_finished = true;
	// Выводим успешность снятия хеша
	return true;
}
/**
 * @brief Конструктор
 *
 * @param type разновидность вырабатываемого хеша
 *
 */
nts::digest::Sha2::Sha2(const sha_t type) noexcept : _type(sha_t::NONE), _finished(true), _size(0) {
	// Выполняем сброс состояния хеширования
	this->reset(type);
}
/**
 * @brief Деструктор
 *
 */
nts::digest::Sha2::~Sha2() noexcept {
	// Выполняем затирание значения хеша
	wipe(this->_hash, sizeof(this->_hash));
	// Выполняем затирание накопителя незавершённого блока
	wipe(this->_block, sizeof(this->_block));
	// Выполняем затирание числа разобранных байтов
	wipe(this->_count, sizeof(this->_count));
}
/**
 * @brief Метод выработки хеша SHA-2 целого сообщения
 *
 * @param type   разновидность вырабатываемого хеша
 * @param data   хешируемое сообщение
 * @param result место, в которое записывается хеш
 * @param size   размер места в байтах, не меньше длины хеша
 *
 * @return       признак успешности выработки хеша
 *
 */
bool nts::digest::sha2(const sha_t type, const view_t & data, uint8_t * result, const size_t size) noexcept {
	// Объект хеширования
	sha2_t hasher(type);
	// Выполняем подачу целого сообщения
	hasher.update(data);
	// Выводим итог снятия хеша
	return hasher.finish(result, size);
}
