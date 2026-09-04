/**
 * @file gcm.cpp
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
 * @brief Режим шифрования с проверкой целостности GCM по NIST SP 800-38D
 *
 * @details Умножение в поле GF(2^128) с многочленом x^128 + x^7 + x^2 + x + 1 ведётся
 *          по таблице шестнадцати кратных ключа хеширования: значение разбирается по
 *          четыре разряда с конца, и каждый шаг - сдвиг на четыре разряда с
 *          приведением по таблице остатков и сложение с кратным. Разряды поля
 *          нумеруются от старшего, как велит стандарт, оттого сдвиг идёт вправо
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
#include <cipher/gcm.hpp>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/machine.hpp>

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
	#if defined(__ARM_FEATURE_AES)
		/**
		 * Атрибут цели не нужен
		 */
		#define __ANTS_GHASH_TARGET__
	/**
	 * Если собиратель clang
	 */
	#elif defined(__clang__)
		/**
		 * Разрешаем команды расширения одной функции
		 */
		#define __ANTS_GHASH_TARGET__ __attribute__((target("crypto")))
	/**
	 * Если собиратель GCC
	 */
	#else
		/**
		 * Разрешаем команды расширения одной функции
		 */
		#define __ANTS_GHASH_TARGET__ __attribute__((target("+crypto")))
	#endif

	/**
	 * Объявляем наличие ветви машинного умножения
	 */
	#define __ANTS_GHASH_ARM__ 1
/**
 * Если сборка ведётся под x86-64 собирателем семейства GCC
 */
#elif defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__)) && !defined(ANTS_NO_MACHINE)
	/**
	 * Подключаем заголовочные файлы команд x86-64
	 */
	#include <tmmintrin.h>
	#include <wmmintrin.h>

	/**
	 * Если расширения уже разрешены ключами сборки
	 */
	#if defined(__PCLMUL__) && defined(__SSSE3__)
		/**
		 * Атрибут цели не нужен
		 */
		#define __ANTS_GHASH_TARGET__
	#else
		/**
		 * Разрешаем команды расширений одной функции
		 */
		#define __ANTS_GHASH_TARGET__ __attribute__((target("pclmul,ssse3,sse2")))
	#endif

	/**
	 * Объявляем наличие ветви машинного умножения
	 */
	#define __ANTS_GHASH_X86__ 1
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
	using namespace nts::cipher;

	/**
	 * @brief Метод затирания области памяти
	 *
	 * @param data затираемая область памяти
	 * @param size размер затираемой области памяти
	 *
	 */
	static void wipe(void * data, const size_t size) noexcept {
		// Получаем изменчивый указатель на затираемую область памяти
		volatile uint8_t * item = static_cast <volatile uint8_t *> (data);
		/**
		 * Выполняем перебор байтов затираемой области памяти
		 */
		for(size_t i = 0; i < size; i++)
			// Обнуляем очередной байт области памяти
			item[i] = 0;
	}

/**
 * Если машина умножает без переносов командой PCLMULQDQ
 */
#if defined(__ANTS_GHASH_X86__)
	/**
	 * @brief Метод отражения разрядов внутри каждого байта
	 *
	 * @details Команды отражения у x86-64 нет: полубайты отражаются двумя таблицами
	 *          перестановки и меняются местами
	 *
	 * @param value отражаемые байты
	 *
	 * @return      байты с отражёнными разрядами
	 *
	 */
	static __ANTS_GHASH_TARGET__ __ANTS_INLINE__ __m128i reflect(const __m128i value) noexcept {
		// Таблица отражения полубайта
		const __m128i table = _mm_setr_epi8(0x00, 0x08, 0x04, 0x0C, 0x02, 0x0A, 0x06, 0x0E, 0x01, 0x09, 0x05, 0x0D, 0x03, 0x0B, 0x07, 0x0F);
		// Маска младшего полубайта
		const __m128i mask = _mm_set1_epi8(0x0F);
		// Отражённые младшие полубайты, идущие в старшие
		const __m128i low = _mm_shuffle_epi8(table, _mm_and_si128(value, mask));
		// Отражённые старшие полубайты, идущие в младшие
		const __m128i high = _mm_shuffle_epi8(table, _mm_and_si128(_mm_srli_epi16(value, 4), mask));
		// Выводим байты с отражёнными разрядами
		return _mm_or_si128(_mm_slli_epi16(low, 4), high);
	}
#endif

	/**
	 * @brief Остатки приведения при сдвиге на четыре разряда
	 *
	 * @details Старшие шестнадцать разрядов произведения младшего полубайта на
	 *          многочлен приведения: сдвиг вправо на четыре разряда выталкивает
	 *          полубайт, и он возвращается в старшее слово умноженным на x^128 mod P
	 *
	 */
	static constexpr uint16_t REMAINDERS[16] = {
		0x0000, 0x1C20, 0x3840, 0x2460, 0x7080, 0x6CA0, 0x48C0, 0x54E0,
		0xE100, 0xFD20, 0xD940, 0xC560, 0x9180, 0x8DA0, 0xA9C0, 0xB5E0
	};

	/**
	 * @brief Метод чтения слова в 64 разряда от старшего байта
	 *
	 * @param data читаемые байты
	 *
	 * @return     прочитанное слово
	 *
	 */
	static __ANTS_INLINE__ uint64_t load(const uint8_t * data) noexcept {
		// Накопленное слово
		uint64_t result = 0;
		/**
		 * Выполняем перебор байтов слова
		 */
		for(size_t i = 0; i < 8; i++)
			// Добавляем очередной байт
			result = ((result << 8) | static_cast <uint64_t> (data[i]));
		// Выводим слово
		return result;
	}

	/**
	 * @brief Метод записи слова в 64 разряда от старшего байта
	 *
	 * @param value записываемое слово
	 * @param data  место, в которое записываются байты
	 *
	 */
	static __ANTS_INLINE__ void store(const uint64_t value, uint8_t * data) noexcept {
		/**
		 * Выполняем перебор байтов слова
		 */
		for(size_t i = 0; i < 8; i++)
			// Записываем очередной байт от старшего
			data[i] = static_cast <uint8_t> (value >> (56 - (i * 8)));
	}

	/**
	 * @brief Метод сличения двух областей байтов за постоянное время
	 *
	 * @param first  первая область
	 * @param second вторая область
	 * @param size   размер областей
	 *
	 * @return       признак совпадения областей
	 *
	 */
	static bool same(const uint8_t * first, const uint8_t * second, const size_t size) noexcept {
		// Накопленное различие
		uint8_t difference = 0;
		/**
		 * Выполняем перебор байтов областей
		 */
		for(size_t i = 0; i < size; i++)
			// Накапливаем различие байтов
			difference = static_cast <uint8_t> (difference | (first[i] ^ second[i]));
		// Выводим признак отсутствия различий
		return (difference == 0);
	}

/**
 * Если есть ветвь машинного умножения PMULL
 */
#if defined(__ANTS_GHASH_ARM__)
	/**
	 * @brief Метод записи ключа хеширования с отражёнными разрядами байтов
	 *
	 * @param key    ключ хеширования
	 * @param mirror место, в которое записывается отражённый ключ
	 *
	 */
	static __ANTS_GHASH_TARGET__ void mirrorArm(const uint8_t * key, uint64_t * mirror) noexcept {
		// Записываем ключ хеширования с отражёнными разрядами байтов
		vst1q_u64(mirror, vreinterpretq_u64_u8(vrbitq_u8(vld1q_u8(key))));
	}
	/**
	 * @brief Метод умножения значения на ключ хеширования командой PMULL
	 *
	 * @param mirror ключ хеширования с отражёнными разрядами байтов
	 * @param value  умножаемое значение, заменяемое произведением
	 *
	 */
	static __ANTS_GHASH_TARGET__ void multiplyArm(const uint64_t * mirror, uint8_t * value) noexcept {
		/**
		 * Разряды поля у GCM нумеруются от старшего внутри байта, а команда множит
		 * многочлены с нумерацией от младшего: разряды каждого байта обоих множителей
		 * отражаются, байты остаются на местах, и слово становится многочленом в
		 * обычной записи. Произведение приводится по многочлену x^128 + x^7 + x^2 + x + 1
		 * и отражается обратно. Ключ хеширования хранится уже отражённым в кратном
		 * восьми таблицы
		 */
		const uint64x2_t a = vreinterpretq_u64_u8(vrbitq_u8(vld1q_u8(value)));
		// Отражённый ключ хеширования
		const uint64x2_t b = vld1q_u64(mirror);
		// Многочлен приведения x^7 + x^2 + x + 1
		const poly64_t r = static_cast <poly64_t> (0x87ULL);
		// Произведение младших половин
		const uint64x2_t p0 = vreinterpretq_u64_p128(vmull_p64(static_cast <poly64_t> (vgetq_lane_u64(a, 0)), static_cast <poly64_t> (vgetq_lane_u64(b, 0))));
		// Произведение старших половин
		const uint64x2_t p2 = vreinterpretq_u64_p128(vmull_p64(static_cast <poly64_t> (vgetq_lane_u64(a, 1)), static_cast <poly64_t> (vgetq_lane_u64(b, 1))));
		// Перекрёстные произведения
		const uint64x2_t p1 = veorq_u64(
			vreinterpretq_u64_p128(vmull_p64(static_cast <poly64_t> (vgetq_lane_u64(a, 0)), static_cast <poly64_t> (vgetq_lane_u64(b, 1)))),
			vreinterpretq_u64_p128(vmull_p64(static_cast <poly64_t> (vgetq_lane_u64(a, 1)), static_cast <poly64_t> (vgetq_lane_u64(b, 0)))));
		// Младшие 128 разрядов произведения: p0 с младшей половиной p1, сдвинутой на 64
		uint64x2_t low = veorq_u64(p0, vextq_u64(vdupq_n_u64(0), p1, 1));
		// Старшие 128 разрядов произведения: p2 со старшей половиной p1
		const uint64x2_t high = veorq_u64(p2, vextq_u64(p1, vdupq_n_u64(0), 1));
		// Приведение старшей половины: младшее слово, умноженное на многочлен
		const uint64x2_t f0 = vreinterpretq_u64_p128(vmull_p64(static_cast <poly64_t> (vgetq_lane_u64(high, 0)), r));
		// Приведение старшей половины: старшее слово, умноженное на многочлен
		const uint64x2_t f1 = vreinterpretq_u64_p128(vmull_p64(static_cast <poly64_t> (vgetq_lane_u64(high, 1)), r));
		// Складываем приведение младшего слова
		low = veorq_u64(low, f0);
		// Складываем младшую половину приведения старшего слова, сдвинутую на 64
		low = veorq_u64(low, vextq_u64(vdupq_n_u64(0), f1, 1));
		// Остаток приведения старшего слова, ушедший за 128 разрядов, приводится ещё раз
		low = veorq_u64(low, vreinterpretq_u64_p128(vmull_p64(static_cast <poly64_t> (vgetq_lane_u64(f1, 1)), r)));
		// Записываем произведение, отразив разряды байтов обратно в порядок GCM
		vst1q_u8(value, vrbitq_u8(vreinterpretq_u8_u64(low)));
	}
	/**
	 * @brief Метод неприведённого умножения двух отражённых многочленов
	 *
	 * @param a    первый множитель
	 * @param b    второй множитель
	 * @param low  младшие 128 разрядов произведения, складываемые с накопленными
	 * @param high старшие 128 разрядов произведения, складываемые с накопленными
	 *
	 */
	static __ANTS_GHASH_TARGET__ __ANTS_INLINE__ void productArm(const uint64x2_t a, const uint64x2_t b, uint64x2_t & low, uint64x2_t & high) noexcept {
		// Произведение младших половин
		const uint64x2_t p0 = vreinterpretq_u64_p128(vmull_p64(static_cast <poly64_t> (vgetq_lane_u64(a, 0)), static_cast <poly64_t> (vgetq_lane_u64(b, 0))));
		// Произведение старших половин
		const uint64x2_t p2 = vreinterpretq_u64_p128(vmull_p64(static_cast <poly64_t> (vgetq_lane_u64(a, 1)), static_cast <poly64_t> (vgetq_lane_u64(b, 1))));
		// Перекрёстные произведения
		const uint64x2_t p1 = veorq_u64(
			vreinterpretq_u64_p128(vmull_p64(static_cast <poly64_t> (vgetq_lane_u64(a, 0)), static_cast <poly64_t> (vgetq_lane_u64(b, 1)))),
			vreinterpretq_u64_p128(vmull_p64(static_cast <poly64_t> (vgetq_lane_u64(a, 1)), static_cast <poly64_t> (vgetq_lane_u64(b, 0)))));
		// Складываем младшие 128 разрядов
		low = veorq_u64(low, veorq_u64(p0, vextq_u64(vdupq_n_u64(0), p1, 1)));
		// Складываем старшие 128 разрядов
		high = veorq_u64(high, veorq_u64(p2, vextq_u64(p1, vdupq_n_u64(0), 1)));
	}
	/**
	 * @brief Метод сложения четырёх блоков в накопитель одним приведением командой PMULL
	 *
	 * @param powers      степени ключа хеширования от четвёртой до первой, отражённые
	 * @param accumulator накопитель многочлена, заменяемый итогом
	 * @param blocks      четыре блока подряд
	 *
	 */
	static __ANTS_GHASH_TARGET__ void aggregateArm(const uint64_t (* powers)[2], uint8_t * accumulator, const uint8_t * blocks) noexcept {
		// Многочлен приведения x^7 + x^2 + x + 1
		const poly64_t r = static_cast <poly64_t> (0x87ULL);
		// Накопитель, сложенный с первым блоком, отражённый
		const uint64x2_t z = vreinterpretq_u64_u8(vrbitq_u8(veorq_u8(vld1q_u8(accumulator), vld1q_u8(blocks))));
		// Младшие и старшие 128 разрядов суммы произведений
		uint64x2_t low = vdupq_n_u64(0), high = vdupq_n_u64(0);
		// Складываем произведение суммы с четвёртой степенью
		productArm(z, vld1q_u64(powers[0]), low, high);
		// Складываем произведение второго блока с третьей степенью
		productArm(vreinterpretq_u64_u8(vrbitq_u8(vld1q_u8(blocks + 16))), vld1q_u64(powers[1]), low, high);
		// Складываем произведение третьего блока со второй степенью
		productArm(vreinterpretq_u64_u8(vrbitq_u8(vld1q_u8(blocks + 32))), vld1q_u64(powers[2]), low, high);
		// Складываем произведение четвёртого блока с первой степенью
		productArm(vreinterpretq_u64_u8(vrbitq_u8(vld1q_u8(blocks + 48))), vld1q_u64(powers[3]), low, high);
		// Приведение старшей половины: младшее слово, умноженное на многочлен
		const uint64x2_t f0 = vreinterpretq_u64_p128(vmull_p64(static_cast <poly64_t> (vgetq_lane_u64(high, 0)), r));
		// Приведение старшей половины: старшее слово, умноженное на многочлен
		const uint64x2_t f1 = vreinterpretq_u64_p128(vmull_p64(static_cast <poly64_t> (vgetq_lane_u64(high, 1)), r));
		// Складываем приведение младшего слова
		low = veorq_u64(low, f0);
		// Складываем младшую половину приведения старшего слова, сдвинутую на 64
		low = veorq_u64(low, vextq_u64(vdupq_n_u64(0), f1, 1));
		// Остаток приведения старшего слова, ушедший за 128 разрядов, приводится ещё раз
		low = veorq_u64(low, vreinterpretq_u64_p128(vmull_p64(static_cast <poly64_t> (vgetq_lane_u64(f1, 1)), r)));
		// Записываем итог, отразив разряды байтов обратно
		vst1q_u8(accumulator, vrbitq_u8(vreinterpretq_u8_u64(low)));
	}
/**
 * Если есть ветвь машинного умножения PCLMULQDQ
 */
#elif defined(__ANTS_GHASH_X86__)
	/**
	 * @brief Метод записи ключа хеширования с отражёнными разрядами байтов
	 *
	 * @param key    ключ хеширования
	 * @param mirror место, в которое записывается отражённый ключ
	 *
	 */
	static __ANTS_GHASH_TARGET__ void mirrorX86(const uint8_t * key, uint64_t * mirror) noexcept {
		// Записываем ключ хеширования с отражёнными разрядами байтов
		_mm_storeu_si128(reinterpret_cast <__m128i *> (mirror), reflect(_mm_loadu_si128(reinterpret_cast <const __m128i *> (key))));
	}
	/**
	 * @brief Метод умножения значения на ключ хеширования командой PCLMULQDQ
	 *
	 * @param mirror ключ хеширования с отражёнными разрядами байтов
	 * @param value  умножаемое значение, заменяемое произведением
	 *
	 */
	static __ANTS_GHASH_TARGET__ void multiplyX86(const uint64_t * mirror, uint8_t * value) noexcept {
		// Значение с отражёнными разрядами байтов
		const __m128i a = reflect(_mm_loadu_si128(reinterpret_cast <const __m128i *> (value)));
		// Ключ хеширования, хранимый отражённым
		const __m128i b = _mm_loadu_si128(reinterpret_cast <const __m128i *> (mirror));
		// Многочлен приведения x^7 + x^2 + x + 1
		const __m128i r = _mm_set_epi64x(0, 0x87);
		// Произведение младших половин
		const __m128i p0 = _mm_clmulepi64_si128(a, b, 0x00);
		// Произведение старших половин
		const __m128i p2 = _mm_clmulepi64_si128(a, b, 0x11);
		// Перекрёстные произведения
		const __m128i p1 = _mm_xor_si128(_mm_clmulepi64_si128(a, b, 0x10), _mm_clmulepi64_si128(a, b, 0x01));
		// Младшие 128 разрядов произведения
		__m128i low = _mm_xor_si128(p0, _mm_slli_si128(p1, 8));
		// Старшие 128 разрядов произведения
		const __m128i high = _mm_xor_si128(p2, _mm_srli_si128(p1, 8));
		// Приведение младшего слова старшей половины
		const __m128i f0 = _mm_clmulepi64_si128(high, r, 0x00);
		// Приведение старшего слова старшей половины
		const __m128i f1 = _mm_clmulepi64_si128(high, r, 0x01);
		// Складываем приведение младшего слова
		low = _mm_xor_si128(low, f0);
		// Складываем младшую половину приведения старшего слова, сдвинутую на 64
		low = _mm_xor_si128(low, _mm_slli_si128(f1, 8));
		// Остаток приведения старшего слова, ушедший за 128 разрядов, приводится ещё раз
		low = _mm_xor_si128(low, _mm_clmulepi64_si128(_mm_srli_si128(f1, 8), r, 0x00));
		// Записываем произведение, отразив разряды байтов обратно
		_mm_storeu_si128(reinterpret_cast <__m128i *> (value), reflect(low));
	}
	/**
	 * @brief Метод неприведённого умножения двух отражённых многочленов
	 *
	 * @param a    первый множитель
	 * @param b    второй множитель
	 * @param low  младшие 128 разрядов произведения, складываемые с накопленными
	 * @param high старшие 128 разрядов произведения, складываемые с накопленными
	 *
	 */
	static __ANTS_GHASH_TARGET__ __ANTS_INLINE__ void productX86(const __m128i a, const __m128i b, __m128i & low, __m128i & high) noexcept {
		// Произведение младших половин
		const __m128i p0 = _mm_clmulepi64_si128(a, b, 0x00);
		// Произведение старших половин
		const __m128i p2 = _mm_clmulepi64_si128(a, b, 0x11);
		// Перекрёстные произведения
		const __m128i p1 = _mm_xor_si128(_mm_clmulepi64_si128(a, b, 0x10), _mm_clmulepi64_si128(a, b, 0x01));
		// Складываем младшие 128 разрядов
		low = _mm_xor_si128(low, _mm_xor_si128(p0, _mm_slli_si128(p1, 8)));
		// Складываем старшие 128 разрядов
		high = _mm_xor_si128(high, _mm_xor_si128(p2, _mm_srli_si128(p1, 8)));
	}
	/**
	 * @brief Метод сложения четырёх блоков в накопитель одним приведением командой PCLMULQDQ
	 *
	 * @param powers      степени ключа хеширования от четвёртой до первой, отражённые
	 * @param accumulator накопитель многочлена, заменяемый итогом
	 * @param blocks      четыре блока подряд
	 *
	 */
	static __ANTS_GHASH_TARGET__ void aggregateX86(const uint64_t (* powers)[2], uint8_t * accumulator, const uint8_t * blocks) noexcept {
		// Многочлен приведения x^7 + x^2 + x + 1
		const __m128i r = _mm_set_epi64x(0, 0x87);
		// Накопитель, сложенный с первым блоком, отражённый
		const __m128i z = reflect(_mm_xor_si128(_mm_loadu_si128(reinterpret_cast <const __m128i *> (accumulator)), _mm_loadu_si128(reinterpret_cast <const __m128i *> (blocks))));
		// Младшие и старшие 128 разрядов суммы произведений
		__m128i low = _mm_setzero_si128(), high = _mm_setzero_si128();
		// Складываем произведение суммы с четвёртой степенью
		productX86(z, _mm_loadu_si128(reinterpret_cast <const __m128i *> (powers[0])), low, high);
		// Складываем произведение второго блока с третьей степенью
		productX86(reflect(_mm_loadu_si128(reinterpret_cast <const __m128i *> (blocks + 16))), _mm_loadu_si128(reinterpret_cast <const __m128i *> (powers[1])), low, high);
		// Складываем произведение третьего блока со второй степенью
		productX86(reflect(_mm_loadu_si128(reinterpret_cast <const __m128i *> (blocks + 32))), _mm_loadu_si128(reinterpret_cast <const __m128i *> (powers[2])), low, high);
		// Складываем произведение четвёртого блока с первой степенью
		productX86(reflect(_mm_loadu_si128(reinterpret_cast <const __m128i *> (blocks + 48))), _mm_loadu_si128(reinterpret_cast <const __m128i *> (powers[3])), low, high);
		// Приведение младшего слова старшей половины
		const __m128i f0 = _mm_clmulepi64_si128(high, r, 0x00);
		// Приведение старшего слова старшей половины
		const __m128i f1 = _mm_clmulepi64_si128(high, r, 0x01);
		// Складываем приведение младшего слова
		low = _mm_xor_si128(low, f0);
		// Складываем младшую половину приведения старшего слова, сдвинутую на 64
		low = _mm_xor_si128(low, _mm_slli_si128(f1, 8));
		// Остаток приведения старшего слова, ушедший за 128 разрядов, приводится ещё раз
		low = _mm_xor_si128(low, _mm_clmulepi64_si128(_mm_srli_si128(f1, 8), r, 0x00));
		// Записываем итог, отразив разряды байтов обратно
		_mm_storeu_si128(reinterpret_cast <__m128i *> (accumulator), reflect(low));
	}
#endif
};

/**
 * @brief Метод умножения значения на ключ хеширования в поле GF(2^128)
 *
 * @param value умножаемое значение, заменяемое произведением
 *
 */
void nts::cipher::Gcm::multiply(uint8_t * value) const noexcept {
/**
 * Если есть ветвь машинного умножения PMULL
 */
#if defined(__ANTS_GHASH_ARM__)
	// Если машина умножает без переносов командой
	if(machine::has(machine::feature_t::CARRYLESS)){
		// Выполняем умножение командой
		multiplyArm(this->_mirror, value);
		// Выходим из метода
		return;
	}
/**
 * Если есть ветвь машинного умножения PCLMULQDQ
 */
#elif defined(__ANTS_GHASH_X86__)
	// Если машина умножает без переносов командой
	if(machine::has(machine::feature_t::CARRYLESS)){
		// Выполняем умножение командой
		multiplyX86(this->_mirror, value);
		// Выходим из метода
		return;
	}
#endif
	// Полубайты последнего байта значения
	uint8_t low = value[15], high = static_cast <uint8_t> (low >> 4);
	// Младший полубайт последнего байта
	low = static_cast <uint8_t> (low & 0x0F);
	// Произведение: старшее и младшее слова
	uint64_t zh = this->_table[low][0], zl = this->_table[low][1];
	// Номер разбираемого байта
	size_t index = 15;
	/**
	 * Выполняем разбор значения по полубайтам от конца
	 */
	while(true){
		// Выталкиваемый полубайт
		uint8_t rem = static_cast <uint8_t> (zl & 0x0F);
		// Сдвигаем младшее слово с переносом из старшего
		zl = ((zh << 60) | (zl >> 4));
		// Сдвигаем старшее слово
		zh >>= 4;
		// Возвращаем вытолкнутый полубайт приведением
		zh ^= (static_cast <uint64_t> (REMAINDERS[rem]) << 48);
		// Складываем с кратным по старшему полубайту
		zh ^= this->_table[high][0];
		// Складываем с кратным по старшему полубайту
		zl ^= this->_table[high][1];
		// Если байты кончились
		if(index == 0)
			// Прерываем разбор
			break;
		// Переходим к предыдущему байту
		index--;
		// Старший полубайт очередного байта
		high = static_cast <uint8_t> (value[index] >> 4);
		// Младший полубайт очередного байта
		low = static_cast <uint8_t> (value[index] & 0x0F);
		// Выталкиваемый полубайт
		rem = static_cast <uint8_t> (zl & 0x0F);
		// Сдвигаем младшее слово с переносом из старшего
		zl = ((zh << 60) | (zl >> 4));
		// Сдвигаем старшее слово
		zh >>= 4;
		// Возвращаем вытолкнутый полубайт приведением
		zh ^= (static_cast <uint64_t> (REMAINDERS[rem]) << 48);
		// Складываем с кратным по младшему полубайту
		zh ^= this->_table[low][0];
		// Складываем с кратным по младшему полубайту
		zl ^= this->_table[low][1];
	}
	// Записываем старшее слово произведения
	store(zh, value);
	// Записываем младшее слово произведения
	store(zl, value + 8);
}
/**
 * @brief Метод сложения четырёх блоков в накопитель многочлена одним приведением
 *
 * @param accumulator накопитель многочлена, заменяемый итогом
 * @param blocks      четыре блока подряд
 *
 * @return            признак того, что машина умножает командами и блоки сложены
 *
 */
bool nts::cipher::Gcm::aggregate(uint8_t * accumulator, const uint8_t * blocks) const noexcept {
/**
 * Если есть ветвь машинного умножения PMULL
 */
#if defined(__ANTS_GHASH_ARM__)
	// Если машина умножает без переносов командой
	if(machine::has(machine::feature_t::CARRYLESS)){
		// Выполняем сложение четырёх блоков командой
		aggregateArm(this->_powers, accumulator, blocks);
		// Выводим признак сложения
		return true;
	}
/**
 * Если есть ветвь машинного умножения PCLMULQDQ
 */
#elif defined(__ANTS_GHASH_X86__)
	// Если машина умножает без переносов командой
	if(machine::has(machine::feature_t::CARRYLESS)){
		// Выполняем сложение четырёх блоков командой
		aggregateX86(this->_powers, accumulator, blocks);
		// Выводим признак сложения
		return true;
	}
#endif
	// Довод накопителя без ветви команд не используется
	(void) accumulator;
	// Довод блоков без ветви команд не используется
	(void) blocks;
	// Выводим отсутствие ветви команд
	return false;
}
/**
 * @brief Метод сложения байтов в накопитель многочлена GHASH
 *
 * @param data складываемые байты
 * @param size число складываемых байтов
 *
 */
void nts::cipher::Gcm::absorb(const uint8_t * data, const size_t size) noexcept {
	// Число ещё не сложенных байтов
	size_t left = size;
	// Позиция чтения
	const uint8_t * cursor = data;
	// Если неполный блок уже копится
	if(this->_filled > 0){
		// Число байтов, дополняющих неполный блок
		const size_t taken = (((16 - this->_filled) < left) ? (16 - this->_filled) : left);
		// Переносим байты в неполный блок
		::memcpy(this->_pending + this->_filled, cursor, taken);
		// Увеличиваем число накопленных байтов
		this->_filled += taken;
		// Сдвигаем позицию чтения
		cursor += taken;
		// Уменьшаем число не сложенных байтов
		left -= taken;
		// Если блок так и остался неполным
		if(this->_filled < 16)
			// Выходим из метода
			return;
		/**
		 * Выполняем сложение собранного блока с накопителем
		 */
		for(size_t i = 0; i < 16; i++)
			// Складываем очередной байт
			this->_accumulator[i] ^= this->_pending[i];
		// Умножаем накопитель на ключ хеширования
		this->multiply(this->_accumulator);
		// Сбрасываем число накопленных байтов
		this->_filled = 0;
	}
	/**
	 * Выполняем сложение по четыре целых блока одним приведением, пока машина умножает командами
	 */
	while((left >= 64) && this->aggregate(this->_accumulator, cursor)){
		// Сдвигаем позицию чтения
		cursor += 64;
		// Уменьшаем число не сложенных байтов
		left -= 64;
	}
	/**
	 * Выполняем сложение целых блоков с накопителем
	 */
	while(left >= 16){
		/**
		 * Выполняем сложение блока с накопителем
		 */
		for(size_t i = 0; i < 16; i++)
			// Складываем очередной байт
			this->_accumulator[i] ^= cursor[i];
		// Умножаем накопитель на ключ хеширования
		this->multiply(this->_accumulator);
		// Сдвигаем позицию чтения
		cursor += 16;
		// Уменьшаем число не сложенных байтов
		left -= 16;
	}
	// Если остался хвост короче блока
	if(left > 0){
		// Переносим хвост в неполный блок
		::memcpy(this->_pending, cursor, left);
		// Запоминаем число накопленных байтов
		this->_filled = left;
	}
}
/**
 * @brief Метод наложения гаммы счётчика с продолжением от остатка блока
 *
 * @param source накладываемые данные
 * @param result место, в которое записывается итог наложения
 *
 * @return       признак успешности наложения
 *
 */
bool nts::cipher::Gcm::cover(const view_t & source, uint8_t * result) noexcept {
	// Число ещё не покрытых байтов
	size_t left = source.size;
	// Позиция чтения данных
	const uint8_t * cursor = source.data;
	// Позиция записи итога
	uint8_t * output = result;
	// Если остаток блока гаммы не израсходован
	if(this->_rest > 0){
		// Число байтов, покрываемых остатком
		const size_t taken = ((this->_rest < left) ? this->_rest : left);
		// Позиция остатка внутри блока гаммы
		const size_t index = (16 - this->_rest);
		/**
		 * Выполняем наложение остатка гаммы
		 */
		for(size_t i = 0; i < taken; i++)
			// Складываем очередной байт с гаммой
			output[i] = static_cast <uint8_t> (cursor[i] ^ this->_gamma[index + i]);
		// Сдвигаем позицию чтения
		cursor += taken;
		// Сдвигаем позицию записи
		output += taken;
		// Уменьшаем число не покрытых байтов
		left -= taken;
		// Уменьшаем остаток блока гаммы
		this->_rest -= taken;
	}
	// Гамма на восемь блоков
	uint8_t gamma[128];
	/**
	 * Выполняем покрытие данных гаммой по восемь блоков
	 */
	while(left > 0){
		// Число блоков гаммы: до восьми
		const size_t count = (((left + 15) / 16) < 8) ? ((left + 15) / 16) : 8;
		// Если шифр умеет вырабатывать гамму по многу блоков
		if(this->_block.stream != nullptr){
			// Если гамму выработать не удалось
			if(!this->_block.stream(this->_block.cipher, this->_counter, count, gamma)){
				// Выполняем затирание гаммы
				wipe(gamma, sizeof(gamma));
				// Выводим отказ наложения
				return false;
			}
			/**
			 * Выполняем продвижение счётчика на выработанные блоки
			 */
			for(size_t b = 0; b < count; b++){
				/**
				 * Выполняем перенос по младшим четырём байтам
				 */
				for(size_t i = 16; i > 12; i--){
					// Если байт не переполнился
					if(++this->_counter[i - 1] != 0)
						// Прерываем перенос
						break;
				}
			}
		// Иначе гамма вырабатывается по одному блоку
		} else {
			/**
			 * Выполняем выработку блоков гаммы
			 */
			for(size_t b = 0; b < count; b++){
				/**
				 * Выполняем увеличение младших 32 разрядов счётчика от старшего байта
				 */
				for(size_t i = 16; i > 12; i--){
					// Если байт не переполнился
					if(++this->_counter[i - 1] != 0)
						// Прерываем перенос
						break;
				}
				// Если блок гаммы выработать не удалось
				if(!this->_block.encrypt(this->_block.cipher, this->_counter, gamma + (b * 16))){
					// Выполняем затирание гаммы
					wipe(gamma, sizeof(gamma));
					// Выводим отказ наложения
					return false;
				}
			}
		}
		// Число байтов, покрываемых выработанной гаммой
		const size_t taken = ((left < (count * 16)) ? left : (count * 16));
		/**
		 * Выполняем наложение гаммы
		 */
		for(size_t i = 0; i < taken; i++)
			// Складываем очередной байт с гаммой
			output[i] = static_cast <uint8_t> (cursor[i] ^ gamma[i]);
		// Если последний блок гаммы израсходован не целиком
		if(taken < (count * 16)){
			// Сохраняем последний блок гаммы остатком
			::memcpy(this->_gamma, gamma + ((count - 1) * 16), 16);
			// Запоминаем число неизрасходованных байтов остатка
			this->_rest = ((count * 16) - taken);
		}
		// Сдвигаем позицию чтения
		cursor += taken;
		// Сдвигаем позицию записи
		output += taken;
		// Уменьшаем число не покрытых байтов
		left -= taken;
	}
	// Выполняем затирание гаммы
	wipe(gamma, sizeof(gamma));
	// Выводим успешность наложения
	return true;
}
/**
 * @brief Метод завершения многочлена GHASH блоком длин
 *
 * @param result место в 16 байтов, в которое записывается значение многочлена
 *
 */
void nts::cipher::Gcm::digest(uint8_t * result) noexcept {
	// Если неполный блок копится
	if(this->_filled > 0){
		/**
		 * Выполняем сложение неполного блока с накопителем: дополнение нулями
		 */
		for(size_t i = 0; i < this->_filled; i++)
			// Складываем очередной байт
			this->_accumulator[i] ^= this->_pending[i];
		// Умножаем накопитель на ключ хеширования
		this->multiply(this->_accumulator);
		// Сбрасываем число накопленных байтов
		this->_filled = 0;
	}
	// Блок длин: разряды связанных данных и шифртекста
	uint8_t lengths[16];
	// Записываем длину связанных данных в разрядах
	store(this->_associated * 8, lengths);
	// Записываем длину шифртекста в разрядах
	store(this->_sealed * 8, lengths + 8);
	/**
	 * Выполняем сложение блока длин с накопителем
	 */
	for(size_t i = 0; i < 16; i++)
		// Складываем очередной байт
		this->_accumulator[i] ^= lengths[i];
	// Умножаем накопитель на ключ хеширования
	this->multiply(this->_accumulator);
	// Переносим значение многочлена в место итога
	::memcpy(result, this->_accumulator, 16);
}
/**
 * @brief Метод вычисления метки целостности по накопленному потоку
 *
 * @param result место в 16 байтов, в которое записывается метка
 *
 * @return       признак успешности вычисления
 *
 */
bool nts::cipher::Gcm::authenticate(uint8_t * result) noexcept {
	// Выполняем завершение многочлена блоком длин
	this->digest(result);
	// Зашифрованный начальный блок счётчика
	uint8_t mask[16];
	// Если начальный блок зашифровать не удалось
	if(!this->_block.encrypt(this->_block.cipher, this->_nonce, mask)){
		// Выполняем затирание маски
		wipe(mask, sizeof(mask));
		// Выводим отказ вычисления
		return false;
	}
	/**
	 * Выполняем сложение многочлена с зашифрованным начальным блоком
	 */
	for(size_t i = 0; i < 16; i++)
		// Складываем очередной байт
		result[i] ^= mask[i];
	// Выполняем затирание маски
	wipe(mask, sizeof(mask));
	// Выводим успешность вычисления
	return true;
}
/**
 * @brief Метод сброса состояния потока
 *
 */
void nts::cipher::Gcm::reset() noexcept {
	// Сбрасываем ступень потока
	this->_stage = 0;
	// Сбрасываем направление потока
	this->_direction = 0;
	// Сбрасываем остаток блока гаммы
	this->_rest = 0;
	// Сбрасываем число накопленных байтов неполного блока
	this->_filled = 0;
	// Сбрасываем длину связанных данных
	this->_associated = 0;
	// Сбрасываем длину шифртекста
	this->_sealed = 0;
	// Начальным значением счётчика служит начальный блок
	::memcpy(this->_counter, this->_nonce, sizeof(this->_counter));
	// Выполняем затирание остатка блока гаммы
	wipe(this->_gamma, sizeof(this->_gamma));
	// Выполняем затирание накопителя многочлена
	wipe(this->_accumulator, sizeof(this->_accumulator));
	// Выполняем затирание неполного блока многочлена
	wipe(this->_pending, sizeof(this->_pending));
}
/**
 * @brief Метод перехода потока к данным
 *
 * @param direction направление потока: единица - зашифрование, двойка - расшифрование
 *
 * @return          признак допустимости перехода
 *
 */
bool nts::cipher::Gcm::proceed(const uint8_t direction) noexcept {
	/**
	 * Выполняем разбор ступени потока
	 */
	switch(this->_stage){
		// Если поток на связанных данных либо ещё не начат
		case 0:
		case 1: {
			// Если направление - зашифрование, а заполнение израсходовано
			if((direction == 1) && this->_spent)
				// Выводим недопустимость перехода
				return false;
			// Если направление - зашифрование
			if(direction == 1)
				// Запоминаем, что заполнение израсходовано
				this->_spent = true;
			// Если неполный блок связанных данных копится
			if(this->_filled > 0){
				/**
				 * Выполняем сложение неполного блока с накопителем: дополнение нулями
				 */
				for(size_t i = 0; i < this->_filled; i++)
					// Складываем очередной байт
					this->_accumulator[i] ^= this->_pending[i];
				// Умножаем накопитель на ключ хеширования
				this->multiply(this->_accumulator);
				// Сбрасываем число накопленных байтов
				this->_filled = 0;
			}
			// Запоминаем направление потока
			this->_direction = direction;
			// Переводим поток на данные
			this->_stage = 2;
			// Выводим допустимость перехода
			return true;
		}
		// Если поток на данных
		case 2:
			// Выводим допустимость лишь того же направления
			return (this->_direction == direction);
	}
	// Поток закрыт: перехода нет
	return false;
}
/**
 * @brief Метод проверки готовности режима к работе
 *
 * @return признак готовности режима
 *
 */
bool nts::cipher::Gcm::ready() const noexcept {
	// Выводим признак готовности режима
	return this->_ready;
}
/**
 * @brief Метод получения длины метки целостности
 *
 * @return длина метки в байтах
 *
 */
size_t nts::cipher::Gcm::size() const noexcept {
	// Выводим длину метки целостности
	return this->_size;
}
/**
 * @brief Метод запуска режима
 *
 * @param block блочный шифр с блоком в 16 байтов и установленным ключом
 * @param nonce начальное заполнение любой ненулевой длины, 12 байтов - прямой путь
 * @param size  длина метки целостности от 4 до 16 байтов, ноль - 16
 *
 * @return      признак успешности запуска
 *
 */
bool nts::cipher::Gcm::start(const block_t & block, const view_t & nonce, const size_t size) noexcept {
	// Выполняем сброс прежнего состояния
	this->clear();
	// Длина метки: ноль означает полную
	const size_t length = ((size == 0) ? GCM_TAG : size);
	// Если шифр не с блоком в 16 байтов, заполнение не передано либо длина метки негодна
	if((block.size != 16) || (block.cipher == nullptr) || (block.encrypt == nullptr) || (nonce.data == nullptr) || (nonce.size == 0) || (length < 4) || (length > 16))
		// Выводим отказ запуска
		return false;
	// Запоминаем базовый шифр
	this->_block = block;
	// Запоминаем длину метки
	this->_size = length;
	// Нулевой блок для выработки ключа хеширования
	uint8_t zeros[16];
	// Выполняем обнуление блока
	::memset(zeros, 0, sizeof(zeros));
	// Ключ хеширования: зашифрованный нулевой блок
	uint8_t key[16];
	// Если ключ хеширования выработать не удалось
	if(!block.encrypt(block.cipher, zeros, key)){
		// Выполняем сброс состояния
		this->clear();
		// Выводим отказ запуска
		return false;
	}
/**
 * Если есть ветвь машинного умножения PMULL
 */
#if defined(__ANTS_GHASH_ARM__)
	// Записываем ключ хеширования с отражёнными разрядами байтов: умножение командой берёт его
	mirrorArm(key, this->_mirror);
/**
 * Если есть ветвь машинного умножения PCLMULQDQ
 */
#elif defined(__ANTS_GHASH_X86__)
	// Если машина умножает без переносов командой: отражение само идёт командами
	if(machine::has(machine::feature_t::CARRYLESS))
		// Записываем ключ хеширования с отражёнными разрядами байтов
		mirrorX86(key, this->_mirror);
#endif
	// Старшее и младшее слова ключа хеширования
	uint64_t high = load(key), low = load(key + 8);
	// Выполняем затирание ключа хеширования
	wipe(key, sizeof(key));
	// Кратное нулю
	this->_table[0][0] = 0;
	// Кратное нулю
	this->_table[0][1] = 0;
	// Кратное восьми: сам ключ
	this->_table[8][0] = high;
	// Кратное восьми: сам ключ
	this->_table[8][1] = low;
	/**
	 * Выполняем построение кратных четырём, двум и единице делением на x
	 */
	for(size_t i = 4; i > 0; i >>= 1){
		// Вытолкнутый разряд
		const uint64_t carry = (low & 0x01);
		// Сдвигаем младшее слово с переносом из старшего
		low = ((high << 63) | (low >> 1));
		// Сдвигаем старшее слово с приведением по многочлену
		high = ((high >> 1) ^ (carry ? 0xE100000000000000ULL : 0ULL));
		// Записываем кратное
		this->_table[i][0] = high;
		// Записываем кратное
		this->_table[i][1] = low;
	}
	/**
	 * Выполняем построение остальных кратных сложением степеней
	 */
	for(size_t i = 2; i < 16; i <<= 1){
		/**
		 * Выполняем перебор уже построенных кратных
		 */
		for(size_t j = 1; j < i; j++){
			// Складываем кратное
			this->_table[i + j][0] = (this->_table[i][0] ^ this->_table[j][0]);
			// Складываем кратное
			this->_table[i + j][1] = (this->_table[i][1] ^ this->_table[j][1]);
		}
	}
/**
 * Если есть ветвь машинного умножения
 */
#if defined(__ANTS_GHASH_ARM__) || defined(__ANTS_GHASH_X86__)
	// Если машина умножает без переносов командой
	if(machine::has(machine::feature_t::CARRYLESS)){
		// Степень ключа хеширования в порядке GCM: сначала первая
		uint8_t power[16];
		// Восстанавливаем ключ хеширования из кратного восьми таблицы
		store(this->_table[8][0], power);
		// Восстанавливаем ключ хеширования из кратного восьми таблицы
		store(this->_table[8][1], power + 8);
		/**
		 * Выполняем построение степеней от первой до четвёртой
		 */
		for(size_t i = 0; i < 4; i++){
			// Если степень не первая
			if(i > 0)
				// Умножаем прежнюю степень на ключ
				this->multiply(power);
/**
 * Если есть ветвь машинного умножения PMULL
 */
#if defined(__ANTS_GHASH_ARM__)
			// Записываем степень отражённой: четвёртая идёт первой
			mirrorArm(power, this->_powers[3 - i]);
#else
			// Записываем степень отражённой: четвёртая идёт первой
			mirrorX86(power, this->_powers[3 - i]);
#endif
		}
		// Выполняем затирание степени
		wipe(power, sizeof(power));
	}
#endif
	// Если заполнение в 12 байтов
	if(nonce.size == 12){
		// Переносим заполнение в начальный блок счётчика
		::memcpy(this->_nonce, nonce.data, 12);
		// Записываем счётчик, равный единице
		this->_nonce[12] = 0x00;
		// Записываем счётчик, равный единице
		this->_nonce[13] = 0x00;
		// Записываем счётчик, равный единице
		this->_nonce[14] = 0x00;
		// Записываем счётчик, равный единице
		this->_nonce[15] = 0x01;
	// Иначе начальный блок вычисляется многочленом по заполнению
	} else {
		// Выполняем сброс состояния потока: накопитель обнулён
		this->reset();
		// Выполняем сложение заполнения в накопитель
		this->absorb(nonce.data, nonce.size);
		/**
		 * Блок длин у заполнения иной: нули и длина заполнения в разрядах, - оттого
		 * многочлен завершается тем же ходом, но с длиной заполнения на месте длины
		 * шифртекста и пустыми связанными данными
		 */
		this->_sealed = static_cast <uint64_t> (nonce.size);
		// Выполняем завершение многочлена в начальный блок счётчика
		this->digest(this->_nonce);
	}
	// Выполняем сброс состояния потока от начального блока
	this->reset();
	// Запоминаем готовность режима
	this->_ready = true;
	// Выводим успешность запуска
	return true;
}
/**
 * @brief Метод сброса режима
 *
 */
void nts::cipher::Gcm::clear() noexcept {
	// Сбрасываем признак готовности
	this->_ready = false;
	// Сбрасываем признак израсходованного заполнения
	this->_spent = false;
	// Сбрасываем длину метки
	this->_size = 0;
	// Сбрасываем базовый шифр
	this->_block = block_t();
	// Выполняем затирание начального блока счётчика
	wipe(this->_nonce, sizeof(this->_nonce));
	// Выполняем затирание таблицы кратных
	wipe(this->_table, sizeof(this->_table));
	// Выполняем затирание отражённого ключа хеширования
	wipe(this->_mirror, sizeof(this->_mirror));
	// Выполняем затирание степеней ключа хеширования
	wipe(this->_powers, sizeof(this->_powers));
	// Выполняем сброс состояния потока
	this->reset();
}
/**
 * @brief Метод подачи связанных данных потока
 *
 * @param associated связанные данные, защищаемые лишь меткой
 *
 * @return           признак успешности подачи
 *
 */
bool nts::cipher::Gcm::associate(const view_t & associated) noexcept {
	// Если режим не готов либо поток уже перешёл к данным
	if(!this->_ready || (this->_stage > 1))
		// Выводим отказ подачи
		return false;
	// Если связанные данные объявлены непустыми, но не переданы
	if((associated.size > 0) && (associated.data == nullptr))
		// Выводим отказ подачи
		return false;
	// Переводим поток на связанные данные
	this->_stage = 1;
	// Выполняем сложение связанных данных в накопитель
	this->absorb(associated.data, associated.size);
	// Увеличиваем длину связанных данных
	this->_associated += static_cast <uint64_t> (associated.size);
	// Выводим успешность подачи
	return true;
}
/**
 * @brief Метод поточного зашифрования куска
 *
 * @param source открытый текст
 * @param result место, в которое записывается шифртекст той же длины
 *
 * @return       признак успешности зашифрования
 *
 */
bool nts::cipher::Gcm::encrypt(const view_t & source, uint8_t * result) noexcept {
	// Если режим не готов
	if(!this->_ready)
		// Выводим отказ зашифрования
		return false;
	// Если текст объявлен непустым, но не передан
	if((source.size > 0) && ((source.data == nullptr) || (result == nullptr)))
		// Выводим отказ зашифрования
		return false;
	// Если переход потока к зашифрованию недопустим
	if(!this->proceed(1))
		// Выводим отказ зашифрования
		return false;
	// Если гамму наложить не удалось
	if(!this->cover(source, result)){
		// Закрываем поток
		this->_stage = 3;
		// Выводим отказ зашифрования
		return false;
	}
	// Выполняем сложение шифртекста в накопитель
	this->absorb(result, source.size);
	// Увеличиваем длину шифртекста
	this->_sealed += static_cast <uint64_t> (source.size);
	// Выводим успешность зашифрования
	return true;
}
/**
 * @brief Метод поточного расшифрования куска
 *
 * @param source шифртекст
 * @param result место, в которое записывается открытый текст той же длины
 *
 * @return       признак успешности расшифрования
 *
 */
bool nts::cipher::Gcm::decrypt(const view_t & source, uint8_t * result) noexcept {
	// Если режим не готов
	if(!this->_ready)
		// Выводим отказ расшифрования
		return false;
	// Если текст объявлен непустым, но не передан
	if((source.size > 0) && ((source.data == nullptr) || (result == nullptr)))
		// Выводим отказ расшифрования
		return false;
	// Если переход потока к расшифрованию недопустим
	if(!this->proceed(2))
		// Выводим отказ расшифрования
		return false;
	// Выполняем сложение шифртекста в накопитель
	this->absorb(source.data, source.size);
	// Увеличиваем длину шифртекста
	this->_sealed += static_cast <uint64_t> (source.size);
	// Если гамму снять не удалось
	if(!this->cover(source, result)){
		// Выполняем затирание неполного открытого текста
		wipe(result, source.size);
		// Закрываем поток
		this->_stage = 3;
		// Выводим отказ расшифрования
		return false;
	}
	// Выводим успешность расшифрования
	return true;
}
/**
 * @brief Метод завершения поточного зашифрования выработкой метки
 *
 * @param tag место, в которое записывается метка установленной длины
 *
 * @return    признак успешности завершения; поток закрывается
 *
 */
bool nts::cipher::Gcm::finish(uint8_t * tag) noexcept {
	// Если режим не готов либо места под метку нет
	if(!this->_ready || (tag == nullptr))
		// Выводим отказ завершения
		return false;
	// Если переход потока к зашифрованию недопустим: пустой текст тоже расходует заполнение
	if(!this->proceed(1))
		// Выводим отказ завершения
		return false;
	// Закрываем поток
	this->_stage = 3;
	// Полная метка
	uint8_t buffer[16];
	// Если метку вычислить не удалось
	if(!this->authenticate(buffer)){
		// Выполняем затирание метки
		wipe(buffer, sizeof(buffer));
		// Выводим отказ завершения
		return false;
	}
	// Переносим метку в установленную длину
	::memcpy(tag, buffer, this->_size);
	// Выполняем затирание полной метки
	wipe(buffer, sizeof(buffer));
	// Выводим успешность завершения
	return true;
}
/**
 * @brief Метод завершения поточного расшифрования сличением метки
 *
 * @param tag проверяемая метка установленной длины
 *
 * @return    признак схождения метки за постоянное время; поток закрывается
 *
 */
bool nts::cipher::Gcm::verify(const view_t & tag) noexcept {
	// Если режим не готов либо метка не установленной длины
	if(!this->_ready || (tag.data == nullptr) || (tag.size != this->_size))
		// Выводим отказ сличения
		return false;
	// Если переход потока к расшифрованию недопустим
	if(!this->proceed(2))
		// Выводим отказ сличения
		return false;
	// Закрываем поток
	this->_stage = 3;
	// Полная метка
	uint8_t buffer[16];
	// Если метку вычислить не удалось
	if(!this->authenticate(buffer)){
		// Выполняем затирание метки
		wipe(buffer, sizeof(buffer));
		// Выводим отказ сличения
		return false;
	}
	// Признак схождения метки за постоянное время
	const bool matched = same(buffer, tag.data, this->_size);
	// Выполняем затирание полной метки
	wipe(buffer, sizeof(buffer));
	// Выводим признак схождения метки
	return matched;
}
/**
 * @brief Метод зашифрования с выработкой метки целостности
 *
 * @param associated связанные данные, защищаемые лишь меткой
 * @param source     открытый текст
 * @param result     место, в которое записывается шифртекст той же длины
 * @param tag        место, в которое записывается метка установленной длины
 *
 * @return           признак успешности зашифрования
 *
 */
bool nts::cipher::Gcm::encrypt(const view_t & associated, const view_t & source, uint8_t * result, uint8_t * tag) noexcept {
	// Если режим не готов, либо места под метку нет, либо заполнение израсходовано
	if(!this->_ready || (tag == nullptr) || this->_spent)
		// Выводим отказ зашифрования
		return false;
	// Если текст объявлен непустым, но не передан
	if((source.size > 0) && ((source.data == nullptr) || (result == nullptr)))
		// Выводим отказ зашифрования
		return false;
	// Если связанные данные объявлены непустыми, но не переданы
	if((associated.size > 0) && (associated.data == nullptr))
		// Выводим отказ зашифрования
		return false;
	// Выполняем сброс состояния потока: разовый вызов не зависит от прежнего
	this->reset();
	// Если связанные данные подать не удалось
	if(!this->associate(associated))
		// Выводим отказ зашифрования
		return false;
	// Если текст зашифровать не удалось
	if(!this->encrypt(source, result))
		// Выводим отказ зашифрования
		return false;
	// Выводим итог выработки метки
	return this->finish(tag);
}
/**
 * @brief Метод расшифрования с проверкой метки целостности
 *
 * @param associated связанные данные
 * @param source     шифртекст
 * @param result     место, в которое записывается открытый текст той же длины
 * @param tag        проверяемая метка установленной длины
 *
 * @return           признак схождения метки; при расхождении открытый текст не тронут
 *
 */
bool nts::cipher::Gcm::decrypt(const view_t & associated, const view_t & source, uint8_t * result, const view_t & tag) noexcept {
	// Если режим не готов либо метка не установленной длины
	if(!this->_ready || (tag.data == nullptr) || (tag.size != this->_size))
		// Выводим отказ расшифрования
		return false;
	// Если текст объявлен непустым, но не передан
	if((source.size > 0) && ((source.data == nullptr) || (result == nullptr)))
		// Выводим отказ расшифрования
		return false;
	// Если связанные данные объявлены непустыми, но не переданы
	if((associated.size > 0) && (associated.data == nullptr))
		// Выводим отказ расшифрования
		return false;
	// Выполняем сброс состояния потока: разовый вызов не зависит от прежнего
	this->reset();
	// Если связанные данные подать не удалось
	if(!this->associate(associated))
		// Выводим отказ расшифрования
		return false;
	/**
	 * Метка сличается прежде снятия гаммы, чтобы при расхождении не раскрыть ни
	 * байта: шифртекст складывается в накопитель без наложения гаммы, а гамма
	 * снимается лишь после схождения метки тем же счётчиком от начального блока
	 */
	if(!this->proceed(2))
		// Выводим отказ расшифрования
		return false;
	// Выполняем сложение шифртекста в накопитель
	this->absorb(source.data, source.size);
	// Увеличиваем длину шифртекста
	this->_sealed += static_cast <uint64_t> (source.size);
	// Если метка не сошлась
	if(!this->verify(tag))
		// Выводим отказ расшифрования, не раскрывая ни байта
		return false;
	// Если гамму снять не удалось
	if(!this->cover(source, result)){
		// Выполняем затирание неполного открытого текста
		wipe(result, source.size);
		// Выводим отказ расшифрования
		return false;
	}
	// Выводим успешность расшифрования
	return true;
}
/**
 * @brief Конструктор
 *
 */
nts::cipher::Gcm::Gcm() noexcept : _ready(false), _spent(false), _size(0), _stage(0), _direction(0), _rest(0), _filled(0), _associated(0), _sealed(0) {
	// Выполняем затирание начального блока счётчика
	wipe(this->_nonce, sizeof(this->_nonce));
	// Выполняем затирание таблицы кратных
	wipe(this->_table, sizeof(this->_table));
	// Выполняем затирание отражённого ключа хеширования
	wipe(this->_mirror, sizeof(this->_mirror));
	// Выполняем затирание степеней ключа хеширования
	wipe(this->_powers, sizeof(this->_powers));
	// Выполняем сброс состояния потока
	this->reset();
}
/**
 * @brief Деструктор
 *
 */
nts::cipher::Gcm::~Gcm() noexcept {
	// Выполняем сброс режима
	this->clear();
}
