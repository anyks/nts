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
 *          по таблице двухсот пятидесяти шести кратных ключа хеширования: значение
 *          разбирается по байту с конца, и каждый шаг - сдвиг на байт с приведением
 *          по таблице остатков и сложение с кратным. Разряды поля
 *          нумеруются от старшего, как велит стандарт, оттого сдвиг идёт вправо
 *
 * @note Таблица байтовая, а не полубайтовая, намеренно: пятнадцать шагов вместо
 *       тридцати одного ценой четырёх килобайтов кратных и полукилобайта остатков на
 *       ключ. На машинах без команды умножения без переносов (Эльбрус, стенды под
 *       QEMU) это удваивает GHASH: 77 → 150 МБ/с на Эльбрус-8С2, 319 → 509 на ARM64 без
 *       PMULL; таблица остатков считается при заведении, а не зашита, чтобы её нельзя
 *       было испортить незаметно для золотых векторов.
 *       Слитое ядро (круг 31, 23.09.2026): на машинах с командами AES и умножения без
 *       переносов гамма счётчика и хеш идут одним проходом по восемь блоков прямо по
 *       расписанию ключа шифра - порознь CTR 13,7 ГБ/с и GHASH 10,5 давали вместе 6,5 на
 *       Apple M4, слитно 9,6 при 10,4 у OpenSSL; остаток короче восьми блоков идёт
 *       прежними путями. Смена заполнения restart оставляет таблицы от запуска: режим
 *       ведёт много сообщений одним ключом, не строя таблицу на каждое.
 *       GHASH на PCLMULQDQ (круг 37, 23.09.2026): у x86-64 нет команды отражения
 *       разрядов, и отражение каждого блока двумя перестановками полубайтов стоило
 *       дороже самого умножения - Xeon E5-2630 v4 давал 2,8 ГБ/с при 6,3 у OpenSSL.
 *       Теперь блоки лишь переставляются байтами, а ключ и его степени хранятся
 *       сдвинутыми на разряд влево с приведением: произведение переставленных
 *       операндов есть переставленное произведение, сдвинутое на разряд вправо, и
 *       сдвиг ключа возмещает это заранее (приём Гуэрона, как у OpenSSL и BoringSSL);
 *       умножение Карацубы на трёх командах вместо четырёх, суммы младших, старших и
 *       средних произведений копятся порознь на восемь блоков и приводятся один раз.
 *       Счётчики восьмёрки (круг 38, 23.09.2026) собираются сложениями в векторе, пока
 *       младший байт не переполняется внутри восьмёрки, и по одному через скаляр на
 *       переносе: сборка через скаляр на каждый блок стоила на Xeon E5-2630 v4
 *       23 такта из 180 на восьмёрку.
 *       Сшитое ядро на ассемблере x86-64 (круг 38, 24.09.2026): собиратель выносил все
 *       умножения без переносов клубком после кругов AES и не давал переплести их с
 *       кругами, а на Broadwell перестановки байтов делят порт с aesenc. Ядро на
 *       ассемблере с кодировкой VEX хеширует прежнюю восьмёрку по блоку между кругами,
 *       переставляет половины блока загрузкой movbe через память и множит половины
 *       порознь без слияния и без Карацубы: Xeon E5-2630 v4 178 → 137 тактов на 128 байт
 *       при 142 у OpenSSL. Ядро требует AVX и MOVBE; без них остаётся ядро на интринсиках
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
	 * Цель слитого ядра: расширение crypto несёт и AES, и умножение без переносов
	 */
	#define __ANTS_FUSED_TARGET__ __ANTS_GHASH_TARGET__
/**
 * Если сборка ведётся под x86-64 собирателем семейства GCC
 */
#elif (defined(__x86_64__) || defined(__e2k__)) && (defined(__GNUC__) || defined(__clang__)) && !defined(ANTS_NO_MACHINE)
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

	/**
	 * Если команды AES и умножения без переносов уже разрешены ключами сборки
	 */
	#if defined(__AES__) && defined(__PCLMUL__) && defined(__SSSE3__)
		/**
		 * Атрибут цели слитого ядра не нужен
		 */
		#define __ANTS_FUSED_TARGET__
	#else
		/**
		 * Разрешаем команды расширений слитого ядра одной функции
		 */
		#define __ANTS_FUSED_TARGET__ __attribute__((target("aes,pclmul,ssse3,sse2")))
	#endif
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
	 * Наибольшая длина открытого текста одного вызова GCM в байтах: (2^39 - 256) / 8
	 */
	static constexpr uint64_t GCM_MOST = ((static_cast <uint64_t> (1) << 36) - 32);
	/**
	 * Наибольшая длина присоединённых данных в байтах: (2^64 - 1) / 8
	 */
	static constexpr uint64_t GCM_ASSOCIATED = (static_cast <uint64_t> (1) << 61);
	/**
	 * Пространство имён библиотеки
	 */
	using namespace nts;

	/**
	 * Пространство имён модуля
	 */
	using namespace nts::cipher;

	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;

/**
 * Если машина умножает без переносов командой PCLMULQDQ
 */
#if defined(__ANTS_GHASH_X86__)
	/**
	 * @brief Метод перестановки байтов блока от старшего к младшему
	 *
	 * @details Блок GCM читается от старшего байта, а команда умножения без переносов
	 *          считает слова от младшего: после перестановки разряды многочлена идут
	 *          в обратном порядке, и произведение переставленных операндов равно
	 *          переставленному произведению, сдвинутому на разряд вправо - сдвиг
	 *          возмещается ключом, хранимым сдвинутым на разряд влево
	 *
	 * @param value переставляемые байты
	 *
	 * @return      байты в обратном порядке
	 *
	 */
	static __ANTS_GHASH_TARGET__ __ANTS_INLINE__ __m128i swap(const __m128i value) noexcept {
		// Выводим байты в обратном порядке
		return _mm_shuffle_epi8(value, _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0));
	}
#endif


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
	 * @brief Метод сложения восьми блоков в накопитель одним приведением командой PMULL
	 *
	 * @param powers      степени ключа хеширования от четвёртой до первой, отражённые
	 * @param accumulator накопитель многочлена, заменяемый итогом
	 * @param blocks      восемь блоков подряд
	 *
	 */
	static __ANTS_GHASH_TARGET__ void aggregateArm(const uint64_t (* powers)[3], uint8_t * accumulator, const uint8_t * blocks) noexcept {
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
		productArm(vreinterpretq_u64_u8(vrbitq_u8(vld1q_u8(blocks + 64))), vld1q_u64(powers[4]), low, high);
		productArm(vreinterpretq_u64_u8(vrbitq_u8(vld1q_u8(blocks + 80))), vld1q_u64(powers[5]), low, high);
		productArm(vreinterpretq_u64_u8(vrbitq_u8(vld1q_u8(blocks + 96))), vld1q_u64(powers[6]), low, high);
		productArm(vreinterpretq_u64_u8(vrbitq_u8(vld1q_u8(blocks + 112))), vld1q_u64(powers[7]), low, high);
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
	 * @brief Метод слитого хода режима: гамма счётчика AES и хеш GHASH по восемь блоков в одном проходе
	 *
	 * @param keys        расписание ключа зашифрования AES
	 * @param rounds      число кругов AES
	 * @param counter     блок счётчика: младшие 32 разряда растут от старшего байта и продвигаются на пройденные блоки
	 * @param powers      степени ключа хеширования от восьмой до первой, отражённые
	 * @param accumulator накопитель хеша
	 * @param sealing     признак зашифрования: хеш берётся от итога, при расшифровании - от источника
	 * @param source      источник: открытый текст либо шифртекст
	 * @param result      место, в которое записывается итог той же длины
	 * @param chunks      число восьмёрок блоков
	 *
	 */
	static __ANTS_FUSED_TARGET__ void fusedArm(const uint8_t * keys, const size_t rounds, uint8_t * counter, const uint64_t (* powers)[3], uint8_t * accumulator, const bool sealing, const uint8_t * source, uint8_t * result, const size_t chunks) noexcept {
		// Ключ, складываемый после последнего круга
		const uint8x16_t last = vld1q_u8(keys + (rounds * 16));
		// Ключ последнего круга подстановки
		const uint8x16_t final = vld1q_u8(keys + ((rounds - 1) * 16));
		// Основание счётчика: заполнение и старшие разряды
		const uint8x16_t base = vld1q_u8(counter);
		// Шаги счётчика в переставленном слове: единица, двойка и четвёрка в старшем байте слова
		const uint32x4_t step1 = vsetq_lane_u32(0x01000000U, vdupq_n_u32(0), 3);
		const uint32x4_t step2 = vaddq_u32(step1, step1);
		const uint32x4_t step4 = vaddq_u32(step2, step2);
		// Младшие 32 разряда счётчика числом
		uint32_t tail = ((static_cast <uint32_t> (counter[12]) << 24) | (static_cast <uint32_t> (counter[13]) << 16) | (static_cast <uint32_t> (counter[14]) << 8) | static_cast <uint32_t> (counter[15]));
		/**
		 * Выполняем перебор восьмёрок блоков: хеш соседней восьмёрки и гамма следующей
		 * идут вперемешку на разных устройствах машины. При зашифровании хеш берётся от
		 * шифртекста прежней восьмёрки, а не только что выработанного: иначе умножение
		 * ждало бы всю цепочку кругов AES, и восьмёрки не накладывались бы друг на друга
		 */
		for(size_t c = 0; c < chunks; c++){
			// При расшифровании хеш берётся от шифртекста до снятия гаммы
			if(!sealing)
				aggregateArm(powers, accumulator, source);
			// При зашифровании хеш берётся от шифртекста прежней восьмёрки
			else if(c > 0)
				aggregateArm(powers, accumulator, result - 128);
			// Восемь блоков счётчика
			uint8x16_t s0, s1, s2, s3, s4, s5, s6, s7;
			/**
			 * Пока младший байт счётчика не переполняется внутри восьмёрки, переставленное
			 * слово растёт прибавлением к своему старшему байту, и восемь счётчиков
			 * собираются сложениями в векторе деревом на трёх шагах (приём aesni-x86_64
			 * OpenSSL); на переносе через младший байт - не чаще раза на тридцать две
			 * восьмёрки - счётчики собираются по одному через скаляр. Сборка через
			 * скаляр на каждый блок стоила на Xeon E5-2630 v4 23 такта из 180 на восьмёрку
			 */
			if((tail & 0xFFU) < 0xF8U){
				// Переставленный счётчик восьмёрки
				const uint32x4_t c0 = vaddq_u32(vsetq_lane_u32(__builtin_bswap32(tail), vreinterpretq_u32_u8(base), 3), step1);
				const uint32x4_t c1 = vaddq_u32(c0, step1);
				const uint32x4_t c2 = vaddq_u32(c0, step2);
				const uint32x4_t c3 = vaddq_u32(c1, step2);
				// Собираем восемь блоков счётчика сложениями
				s0 = vreinterpretq_u8_u32(c0);
				s1 = vreinterpretq_u8_u32(c1);
				s2 = vreinterpretq_u8_u32(c2);
				s3 = vreinterpretq_u8_u32(c3);
				s4 = vreinterpretq_u8_u32(vaddq_u32(c0, step4));
				s5 = vreinterpretq_u8_u32(vaddq_u32(c1, step4));
				s6 = vreinterpretq_u8_u32(vaddq_u32(c2, step4));
				s7 = vreinterpretq_u8_u32(vaddq_u32(c3, step4));
			// Иначе младший байт переполняется внутри восьмёрки
			} else {
				// Собираем восемь блоков счётчика по одному
				s0 = vreinterpretq_u8_u32(vsetq_lane_u32(__builtin_bswap32(tail + 1), vreinterpretq_u32_u8(base), 3));
				s1 = vreinterpretq_u8_u32(vsetq_lane_u32(__builtin_bswap32(tail + 2), vreinterpretq_u32_u8(base), 3));
				s2 = vreinterpretq_u8_u32(vsetq_lane_u32(__builtin_bswap32(tail + 3), vreinterpretq_u32_u8(base), 3));
				s3 = vreinterpretq_u8_u32(vsetq_lane_u32(__builtin_bswap32(tail + 4), vreinterpretq_u32_u8(base), 3));
				s4 = vreinterpretq_u8_u32(vsetq_lane_u32(__builtin_bswap32(tail + 5), vreinterpretq_u32_u8(base), 3));
				s5 = vreinterpretq_u8_u32(vsetq_lane_u32(__builtin_bswap32(tail + 6), vreinterpretq_u32_u8(base), 3));
				s6 = vreinterpretq_u8_u32(vsetq_lane_u32(__builtin_bswap32(tail + 7), vreinterpretq_u32_u8(base), 3));
				s7 = vreinterpretq_u8_u32(vsetq_lane_u32(__builtin_bswap32(tail + 8), vreinterpretq_u32_u8(base), 3));
			}
			// Продвигаем счётчик на восемь блоков
			tail += 8;
			/**
			 * Выполняем круги подстановки
			 */
			for(size_t round = 0; (round + 1) < rounds; round++){
				// Ключ круга
				const uint8x16_t key = vld1q_u8(keys + (round * 16));
				s0 = vaesmcq_u8(vaeseq_u8(s0, key));
				s1 = vaesmcq_u8(vaeseq_u8(s1, key));
				s2 = vaesmcq_u8(vaeseq_u8(s2, key));
				s3 = vaesmcq_u8(vaeseq_u8(s3, key));
				s4 = vaesmcq_u8(vaeseq_u8(s4, key));
				s5 = vaesmcq_u8(vaeseq_u8(s5, key));
				s6 = vaesmcq_u8(vaeseq_u8(s6, key));
				s7 = vaesmcq_u8(vaeseq_u8(s7, key));
			}
			// Накладываем гамму на источник
			vst1q_u8(result, veorq_u8(veorq_u8(vaeseq_u8(s0, final), last), vld1q_u8(source)));
			vst1q_u8(result + 16, veorq_u8(veorq_u8(vaeseq_u8(s1, final), last), vld1q_u8(source + 16)));
			vst1q_u8(result + 32, veorq_u8(veorq_u8(vaeseq_u8(s2, final), last), vld1q_u8(source + 32)));
			vst1q_u8(result + 48, veorq_u8(veorq_u8(vaeseq_u8(s3, final), last), vld1q_u8(source + 48)));
			vst1q_u8(result + 64, veorq_u8(veorq_u8(vaeseq_u8(s4, final), last), vld1q_u8(source + 64)));
			vst1q_u8(result + 80, veorq_u8(veorq_u8(vaeseq_u8(s5, final), last), vld1q_u8(source + 80)));
			vst1q_u8(result + 96, veorq_u8(veorq_u8(vaeseq_u8(s6, final), last), vld1q_u8(source + 96)));
			vst1q_u8(result + 112, veorq_u8(veorq_u8(vaeseq_u8(s7, final), last), vld1q_u8(source + 112)));
			// Переходим к следующей восьмёрке
			source += 128;
			result += 128;
		}
		// При зашифровании хеш последней восьмёрки шифртекста берётся после цикла
		if(sealing)
			aggregateArm(powers, accumulator, result - 128);
		// Записываем продвинутый счётчик
		counter[12] = static_cast <uint8_t> (tail >> 24);
		counter[13] = static_cast <uint8_t> (tail >> 16);
		counter[14] = static_cast <uint8_t> (tail >> 8);
		counter[15] = static_cast <uint8_t> (tail);
	}
/**
 * Если есть ветвь машинного умножения PCLMULQDQ
 */
#elif defined(__ANTS_GHASH_X86__)
	/**
	 * @brief Метод записи ключа хеширования в виде под команду PCLMULQDQ
	 *
	 * @details Байты переставляются от старшего к младшему, и ключ сдвигается на разряд
	 *          влево с приведением вынесенного разряда по многочлену поля: так сдвиг
	 *          произведения переставленных операндов возмещается заранее. Третьим
	 *          словом хранится сумма половин ключа под умножение Карацубы
	 *
	 * @param key   ключ хеширования либо его степень в порядке GCM
	 * @param twist место под три слова: сдвинутый ключ и сумма его половин
	 *
	 */
	static __ANTS_GHASH_TARGET__ void twistX86(const uint8_t * key, uint64_t * twist) noexcept {
		// Ключ с переставленными байтами
		const __m128i value = swap(_mm_loadu_si128(reinterpret_cast <const __m128i *> (key)));
		// Ключ, сдвинутый на разряд влево по словам, со старшими разрядами слов, перешедшими в соседнее слово
		__m128i result = _mm_or_si128(_mm_slli_epi64(value, 1), _mm_slli_si128(_mm_srli_epi64(value, 63), 8));
		// Маска старшего разряда ключа: все единицы, если он вынесен за край поля
		const __m128i mask = _mm_shuffle_epi32(_mm_srai_epi32(value, 31), 0xFF);
		// Приведение вынесенного разряда: многочлен x^7 + x^2 + x + 1 в переставленном виде
		result = _mm_xor_si128(result, _mm_and_si128(mask, _mm_set_epi64x(static_cast <int64_t> (0xC200000000000000ULL), 1)));
		// Записываем сдвинутый ключ
		_mm_storeu_si128(reinterpret_cast <__m128i *> (twist), result);
		// Записываем сумму половин ключа
		twist[2] = (twist[0] ^ twist[1]);
	}
	/**
	 * @brief Метод умножения Карацубы двух переставленных многочленов без приведения
	 *
	 * @details Три команды умножения вместо четырёх: произведения младших половин,
	 *          старших половин и сумм половин; средние произведения копятся порознь и
	 *          складываются с крайними один раз при приведении
	 *
	 * @param a      первый множитель: блок с переставленными байтами
	 * @param b      второй множитель: сдвинутый ключ либо его степень
	 * @param ab     сумма половин второго множителя в обоих словах
	 * @param low    произведения младших половин, складываемые с накопленными
	 * @param high   произведения старших половин, складываемые с накопленными
	 * @param middle произведения сумм половин, складываемые с накопленными
	 *
	 */
	static __ANTS_GHASH_TARGET__ __ANTS_INLINE__ void productX86(const __m128i a, const __m128i b, const __m128i ab, __m128i & low, __m128i & high, __m128i & middle) noexcept {
		// Складываем произведение младших половин
		low = _mm_xor_si128(low, _mm_clmulepi64_si128(a, b, 0x00));
		// Складываем произведение старших половин
		high = _mm_xor_si128(high, _mm_clmulepi64_si128(a, b, 0x11));
		// Складываем произведение сумм половин: сумма половин первого множителя в обоих словах
		middle = _mm_xor_si128(middle, _mm_clmulepi64_si128(_mm_xor_si128(a, _mm_shuffle_epi32(a, 0x4E)), ab, 0x00));
	}
	/**
	 * @brief Метод приведения суммы произведений по многочлену поля в переставленном виде
	 *
	 * @details Средние произведения Карацубы складываются с крайними и делятся между
	 *          половинами, затем старшая половина сворачивается в младшую: умножение
	 *          на x^7 + x^2 + x + 1 в переставленном виде - это сдвиги на 63, 62 и 57
	 *          разрядов влево и на 1, 2 и 7 вправо по словам с переносом между словами
	 *
	 * @param low    сумма произведений младших половин
	 * @param high   сумма произведений старших половин
	 * @param middle сумма произведений сумм половин
	 *
	 * @return       приведённое произведение с переставленными байтами
	 *
	 */
	static __ANTS_GHASH_TARGET__ __ANTS_INLINE__ __m128i reduceX86(__m128i low, __m128i high, __m128i middle) noexcept {
		// Средние произведения без крайних: перекрёстные произведения половин
		middle = _mm_xor_si128(middle, _mm_xor_si128(low, high));
		// Младшая половина произведения с младшим словом перекрёстных
		low = _mm_xor_si128(low, _mm_slli_si128(middle, 8));
		// Старшая половина произведения со старшим словом перекрёстных
		high = _mm_xor_si128(high, _mm_srli_si128(middle, 8));
		// Первая ступень: младшая половина, сдвинутая на 63, 62 и 57 разрядов влево по словам
		__m128i shifted = _mm_slli_epi64(low, 5);
		// Сумма сдвигов на 5 и 0
		const __m128i partial = _mm_xor_si128(low, shifted);
		// Сумма сдвигов на 6, 5 и 0
		shifted = _mm_xor_si128(_mm_slli_epi64(shifted, 1), partial);
		// Сумма сдвигов на 63, 62 и 57
		shifted = _mm_slli_epi64(shifted, 57);
		// Младшая половина с перенесённым в старшее слово младшим словом сдвига
		low = _mm_xor_si128(low, _mm_slli_si128(shifted, 8));
		// Старшая половина со старшим словом сдвига
		high = _mm_xor_si128(high, _mm_srli_si128(shifted, 8));
		// Вторая ступень: старшая половина, сложенная с младшей
		high = _mm_xor_si128(high, low);
		// Младшая половина, сдвинутая на разряд вправо
		shifted = _mm_srli_epi64(low, 1);
		// Сумма сдвигов на 1 и 0
		const __m128i mixed = _mm_xor_si128(low, shifted);
		// Сумма сдвигов на 6, 1 и 0
		shifted = _mm_xor_si128(_mm_srli_epi64(shifted, 5), mixed);
		// Сумма сдвигов на 7, 2 и 1
		shifted = _mm_srli_epi64(shifted, 1);
		// Выводим приведённое произведение
		return _mm_xor_si128(shifted, high);
	}
	/**
	 * @brief Метод умножения значения на ключ хеширования командой PCLMULQDQ
	 *
	 * @param twist сдвинутый ключ хеширования с суммой половин
	 * @param value умножаемое значение в порядке GCM, заменяемое произведением
	 *
	 */
	static __ANTS_GHASH_TARGET__ void multiplyX86(const uint64_t * twist, uint8_t * value) noexcept {
		// Значение с переставленными байтами
		const __m128i a = swap(_mm_loadu_si128(reinterpret_cast <const __m128i *> (value)));
		// Суммы произведений
		__m128i low = _mm_setzero_si128(), high = _mm_setzero_si128(), middle = _mm_setzero_si128();
		// Умножаем значение на ключ
		productX86(a, _mm_loadu_si128(reinterpret_cast <const __m128i *> (twist)), _mm_set1_epi64x(static_cast <int64_t> (twist[2])), low, high, middle);
		// Записываем приведённое произведение в порядке GCM
		_mm_storeu_si128(reinterpret_cast <__m128i *> (value), swap(reduceX86(low, high, middle)));
	}
	/**
	 * @brief Метод сложения восьми блоков в накопитель одним приведением командой PCLMULQDQ
	 *
	 * @param powers      степени ключа хеширования от восьмой до первой, сдвинутые, с суммами половин
	 * @param accumulator накопитель многочлена, заменяемый итогом
	 * @param blocks      восемь блоков подряд
	 *
	 */
	static __ANTS_GHASH_TARGET__ void aggregateX86(const uint64_t (* powers)[3], uint8_t * accumulator, const uint8_t * blocks) noexcept {
		// Суммы произведений
		__m128i low = _mm_setzero_si128(), high = _mm_setzero_si128(), middle = _mm_setzero_si128();
		// Накопитель, сложенный с первым блоком, с переставленными байтами
		const __m128i z = swap(_mm_xor_si128(_mm_loadu_si128(reinterpret_cast <const __m128i *> (accumulator)), _mm_loadu_si128(reinterpret_cast <const __m128i *> (blocks))));
		// Складываем произведение суммы с восьмой степенью
		productX86(z, _mm_loadu_si128(reinterpret_cast <const __m128i *> (powers[0])), _mm_set1_epi64x(static_cast <int64_t> (powers[0][2])), low, high, middle);
		/**
		 * Выполняем сложение произведений прочих блоков со степенями от седьмой до первой
		 */
		for(size_t i = 1; i < 8; i++)
			// Складываем произведение очередного блока с очередной степенью
			productX86(swap(_mm_loadu_si128(reinterpret_cast <const __m128i *> (blocks + (i * 16)))), _mm_loadu_si128(reinterpret_cast <const __m128i *> (powers[i])), _mm_set1_epi64x(static_cast <int64_t> (powers[i][2])), low, high, middle);
		// Записываем приведённый итог в порядке GCM
		_mm_storeu_si128(reinterpret_cast <__m128i *> (accumulator), swap(reduceX86(low, high, middle)));
	}
	/**
	 * @brief Метод слитого хода режима: гамма счётчика AES-NI и хеш GHASH по восемь блоков в одном проходе
	 *
	 * @param keys        расписание ключа зашифрования AES
	 * @param rounds      число кругов AES
	 * @param counter     блок счётчика: младшие 32 разряда растут от старшего байта и продвигаются на пройденные блоки
	 * @param powers      степени ключа хеширования от восьмой до первой, сдвинутые, с суммами половин
	 * @param accumulator накопитель хеша
	 * @param sealing     признак зашифрования: хеш берётся от итога, при расшифровании - от источника
	 * @param source      источник: открытый текст либо шифртекст
	 * @param result      место, в которое записывается итог той же длины
	 * @param chunks      число восьмёрок блоков
	 *
	 */
	static __ANTS_FUSED_TARGET__ void fusedX86(const uint8_t * keys, const size_t rounds, uint8_t * counter, const uint64_t (* powers)[3], uint8_t * accumulator, const bool sealing, const uint8_t * source, uint8_t * result, const size_t chunks) noexcept {
		// Ключ первого круга
		const __m128i first = _mm_loadu_si128(reinterpret_cast <const __m128i *> (keys));
		// Ключ последнего круга
		const __m128i last = _mm_loadu_si128(reinterpret_cast <const __m128i *> (keys + (rounds * 16)));
		// Основание счётчика: заполнение и старшие разряды без младшего слова
		const __m128i head = _mm_and_si128(_mm_loadu_si128(reinterpret_cast <const __m128i *> (counter)), _mm_set_epi32(0, -1, -1, -1));
		// Шаги счётчика в переставленном слове: единица, двойка и четвёрка в старшем байте слова
		const __m128i step1 = _mm_set_epi32(0x01000000, 0, 0, 0);
		const __m128i step2 = _mm_add_epi32(step1, step1);
		const __m128i step4 = _mm_add_epi32(step2, step2);
		// Младшие 32 разряда счётчика числом
		uint32_t tail = ((static_cast <uint32_t> (counter[12]) << 24) | (static_cast <uint32_t> (counter[13]) << 16) | (static_cast <uint32_t> (counter[14]) << 8) | static_cast <uint32_t> (counter[15]));
		/**
		 * Выполняем перебор восьмёрок блоков: хеш соседней восьмёрки и гамма следующей
		 * идут вперемешку на разных устройствах машины. При зашифровании хеш берётся от
		 * шифртекста прежней восьмёрки, а не только что выработанного: иначе умножение
		 * ждало бы всю цепочку кругов AES, и восьмёрки не накладывались бы друг на друга
		 */
		for(size_t c = 0; c < chunks; c++){
			// При расшифровании хеш берётся от шифртекста до снятия гаммы
			if(!sealing)
				aggregateX86(powers, accumulator, source);
			// При зашифровании хеш берётся от шифртекста прежней восьмёрки
			else if(c > 0)
				aggregateX86(powers, accumulator, result - 128);
			// Восемь блоков счётчика
			__m128i s0, s1, s2, s3, s4, s5, s6, s7;
			/**
			 * Пока младший байт счётчика не переполняется внутри восьмёрки, переставленное
			 * слово растёт прибавлением к своему старшему байту, и восемь счётчиков
			 * собираются сложениями в векторе деревом на трёх шагах (приём aesni-x86_64
			 * OpenSSL); на переносе через младший байт - не чаще раза на тридцать две
			 * восьмёрки - счётчики собираются по одному через скаляр. Сборка через
			 * скаляр на каждый блок стоила на Xeon E5-2630 v4 23 такта из 180 на восьмёрку
			 */
			if((tail & 0xFFU) < 0xF8U){
				// Переставленный счётчик восьмёрки
				const __m128i c0 = _mm_add_epi32(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (__builtin_bswap32(tail)), 0, 0, 0)), step1);
				const __m128i c1 = _mm_add_epi32(c0, step1);
				const __m128i c2 = _mm_add_epi32(c0, step2);
				const __m128i c3 = _mm_add_epi32(c1, step2);
				// Собираем восемь блоков счётчика сложениями под первым ключом
				s0 = _mm_xor_si128(c0, first);
				s1 = _mm_xor_si128(c1, first);
				s2 = _mm_xor_si128(c2, first);
				s3 = _mm_xor_si128(c3, first);
				s4 = _mm_xor_si128(_mm_add_epi32(c0, step4), first);
				s5 = _mm_xor_si128(_mm_add_epi32(c1, step4), first);
				s6 = _mm_xor_si128(_mm_add_epi32(c2, step4), first);
				s7 = _mm_xor_si128(_mm_add_epi32(c3, step4), first);
			// Иначе младший байт переполняется внутри восьмёрки
			} else {
				// Собираем восемь блоков счётчика по одному под первым ключом
				s0 = _mm_xor_si128(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (__builtin_bswap32(tail + 1)), 0, 0, 0)), first);
				s1 = _mm_xor_si128(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (__builtin_bswap32(tail + 2)), 0, 0, 0)), first);
				s2 = _mm_xor_si128(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (__builtin_bswap32(tail + 3)), 0, 0, 0)), first);
				s3 = _mm_xor_si128(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (__builtin_bswap32(tail + 4)), 0, 0, 0)), first);
				s4 = _mm_xor_si128(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (__builtin_bswap32(tail + 5)), 0, 0, 0)), first);
				s5 = _mm_xor_si128(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (__builtin_bswap32(tail + 6)), 0, 0, 0)), first);
				s6 = _mm_xor_si128(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (__builtin_bswap32(tail + 7)), 0, 0, 0)), first);
				s7 = _mm_xor_si128(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (__builtin_bswap32(tail + 8)), 0, 0, 0)), first);
			}
			// Продвигаем счётчик на восемь блоков
			tail += 8;
			/**
			 * Выполняем круги подстановки
			 */
			for(size_t round = 1; round < rounds; round++){
				// Ключ круга
				const __m128i key = _mm_loadu_si128(reinterpret_cast <const __m128i *> (keys + (round * 16)));
				s0 = _mm_aesenc_si128(s0, key);
				s1 = _mm_aesenc_si128(s1, key);
				s2 = _mm_aesenc_si128(s2, key);
				s3 = _mm_aesenc_si128(s3, key);
				s4 = _mm_aesenc_si128(s4, key);
				s5 = _mm_aesenc_si128(s5, key);
				s6 = _mm_aesenc_si128(s6, key);
				s7 = _mm_aesenc_si128(s7, key);
			}
			// Накладываем гамму на источник
			_mm_storeu_si128(reinterpret_cast <__m128i *> (result), _mm_xor_si128(_mm_aesenclast_si128(s0, last), _mm_loadu_si128(reinterpret_cast <const __m128i *> (source))));
			_mm_storeu_si128(reinterpret_cast <__m128i *> (result + 16), _mm_xor_si128(_mm_aesenclast_si128(s1, last), _mm_loadu_si128(reinterpret_cast <const __m128i *> (source + 16))));
			_mm_storeu_si128(reinterpret_cast <__m128i *> (result + 32), _mm_xor_si128(_mm_aesenclast_si128(s2, last), _mm_loadu_si128(reinterpret_cast <const __m128i *> (source + 32))));
			_mm_storeu_si128(reinterpret_cast <__m128i *> (result + 48), _mm_xor_si128(_mm_aesenclast_si128(s3, last), _mm_loadu_si128(reinterpret_cast <const __m128i *> (source + 48))));
			_mm_storeu_si128(reinterpret_cast <__m128i *> (result + 64), _mm_xor_si128(_mm_aesenclast_si128(s4, last), _mm_loadu_si128(reinterpret_cast <const __m128i *> (source + 64))));
			_mm_storeu_si128(reinterpret_cast <__m128i *> (result + 80), _mm_xor_si128(_mm_aesenclast_si128(s5, last), _mm_loadu_si128(reinterpret_cast <const __m128i *> (source + 80))));
			_mm_storeu_si128(reinterpret_cast <__m128i *> (result + 96), _mm_xor_si128(_mm_aesenclast_si128(s6, last), _mm_loadu_si128(reinterpret_cast <const __m128i *> (source + 96))));
			_mm_storeu_si128(reinterpret_cast <__m128i *> (result + 112), _mm_xor_si128(_mm_aesenclast_si128(s7, last), _mm_loadu_si128(reinterpret_cast <const __m128i *> (source + 112))));
			// Переходим к следующей восьмёрке
			source += 128;
			result += 128;
		}
		// При зашифровании хеш последней восьмёрки шифртекста берётся после цикла
		if(sealing)
			aggregateX86(powers, accumulator, result - 128);
		// Записываем продвинутый счётчик
		counter[12] = static_cast <uint8_t> (tail >> 24);
		counter[13] = static_cast <uint8_t> (tail >> 16);
		counter[14] = static_cast <uint8_t> (tail >> 8);
		counter[15] = static_cast <uint8_t> (tail);
	}
/**
 * Если собиратель семейства GCC: встроенный ассемблер
 */
#if defined(__GNUC__) || defined(__clang__)
	/**
	 * @brief Метод слитого хода целых восьмёрок на ассемблере x86-64: сшивка AES-CTR и GHASH
	 *
	 * @details Ядро на интринсиках упиралось не в порты: на Broadwell перестановки байтов
	 *          vpshufb и vpshufd делят порт с aesenc, и каждая стоила такт потока AES, а
	 *          собиратель к тому же выносил все умножения без переносов клубком после кругов.
	 *          Здесь хеш прежней восьмёрки идёт по блоку между кругами AES с первого по
	 *          восьмой; половины хешируемого блока переставляются загрузкой movbe в
	 *          регистры общего назначения, пишутся в ячейки и грузятся порознь двумя vmovq
	 *          (порты загрузки и записи, ни одной перестановки), а четыре умножения без
	 *          переносов берут по половине из двух регистров: слияние половин и приём
	 *          Карацубы не нужны. Приведение суммы произведений идёт после записи итога,
	 *          вне кругов; счётчики следующей восьмёрки собираются прибавлением к основанию.
	 *          Xeon E5-2630 v4: 178 тактов на 128 байт у ядра на интринсиках, 137 здесь при
	 *          142 у OpenSSL, 112 - одни круги AES. Ключ круга грузится в регистр, степени
	 *          ключа хеша идут операндами в памяти: регистров ровно шестнадцать
	 *
	 * @note Хеш обязан быть на каждой восьмёрке: первую восьмёрку зашифрования, у которой
	 *       прежней нет, ведёт снаружи гамма шифра без хеша. Младший байт счётчика не вправе
	 *       переполняться внутри хода: число восьмёрок ограничивает водитель
	 *
	 * @param keys        расписание ключа шифрования
	 * @param rounds      число кругов: 10, 12 либо 14
	 * @param counter     блок счётчика: младшие четыре байта растут от старшего байта, первый блок - плюс один
	 * @param powers      степени ключа хеша от восьмой к первой, сдвинутые на разряд
	 * @param accumulator накопитель хеша в порядке байтов GCM, заменяемый итогом
	 * @param hash        хешируемые блоки: прежняя восьмёрка итога при зашифровании, исходные при расшифровании
	 * @param source      исходные данные
	 * @param result      место под итог
	 * @param chunks      число восьмёрок: не меньше одной
	 *
	 */
	static void stitchX86(const uint8_t * keys, const size_t rounds, const uint8_t * counter, const uint64_t (* powers)[3], uint8_t * accumulator, const uint8_t * hash, const uint8_t * source, uint8_t * result, const size_t chunks) noexcept {
		// Шаги счётчика в старшем байте старшего слова и маска перестановки байтов
		static const uint8_t STEPS[144] = {
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8,
			15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
		};
		/**
		 * Стол ядра: шаги (0), маска (128), основание счётчика (144), ячейки половин (160),
		 * число средних кругов (288), накопитель (304)
		 */
		alignas(16) uint8_t table[320];
		// Записываем шаги и маску
		::memcpy(table, STEPS, sizeof(STEPS));
		// Записываем основание счётчика
		::memcpy(table + 144, counter, 16);
		// Число кругов с девятого до предпоследнего
		const uint64_t middle = static_cast <uint64_t> (rounds - 9);
		// Записываем число средних кругов
		::memcpy(table + 288, &middle, sizeof(middle));
		// Записываем накопитель
		::memcpy(table + 304, accumulator, 16);
		// Шаг хешируемых блоков
		const size_t step = 128;
		// Позиция ключа круга и число кругов средней части
		const uint8_t * kp = nullptr;
		size_t n = 0;
		// Половины хешируемого блока
		uint64_t t0 = 0, t1 = 0;
		// Число восьмёрок хода
		size_t count = chunks;
		/**
		 * Выполняем слитый ход: регистры 0…7 - блоки, 8…10 - суммы младших, старших и средних
		 * произведений, 11 и 12 - половины хешируемого блока, 13 - произведение и старшая
		 * половина накопителя, 14 - ключ круга, 15 - накопитель переставленный
		 */
		__asm__ __volatile__ (
			// Накопитель переставленный и его старшая половина младшей половиной регистра
			"vmovdqu 128(%[tab]), %%xmm11\n\t"
			"vmovdqu 304(%[tab]), %%xmm15\n\t"
			"vpshufb %%xmm11, %%xmm15, %%xmm15\n\t"
			"vpsrldq $8, %%xmm15, %%xmm13\n\t"
			// Счётчики первой восьмёрки под первым ключом
			"vmovdqu 144(%[tab]), %%xmm11\n\t"
			"vpaddd 0(%[tab]), %%xmm11, %%xmm0\n\t" "vpaddd 16(%[tab]), %%xmm11, %%xmm1\n\t" "vpaddd 32(%[tab]), %%xmm11, %%xmm2\n\t" "vpaddd 48(%[tab]), %%xmm11, %%xmm3\n\t"
			"vpaddd 64(%[tab]), %%xmm11, %%xmm4\n\t" "vpaddd 80(%[tab]), %%xmm11, %%xmm5\n\t" "vpaddd 96(%[tab]), %%xmm11, %%xmm6\n\t" "vpaddd 112(%[tab]), %%xmm11, %%xmm7\n\t"
			"vpxor (%[keys]), %%xmm0, %%xmm0\n\t" "vpxor (%[keys]), %%xmm1, %%xmm1\n\t" "vpxor (%[keys]), %%xmm2, %%xmm2\n\t" "vpxor (%[keys]), %%xmm3, %%xmm3\n\t" "vpxor (%[keys]), %%xmm4, %%xmm4\n\t" "vpxor (%[keys]), %%xmm5, %%xmm5\n\t" "vpxor (%[keys]), %%xmm6, %%xmm6\n\t" "vpxor (%[keys]), %%xmm7, %%xmm7\n\t"
			"1:\n\t"
			// Суммы произведений
			"vpxor %%xmm8, %%xmm8, %%xmm8\n\t" "vpxor %%xmm9, %%xmm9, %%xmm9\n\t" "vpxor %%xmm10, %%xmm10, %%xmm10\n\t"
			// Круг 1 и блок 0 хеша с накопителем
			"vmovdqu 16(%[keys]), %%xmm14\n\t" "vaesenc %%xmm14, %%xmm0, %%xmm0\n\t" "vaesenc %%xmm14, %%xmm1, %%xmm1\n\t" "vaesenc %%xmm14, %%xmm2, %%xmm2\n\t" "vaesenc %%xmm14, %%xmm3, %%xmm3\n\t" "vaesenc %%xmm14, %%xmm4, %%xmm4\n\t" "vaesenc %%xmm14, %%xmm5, %%xmm5\n\t" "vaesenc %%xmm14, %%xmm6, %%xmm6\n\t" "vaesenc %%xmm14, %%xmm7, %%xmm7\n\t"
			"movbe 0(%[hash]), %[t0]\n\t" "movbe 8(%[hash]), %[t1]\n\t" "movq %[t1], 160(%[tab])\n\t" "movq %[t0], 168(%[tab])\n\t" "vmovq 160(%[tab]), %%xmm11\n\t" "vmovq 168(%[tab]), %%xmm12\n\t" "vpxor %%xmm15, %%xmm11, %%xmm11\n\t" "vpxor %%xmm13, %%xmm12, %%xmm12\n\t"
			"vpclmulqdq $0x00, 0(%[pow]), %%xmm11, %%xmm13\n\t" "vpxor %%xmm13, %%xmm8, %%xmm8\n\t" "vpclmulqdq $0x10, 0(%[pow]), %%xmm11, %%xmm13\n\t" "vpxor %%xmm13, %%xmm10, %%xmm10\n\t" "vpclmulqdq $0x00, 0(%[pow]), %%xmm12, %%xmm13\n\t" "vpxor %%xmm13, %%xmm10, %%xmm10\n\t" "vpclmulqdq $0x10, 0(%[pow]), %%xmm12, %%xmm13\n\t" "vpxor %%xmm13, %%xmm9, %%xmm9\n\t"
			// Круг 2 и блок 1 хеша
			"vmovdqu 32(%[keys]), %%xmm14\n\t" "vaesenc %%xmm14, %%xmm0, %%xmm0\n\t" "vaesenc %%xmm14, %%xmm1, %%xmm1\n\t" "vaesenc %%xmm14, %%xmm2, %%xmm2\n\t" "vaesenc %%xmm14, %%xmm3, %%xmm3\n\t" "vaesenc %%xmm14, %%xmm4, %%xmm4\n\t" "vaesenc %%xmm14, %%xmm5, %%xmm5\n\t" "vaesenc %%xmm14, %%xmm6, %%xmm6\n\t" "vaesenc %%xmm14, %%xmm7, %%xmm7\n\t"
			"movbe 16(%[hash]), %[t0]\n\t" "movbe 24(%[hash]), %[t1]\n\t" "movq %[t1], 176(%[tab])\n\t" "movq %[t0], 184(%[tab])\n\t" "vmovq 176(%[tab]), %%xmm11\n\t" "vmovq 184(%[tab]), %%xmm12\n\t" "vpclmulqdq $0x00, 24(%[pow]), %%xmm11, %%xmm13\n\t" "vpxor %%xmm13, %%xmm8, %%xmm8\n\t" "vpclmulqdq $0x10, 24(%[pow]), %%xmm11, %%xmm13\n\t" "vpxor %%xmm13, %%xmm10, %%xmm10\n\t" "vpclmulqdq $0x00, 24(%[pow]), %%xmm12, %%xmm13\n\t" "vpxor %%xmm13, %%xmm10, %%xmm10\n\t" "vpclmulqdq $0x10, 24(%[pow]), %%xmm12, %%xmm13\n\t" "vpxor %%xmm13, %%xmm9, %%xmm9\n\t"
			// Круг 3 и блок 2 хеша
			"vmovdqu 48(%[keys]), %%xmm14\n\t" "vaesenc %%xmm14, %%xmm0, %%xmm0\n\t" "vaesenc %%xmm14, %%xmm1, %%xmm1\n\t" "vaesenc %%xmm14, %%xmm2, %%xmm2\n\t" "vaesenc %%xmm14, %%xmm3, %%xmm3\n\t" "vaesenc %%xmm14, %%xmm4, %%xmm4\n\t" "vaesenc %%xmm14, %%xmm5, %%xmm5\n\t" "vaesenc %%xmm14, %%xmm6, %%xmm6\n\t" "vaesenc %%xmm14, %%xmm7, %%xmm7\n\t"
			"movbe 32(%[hash]), %[t0]\n\t" "movbe 40(%[hash]), %[t1]\n\t" "movq %[t1], 192(%[tab])\n\t" "movq %[t0], 200(%[tab])\n\t" "vmovq 192(%[tab]), %%xmm11\n\t" "vmovq 200(%[tab]), %%xmm12\n\t" "vpclmulqdq $0x00, 48(%[pow]), %%xmm11, %%xmm13\n\t" "vpxor %%xmm13, %%xmm8, %%xmm8\n\t" "vpclmulqdq $0x10, 48(%[pow]), %%xmm11, %%xmm13\n\t" "vpxor %%xmm13, %%xmm10, %%xmm10\n\t" "vpclmulqdq $0x00, 48(%[pow]), %%xmm12, %%xmm13\n\t" "vpxor %%xmm13, %%xmm10, %%xmm10\n\t" "vpclmulqdq $0x10, 48(%[pow]), %%xmm12, %%xmm13\n\t" "vpxor %%xmm13, %%xmm9, %%xmm9\n\t"
			// Круг 4 и блок 3 хеша
			"vmovdqu 64(%[keys]), %%xmm14\n\t" "vaesenc %%xmm14, %%xmm0, %%xmm0\n\t" "vaesenc %%xmm14, %%xmm1, %%xmm1\n\t" "vaesenc %%xmm14, %%xmm2, %%xmm2\n\t" "vaesenc %%xmm14, %%xmm3, %%xmm3\n\t" "vaesenc %%xmm14, %%xmm4, %%xmm4\n\t" "vaesenc %%xmm14, %%xmm5, %%xmm5\n\t" "vaesenc %%xmm14, %%xmm6, %%xmm6\n\t" "vaesenc %%xmm14, %%xmm7, %%xmm7\n\t"
			"movbe 48(%[hash]), %[t0]\n\t" "movbe 56(%[hash]), %[t1]\n\t" "movq %[t1], 208(%[tab])\n\t" "movq %[t0], 216(%[tab])\n\t" "vmovq 208(%[tab]), %%xmm11\n\t" "vmovq 216(%[tab]), %%xmm12\n\t" "vpclmulqdq $0x00, 72(%[pow]), %%xmm11, %%xmm13\n\t" "vpxor %%xmm13, %%xmm8, %%xmm8\n\t" "vpclmulqdq $0x10, 72(%[pow]), %%xmm11, %%xmm13\n\t" "vpxor %%xmm13, %%xmm10, %%xmm10\n\t" "vpclmulqdq $0x00, 72(%[pow]), %%xmm12, %%xmm13\n\t" "vpxor %%xmm13, %%xmm10, %%xmm10\n\t" "vpclmulqdq $0x10, 72(%[pow]), %%xmm12, %%xmm13\n\t" "vpxor %%xmm13, %%xmm9, %%xmm9\n\t"
			// Круг 5 и блок 4 хеша
			"vmovdqu 80(%[keys]), %%xmm14\n\t" "vaesenc %%xmm14, %%xmm0, %%xmm0\n\t" "vaesenc %%xmm14, %%xmm1, %%xmm1\n\t" "vaesenc %%xmm14, %%xmm2, %%xmm2\n\t" "vaesenc %%xmm14, %%xmm3, %%xmm3\n\t" "vaesenc %%xmm14, %%xmm4, %%xmm4\n\t" "vaesenc %%xmm14, %%xmm5, %%xmm5\n\t" "vaesenc %%xmm14, %%xmm6, %%xmm6\n\t" "vaesenc %%xmm14, %%xmm7, %%xmm7\n\t"
			"movbe 64(%[hash]), %[t0]\n\t" "movbe 72(%[hash]), %[t1]\n\t" "movq %[t1], 224(%[tab])\n\t" "movq %[t0], 232(%[tab])\n\t" "vmovq 224(%[tab]), %%xmm11\n\t" "vmovq 232(%[tab]), %%xmm12\n\t" "vpclmulqdq $0x00, 96(%[pow]), %%xmm11, %%xmm13\n\t" "vpxor %%xmm13, %%xmm8, %%xmm8\n\t" "vpclmulqdq $0x10, 96(%[pow]), %%xmm11, %%xmm13\n\t" "vpxor %%xmm13, %%xmm10, %%xmm10\n\t" "vpclmulqdq $0x00, 96(%[pow]), %%xmm12, %%xmm13\n\t" "vpxor %%xmm13, %%xmm10, %%xmm10\n\t" "vpclmulqdq $0x10, 96(%[pow]), %%xmm12, %%xmm13\n\t" "vpxor %%xmm13, %%xmm9, %%xmm9\n\t"
			// Круг 6 и блок 5 хеша
			"vmovdqu 96(%[keys]), %%xmm14\n\t" "vaesenc %%xmm14, %%xmm0, %%xmm0\n\t" "vaesenc %%xmm14, %%xmm1, %%xmm1\n\t" "vaesenc %%xmm14, %%xmm2, %%xmm2\n\t" "vaesenc %%xmm14, %%xmm3, %%xmm3\n\t" "vaesenc %%xmm14, %%xmm4, %%xmm4\n\t" "vaesenc %%xmm14, %%xmm5, %%xmm5\n\t" "vaesenc %%xmm14, %%xmm6, %%xmm6\n\t" "vaesenc %%xmm14, %%xmm7, %%xmm7\n\t"
			"movbe 80(%[hash]), %[t0]\n\t" "movbe 88(%[hash]), %[t1]\n\t" "movq %[t1], 240(%[tab])\n\t" "movq %[t0], 248(%[tab])\n\t" "vmovq 240(%[tab]), %%xmm11\n\t" "vmovq 248(%[tab]), %%xmm12\n\t" "vpclmulqdq $0x00, 120(%[pow]), %%xmm11, %%xmm13\n\t" "vpxor %%xmm13, %%xmm8, %%xmm8\n\t" "vpclmulqdq $0x10, 120(%[pow]), %%xmm11, %%xmm13\n\t" "vpxor %%xmm13, %%xmm10, %%xmm10\n\t" "vpclmulqdq $0x00, 120(%[pow]), %%xmm12, %%xmm13\n\t" "vpxor %%xmm13, %%xmm10, %%xmm10\n\t" "vpclmulqdq $0x10, 120(%[pow]), %%xmm12, %%xmm13\n\t" "vpxor %%xmm13, %%xmm9, %%xmm9\n\t"
			// Круг 7 и блок 6 хеша
			"vmovdqu 112(%[keys]), %%xmm14\n\t" "vaesenc %%xmm14, %%xmm0, %%xmm0\n\t" "vaesenc %%xmm14, %%xmm1, %%xmm1\n\t" "vaesenc %%xmm14, %%xmm2, %%xmm2\n\t" "vaesenc %%xmm14, %%xmm3, %%xmm3\n\t" "vaesenc %%xmm14, %%xmm4, %%xmm4\n\t" "vaesenc %%xmm14, %%xmm5, %%xmm5\n\t" "vaesenc %%xmm14, %%xmm6, %%xmm6\n\t" "vaesenc %%xmm14, %%xmm7, %%xmm7\n\t"
			"movbe 96(%[hash]), %[t0]\n\t" "movbe 104(%[hash]), %[t1]\n\t" "movq %[t1], 256(%[tab])\n\t" "movq %[t0], 264(%[tab])\n\t" "vmovq 256(%[tab]), %%xmm11\n\t" "vmovq 264(%[tab]), %%xmm12\n\t" "vpclmulqdq $0x00, 144(%[pow]), %%xmm11, %%xmm13\n\t" "vpxor %%xmm13, %%xmm8, %%xmm8\n\t" "vpclmulqdq $0x10, 144(%[pow]), %%xmm11, %%xmm13\n\t" "vpxor %%xmm13, %%xmm10, %%xmm10\n\t" "vpclmulqdq $0x00, 144(%[pow]), %%xmm12, %%xmm13\n\t" "vpxor %%xmm13, %%xmm10, %%xmm10\n\t" "vpclmulqdq $0x10, 144(%[pow]), %%xmm12, %%xmm13\n\t" "vpxor %%xmm13, %%xmm9, %%xmm9\n\t"
			// Круг 8 и блок 7 хеша
			"vmovdqu 128(%[keys]), %%xmm14\n\t" "vaesenc %%xmm14, %%xmm0, %%xmm0\n\t" "vaesenc %%xmm14, %%xmm1, %%xmm1\n\t" "vaesenc %%xmm14, %%xmm2, %%xmm2\n\t" "vaesenc %%xmm14, %%xmm3, %%xmm3\n\t" "vaesenc %%xmm14, %%xmm4, %%xmm4\n\t" "vaesenc %%xmm14, %%xmm5, %%xmm5\n\t" "vaesenc %%xmm14, %%xmm6, %%xmm6\n\t" "vaesenc %%xmm14, %%xmm7, %%xmm7\n\t"
			"movbe 112(%[hash]), %[t0]\n\t" "movbe 120(%[hash]), %[t1]\n\t" "movq %[t1], 272(%[tab])\n\t" "movq %[t0], 280(%[tab])\n\t" "vmovq 272(%[tab]), %%xmm11\n\t" "vmovq 280(%[tab]), %%xmm12\n\t" "vpclmulqdq $0x00, 168(%[pow]), %%xmm11, %%xmm13\n\t" "vpxor %%xmm13, %%xmm8, %%xmm8\n\t" "vpclmulqdq $0x10, 168(%[pow]), %%xmm11, %%xmm13\n\t" "vpxor %%xmm13, %%xmm10, %%xmm10\n\t" "vpclmulqdq $0x00, 168(%[pow]), %%xmm12, %%xmm13\n\t" "vpxor %%xmm13, %%xmm10, %%xmm10\n\t" "vpclmulqdq $0x10, 168(%[pow]), %%xmm12, %%xmm13\n\t" "vpxor %%xmm13, %%xmm9, %%xmm9\n\t"
			// Круги с девятого до предпоследнего
			"leaq 144(%[keys]), %[kp]\n\t" "movq 288(%[tab]), %[n]\n\t"
			"3:\n\t"
			"vmovdqu (%[kp]), %%xmm14\n\t" "vaesenc %%xmm14, %%xmm0, %%xmm0\n\t" "vaesenc %%xmm14, %%xmm1, %%xmm1\n\t" "vaesenc %%xmm14, %%xmm2, %%xmm2\n\t" "vaesenc %%xmm14, %%xmm3, %%xmm3\n\t" "vaesenc %%xmm14, %%xmm4, %%xmm4\n\t" "vaesenc %%xmm14, %%xmm5, %%xmm5\n\t" "vaesenc %%xmm14, %%xmm6, %%xmm6\n\t" "vaesenc %%xmm14, %%xmm7, %%xmm7\n\t"
			"addq $16, %[kp]\n\t" "decq %[n]\n\t" "jnz 3b\n\t"
			// Последний круг, наложение гаммы и запись итога
			"vmovdqu (%[kp]), %%xmm14\n\t" "vaesenclast %%xmm14, %%xmm0, %%xmm0\n\t" "vaesenclast %%xmm14, %%xmm1, %%xmm1\n\t" "vaesenclast %%xmm14, %%xmm2, %%xmm2\n\t" "vaesenclast %%xmm14, %%xmm3, %%xmm3\n\t" "vaesenclast %%xmm14, %%xmm4, %%xmm4\n\t" "vaesenclast %%xmm14, %%xmm5, %%xmm5\n\t" "vaesenclast %%xmm14, %%xmm6, %%xmm6\n\t" "vaesenclast %%xmm14, %%xmm7, %%xmm7\n\t"
			"vpxor (%[src]), %%xmm0, %%xmm0\n\t" "vmovdqu %%xmm0, (%[dst])\n\t"
			"vpxor 16(%[src]), %%xmm1, %%xmm1\n\t" "vmovdqu %%xmm1, 16(%[dst])\n\t"
			"vpxor 32(%[src]), %%xmm2, %%xmm2\n\t" "vmovdqu %%xmm2, 32(%[dst])\n\t"
			"vpxor 48(%[src]), %%xmm3, %%xmm3\n\t" "vmovdqu %%xmm3, 48(%[dst])\n\t"
			"vpxor 64(%[src]), %%xmm4, %%xmm4\n\t" "vmovdqu %%xmm4, 64(%[dst])\n\t"
			"vpxor 80(%[src]), %%xmm5, %%xmm5\n\t" "vmovdqu %%xmm5, 80(%[dst])\n\t"
			"vpxor 96(%[src]), %%xmm6, %%xmm6\n\t" "vmovdqu %%xmm6, 96(%[dst])\n\t"
			"vpxor 112(%[src]), %%xmm7, %%xmm7\n\t" "vmovdqu %%xmm7, 112(%[dst])\n\t"
			// Приведение суммы произведений в накопитель: средняя часть полная, без поправки Карацубы
			"vpslldq $8, %%xmm10, %%xmm11\n\t" "vpxor %%xmm11, %%xmm8, %%xmm8\n\t"
			"vpsrldq $8, %%xmm10, %%xmm11\n\t" "vpxor %%xmm11, %%xmm9, %%xmm9\n\t"
			"vpsllq $5, %%xmm8, %%xmm11\n\t" "vpxor %%xmm8, %%xmm11, %%xmm12\n\t"
			"vpsllq $1, %%xmm11, %%xmm11\n\t" "vpxor %%xmm12, %%xmm11, %%xmm11\n\t"
			"vpsllq $57, %%xmm11, %%xmm11\n\t"
			"vpslldq $8, %%xmm11, %%xmm12\n\t" "vpxor %%xmm12, %%xmm8, %%xmm8\n\t"
			"vpsrldq $8, %%xmm11, %%xmm12\n\t" "vpxor %%xmm12, %%xmm9, %%xmm9\n\t"
			"vpxor %%xmm8, %%xmm9, %%xmm9\n\t"
			"vpsrlq $1, %%xmm8, %%xmm11\n\t" "vpxor %%xmm8, %%xmm11, %%xmm12\n\t"
			"vpsrlq $5, %%xmm11, %%xmm11\n\t" "vpxor %%xmm12, %%xmm11, %%xmm11\n\t"
			"vpsrlq $1, %%xmm11, %%xmm11\n\t"
			"vpxor %%xmm11, %%xmm9, %%xmm15\n\t"
			"vpsrldq $8, %%xmm15, %%xmm13\n\t"
			// Следующие хешируемые блоки, исходные данные и итог
			"addq %[step], %[hash]\n\t" "addq $128, %[src]\n\t" "addq $128, %[dst]\n\t"
			// Счётчики следующей восьмёрки под первым ключом
			"vmovdqu 144(%[tab]), %%xmm11\n\t" "vpaddd 112(%[tab]), %%xmm11, %%xmm11\n\t" "vmovdqu %%xmm11, 144(%[tab])\n\t"
			"vpaddd 0(%[tab]), %%xmm11, %%xmm0\n\t" "vpaddd 16(%[tab]), %%xmm11, %%xmm1\n\t" "vpaddd 32(%[tab]), %%xmm11, %%xmm2\n\t" "vpaddd 48(%[tab]), %%xmm11, %%xmm3\n\t"
			"vpaddd 64(%[tab]), %%xmm11, %%xmm4\n\t" "vpaddd 80(%[tab]), %%xmm11, %%xmm5\n\t" "vpaddd 96(%[tab]), %%xmm11, %%xmm6\n\t" "vpaddd 112(%[tab]), %%xmm11, %%xmm7\n\t"
			"vpxor (%[keys]), %%xmm0, %%xmm0\n\t" "vpxor (%[keys]), %%xmm1, %%xmm1\n\t" "vpxor (%[keys]), %%xmm2, %%xmm2\n\t" "vpxor (%[keys]), %%xmm3, %%xmm3\n\t" "vpxor (%[keys]), %%xmm4, %%xmm4\n\t" "vpxor (%[keys]), %%xmm5, %%xmm5\n\t" "vpxor (%[keys]), %%xmm6, %%xmm6\n\t" "vpxor (%[keys]), %%xmm7, %%xmm7\n\t"
			"decq %[cnt]\n\t" "jnz 1b\n\t"
			// Накопитель обратно в порядок байтов GCM
			"vmovdqu 128(%[tab]), %%xmm11\n\t" "vpshufb %%xmm11, %%xmm15, %%xmm15\n\t" "vmovdqu %%xmm15, 304(%[tab])\n\t"
			"vzeroupper\n\t"
			: [src] "+r" (source), [dst] "+r" (result), [hash] "+r" (hash), [cnt] "+r" (count), [kp] "=&r" (kp), [n] "=&r" (n), [t0] "=&r" (t0), [t1] "=&r" (t1)
			: [keys] "r" (keys), [pow] "r" (powers), [tab] "r" (table), [step] "r" (step)
			: "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15", "cc", "memory"
		);
		// Забираем накопитель
		::memcpy(accumulator, table + 304, 16);
		// Выполняем затирание стола
		wipe(table, sizeof(table));
	}
	/**
	 * @brief Метод слитого хода целых восьмёрок сшитым ядром с водителем счётчика
	 *
	 * @details Сшитое ядро ведёт лишь восьмёрки, внутри которых младший байт счётчика не
	 *          переполняется, и хеширует прежнюю восьмёрку на каждой. Водитель режет ход на
	 *          такие пробеги; первую восьмёрку зашифрования и восьмёрку с переносом через
	 *          младший байт - не чаще одной на тридцать две - ведёт гамма шифра без хеша,
	 *          а хеш прежней восьмёрки перед ними и последней после хода берётся порознь.
	 *          При расшифровании хешируются исходные данные той же восьмёрки: отставания нет
	 *
	 * @param block       блочный шифр с расписанием ключа и выработкой гаммы
	 * @param counter     блок счётчика, продвигаемый на выработанные блоки
	 * @param powers      степени ключа хеша от восьмой к первой, сдвинутые на разряд
	 * @param accumulator накопитель хеша, заменяемый итогом
	 * @param sealing     признак зашифрования
	 * @param source      исходные данные
	 * @param result      место под итог
	 * @param chunks      число восьмёрок: не меньше одной
	 *
	 * @return            признак успешности хода
	 *
	 */
	static bool stitchedX86(const block_t & block, uint8_t * counter, const uint64_t (* powers)[3], uint8_t * accumulator, const bool sealing, const uint8_t * source, uint8_t * result, const size_t chunks) noexcept {
		// Младшие четыре байта счётчика числом
		uint32_t tail = ((static_cast <uint32_t> (counter[12]) << 24) | (static_cast <uint32_t> (counter[13]) << 16) | (static_cast <uint32_t> (counter[14]) << 8) | static_cast <uint32_t> (counter[15]));
		/**
		 * Выполняем ход по восьмёркам пробегами
		 */
		for(size_t c = 0; c < chunks;){
			// Записываем текущие младшие байты счётчика
			counter[12] = static_cast <uint8_t> (tail >> 24);
			counter[13] = static_cast <uint8_t> (tail >> 16);
			counter[14] = static_cast <uint8_t> (tail >> 8);
			counter[15] = static_cast <uint8_t> (tail);
			// Число восьмёрок до переноса через младший байт счётчика
			size_t run = (((tail & 0xFFU) <= 0xF7U) ? (((0xF7U - (tail & 0xFFU)) / 8U) + 1U) : 0U);
			// Ограничиваем пробег оставшимися восьмёрками
			if(run > (chunks - c))
				// Пробег не длиннее хода
				run = (chunks - c);
			/**
			 * Если восьмёрку ведёт гамма шифра: первая при зашифровании либо перенос через младший байт
			 */
			if((sealing && (c == 0)) || (run == 0)){
				// При зашифровании прежняя восьмёрка ещё не хеширована
				if(sealing && (c > 0))
					// Хешируем прежнюю восьмёрку итога
					aggregateX86(powers, accumulator, result + ((c - 1) * 128));
				// Если гамму на восьмёрку наложить не удалось
				if(!block.stream(block.cipher, counter, 8, source + (c * 128), result + (c * 128)))
					// Выводим отказ хода
					return false;
				// При расшифровании хешируются исходные данные восьмёрки
				if(!sealing)
					// Хешируем восьмёрку исходных данных
					aggregateX86(powers, accumulator, source + (c * 128));
				// Сдвигаем счётчик на восьмёрку
				tail += 8;
				// Переходим к следующей восьмёрке
				c++;
			// Иначе пробег ведёт сшитое ядро
			} else {
				// Выполняем пробег сшитым ядром: при зашифровании хешируется прежняя восьмёрка итога, при расшифровании - исходные данные
				stitchX86(block.schedule, block.rounds, counter, powers, accumulator, (sealing ? (result + ((c - 1) * 128)) : (source + (c * 128))), source + (c * 128), result + (c * 128), run);
				// Сдвигаем счётчик на пробег
				tail += static_cast <uint32_t> (run * 8);
				// Переходим к восьмёрке за пробегом
				c += run;
			}
		}
		// При зашифровании хеш последней восьмёрки итога берётся после хода
		if(sealing)
			aggregateX86(powers, accumulator, result + ((chunks - 1) * 128));
		// Записываем продвинутый счётчик
		counter[12] = static_cast <uint8_t> (tail >> 24);
		counter[13] = static_cast <uint8_t> (tail >> 16);
		counter[14] = static_cast <uint8_t> (tail >> 8);
		counter[15] = static_cast <uint8_t> (tail);
		// Выводим успешность хода
		return true;
	}
#endif
#endif
};

/**
 * @brief Метод слитого хода режима: гамма счётчика AES и хеш по восемь блоков в одном проходе
 *
 * @param sealing признак зашифрования
 * @param source  источник целыми восьмёрками блоков
 * @param result  место под итог той же длины
 * @param chunks  число восьмёрок блоков
 *
 * @return        признак того, что ход выполнен
 *
 */
bool nts::cipher::Gcm::travel(const bool sealing, const uint8_t * source, uint8_t * result, const size_t chunks) noexcept {
/**
 * Если есть ветвь машинного умножения
 */
#if defined(__ANTS_GHASH_ARM__) || defined(__ANTS_GHASH_X86__)
	// Если расписания ключа AES нет либо команд машины нет: путь идёт порознь
	if((this->_block.schedule == nullptr) || (chunks == 0) || !machine::has(machine::feature_t::CARRYLESS) || !machine::has(machine::feature_t::AES))
		// Выводим отказ слитого хода
		return false;
	/**
	 * Если есть ветвь машинного умножения PMULL
	 */
	#if defined(__ANTS_GHASH_ARM__)
		// Выполняем слитый ход командами ARMv8
		fusedArm(this->_block.schedule, this->_block.rounds, this->_counter, this->_powers, this->_accumulator, sealing, source, result, chunks);
	#else
		/**
		 * Если есть сшитое ядро на ассемблере, а машина несёт кодировку VEX и MOVBE
		 */
		#if defined(__GNUC__) || defined(__clang__)
			// Если машина несёт кодировку VEX, загрузку с перестановкой байтов и гамму шифра
			if(machine::has(machine::feature_t::AVX) && machine::has(machine::feature_t::MOVBE) && (this->_block.stream != nullptr))
				// Выводим итог слитого хода сшитым ядром
				return stitchedX86(this->_block, this->_counter, this->_powers, this->_accumulator, sealing, source, result, chunks);
		#endif
		// Выполняем слитый ход командами x86-64
		fusedX86(this->_block.schedule, this->_block.rounds, this->_counter, this->_powers, this->_accumulator, sealing, source, result, chunks);
	#endif
	// Выводим успешность слитого хода
	return true;
#else
	(void) sealing;
	(void) source;
	(void) result;
	(void) chunks;
	// Выводим отказ слитого хода: ветви машины нет
	return false;
#endif
}
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
	/**
	 * Умножение по байтовой таблице: младший байт значения даёт первое кратное, а
	 * всякий следующий шаг сдвигает накопленное на байт с приведением вынесенного
	 * байта по таблице остатков и складывает с кратным очередного байта. Шагов
	 * пятнадцать, число их постоянно - собиратель разворачивает их целиком
	 */
	uint64_t zh = this->_table[value[15]][0], zl = this->_table[value[15]][1];
	/**
	 * Выполняем перебор байтов значения от четырнадцатого к нулевому
	 */
	for(size_t index = 15; index > 0; index--){
		// Вынесенный за младший край байт накопленного значения
		const uint8_t rem = static_cast <uint8_t> (zl);
		// Сдвигаем накопленное значение на байт
		zl = ((zh << 56) | (zl >> 8));
		// Сдвигаем старшую половину на байт
		zh >>= 8;
		// Приводим вынесенный байт по таблице остатков
		zh ^= (static_cast <uint64_t> (this->_remainders[rem]) << 48);
		// Складываем с кратным очередного байта значения
		zh ^= this->_table[value[index - 1]][0];
		// Складываем с кратным очередного байта значения
		zl ^= this->_table[value[index - 1]][1];
	}
	// Записываем старшую половину произведения
	store(zh, value);
	// Записываем младшую половину произведения
	store(zl, value + 8);
}
/**
 * @brief Метод сложения восьми блоков в накопитель многочлена одним приведением
 *
 * @param accumulator накопитель многочлена, заменяемый итогом
 * @param blocks      восемь блоков подряд
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
		// Выполняем сложение восьми блоков командой
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
		// Выполняем сложение восьми блоков командой
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
	// Если кусок пуст: складывать нечего, а копирование с нулевым указателем недопустимо
	if(size == 0)
		// Выходим из метода
		return;
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
	while((left >= 128) && this->aggregate(this->_accumulator, cursor)){
		// Сдвигаем позицию чтения
		cursor += 128;
		// Уменьшаем число не сложенных байтов
		left -= 128;
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
	/**
	 * Гамма на тридцать два блока: выработка гаммы по восемь блоков за вызов давала
	 * 6,8 ГБ/с против 8,5 при выработке разом, разница - цена самого вызова
	 */
	uint8_t gamma[512];
	/**
	 * Выполняем покрытие данных гаммой по тридцать два блока
	 */
	while(left > 0){
		// Число блоков гаммы: до тридцати двух
		const size_t count = (((left + 15) / 16) < 32) ? ((left + 15) / 16) : 32;
		// Если шифр умеет вырабатывать гамму по многу блоков
		if(this->_block.stream != nullptr){
			// Если гамму выработать не удалось
			if(!this->_block.stream(this->_block.cipher, this->_counter, count, nullptr, gamma)){
				// Выполняем затирание гаммы
				wipe(gamma, sizeof(gamma));
				// Выводим отказ наложения
				return false;
			}
			/**
			 * Выполняем продвижение счётчика на выработанные блоки
			 */
			/**
			 * Сдвигаем счётчик на число блоков числом, а не побайтно: младшие четыре
			 * байта идут от старшего и по кругу, как и у побайтового переноса
			 */
			const uint32_t tail = ((static_cast <uint32_t> (this->_counter[12]) << 24) | (static_cast <uint32_t> (this->_counter[13]) << 16) | (static_cast <uint32_t> (this->_counter[14]) << 8) | static_cast <uint32_t> (this->_counter[15])) + static_cast <uint32_t> (count);
			// Записываем сдвинутый счётчик от старшего байта
			this->_counter[12] = static_cast <uint8_t> (tail >> 24);
			this->_counter[13] = static_cast <uint8_t> (tail >> 16);
			this->_counter[14] = static_cast <uint8_t> (tail >> 8);
			this->_counter[15] = static_cast <uint8_t> (tail);
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
		// Число целых слов накладываемой гаммы
		const size_t whole = (taken / 8);
		/**
		 * Выполняем наложение гаммы словами по восемь байтов: побайтовое наложение
		 * стоило столько же, сколько сама выработка гаммы машинными командами
		 */
		for(size_t i = 0; i < whole; i++){
			// Слово исходных данных
			uint64_t word = 0;
			// Слово гаммы
			uint64_t mask = 0;
			// Считываем слово исходных данных
			::memcpy(&word, cursor + (i * 8), 8);
			// Считываем слово гаммы
			::memcpy(&mask, gamma + (i * 8), 8);
			// Накладываем гамму на слово
			word ^= mask;
			// Записываем слово итога
			::memcpy(output + (i * 8), &word, 8);
		}
		/**
		 * Выполняем наложение гаммы на хвост, не кратный слову
		 */
		for(size_t i = (whole * 8); i < taken; i++)
			// Накладываем гамму на очередной байт
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
		twistX86(key, this->_mirror);
#endif
	// Старшее и младшее слова ключа хеширования
	uint64_t high = load(key), low = load(key + 8);
	// Выполняем затирание ключа хеширования
	wipe(key, sizeof(key));
	// Кратное нулю
	// Нулевое кратное ключа хеширования
	this->_table[0][0] = 0;
	// Нулевое кратное ключа хеширования
	this->_table[0][1] = 0;
	// Кратное ключа хеширования для старшего разряда байта
	this->_table[128][0] = high;
	// Кратное ключа хеширования для старшего разряда байта
	this->_table[128][1] = low;
	/**
	 * Выполняем выработку кратных для младших разрядов байта делением на x
	 */
	for(size_t i = 64; i > 0; i >>= 1){
		// Разряд, выносимый за край поля
		const uint64_t carry = (low & 0x01);
		// Делим младшую половину на x
		low = ((high << 63) | (low >> 1));
		// Делим старшую половину на x с приведением по многочлену поля
		high = ((high >> 1) ^ (carry ? 0xE100000000000000ULL : 0ULL));
		// Записываем кратное для очередного разряда
		this->_table[i][0] = high;
		// Записываем кратное для очередного разряда
		this->_table[i][1] = low;
	}
	/**
	 * Выполняем выработку остальных кратных сложением кратных разрядов
	 */
	for(size_t i = 2; i < 256; i <<= 1){
		for(size_t j = 1; j < i; j++){
			// Складываем кратные разрядов
			this->_table[i + j][0] = (this->_table[i][0] ^ this->_table[j][0]);
			// Складываем кратные разрядов
			this->_table[i + j][1] = (this->_table[i][1] ^ this->_table[j][1]);
		}
	}
	/**
	 * Выполняем выработку таблицы остатков: вынесенный за младший край байт
	 * возвращается в старшие разряды приведением по многочлену поля разряд за разрядом
	 */
	for(size_t i = 0; i < 256; i++){
		// Приводимое значение в старших разрядах
		uint64_t item = 0;
		// Вынесенный байт
		uint64_t rest = i;
		/**
		 * Выполняем приведение восьми разрядов
		 */
		for(size_t bit = 0; bit < 8; bit++){
			// Разряд, выносимый за край поля
			const uint64_t carry = (rest & 0x01);
			// Сдвигаем вынесенный байт
			rest >>= 1;
			// Приводим разряд по многочлену поля
			item = ((item >> 1) ^ (carry ? 0xE100000000000000ULL : 0ULL));
		}
		// Записываем старшие шестнадцать разрядов приведения
		this->_remainders[i] = static_cast <uint16_t> (item >> 48);
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
		store(this->_table[128][0], power);
		// Восстанавливаем ключ хеширования из кратного восьми таблицы
		store(this->_table[128][1], power + 8);
		/**
		 * Выполняем построение степеней от первой до восьмой: восемь блоков
		 * сворачиваются одним приведением
		 */
		for(size_t i = 0; i < 8; i++){
			// Если степень не первая
			if(i > 0)
				// Умножаем прежнюю степень на ключ
				this->multiply(power);
/**
 * Если есть ветвь машинного умножения PMULL
 */
#if defined(__ANTS_GHASH_ARM__)
			// Записываем степень отражённой: восьмая идёт первой
			mirrorArm(power, this->_powers[7 - i]);
#else
			// Записываем степень сдвинутой с суммой половин: восьмая идёт первой
			twistX86(power, this->_powers[7 - i]);
#endif
		}
		// Выполняем затирание степени
		wipe(power, sizeof(power));
	}
#endif
	// Запоминаем готовность режима: таблицы построены, начальный блок ставит смена заполнения
	this->_ready = true;
	// Выводим итог установки начального заполнения
	return this->restart(nonce);
}
/**
 * @brief Метод смены начального заполнения у запущенного режима
 *
 * @param nonce начальное заполнение любой ненулевой длины, 12 байтов - прямой путь
 *
 * @return      признак успешности смены
 *
 */
bool nts::cipher::Gcm::restart(const view_t & nonce) noexcept {
	// Если режим не запущен: таблиц кратных ключа хеширования нет
	if(!this->_ready)
		// Выводим отказ смены заполнения
		return false;
	// Если заполнение не передано
	if((nonce.data == nullptr) || (nonce.size == 0))
		// Выводим отказ смены заполнения
		return false;
	// Заполнение новое: прежнее израсходованным более не считается
	this->_spent = false;
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
	// Выводим успешность смены заполнения
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
	// Выполняем затирание таблицы остатков
	wipe(this->_remainders, sizeof(this->_remainders));
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
	// Раздел 5.2.1.1 NIST SP 800-38D: присоединённые данные не длиннее 2^64 - 1 разрядов - до поглощения, иначе поглотились бы байты сверх предела
	if((this->_associated + static_cast <uint64_t> (associated.size)) >= GCM_ASSOCIATED)
		// Выводим отказ
		return false;
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
	/**
	 * Раздел 5.2.1.1 NIST SP 800-38D: открытый текст не длиннее 2^39 - 256 разрядов
	 * (2^32 - 2 блоков), иначе 32-разрядный счётчик замыкается на J0 и гамма повторяется
	 */
	if((this->_sealed + static_cast <uint64_t> (source.size)) > GCM_MOST){
		// Останавливаем шифрование
		this->_stage = 3;
		// Выводим отказ
		return false;
	}
	if(!this->proceed(1))
		// Выводим отказ зашифрования
		return false;
	// Длина, пройденная слитым ядром
	size_t passed = 0;
	/**
	 * Целые восьмёрки блоков при выровненном потоке идут слитым ядром: гамма и хеш в
	 * одном проходе, остаток - порознь, как прежде
	 */
	if((this->_rest == 0) && (this->_filled == 0) && (source.size >= 128) && this->travel(true, source.data, result, (source.size / 128)))
		// Запоминаем длину, пройденную слитым ядром
		passed = ((source.size / 128) * 128);
	// Если остался хвост либо слитого ядра нет
	if(passed < source.size){
		// Если гамму наложить не удалось
		if(!this->cover(view_t(source.data + passed, source.size - passed), result + passed)){
			// Закрываем поток
			this->_stage = 3;
			// Выводим отказ зашифрования
			return false;
		}
		// Выполняем сложение шифртекста в накопитель
		this->absorb(result + passed, source.size - passed);
	}
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
	/**
	 * Раздел 5.2.1.1 NIST SP 800-38D: открытый текст не длиннее 2^39 - 256 разрядов
	 * (2^32 - 2 блоков), иначе 32-разрядный счётчик замыкается на J0 и гамма повторяется
	 */
	if((this->_sealed + static_cast <uint64_t> (source.size)) > GCM_MOST){
		// Останавливаем шифрование
		this->_stage = 3;
		// Выводим отказ
		return false;
	}
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
	// Длина, пройденная слитым ядром
	size_t passed = 0;
	/**
	 * Целые восьмёрки блоков при выровненном потоке идут слитым ядром: хеш от
	 * шифртекста и гамма в одном проходе, остаток - порознь, как прежде
	 */
	if((this->_rest == 0) && (this->_filled == 0) && (source.size >= 128) && this->travel(false, source.data, result, (source.size / 128)))
		// Запоминаем длину, пройденную слитым ядром
		passed = ((source.size / 128) * 128);
	// Выполняем сложение остатка шифртекста в накопитель
	this->absorb(source.data + passed, source.size - passed);
	// Увеличиваем длину шифртекста
	this->_sealed += static_cast <uint64_t> (source.size);
	// Если гамму с остатка снять не удалось
	if((passed < source.size) && !this->cover(view_t(source.data + passed, source.size - passed), result + passed)){
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
	// Раздел 5.2.1.1 NIST SP 800-38D: предел открытого текста и у одновызовного пути - поточный decrypt() здесь минуется
	if(static_cast <uint64_t> (source.size) > GCM_MOST)
		// Выводим отказ
		return false;
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
	// Выполняем затирание таблицы остатков
	wipe(this->_remainders, sizeof(this->_remainders));
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
