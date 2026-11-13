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
 *       Хеш пачками (круг 42, 28.09.2026): связанные данные и хвосты шли по восьмёрке на
 *       вызов с перестановкой накопителя на каждой и ядром на интринсиках в кодировке SSE
 *       (Xeon E5-2630 v4 5,2 ГБ/с при 6,3 у OpenSSL), а на машинах без умножения без
 *       переносов - по блоку через multiply с побайтовым сложением (стенды под QEMU
 *       210…270 МБ/с при 350 у gcm_ghash_4bit OpenSSL). Теперь восьмёрки идут циклом внутри
 *       ядра на ассемблере с кодировкой VEX конвейером: приведение прошлой восьмёрки идёт
 *       вперемешку с произведениями текущей, а блок с накопителем множится последним - без
 *       конвейера ядро упиралось в цепочку накопитель → произведение → приведение (50 тактов
 *       на восьмёрку при 24 умножениях по такту), с ним 40 при 37 у gcm_ghash_avx; табличный
 *       путь ведёт все целые блоки одним проходом с накопителем в двух словах регистров
 *       Сшитое ядро на ассемблере x86-64 (круг 38, 24.09.2026): собиратель выносил все
 *       умножения без переносов клубком после кругов AES и не давал переплести их с
 *       кругами, а на Broadwell перестановки байтов делят порт с aesenc. Ядро на
 *       ассемблере с кодировкой VEX хеширует прежнюю восьмёрку по блоку между кругами,
 *       переставляет половины блока загрузкой movbe через память и множит половины
 *       порознь без слияния и без Карацубы: Xeon E5-2630 v4 178 → 137 тактов на 128 байт
 *       при 142 у OpenSSL. Ядро требует AVX и MOVBE; без них остаётся ядро на интринсиках.
 *       Сшитые ядра из порождателя tools/cipher/gcm.py (круг 43, 28.09.2026): ядро x86-64
 *       переносит через младший байт счётчика само (редкая ветвь через скалярный регистр), и
 *       ход любой длины идёт одним вызовом вместо пробегов по тридцать одной восьмёрке с
 *       медленной восьмёркой и прологом на каждом - Xeon AES-128-GCM 112 → 106 тактов на
 *       128 байт при 104 у OpenSSL, AES-256-GCM 135 при 142; пробы на Broadwell с блоком с
 *       накопителем последним, перестановкой за круг до умножений, приведением прошлой
 *       восьмёрки вперемешку с произведениями, блоком одним регистром через vpshufb и
 *       предвыборкой выигрыша не дали и не взяты. Ядро AArch64 - новое: замер устройств
 *       Apple M4 показал, что пары aese+aesmc и pmull идут на одних устройствах и ход
 *       упирается в число команд и в цепочку приведения (AES-256 восьмёрки 40 тактов, хеш
 *       восьмёрки 40, слитно на интринсиках 62…71), потому блоки отражаются rbit,
 *       произведение Карацубы тремя pmull с суммой половин степени из таблицы, произведения
 *       пары блоков складываются в суммы разом (eor3 при FEAT_SHA3), суммы прошлой
 *       восьмёрки приводятся вперемешку с произведениями текущей, а блок с накопителем
 *       множится последним: M4 AES-128-GCM 13,4 → 10,9 нс на 128 байт при 12,2 у OpenSSL,
 *       AES-256-GCM 15,8 → 12,8 при 14,2
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
 * Подключаем внутренний модуль сшитых ядер AES-CTR + GHASH на ассемблере
 */
#include <internal/cipher/gcm.hpp>

/**
 * Если сборка ведётся под ARM64
 */
#if (defined(__aarch64__) || defined(__ANTS_MSVC_ARM64__)) && !defined(ANTS_NO_MACHINE)
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
	 * Если собиратель Microsoft Visual C++: внутренние функции расширения доступны ему без ключей
	 */
	#elif defined(_MSC_VER)
		/**
		 * Атрибута цели у собирателя нет, и он не нужен
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
	 * Если собиратель Microsoft Visual C++: его команда умножения без переносов принимает
	 * вектор из одного места, собранный из слова внутренней функцией
	 */
	#if defined(_MSC_VER)
		/**
		 * Умножение слова на слово без переносов командой PMULL
		 */
		#define __ANTS_PMULL64__(first, second) vmull_p64(vcreate_p64(first), vcreate_p64(second))
	/**
	 * У собирателей семейства GCC команда принимает слово в типе многочлена
	 */
	#else
		/**
		 * Умножение слова на слово без переносов командой PMULL
		 */
		#define __ANTS_PMULL64__(first, second) vmull_p64(static_cast <poly64_t> (first), static_cast <poly64_t> (second))
	#endif
/**
 * Если сборка ведётся под x86-64 собирателем семейства GCC
 */
#elif (defined(__x86_64__) || defined(__e2k__) || defined(__ANTS_MSVC_X64__)) && (defined(__GNUC__) || defined(__clang__) || defined(_MSC_VER)) && !defined(ANTS_NO_MACHINE)
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
	/**
	 * Если собиратель Microsoft Visual C++: внутренние функции расширения доступны ему без ключей
	 */
	#elif defined(_MSC_VER)
		/**
		 * Атрибута цели у собирателя нет, и он не нужен
		 */
		#define __ANTS_GHASH_TARGET__
	/**
	 * Иначе команды расширений разрешаем одной функции
	 */
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
	/**
	 * Если собиратель Microsoft Visual C++: внутренние функции расширения доступны ему без ключей
	 */
	#elif defined(_MSC_VER)
		/**
		 * Атрибута цели у собирателя нет, и он не нужен
		 */
		#define __ANTS_FUSED_TARGET__
	/**
	 * Иначе команды расширений слитого ядра разрешаем одной функции
	 */
	#else
		/**
		 * Разрешаем команды расширений слитого ядра одной функции
		 */
		#define __ANTS_FUSED_TARGET__ __attribute__((target("aes,pclmul,ssse3,sse2")))
	#endif
#endif


/**
 * Перестановка байтов слова: у собирателей семейства GCC это встроенная функция
 * собирателя, у Microsoft Visual C++ - внутренняя функция того же действия
 */
#if defined(_MSC_VER)
	/**
	 * Подключаем заголовочный файл внутренних функций перестановки байтов
	 */
	#include <cstdlib>

	/**
	 * Объявляем перестановку байтов слова в тридцать два разряда
	 */
	#define __ANTS_BSWAP32__(value) ::_byteswap_ulong(value)
	/**
	 * Объявляем перестановку байтов слова в шестьдесят четыре разряда
	 */
	#define __ANTS_BSWAP64__(value) ::_byteswap_uint64(value)
/**
 * Для собирателей семейства GCC и Эльбруса
 */
#else
	/**
	 * Объявляем перестановку байтов слова в тридцать два разряда
	 */
	#define __ANTS_BSWAP32__(value) __builtin_bswap32(value)
	/**
	 * Объявляем перестановку байтов слова в шестьдесят четыре разряда
	 */
	#define __ANTS_BSWAP64__(value) __builtin_bswap64(value)
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
		 * @brief Функция перестановки байтов блока от старшего к младшему
		 *
		 * @details Блок GCM читается от старшего байта, а команда умножения без переносов
		 *          считает слова от младшего: после перестановки разряды многочлена идут
		 *          в обратном порядке, и произведение переставленных операндов равно
		 *          переставленному произведению, сдвинутому на разряд вправо - сдвиг
		 *          возмещается ключом, хранимым сдвинутым на разряд влево
		 *
		 * @param value переставляемые байты
		 * @return      байты в обратном порядке
		 *
		 */
		static __ANTS_GHASH_TARGET__ __ANTS_INLINE__ __m128i swap(const __m128i value) noexcept {
			// Выводим байты в обратном порядке
			return _mm_shuffle_epi8(value, _mm_setr_epi8(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0));
		}
	#endif


	/**
	 * @brief Функция чтения слова в 64 разряда от старшего байта
	 *
	 * @param data читаемые байты
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
	 * @brief Функция записи слова в 64 разряда от старшего байта
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
	 * @brief Функция сличения двух областей байтов за постоянное время
	 *
	 * @param first  первая область
	 * @param second вторая область
	 * @param size   размер областей
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
	 * @brief Функция сложения целых блоков в накопитель умножением по байтовой таблице
	 *
	 * @details Накопитель держится двумя словами в регистрах на все блоки: блок складывается
	 *          с ним словами, и байты суммы дают пятнадцать шагов сдвига с приведением по
	 *          таблице остатков и сложением с кратным - те же шаги, что у умножения одного
	 *          значения, без записи и чтения накопителя на каждом блоке
	 *
	 * @param table       таблица кратных ключа хеширования по байту
	 * @param remainders  таблица остатков вынесенного байта
	 * @param accumulator накопитель многочлена в порядке GCM, заменяемый итогом
	 * @param blocks      блоки подряд
	 * @param count       число блоков: не меньше одного
	 *
	 */
	static void absorbTable(const uint64_t (* table)[2], const uint16_t * remainders, uint8_t * accumulator, const uint8_t * blocks, size_t count) noexcept {
		// Слова накопителя
		uint64_t zh = load(accumulator), zl = load(accumulator + 8);
		/**
		 * Выполняем перебор блоков
		 */
		for(; count > 0; count--, blocks += 16){
			// Слова суммы накопителя с блоком: старшее и младшее
			const uint64_t high = (zh ^ load(blocks)), low = (zl ^ load(blocks + 8));
			// Кратное последнего байта суммы
			zh = table[low & 0xFF][0];
			// Кратное последнего байта суммы
			zl = table[low & 0xFF][1];
			/**
			 * Выполняем пятнадцать шагов по байтам суммы от четырнадцатого к нулевому
			 */
			for(size_t index = 15; index > 0; index--){
				// Очередной байт суммы от старшего: младшее слово несёт байты с восьмого по пятнадцатый
				const size_t byte = static_cast <size_t> (((index > 8) ? (low >> ((16 - index) * 8)) : (high >> ((8 - index) * 8))) & 0xFF);
				// Вынесенный за младший край байт накопленного значения
				const uint8_t rem = static_cast <uint8_t> (zl);
				// Сдвигаем накопленное значение на байт
				zl = ((zh << 56) | (zl >> 8));
				// Сдвигаем старшую половину на байт
				zh >>= 8;
				// Приводим вынесенный байт по таблице остатков
				zh ^= (static_cast <uint64_t> (remainders[rem]) << 48);
				// Складываем с кратным очередного байта суммы
				zh ^= table[byte][0];
				// Складываем с кратным очередного байта суммы
				zl ^= table[byte][1];
			}
		}
		// Записываем старшую половину накопителя
		store(zh, accumulator);
		// Записываем младшую половину накопителя
		store(zl, accumulator + 8);
	}

	/**
	 * Если есть ветвь машинного умножения PMULL
	 */
	#if defined(__ANTS_GHASH_ARM__)
		/**
		 * @brief Функция записи ключа хеширования с отражёнными разрядами байтов
		 *
		 * @param key    ключ хеширования
		 * @param mirror место под три слова: отражённый ключ и сумма его половин
		 *
		 */
		static __ANTS_GHASH_TARGET__ void mirrorArm(const uint8_t * key, uint64_t * mirror) noexcept {
			// Записываем ключ хеширования с отражёнными разрядами байтов
			vst1q_u64(mirror, vreinterpretq_u64_u8(vrbitq_u8(vld1q_u8(key))));
			// Записываем сумму половин ключа под умножение Карацубы сшитого ядра
			mirror[2] = (mirror[0] ^ mirror[1]);
		}
		/**
		 * @brief Функция умножения значения на ключ хеширования командой PMULL
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
			const uint64_t r = 0x87ULL;
			// Произведение младших половин
			const uint64x2_t p0 = vreinterpretq_u64_p128(__ANTS_PMULL64__(vgetq_lane_u64(a, 0), vgetq_lane_u64(b, 0)));
			// Произведение старших половин
			const uint64x2_t p2 = vreinterpretq_u64_p128(__ANTS_PMULL64__(vgetq_lane_u64(a, 1), vgetq_lane_u64(b, 1)));
			// Перекрёстные произведения
			const uint64x2_t p1 = veorq_u64(
			vreinterpretq_u64_p128(__ANTS_PMULL64__(vgetq_lane_u64(a, 0), vgetq_lane_u64(b, 1))),
			vreinterpretq_u64_p128(__ANTS_PMULL64__(vgetq_lane_u64(a, 1), vgetq_lane_u64(b, 0))));
			// Младшие 128 разрядов произведения: p0 с младшей половиной p1, сдвинутой на 64
			uint64x2_t low = veorq_u64(p0, vextq_u64(vdupq_n_u64(0), p1, 1));
			// Старшие 128 разрядов произведения: p2 со старшей половиной p1
			const uint64x2_t high = veorq_u64(p2, vextq_u64(p1, vdupq_n_u64(0), 1));
			// Приведение старшей половины: младшее слово, умноженное на многочлен
			const uint64x2_t f0 = vreinterpretq_u64_p128(__ANTS_PMULL64__(vgetq_lane_u64(high, 0), r));
			// Приведение старшей половины: старшее слово, умноженное на многочлен
			const uint64x2_t f1 = vreinterpretq_u64_p128(__ANTS_PMULL64__(vgetq_lane_u64(high, 1), r));
			// Складываем приведение младшего слова
			low = veorq_u64(low, f0);
			// Складываем младшую половину приведения старшего слова, сдвинутую на 64
			low = veorq_u64(low, vextq_u64(vdupq_n_u64(0), f1, 1));
			// Остаток приведения старшего слова, ушедший за 128 разрядов, приводится ещё раз
			low = veorq_u64(low, vreinterpretq_u64_p128(__ANTS_PMULL64__(vgetq_lane_u64(f1, 1), r)));
			// Записываем произведение, отразив разряды байтов обратно в порядок GCM
			vst1q_u8(value, vrbitq_u8(vreinterpretq_u8_u64(low)));
		}
		/**
		 * @brief Функция неприведённого умножения двух отражённых многочленов
		 *
		 * @param a    первый множитель
		 * @param b    второй множитель
		 * @param low  младшие 128 разрядов произведения, складываемые с накопленными
		 * @param high старшие 128 разрядов произведения, складываемые с накопленными
		 *
		 */
		static __ANTS_GHASH_TARGET__ __ANTS_INLINE__ void productArm(const uint64x2_t a, const uint64x2_t b, uint64x2_t & low, uint64x2_t & high) noexcept {
			// Произведение младших половин
			const uint64x2_t p0 = vreinterpretq_u64_p128(__ANTS_PMULL64__(vgetq_lane_u64(a, 0), vgetq_lane_u64(b, 0)));
			// Произведение старших половин
			const uint64x2_t p2 = vreinterpretq_u64_p128(__ANTS_PMULL64__(vgetq_lane_u64(a, 1), vgetq_lane_u64(b, 1)));
			// Перекрёстные произведения
			const uint64x2_t p1 = veorq_u64(
			vreinterpretq_u64_p128(__ANTS_PMULL64__(vgetq_lane_u64(a, 0), vgetq_lane_u64(b, 1))),
			vreinterpretq_u64_p128(__ANTS_PMULL64__(vgetq_lane_u64(a, 1), vgetq_lane_u64(b, 0))));
			// Складываем младшие 128 разрядов
			low = veorq_u64(low, veorq_u64(p0, vextq_u64(vdupq_n_u64(0), p1, 1)));
			// Складываем старшие 128 разрядов
			high = veorq_u64(high, veorq_u64(p2, vextq_u64(p1, vdupq_n_u64(0), 1)));
		}
		/**
		 * @brief Функция сложения восьми блоков в накопитель одним приведением командой PMULL
		 *
		 * @param powers      степени ключа хеширования от четвёртой до первой, отражённые
		 * @param accumulator накопитель многочлена, заменяемый итогом
		 * @param blocks      восемь блоков подряд
		 *
		 */
		static __ANTS_GHASH_TARGET__ void aggregateArm(const uint64_t (* powers)[3], uint8_t * accumulator, const uint8_t * blocks) noexcept {
			// Многочлен приведения x^7 + x^2 + x + 1
			const uint64_t r = 0x87ULL;
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
			const uint64x2_t f0 = vreinterpretq_u64_p128(__ANTS_PMULL64__(vgetq_lane_u64(high, 0), r));
			// Приведение старшей половины: старшее слово, умноженное на многочлен
			const uint64x2_t f1 = vreinterpretq_u64_p128(__ANTS_PMULL64__(vgetq_lane_u64(high, 1), r));
			// Складываем приведение младшего слова
			low = veorq_u64(low, f0);
			// Складываем младшую половину приведения старшего слова, сдвинутую на 64
			low = veorq_u64(low, vextq_u64(vdupq_n_u64(0), f1, 1));
			// Остаток приведения старшего слова, ушедший за 128 разрядов, приводится ещё раз
			low = veorq_u64(low, vreinterpretq_u64_p128(__ANTS_PMULL64__(vgetq_lane_u64(f1, 1), r)));
			// Записываем итог, отразив разряды байтов обратно
			vst1q_u8(accumulator, vrbitq_u8(vreinterpretq_u8_u64(low)));
		}
		/**
		 * @brief Функция слитого хода режима: гамма счётчика AES и хеш GHASH по восемь блоков в одном проходе
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
			// Двойной шаг счётчика
			const uint32x4_t step2 = vaddq_u32(step1, step1);
			// Сдвоенный шаг счётчика
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
				// Складываем источник с накопителем хеша
				aggregateArm(powers, accumulator, source);
				// При зашифровании хеш берётся от шифртекста прежней восьмёрки
				else if(c > 0)
				// Складываем шифртекст прежней восьмёрки с накопителем
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
					const uint32x4_t c0 = vaddq_u32(vsetq_lane_u32(__ANTS_BSWAP32__(tail), vreinterpretq_u32_u8(base), 3), step1);
					// Счётчик восьмёрки со сдвигом на шаг
					const uint32x4_t c1 = vaddq_u32(c0, step1);
					// Счётчик восьмёрки со сдвигом на два шага
					const uint32x4_t c2 = vaddq_u32(c0, step2);
					// Счётчик восьмёрки со сдвигом на три шага
					const uint32x4_t c3 = vaddq_u32(c1, step2);
					// Собираем восемь блоков счётчика сложениями
					s0 = vreinterpretq_u8_u32(c0);
					// второй блок счётчика сложением
					s1 = vreinterpretq_u8_u32(c1);
					// третий блок счётчика сложением
					s2 = vreinterpretq_u8_u32(c2);
					// четвёртый блок счётчика сложением
					s3 = vreinterpretq_u8_u32(c3);
					// пятый блок счётчика сложением
					s4 = vreinterpretq_u8_u32(vaddq_u32(c0, step4));
					// шестой блок счётчика сложением
					s5 = vreinterpretq_u8_u32(vaddq_u32(c1, step4));
					// седьмой блок счётчика сложением
					s6 = vreinterpretq_u8_u32(vaddq_u32(c2, step4));
					// восьмой блок счётчика сложением
					s7 = vreinterpretq_u8_u32(vaddq_u32(c3, step4));
				// Иначе младший байт переполняется внутри восьмёрки
				} else {
					// Собираем восемь блоков счётчика по одному
					s0 = vreinterpretq_u8_u32(vsetq_lane_u32(__ANTS_BSWAP32__(tail + 1), vreinterpretq_u32_u8(base), 3));
					// второй блок счётчика через скаляр
					s1 = vreinterpretq_u8_u32(vsetq_lane_u32(__ANTS_BSWAP32__(tail + 2), vreinterpretq_u32_u8(base), 3));
					// третий блок счётчика через скаляр
					s2 = vreinterpretq_u8_u32(vsetq_lane_u32(__ANTS_BSWAP32__(tail + 3), vreinterpretq_u32_u8(base), 3));
					// четвёртый блок счётчика через скаляр
					s3 = vreinterpretq_u8_u32(vsetq_lane_u32(__ANTS_BSWAP32__(tail + 4), vreinterpretq_u32_u8(base), 3));
					// пятый блок счётчика через скаляр
					s4 = vreinterpretq_u8_u32(vsetq_lane_u32(__ANTS_BSWAP32__(tail + 5), vreinterpretq_u32_u8(base), 3));
					// шестой блок счётчика через скаляр
					s5 = vreinterpretq_u8_u32(vsetq_lane_u32(__ANTS_BSWAP32__(tail + 6), vreinterpretq_u32_u8(base), 3));
					// седьмой блок счётчика через скаляр
					s6 = vreinterpretq_u8_u32(vsetq_lane_u32(__ANTS_BSWAP32__(tail + 7), vreinterpretq_u32_u8(base), 3));
					// восьмой блок счётчика через скаляр
					s7 = vreinterpretq_u8_u32(vsetq_lane_u32(__ANTS_BSWAP32__(tail + 8), vreinterpretq_u32_u8(base), 3));
				}
				// Продвигаем счётчик на восемь блоков
				tail += 8;
				/**
				 * Выполняем круги подстановки
				 */
				for(size_t round = 0; (round + 1) < rounds; round++){
					// Ключ круга
					const uint8x16_t key = vld1q_u8(keys + (round * 16));
					// первый блок на круге подстановки
					s0 = vaesmcq_u8(vaeseq_u8(s0, key));
					// второй блок на круге подстановки
					s1 = vaesmcq_u8(vaeseq_u8(s1, key));
					// третий блок на круге подстановки
					s2 = vaesmcq_u8(vaeseq_u8(s2, key));
					// четвёртый блок на круге подстановки
					s3 = vaesmcq_u8(vaeseq_u8(s3, key));
					// пятый блок на круге подстановки
					s4 = vaesmcq_u8(vaeseq_u8(s4, key));
					// шестой блок на круге подстановки
					s5 = vaesmcq_u8(vaeseq_u8(s5, key));
					// седьмой блок на круге подстановки
					s6 = vaesmcq_u8(vaeseq_u8(s6, key));
					// восьмой блок на круге подстановки
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
				// Сдвигаем место записи итога на восьмёрку
				result += 128;
			}
			// При зашифровании хеш последней восьмёрки шифртекста берётся после цикла
			if(sealing)
			// Складываем шифртекст последней восьмёрки с накопителем
			aggregateArm(powers, accumulator, result - 128);
			// Записываем продвинутый счётчик
			counter[12] = static_cast <uint8_t> (tail >> 24);
			// Записываем продвинутый счётчик дальше
			counter[13] = static_cast <uint8_t> (tail >> 16);
			// Записываем продвинутый счётчик ещё дальше
			counter[14] = static_cast <uint8_t> (tail >> 8);
			// Записываем младший байт продвинутого счётчика
			counter[15] = static_cast <uint8_t> (tail);
		}
	/**
	 * Если есть ветвь машинного умножения PCLMULQDQ
	 */
	#elif defined(__ANTS_GHASH_X86__)
		/**
		 * @brief Функция записи ключа хеширования в виде под команду PCLMULQDQ
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
		 * @brief Функция умножения Карацубы двух переставленных многочленов без приведения
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
		 * @brief Функция приведения суммы произведений по многочлену поля в переставленном виде
		 *
		 * @details Средние произведения Карацубы складываются с крайними и делятся между
		 *          половинами, затем старшая половина сворачивается в младшую: умножение
		 *          на x^7 + x^2 + x + 1 в переставленном виде - это сдвиги на 63, 62 и 57
		 *          разрядов влево и на 1, 2 и 7 вправо по словам с переносом между словами
		 *
		 * @param low    сумма произведений младших половин
		 * @param high   сумма произведений старших половин
		 * @param middle сумма произведений сумм половин
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
		 * @brief Функция умножения значения на ключ хеширования командой PCLMULQDQ
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
		 * @brief Функция сложения восьми блоков в накопитель одним приведением командой PCLMULQDQ
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
		 * Если собиратель семейства GCC под x86-64: ядро сложения восьмёрок на ассемблере
		 */
		#if(defined(__GNUC__) || defined(__clang__)) && defined(__x86_64__)
			/**
			 * @brief Функция сложения восьмёрок блоков в накопитель ядром на ассемблере с кодировкой VEX
			 *
			 * @details Восьмёрки идут циклом внутри вставки конвейером, как у gcm_ghash_avx OpenSSL:
			 *          блок множится на степень ключа умножением Карацубы тремя командами, суммы
			 *          младших, старших и средних произведений копятся на восьмёрку, а приводятся на
			 *          следующей - вперемешку с её произведениями, двумя умножениями на многочлен и
			 *          перестановками слов; блок с накопителем идёт в восьмёрке последним, оттого
			 *          цепочка зависимости через накопитель короче пропускной способности умножений.
			 *          Накопитель живёт в регистре переставленным и переставляется обратно один раз
			 *          на выходе. Ядро требует AVX и PCLMULQDQ; без AVX остаётся ядро на интринсиках
			 *
			 * @param powers      степени ключа хеширования от восьмой до первой, сдвинутые, с суммами половин
			 * @param accumulator накопитель многочлена в порядке GCM, заменяемый итогом
			 * @param blocks      восьмёрки блоков подряд
			 * @param count       число восьмёрок: не меньше одной
			 *
			 */
			static void aggregateVexX86(const uint64_t (* powers)[3], uint8_t * accumulator, const uint8_t * blocks, size_t count) noexcept {
				// Маска перестановки байтов от старшего к младшему
				alignas(16) static const uint8_t SWAP[16] = {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0};
				// Многочлен приведения в переставленном виде: x^63 + x^62 + x^57 старшим словом
				alignas(16) static const uint64_t POLY[2] = {1, 0xC200000000000000ULL};
				/**
				 * Выполняем сложение: регистры 0 и 1 - блоки попеременно, 2 и 3 - суммы половин блоков,
				 * 4 - произведение, 5…7 - суммы прошлой восьмёрки на приведении, 8…10 - суммы текущей,
				 * 11 - сумма половин степени, 12 - временный, 13 - многочлен, 14 - накопитель, 15 - маска
				 */
				__asm__ __volatile__ (
				// Маска перестановки, многочлен приведения, накопитель переставленный
				"vmovdqa (%[mask]), %%xmm15\n\t" "vmovdqa (%[poly]), %%xmm13\n\t" "vmovdqu (%[acc]), %%xmm14\n\t" "vpshufb %%xmm15, %%xmm14, %%xmm14\n\t"
				// Первая восьмёрка: произведения без приведения, блок с накопителем последним
				// Блок 7: перестановка байтов, сумма половин, произведения со степенью 1 прямо в суммы
				"vmovdqu 112(%[blk]), %%xmm1\n\t" "vpshufb %%xmm15, %%xmm1, %%xmm1\n\t"
				"vpshufd $0x4E, %%xmm1, %%xmm3\n\t" "vpxor %%xmm1, %%xmm3, %%xmm3\n\t" "vmovddup 184(%[pow]), %%xmm11\n\t"
				"vpclmulqdq $0x00, 168(%[pow]), %%xmm1, %%xmm8\n\t" "vpclmulqdq $0x11, 168(%[pow]), %%xmm1, %%xmm9\n\t" "vpclmulqdq $0x00, %%xmm11, %%xmm3, %%xmm10\n\t"
				// Блок 6: перестановка байтов, сумма половин, произведения со степенью 2
				"vmovdqu 96(%[blk]), %%xmm0\n\t" "vpshufb %%xmm15, %%xmm0, %%xmm0\n\t"
				"vpshufd $0x4E, %%xmm0, %%xmm2\n\t" "vpxor %%xmm0, %%xmm2, %%xmm2\n\t" "vmovddup 160(%[pow]), %%xmm11\n\t"
				"vpclmulqdq $0x00, 144(%[pow]), %%xmm0, %%xmm4\n\t" "vpxor %%xmm4, %%xmm8, %%xmm8\n\t" "vpclmulqdq $0x11, 144(%[pow]), %%xmm0, %%xmm4\n\t" "vpxor %%xmm4, %%xmm9, %%xmm9\n\t" "vpclmulqdq $0x00, %%xmm11, %%xmm2, %%xmm4\n\t" "vpxor %%xmm4, %%xmm10, %%xmm10\n\t"
				// Блок 5: перестановка байтов, сумма половин, произведения со степенью 3
				"vmovdqu 80(%[blk]), %%xmm1\n\t" "vpshufb %%xmm15, %%xmm1, %%xmm1\n\t"
				"vpshufd $0x4E, %%xmm1, %%xmm3\n\t" "vpxor %%xmm1, %%xmm3, %%xmm3\n\t" "vmovddup 136(%[pow]), %%xmm11\n\t"
				"vpclmulqdq $0x00, 120(%[pow]), %%xmm1, %%xmm4\n\t" "vpxor %%xmm4, %%xmm8, %%xmm8\n\t" "vpclmulqdq $0x11, 120(%[pow]), %%xmm1, %%xmm4\n\t" "vpxor %%xmm4, %%xmm9, %%xmm9\n\t" "vpclmulqdq $0x00, %%xmm11, %%xmm3, %%xmm4\n\t" "vpxor %%xmm4, %%xmm10, %%xmm10\n\t"
				// Блок 4: перестановка байтов, сумма половин, произведения со степенью 4
				"vmovdqu 64(%[blk]), %%xmm0\n\t" "vpshufb %%xmm15, %%xmm0, %%xmm0\n\t"
				"vpshufd $0x4E, %%xmm0, %%xmm2\n\t" "vpxor %%xmm0, %%xmm2, %%xmm2\n\t" "vmovddup 112(%[pow]), %%xmm11\n\t"
				"vpclmulqdq $0x00, 96(%[pow]), %%xmm0, %%xmm4\n\t" "vpxor %%xmm4, %%xmm8, %%xmm8\n\t" "vpclmulqdq $0x11, 96(%[pow]), %%xmm0, %%xmm4\n\t" "vpxor %%xmm4, %%xmm9, %%xmm9\n\t" "vpclmulqdq $0x00, %%xmm11, %%xmm2, %%xmm4\n\t" "vpxor %%xmm4, %%xmm10, %%xmm10\n\t"
				// Блок 3: перестановка байтов, сумма половин, произведения со степенью 5
				"vmovdqu 48(%[blk]), %%xmm1\n\t" "vpshufb %%xmm15, %%xmm1, %%xmm1\n\t"
				"vpshufd $0x4E, %%xmm1, %%xmm3\n\t" "vpxor %%xmm1, %%xmm3, %%xmm3\n\t" "vmovddup 88(%[pow]), %%xmm11\n\t"
				"vpclmulqdq $0x00, 72(%[pow]), %%xmm1, %%xmm4\n\t" "vpxor %%xmm4, %%xmm8, %%xmm8\n\t" "vpclmulqdq $0x11, 72(%[pow]), %%xmm1, %%xmm4\n\t" "vpxor %%xmm4, %%xmm9, %%xmm9\n\t" "vpclmulqdq $0x00, %%xmm11, %%xmm3, %%xmm4\n\t" "vpxor %%xmm4, %%xmm10, %%xmm10\n\t"
				// Блок 2: перестановка байтов, сумма половин, произведения со степенью 6
				"vmovdqu 32(%[blk]), %%xmm0\n\t" "vpshufb %%xmm15, %%xmm0, %%xmm0\n\t"
				"vpshufd $0x4E, %%xmm0, %%xmm2\n\t" "vpxor %%xmm0, %%xmm2, %%xmm2\n\t" "vmovddup 64(%[pow]), %%xmm11\n\t"
				"vpclmulqdq $0x00, 48(%[pow]), %%xmm0, %%xmm4\n\t" "vpxor %%xmm4, %%xmm8, %%xmm8\n\t" "vpclmulqdq $0x11, 48(%[pow]), %%xmm0, %%xmm4\n\t" "vpxor %%xmm4, %%xmm9, %%xmm9\n\t" "vpclmulqdq $0x00, %%xmm11, %%xmm2, %%xmm4\n\t" "vpxor %%xmm4, %%xmm10, %%xmm10\n\t"
				// Блок 1: перестановка байтов, сумма половин, произведения со степенью 7
				"vmovdqu 16(%[blk]), %%xmm1\n\t" "vpshufb %%xmm15, %%xmm1, %%xmm1\n\t"
				"vpshufd $0x4E, %%xmm1, %%xmm3\n\t" "vpxor %%xmm1, %%xmm3, %%xmm3\n\t" "vmovddup 40(%[pow]), %%xmm11\n\t"
				"vpclmulqdq $0x00, 24(%[pow]), %%xmm1, %%xmm4\n\t" "vpxor %%xmm4, %%xmm8, %%xmm8\n\t" "vpclmulqdq $0x11, 24(%[pow]), %%xmm1, %%xmm4\n\t" "vpxor %%xmm4, %%xmm9, %%xmm9\n\t" "vpclmulqdq $0x00, %%xmm11, %%xmm3, %%xmm4\n\t" "vpxor %%xmm4, %%xmm10, %%xmm10\n\t"
				// Блок 0: перестановка байтов и сложение с накопителем, сумма половин, произведения со степенью 8
				"vmovdqu 0(%[blk]), %%xmm0\n\t" "vpshufb %%xmm15, %%xmm0, %%xmm0\n\t" "vpxor %%xmm14, %%xmm0, %%xmm0\n\t"
				"vpshufd $0x4E, %%xmm0, %%xmm2\n\t" "vpxor %%xmm0, %%xmm2, %%xmm2\n\t" "vmovddup 16(%[pow]), %%xmm11\n\t"
				"vpclmulqdq $0x00, 0(%[pow]), %%xmm0, %%xmm4\n\t" "vpxor %%xmm4, %%xmm8, %%xmm8\n\t" "vpclmulqdq $0x11, 0(%[pow]), %%xmm0, %%xmm4\n\t" "vpxor %%xmm4, %%xmm9, %%xmm9\n\t" "vpclmulqdq $0x00, %%xmm11, %%xmm2, %%xmm4\n\t" "vpxor %%xmm4, %%xmm10, %%xmm10\n\t"
				"addq $128, %[blk]\n\t" "decq %[cnt]\n\t" "jz 2f\n\t"
				"1:\n\t"
				// Суммы прошлой восьмёрки в регистры 5…7, приведение их идёт вперемешку с произведениями текущей
				"vmovdqa %%xmm8, %%xmm5\n\t" "vmovdqa %%xmm9, %%xmm6\n\t" "vmovdqa %%xmm10, %%xmm7\n\t"
				// Блок 7: перестановка байтов, сумма половин, произведения со степенью 1 прямо в суммы
				"vmovdqu 112(%[blk]), %%xmm1\n\t" "vpshufb %%xmm15, %%xmm1, %%xmm1\n\t"
				"vpshufd $0x4E, %%xmm1, %%xmm3\n\t" "vpxor %%xmm1, %%xmm3, %%xmm3\n\t" "vmovddup 184(%[pow]), %%xmm11\n\t"
				"vpclmulqdq $0x00, 168(%[pow]), %%xmm1, %%xmm8\n\t" "vpclmulqdq $0x11, 168(%[pow]), %%xmm1, %%xmm9\n\t" "vpclmulqdq $0x00, %%xmm11, %%xmm3, %%xmm10\n\t"
				// Приведение прошлой восьмёрки: поправка Карацубы
				"vpxor %%xmm5, %%xmm7, %%xmm7\n\t" "vpxor %%xmm6, %%xmm7, %%xmm7\n\t"
				// Блок 6: перестановка байтов, сумма половин, произведения со степенью 2
				"vmovdqu 96(%[blk]), %%xmm0\n\t" "vpshufb %%xmm15, %%xmm0, %%xmm0\n\t"
				"vpshufd $0x4E, %%xmm0, %%xmm2\n\t" "vpxor %%xmm0, %%xmm2, %%xmm2\n\t" "vmovddup 160(%[pow]), %%xmm11\n\t"
				"vpclmulqdq $0x00, 144(%[pow]), %%xmm0, %%xmm4\n\t" "vpxor %%xmm4, %%xmm8, %%xmm8\n\t" "vpclmulqdq $0x11, 144(%[pow]), %%xmm0, %%xmm4\n\t" "vpxor %%xmm4, %%xmm9, %%xmm9\n\t" "vpclmulqdq $0x00, %%xmm11, %%xmm2, %%xmm4\n\t" "vpxor %%xmm4, %%xmm10, %%xmm10\n\t"
				// Раздача средних произведений по половинам
				"vpslldq $8, %%xmm7, %%xmm12\n\t" "vpxor %%xmm12, %%xmm5, %%xmm5\n\t" "vpsrldq $8, %%xmm7, %%xmm12\n\t" "vpxor %%xmm12, %%xmm6, %%xmm6\n\t"
				// Блок 5: перестановка байтов, сумма половин, произведения со степенью 3
				"vmovdqu 80(%[blk]), %%xmm1\n\t" "vpshufb %%xmm15, %%xmm1, %%xmm1\n\t"
				"vpshufd $0x4E, %%xmm1, %%xmm3\n\t" "vpxor %%xmm1, %%xmm3, %%xmm3\n\t" "vmovddup 136(%[pow]), %%xmm11\n\t"
				"vpclmulqdq $0x00, 120(%[pow]), %%xmm1, %%xmm4\n\t" "vpxor %%xmm4, %%xmm8, %%xmm8\n\t" "vpclmulqdq $0x11, 120(%[pow]), %%xmm1, %%xmm4\n\t" "vpxor %%xmm4, %%xmm9, %%xmm9\n\t" "vpclmulqdq $0x00, %%xmm11, %%xmm3, %%xmm4\n\t" "vpxor %%xmm4, %%xmm10, %%xmm10\n\t"
				// Первая ступень: младшее слово на многочлен x^63 + x^62 + x^57
				"vpclmulqdq $0x10, %%xmm13, %%xmm5, %%xmm12\n\t"
				// Блок 4: перестановка байтов, сумма половин, произведения со степенью 4
				"vmovdqu 64(%[blk]), %%xmm0\n\t" "vpshufb %%xmm15, %%xmm0, %%xmm0\n\t"
				"vpshufd $0x4E, %%xmm0, %%xmm2\n\t" "vpxor %%xmm0, %%xmm2, %%xmm2\n\t" "vmovddup 112(%[pow]), %%xmm11\n\t"
				"vpclmulqdq $0x00, 96(%[pow]), %%xmm0, %%xmm4\n\t" "vpxor %%xmm4, %%xmm8, %%xmm8\n\t" "vpclmulqdq $0x11, 96(%[pow]), %%xmm0, %%xmm4\n\t" "vpxor %%xmm4, %%xmm9, %%xmm9\n\t" "vpclmulqdq $0x00, %%xmm11, %%xmm2, %%xmm4\n\t" "vpxor %%xmm4, %%xmm10, %%xmm10\n\t"
				// Перестановка слов и сложение
				"vpalignr $8, %%xmm5, %%xmm5, %%xmm5\n\t" "vpxor %%xmm12, %%xmm5, %%xmm5\n\t"
				// Блок 3: перестановка байтов, сумма половин, произведения со степенью 5
				"vmovdqu 48(%[blk]), %%xmm1\n\t" "vpshufb %%xmm15, %%xmm1, %%xmm1\n\t"
				"vpshufd $0x4E, %%xmm1, %%xmm3\n\t" "vpxor %%xmm1, %%xmm3, %%xmm3\n\t" "vmovddup 88(%[pow]), %%xmm11\n\t"
				"vpclmulqdq $0x00, 72(%[pow]), %%xmm1, %%xmm4\n\t" "vpxor %%xmm4, %%xmm8, %%xmm8\n\t" "vpclmulqdq $0x11, 72(%[pow]), %%xmm1, %%xmm4\n\t" "vpxor %%xmm4, %%xmm9, %%xmm9\n\t" "vpclmulqdq $0x00, %%xmm11, %%xmm3, %%xmm4\n\t" "vpxor %%xmm4, %%xmm10, %%xmm10\n\t"
				// Вторая ступень
				"vpclmulqdq $0x10, %%xmm13, %%xmm5, %%xmm12\n\t"
				// Блок 2: перестановка байтов, сумма половин, произведения со степенью 6
				"vmovdqu 32(%[blk]), %%xmm0\n\t" "vpshufb %%xmm15, %%xmm0, %%xmm0\n\t"
				"vpshufd $0x4E, %%xmm0, %%xmm2\n\t" "vpxor %%xmm0, %%xmm2, %%xmm2\n\t" "vmovddup 64(%[pow]), %%xmm11\n\t"
				"vpclmulqdq $0x00, 48(%[pow]), %%xmm0, %%xmm4\n\t" "vpxor %%xmm4, %%xmm8, %%xmm8\n\t" "vpclmulqdq $0x11, 48(%[pow]), %%xmm0, %%xmm4\n\t" "vpxor %%xmm4, %%xmm9, %%xmm9\n\t" "vpclmulqdq $0x00, %%xmm11, %%xmm2, %%xmm4\n\t" "vpxor %%xmm4, %%xmm10, %%xmm10\n\t"
				// Перестановка слов и сложение
				"vpalignr $8, %%xmm5, %%xmm5, %%xmm5\n\t" "vpxor %%xmm12, %%xmm5, %%xmm5\n\t"
				// Блок 1: перестановка байтов, сумма половин, произведения со степенью 7
				"vmovdqu 16(%[blk]), %%xmm1\n\t" "vpshufb %%xmm15, %%xmm1, %%xmm1\n\t"
				"vpshufd $0x4E, %%xmm1, %%xmm3\n\t" "vpxor %%xmm1, %%xmm3, %%xmm3\n\t" "vmovddup 40(%[pow]), %%xmm11\n\t"
				"vpclmulqdq $0x00, 24(%[pow]), %%xmm1, %%xmm4\n\t" "vpxor %%xmm4, %%xmm8, %%xmm8\n\t" "vpclmulqdq $0x11, 24(%[pow]), %%xmm1, %%xmm4\n\t" "vpxor %%xmm4, %%xmm9, %%xmm9\n\t" "vpclmulqdq $0x00, %%xmm11, %%xmm3, %%xmm4\n\t" "vpxor %%xmm4, %%xmm10, %%xmm10\n\t"
				// Накопитель: старшая половина, сложенная с приведённой младшей
				"vpxor %%xmm6, %%xmm5, %%xmm14\n\t"
				// Блок 0: перестановка байтов и сложение с накопителем, сумма половин, произведения со степенью 8
				"vmovdqu 0(%[blk]), %%xmm0\n\t" "vpshufb %%xmm15, %%xmm0, %%xmm0\n\t" "vpxor %%xmm14, %%xmm0, %%xmm0\n\t"
				"vpshufd $0x4E, %%xmm0, %%xmm2\n\t" "vpxor %%xmm0, %%xmm2, %%xmm2\n\t" "vmovddup 16(%[pow]), %%xmm11\n\t"
				"vpclmulqdq $0x00, 0(%[pow]), %%xmm0, %%xmm4\n\t" "vpxor %%xmm4, %%xmm8, %%xmm8\n\t" "vpclmulqdq $0x11, 0(%[pow]), %%xmm0, %%xmm4\n\t" "vpxor %%xmm4, %%xmm9, %%xmm9\n\t" "vpclmulqdq $0x00, %%xmm11, %%xmm2, %%xmm4\n\t" "vpxor %%xmm4, %%xmm10, %%xmm10\n\t"
				"addq $128, %[blk]\n\t" "decq %[cnt]\n\t" "jnz 1b\n\t"
				"2:\n\t"
				// Приведение последней восьмёрки
				"vmovdqa %%xmm8, %%xmm5\n\t" "vmovdqa %%xmm9, %%xmm6\n\t" "vmovdqa %%xmm10, %%xmm7\n\t"
				// Приведение прошлой восьмёрки: поправка Карацубы
				"vpxor %%xmm5, %%xmm7, %%xmm7\n\t" "vpxor %%xmm6, %%xmm7, %%xmm7\n\t"
				// Раздача средних произведений по половинам
				"vpslldq $8, %%xmm7, %%xmm12\n\t" "vpxor %%xmm12, %%xmm5, %%xmm5\n\t" "vpsrldq $8, %%xmm7, %%xmm12\n\t" "vpxor %%xmm12, %%xmm6, %%xmm6\n\t"
				// Первая ступень: младшее слово на многочлен x^63 + x^62 + x^57
				"vpclmulqdq $0x10, %%xmm13, %%xmm5, %%xmm12\n\t"
				// Перестановка слов и сложение
				"vpalignr $8, %%xmm5, %%xmm5, %%xmm5\n\t" "vpxor %%xmm12, %%xmm5, %%xmm5\n\t"
				// Вторая ступень
				"vpclmulqdq $0x10, %%xmm13, %%xmm5, %%xmm12\n\t"
				// Перестановка слов и сложение
				"vpalignr $8, %%xmm5, %%xmm5, %%xmm5\n\t" "vpxor %%xmm12, %%xmm5, %%xmm5\n\t"
				// Накопитель: старшая половина, сложенная с приведённой младшей
				"vpxor %%xmm6, %%xmm5, %%xmm14\n\t"
				// Накопитель обратно в порядок байтов GCM
				"vpshufb %%xmm15, %%xmm14, %%xmm14\n\t" "vmovdqu %%xmm14, (%[acc])\n\t"
				: [blk] "+r" (blocks), [cnt] "+r" (count)
				: [pow] "r" (powers), [acc] "r" (accumulator), [mask] "r" (SWAP), [poly] "r" (POLY)
				: "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15", "cc", "memory"
				);
			}
		#endif
		/**
		 * @brief Функция слитого хода режима: гамма счётчика AES-NI и хеш GHASH по восемь блоков в одном проходе
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
			// Двойной шаг счётчика
			const __m128i step2 = _mm_add_epi32(step1, step1);
			// Сдвоенный шаг счётчика
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
				// Складываем источник с накопителем хеша
				aggregateX86(powers, accumulator, source);
				// При зашифровании хеш берётся от шифртекста прежней восьмёрки
				else if(c > 0)
				// Складываем шифртекст прежней восьмёрки с накопителем
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
					const __m128i c0 = _mm_add_epi32(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (__ANTS_BSWAP32__(tail)), 0, 0, 0)), step1);
					// Счётчик восьмёрки со сдвигом на шаг
					const __m128i c1 = _mm_add_epi32(c0, step1);
					// Счётчик восьмёрки со сдвигом на два шага
					const __m128i c2 = _mm_add_epi32(c0, step2);
					// Счётчик восьмёрки со сдвигом на три шага
					const __m128i c3 = _mm_add_epi32(c1, step2);
					// Собираем восемь блоков счётчика сложениями под первым ключом
					s0 = _mm_xor_si128(c0, first);
					// второй блок счётчика под первым ключом
					s1 = _mm_xor_si128(c1, first);
					// третий блок счётчика под первым ключом
					s2 = _mm_xor_si128(c2, first);
					// четвёртый блок счётчика под первым ключом
					s3 = _mm_xor_si128(c3, first);
					// пятый блок счётчика под первым ключом
					s4 = _mm_xor_si128(_mm_add_epi32(c0, step4), first);
					// шестой блок счётчика под первым ключом
					s5 = _mm_xor_si128(_mm_add_epi32(c1, step4), first);
					// седьмой блок счётчика под первым ключом
					s6 = _mm_xor_si128(_mm_add_epi32(c2, step4), first);
					// восьмой блок счётчика под первым ключом
					s7 = _mm_xor_si128(_mm_add_epi32(c3, step4), first);
				// Иначе младший байт переполняется внутри восьмёрки
				} else {
					// Собираем восемь блоков счётчика по одному под первым ключом
					s0 = _mm_xor_si128(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (__ANTS_BSWAP32__(tail + 1)), 0, 0, 0)), first);
					// второй блок счётчика через скаляр
					s1 = _mm_xor_si128(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (__ANTS_BSWAP32__(tail + 2)), 0, 0, 0)), first);
					// третий блок счётчика через скаляр
					s2 = _mm_xor_si128(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (__ANTS_BSWAP32__(tail + 3)), 0, 0, 0)), first);
					// четвёртый блок счётчика через скаляр
					s3 = _mm_xor_si128(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (__ANTS_BSWAP32__(tail + 4)), 0, 0, 0)), first);
					// пятый блок счётчика через скаляр
					s4 = _mm_xor_si128(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (__ANTS_BSWAP32__(tail + 5)), 0, 0, 0)), first);
					// шестой блок счётчика через скаляр
					s5 = _mm_xor_si128(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (__ANTS_BSWAP32__(tail + 6)), 0, 0, 0)), first);
					// седьмой блок счётчика через скаляр
					s6 = _mm_xor_si128(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (__ANTS_BSWAP32__(tail + 7)), 0, 0, 0)), first);
					// восьмой блок счётчика через скаляр
					s7 = _mm_xor_si128(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (__ANTS_BSWAP32__(tail + 8)), 0, 0, 0)), first);
				}
				// Продвигаем счётчик на восемь блоков
				tail += 8;
				/**
				 * Выполняем круги подстановки
				 */
				for(size_t round = 1; round < rounds; round++){
					// Ключ круга
					const __m128i key = _mm_loadu_si128(reinterpret_cast <const __m128i *> (keys + (round * 16)));
					// первый блок на круге подстановки
					s0 = _mm_aesenc_si128(s0, key);
					// второй блок на круге подстановки
					s1 = _mm_aesenc_si128(s1, key);
					// третий блок на круге подстановки
					s2 = _mm_aesenc_si128(s2, key);
					// четвёртый блок на круге подстановки
					s3 = _mm_aesenc_si128(s3, key);
					// пятый блок на круге подстановки
					s4 = _mm_aesenc_si128(s4, key);
					// шестой блок на круге подстановки
					s5 = _mm_aesenc_si128(s5, key);
					// седьмой блок на круге подстановки
					s6 = _mm_aesenc_si128(s6, key);
					// восьмой блок на круге подстановки
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
				// Сдвигаем место записи итога на восьмёрку
				result += 128;
			}
			// При зашифровании хеш последней восьмёрки шифртекста берётся после цикла
			if(sealing)
			// Складываем шифртекст последней восьмёрки с накопителем
			aggregateX86(powers, accumulator, result - 128);
			// Записываем продвинутый счётчик
			counter[12] = static_cast <uint8_t> (tail >> 24);
			// Записываем продвинутый счётчик дальше
			counter[13] = static_cast <uint8_t> (tail >> 16);
			// Записываем продвинутый счётчик ещё дальше
			counter[14] = static_cast <uint8_t> (tail >> 8);
			// Записываем младший байт продвинутого счётчика
			counter[15] = static_cast <uint8_t> (tail);
		}
	#endif
	/**
	 * Если есть сшитое ядро на ассемблере
	 */
	#if defined(__ANTS_GCM_STITCH__)
		/**
		 * @brief Функция слитого хода целых восьмёрок сшитым ядром на ассемблере
		 *
		 * @details Ядро из порождателя tools/cipher/gcm.py хеширует на каждой восьмёрке прежнюю
		 *          (при зашифровании - итог прошлой, при расшифровании - исходные данные текущей)
		 *          и само переносит через младший байт счётчика, оттого ход любой длины идёт
		 *          одним вызовом; первую восьмёрку зашифрования, у которой прежней нет, ведёт
		 *          гамма шифра без хеша, а хеш последней восьмёрки итога берётся после хода.
		 *          Кадр ядра затирается после
		 *
		 * @param block       блочный шифр с расписанием ключа и выработкой гаммы
		 * @param counter     блок счётчика, продвигаемый на выработанные блоки
		 * @param powers      степени ключа хеша от восьмой к первой в виде под ядро
		 * @param accumulator накопитель хеша, заменяемый итогом
		 * @param sealing     признак зашифрования
		 * @param source      исходные данные
		 * @param result      место под итог
		 * @param chunks      число восьмёрок: не меньше одной
		 * @return            признак успешности хода
		 *
		 */
		static bool stitched(const block_t & block, uint8_t * counter, const uint64_t (* powers)[3], uint8_t * accumulator, const bool sealing, const uint8_t * source, uint8_t * result, const size_t chunks) noexcept {
			// Кадр ядра
			alignas(16) uint8_t frame[kernel::FRAME];
			// Число восьмёрок, проведённых гаммой шифра
			size_t first = 0;
			// При зашифровании прежней восьмёрки итога у первой нет: её ведёт гамма шифра
			if(sealing){
				// Если гамму на восьмёрку наложить не удалось
				if(!block.stream(block.cipher, counter, 8, source, result))
				// Выводим отказ хода
				return false;
				// Младшие четыре байта счётчика числом, сдвинутые на восьмёрку
				const uint32_t tail = (((static_cast <uint32_t> (counter[12]) << 24) | (static_cast <uint32_t> (counter[13]) << 16) | (static_cast <uint32_t> (counter[14]) << 8) | static_cast <uint32_t> (counter[15])) + 8U);
				// Записываем продвинутый счётчик
				counter[12] = static_cast <uint8_t> (tail >> 24);
				// Записываем продвинутый счётчик дальше
				counter[13] = static_cast <uint8_t> (tail >> 16);
				// Записываем продвинутый счётчик ещё дальше
				counter[14] = static_cast <uint8_t> (tail >> 8);
				// Записываем младший байт продвинутого счётчика
				counter[15] = static_cast <uint8_t> (tail);
				// Первая восьмёрка пройдена
				first = 1;
			}
			// Если остались восьмёрки под ядро
			if(chunks > first){
				/**
				 * Если сборка ведётся под ARM64
				 */
				#if defined(__aarch64__)
					// Выполняем ход ядром AArch64: при зашифровании хешируется прежняя восьмёрка итога, при расшифровании - исходные данные
					kernel::stitchArm(block.schedule, block.rounds, counter, powers, accumulator, frame, (sealing ? result : source), source + (first * 128), result + (first * 128), chunks - first);
				/**
				 * Иначе ход выполняется ядром x86-64
				 */
				#else
					/**
					 * Выполняем ход ядром x86-64: при зашифровании хешируется прежняя восьмёрка итога, при расшифровании - исходные данные
					 */
					kernel::stitchX86(block.schedule, block.rounds, counter, powers, accumulator, frame, (sealing ? result : source), source + (first * 128), result + (first * 128), chunks - first);
				#endif
				// Выполняем затирание кадра
				wipe(frame, sizeof(frame));
			}
			// При зашифровании хеш последней восьмёрки итога берётся после хода
			if(sealing){
				/**
				 * Если сборка ведётся под ARM64
				 */
				#if defined(__aarch64__)
					// Хешируем последнюю восьмёрку итога командой PMULL
					aggregateArm(powers, accumulator, result + ((chunks - 1) * 128));
				/**
				 * Иначе хеширование идёт командой PCLMULQDQ
				 */
				#else
					/**
					 * Хешируем последнюю восьмёрку итога командой PCLMULQDQ
					 */
					aggregateX86(powers, accumulator, result + ((chunks - 1) * 128));
				#endif
			}
			// Выводим успешность хода
			return true;
		}
	#endif
};

/**
 * @brief Метод слитого хода режима: гамма счётчика AES и хеш по восемь блоков в одном проходе
 *
 * @param sealing признак зашифрования: хеш берётся от итога, при расшифровании - от источника
 * @param source  источник целыми восьмёрками блоков
 * @param result  место, в которое записывается итог той же длины
 * @param chunks  число восьмёрок блоков
 * @return        признак того, что ход выполнен: без расписания ключа AES либо команд машины - отказ, и путь идёт порознь
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
			/**
			 * Если есть сшитое ядро на ассемблере
			 */
			#if defined(__ANTS_GCM_STITCH__)
				// Если шифр вырабатывает гамму
				if(this->_block.stream != nullptr)
				// Выводим итог слитого хода сшитым ядром
				return stitched(this->_block, this->_counter, this->_powers, this->_accumulator, sealing, source, result, chunks);
			#endif
			// Выполняем слитый ход командами ARMv8
			fusedArm(this->_block.schedule, this->_block.rounds, this->_counter, this->_powers, this->_accumulator, sealing, source, result, chunks);
		/**
		 * Иначе слитый ход выполняется командами x86-64
		 */
		#else
			/**
			 * Если есть сшитое ядро на ассемблере, а машина несёт кодировку VEX и MOVBE
			 */
			#if defined(__ANTS_GCM_STITCH__)
				// Если машина несёт кодировку VEX, загрузку с перестановкой байтов и гамму шифра
				if(machine::has(machine::feature_t::AVX) && machine::has(machine::feature_t::MOVBE) && (this->_block.stream != nullptr))
				// Выводим итог слитого хода сшитым ядром
				return stitched(this->_block, this->_counter, this->_powers, this->_accumulator, sealing, source, result, chunks);
			#endif
			// Выполняем слитый ход командами x86-64
			fusedX86(this->_block.schedule, this->_block.rounds, this->_counter, this->_powers, this->_accumulator, sealing, source, result, chunks);
		#endif
		// Выводим успешность слитого хода
		return true;
	/**
	 * Иначе ветви машинного умножения нет
	 */
	#else
		// Довод способа без ветви машины не используется
		(void) sealing;
		// Довод источника без ветви машины не используется
		(void) source;
		// Довод итога без ветви машины не используется
		(void) result;
		// Довод числа восьмёрок без ветви машины не используется
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
 * @brief Метод сложения восьмёрок блоков в накопитель многочлена по одному приведению на восьмёрку
 *
 * @param accumulator накопитель многочлена, заменяемый итогом
 * @param blocks      восьмёрки блоков подряд
 * @param count       число восьмёрок: не меньше одной
 * @return            признак того, что машина умножает командами и восьмёрки сложены
 *
 */
bool nts::cipher::Gcm::aggregate(uint8_t * accumulator, const uint8_t * blocks, const size_t count) const noexcept {
	/**
	 * Если есть ветвь машинного умножения PMULL
	 */
	#if defined(__ANTS_GHASH_ARM__)
		// Если машина умножает без переносов командой
		if(machine::has(machine::feature_t::CARRYLESS)){
			/**
			 * Выполняем сложение восьмёрок командой
			 */
			for(size_t i = 0; i < count; i++)
			// Складываем очередную восьмёрку
			aggregateArm(this->_powers, accumulator, blocks + (i * 128));
			// Выводим признак сложения
			return true;
		}
	/**
	 * Если есть ветвь машинного умножения PCLMULQDQ
	 */
	#elif defined(__ANTS_GHASH_X86__)
		// Если машина умножает без переносов командой
		if(machine::has(machine::feature_t::CARRYLESS)){
			/**
			 * Если есть ядро на ассемблере
			 */
			#if(defined(__GNUC__) || defined(__clang__)) && defined(__x86_64__)
				// Если машина несёт кодировку VEX
				if(machine::has(machine::feature_t::AVX)){
					// Выполняем сложение восьмёрок ядром одним вызовом
					aggregateVexX86(this->_powers, accumulator, blocks, count);
					// Выводим признак сложения
					return true;
				}
			#endif
			/**
			 * Выполняем сложение восьмёрок командой
			 */
			for(size_t i = 0; i < count; i++)
			// Складываем очередную восьмёрку
			aggregateX86(this->_powers, accumulator, blocks + (i * 128));
			// Выводим признак сложения
			return true;
		}
	#endif
	// Довод накопителя без ветви команд не используется
	(void) accumulator;
	// Довод блоков без ветви команд не используется
	(void) blocks;
	// Довод числа восьмёрок без ветви команд не используется
	(void) count;
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
	// Признак умножения командами машины
	bool commands = false;
	/**
	 * Если есть ветвь машинного умножения
	 */
	#if defined(__ANTS_GHASH_ARM__) || defined(__ANTS_GHASH_X86__)
		// Запоминаем, умножает ли машина без переносов командой
		commands = machine::has(machine::feature_t::CARRYLESS);
	#endif
	// Если впереди хотя бы восьмёрка целых блоков, а машина умножает командами
	if(commands && (left >= 128)){
		// Число восьмёрок целых блоков
		const size_t groups = (left / 128);
		// Если восьмёрки сложены одним вызовом по одному приведению на восьмёрку
		if(this->aggregate(this->_accumulator, cursor, groups)){
			// Сдвигаем позицию чтения
			cursor += (groups * 128);
			// Уменьшаем число не сложенных байтов
			left -= (groups * 128);
		}
	}
	// Если умножение идёт таблицей и впереди хотя бы целый блок
	if(!commands && (left >= 16)){
		// Число целых блоков
		const size_t whole = (left / 16);
		// Выполняем сложение целых блоков одним проходом с накопителем в регистрах
		absorbTable(this->_table, this->_remainders, this->_accumulator, cursor, whole);
		// Сдвигаем позицию чтения
		cursor += (whole * 16);
		// Уменьшаем число не сложенных байтов
		left -= (whole * 16);
	}
	/**
	 * Выполняем сложение целых блоков остатка с накопителем по одному
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
			// Записываем сдвинутый счётчик дальше
			this->_counter[13] = static_cast <uint8_t> (tail >> 16);
			// Записываем сдвинутый счётчик ещё дальше
			this->_counter[14] = static_cast <uint8_t> (tail >> 8);
			// Записываем младший байт сдвинутого счётчика
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
		/**
		 * Перебираем слагаемые внутри степени двойки
		 */
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
				/**
				 * Иначе запись идёт ветвью машинного умножения PCLMULQDQ
				 */
				#else
					/**
					 * Записываем степень сдвинутой с суммой половин: восьмая идёт первой
					 */
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
 * @return      признак успешности смены: отказ у незапущенного режима либо пустого заполнения
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
		// Выводим отрицательный результат - присоединённые данные выходят за предел
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
		// Выводим отрицательный результат - переход к зашифрованию недопустим
		return false;
	}
	// Если поток перевести к зашифрованию не удалось
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
		// Выводим отрицательный результат - расшифровка выходит за предел
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
 * @return           признак схождения метки; при расхождении открытый текст не тронут
 *
 */
bool nts::cipher::Gcm::decrypt(const view_t & associated, const view_t & source, uint8_t * result, const view_t & tag) noexcept {
	// Раздел 5.2.1.1 NIST SP 800-38D: предел открытого текста и у одновызовного пути - поточный decrypt() здесь минуется
	if(static_cast <uint64_t> (source.size) > GCM_MOST)
		// Выводим отрицательный результат - открытый текст выходит за предел
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
