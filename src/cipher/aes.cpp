/**
 * @file aes.cpp
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
 * @brief Модуль блочного шифра AES по FIPS 197
 *
 * @details Раунд идёт четырьмя таблицами по 256 слов: таблица объединяет подстановку
 *          байтов, сдвиг строк и перемешивание столбцов, и на слово состояния
 *          приходится четыре обращения к памяти. Таблицы вычисляются при сборке из
 *          арифметики поля GF(2^8) с многочленом x^8 + x^4 + x^3 + x + 1: ни одно
 *          число стандарта не переписано вручную
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
#include <cipher/aes.hpp>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/machine.hpp>
#include <sys/wipe.hpp>

/**
 * @note Табличный путь ведёт круги прямой линией по числу кругов ключа (шаблон на 10, 12
 *       и 14, круги 10…13 под условиями) и шифрует независимые блоки по четыре в одном теле
 *       (гамма счётчика и пачка `batch`): шестьдесят четыре чтения таблиц на круг не зависят
 *       друг от друга, и процессор с широкой командой либо глубоким конвейером исполняет их
 *       внахлёст. Так решено по замерам на Эльбрусе: круг 19 - один блок 95 МБ/с, четыре 141,
 *       цикл со счётчиком кругов 79; круг 51 (29.09.2026) - цикл по кругам lcc сворачивал в
 *       конвейерный цикл с платой за вход на всякую пачку, а один блок прямой линией упирается
 *       в задержку круга около девяти тактов (извлечение индекса, чтение таблицы, сложение):
 *       один блок 229 тактов, два 161, четыре 140, шесть 152, восемь 167 при 128 у OpenSSL
 *       1.1.1n по блоку. Слова читаются и пишутся одной командой с перестановкой байтов через
 *       указатель с признаком совместимости по памяти (lcc не сворачивает сбор из байтов),
 *       счётчики гаммы собираются словами, а гамма накладывается на слова исходных данных в
 *       порядке машины с одной перестановкой слова гаммы - буферов на стеке нет; байтовые
 *       записи гаммы с чтением словами стопорили память Эльбруса (342…464 такта на блок), а
 *       наложение через чтение и запись с перестановкой стоило 148 против 140. Эльбрус-8С2,
 *       lcc 1.27, 64 КиБ: AES-256-CTR 134 → 171,8 МБ/с при 188 (1,41 → 1,09), AES-256-GCM
 *       81,7 → 97,7 при 82,0 (0,84), AES-128-GCM 93,5 → 115,4 при 93,2 (0,81); x86-64 и ARM64
 *       идут командами AES, таблицы там лишь под запретом команд
 *
 * @note Гамма счётчика (круг 38, 23.09.2026) накладывается на исходные данные самим
 *       ядром: отдельный буфер гаммы с последующим наложением по словам стоил на Xeon
 *       E5-2630 v4 45 тактов из 180 на восемь блоков при 112 на сами круги. Восемь
 *       счётчиков собираются сложениями в векторе, пока младший байт не переполняется
 *       внутри восьмёрки, и по одному через скаляр на переносе - сборка через скаляр
 *       на каждый блок стоила ещё 23 такта
 *
 * @note Обе ветви - командами и таблицами - собираются в один двоичный файл, а выбор
 *       делается на исполнении по опознанию машины (sys/machine.hpp). Команды
 *       порождаются в отдельных функциях с атрибутом цели, оттого общих ключей
 *       расширений сборке не нужно. Признак ANTS_NO_MACHINE выбрасывает ветвь команд
 *       из сборки вовсе
 *
 */

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
		#define __ANTS_AES_TARGET__
	/**
	 * Если собиратель clang
	 */
	#elif defined(__clang__)
		/**
		 * Разрешаем команды расширения одной функции
		 */
		#define __ANTS_AES_TARGET__ __attribute__((target("crypto")))
	/**
	 * Если собиратель GCC
	 */
	#else
		/**
		 * Разрешаем команды расширения одной функции
		 */
		#define __ANTS_AES_TARGET__ __attribute__((target("+crypto")))
	#endif

	/**
	 * Объявляем наличие ветви команд AES
	 */
	#define __ANTS_AES_ARM__ 1
/**
 * Если сборка ведётся под x86-64 собирателем семейства GCC
 */
#elif (defined(__x86_64__) || defined(__e2k__)) && (defined(__GNUC__) || defined(__clang__)) && !defined(ANTS_NO_MACHINE)
	/**
	 * Подключаем заголовочный файл команд x86-64
	 */
	#include <wmmintrin.h>

	/**
	 * Если расширение уже разрешено ключами сборки
	 */
	#if defined(__AES__)
		/**
		 * Атрибут цели не нужен
		 */
		#define __ANTS_AES_TARGET__
	/**
	 * Иначе разрешаем команды расширения одной функции атрибутом цели
	 */
	#else
		/**
		 * Разрешаем команды расширения одной функции
		 */
		#define __ANTS_AES_TARGET__ __attribute__((target("aes,sse2")))
	#endif

	/**
	 * Объявляем наличие ветви команд AES
	 */
	#define __ANTS_AES_X86__ 1
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

	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;

	/**
	 * @brief Функция удвоения элемента поля GF(2^8)
	 *
	 * @param value удваиваемый элемент
	 * @return      удвоенный элемент по модулю многочлена поля
	 *
	 */
	static constexpr uint8_t twice(const uint8_t value) noexcept {
		// Выводим удвоенный элемент с приведением по многочлену 0x11B
		return static_cast <uint8_t> ((value << 1) ^ ((value & 0x80) ? 0x1B : 0x00));
	}

	/**
	 * @brief Функция умножения элементов поля GF(2^8)
	 *
	 * @param first  первый множитель
	 * @param second второй множитель
	 * @return       произведение по модулю многочлена поля
	 *
	 */
	static constexpr uint8_t multiply(const uint8_t first, const uint8_t second) noexcept {
		// Накопленное произведение
		uint8_t result = 0;
		// Сдвигаемый первый множитель
		uint8_t item = first;
		// Разряды второго множителя
		uint8_t bits = second;
		/**
		 * Выполняем перебор разрядов второго множителя
		 */
		for(size_t i = 0; i < 8; i++){
			// Если очередной разряд установлен
			if(bits & 0x01)
				// Складываем первый множитель с произведением
				result = static_cast <uint8_t> (result ^ item);
			// Удваиваем первый множитель
			item = twice(item);
			// Сдвигаем разряды второго множителя
			bits = static_cast <uint8_t> (bits >> 1);
		}
		// Выводим произведение
		return result;
	}

	/**
	 * @brief Функция кругового сдвига байта влево
	 *
	 * @param value сдвигаемый байт
	 * @param count число разрядов сдвига
	 * @return      сдвинутый байт
	 *
	 */
	static constexpr uint8_t rotate(const uint8_t value, const unsigned count) noexcept {
		// Выводим байт, сдвинутый по кругу
		return static_cast <uint8_t> ((value << count) | (value >> (8 - count)));
	}

	/**
	 * @brief Таблицы преобразования шифра
	 *
	 */
	typedef struct Tables {
		// Подстановка байтов
		uint8_t sbox[256];
		// Обратная подстановка байтов
		uint8_t inverse[256];
		// Таблицы раунда зашифрования
		uint32_t te[4][256];
		// Таблицы раунда расшифрования
		uint32_t td[4][256];
	} tables_t;

	/**
	 * @brief Функция вычисления таблиц преобразования шифра
	 *
	 * @details Подстановка строится из обратных элементов поля через порождающий
	 *          элемент 3 и аффинного преобразования раздела 5.1.1 FIPS 197; таблицы
	 *          раунда складываются из подстановки и перемешивания столбцов
	 *
	 * @return вычисленные таблицы
	 *
	 */
	static constexpr tables_t build() noexcept {
		// Вычисляемые таблицы
		tables_t tables{};
		// Степень порождающего элемента и обратный ей элемент
		uint8_t power = 1, opposite = 1;
		/**
		 * Выполняем перебор всех ненулевых элементов поля степенями порождающего
		 */
		do {
			// Умножаем степень на порождающий элемент 3
			power = static_cast <uint8_t> (power ^ twice(power));
			// Делим обратный элемент на 3: умножение на обратный к 3 через сдвиги
			opposite = static_cast <uint8_t> (opposite ^ (opposite << 1));
			// Продолжаем деление
			opposite = static_cast <uint8_t> (opposite ^ (opposite << 2));
			// Продолжаем деление
			opposite = static_cast <uint8_t> (opposite ^ (opposite << 4));
			// Приводим по многочлену поля
			opposite = static_cast <uint8_t> (opposite ^ ((opposite & 0x80) ? 0x09 : 0x00));
			// Аффинное преобразование обратного элемента
			const uint8_t affine = static_cast <uint8_t> (opposite ^ rotate(opposite, 1) ^ rotate(opposite, 2) ^ rotate(opposite, 3) ^ rotate(opposite, 4));
			// Записываем значение подстановки
			tables.sbox[power] = static_cast <uint8_t> (affine ^ 0x63);
		} while(power != 1);
		// Нулевой элемент обратного не имеет: подстановка даёт постоянную аффинного преобразования
		tables.sbox[0] = 0x63;
		/**
		 * Выполняем построение обратной подстановки
		 */
		for(size_t i = 0; i < 256; i++)
			// Записываем обратное значение подстановки
			tables.inverse[tables.sbox[i]] = static_cast <uint8_t> (i);
		/**
		 * Выполняем построение таблиц раунда
		 */
		for(size_t i = 0; i < 256; i++){
			// Подставленный байт
			const uint8_t s = tables.sbox[i];
			// Подставленный байт, умноженный на 2
			const uint8_t s2 = twice(s);
			// Подставленный байт, умноженный на 3
			const uint8_t s3 = static_cast <uint8_t> (s2 ^ s);
			// Слово столбца зашифрования
			tables.te[0][i] = ((static_cast <uint32_t> (s2) << 24) | (static_cast <uint32_t> (s) << 16) | (static_cast <uint32_t> (s) << 8) | static_cast <uint32_t> (s3));
			// Слово столбца, сдвинутое на байт
			tables.te[1][i] = ((static_cast <uint32_t> (s3) << 24) | (static_cast <uint32_t> (s2) << 16) | (static_cast <uint32_t> (s) << 8) | static_cast <uint32_t> (s));
			// Слово столбца, сдвинутое на два байта
			tables.te[2][i] = ((static_cast <uint32_t> (s) << 24) | (static_cast <uint32_t> (s3) << 16) | (static_cast <uint32_t> (s2) << 8) | static_cast <uint32_t> (s));
			// Слово столбца, сдвинутое на три байта
			tables.te[3][i] = ((static_cast <uint32_t> (s) << 24) | (static_cast <uint32_t> (s) << 16) | (static_cast <uint32_t> (s3) << 8) | static_cast <uint32_t> (s2));
			// Обратно подставленный байт
			const uint8_t v = tables.inverse[i];
			// Произведения обратно подставленного байта на 9, 11, 13 и 14
			const uint8_t v9 = multiply(v, 9), v11 = multiply(v, 11), v13 = multiply(v, 13), v14 = multiply(v, 14);
			// Слово столбца расшифрования
			tables.td[0][i] = ((static_cast <uint32_t> (v14) << 24) | (static_cast <uint32_t> (v9) << 16) | (static_cast <uint32_t> (v13) << 8) | static_cast <uint32_t> (v11));
			// Слово столбца, сдвинутое на байт
			tables.td[1][i] = ((static_cast <uint32_t> (v11) << 24) | (static_cast <uint32_t> (v14) << 16) | (static_cast <uint32_t> (v9) << 8) | static_cast <uint32_t> (v13));
			// Слово столбца, сдвинутое на два байта
			tables.td[2][i] = ((static_cast <uint32_t> (v13) << 24) | (static_cast <uint32_t> (v11) << 16) | (static_cast <uint32_t> (v14) << 8) | static_cast <uint32_t> (v9));
			// Слово столбца, сдвинутое на три байта
			tables.td[3][i] = ((static_cast <uint32_t> (v9) << 24) | (static_cast <uint32_t> (v13) << 16) | (static_cast <uint32_t> (v11) << 8) | static_cast <uint32_t> (v14));
		}
		// Выводим вычисленные таблицы
		return tables;
	}

	/**
	 * @brief Таблицы преобразования шифра, вычисленные при сборке
	 *
	 */
	static constexpr tables_t TABLES = build();

	/**
	 * Слова от старшего байта читаются и пишутся одной командой с перестановкой байтов там, где
	 * собиратель семейства GCC даёт встроенную перестановку, а машина читает слова по любому адресу
	 * (x86-64, ARM64, Эльбрус): lcc не сворачивает четыре чтения байтов со сдвигами в одно чтение,
	 * а чтение через memcpy проводит через кадр стека (круг 51, 29.09.2026)
	 */
	#if(defined(__GNUC__) || defined(__clang__)) && (defined(__x86_64__) || defined(__aarch64__) || defined(__e2k__)) && defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
		/**
		 * Объявляем чтение слов одной командой с перестановкой байтов
		 */
		#define __ANTS_AES_SWAP__ 1

		/**
		 * Слово, совместимое по памяти с любым типом
		 */
		typedef uint32_t __attribute__((may_alias)) aliased_t;
	#endif

	/**
	 * @brief Функция чтения слова от старшего байта
	 *
	 * @param data читаемые байты
	 * @return     прочитанное слово
	 *
	 */
	static __ANTS_INLINE__ uint32_t load(const uint8_t * data) noexcept {
		/**
		 * Если слово читается одной командой с перестановкой байтов
		 */
		#if defined(__ANTS_AES_SWAP__)
			// Выводим слово, прочитанное разом и переставленное от старшего байта
			return __builtin_bswap32(* reinterpret_cast <const aliased_t *> (data));
		/**
		 * Иначе слово собирается из байтов
		 */
		#else
			// Выводим слово, собранное от старшего байта
			return ((static_cast <uint32_t> (data[0]) << 24) | (static_cast <uint32_t> (data[1]) << 16) |
			        (static_cast <uint32_t> (data[2]) << 8) | static_cast <uint32_t> (data[3]));
		#endif
	}

	/**
	 * @brief Функция записи слова от старшего байта
	 *
	 * @param value записываемое слово
	 * @param data  место, в которое записываются байты
	 *
	 */
	static __ANTS_INLINE__ void store(const uint32_t value, uint8_t * data) noexcept {
		/**
		 * Если слово пишется одной командой с перестановкой байтов
		 */
		#if defined(__ANTS_AES_SWAP__)
			// Записываем слово разом, переставив байты от старшего
			(* reinterpret_cast <aliased_t *> (data)) = __builtin_bswap32(value);
		/**
		 * Иначе слово пишется байтами
		 */
		#else
			// Записываем старший байт слова
			data[0] = static_cast <uint8_t> (value >> 24);
			// Записываем второй байт слова
			data[1] = static_cast <uint8_t> (value >> 16);
			// Записываем третий байт слова
			data[2] = static_cast <uint8_t> (value >> 8);
			// Записываем младший байт слова
			data[3] = static_cast <uint8_t> (value);
		#endif
	}

	/**
	 * @brief Функция чтения слова в порядке байтов машины
	 *
	 * @details Гамма накладывается на слова в порядке машины: слово исходных данных
	 *          читается как есть, а под него переставляется слово гаммы - одна
	 *          перестановка на слово вместо двух (круг 51, 29.09.2026). Без перестановок
	 *          одной командой порядок машины подменяется порядком от старшего байта
	 *
	 * @param data читаемые байты
	 * @return     прочитанное слово
	 *
	 */
	static __ANTS_INLINE__ uint32_t native(const uint8_t * data) noexcept {
		/**
		 * Если слово читается одной командой
		 */
		#if defined(__ANTS_AES_SWAP__)
			// Выводим слово, прочитанное разом
			return (* reinterpret_cast <const aliased_t *> (data));
		/**
		 * Иначе слово читается от старшего байта
		 */
		#else
			// Выводим слово от старшего байта
			return load(data);
		#endif
	}

	/**
	 * @brief Функция записи слова в порядке байтов машины
	 *
	 * @param value записываемое слово
	 * @param data  место, в которое записываются байты
	 *
	 */
	static __ANTS_INLINE__ void nativeStore(const uint32_t value, uint8_t * data) noexcept {
		/**
		 * Если слово пишется одной командой
		 */
		#if defined(__ANTS_AES_SWAP__)
			// Записываем слово разом
			(* reinterpret_cast <aliased_t *> (data)) = value;
		/**
		 * Иначе слово пишется от старшего байта
		 */
		#else
			// Записываем слово от старшего байта
			store(value, data);
		#endif
	}

	/**
	 * @brief Функция перестановки слова от старшего байта под порядок машины
	 *
	 * @param value переставляемое слово
	 * @return      слово под порядок машины
	 *
	 */
	static __ANTS_INLINE__ uint32_t swap(const uint32_t value) noexcept {
		/**
		 * Если слова читаются одной командой
		 */
		#if defined(__ANTS_AES_SWAP__)
			// Выводим слово с переставленными байтами
			return __builtin_bswap32(value);
		/**
		 * Иначе слова и так идут от старшего байта
		 */
		#else
			// Выводим слово как есть
			return value;
		#endif
	}

	/**
	 * @brief Функция подстановки всех байтов слова
	 *
	 * @param value слово, байты которого подставляются
	 * @return      слово с подставленными байтами
	 *
	 */
	static __ANTS_INLINE__ uint32_t substitute(const uint32_t value) noexcept {
		// Выводим слово с подставленными байтами
		return ((static_cast <uint32_t> (TABLES.sbox[value >> 24]) << 24) | (static_cast <uint32_t> (TABLES.sbox[(value >> 16) & 0xFF]) << 16) |
		        (static_cast <uint32_t> (TABLES.sbox[(value >> 8) & 0xFF]) << 8) | static_cast <uint32_t> (TABLES.sbox[value & 0xFF]));
	}

	/**
	 * Если есть ветвь команд AES расширения ARMv8
	 */
	#if defined(__ANTS_AES_ARM__)
		/**
		 * @brief Функция зашифрования блока командами AESE и AESMC
		 *
		 * @param keys   раундовые ключи байтами в порядке памяти
		 * @param rounds число раундов
		 * @param source исходный блок
		 * @param result место, в которое записывается зашифрованный блок
		 *
		 */
		static __ANTS_AES_TARGET__ void sealArm(const uint8_t * keys, const size_t rounds, const uint8_t * source, uint8_t * result) noexcept {
			// Состояние шифра
			uint8x16_t state = vld1q_u8(source);
			/**
			 * Выполняем внутренние раунды: подстановка со сдвигом и ключом, затем перемешивание
			 */
			for(size_t round = 0; (round + 1) < rounds; round++)
			// Выполняем раунд командами AESE и AESMC
			state = vaesmcq_u8(vaeseq_u8(state, vld1q_u8(keys + (round * 16))));
			// Выполняем последний раунд без перемешивания и складываем с последним ключом
			state = veorq_u8(vaeseq_u8(state, vld1q_u8(keys + ((rounds - 1) * 16))), vld1q_u8(keys + (rounds * 16)));
			// Записываем зашифрованный блок
			vst1q_u8(result, state);
		}
		/**
		 * @brief Функция расшифрования блока командами AESD и AESIMC
		 *
		 * @param keys   раундовые ключи расшифрования байтами в порядке памяти
		 * @param rounds число раундов
		 * @param source зашифрованный блок
		 * @param result место, в которое записывается расшифрованный блок
		 *
		 */
		static __ANTS_AES_TARGET__ void openArm(const uint8_t * keys, const size_t rounds, const uint8_t * source, uint8_t * result) noexcept {
			// Состояние шифра
			uint8x16_t state = vld1q_u8(source);
			/**
			 * Выполняем внутренние раунды: ключи расшифрования уже пропущены через обратное перемешивание
			 */
			for(size_t round = 0; (round + 1) < rounds; round++)
			// Выполняем раунд командами AESD и AESIMC
			state = vaesimcq_u8(vaesdq_u8(state, vld1q_u8(keys + (round * 16))));
			// Выполняем последний раунд без перемешивания и складываем с последним ключом
			state = veorq_u8(vaesdq_u8(state, vld1q_u8(keys + ((rounds - 1) * 16))), vld1q_u8(keys + (rounds * 16)));
			// Записываем расшифрованный блок
			vst1q_u8(result, state);
		}
	/**
	 * Если есть ветвь команд AES-NI
	 */
	#elif defined(__ANTS_AES_X86__)
		/**
		 * @brief Функция зашифрования блока командами AESENC
		 *
		 * @param keys   раундовые ключи байтами в порядке памяти
		 * @param rounds число раундов
		 * @param source исходный блок
		 * @param result место, в которое записывается зашифрованный блок
		 *
		 */
		static __ANTS_AES_TARGET__ void sealX86(const uint8_t * keys, const size_t rounds, const uint8_t * source, uint8_t * result) noexcept {
			// Состояние шифра, сложенное с первым ключом
			__m128i state = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast <const __m128i *> (source)), _mm_loadu_si128(reinterpret_cast <const __m128i *> (keys)));
			/**
			 * Выполняем внутренние раунды командой AESENC
			 */
			for(size_t round = 1; round < rounds; round++)
			// Выполняем очередной раунд
			state = _mm_aesenc_si128(state, _mm_loadu_si128(reinterpret_cast <const __m128i *> (keys + (round * 16))));
			// Выполняем последний раунд командой AESENCLAST
			state = _mm_aesenclast_si128(state, _mm_loadu_si128(reinterpret_cast <const __m128i *> (keys + (rounds * 16))));
			// Записываем зашифрованный блок
			_mm_storeu_si128(reinterpret_cast <__m128i *> (result), state);
		}
		/**
		 * @brief Функция расшифрования блока командами AESDEC
		 *
		 * @param keys   раундовые ключи расшифрования байтами в порядке памяти
		 * @param rounds число раундов
		 * @param source зашифрованный блок
		 * @param result место, в которое записывается расшифрованный блок
		 *
		 */
		static __ANTS_AES_TARGET__ void openX86(const uint8_t * keys, const size_t rounds, const uint8_t * source, uint8_t * result) noexcept {
			// Состояние шифра, сложенное с первым ключом
			__m128i state = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast <const __m128i *> (source)), _mm_loadu_si128(reinterpret_cast <const __m128i *> (keys)));
			/**
			 * Выполняем внутренние раунды командой AESDEC
			 */
			for(size_t round = 1; round < rounds; round++)
			// Выполняем очередной раунд
			state = _mm_aesdec_si128(state, _mm_loadu_si128(reinterpret_cast <const __m128i *> (keys + (round * 16))));
			// Выполняем последний раунд командой AESDECLAST
			state = _mm_aesdeclast_si128(state, _mm_loadu_si128(reinterpret_cast <const __m128i *> (keys + (rounds * 16))));
			// Записываем расшифрованный блок
			_mm_storeu_si128(reinterpret_cast <__m128i *> (result), state);
		}
	#endif

	/**
	 * @brief Функция разворота байтов числа: младшие четыре байта счётчика идут от старшего
	 *
	 * @param value разворачиваемое число
	 * @return      число с обратным порядком байтов
	 *
	 */
	static __ANTS_INLINE__ uint32_t reversed(const uint32_t value) noexcept {
		// Разворачиваем байты сдвигами: собиратель сводит это к одной команде
		return ((value >> 24) | ((value >> 8) & 0x0000FF00U) | ((value << 8) & 0x00FF0000U) | (value << 24));
	}
	/**
	 * @brief Функция увеличения младших 32 разрядов счётчика от старшего байта
	 *
	 * @param counter увеличиваемый блок счётчика
	 *
	 */
	static __ANTS_INLINE__ void advance(uint8_t * counter) noexcept {
		/**
		 * Выполняем перенос по младшим четырём байтам
		 */
		for(size_t i = 16; i > 12; i--){
			// Если байт не переполнился
			if(++counter[i - 1] != 0)
				// Прерываем перенос
				break;
		}
	}

	/**
	 * Слова состояния табличного пути на Эльбрусе держатся в 64 разряда (круг 59, 30.09.2026): индекс
	 * таблицы из слова в 32 разряда lcc расширяет до адреса отдельной командой на каждое из шестнадцати
	 * чтений круга, а из слова в 64 разряда извлекает полем сразу; значения слов при этом не выходят за
	 * 32 разряда, ибо приходят из таблиц, ключей и слов блока, а счётчик гаммы считается в 32 разрядах.
	 * Эльбрус-8С2, lcc 1.27, 64 КиБ AES-256-CTR: 172 → 195 МБ/с при 188 у OpenSSL 1.1.1n (1,09 → 0,96).
	 * Таблицы вчетверо с индексом полем из десяти разрядов (байт и два разряда соседнего байта, без
	 * сдвига индекса) пробовали и не взяли: 1,18 при словах в 32 разряда и 1,06 при 64. Иные машины
	 * идут командами AES, а их табличный путь под запретом команд оставлен на словах в 32 разряда
	 */
	#if defined(__e2k__)
		/**
		 * Слово состояния табличного пути
		 */
		typedef uint64_t word_t;
		/**
		 * Иначе слово состояния табличного пути в 32 разряда
		 */
	#else
		/**
		 * Слово состояния табличного пути
		 */
		typedef uint32_t word_t;
	#endif

	/**
	 * @brief Круг шифрования таблицами: четыре слова состояния в четыре новых
	 *
	 * @param s0  первое слово состояния
	 * @param s1  второе слово состояния
	 * @param s2  третье слово состояния
	 * @param s3  четвёртое слово состояния
	 * @param key ключ круга
	 * @param t0  место первого слова нового состояния
	 * @param t1  место второго слова нового состояния
	 * @param t2  место третьего слова нового состояния
	 * @param t3  место четвёртого слова нового состояния
	 *
	 */
	static __ANTS_INLINE__ void sealRound(const word_t s0, const word_t s1, const word_t s2, const word_t s3, const uint32_t * key, word_t & t0, word_t & t1, word_t & t2, word_t & t3) noexcept {
		// Собираем первое слово нового состояния
		t0 = (TABLES.te[0][s0 >> 24] ^ TABLES.te[1][(s1 >> 16) & 0xFF] ^ TABLES.te[2][(s2 >> 8) & 0xFF] ^ TABLES.te[3][s3 & 0xFF] ^ key[0]);
		// Собираем второе слово нового состояния
		t1 = (TABLES.te[0][s1 >> 24] ^ TABLES.te[1][(s2 >> 16) & 0xFF] ^ TABLES.te[2][(s3 >> 8) & 0xFF] ^ TABLES.te[3][s0 & 0xFF] ^ key[1]);
		// Собираем третье слово нового состояния
		t2 = (TABLES.te[0][s2 >> 24] ^ TABLES.te[1][(s3 >> 16) & 0xFF] ^ TABLES.te[2][(s0 >> 8) & 0xFF] ^ TABLES.te[3][s1 & 0xFF] ^ key[2]);
		// Собираем четвёртое слово нового состояния
		t3 = (TABLES.te[0][s3 >> 24] ^ TABLES.te[1][(s0 >> 16) & 0xFF] ^ TABLES.te[2][(s1 >> 8) & 0xFF] ^ TABLES.te[3][s2 & 0xFF] ^ key[3]);
	}
	/**
	 * @brief Последний круг шифрования таблицами: подстановка байтов
	 *
	 * @param s0  первое слово состояния
	 * @param s1  второе слово состояния
	 * @param s2  третье слово состояния
	 * @param s3  четвёртое слово состояния
	 * @param key ключ последнего круга
	 * @param g0  место первого слова зашифрованного блока
	 * @param g1  место второго слова зашифрованного блока
	 * @param g2  место третьего слова зашифрованного блока
	 * @param g3  место четвёртого слова зашифрованного блока
	 *
	 */
	static __ANTS_INLINE__ void sealLast(const word_t s0, const word_t s1, const word_t s2, const word_t s3, const uint32_t * key, word_t & g0, word_t & g1, word_t & g2, word_t & g3) noexcept {
		// Подставляем байты первого слова зашифрованного блока
		g0 = (((static_cast <word_t> (TABLES.sbox[s0 >> 24]) << 24) | (static_cast <word_t> (TABLES.sbox[(s1 >> 16) & 0xFF]) << 16) | (static_cast <word_t> (TABLES.sbox[(s2 >> 8) & 0xFF]) << 8) | static_cast <word_t> (TABLES.sbox[s3 & 0xFF])) ^ key[0]);
		// Подставляем байты второго слова зашифрованного блока
		g1 = (((static_cast <word_t> (TABLES.sbox[s1 >> 24]) << 24) | (static_cast <word_t> (TABLES.sbox[(s2 >> 16) & 0xFF]) << 16) | (static_cast <word_t> (TABLES.sbox[(s3 >> 8) & 0xFF]) << 8) | static_cast <word_t> (TABLES.sbox[s0 & 0xFF])) ^ key[1]);
		// Подставляем байты третьего слова зашифрованного блока
		g2 = (((static_cast <word_t> (TABLES.sbox[s2 >> 24]) << 24) | (static_cast <word_t> (TABLES.sbox[(s3 >> 16) & 0xFF]) << 16) | (static_cast <word_t> (TABLES.sbox[(s0 >> 8) & 0xFF]) << 8) | static_cast <word_t> (TABLES.sbox[s1 & 0xFF])) ^ key[2]);
		// Подставляем байты четвёртого слова зашифрованного блока
		g3 = (((static_cast <word_t> (TABLES.sbox[s3 >> 24]) << 24) | (static_cast <word_t> (TABLES.sbox[(s0 >> 16) & 0xFF]) << 16) | (static_cast <word_t> (TABLES.sbox[(s1 >> 8) & 0xFF]) << 8) | static_cast <word_t> (TABLES.sbox[s2 & 0xFF])) ^ key[3]);
	}
	/**
	 * @brief Круг расшифрования таблицами: четыре слова состояния в четыре новых
	 *
	 * @param s0  первое слово состояния
	 * @param s1  второе слово состояния
	 * @param s2  третье слово состояния
	 * @param s3  четвёртое слово состояния
	 * @param key ключ круга
	 * @param t0  место первого слова нового состояния
	 * @param t1  место второго слова нового состояния
	 * @param t2  место третьего слова нового состояния
	 * @param t3  место четвёртого слова нового состояния
	 *
	 */
	static __ANTS_INLINE__ void openRound(const word_t s0, const word_t s1, const word_t s2, const word_t s3, const uint32_t * key, word_t & t0, word_t & t1, word_t & t2, word_t & t3) noexcept {
		// Собираем первое слово нового состояния
		t0 = (TABLES.td[0][s0 >> 24] ^ TABLES.td[1][(s3 >> 16) & 0xFF] ^ TABLES.td[2][(s2 >> 8) & 0xFF] ^ TABLES.td[3][s1 & 0xFF] ^ key[0]);
		// Собираем второе слово нового состояния
		t1 = (TABLES.td[0][s1 >> 24] ^ TABLES.td[1][(s0 >> 16) & 0xFF] ^ TABLES.td[2][(s3 >> 8) & 0xFF] ^ TABLES.td[3][s2 & 0xFF] ^ key[1]);
		// Собираем третье слово нового состояния
		t2 = (TABLES.td[0][s2 >> 24] ^ TABLES.td[1][(s1 >> 16) & 0xFF] ^ TABLES.td[2][(s0 >> 8) & 0xFF] ^ TABLES.td[3][s3 & 0xFF] ^ key[2]);
		// Собираем четвёртое слово нового состояния
		t3 = (TABLES.td[0][s3 >> 24] ^ TABLES.td[1][(s2 >> 16) & 0xFF] ^ TABLES.td[2][(s1 >> 8) & 0xFF] ^ TABLES.td[3][s0 & 0xFF] ^ key[3]);
	}
	/**
	 * @brief Последний круг расшифрования таблицами: обратная подстановка
	 *
	 * @param s0  первое слово состояния
	 * @param s1  второе слово состояния
	 * @param s2  третье слово состояния
	 * @param s3  четвёртое слово состояния
	 * @param key ключ последнего круга
	 * @param g0  место первого слова расшифрованного блока
	 * @param g1  место второго слова расшифрованного блока
	 * @param g2  место третьего слова расшифрованного блока
	 * @param g3  место четвёртого слова расшифрованного блока
	 *
	 */
	static __ANTS_INLINE__ void openLast(const word_t s0, const word_t s1, const word_t s2, const word_t s3, const uint32_t * key, word_t & g0, word_t & g1, word_t & g2, word_t & g3) noexcept {
		// Подставляем байты первого слова расшифрованного блока
		g0 = (((static_cast <word_t> (TABLES.inverse[s0 >> 24]) << 24) | (static_cast <word_t> (TABLES.inverse[(s3 >> 16) & 0xFF]) << 16) | (static_cast <word_t> (TABLES.inverse[(s2 >> 8) & 0xFF]) << 8) | static_cast <word_t> (TABLES.inverse[s1 & 0xFF])) ^ key[0]);
		// Подставляем байты второго слова расшифрованного блока
		g1 = (((static_cast <word_t> (TABLES.inverse[s1 >> 24]) << 24) | (static_cast <word_t> (TABLES.inverse[(s0 >> 16) & 0xFF]) << 16) | (static_cast <word_t> (TABLES.inverse[(s3 >> 8) & 0xFF]) << 8) | static_cast <word_t> (TABLES.inverse[s2 & 0xFF])) ^ key[1]);
		// Подставляем байты третьего слова расшифрованного блока
		g2 = (((static_cast <word_t> (TABLES.inverse[s2 >> 24]) << 24) | (static_cast <word_t> (TABLES.inverse[(s1 >> 16) & 0xFF]) << 16) | (static_cast <word_t> (TABLES.inverse[(s0 >> 8) & 0xFF]) << 8) | static_cast <word_t> (TABLES.inverse[s3 & 0xFF])) ^ key[2]);
		// Подставляем байты четвёртого слова расшифрованного блока
		g3 = (((static_cast <word_t> (TABLES.inverse[s3 >> 24]) << 24) | (static_cast <word_t> (TABLES.inverse[(s2 >> 16) & 0xFF]) << 16) | (static_cast <word_t> (TABLES.inverse[(s1 >> 8) & 0xFF]) << 8) | static_cast <word_t> (TABLES.inverse[s0 & 0xFF])) ^ key[3]);
	}
	/**
	 * @brief Функция кругов шифрования одного блока прямой линией
	 *
	 * @details Число кругов заложено постоянной шаблона, и круги выписаны подряд без цикла:
	 *          lcc сворачивал цикл по кругам в конвейерный цикл с платой за вход на каждом
	 *          блоке (круг 51, 29.09.2026). Полных кругов нечётное число у всех трёх длин
	 *          ключа (9, 11, 13): они идут парами, последний полный - отдельно, а итог
	 *          заключительной подстановки возвращается словами на место состояния
	 *
	 * @param keys развёрнутое расписание ключей шифрования
	 * @param s0   первое слово блока: заменяется словом итога
	 * @param s1   второе слово блока: заменяется словом итога
	 * @param s2   третье слово блока: заменяется словом итога
	 * @param s3   четвёртое слово блока: заменяется словом итога
	 *
	 */
	template <size_t ROUNDS>
	static __ANTS_INLINE__ void sealWords(const uint32_t * keys, word_t & s0, word_t & s1, word_t & s2, word_t & s3) noexcept {
		// Складываем блок с первым ключом
		s0 ^= keys[0], s1 ^= keys[1], s2 ^= keys[2], s3 ^= keys[3];
		// Второе состояние пары кругов
		word_t t0 = 0, t1 = 0, t2 = 0, t3 = 0;
		// Выполняем полные круги парами от начального состояния
		sealRound(s0, s1, s2, s3, keys + 4, t0, t1, t2, t3);
		sealRound(t0, t1, t2, t3, keys + 8, s0, s1, s2, s3);
		sealRound(s0, s1, s2, s3, keys + 12, t0, t1, t2, t3);
		sealRound(t0, t1, t2, t3, keys + 16, s0, s1, s2, s3);
		sealRound(s0, s1, s2, s3, keys + 20, t0, t1, t2, t3);
		sealRound(t0, t1, t2, t3, keys + 24, s0, s1, s2, s3);
		sealRound(s0, s1, s2, s3, keys + 28, t0, t1, t2, t3);
		sealRound(t0, t1, t2, t3, keys + 32, s0, s1, s2, s3);
		sealRound(s0, s1, s2, s3, keys + 36, t0, t1, t2, t3);
		// Если кругов больше десяти (AES-192 и AES-256)
		if(ROUNDS > 10){
			// Выполняем круги десять и одиннадцать
			sealRound(t0, t1, t2, t3, keys + 40, s0, s1, s2, s3);
			sealRound(s0, s1, s2, s3, keys + 44, t0, t1, t2, t3);
		}
		// Если кругов больше двенадцати (AES-256)
		if(ROUNDS > 12){
			// Выполняем круги двенадцать и тринадцать
			sealRound(t0, t1, t2, t3, keys + 48, s0, s1, s2, s3);
			sealRound(s0, s1, s2, s3, keys + 52, t0, t1, t2, t3);
		}
		// Заключительная подстановка с последним ключом
		sealLast(t0, t1, t2, t3, keys + (ROUNDS * 4), s0, s1, s2, s3);
	}
	/**
	 * @brief Функция кругов расшифрования одного блока прямой линией
	 *
	 * @details Круги выписаны подряд без цикла, как у шифрования
	 *
	 * @param keys развёрнутое расписание ключей расшифрования
	 * @param s0   первое слово блока: заменяется словом итога
	 * @param s1   второе слово блока: заменяется словом итога
	 * @param s2   третье слово блока: заменяется словом итога
	 * @param s3   четвёртое слово блока: заменяется словом итога
	 *
	 */
	template <size_t ROUNDS>
	static __ANTS_INLINE__ void openWords(const uint32_t * keys, word_t & s0, word_t & s1, word_t & s2, word_t & s3) noexcept {
		// Складываем блок с первым ключом
		s0 ^= keys[0], s1 ^= keys[1], s2 ^= keys[2], s3 ^= keys[3];
		// Второе состояние пары кругов
		word_t t0 = 0, t1 = 0, t2 = 0, t3 = 0;
		// Выполняем полные круги парами от начального состояния
		openRound(s0, s1, s2, s3, keys + 4, t0, t1, t2, t3);
		openRound(t0, t1, t2, t3, keys + 8, s0, s1, s2, s3);
		openRound(s0, s1, s2, s3, keys + 12, t0, t1, t2, t3);
		openRound(t0, t1, t2, t3, keys + 16, s0, s1, s2, s3);
		openRound(s0, s1, s2, s3, keys + 20, t0, t1, t2, t3);
		openRound(t0, t1, t2, t3, keys + 24, s0, s1, s2, s3);
		openRound(s0, s1, s2, s3, keys + 28, t0, t1, t2, t3);
		openRound(t0, t1, t2, t3, keys + 32, s0, s1, s2, s3);
		openRound(s0, s1, s2, s3, keys + 36, t0, t1, t2, t3);
		// Если кругов больше десяти (AES-192 и AES-256)
		if(ROUNDS > 10){
			// Выполняем круги десять и одиннадцать
			openRound(t0, t1, t2, t3, keys + 40, s0, s1, s2, s3);
			openRound(s0, s1, s2, s3, keys + 44, t0, t1, t2, t3);
		}
		// Если кругов больше двенадцати (AES-256)
		if(ROUNDS > 12){
			// Выполняем круги двенадцать и тринадцать
			openRound(t0, t1, t2, t3, keys + 48, s0, s1, s2, s3);
			openRound(s0, s1, s2, s3, keys + 52, t0, t1, t2, t3);
		}
		// Заключительная подстановка с последним ключом
		openLast(t0, t1, t2, t3, keys + (ROUNDS * 4), s0, s1, s2, s3);
	}
	/**
	 * @brief Круг шифрования таблицами четырёх блоков разом
	 *
	 * @param key ключ круга
	 * @param a0…a3 слова состояния блока
	 * @param b0…b3 слова состояния блока
	 * @param c0…c3 слова состояния блока
	 * @param d0…d3 слова состояния блока
	 * @param x0…x3 место слов нового состояния блока
	 * @param y0…y3 место слов нового состояния блока
	 * @param z0…z3 место слов нового состояния блока
	 * @param w0…w3 место слов нового состояния блока
	 *
	 */
	static __ANTS_INLINE__ void sealMany(const uint32_t * key, const word_t a0, const word_t a1, const word_t a2, const word_t a3, const word_t b0, const word_t b1, const word_t b2, const word_t b3, const word_t c0, const word_t c1, const word_t c2, const word_t c3, const word_t d0, const word_t d1, const word_t d2, const word_t d3, word_t & x0, word_t & x1, word_t & x2, word_t & x3, word_t & y0, word_t & y1, word_t & y2, word_t & y3, word_t & z0, word_t & z1, word_t & z2, word_t & z3, word_t & w0, word_t & w1, word_t & w2, word_t & w3) noexcept {
		// Шифруем четыре блока одним ключом круга
		sealRound(a0, a1, a2, a3, key, x0, x1, x2, x3);
		sealRound(b0, b1, b2, b3, key, y0, y1, y2, y3);
		sealRound(c0, c1, c2, c3, key, z0, z1, z2, z3);
		sealRound(d0, d1, d2, d3, key, w0, w1, w2, w3);
	}
	/**
	 * @brief Функция кругов шифрования четырёх независимых блоков прямой линией
	 *
	 * @details Четыре блока идут одним телом, круг за кругом без цикла: на Эльбрусе
	 *          круг одного блока упирается в задержки извлечения индекса, чтения таблицы
	 *          и сложения, а независимые блоки заполняют широкие команды между ними;
	 *          цикл по кругам lcc сворачивал в конвейерный цикл с платой за вход на
	 *          всякую пачку (круг 51, 29.09.2026)
	 *
	 * @param keys развёрнутое расписание ключей шифрования
	 * @param a0…a3 слова блока: заменяются словами зашифрованного блока
	 * @param b0…b3 слова блока: заменяются словами зашифрованного блока
	 * @param c0…c3 слова блока: заменяются словами зашифрованного блока
	 * @param d0…d3 слова блока: заменяются словами зашифрованного блока
	 *
	 */
	template <size_t ROUNDS>
	static __ANTS_INLINE__ void sealManyWords(const uint32_t * keys, word_t & a0, word_t & a1, word_t & a2, word_t & a3, word_t & b0, word_t & b1, word_t & b2, word_t & b3, word_t & c0, word_t & c1, word_t & c2, word_t & c3, word_t & d0, word_t & d1, word_t & d2, word_t & d3) noexcept {
		// Складываем блоки с первым ключом
		a0 ^= keys[0], a1 ^= keys[1], a2 ^= keys[2], a3 ^= keys[3];
		// Складываем второй блок с первым ключом
		b0 ^= keys[0], b1 ^= keys[1], b2 ^= keys[2], b3 ^= keys[3];
		// Складываем третий блок с первым ключом
		c0 ^= keys[0], c1 ^= keys[1], c2 ^= keys[2], c3 ^= keys[3];
		// Складываем четвёртый блок с первым ключом
		d0 ^= keys[0], d1 ^= keys[1], d2 ^= keys[2], d3 ^= keys[3];
		// Вторые состояния пары кругов
		word_t x0 = 0, x1 = 0, x2 = 0, x3 = 0, y0 = 0, y1 = 0, y2 = 0, y3 = 0, z0 = 0, z1 = 0, z2 = 0, z3 = 0, w0 = 0, w1 = 0, w2 = 0, w3 = 0;
		// Выполняем полные круги парами четырёх блоков
		sealMany(keys + 4, a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, d0, d1, d2, d3, x0, x1, x2, x3, y0, y1, y2, y3, z0, z1, z2, z3, w0, w1, w2, w3);
		sealMany(keys + 8, x0, x1, x2, x3, y0, y1, y2, y3, z0, z1, z2, z3, w0, w1, w2, w3, a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, d0, d1, d2, d3);
		sealMany(keys + 12, a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, d0, d1, d2, d3, x0, x1, x2, x3, y0, y1, y2, y3, z0, z1, z2, z3, w0, w1, w2, w3);
		sealMany(keys + 16, x0, x1, x2, x3, y0, y1, y2, y3, z0, z1, z2, z3, w0, w1, w2, w3, a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, d0, d1, d2, d3);
		sealMany(keys + 20, a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, d0, d1, d2, d3, x0, x1, x2, x3, y0, y1, y2, y3, z0, z1, z2, z3, w0, w1, w2, w3);
		sealMany(keys + 24, x0, x1, x2, x3, y0, y1, y2, y3, z0, z1, z2, z3, w0, w1, w2, w3, a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, d0, d1, d2, d3);
		sealMany(keys + 28, a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, d0, d1, d2, d3, x0, x1, x2, x3, y0, y1, y2, y3, z0, z1, z2, z3, w0, w1, w2, w3);
		sealMany(keys + 32, x0, x1, x2, x3, y0, y1, y2, y3, z0, z1, z2, z3, w0, w1, w2, w3, a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, d0, d1, d2, d3);
		sealMany(keys + 36, a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, d0, d1, d2, d3, x0, x1, x2, x3, y0, y1, y2, y3, z0, z1, z2, z3, w0, w1, w2, w3);
		// Если кругов больше десяти (AES-192 и AES-256)
		if(ROUNDS > 10){
			// Выполняем круги десять и одиннадцать четырёх блоков
			sealMany(keys + 40, x0, x1, x2, x3, y0, y1, y2, y3, z0, z1, z2, z3, w0, w1, w2, w3, a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, d0, d1, d2, d3);
			sealMany(keys + 44, a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, d0, d1, d2, d3, x0, x1, x2, x3, y0, y1, y2, y3, z0, z1, z2, z3, w0, w1, w2, w3);
		}
		// Если кругов больше двенадцати (AES-256)
		if(ROUNDS > 12){
			// Выполняем круги двенадцать и тринадцать четырёх блоков
			sealMany(keys + 48, x0, x1, x2, x3, y0, y1, y2, y3, z0, z1, z2, z3, w0, w1, w2, w3, a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, d0, d1, d2, d3);
			sealMany(keys + 52, a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, d0, d1, d2, d3, x0, x1, x2, x3, y0, y1, y2, y3, z0, z1, z2, z3, w0, w1, w2, w3);
		}
		// Заключительная подстановка с последним ключом
		sealLast(x0, x1, x2, x3, keys + (ROUNDS * 4), a0, a1, a2, a3);
		sealLast(y0, y1, y2, y3, keys + (ROUNDS * 4), b0, b1, b2, b3);
		sealLast(z0, z1, z2, z3, keys + (ROUNDS * 4), c0, c1, c2, c3);
		sealLast(w0, w1, w2, w3, keys + (ROUNDS * 4), d0, d1, d2, d3);
	}
	/**
	 * @brief Функция шифрования одного блока таблицами с известным на сборке числом кругов
	 *
	 * @param keys   развёрнутое расписание ключей шифрования
	 * @param source шифруемый блок
	 * @param result место, в которое помещается зашифрованный блок
	 *
	 */
	template <size_t ROUNDS>
	static void sealTables(const uint32_t * keys, const uint8_t * source, uint8_t * result) noexcept {
		// Слова блока от старшего байта
		word_t s0 = load(source), s1 = load(source + 4), s2 = load(source + 8), s3 = load(source + 12);
		// Шифруем блок прямой линией кругов
		sealWords <ROUNDS> (keys, s0, s1, s2, s3);
		// Записываем зашифрованный блок
		store(s0, result), store(s1, result + 4), store(s2, result + 8), store(s3, result + 12);
	}
	/**
	 * @brief Функция расшифрования одного блока таблицами с известным на сборке числом кругов
	 *
	 * @param keys   развёрнутое расписание ключей расшифрования
	 * @param source расшифровываемый блок
	 * @param result место, в которое помещается расшифрованный блок
	 *
	 */
	template <size_t ROUNDS>
	static void openTables(const uint32_t * keys, const uint8_t * source, uint8_t * result) noexcept {
		// Слова блока от старшего байта
		word_t s0 = load(source), s1 = load(source + 4), s2 = load(source + 8), s3 = load(source + 12);
		// Расшифровываем блок прямой линией кругов
		openWords <ROUNDS> (keys, s0, s1, s2, s3);
		// Записываем расшифрованный блок
		store(s0, result), store(s1, result + 4), store(s2, result + 8), store(s3, result + 12);
	}
	/**
	 * @brief Функция шифрования четырёх блоков таблицами разом
	 *
	 * @param keys   развёрнутое расписание ключей шифрования
	 * @param source четыре шифруемых блоков подряд
	 * @param result место, в которое помещаются зашифрованные блоки
	 *
	 */
	template <size_t ROUNDS>
	static void sealFour(const uint32_t * keys, const uint8_t * source, uint8_t * result) noexcept {
		// Слова блоков от старшего байта
		word_t a0 = load(source + 0), a1 = load(source + 4), a2 = load(source + 8), a3 = load(source + 12);
		// Слова второго блока от старшего байта
		word_t b0 = load(source + 16), b1 = load(source + 20), b2 = load(source + 24), b3 = load(source + 28);
		// Слова третьего блока от старшего байта
		word_t c0 = load(source + 32), c1 = load(source + 36), c2 = load(source + 40), c3 = load(source + 44);
		// Слова четвёртого блока от старшего байта
		word_t d0 = load(source + 48), d1 = load(source + 52), d2 = load(source + 56), d3 = load(source + 60);
		// Шифруем блоки одним телом
		sealManyWords <ROUNDS> (keys, a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, d0, d1, d2, d3);
		// Записываем зашифрованные блоки
		store(a0, result + 0), store(a1, result + 4), store(a2, result + 8), store(a3, result + 12);
		store(b0, result + 16), store(b1, result + 20), store(b2, result + 24), store(b3, result + 28);
		store(c0, result + 32), store(c1, result + 36), store(c2, result + 40), store(c3, result + 44);
		store(d0, result + 48), store(d1, result + 52), store(d2, result + 56), store(d3, result + 60);
	}
	/**
	 * Если есть ветвь команд AES расширения ARMv8
	 */
	#if defined(__ANTS_AES_ARM__)
		/**
		 * @brief Функция зашифрования сообщения цепочкой сцепления командами AESE и AESMC
		 *
		 * @param keys   раундовые ключи байтами в порядке памяти
		 * @param rounds число раундов
		 * @param record регистр сдвига: на входе прежнее заполнение, на выходе последний шифрблок
		 * @param source зашифровываемое сообщение
		 * @param size   длина сообщения в байтах
		 * @param result место, в которое записывается шифртекст
		 *
		 */
		static __ANTS_AES_TARGET__ void chainArm(const uint8_t * keys, const size_t rounds, uint8_t * record, const uint8_t * source, const size_t size, uint8_t * result) noexcept {
			// Регистр сцепления держится вектором на весь проход
			uint8x16_t state = vld1q_u8(record);
			// Число блоков сообщения
			const size_t blocks = size >> 4;
			/**
			 * Выполняем перебор блоков сообщения
			 */
			for(size_t b = 0; b < blocks; b++){
				// Складываем блок сообщения с регистром сцепления
				state = veorq_u8(state, vld1q_u8(source + (b << 4)));
				/**
				 * Выполняем внутренние раунды: подстановка со сдвигом и ключом, затем перемешивание
				 */
				for(size_t round = 0; (round + 1) < rounds; round++)
				// Выполняем раунд командами AESE и AESMC
				state = vaesmcq_u8(vaeseq_u8(state, vld1q_u8(keys + (round * 16))));
				// Выполняем последний раунд без перемешивания и складываем с последним ключом
				state = veorq_u8(vaeseq_u8(state, vld1q_u8(keys + ((rounds - 1) * 16))), vld1q_u8(keys + (rounds * 16)));
				// Записываем шифрблок на место итога
				vst1q_u8(result + (b << 4), state);
			}
			// Записываем последний шифрблок в регистр сцепления
			vst1q_u8(record, state);
		}
	#endif
	/**
	 * Если есть ветвь команд AES-NI
	 */
	#if defined(__ANTS_AES_X86__)
		/**
		 * @brief Функция зашифрования сообщения цепочкой сцепления командами AES-NI
		 *
		 * @param keys   раундовые ключи байтами в порядке памяти
		 * @param rounds число раундов
		 * @param record регистр сдвига: на входе прежнее заполнение, на выходе последний шифрблок
		 * @param source зашифровываемое сообщение
		 * @param size   длина сообщения в байтах
		 * @param result место, в которое записывается шифртекст
		 *
		 */
		static __ANTS_AES_TARGET__ void chainX86(const uint8_t * keys, const size_t rounds, uint8_t * record, const uint8_t * source, const size_t size, uint8_t * result) noexcept {
			// Регистр сцепления держится вектором на весь проход
			__m128i state = _mm_loadu_si128(reinterpret_cast <const __m128i *> (record));
			// Число блоков сообщения
			const size_t blocks = size >> 4;
			/**
			 * Выполняем перебор блоков сообщения
			 */
			for(size_t b = 0; b < blocks; b++){
				// Складываем блок сообщения с регистром сцепления
				state = _mm_xor_si128(state, _mm_loadu_si128(reinterpret_cast <const __m128i *> (source + (b << 4))));
				/**
				 * Выполняем внутренние раунды: подстановка со сдвигом и ключом, затем перемешивание
				 */
				for(size_t round = 0; (round + 1) < rounds; round++)
				// Выполняем раунд командами AESENC
				state = _mm_aesenc_si128(state, _mm_loadu_si128(reinterpret_cast <const __m128i *> (keys + (round * 16))));
				// Выполняем последний раунд без перемешивания и складываем с последним ключом
				state = _mm_aesenclast_si128(state, _mm_loadu_si128(reinterpret_cast <const __m128i *> (keys + (rounds * 16))));
				// Записываем шифрблок на место итога
				_mm_storeu_si128(reinterpret_cast <__m128i *> (result + (b << 4)), state);
			}
			// Записываем последний шифрблок в регистр сцепления
			_mm_storeu_si128(reinterpret_cast <__m128i *> (record), state);
		}
	#endif
	/**
	 * @brief Функция выработки гаммы таблицами: по четыре блоков счётчика разом
	 *
	 * @details Счётчики собираются словами, а гамма накладывается на слова исходных данных
	 *          в порядке машины: буферов на стеке нет, и затирать нечего. Байтовые
	 *          записи гаммы с последующим чтением словами стопорили конвейер памяти Эльбруса
	 *          (круг 51, 29.09.2026). Ядро продвигает лишь младшие четыре байта счётчика по кругу
	 *
	 * @param keys    развёрнутое расписание ключей шифрования
	 * @param counter начальное значение счётчика: ядро начинает с приращения
	 * @param blocks  число блоков гаммы
	 * @param source  исходные данные, на которые гамма накладывается: пусто, если нужна сама гамма
	 * @param result  место, в которое помещается гамма либо исходные данные под ней
	 *
	 */
	template <size_t ROUNDS>
	static void streamTables(const uint32_t * keys, const uint8_t * counter, const size_t blocks, const uint8_t * source, uint8_t * result) noexcept {
		// Старшие двенадцать байтов счётчика словами: не меняются
		const word_t head0 = load(counter), head1 = load(counter + 4), head2 = load(counter + 8);
		// Младшие четыре байта счётчика числом по кругу: ядро начинает с приращения
		uint32_t tail = (load(counter + 12) + 1);
		// Число оставшихся блоков
		size_t left = blocks;
		/**
		 * Выполняем выработку гаммы по четыре блоков
		 */
		while(left >= 4){
			// Блоки счётчика словами
			word_t a0 = head0, a1 = head1, a2 = head2, a3 = tail;
			// Второй блок счётчика словами
			word_t b0 = head0, b1 = head1, b2 = head2, b3 = (tail + 1);
			// Третий блок счётчика словами
			word_t c0 = head0, c1 = head1, c2 = head2, c3 = (tail + 2);
			// Четвёртый блок счётчика словами
			word_t d0 = head0, d1 = head1, d2 = head2, d3 = (tail + 3);
			// Шифруем блоки счётчика разом в гамму
			sealManyWords <ROUNDS> (keys, a0, a1, a2, a3, b0, b1, b2, b3, c0, c1, c2, c3, d0, d1, d2, d3);
			// Если гамма накладывается на исходные данные
			if(source != nullptr){
				// Записываем слова исходных данных под гаммой: исходные данные вправе совпадать с местом записи
				nativeStore(native(source + 0) ^ swap(a0), result + 0), nativeStore(native(source + 4) ^ swap(a1), result + 4), nativeStore(native(source + 8) ^ swap(a2), result + 8), nativeStore(native(source + 12) ^ swap(a3), result + 12);
				nativeStore(native(source + 16) ^ swap(b0), result + 16), nativeStore(native(source + 20) ^ swap(b1), result + 20), nativeStore(native(source + 24) ^ swap(b2), result + 24), nativeStore(native(source + 28) ^ swap(b3), result + 28);
				nativeStore(native(source + 32) ^ swap(c0), result + 32), nativeStore(native(source + 36) ^ swap(c1), result + 36), nativeStore(native(source + 40) ^ swap(c2), result + 40), nativeStore(native(source + 44) ^ swap(c3), result + 44);
				nativeStore(native(source + 48) ^ swap(d0), result + 48), nativeStore(native(source + 52) ^ swap(d1), result + 52), nativeStore(native(source + 56) ^ swap(d2), result + 56), nativeStore(native(source + 60) ^ swap(d3), result + 60);
				// Сдвигаем позицию чтения
				source += 64;
			// Иначе гамма пишется сразу на место
			} else {
				// Записываем блоки гаммы от старшего байта
				store(a0, result + 0), store(a1, result + 4), store(a2, result + 8), store(a3, result + 12);
				store(b0, result + 16), store(b1, result + 20), store(b2, result + 24), store(b3, result + 28);
				store(c0, result + 32), store(c1, result + 36), store(c2, result + 40), store(c3, result + 44);
				store(d0, result + 48), store(d1, result + 52), store(d2, result + 56), store(d3, result + 60);
			}
			// Сдвигаем позицию записи
			result += 64;
			// Продвигаем счётчик на выработанные блоки
			tail += 4;
			// Уменьшаем число оставшихся блоков
			left -= 4;
		}
		/**
		 * Выполняем выработку хвоста гаммы по блоку
		 */
		while(left > 0){
			// Блок счётчика словами
			word_t s0 = head0, s1 = head1, s2 = head2, s3 = tail;
			// Шифруем блок счётчика в гамму
			sealWords <ROUNDS> (keys, s0, s1, s2, s3);
			// Если гамма накладывается на исходные данные
			if(source != nullptr){
				// Записываем слова исходных данных под гаммой
				nativeStore(native(source) ^ swap(s0), result), nativeStore(native(source + 4) ^ swap(s1), result + 4), nativeStore(native(source + 8) ^ swap(s2), result + 8), nativeStore(native(source + 12) ^ swap(s3), result + 12);
				// Сдвигаем позицию чтения
				source += 16;
			// Иначе гамма пишется сразу на место
			} else
				// Записываем блок гаммы
				store(s0, result), store(s1, result + 4), store(s2, result + 8), store(s3, result + 12);
			// Сдвигаем позицию записи
			result += 16;
			// Продвигаем счётчик
			tail++;
			// Уменьшаем число оставшихся блоков
			left--;
		}
	}

	/**
	 * Если есть ветвь команд AES расширения ARMv8
	 */
	#if defined(__ANTS_AES_ARM__)
		/**
		 * @brief Функция выработки гаммы счётчика командами по четыре блока разом
		 *
		 * @param keys    раундовые ключи байтами в порядке памяти
		 * @param rounds  число раундов
		 * @param counter начальный блок счётчика
		 * @param blocks  число блоков гаммы
		 * @param source  исходные данные, на которые гамма накладывается: пусто, если нужна сама гамма
		 * @param result  место, в которое записывается гамма либо исходные данные под ней
		 *
		 */
		static __ANTS_AES_TARGET__ void streamArm(const uint8_t * keys, const size_t rounds, const uint8_t * counter, const size_t blocks, const uint8_t * source, uint8_t * result) noexcept {
			// Текущее значение счётчика
			uint8_t current[16];
			// Копируем начальное значение счётчика
			::memcpy(current, counter, sizeof(current));
			// Последний ключ раунда
			const uint8x16_t last = vld1q_u8(keys + (rounds * 16));
			// Начальный блок счётчика словами: младшие четыре байта подставляются в старшее слово
			const uint32x4_t base = vreinterpretq_u32_u8(vld1q_u8(current));
			// Шаги счётчика в переставленном слове: единица, двойка и четвёрка в старшем байте слова
			const uint32x4_t step1 = vsetq_lane_u32(0x01000000U, vdupq_n_u32(0), 3);
			// Двойной шаг счётчика
			const uint32x4_t step2 = vaddq_u32(step1, step1);
			// Четверной шаг счётчика
			const uint32x4_t step4 = vaddq_u32(step2, step2);
			// Младшие четыре байта счётчика числом
			uint32_t tail = (static_cast <uint32_t> (current[12]) << 24) | (static_cast <uint32_t> (current[13]) << 16) | (static_cast <uint32_t> (current[14]) << 8) | static_cast <uint32_t> (current[15]);
			// Число оставшихся блоков
			size_t left = blocks;
			/**
			 * Выполняем выработку гаммы по восемь блоков: столько блоков держит в полёте
			 * конвейер команд AES
			 */
			while(left >= 8){
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
					const uint32x4_t c0 = vaddq_u32(vsetq_lane_u32(reversed(tail), base, 3), step1);
					// Второй счётчик восьмёрки
					const uint32x4_t c1 = vaddq_u32(c0, step1);
					// Третий счётчик восьмёрки
					const uint32x4_t c2 = vaddq_u32(c0, step2);
					// Четвёртый счётчик восьмёрки
					const uint32x4_t c3 = vaddq_u32(c1, step2);
					// Собираем восемь блоков счётчика сложениями
					s0 = vreinterpretq_u8_u32(c0);
					// Второй блок счётчика
					s1 = vreinterpretq_u8_u32(c1);
					// Третий блок счётчика
					s2 = vreinterpretq_u8_u32(c2);
					// Четвёртый блок счётчика
					s3 = vreinterpretq_u8_u32(c3);
					// Пятый блок счётчика
					s4 = vreinterpretq_u8_u32(vaddq_u32(c0, step4));
					// Шестой блок счётчика
					s5 = vreinterpretq_u8_u32(vaddq_u32(c1, step4));
					// Седьмой блок счётчика
					s6 = vreinterpretq_u8_u32(vaddq_u32(c2, step4));
					// Восьмой блок счётчика
					s7 = vreinterpretq_u8_u32(vaddq_u32(c3, step4));
				// Иначе младший байт переполняется внутри восьмёрки
				} else {
					// Собираем восемь блоков счётчика по одному
					s0 = vreinterpretq_u8_u32(vsetq_lane_u32(reversed(tail + 1), base, 3));
					// Второй блок счётчика по одному
					s1 = vreinterpretq_u8_u32(vsetq_lane_u32(reversed(tail + 2), base, 3));
					// Третий блок счётчика по одному
					s2 = vreinterpretq_u8_u32(vsetq_lane_u32(reversed(tail + 3), base, 3));
					// Четвёртый блок счётчика по одному
					s3 = vreinterpretq_u8_u32(vsetq_lane_u32(reversed(tail + 4), base, 3));
					// Пятый блок счётчика по одному
					s4 = vreinterpretq_u8_u32(vsetq_lane_u32(reversed(tail + 5), base, 3));
					// Шестой блок счётчика по одному
					s5 = vreinterpretq_u8_u32(vsetq_lane_u32(reversed(tail + 6), base, 3));
					// Седьмой блок счётчика по одному
					s6 = vreinterpretq_u8_u32(vsetq_lane_u32(reversed(tail + 7), base, 3));
					// Восьмой блок счётчика по одному
					s7 = vreinterpretq_u8_u32(vsetq_lane_u32(reversed(tail + 8), base, 3));
				}
				// Сдвигаем счётчик на восемь блоков
				tail += 8;
				/**
				 * Выполняем круги шифрования восьми блоков разом
				 */
				for(size_t round = 0; (round + 1) < rounds; round++){
					// Ключ круга
					const uint8x16_t key = vld1q_u8(keys + (round * 16));
					// Выполняем круг для каждого блока
					s0 = vaesmcq_u8(vaeseq_u8(s0, key));
					// Выполняем круг для второго блока
					s1 = vaesmcq_u8(vaeseq_u8(s1, key));
					// Выполняем круг для третьего блока
					s2 = vaesmcq_u8(vaeseq_u8(s2, key));
					// Выполняем круг для четвёртого блока
					s3 = vaesmcq_u8(vaeseq_u8(s3, key));
					// Выполняем круг для пятого блока
					s4 = vaesmcq_u8(vaeseq_u8(s4, key));
					// Выполняем круг для шестого блока
					s5 = vaesmcq_u8(vaeseq_u8(s5, key));
					// Выполняем круг для седьмого блока
					s6 = vaesmcq_u8(vaeseq_u8(s6, key));
					// Выполняем круг для восьмого блока
					s7 = vaesmcq_u8(vaeseq_u8(s7, key));
				}
				// Ключ последнего круга
				const uint8x16_t key = vld1q_u8(keys + ((rounds - 1) * 16));
				// Если гамма накладывается на исходные данные
				if(source != nullptr){
					// Записываем восемь блоков исходных данных под гаммой
					vst1q_u8(result, veorq_u8(veorq_u8(vaeseq_u8(s0, key), last), vld1q_u8(source)));
					vst1q_u8(result + 16, veorq_u8(veorq_u8(vaeseq_u8(s1, key), last), vld1q_u8(source + 16)));
					vst1q_u8(result + 32, veorq_u8(veorq_u8(vaeseq_u8(s2, key), last), vld1q_u8(source + 32)));
					vst1q_u8(result + 48, veorq_u8(veorq_u8(vaeseq_u8(s3, key), last), vld1q_u8(source + 48)));
					vst1q_u8(result + 64, veorq_u8(veorq_u8(vaeseq_u8(s4, key), last), vld1q_u8(source + 64)));
					vst1q_u8(result + 80, veorq_u8(veorq_u8(vaeseq_u8(s5, key), last), vld1q_u8(source + 80)));
					vst1q_u8(result + 96, veorq_u8(veorq_u8(vaeseq_u8(s6, key), last), vld1q_u8(source + 96)));
					vst1q_u8(result + 112, veorq_u8(veorq_u8(vaeseq_u8(s7, key), last), vld1q_u8(source + 112)));
					// Сдвигаем позицию чтения
					source += 128;
				// Иначе записывается сама гамма
				} else {
					// Записываем восемь блоков гаммы
					vst1q_u8(result, veorq_u8(vaeseq_u8(s0, key), last));
					vst1q_u8(result + 16, veorq_u8(vaeseq_u8(s1, key), last));
					vst1q_u8(result + 32, veorq_u8(vaeseq_u8(s2, key), last));
					vst1q_u8(result + 48, veorq_u8(vaeseq_u8(s3, key), last));
					vst1q_u8(result + 64, veorq_u8(vaeseq_u8(s4, key), last));
					vst1q_u8(result + 80, veorq_u8(vaeseq_u8(s5, key), last));
					vst1q_u8(result + 96, veorq_u8(vaeseq_u8(s6, key), last));
					vst1q_u8(result + 112, veorq_u8(vaeseq_u8(s7, key), last));
				}
				// Сдвигаем позицию записи
				result += 128;
				// Уменьшаем число оставшихся блоков
				left -= 8;
			}
			// Записываем сдвинутый счётчик от старшего байта
			current[12] = static_cast <uint8_t> (tail >> 24);
			// Записываем тринадцатый байт сдвинутого счётчика
			current[13] = static_cast <uint8_t> (tail >> 16);
			// Записываем четырнадцатый байт сдвинутого счётчика
			current[14] = static_cast <uint8_t> (tail >> 8);
			// Записываем пятнадцатый байт сдвинутого счётчика
			current[15] = static_cast <uint8_t> (tail);
			/**
			 * Выполняем выработку хвоста гаммы по блоку
			 */
			while(left > 0){
				// Увеличиваем счётчик
				advance(current);
				// Если гамма накладывается на исходные данные
				if(source != nullptr){
					// Блок исходных данных читается до шифрования: он вправе совпадать с местом записи
					const uint8x16_t plain = vld1q_u8(source);
					// Шифруем блок счётчика
					sealArm(keys, rounds, current, result);
					// Накладываем гамму на блок исходных данных
					vst1q_u8(result, veorq_u8(vld1q_u8(result), plain));
					// Сдвигаем позицию чтения
					source += 16;
				// Иначе гамма пишется сразу на место
				} else
				// Шифруем блок счётчика
				sealArm(keys, rounds, current, result);
				// Сдвигаем позицию записи
				result += 16;
				// Уменьшаем число оставшихся блоков
				left--;
			}
			// Выполняем затирание счётчика
			wipe(current, sizeof(current));
		}
		/**
		 * Иначе если есть ветвь команд AES-NI
		 */
	#elif defined(__ANTS_AES_X86__)
		/**
		 * @brief Функция выработки гаммы счётчика командами по четыре блока разом
		 *
		 * @param keys    раундовые ключи байтами в порядке памяти
		 * @param rounds  число раундов
		 * @param counter начальный блок счётчика
		 * @param blocks  число блоков гаммы
		 * @param source  исходные данные, на которые гамма накладывается: пусто, если нужна сама гамма
		 * @param result  место, в которое записывается гамма либо исходные данные под ней
		 *
		 */
		static __ANTS_AES_TARGET__ void streamX86(const uint8_t * keys, const size_t rounds, const uint8_t * counter, const size_t blocks, const uint8_t * source, uint8_t * result) noexcept {
			// Текущее значение счётчика
			uint8_t current[16];
			// Копируем начальное значение счётчика
			::memcpy(current, counter, sizeof(current));
			// Первый ключ раунда
			const __m128i first = _mm_loadu_si128(reinterpret_cast <const __m128i *> (keys));
			// Последний ключ раунда
			const __m128i last = _mm_loadu_si128(reinterpret_cast <const __m128i *> (keys + (rounds * 16)));
			/**
			 * Счётчик держится в регистре: старшие двенадцать байтов не меняются и берутся
			 * маской, а младшие четыре идут числом от старшего байта и подставляются в
			 * старшее слово; перенос за пределы четырёх байтов не делается, как и у
			 * побайтового переноса
			 */
			const __m128i head = _mm_and_si128(_mm_loadu_si128(reinterpret_cast <const __m128i *> (current)), _mm_set_epi32(0, -1, -1, -1));
			// Шаги счётчика в переставленном слове: единица, двойка и четвёрка в старшем байте слова
			const __m128i step1 = _mm_set_epi32(0x01000000, 0, 0, 0);
			// Двойной шаг счётчика
			const __m128i step2 = _mm_add_epi32(step1, step1);
			// Четверной шаг счётчика
			const __m128i step4 = _mm_add_epi32(step2, step2);
			// Младшие четыре байта счётчика числом
			uint32_t tail = (static_cast <uint32_t> (current[12]) << 24) | (static_cast <uint32_t> (current[13]) << 16) | (static_cast <uint32_t> (current[14]) << 8) | static_cast <uint32_t> (current[15]);
			// Число оставшихся блоков
			size_t left = blocks;
			/**
			 * Выполняем выработку гаммы по восемь блоков: столько блоков держит в полёте
			 * конвейер команд AES
			 */
			while(left >= 8){
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
					const __m128i c0 = _mm_add_epi32(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (reversed(tail)), 0, 0, 0)), step1);
					// Второй счётчик восьмёрки
					const __m128i c1 = _mm_add_epi32(c0, step1);
					// Третий счётчик восьмёрки
					const __m128i c2 = _mm_add_epi32(c0, step2);
					// Четвёртый счётчик восьмёрки
					const __m128i c3 = _mm_add_epi32(c1, step2);
					// Собираем восемь блоков счётчика сложениями под первым ключом
					s0 = _mm_xor_si128(c0, first);
					// Второй блок счётчика
					s1 = _mm_xor_si128(c1, first);
					// Третий блок счётчика
					s2 = _mm_xor_si128(c2, first);
					// Четвёртый блок счётчика
					s3 = _mm_xor_si128(c3, first);
					// Пятый блок счётчика
					s4 = _mm_xor_si128(_mm_add_epi32(c0, step4), first);
					// Шестой блок счётчика
					s5 = _mm_xor_si128(_mm_add_epi32(c1, step4), first);
					// Седьмой блок счётчика
					s6 = _mm_xor_si128(_mm_add_epi32(c2, step4), first);
					// Восьмой блок счётчика
					s7 = _mm_xor_si128(_mm_add_epi32(c3, step4), first);
				// Иначе младший байт переполняется внутри восьмёрки
				} else {
					// Собираем восемь блоков счётчика по одному под первым ключом
					s0 = _mm_xor_si128(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (reversed(tail + 1)), 0, 0, 0)), first);
					// Второй блок счётчика по одному
					s1 = _mm_xor_si128(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (reversed(tail + 2)), 0, 0, 0)), first);
					// Третий блок счётчика по одному
					s2 = _mm_xor_si128(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (reversed(tail + 3)), 0, 0, 0)), first);
					// Четвёртый блок счётчика по одному
					s3 = _mm_xor_si128(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (reversed(tail + 4)), 0, 0, 0)), first);
					// Пятый блок счётчика по одному
					s4 = _mm_xor_si128(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (reversed(tail + 5)), 0, 0, 0)), first);
					// Шестой блок счётчика по одному
					s5 = _mm_xor_si128(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (reversed(tail + 6)), 0, 0, 0)), first);
					// Седьмой блок счётчика по одному
					s6 = _mm_xor_si128(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (reversed(tail + 7)), 0, 0, 0)), first);
					// Восьмой блок счётчика по одному
					s7 = _mm_xor_si128(_mm_or_si128(head, _mm_set_epi32(static_cast <int> (reversed(tail + 8)), 0, 0, 0)), first);
				}
				// Сдвигаем счётчик на восемь блоков
				tail += 8;
				/**
				 * Выполняем круги шифрования восьми блоков разом
				 */
				for(size_t round = 1; round < rounds; round++){
					// Ключ круга
					const __m128i key = _mm_loadu_si128(reinterpret_cast <const __m128i *> (keys + (round * 16)));
					// Выполняем круг для каждого блока
					s0 = _mm_aesenc_si128(s0, key);
					// Выполняем круг для второго блока
					s1 = _mm_aesenc_si128(s1, key);
					// Выполняем круг для третьего блока
					s2 = _mm_aesenc_si128(s2, key);
					// Выполняем круг для четвёртого блока
					s3 = _mm_aesenc_si128(s3, key);
					// Выполняем круг для пятого блока
					s4 = _mm_aesenc_si128(s4, key);
					// Выполняем круг для шестого блока
					s5 = _mm_aesenc_si128(s5, key);
					// Выполняем круг для седьмого блока
					s6 = _mm_aesenc_si128(s6, key);
					// Выполняем круг для восьмого блока
					s7 = _mm_aesenc_si128(s7, key);
				}
				// Если гамма накладывается на исходные данные
				if(source != nullptr){
					// Записываем восемь блоков исходных данных под гаммой
					_mm_storeu_si128(reinterpret_cast <__m128i *> (result), _mm_xor_si128(_mm_aesenclast_si128(s0, last), _mm_loadu_si128(reinterpret_cast <const __m128i *> (source))));
					_mm_storeu_si128(reinterpret_cast <__m128i *> (result + 16), _mm_xor_si128(_mm_aesenclast_si128(s1, last), _mm_loadu_si128(reinterpret_cast <const __m128i *> (source + 16))));
					_mm_storeu_si128(reinterpret_cast <__m128i *> (result + 32), _mm_xor_si128(_mm_aesenclast_si128(s2, last), _mm_loadu_si128(reinterpret_cast <const __m128i *> (source + 32))));
					_mm_storeu_si128(reinterpret_cast <__m128i *> (result + 48), _mm_xor_si128(_mm_aesenclast_si128(s3, last), _mm_loadu_si128(reinterpret_cast <const __m128i *> (source + 48))));
					_mm_storeu_si128(reinterpret_cast <__m128i *> (result + 64), _mm_xor_si128(_mm_aesenclast_si128(s4, last), _mm_loadu_si128(reinterpret_cast <const __m128i *> (source + 64))));
					_mm_storeu_si128(reinterpret_cast <__m128i *> (result + 80), _mm_xor_si128(_mm_aesenclast_si128(s5, last), _mm_loadu_si128(reinterpret_cast <const __m128i *> (source + 80))));
					_mm_storeu_si128(reinterpret_cast <__m128i *> (result + 96), _mm_xor_si128(_mm_aesenclast_si128(s6, last), _mm_loadu_si128(reinterpret_cast <const __m128i *> (source + 96))));
					_mm_storeu_si128(reinterpret_cast <__m128i *> (result + 112), _mm_xor_si128(_mm_aesenclast_si128(s7, last), _mm_loadu_si128(reinterpret_cast <const __m128i *> (source + 112))));
					// Сдвигаем позицию чтения
					source += 128;
				// Иначе записывается сама гамма
				} else {
					// Записываем восемь блоков гаммы
					_mm_storeu_si128(reinterpret_cast <__m128i *> (result), _mm_aesenclast_si128(s0, last));
					_mm_storeu_si128(reinterpret_cast <__m128i *> (result + 16), _mm_aesenclast_si128(s1, last));
					_mm_storeu_si128(reinterpret_cast <__m128i *> (result + 32), _mm_aesenclast_si128(s2, last));
					_mm_storeu_si128(reinterpret_cast <__m128i *> (result + 48), _mm_aesenclast_si128(s3, last));
					_mm_storeu_si128(reinterpret_cast <__m128i *> (result + 64), _mm_aesenclast_si128(s4, last));
					_mm_storeu_si128(reinterpret_cast <__m128i *> (result + 80), _mm_aesenclast_si128(s5, last));
					_mm_storeu_si128(reinterpret_cast <__m128i *> (result + 96), _mm_aesenclast_si128(s6, last));
					_mm_storeu_si128(reinterpret_cast <__m128i *> (result + 112), _mm_aesenclast_si128(s7, last));
				}
				// Сдвигаем позицию записи
				result += 128;
				// Уменьшаем число оставшихся блоков
				left -= 8;
			}
			// Записываем сдвинутый счётчик от старшего байта
			current[12] = static_cast <uint8_t> (tail >> 24);
			// Записываем тринадцатый байт сдвинутого счётчика
			current[13] = static_cast <uint8_t> (tail >> 16);
			// Записываем четырнадцатый байт сдвинутого счётчика
			current[14] = static_cast <uint8_t> (tail >> 8);
			// Записываем пятнадцатый байт сдвинутого счётчика
			current[15] = static_cast <uint8_t> (tail);
			/**
			 * Выполняем выработку хвоста гаммы по блоку
			 */
			while(left > 0){
				// Увеличиваем счётчик
				advance(current);
				// Если гамма накладывается на исходные данные
				if(source != nullptr){
					// Блок исходных данных читается до шифрования: он вправе совпадать с местом записи
					const __m128i plain = _mm_loadu_si128(reinterpret_cast <const __m128i *> (source));
					// Шифруем блок счётчика
					sealX86(keys, rounds, current, result);
					// Накладываем гамму на блок исходных данных
					_mm_storeu_si128(reinterpret_cast <__m128i *> (result), _mm_xor_si128(_mm_loadu_si128(reinterpret_cast <const __m128i *> (result)), plain));
					// Сдвигаем позицию чтения
					source += 16;
				// Иначе гамма пишется сразу на место
				} else
				// Шифруем блок счётчика
				sealX86(keys, rounds, current, result);
				// Сдвигаем позицию записи
				result += 16;
				// Уменьшаем число оставшихся блоков
				left--;
			}
			// Выполняем затирание счётчика
			wipe(current, sizeof(current));
		}
	#endif
};

/**
 * @brief Метод проверки готовности шифра к работе
 *
 * @return признак того, что ключ установлен
 *
 */
bool nts::cipher::Aes::ready() const noexcept {
	// Выводим признак установленного ключа
	return this->_ready;
}
/**
 * @brief Метод установки ключа шифрования
 *
 * @param key устанавливаемый ключ шифрования
 * @return    признак успешности установки ключа
 *
 */
bool nts::cipher::Aes::key(const view_t & key) noexcept {
	// Выполняем сброс прежнего ключа
	this->clear();
	// Если ключ не передан либо его длина не из дозволенных
	if((key.data == nullptr) || ((key.size != 16) && (key.size != 24) && (key.size != 32)))
		// Выводим отказ установки ключа
		return false;
	// Число слов ключа
	const size_t words = (key.size / 4);
	// Число раундов: 10, 12 либо 14
	this->_rounds = (words + 6);
	// Число слов развёрнутого ключа
	const size_t total = (4 * (this->_rounds + 1));
	/**
	 * Выполняем перенос слов ключа в начало развёртки
	 */
	for(size_t i = 0; i < words; i++)
		// Читаем очередное слово ключа от старшего байта
		this->_encryption[i] = load(key.data + (i * 4));
	// Раундовая постоянная
	uint8_t rcon = 0x01;
	/**
	 * Выполняем развёртывание ключа по разделу 5.2 FIPS 197
	 */
	for(size_t i = words; i < total; i++){
		// Предыдущее слово развёртки
		uint32_t item = this->_encryption[i - 1];
		// Если слово кратно длине ключа
		if((i % words) == 0){
			// Сдвигаем слово по кругу на байт, подставляем байты и складываем с постоянной
			item = (substitute((item << 8) | (item >> 24)) ^ (static_cast <uint32_t> (rcon) << 24));
			// Удваиваем раундовую постоянную в поле
			rcon = twice(rcon);
		// Если ключ в восемь слов и слово на его середине
		} else if((words == 8) && ((i % words) == 4))
			// Подставляем байты слова
			item = substitute(item);
		// Складываем очередное слово развёртки
		this->_encryption[i] = (this->_encryption[i - words] ^ item);
	}
	/**
	 * Выполняем развёртывание ключа расшифрования: раундовые ключи в обратном порядке,
	 * а внутренние пропущены через обратное перемешивание столбцов
	 */
	for(size_t i = 0; i < total; i++)
		// Переносим слово в обратном порядке раундов
		this->_decryption[i] = this->_encryption[total - 4 - ((i / 4) * 4) + (i % 4)];
	/**
	 * Выполняем обратное перемешивание столбцов внутренних раундовых ключей
	 */
	for(size_t i = 4; i < (total - 4); i++){
		// Слово раундового ключа
		const uint32_t item = this->_decryption[i];
		// Обратное перемешивание столбца через таблицы расшифрования и подстановку
		this->_decryption[i] = (TABLES.td[0][TABLES.sbox[item >> 24]] ^ TABLES.td[1][TABLES.sbox[(item >> 16) & 0xFF]] ^
		                        TABLES.td[2][TABLES.sbox[(item >> 8) & 0xFF]] ^ TABLES.td[3][TABLES.sbox[item & 0xFF]]);
	}
	/**
	 * Выполняем запись раундовых ключей байтами в порядке памяти
	 */
	for(size_t i = 0; i < total; i++){
		// Записываем слово ключа зашифрования от старшего байта
		store(this->_encryption[i], this->_sealing + (i * 4));
		// Записываем слово ключа расшифрования от старшего байта
		store(this->_decryption[i], this->_opening + (i * 4));
	}
	// Запоминаем, что ключ установлен
	this->_ready = true;
	// Выводим успешность установки ключа
	return true;
}
/**
 * @brief Метод затирания раундовых ключей
 *
 */
void nts::cipher::Aes::clear() noexcept {
	// Сбрасываем признак установленного ключа
	this->_ready = false;
	// Сбрасываем число раундов
	this->_rounds = 0;
	// Выполняем затирание ключей зашифрования
	wipe(this->_encryption, sizeof(this->_encryption));
	// Выполняем затирание ключей расшифрования
	wipe(this->_decryption, sizeof(this->_decryption));
	// Выполняем затирание байтовых ключей зашифрования
	wipe(this->_sealing, sizeof(this->_sealing));
	// Выполняем затирание байтовых ключей расшифрования
	wipe(this->_opening, sizeof(this->_opening));
}
/**
 * @brief Метод зашифрования блока
 *
 * @param source зашифровываемый блок
 * @param result место, в которое помещается зашифрованный блок
 * @return       признак успешности зашифрования
 *
 */
bool nts::cipher::Aes::encrypt(const uint8_t * source, uint8_t * result) const noexcept {
	// Если ключ не установлен либо блоки не переданы
	if(!this->_ready || (source == nullptr) || (result == nullptr))
		// Выводим отказ зашифрования
		return false;
	/**
	 * Если есть ветвь команд AES расширения ARMv8
	 */
	#if defined(__ANTS_AES_ARM__)
		// Если машина шифрует командами
		if(machine::has(machine::feature_t::AES)){
			// Выполняем зашифрование командами
			sealArm(this->_sealing, this->_rounds, source, result);
			// Выводим успешность зашифрования
			return true;
		}
	/**
	 * Если есть ветвь команд AES-NI
	 */
	#elif defined(__ANTS_AES_X86__)
		// Если машина шифрует командами
		if(machine::has(machine::feature_t::AES)){
			// Выполняем зашифрование командами
			sealX86(this->_sealing, this->_rounds, source, result);
			// Выводим успешность зашифрования
			return true;
		}
	#endif
	// Раундовые ключи
	/**
	 * Число кругов известно с установки ключа: путь с ним, заложенным на сборке,
	 * разворачивает круги целиком и держит состояние в регистрах
	 */
	switch(this->_rounds){
		// Круги AES-128
		case 10: sealTables <10> (this->_encryption, source, result); break;
		// Круги AES-192
		case 12: sealTables <12> (this->_encryption, source, result); break;
		// Круги AES-256
		default: sealTables <14> (this->_encryption, source, result); break;
	}
	// Выводим успешность шифрования
	return true;
}
/**
 * @brief Функция расшифрования блока
 *
 * @param source зашифрованный блок
 * @param result место, в которое записывается расшифрованный блок
 * @return       признак успешности расшифрования
 *
 */
/**
 * @brief Метод зашифрования нескольких независимых блоков разом
 *
 * @param sources зашифровываемые блоки подряд
 * @param blocks  число блоков
 * @param results место, в которое помещаются зашифрованные блоки подряд
 * @return        признак успешности зашифрования
 *
 */
bool nts::cipher::Aes::batch(const uint8_t * sources, const size_t blocks, uint8_t * results) const noexcept {
	// Если ключ не установлен либо места не переданы
	if(!this->_ready || ((blocks > 0) && ((sources == nullptr) || (results == nullptr))))
		// Выводим отказ зашифрования
		return false;
	/**
	 * Если есть ветвь команд AES
	 */
	#if defined(__ANTS_AES_ARM__) || defined(__ANTS_AES_X86__)
		// Если у машины есть команды AES: блок за блоком командами, они и так не ждут таблиц
		if(machine::has(machine::feature_t::AES)){
			/**
			 * Выполняем перебор блоков
			 */
			for(size_t i = 0; i < blocks; i++)
			// Шифруем очередной блок командами
			this->encrypt(sources + (i * 16), results + (i * 16));
			// Выводим успешность зашифрования
			return true;
		}
	#endif
	// Число оставшихся блоков
	size_t left = blocks;
	/**
	 * Выполняем шифрование по четыре блоков разом прямой линией кругов
	 */
	while(left >= 4){
		/**
		 * Шифруем четыре блоков таблицами одним телом
		 */
		switch(this->_rounds){
			// Круги AES-128
			case 10: sealFour <10> (this->_encryption, sources, results); break;
			// Круги AES-192
			case 12: sealFour <12> (this->_encryption, sources, results); break;
			// Круги AES-256
			default: sealFour <14> (this->_encryption, sources, results); break;
		}
		// Сдвигаем исходные блоки
		sources += 64;
		// Сдвигаем место итога
		results += 64;
		// Уменьшаем число оставшихся блоков
		left -= 4;
	}
	/**
	 * Выполняем шифрование хвоста по блоку
	 */
	for(size_t i = 0; i < left; i++)
		// Шифруем очередной блок
		this->encrypt(sources + (i * 16), results + (i * 16));
	// Выводим успешность зашифрования
	return true;
}
	/**
	 * @brief Метод расшифрования блока
	 *
	 * @param source расшифровываемый блок
	 * @param result место, в которое помещается расшифрованный блок
	 * @return       признак успешности расшифрования
	 *
	 */
bool nts::cipher::Aes::decrypt(const uint8_t * source, uint8_t * result) const noexcept {
	// Если ключ не установлен либо блоки не переданы
	if(!this->_ready || (source == nullptr) || (result == nullptr))
		// Выводим отказ расшифрования
		return false;
	/**
	 * Если есть ветвь команд AES расширения ARMv8
	 */
	#if defined(__ANTS_AES_ARM__)
		// Если машина шифрует командами
		if(machine::has(machine::feature_t::AES)){
			// Выполняем расшифрование командами
			openArm(this->_opening, this->_rounds, source, result);
			// Выводим успешность расшифрования
			return true;
		}
	/**
	 * Если есть ветвь команд AES-NI
	 */
	#elif defined(__ANTS_AES_X86__)
		// Если машина шифрует командами
		if(machine::has(machine::feature_t::AES)){
			// Выполняем расшифрование командами
			openX86(this->_opening, this->_rounds, source, result);
			// Выводим успешность расшифрования
			return true;
		}
	#endif
	/**
	 * Раундовые ключи расшифрования: число кругов известно с установки ключа,
	 * круги развёрнуты по нему на сборке
	 */
	switch(this->_rounds){
		// Круги AES-128
		case 10: openTables <10> (this->_decryption, source, result); break;
		// Круги AES-192
		case 12: openTables <12> (this->_decryption, source, result); break;
		// Круги AES-256
		default: openTables <14> (this->_decryption, source, result); break;
	}
	// Выводим успешность расшифрования
	return true;
}
/**
 * @brief Метод выработки гаммы счётчика
 *
 * @param counter начальный блок счётчика: младшие 32 разряда растут от старшего байта
 * @param blocks  число блоков гаммы
 * @param source  исходные данные, на которые гамма накладывается: 16 байтов на блок, пусто, если нужна сама гамма
 * @param result  место, в которое записывается гамма либо исходные данные под ней: 16 байтов на блок
 * @return        признак успешности выработки
 *
 */
bool nts::cipher::Aes::stream(const uint8_t * counter, const size_t blocks, const uint8_t * source, uint8_t * result) const noexcept {
	// Если ключ не установлен либо места не переданы
	if(!this->_ready || (counter == nullptr) || ((blocks > 0) && (result == nullptr)))
		// Выводим отказ выработки
		return false;
	/**
	 * Если есть ветвь команд AES расширения ARMv8
	 */
	#if defined(__ANTS_AES_ARM__)
		// Если машина шифрует командами
		if(machine::has(machine::feature_t::AES)){
			// Выполняем выработку гаммы командами
			streamArm(this->_sealing, this->_rounds, counter, blocks, source, result);
			// Выводим успешность выработки
			return true;
		}
	/**
	 * Если есть ветвь команд AES-NI
	 */
	#elif defined(__ANTS_AES_X86__)
		// Если машина шифрует командами
		if(machine::has(machine::feature_t::AES)){
			// Выполняем выработку гаммы командами
			streamX86(this->_sealing, this->_rounds, counter, blocks, source, result);
			// Выводим успешность выработки
			return true;
		}
	#endif
	// Текущий блок счётчика
	/**
	 * Гамма таблицами по четыре блоков разом, круги прямой линией по числу кругов ключа
	 */
	switch(this->_rounds){
		// Круги AES-128
		case 10: streamTables <10> (this->_encryption, counter, blocks, source, result); break;
		// Круги AES-192
		case 12: streamTables <12> (this->_encryption, counter, blocks, source, result); break;
		// Круги AES-256
		default: streamTables <14> (this->_encryption, counter, blocks, source, result); break;
	}
	// Выводим успешность выработки гаммы
	return true;
}
/**
 * @brief Метод зашифрования сообщения цепочкой сцепления блоков
 *
 * @param record регистр сдвига: на входе прежнее заполнение, на выходе последний шифрблок
 * @param source зашифровываемое сообщение
 * @param size   длина сообщения в байтах
 * @param result место, в которое помещается шифртекст
 * @return       признак успешности зашифрования: без команд машины цепочки нет
 *
 */
bool nts::cipher::Aes::chain(uint8_t * record, const uint8_t * source, const size_t size, uint8_t * result) const noexcept {
	// Если ключ не установлен либо регистр не передан
	if(!this->_ready || (record == nullptr))
		// Выводим отказ зашифрования
		return false;
	// Если длина сообщения не кратна блоку
	if((size & 0xF) != 0)
		// Выводим отказ зашифрования
		return false;
	// Если сообщение пусто, регистр сцепления не меняется
	if(size == 0)
		// Выводим успешность зашифрования
		return true;
	// Если места не переданы
	if((source == nullptr) || (result == nullptr))
		// Выводим отказ зашифрования
		return false;
	/**
	 * Если есть ветвь команд AES расширения ARMv8
	 */
	#if defined(__ANTS_AES_ARM__)
	// Если машина шифрует командами
	if(machine::has(machine::feature_t::AES)){
		// Выполняем зашифрование цепочкой командами
		chainArm(this->_sealing, this->_rounds, record, source, size, result);
		// Выводим успешность зашифрования
		return true;
	}
	/**
	 * Если есть ветвь команд AES-NI
	 */
	#elif defined(__ANTS_AES_X86__)
	// Если машина шифрует командами
	if(machine::has(machine::feature_t::AES)){
		// Выполняем зашифрование цепочкой командами
		chainX86(this->_sealing, this->_rounds, record, source, size, result);
		// Выводим успешность зашифрования
		return true;
	}
	#endif
	// Без команд машины цепочки нет: режим ведёт сообщение общим путём
	return false;
}
/**
 * @brief Метод получения расписания ключа зашифрования для слитых ядер режимов
 *
 * @return расписание ключа: ключей на один больше числа кругов, по шестнадцать байтов; пусто без ключа либо без команд машины
 *
 */
const uint8_t * nts::cipher::Aes::schedule() const noexcept {
	/**
	 * Если есть ветвь машинных команд AES
	 */
	#if defined(__ANTS_AES_ARM__) || defined(__ANTS_AES_X86__)
		// Если ключ установлен и команды AES у машины есть
		if(this->_ready && machine::has(machine::feature_t::AES))
		// Выводим расписание ключа зашифрования
		return this->_sealing;
	#endif
	// Выводим пустое расписание: слитым ядрам режимов нечего взять
	return nullptr;
}
/**
 * @brief Метод получения числа кругов шифра
 *
 * @return число кругов: 10, 12 либо 14 по длине ключа, ноль без ключа
 *
 */
size_t nts::cipher::Aes::rounds() const noexcept {
	// Выводим число кругов установленного ключа
	return (this->_ready ? this->_rounds : 0);
}
/**
 * @brief Конструктор
 *
 */
nts::cipher::Aes::Aes() noexcept : _ready(false), _rounds(0) {
	// Выполняем сброс ключа шифрования
	this->clear();
}
/**
 * @brief Деструктор
 *
 */
nts::cipher::Aes::~Aes() noexcept {
	// Выполняем сброс ключа шифрования
	this->clear();
}
