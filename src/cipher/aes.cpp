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

/**
 * @note Обе ветви - командами и таблицами - собираются в один двоичный файл, а выбор
 *       делается на исполнении по опознанию машины (sys/machine.hpp). Команды
 *       порождаются в отдельных функциях с атрибутом цели, оттого общих ключей
 *       расширений сборке не нужно. Признак ANTS_NO_MACHINE выбрасывает ветвь команд
 *       из сборки вовсе
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
#elif defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__)) && !defined(ANTS_NO_MACHINE)
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
	 * @brief Метод удвоения элемента поля GF(2^8)
	 *
	 * @param value удваиваемый элемент
	 *
	 * @return      удвоенный элемент по модулю многочлена поля
	 *
	 */
	static constexpr uint8_t twice(const uint8_t value) noexcept {
		// Выводим удвоенный элемент с приведением по многочлену 0x11B
		return static_cast <uint8_t> ((value << 1) ^ ((value & 0x80) ? 0x1B : 0x00));
	}

	/**
	 * @brief Метод умножения элементов поля GF(2^8)
	 *
	 * @param first  первый множитель
	 * @param second второй множитель
	 *
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
	 * @brief Метод кругового сдвига байта влево
	 *
	 * @param value сдвигаемый байт
	 * @param count число разрядов сдвига
	 *
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
	 * @brief Метод вычисления таблиц преобразования шифра
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
	 * @brief Метод чтения слова от старшего байта
	 *
	 * @param data читаемые байты
	 *
	 * @return     прочитанное слово
	 *
	 */
	static __ANTS_INLINE__ uint32_t load(const uint8_t * data) noexcept {
		// Выводим слово, собранное от старшего байта
		return ((static_cast <uint32_t> (data[0]) << 24) | (static_cast <uint32_t> (data[1]) << 16) |
		        (static_cast <uint32_t> (data[2]) << 8) | static_cast <uint32_t> (data[3]));
	}

	/**
	 * @brief Метод записи слова от старшего байта
	 *
	 * @param value записываемое слово
	 * @param data  место, в которое записываются байты
	 *
	 */
	static __ANTS_INLINE__ void store(const uint32_t value, uint8_t * data) noexcept {
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
	 * @brief Метод подстановки всех байтов слова
	 *
	 * @param value слово, байты которого подставляются
	 *
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
	 * @brief Метод зашифрования блока командами AESE и AESMC
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
	 * @brief Метод расшифрования блока командами AESD и AESIMC
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
	 * @brief Метод зашифрования блока командами AESENC
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
	 * @brief Метод расшифрования блока командами AESDEC
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
	 * @brief Метод увеличения младших 32 разрядов счётчика от старшего байта
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
 * Если есть ветвь команд AES расширения ARMv8
 */
#if defined(__ANTS_AES_ARM__)
	/**
	 * @brief Метод выработки гаммы счётчика командами по четыре блока разом
	 *
	 * @param keys    раундовые ключи байтами в порядке памяти
	 * @param rounds  число раундов
	 * @param counter начальный блок счётчика
	 * @param blocks  число блоков гаммы
	 * @param result  место, в которое записывается гамма
	 *
	 */
	static __ANTS_AES_TARGET__ void streamArm(const uint8_t * keys, const size_t rounds, const uint8_t * counter, const size_t blocks, uint8_t * result) noexcept {
		// Текущий блок счётчика
		uint8_t current[16];
		// Переносим начальный блок счётчика
		::memcpy(current, counter, sizeof(current));
		// Последний ключ
		const uint8x16_t last = vld1q_u8(keys + (rounds * 16));
		// Число ещё не выработанных блоков
		size_t left = blocks;
		/**
		 * Выполняем выработку гаммы по четыре блока
		 */
		while(left >= 4){
			// Увеличиваем счётчик
			advance(current);
			// Первое состояние
			uint8x16_t s0 = vld1q_u8(current);
			// Увеличиваем счётчик
			advance(current);
			// Второе состояние
			uint8x16_t s1 = vld1q_u8(current);
			// Увеличиваем счётчик
			advance(current);
			// Третье состояние
			uint8x16_t s2 = vld1q_u8(current);
			// Увеличиваем счётчик
			advance(current);
			// Четвёртое состояние
			uint8x16_t s3 = vld1q_u8(current);
			/**
			 * Выполняем внутренние раунды над четырьмя состояниями разом
			 */
			for(size_t round = 0; (round + 1) < rounds; round++){
				// Раундовый ключ
				const uint8x16_t key = vld1q_u8(keys + (round * 16));
				// Выполняем раунд первого состояния
				s0 = vaesmcq_u8(vaeseq_u8(s0, key));
				// Выполняем раунд второго состояния
				s1 = vaesmcq_u8(vaeseq_u8(s1, key));
				// Выполняем раунд третьего состояния
				s2 = vaesmcq_u8(vaeseq_u8(s2, key));
				// Выполняем раунд четвёртого состояния
				s3 = vaesmcq_u8(vaeseq_u8(s3, key));
			}
			// Предпоследний ключ
			const uint8x16_t key = vld1q_u8(keys + ((rounds - 1) * 16));
			// Записываем первый блок гаммы
			vst1q_u8(result, veorq_u8(vaeseq_u8(s0, key), last));
			// Записываем второй блок гаммы
			vst1q_u8(result + 16, veorq_u8(vaeseq_u8(s1, key), last));
			// Записываем третий блок гаммы
			vst1q_u8(result + 32, veorq_u8(vaeseq_u8(s2, key), last));
			// Записываем четвёртый блок гаммы
			vst1q_u8(result + 48, veorq_u8(vaeseq_u8(s3, key), last));
			// Сдвигаем позицию записи
			result += 64;
			// Уменьшаем число не выработанных блоков
			left -= 4;
		}
		/**
		 * Выполняем выработку остатка по одному блоку
		 */
		while(left > 0){
			// Увеличиваем счётчик
			advance(current);
			// Выполняем зашифрование блока счётчика
			sealArm(keys, rounds, current, result);
			// Сдвигаем позицию записи
			result += 16;
			// Уменьшаем число не выработанных блоков
			left--;
		}
		// Выполняем затирание счётчика
		wipe(current, sizeof(current));
	}
/**
 * Если есть ветвь команд AES-NI
 */
#elif defined(__ANTS_AES_X86__)
	/**
	 * @brief Метод выработки гаммы счётчика командами по четыре блока разом
	 *
	 * @param keys    раундовые ключи байтами в порядке памяти
	 * @param rounds  число раундов
	 * @param counter начальный блок счётчика
	 * @param blocks  число блоков гаммы
	 * @param result  место, в которое записывается гамма
	 *
	 */
	static __ANTS_AES_TARGET__ void streamX86(const uint8_t * keys, const size_t rounds, const uint8_t * counter, const size_t blocks, uint8_t * result) noexcept {
		// Текущий блок счётчика
		uint8_t current[16];
		// Переносим начальный блок счётчика
		::memcpy(current, counter, sizeof(current));
		// Первый и последний ключи
		const __m128i first = _mm_loadu_si128(reinterpret_cast <const __m128i *> (keys));
		// Последний ключ
		const __m128i last = _mm_loadu_si128(reinterpret_cast <const __m128i *> (keys + (rounds * 16)));
		// Число ещё не выработанных блоков
		size_t left = blocks;
		/**
		 * Выполняем выработку гаммы по четыре блока
		 */
		while(left >= 4){
			// Увеличиваем счётчик
			advance(current);
			// Первое состояние
			__m128i s0 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast <const __m128i *> (current)), first);
			// Увеличиваем счётчик
			advance(current);
			// Второе состояние
			__m128i s1 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast <const __m128i *> (current)), first);
			// Увеличиваем счётчик
			advance(current);
			// Третье состояние
			__m128i s2 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast <const __m128i *> (current)), first);
			// Увеличиваем счётчик
			advance(current);
			// Четвёртое состояние
			__m128i s3 = _mm_xor_si128(_mm_loadu_si128(reinterpret_cast <const __m128i *> (current)), first);
			/**
			 * Выполняем внутренние раунды над четырьмя состояниями разом
			 */
			for(size_t round = 1; round < rounds; round++){
				// Раундовый ключ
				const __m128i key = _mm_loadu_si128(reinterpret_cast <const __m128i *> (keys + (round * 16)));
				// Выполняем раунд первого состояния
				s0 = _mm_aesenc_si128(s0, key);
				// Выполняем раунд второго состояния
				s1 = _mm_aesenc_si128(s1, key);
				// Выполняем раунд третьего состояния
				s2 = _mm_aesenc_si128(s2, key);
				// Выполняем раунд четвёртого состояния
				s3 = _mm_aesenc_si128(s3, key);
			}
			// Записываем первый блок гаммы
			_mm_storeu_si128(reinterpret_cast <__m128i *> (result), _mm_aesenclast_si128(s0, last));
			// Записываем второй блок гаммы
			_mm_storeu_si128(reinterpret_cast <__m128i *> (result + 16), _mm_aesenclast_si128(s1, last));
			// Записываем третий блок гаммы
			_mm_storeu_si128(reinterpret_cast <__m128i *> (result + 32), _mm_aesenclast_si128(s2, last));
			// Записываем четвёртый блок гаммы
			_mm_storeu_si128(reinterpret_cast <__m128i *> (result + 48), _mm_aesenclast_si128(s3, last));
			// Сдвигаем позицию записи
			result += 64;
			// Уменьшаем число не выработанных блоков
			left -= 4;
		}
		/**
		 * Выполняем выработку остатка по одному блоку
		 */
		while(left > 0){
			// Увеличиваем счётчик
			advance(current);
			// Выполняем зашифрование блока счётчика
			sealX86(keys, rounds, current, result);
			// Сдвигаем позицию записи
			result += 16;
			// Уменьшаем число не выработанных блоков
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
 *
 * @return признак успешности установки ключа
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
 * @brief Метод сброса ключа шифрования
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
 * @param source исходный блок
 * @param result место, в которое записывается зашифрованный блок
 *
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
	const uint32_t * keys = this->_encryption;
	// Слова состояния, сложенные с первым раундовым ключом
	uint32_t s0 = (load(source) ^ keys[0]), s1 = (load(source + 4) ^ keys[1]);
	// Слова состояния, сложенные с первым раундовым ключом
	uint32_t s2 = (load(source + 8) ^ keys[2]), s3 = (load(source + 12) ^ keys[3]);
	/**
	 * Выполняем внутренние раунды по таблицам
	 */
	for(size_t round = 1; round < this->_rounds; round++){
		// Раундовый ключ
		const uint32_t * key = (keys + (round * 4));
		// Первое слово нового состояния
		const uint32_t t0 = (TABLES.te[0][s0 >> 24] ^ TABLES.te[1][(s1 >> 16) & 0xFF] ^ TABLES.te[2][(s2 >> 8) & 0xFF] ^ TABLES.te[3][s3 & 0xFF] ^ key[0]);
		// Второе слово нового состояния
		const uint32_t t1 = (TABLES.te[0][s1 >> 24] ^ TABLES.te[1][(s2 >> 16) & 0xFF] ^ TABLES.te[2][(s3 >> 8) & 0xFF] ^ TABLES.te[3][s0 & 0xFF] ^ key[1]);
		// Третье слово нового состояния
		const uint32_t t2 = (TABLES.te[0][s2 >> 24] ^ TABLES.te[1][(s3 >> 16) & 0xFF] ^ TABLES.te[2][(s0 >> 8) & 0xFF] ^ TABLES.te[3][s1 & 0xFF] ^ key[2]);
		// Четвёртое слово нового состояния
		const uint32_t t3 = (TABLES.te[0][s3 >> 24] ^ TABLES.te[1][(s0 >> 16) & 0xFF] ^ TABLES.te[2][(s1 >> 8) & 0xFF] ^ TABLES.te[3][s2 & 0xFF] ^ key[3]);
		// Переносим новое состояние
		s0 = t0;
		// Переносим новое состояние
		s1 = t1;
		// Переносим новое состояние
		s2 = t2;
		// Переносим новое состояние
		s3 = t3;
	}
	// Последний раундовый ключ
	const uint32_t * last = (keys + (this->_rounds * 4));
	// Последний раунд без перемешивания столбцов: подстановка, сдвиг строк и ключ
	store(((static_cast <uint32_t> (TABLES.sbox[s0 >> 24]) << 24) | (static_cast <uint32_t> (TABLES.sbox[(s1 >> 16) & 0xFF]) << 16) | (static_cast <uint32_t> (TABLES.sbox[(s2 >> 8) & 0xFF]) << 8) | static_cast <uint32_t> (TABLES.sbox[s3 & 0xFF])) ^ last[0], result);
	// Второе слово итога
	store(((static_cast <uint32_t> (TABLES.sbox[s1 >> 24]) << 24) | (static_cast <uint32_t> (TABLES.sbox[(s2 >> 16) & 0xFF]) << 16) | (static_cast <uint32_t> (TABLES.sbox[(s3 >> 8) & 0xFF]) << 8) | static_cast <uint32_t> (TABLES.sbox[s0 & 0xFF])) ^ last[1], result + 4);
	// Третье слово итога
	store(((static_cast <uint32_t> (TABLES.sbox[s2 >> 24]) << 24) | (static_cast <uint32_t> (TABLES.sbox[(s3 >> 16) & 0xFF]) << 16) | (static_cast <uint32_t> (TABLES.sbox[(s0 >> 8) & 0xFF]) << 8) | static_cast <uint32_t> (TABLES.sbox[s1 & 0xFF])) ^ last[2], result + 8);
	// Четвёртое слово итога
	store(((static_cast <uint32_t> (TABLES.sbox[s3 >> 24]) << 24) | (static_cast <uint32_t> (TABLES.sbox[(s0 >> 16) & 0xFF]) << 16) | (static_cast <uint32_t> (TABLES.sbox[(s1 >> 8) & 0xFF]) << 8) | static_cast <uint32_t> (TABLES.sbox[s2 & 0xFF])) ^ last[3], result + 12);
	// Выводим успешность зашифрования
	return true;
}
/**
 * @brief Метод расшифрования блока
 *
 * @param source зашифрованный блок
 * @param result место, в которое записывается расшифрованный блок
 *
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
	// Раундовые ключи расшифрования
	const uint32_t * keys = this->_decryption;
	// Слова состояния, сложенные с первым раундовым ключом
	uint32_t s0 = (load(source) ^ keys[0]), s1 = (load(source + 4) ^ keys[1]);
	// Слова состояния, сложенные с первым раундовым ключом
	uint32_t s2 = (load(source + 8) ^ keys[2]), s3 = (load(source + 12) ^ keys[3]);
	/**
	 * Выполняем внутренние раунды по таблицам расшифрования
	 */
	for(size_t round = 1; round < this->_rounds; round++){
		// Раундовый ключ
		const uint32_t * key = (keys + (round * 4));
		// Первое слово нового состояния
		const uint32_t t0 = (TABLES.td[0][s0 >> 24] ^ TABLES.td[1][(s3 >> 16) & 0xFF] ^ TABLES.td[2][(s2 >> 8) & 0xFF] ^ TABLES.td[3][s1 & 0xFF] ^ key[0]);
		// Второе слово нового состояния
		const uint32_t t1 = (TABLES.td[0][s1 >> 24] ^ TABLES.td[1][(s0 >> 16) & 0xFF] ^ TABLES.td[2][(s3 >> 8) & 0xFF] ^ TABLES.td[3][s2 & 0xFF] ^ key[1]);
		// Третье слово нового состояния
		const uint32_t t2 = (TABLES.td[0][s2 >> 24] ^ TABLES.td[1][(s1 >> 16) & 0xFF] ^ TABLES.td[2][(s0 >> 8) & 0xFF] ^ TABLES.td[3][s3 & 0xFF] ^ key[2]);
		// Четвёртое слово нового состояния
		const uint32_t t3 = (TABLES.td[0][s3 >> 24] ^ TABLES.td[1][(s2 >> 16) & 0xFF] ^ TABLES.td[2][(s1 >> 8) & 0xFF] ^ TABLES.td[3][s0 & 0xFF] ^ key[3]);
		// Переносим новое состояние
		s0 = t0;
		// Переносим новое состояние
		s1 = t1;
		// Переносим новое состояние
		s2 = t2;
		// Переносим новое состояние
		s3 = t3;
	}
	// Последний раундовый ключ
	const uint32_t * last = (keys + (this->_rounds * 4));
	// Последний раунд: обратная подстановка, обратный сдвиг строк и ключ
	store(((static_cast <uint32_t> (TABLES.inverse[s0 >> 24]) << 24) | (static_cast <uint32_t> (TABLES.inverse[(s3 >> 16) & 0xFF]) << 16) | (static_cast <uint32_t> (TABLES.inverse[(s2 >> 8) & 0xFF]) << 8) | static_cast <uint32_t> (TABLES.inverse[s1 & 0xFF])) ^ last[0], result);
	// Второе слово итога
	store(((static_cast <uint32_t> (TABLES.inverse[s1 >> 24]) << 24) | (static_cast <uint32_t> (TABLES.inverse[(s0 >> 16) & 0xFF]) << 16) | (static_cast <uint32_t> (TABLES.inverse[(s3 >> 8) & 0xFF]) << 8) | static_cast <uint32_t> (TABLES.inverse[s2 & 0xFF])) ^ last[1], result + 4);
	// Третье слово итога
	store(((static_cast <uint32_t> (TABLES.inverse[s2 >> 24]) << 24) | (static_cast <uint32_t> (TABLES.inverse[(s1 >> 16) & 0xFF]) << 16) | (static_cast <uint32_t> (TABLES.inverse[(s0 >> 8) & 0xFF]) << 8) | static_cast <uint32_t> (TABLES.inverse[s3 & 0xFF])) ^ last[2], result + 8);
	// Четвёртое слово итога
	store(((static_cast <uint32_t> (TABLES.inverse[s3 >> 24]) << 24) | (static_cast <uint32_t> (TABLES.inverse[(s2 >> 16) & 0xFF]) << 16) | (static_cast <uint32_t> (TABLES.inverse[(s1 >> 8) & 0xFF]) << 8) | static_cast <uint32_t> (TABLES.inverse[s0 & 0xFF])) ^ last[3], result + 12);
	// Выводим успешность расшифрования
	return true;
}
/**
 * @brief Метод выработки гаммы счётчика
 *
 * @param counter начальный блок счётчика: младшие 32 разряда растут от старшего байта
 * @param blocks  число блоков гаммы
 * @param result  место, в которое записывается гамма: 16 байтов на блок
 *
 * @return        признак успешности выработки
 *
 */
bool nts::cipher::Aes::stream(const uint8_t * counter, const size_t blocks, uint8_t * result) const noexcept {
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
		streamArm(this->_sealing, this->_rounds, counter, blocks, result);
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
		streamX86(this->_sealing, this->_rounds, counter, blocks, result);
		// Выводим успешность выработки
		return true;
	}
#endif
	// Текущий блок счётчика
	uint8_t current[16];
	// Переносим начальный блок счётчика
	::memcpy(current, counter, sizeof(current));
	/**
	 * Выполняем выработку гаммы по одному блоку
	 */
	for(size_t i = 0; i < blocks; i++){
		// Увеличиваем счётчик
		advance(current);
		// Выполняем зашифрование блока счётчика
		this->encrypt(current, result + (i * 16));
	}
	// Выполняем затирание счётчика
	wipe(current, sizeof(current));
	// Выводим успешность выработки
	return true;
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
