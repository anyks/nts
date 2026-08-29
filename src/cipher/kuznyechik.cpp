/**
 * @file kuznyechik.cpp
 * @date 2026-08-29
 *
 * @license{LicenseRef-ANYKS-TLS-1.0}
 *
 * @author Yuriy Lobarev
 *
 * @telegram{forman}
 * @phone{+7 (910) 983-95-90}
 *
 * @email forman@anyks.com
 * @site https://anyks.com
 *
 * @brief Исходный файл модуля блочного шифра «Кузнечик» — реализация по
 *        ГОСТ Р 34.12-2015
 *
 * @note Блок хранится байтами в том порядке, в каком он приходит потоком: байт с
 *       номером нуль отвечает старшему байту вектора a_15. Порядок этот прямой, в
 *       отличие от Стрибога, где вектор укладывается младшими байтами вперёд
 *
 * @note Больших совмещённых таблиц преобразования LS здесь нет намеренно. Приём
 *       этот ускоряет шифр в разы, но требует таблиц на 64 кибибайта, обращение к
 *       которым идёт по секретному значению: чем таблица крупнее, тем шире след,
 *       оставляемый ею в кэше, и тем надёжнее он читается со стороны. Взяты
 *       таблицы умножения на постоянные множители - четыре кибибайта, - которые
 *       следа шире, чем сама подстановка, не оставляют
 *
 * @note Постоянного времени работы шифр пока не обеспечивает: обращение к
 *       подстановке идёт по секретному значению. Устранение этого требует
 *       поразрядной реализации и вынесено отдельной работой
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
#include <cipher/kuznyechik.hpp>

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
	using namespace anyks;

	/**
	 * Пространство имён модуля
	 */
	using namespace anyks::cipher;

	/**
	 * @brief Нелинейное биективное преобразование множества двоичных векторов
	 *
	 * @details Подстановка Pi' по разделу 4.1 ГОСТ Р 34.12-2015. Таблица эта совпадает
	 *          с таблицей Стрибога - совпадение сличено при переносе, - но взята из
	 *          своего стандарта и своей копией здесь и остаётся: стандарты разные и
	 *          вправе разойтись, а общая таблица связала бы два модуля без нужды
	 *
	 */
	static constexpr uint8_t PI[256] = {
		0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16,
		0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
		0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA,
		0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
		0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21,
		0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
		0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0,
		0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
		0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB,
		0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
		0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12,
		0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
		0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7,
		0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
		0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E,
		0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
		0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9,
		0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
		0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC,
		0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
		0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44,
		0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
		0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F,
		0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
		0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7,
		0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
		0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE,
		0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
		0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B,
		0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
		0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0,
		0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6
	};

	/**
	 * @brief Множители линейного преобразования
	 *
	 * @details Постоянные множители функции l по разделу 4.2 ГОСТ Р 34.12-2015,
	 *          записанные от старшего байта вектора к младшему
	 *
	 */
	static constexpr uint8_t FACTORS[16] = {
		0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB,
		0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01
	};
	/**
	 * @brief Метод умножения в поле Галуа
	 *
	 * @details Поле задано неприводимым многочленом x^8 + x^7 + x^6 + x + 1 по
	 *          разделу 3 ГОСТ Р 34.12-2015
	 *
	 * @param first  первый множитель
	 * @param second второй множитель
	 *
	 * @return       произведение множителей в поле
	 *
	 */
	static constexpr uint8_t multiply(const uint8_t first, const uint8_t second) noexcept {
		// Накапливаемое произведение
		uint8_t result = 0;
		// Текущее значение первого множителя
		uint8_t item = first;
		// Оставшиеся разряды второго множителя
		uint8_t rest = second;
		/**
		 * Выполняем перебор разрядов второго множителя
		 */
		while(rest != 0){
			// Если разряд второго множителя установлен
			if((rest & 0x01) != 0)
				// Дополняем произведение текущим значением первого множителя
				result ^= item;
			// Запоминаем признак выхода первого множителя за разрядную сетку
			const bool overflow = ((item & 0x80) != 0);
			// Сдвигаем первый множитель на разряд влево
			item = static_cast <uint8_t> (item << 1);
			// Если первый множитель вышел за разрядную сетку
			if(overflow)
				// Приводим первый множитель по неприводимому многочлену
				item ^= 0xC3;
			// Сдвигаем второй множитель на разряд вправо
			rest = static_cast <uint8_t> (rest >> 1);
		}
		// Выводим произведение множителей
		return result;
	}

	/**
	 * @brief Таблицы умножения на постоянные множители
	 *
	 */
	typedef struct Tables {
		// Произведения по номеру множителя и значению байта
		uint8_t values[16][256];
	} tables_t;

	/**
	 * @brief Метод вычисления таблиц умножения на постоянные множители
	 *
	 * @return вычисленные таблицы умножения
	 *
	 */
	static constexpr tables_t compute() noexcept {
		// Вычисляемые таблицы умножения
		tables_t result = {};
		/**
		 * Выполняем перебор постоянных множителей
		 */
		for(size_t i = 0; i < 16; i++){
			/**
			 * Выполняем перебор возможных значений байта
			 */
			for(size_t j = 0; j < 256; j++)
				// Вычисляем произведение множителя на значение байта
				result.values[i][j] = multiply(FACTORS[i], static_cast <uint8_t> (j));
		}
		// Выводим вычисленные таблицы умножения
		return result;
	}

	/**
	 * @brief Таблицы умножения на постоянные множители
	 *
	 */
	static constexpr tables_t TABLES = compute();

	/**
	 * @brief Обратная подстановка
	 *
	 */
	typedef struct Reversed {
		// Значения обратной подстановки
		uint8_t values[256];
	} reversed_t;

	/**
	 * @brief Метод вычисления обратной подстановки
	 *
	 * @return вычисленная обратная подстановка
	 *
	 */
	static constexpr reversed_t reverse() noexcept {
		// Вычисляемая обратная подстановка
		reversed_t result = {};
		/**
		 * Выполняем перебор возможных значений байта
		 *
		 * @note Обратная подстановка вычисляется обращением прямой, а не переносится
		 *       из текста стандарта: так она обратна ей заведомо, а не по недосмотру
		 */
		for(size_t i = 0; i < 256; i++)
			// Записываем значение обратной подстановки
			result.values[PI[i]] = static_cast <uint8_t> (i);
		// Выводим вычисленную обратную подстановку
		return result;
	}

	/**
	 * @brief Обратная подстановка
	 *
	 */
	static constexpr reversed_t REVERSED = reverse();

	/**
	 * @brief Метод линейного преобразования одного байта
	 *
	 * @details Функция l по разделу 4.2 ГОСТ Р 34.12-2015
	 *
	 * @param block преобразуемый блок
	 *
	 * @return      значение линейного преобразования
	 *
	 */
	static uint8_t linear(const uint8_t * block) noexcept {
		// Накапливаемое значение преобразования
		uint8_t result = 0;
		/**
		 * Выполняем перебор байтов преобразуемого блока
		 */
		for(size_t i = 0; i < KUZNYECHIK_BLOCK; i++)
			// Дополняем значение произведением байта на его множитель
			result ^= TABLES.values[i][block[i]];
		// Выводим значение линейного преобразования
		return result;
	}
	/**
	 * @brief Метод преобразования R
	 *
	 * @details Преобразование R по разделу 4.3 ГОСТ Р 34.12-2015
	 *
	 * @param block преобразуемый блок
	 *
	 */
	static void shift(uint8_t * block) noexcept {
		// Вычисляем значение линейного преобразования блока
		const uint8_t value = linear(block);
		/**
		 * Выполняем сдвиг байтов блока от конца к началу
		 */
		for(size_t i = KUZNYECHIK_BLOCK - 1; i > 0; i--)
			// Переносим очередной байт блока
			block[i] = block[i - 1];
		// Записываем значение линейного преобразования старшим байтом блока
		block[0] = value;
	}
	/**
	 * @brief Метод обратного преобразования R
	 *
	 * @param block преобразуемый блок
	 *
	 */
	static void unshift(uint8_t * block) noexcept {
		// Запоминаем старший байт блока
		const uint8_t value = block[0];
		/**
		 * Выполняем сдвиг байтов блока от начала к концу
		 */
		for(size_t i = 0; i < (KUZNYECHIK_BLOCK - 1); i++)
			// Переносим очередной байт блока
			block[i] = block[i + 1];
		/**
		 * Запомненный старший байт помещается на место младшего: линейное
		 * преобразование обязано увидеть его именно там, а вычисленное значение
		 * затем это же место и занимает
		 */
		block[KUZNYECHIK_BLOCK - 1] = value;
		// Записываем значение линейного преобразования младшим байтом блока
		block[KUZNYECHIK_BLOCK - 1] = linear(block);
	}
	/**
	 * @brief Метод преобразования L
	 *
	 * @details Преобразование L по разделу 4.3 ГОСТ Р 34.12-2015
	 *
	 * @param block преобразуемый блок
	 *
	 */
	static void spread(uint8_t * block) noexcept {
		/**
		 * Выполняем шестнадцать применений преобразования R
		 */
		for(size_t i = 0; i < KUZNYECHIK_BLOCK; i++)
			// Применяем преобразование R к блоку
			shift(block);
	}
	/**
	 * @brief Метод обратного преобразования L
	 *
	 * @param block преобразуемый блок
	 *
	 */
	static void unspread(uint8_t * block) noexcept {
		/**
		 * Выполняем шестнадцать применений обратного преобразования R
		 */
		for(size_t i = 0; i < KUZNYECHIK_BLOCK; i++)
			// Применяем обратное преобразование R к блоку
			unshift(block);
	}
	/**
	 * @brief Метод подстановки байтов блока
	 *
	 * @details Преобразование S по разделу 4.3 ГОСТ Р 34.12-2015
	 *
	 * @param block преобразуемый блок
	 *
	 */
	static void substitute(uint8_t * block) noexcept {
		/**
		 * Выполняем перебор байтов преобразуемого блока
		 */
		for(size_t i = 0; i < KUZNYECHIK_BLOCK; i++)
			// Выполняем подстановку очередного байта блока
			block[i] = PI[block[i]];
	}
	/**
	 * @brief Метод обратной подстановки байтов блока
	 *
	 * @param block преобразуемый блок
	 *
	 */
	static void unsubstitute(uint8_t * block) noexcept {
		/**
		 * Выполняем перебор байтов преобразуемого блока
		 */
		for(size_t i = 0; i < KUZNYECHIK_BLOCK; i++)
			// Выполняем обратную подстановку очередного байта блока
			block[i] = REVERSED.values[block[i]];
	}
	/**
	 * @brief Метод сложения блока с ключом
	 *
	 * @details Преобразование X по разделу 4.3 ГОСТ Р 34.12-2015
	 *
	 * @param block преобразуемый блок
	 * @param key   складываемый ключ
	 *
	 */
	static void add(uint8_t * block, const uint8_t * key) noexcept {
		/**
		 * Выполняем перебор байтов преобразуемого блока
		 */
		for(size_t i = 0; i < KUZNYECHIK_BLOCK; i++)
			// Складываем очередной байт блока с байтом ключа
			block[i] ^= key[i];
	}
	/**
	 * @brief Метод затирания области памяти
	 *
	 * @details Затирание ведётся через изменчивый указатель: обычное присваивание
	 *          собиратель вправе выбросить, увидев, что записанное значение больше
	 *          никем не читается, - и ключ остался бы в памяти
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
};

/**
 * @brief Метод проверки готовности шифра к работе
 *
 * @return признак того, что ключ установлен
 *
 */
bool anyks::cipher::Kuznyechik::ready() const noexcept {
	// Выводим признак того, что ключ установлен
	return this->_ready;
}
/**
 * @brief Метод установки ключа шифрования
 *
 * @param key устанавливаемый ключ шифрования
 *
 * @return    признак успешности установки ключа
 *
 */
bool anyks::cipher::Kuznyechik::key(const view_t & key) noexcept {
	// Выполняем затирание прежних раундовых ключей
	this->clear();
	// Если ключ шифрования не той длины
	if((key.data == nullptr) || (key.size != KUZNYECHIK_KEY))
		// Выводим отказ установки ключа
		return false;
	// Пара ключей, из которой вырабатываются раундовые
	uint8_t pair[2][KUZNYECHIK_BLOCK];
	// Переносим старшую половину ключа шифрования
	::memcpy(pair[0], key.data, KUZNYECHIK_BLOCK);
	// Переносим младшую половину ключа шифрования
	::memcpy(pair[1], key.data + KUZNYECHIK_BLOCK, KUZNYECHIK_BLOCK);
	// Запоминаем первые два раундовых ключа
	::memcpy(this->_keys[0], pair[0], KUZNYECHIK_BLOCK);
	::memcpy(this->_keys[1], pair[1], KUZNYECHIK_BLOCK);
	/**
	 * Выполняем выработку оставшихся четырёх пар раундовых ключей
	 */
	for(size_t i = 0; i < 4; i++){
		/**
		 * Выполняем восемь применений преобразования Фейстеля
		 */
		for(size_t j = 0; j < 8; j++){
			// Постоянная величина итерации
			uint8_t constant[KUZNYECHIK_BLOCK];
			// Обнуляем постоянную величину итерации
			::memset(constant, 0, sizeof(constant));
			// Записываем номер итерации младшим байтом постоянной величины
			constant[KUZNYECHIK_BLOCK - 1] = static_cast <uint8_t> ((i * 8) + j + 1);
			// Вырабатываем постоянную величину итерации
			spread(constant);
			// Преобразуемая половина пары ключей
			uint8_t item[KUZNYECHIK_BLOCK];
			// Переносим преобразуемую половину пары ключей
			::memcpy(item, pair[0], KUZNYECHIK_BLOCK);
			// Складываем половину пары с постоянной величиной итерации
			add(item, constant);
			// Выполняем подстановку байтов половины пары
			substitute(item);
			// Выполняем линейное преобразование половины пары
			spread(item);
			// Складываем итог преобразования со второй половиной пары
			add(item, pair[1]);
			// Переносим прежнюю первую половину пары во вторую
			::memcpy(pair[1], pair[0], KUZNYECHIK_BLOCK);
			// Запоминаем итог преобразования первой половиной пары
			::memcpy(pair[0], item, KUZNYECHIK_BLOCK);
			// Выполняем затирание преобразуемой половины пары
			wipe(item, sizeof(item));
		}
		// Запоминаем очередную пару раундовых ключей
		::memcpy(this->_keys[(i * 2) + 2], pair[0], KUZNYECHIK_BLOCK);
		::memcpy(this->_keys[(i * 2) + 3], pair[1], KUZNYECHIK_BLOCK);
	}
	// Выполняем затирание пары ключей
	wipe(pair, sizeof(pair));
	// Устанавливаем признак того, что ключ установлен
	this->_ready = true;
	// Выводим успешность установки ключа
	return true;
}
/**
 * @brief Метод затирания раундовых ключей
 *
 */
void anyks::cipher::Kuznyechik::clear() noexcept {
	// Выполняем затирание раундовых ключей
	wipe(this->_keys, sizeof(this->_keys));
	// Снимаем признак того, что ключ установлен
	this->_ready = false;
}
/**
 * @brief Метод зашифрования блока
 *
 * @param source зашифровываемый блок
 * @param result место, в которое помещается зашифрованный блок
 *
 * @return       признак успешности зашифрования
 *
 */
bool anyks::cipher::Kuznyechik::encrypt(const uint8_t * source, uint8_t * result) const noexcept {
	// Если ключ не установлен либо места не переданы
	if(!this->_ready || (source == nullptr) || (result == nullptr))
		// Выводим отказ зашифрования
		return false;
	// Преобразуемый блок
	uint8_t block[KUZNYECHIK_BLOCK];
	// Переносим зашифровываемый блок
	::memcpy(block, source, KUZNYECHIK_BLOCK);
	/**
	 * Выполняем девять раундов зашифрования
	 */
	for(size_t i = 0; i < 9; i++){
		// Складываем блок с раундовым ключом
		add(block, this->_keys[i]);
		// Выполняем подстановку байтов блока
		substitute(block);
		// Выполняем линейное преобразование блока
		spread(block);
	}
	// Складываем блок с последним раундовым ключом
	add(block, this->_keys[9]);
	// Переносим зашифрованный блок
	::memcpy(result, block, KUZNYECHIK_BLOCK);
	// Выполняем затирание преобразуемого блока
	wipe(block, sizeof(block));
	// Выводим успешность зашифрования
	return true;
}
/**
 * @brief Метод расшифрования блока
 *
 * @param source расшифровываемый блок
 * @param result место, в которое помещается расшифрованный блок
 *
 * @return       признак успешности расшифрования
 *
 */
bool anyks::cipher::Kuznyechik::decrypt(const uint8_t * source, uint8_t * result) const noexcept {
	// Если ключ не установлен либо места не переданы
	if(!this->_ready || (source == nullptr) || (result == nullptr))
		// Выводим отказ расшифрования
		return false;
	// Преобразуемый блок
	uint8_t block[KUZNYECHIK_BLOCK];
	// Переносим расшифровываемый блок
	::memcpy(block, source, KUZNYECHIK_BLOCK);
	/**
	 * Выполняем девять раундов расшифрования
	 */
	for(size_t i = 9; i > 0; i--){
		// Складываем блок с раундовым ключом
		add(block, this->_keys[i]);
		// Выполняем обратное линейное преобразование блока
		unspread(block);
		// Выполняем обратную подстановку байтов блока
		unsubstitute(block);
	}
	// Складываем блок с первым раундовым ключом
	add(block, this->_keys[0]);
	// Переносим расшифрованный блок
	::memcpy(result, block, KUZNYECHIK_BLOCK);
	// Выполняем затирание преобразуемого блока
	wipe(block, sizeof(block));
	// Выводим успешность расшифрования
	return true;
}
/**
 * @brief Конструктор
 *
 */
anyks::cipher::Kuznyechik::Kuznyechik() noexcept : _ready(false) {
	// Выполняем затирание раундовых ключей
	wipe(this->_keys, sizeof(this->_keys));
}
/**
 * @brief Деструктор
 *
 */
anyks::cipher::Kuznyechik::~Kuznyechik() noexcept {
	// Выполняем затирание раундовых ключей
	this->clear();
}
