/**
 * @file blake2.cpp
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
 * @brief Модуль хеширования BLAKE2b и BLAKE2s по RFC 7693
 *
 * @details Одно преобразование над двумя ширинами слов: BLAKE2b - слова в 64 разряда, блок
 *          128 байтов, 12 кругов, сдвиги 32/24/16/63; BLAKE2s - слова в 32 разряда, блок 64
 *          байта, 10 кругов, сдвиги 16/12/8/7. Слова читаются и пишутся от младшего байта.
 *          Ключ, если задан, кладётся первым блоком с дополнением нулями (раздел 3.3)
 *
 * @section Намеренные решения
 *
 * 1. Оба преобразования расписаны одним кодом над 64-разрядными словами: у BLAKE2s значимы
 *    младшие 32 разряда, а сдвиги и константы выбираются разновидностью. Так одна функция
 *    сжатия сверяется с разделом 3.2 RFC 7693, а не две.
 *
 * 2. Блок не сжимается, пока не пришёл следующий байт: последний блок сжимается лишь при
 *    снятии итога с признаком завершения, как велит раздел 3.3 (пустое сообщение - один
 *    блок нулей с признаком завершения).
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
#include <digest/blake2.hpp>
#include <sys/wipe.hpp>

/**
 * @brief Служебные объекты модуля
 *
 */
namespace {
	/**
	 * Подписываемся на метод затирания памяти
	 */
	using nts::sys::wipe;

	/**
	 * Начальные значения BLAKE2b
	 */
	static constexpr uint64_t IV64[8] = {
		// Первые четыре слова вектора инициализации SHA-512
		0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL, 0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
		0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL, 0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
	};
	/**
	 * Начальные значения BLAKE2s
	 */
	static constexpr uint32_t IV32[8] = {
		// Слова вектора инициализации SHA-256
		0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
	};
	/**
	 * Перестановки слов сообщения по кругам
	 */
	static constexpr uint8_t SIGMA[12][16] = {
		// Круг 0: тождественная перестановка
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
		{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
		{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
		{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
		{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
		{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
		{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
		{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
		{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}
	};

	/**
	 * @brief Функция кругового сдвига слова вправо в заданной ширине
	 *
	 * @param word  сдвигаемое слово
	 * @param count число разрядов сдвига
	 * @param wide  признак ширины в 64 разряда
	 * @return      сдвинутое слово
	 *
	 */
	static constexpr uint64_t spin(const uint64_t word, const size_t count, const bool wide) noexcept {
		// Если слово широкое
		if(wide)
			// Выводим сдвиг в 64 разрядах
			return ((word >> count) | (word << (64 - count)));
		// Младшие 32 разряда слова
		const uint32_t narrow = static_cast <uint32_t> (word);
		// Выводим сдвиг в 32 разрядах
		return static_cast <uint64_t> ((narrow >> count) | (narrow << (32 - count)));
	}
	/**
	 * @brief Функция чтения слова сообщения от младшего байта
	 *
	 * @param data байты слова
	 * @param wide признак ширины в 64 разряда
	 * @return     слово
	 *
	 */
	static __ANTS_INLINE__ uint64_t fetch(const uint8_t * data, const bool wide) noexcept {
		// Собираемое слово
		uint64_t result = 0;
		/**
		 * Выполняем перебор байтов слова
		 */
		for(size_t i = 0; i < (wide ? 8 : 4); i++)
			// Складываем байт на своё место
			result |= (static_cast <uint64_t> (data[i]) << (8 * i));
		// Выводим слово
		return result;
	}
	/**
	 * @brief Функция смешивания четырёх слов рабочего вектора
	 *
	 * @param v    рабочий вектор
	 * @param a    место первого слова
	 * @param b    место второго слова
	 * @param c    место третьего слова
	 * @param d    место четвёртого слова
	 * @param x    первое слово сообщения
	 * @param y    второе слово сообщения
	 * @param wide признак ширины в 64 разряда
	 *
	 */
	static __ANTS_INLINE__ void mix(uint64_t * v, const size_t a, const size_t b, const size_t c, const size_t d, const uint64_t x, const uint64_t y, const bool wide) noexcept {
		// Маска ширины слова
		const uint64_t mask = (wide ? 0xFFFFFFFFFFFFFFFFULL : 0xFFFFFFFFULL);
		// Сдвиги разновидности
		const size_t r1 = (wide ? 32 : 16), r2 = (wide ? 24 : 12), r3 = (wide ? 16 : 8), r4 = (wide ? 63 : 7);
		// Первое сложение
		v[a] = ((v[a] + v[b] + x) & mask);
		// Первый сдвиг
		v[d] = spin(v[d] ^ v[a], r1, wide);
		// Второе сложение
		v[c] = ((v[c] + v[d]) & mask);
		// Второй сдвиг
		v[b] = spin(v[b] ^ v[c], r2, wide);
		// Третье сложение
		v[a] = ((v[a] + v[b] + y) & mask);
		// Третий сдвиг
		v[d] = spin(v[d] ^ v[a], r3, wide);
		// Четвёртое сложение
		v[c] = ((v[c] + v[d]) & mask);
		// Четвёртый сдвиг
		v[b] = spin(v[b] ^ v[c], r4, wide);
	}
};

/**
 * @brief Метод сжатия блока
 *
 * @param last признак последнего блока
 *
 */
void nts::digest::Blake2::compress(const bool last) noexcept {
	// Признак ширины слов
	const bool wide = (this->_type == blake_t::BLAKE2B);
	// Маска ширины слова
	const uint64_t mask = (wide ? 0xFFFFFFFFFFFFFFFFULL : 0xFFFFFFFFULL);
	// Слова сообщения
	uint64_t m[16];
	/**
	 * Выполняем чтение слов блока
	 */
	for(size_t i = 0; i < 16; i++)
		// Читаем слово от младшего байта
		m[i] = fetch(this->_block + (i * (wide ? 8 : 4)), wide);
	// Рабочий вектор
	uint64_t v[16];
	/**
	 * Выполняем заполнение рабочего вектора состоянием и начальными значениями
	 */
	for(size_t i = 0; i < 8; i++){
		// Состояние
		v[i] = this->_hash[i];
		// Начальное значение
		v[8 + i] = (wide ? IV64[i] : static_cast <uint64_t> (IV32[i]));
	}
	// Складываем счётчик байтов
	v[12] ^= (this->_count[0] & mask);
	// Складываем старшую часть счётчика
	v[13] ^= (wide ? this->_count[1] : ((this->_count[0] >> 32) & mask));
	// Если блок последний
	if(last)
		// Обращаем слово завершения
		v[14] ^= mask;
	/**
	 * Выполняем круги смешивания
	 */
	for(size_t round = 0; round < (wide ? 12 : 10); round++){
		// Перестановка круга
		const uint8_t * s = SIGMA[round];
		// Столбцы
		mix(v, 0, 4, 8, 12, m[s[0]], m[s[1]], wide);
		mix(v, 1, 5, 9, 13, m[s[2]], m[s[3]], wide);
		mix(v, 2, 6, 10, 14, m[s[4]], m[s[5]], wide);
		mix(v, 3, 7, 11, 15, m[s[6]], m[s[7]], wide);
		// Диагонали
		mix(v, 0, 5, 10, 15, m[s[8]], m[s[9]], wide);
		mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]], wide);
		mix(v, 2, 7, 8, 13, m[s[12]], m[s[13]], wide);
		mix(v, 3, 4, 9, 14, m[s[14]], m[s[15]], wide);
	}
	/**
	 * Выполняем сложение половин рабочего вектора с состоянием
	 */
	for(size_t i = 0; i < 8; i++)
		// Складываем состояние
		this->_hash[i] = (this->_hash[i] ^ v[i] ^ v[8 + i]);
	// Выполняем затирание слов сообщения
	wipe(m, sizeof(m));
	// Выполняем затирание рабочего вектора
	wipe(v, sizeof(v));
}
/**
 * @brief Метод получения разновидности хеша
 *
 * @return разновидность хеша
 *
 */
nts::digest::blake_t nts::digest::Blake2::type() const noexcept {
	// Выводим разновидность
	return this->_type;
}
/**
 * @brief Метод получения длины итога
 *
 * @return длина итога в байтах
 *
 */
size_t nts::digest::Blake2::length() const noexcept {
	// Выводим длину итога
	return this->_length;
}
/**
 * @brief Метод получения размера блока разновидности
 *
 * @return размер блока в байтах
 *
 */
size_t nts::digest::Blake2::block() const noexcept {
	// Выводим размер блока
	return ((this->_type == blake_t::BLAKE2B) ? 128 : ((this->_type == blake_t::BLAKE2S) ? 64 : 0));
}
/**
 * @brief Метод заведения хеша
 *
 * @param type   разновидность
 * @param length длина итога в байтах от 1 до наибольшей у разновидности
 * @param key    ключ имитовставки либо пустой вид
 * @return       признак того, что хеш заведён
 *
 */
bool nts::digest::Blake2::start(const blake_t type, const size_t length, const view_t & key) noexcept {
	// Наибольшая длина итога и ключа разновидности
	const size_t widest = ((type == blake_t::BLAKE2B) ? BLAKE2B_LENGTH : ((type == blake_t::BLAKE2S) ? BLAKE2S_LENGTH : 0));
	// Если разновидность не установлена, длина итога негодна либо ключ длиннее дозволенного
	if((widest == 0) || (length == 0) || (length > widest) || (key.size > widest) || ((key.size > 0) && (key.data == nullptr))){
		// Отмечаем, что хеш не заведён
		this->_finished = true;
		// Выводим отказ заведения
		return false;
	}
	// Запоминаем разновидность
	this->_type = type;
	// Запоминаем длину итога
	this->_length = length;
	// Сбрасываем признак снятия итога
	this->_finished = false;
	// Сбрасываем число байтов незавершённого блока
	this->_size = 0;
	// Сбрасываем счётчик байтов
	this->_count[0] = 0;
	// Сбрасываем старшую половину счётчика байтов
	this->_count[1] = 0;
	// Признак ширины слов
	const bool wide = (type == blake_t::BLAKE2B);
	/**
	 * Выполняем заполнение состояния начальными значениями
	 */
	for(size_t i = 0; i < 8; i++)
		// Начальное значение
		this->_hash[i] = (wide ? IV64[i] : static_cast <uint64_t> (IV32[i]));
	// Раздел 2.8 RFC 7693: блок параметров - длина итога, длина ключа, разветвление 1, глубина 1
	this->_hash[0] ^= (0x01010000ULL | (static_cast <uint64_t> (key.size) << 8) | static_cast <uint64_t> (length));
	// Обнуляем накопитель блока
	::memset(this->_block, 0, sizeof(this->_block));
	// Если ключ задан
	if(key.size > 0){
		// Переносим ключ в первый блок
		::memcpy(this->_block, key.data, key.size);
		// Блок ключа занят целиком: дополнение нулями
		this->_size = this->block();
	}
	// Выводим успешность заведения
	return true;
}
/**
 * @brief Метод подачи куска сообщения
 *
 * @param data кусок сообщения
 * @return     признак того, что кусок поглощён
 *
 */
bool nts::digest::Blake2::update(const view_t & data) noexcept {
	// Если хеш не заведён либо итог уже снят
	if(this->_finished)
		// Выводим отказ подачи
		return false;
	// Если кусок пуст
	if(data.size == 0)
		// Выводим успешность подачи пустого куска
		return true;
	// Если байты куска не переданы
	if(data.data == nullptr)
		// Выводим отказ подачи
		return false;
	// Размер блока
	const size_t width = this->block();
	/**
	 * Выполняем перебор байтов куска
	 */
	for(size_t i = 0; i < data.size; i++){
		// Если накопитель полон: следующий байт пришёл, блок не последний
		if(this->_size == width){
			// Продвигаем счётчик байтов
			this->_count[0] += width;
			// Если младшая часть переполнилась
			if(this->_count[0] < width)
				// Продвигаем старшую часть
				this->_count[1]++;
			// Сжимаем блок
			this->compress(false);
			// Сбрасываем накопитель
			this->_size = 0;
		}
		// Складываем байт в накопитель
		this->_block[this->_size++] = data.data[i];
	}
	// Выводим успешность подачи
	return true;
}
/**
 * @brief Метод снятия итога
 *
 * @param result место, в которое помещается итог
 * @param size   длина места: ровно длина итога
 * @return       признак того, что итог снят; повторное снятие отвергается
 *
 */
bool nts::digest::Blake2::finish(uint8_t * result, const size_t size) noexcept {
	// Если хеш не заведён, итог снят, место не передано либо длина не сходится
	if(this->_finished || (result == nullptr) || (size != this->_length))
		// Выводим отказ снятия
		return false;
	// Продвигаем счётчик байтов на незавершённый блок
	this->_count[0] += this->_size;
	// Если младшая часть переполнилась
	if(this->_count[0] < this->_size)
		// Продвигаем старшую часть
		this->_count[1]++;
	// Дополняем блок нулями
	::memset(this->_block + this->_size, 0, sizeof(this->_block) - this->_size);
	// Сжимаем последний блок
	this->compress(true);
	// Признак ширины слов
	const bool wide = (this->_type == blake_t::BLAKE2B);
	/**
	 * Выполняем запись итога от младшего байта
	 */
	for(size_t i = 0; i < size; i++)
		// Байт слова состояния
		result[i] = static_cast <uint8_t> (this->_hash[i / (wide ? 8 : 4)] >> (8 * (i % (wide ? 8 : 4))));
	// Отмечаем снятие итога
	this->_finished = true;
	// Выполняем затирание накопителя
	wipe(this->_block, sizeof(this->_block));
	// Выводим успешность снятия
	return true;
}
/**
 * @brief Конструктор: хеш не заведён
 *
 */
nts::digest::Blake2::Blake2() noexcept : _type(blake_t::NONE), _finished(true), _length(0), _size(0) {
	// Обнуляем состояние
	::memset(this->_hash, 0, sizeof(this->_hash));
	// Обнуляем счётчик
	::memset(this->_count, 0, sizeof(this->_count));
	// Обнуляем накопитель
	::memset(this->_block, 0, sizeof(this->_block));
}
/**
 * @brief Деструктор: состояние затирается
 *
 */
nts::digest::Blake2::~Blake2() noexcept {
	// Выполняем затирание состояния
	wipe(this->_hash, sizeof(this->_hash));
	// Выполняем затирание накопителя
	wipe(this->_block, sizeof(this->_block));
}

/**
 * @brief Функция хеширования сообщения за один вызов
 *
 * @param type   разновидность
 * @param key    ключ имитовставки либо пустой вид
 * @param data   сообщение
 * @param result место, в которое помещается итог
 * @param size   длина итога в байтах от 1 до наибольшей у разновидности
 * @return       признак того, что итог вычислен
 *
 */
bool nts::digest::blake2(const blake_t type, const view_t & key, const view_t & data, uint8_t * result, const size_t size) noexcept {
	// Объект хеширования
	blake2_t hasher;
	// Если хеш завести не удалось
	if(!hasher.start(type, size, key))
		// Выводим отрицательный результат - хеш завести не удалось
		return false;
	// Если сообщение подать не удалось
	if(!hasher.update(data))
		// Выводим отрицательный результат - сообщение подать не удалось
		return false;
	// Выводим итог снятия
	return hasher.finish(result, size);
}
