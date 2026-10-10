/**
 * @file ripemd.cpp
 * @date 2026-10-10
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
 * @brief Модуль хеш-функции RIPEMD-160
 *
 * @details Блок сообщения в 64 байта проходит восемьдесят шагов в двух параллельных
 *          потоках (левом и правом) над пятью рабочими словами каждый: потоки различаются
 *          функциями кругов, константами, порядком слов сообщения и величинами сдвигов.
 *          Итоги потоков сходятся в значение хеша перекрёстным сложением. Сообщение
 *          дополняется байтом 0x80 и длиной в разрядах от младшего байта
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <digest/ripemd.hpp>
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
	 * @brief Порядок слов сообщения у левого потока по кругам
	 *
	 */
	constexpr uint8_t LEFT_ORDER[80] = {
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
		3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
		1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
		4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
	};
	/**
	 * @brief Порядок слов сообщения у правого потока по кругам
	 *
	 */
	constexpr uint8_t RIGHT_ORDER[80] = {
		5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
		6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
		15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
		8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
		12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
	};
	/**
	 * @brief Величины круговых сдвигов у левого потока по кругам
	 *
	 */
	constexpr uint8_t LEFT_SHIFT[80] = {
		11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
		7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
		11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
		11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
		9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
	};
	/**
	 * @brief Величины круговых сдвигов у правого потока по кругам
	 *
	 */
	constexpr uint8_t RIGHT_SHIFT[80] = {
		8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
		9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
		9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
		15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
		8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
	};
	/**
	 * @brief Константы кругов левого потока
	 *
	 */
	constexpr uint32_t LEFT_K[5] = {0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E};
	/**
	 * @brief Константы кругов правого потока
	 *
	 */
	constexpr uint32_t RIGHT_K[5] = {0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000};
	/**
	 * @brief Начальные значения хеша
	 *
	 */
	constexpr uint32_t H[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
	/**
	 * @brief Метод кругового сдвига слова влево
	 *
	 * @param value сдвигаемое слово
	 * @param count число разрядов сдвига
	 *
	 * @return      сдвинутое слово
	 *
	 */
	static __ANTS_INLINE__ uint32_t rotl(const uint32_t value, const unsigned count) noexcept {
		// Выводим слово, сдвинутое по кругу
		return ((value << count) | (value >> (32 - count)));
	}
	/**
	 * @brief Метод функции круга по её номеру
	 *
	 * @param round номер круга (от нуля до четырёх)
	 * @param x     первое слово
	 * @param y     второе слово
	 * @param z     третье слово
	 *
	 * @return      значение функции круга
	 *
	 */
	static __ANTS_INLINE__ uint32_t fn(const size_t round, const uint32_t x, const uint32_t y, const uint32_t z) noexcept {
		// Выбираем функцию по номеру круга
		switch(round){
			// Первая функция: x ^ y ^ z
			case 0: return (x ^ y ^ z);
			// Вторая функция: (x & y) | (~x & z)
			case 1: return ((x & y) | (~x & z));
			// Третья функция: (x | ~y) ^ z
			case 2: return ((x | ~y) ^ z);
			// Четвёртая функция: (x & z) | (y & ~z)
			case 3: return ((x & z) | (y & ~z));
			// Пятая функция: x ^ (y | ~z)
			default: return (x ^ (y | ~z));
		}
	}
	/**
	 * @brief Метод чтения слова от младшего байта
	 *
	 * @param data читаемые байты
	 *
	 * @return     прочитанное слово
	 *
	 */
	static __ANTS_INLINE__ uint32_t load(const uint8_t * data) noexcept {
		// Выводим слово, собранное от младшего байта
		return (static_cast <uint32_t> (data[0]) | (static_cast <uint32_t> (data[1]) << 8) |
		        (static_cast <uint32_t> (data[2]) << 16) | (static_cast <uint32_t> (data[3]) << 24));
	}
	/**
	 * @brief Метод записи слова от младшего байта
	 *
	 * @param value записываемое слово
	 * @param data  место, в которое записываются байты
	 *
	 */
	static __ANTS_INLINE__ void store(const uint32_t value, uint8_t * data) noexcept {
		// Записываем младший байт слова
		data[0] = static_cast <uint8_t> (value);
		// Записываем второй байт слова
		data[1] = static_cast <uint8_t> (value >> 8);
		// Записываем третий байт слова
		data[2] = static_cast <uint8_t> (value >> 16);
		// Записываем старший байт слова
		data[3] = static_cast <uint8_t> (value >> 24);
	}
};

/**
 * @brief Метод разбора блока сообщения
 *
 * @param block разбираемый блок: накопитель либо сам кусок сообщения
 *
 */
void nts::digest::Ripemd::compress(const uint8_t * block) noexcept {
	// Слова блока сообщения
	uint32_t m[16];
	/**
	 * Выполняем чтение шестнадцати слов блока
	 */
	for(size_t i = 0; i < 16; i++)
		// Читаем очередное слово блока от младшего байта
		m[i] = load(block + (i * 4));
	// Рабочие переменные левого потока
	uint32_t al = this->_hash[0], bl = this->_hash[1], cl = this->_hash[2], dl = this->_hash[3], el = this->_hash[4];
	// Рабочие переменные правого потока
	uint32_t ar = this->_hash[0], br = this->_hash[1], cr = this->_hash[2], dr = this->_hash[3], er = this->_hash[4];
	/**
	 * Выполняем восемьдесят шагов двух потоков
	 */
	for(size_t i = 0; i < 80; i++){
		// Номер круга шага
		const size_t round = (i / 16);
		// Временная переменная левого потока
		uint32_t t = (al + fn(round, bl, cl, dl) + m[LEFT_ORDER[i]] + LEFT_K[round]);
		// Сдвигаем левый поток
		t = (rotl(t, LEFT_SHIFT[i]) + el);
		// Сдвигаем рабочие переменные левого потока
		al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = t;
		// Временная переменная правого потока (функции кругов идут в обратном порядке)
		t = (ar + fn(4 - round, br, cr, dr) + m[RIGHT_ORDER[i]] + RIGHT_K[round]);
		// Сдвигаем правый поток
		t = (rotl(t, RIGHT_SHIFT[i]) + er);
		// Сдвигаем рабочие переменные правого потока
		ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = t;
	}
	// Итоги потоков сходятся перекрёстным сложением
	const uint32_t t = (this->_hash[1] + cl + dr);
	// Складываем итоги потоков в значение хеша
	this->_hash[1] = (this->_hash[2] + dl + er);
	this->_hash[2] = (this->_hash[3] + el + ar);
	this->_hash[3] = (this->_hash[4] + al + br);
	this->_hash[4] = (this->_hash[0] + bl + cr);
	this->_hash[0] = t;
	// Затираем слова блока сообщения
	wipe(m, sizeof(m));
}
/**
 * @brief Метод сброса состояния хеширования
 *
 */
void nts::digest::Ripemd::reset() noexcept {
	// Сбрасываем признак снятого хеша
	this->_finished = false;
	// Сбрасываем число байтов незавершённого блока
	this->_size = 0;
	// Сбрасываем число разобранных байтов
	this->_count = 0;
	/**
	 * Выполняем перенос начальных значений хеша
	 */
	for(size_t i = 0; i < 5; i++)
		// Переносим очередное начальное значение
		this->_hash[i] = H[i];
	// Выполняем затирание накопителя незавершённого блока
	wipe(this->_block, sizeof(this->_block));
}
/**
 * @brief Метод подачи куска сообщения
 *
 * @param data подаваемый кусок сообщения
 *
 */
void nts::digest::Ripemd::update(const view_t & data) noexcept {
	// Если кусок задан длиной без места: подача порчена, хеш сниматься не будет
	if((data.data == nullptr) && (data.size > 0)){
		// Запоминаем порчу подачи: снятие хеша отказывает
		this->_finished = true;
		// Выходим из метода
		return;
	}
	// Если хеш уже снят либо кусок сообщения пуст
	if(this->_finished || (data.data == nullptr) || (data.size == 0))
		// Выходим из метода
		return;
	// Число ещё не разобранных байтов куска
	size_t left = data.size;
	// Позиция чтения куска
	const uint8_t * cursor = data.data;
	// Считаем поданные байты
	this->_count += static_cast <uint64_t> (data.size);
	// Если в накопителе есть незавершённый блок
	if(this->_size > 0){
		// Число байтов, которых накопителю не хватает до целого блока
		const size_t needed = (64 - this->_size);
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
		if(this->_size == 64){
			// Выполняем разбор накопленного блока
			this->compress(this->_block);
			// Сбрасываем число байтов незавершённого блока
			this->_size = 0;
		// Иначе весь кусок ушёл в накопитель, и блок ещё не полон
		} else return;
	}
	/**
	 * Выполняем разбор целых блоков куска прямо из него
	 */
	while(left >= 64){
		// Выполняем разбор очередного блока куска
		this->compress(cursor);
		// Сдвигаем позицию чтения куска
		cursor += 64;
		// Уменьшаем число не разобранных байтов
		left -= 64;
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
bool nts::digest::Ripemd::finish(uint8_t * result, const size_t size) noexcept {
	// Если хеш уже снят, либо места под него нет, либо оно мало
	if(this->_finished || (result == nullptr) || (size < RIPEMD160))
		// Выводим отказ снятия хеша
		return false;
	// Число разобранных разрядов сообщения
	const uint64_t bits = (this->_count << 3);
	// Записываем байт-отделитель за последним байтом сообщения
	this->_block[this->_size++] = 0x80;
	// Если места под поле длины в этом блоке не осталось
	if(this->_size > 56){
		/**
		 * Выполняем дополнение блока нулями до конца
		 */
		for(size_t i = this->_size; i < 64; i++)
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
	for(size_t i = this->_size; i < 56; i++)
		// Записываем очередной нулевой байт
		this->_block[i] = 0;
	// Записываем младшую половину длины сообщения от младшего байта
	store(static_cast <uint32_t> (bits), this->_block + 56);
	// Записываем старшую половину длины сообщения от младшего байта
	store(static_cast <uint32_t> (bits >> 32), this->_block + 60);
	// Выполняем разбор последнего блока
	this->compress(this->_block);
	/**
	 * Выполняем запись слов хеша от младшего байта
	 */
	for(size_t i = 0; i < 5; i++)
		// Записываем очередное слово хеша
		store(this->_hash[i], result + (i * 4));
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
 */
nts::digest::Ripemd::Ripemd() noexcept : _finished(true), _size(0), _count(0) {
	// Выполняем сброс состояния хеширования
	this->reset();
}
/**
 * @brief Деструктор
 *
 */
nts::digest::Ripemd::~Ripemd() noexcept {
	// Выполняем затирание значения хеша
	wipe(this->_hash, sizeof(this->_hash));
	// Выполняем затирание накопителя незавершённого блока
	wipe(this->_block, sizeof(this->_block));
}

/**
 * @brief Метод выработки хеша RIPEMD-160 целого сообщения
 *
 * @param data   хешируемое сообщение
 * @param result место, в которое записывается хеш
 * @param size   размер места в байтах, не меньше длины хеша
 *
 * @return       признак успешности выработки хеша
 *
 */
bool nts::digest::ripemd160(const view_t & data, uint8_t * result, const size_t size) noexcept {
	// Если место под хеш не передано либо мало
	if((result == nullptr) || (size < RIPEMD160))
		// Выводим отказ выработки хеша
		return false;
	// Хешируемое сообщение
	ripemd_t hasher;
	// Подаём сообщение
	hasher.update(data);
	// Выводим итог снятия хеша
	return hasher.finish(result, size);
}
