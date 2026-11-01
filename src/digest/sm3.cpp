/**
 * @file sm3.cpp
 * @date 2026-10-04
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
 * @brief Модуль хеширования SM3 по GB/T 32905-2016
 *
 * @details Преобразование над восемью словами в 32 разряда с блоком в 64 байта и 64
 *          кругами; слова читаются и пишутся от старшего байта
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <digest/sm3.hpp>
#include <sys/wipe.hpp>

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
	 * @brief Начальные значения хеша
	 *
	 * @details Раздел 5.3 GB/T 32905-2016
	 *
	 */
	static constexpr uint32_t H[8] = {
		// Первые четыре начальных значения хеша
		0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
		0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
	};

	/**
	 * @brief Функция кругового сдвига слова влево
	 *
	 * @param value сдвигаемое слово
	 * @param count число разрядов сдвига
	 * @return      сдвинутое слово
	 *
	 */
	static __ANTS_INLINE__ uint32_t rotl(const uint32_t value, const unsigned count) noexcept {
		// Если сдвиг нулевой, слово не меняется: сдвиг вправо на 32 разряда не определён
		if(count == 0)
			// Выводим слово без сдвига
			return value;
		// Выводим слово, сдвинутое по кругу
		return ((value << count) | (value >> (32 - count)));
	}

	/**
	 * @brief Функция чтения слова от старшего байта
	 *
	 * @param data читаемые байты
	 * @return     прочитанное слово
	 *
	 */
	static __ANTS_INLINE__ uint32_t load(const uint8_t * data) noexcept {
		// Выводим слово, собранное от старшего байта
		return ((static_cast <uint32_t> (data[0]) << 24) | (static_cast <uint32_t> (data[1]) << 16) |
		        (static_cast <uint32_t> (data[2]) << 8) | static_cast <uint32_t> (data[3]));
	}

	/**
	 * @brief Функция записи слова от старшего байта
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
	 * @brief Функция перестановки P0 расширения расписания
	 *
	 * @param value переставляемое слово
	 * @return      переставленное слово
	 *
	 */
	static __ANTS_INLINE__ uint32_t p0(const uint32_t value) noexcept {
		// Выводим слово, переставленное по правилу P0
		return (value ^ rotl(value, 9) ^ rotl(value, 17));
	}

	/**
	 * @brief Функция перестановки P1 расширения расписания
	 *
	 * @param value переставляемое слово
	 * @return      переставленное слово
	 *
	 */
	static __ANTS_INLINE__ uint32_t p1(const uint32_t value) noexcept {
		// Выводим слово, переставленное по правилу P1
		return (value ^ rotl(value, 15) ^ rotl(value, 23));
	}

	/**
	 * @brief Функция функции FF круга
	 *
	 * @param x первое слово
	 * @param y второе слово
	 * @param z третье слово
	 * @param i номер круга
	 * @return  значение функции круга
	 *
	 */
	static __ANTS_INLINE__ uint32_t ff(const uint32_t x, const uint32_t y, const uint32_t z, const size_t i) noexcept {
		// Если идёт первая шестнадцатка кругов
		if(i < 16)
			// Выводим функцию чётности
			return (x ^ y ^ z);
		// Выводим функцию большинства
		return ((x & y) | (x & z) | (y & z));
	}

	/**
	 * @brief Функция функции GG круга
	 *
	 * @param x первое слово
	 * @param y второе слово
	 * @param z третье слово
	 * @param i номер круга
	 * @return  значение функции круга
	 *
	 */
	static __ANTS_INLINE__ uint32_t gg(const uint32_t x, const uint32_t y, const uint32_t z, const size_t i) noexcept {
		// Если идёт первая шестнадцатка кругов
		if(i < 16)
			// Выводим функцию чётности
			return (x ^ y ^ z);
		// Выводим функцию выбора
		return ((x & y) | ((~x) & z));
	}
};

/**
 * @brief Метод разбора блока сообщения
 *
 * @param block разбираемый блок: накопитель либо сам кусок сообщения
 *
 */
void nts::digest::Sm3::compress(const uint8_t * block) noexcept {
	// Расписание слов сообщения
	uint32_t w[68];
	// Расширение расписания слов сообщения
	uint32_t w1[64];
	/**
	 * Выполняем чтение шестнадцати слов блока
	 */
	for(size_t i = 0; i < 16; i++)
		// Читаем очередное слово блока от старшего байта
		w[i] = load(block + (i * 4));
	/**
	 * Выполняем расширение расписания до 68 слов
	 */
	for(size_t i = 16; i < 68; i++)
		// Складываем очередное слово расписания по правилу расширения
		w[i] = (p1(w[i - 16] ^ w[i - 9] ^ rotl(w[i - 3], 15)) ^ rotl(w[i - 13], 7) ^ w[i - 6]);
	/**
	 * Выполняем расширение расписания до 64 слов
	 */
	for(size_t i = 0; i < 64; i++)
		// Складываем очередное слово расширения
		w1[i] = (w[i] ^ w[i + 4]);
	// Рабочие переменные круга
	uint32_t a = this->_hash[0], b = this->_hash[1], c = this->_hash[2], d = this->_hash[3];
	// Рабочие переменные круга
	uint32_t e = this->_hash[4], f = this->_hash[5], g = this->_hash[6], h = this->_hash[7];
	/**
	 * Выполняем 64 круга преобразования
	 */
	for(size_t i = 0; i < 64; i++){
		// Постоянная круга: 0x79CC4519 первой шестнадцатки, 0x7A879D8A остальных
		const uint32_t t = ((i < 16) ? 0x79CC4519 : 0x7A879D8A);
		// Промежуточная сумма круга
		const uint32_t ss1 = rotl((rotl(a, 12) + e + rotl(t, static_cast <unsigned> (i & 31))), 7);
		// Промежуточная сумма круга
		const uint32_t ss2 = (ss1 ^ rotl(a, 12));
		// Промежуточная сумма круга
		const uint32_t tt1 = (ff(a, b, c, i) + d + ss2 + w1[i]);
		// Промежуточная сумма круга
		const uint32_t tt2 = (gg(e, f, g, i) + h + ss1 + w[i]);
		// Сдвигаем рабочие переменные
		d = c;
		// Сдвигаем рабочие переменные с круговым сдвигом
		c = rotl(b, 9);
		// Сдвигаем рабочие переменные
		b = a;
		// Складываем новое значение переменной a
		a = tt1;
		// Сдвигаем рабочие переменные
		h = g;
		// Сдвигаем рабочие переменные с круговым сдвигом
		g = rotl(f, 19);
		// Сдвигаем рабочие переменные
		f = e;
		// Складываем новое значение переменной e с перестановкой P0
		e = p0(tt2);
	}
	// Складываем итог круга с прежним значением хеша
	this->_hash[0] ^= a;
	// Складываем итог круга с прежним значением хеша
	this->_hash[1] ^= b;
	// Складываем итог круга с прежним значением хеша
	this->_hash[2] ^= c;
	// Складываем итог круга с прежним значением хеша
	this->_hash[3] ^= d;
	// Складываем итог круга с прежним значением хеша
	this->_hash[4] ^= e;
	// Складываем итог круга с прежним значением хеша
	this->_hash[5] ^= f;
	// Складываем итог круга с прежним значением хеша
	this->_hash[6] ^= g;
	// Складываем итог круга с прежним значением хеша
	this->_hash[7] ^= h;
}
/**
 * @brief Метод сброса состояния хеширования
 *
 */
void nts::digest::Sm3::reset() noexcept {
	// Сбрасываем признак снятого хеша
	this->_finished = false;
	// Сбрасываем число байтов незавершённого блока
	this->_size = 0;
	// Сбрасываем число разобранных байтов
	this->_count = 0;
	/**
	 * Выполняем перенос начальных значений хеша
	 */
	for(size_t i = 0; i < 8; i++)
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
void nts::digest::Sm3::update(const view_t & data) noexcept {
	// Если кусок задан длиной без места: подача порчена, хеш сниматься не будет (договор тот же, что у Hasher)
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
 * @return       признак успешности снятия хеша
 *
 */
bool nts::digest::Sm3::finish(uint8_t * result, const size_t size) noexcept {
	// Если хеш уже снят, либо места под него нет, либо оно мало
	if(this->_finished || (result == nullptr) || (size < 32))
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
	// Записываем старшую половину длины сообщения
	store(static_cast <uint32_t> (bits >> 32), this->_block + 56);
	// Записываем младшую половину длины сообщения
	store(static_cast <uint32_t> (bits), this->_block + 60);
	// Выполняем разбор последнего блока
	this->compress(this->_block);
	/**
	 * Выполняем запись слов хеша от старшего байта
	 */
	for(size_t i = 0; i < 8; i++)
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
nts::digest::Sm3::Sm3() noexcept : _finished(true), _size(0), _count(0) {
	// Выполняем сброс состояния хеширования
	this->reset();
}
/**
 * @brief Деструктор
 *
 */
nts::digest::Sm3::~Sm3() noexcept {
	// Выполняем затирание значения хеша
	wipe(this->_hash, sizeof(this->_hash));
	// Выполняем затирание накопителя незавершённого блока
	wipe(this->_block, sizeof(this->_block));
}
/**
 * @brief Функция выработки хеша SM3 целого сообщения
 *
 * @param data   хешируемое сообщение
 * @param result место, в которое записывается хеш
 * @param size   размер места в байтах, не меньше длины хеша
 * @return       признак успешности выработки хеша
 *
 */
bool nts::digest::sm3(const view_t & data, uint8_t * result, const size_t size) noexcept {
	// Объект хеширования
	sm3_t hasher;
	// Выполняем подачу целого сообщения
	hasher.update(data);
	// Выводим итог снятия хеша
	return hasher.finish(result, size);
}
