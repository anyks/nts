/**
 * @file md5.cpp
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
 * @brief Модуль хеширования MD5 по RFC 1321
 *
 * @details Преобразование над четырьмя словами в 32 разряда с блоком в 64 байта и
 *          64 кругами; слова читаются и пишутся от младшего байта
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <digest/md5.hpp>
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
	 * @brief Круговые постоянные
	 *
	 * @details Целые части чисел 2^32 · |sin(i + 1)|, раздел 3.4 RFC 1321
	 *
	 */
	static constexpr uint32_t K[64] = {
		// Первые восемь круговых постоянных
		0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
		0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE, 0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
		0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
		0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
		0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C, 0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
		0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
		0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
		0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1, 0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391
	};

	/**
	 * @brief Величины круговых сдвигов по кругам
	 *
	 * @details Раздел 3.4 RFC 1321: по четыре величины на каждую из четырёх четвертей
	 *
	 */
	static constexpr unsigned S[64] = {
		// Величины сдвигов первой четверти кругов
		7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
		5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
		4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
		6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
	};

	/**
	 * @brief Начальные значения хеша
	 *
	 * @details Раздел 3.3 RFC 1321
	 *
	 */
	static constexpr uint32_t H[4] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476};

	/**
	 * @brief Функция кругового сдвига слова влево
	 *
	 * @param value сдвигаемое слово
	 * @param count число разрядов сдвига
	 * @return      сдвинутое слово
	 *
	 */
	static __ANTS_INLINE__ uint32_t rotl(const uint32_t value, const unsigned count) noexcept {
		// Выводим слово, сдвинутое по кругу
		return ((value << count) | (value >> (32 - count)));
	}

	/**
	 * @brief Функция чтения слова от младшего байта
	 *
	 * @param data читаемые байты
	 * @return     прочитанное слово
	 *
	 */
	static __ANTS_INLINE__ uint32_t load(const uint8_t * data) noexcept {
		// Выводим слово, собранное от младшего байта
		return (static_cast <uint32_t> (data[0]) | (static_cast <uint32_t> (data[1]) << 8) |
		        (static_cast <uint32_t> (data[2]) << 16) | (static_cast <uint32_t> (data[3]) << 24));
	}

	/**
	 * @brief Функция записи слова от младшего байта
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
void nts::digest::Md5::compress(const uint8_t * block) noexcept {
	// Слова блока сообщения
	uint32_t m[16];
	/**
	 * Выполняем чтение шестнадцати слов блока
	 */
	for(size_t i = 0; i < 16; i++)
		// Читаем очередное слово блока от младшего байта
		m[i] = load(block + (i * 4));
	// Рабочие переменные круга
	uint32_t a = this->_hash[0], b = this->_hash[1], c = this->_hash[2], d = this->_hash[3];
	/**
	 * Выполняем 64 круга преобразования
	 */
	for(size_t i = 0; i < 64; i++){
		// Значение функции круга
		uint32_t f = 0;
		// Номер слова блока, берущегося в круге
		size_t g = 0;
		// Если идёт первая четверть кругов
		if(i < 16){
			// Функция первой четверти
			f = ((b & c) | ((~b) & d));
			// Слова берутся подряд
			g = i;
		// Если идёт вторая четверть кругов
		} else if(i < 32){
			// Функция второй четверти
			f = ((d & b) | ((~d) & c));
			// Слова берутся с шагом пять
			g = (((5 * i) + 1) % 16);
		// Если идёт третья четверть кругов
		} else if(i < 48){
			// Функция третьей четверти
			f = (b ^ c ^ d);
			// Слова берутся с шагом три
			g = (((3 * i) + 5) % 16);
		// Если идёт последняя четверть кругов
		} else {
			// Функция последней четверти
			f = (c ^ (b | (~d)));
			// Слова берутся с шагом семь
			g = ((7 * i) % 16);
		}
		// Сумма круга
		const uint32_t sum = (a + f + K[i] + m[g]);
		// Сдвигаем рабочие переменные
		a = d;
		// Сдвигаем рабочие переменные
		d = c;
		// Сдвигаем рабочие переменные
		c = b;
		// Складываем новое значение переменной b
		b = (b + rotl(sum, S[i]));
	}
	// Складываем итог круга с прежним значением хеша
	this->_hash[0] += a;
	// Складываем итог круга с прежним значением хеша
	this->_hash[1] += b;
	// Складываем итог круга с прежним значением хеша
	this->_hash[2] += c;
	// Складываем итог круга с прежним значением хеша
	this->_hash[3] += d;
}
/**
 * @brief Метод сброса состояния хеширования
 *
 */
void nts::digest::Md5::reset() noexcept {
	// Сбрасываем признак снятого хеша
	this->_finished = false;
	// Сбрасываем число байтов незавершённого блока
	this->_size = 0;
	// Сбрасываем число разобранных байтов
	this->_count = 0;
	/**
	 * Выполняем перенос начальных значений хеша
	 */
	for(size_t i = 0; i < 4; i++)
		// Переносим очередное начальное значение
		this->_hash[i] = H[i];
	// Затирание накопителя незавершённого блока
	wipe(this->_block, sizeof(this->_block));
}
/**
 * @brief Метод подачи куска сообщения
 *
 * @param data подаваемый кусок сообщения
 *
 */
void nts::digest::Md5::update(const view_t & data) noexcept {
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
			// Разбор накопленного блока
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
		// Разбор очередного блока куска
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
bool nts::digest::Md5::finish(uint8_t * result, const size_t size) noexcept {
	// Если хеш уже снят, либо места под него нет, либо оно мало
	if(this->_finished || (result == nullptr) || (size < 16))
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
		// Разбор дополненного блока
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
	// Разбор последнего блока
	this->compress(this->_block);
	/**
	 * Выполняем запись слов хеша от младшего байта
	 */
	for(size_t i = 0; i < 4; i++)
		// Записываем очередное слово хеша
		store(this->_hash[i], result + (i * 4));
	// Затирание значения хеша
	wipe(this->_hash, sizeof(this->_hash));
	// Затирание накопителя незавершённого блока
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
nts::digest::Md5::Md5() noexcept : _finished(true), _size(0), _count(0) {
	// Сброс состояния хеширования
	this->reset();
}
/**
 * @brief Деструктор
 *
 */
nts::digest::Md5::~Md5() noexcept {
	// Затирание значения хеша
	wipe(this->_hash, sizeof(this->_hash));
	// Затирание накопителя незавершённого блока
	wipe(this->_block, sizeof(this->_block));
}
/**
 * @brief Функция выработки хеша MD5 целого сообщения
 *
 * @param data   хешируемое сообщение
 * @param result место, в которое записывается хеш
 * @param size   размер места в байтах, не меньше длины хеша
 * @return       признак успешности выработки хеша
 *
 */
bool nts::digest::md5(const view_t & data, uint8_t * result, const size_t size) noexcept {
	// Объект хеширования
	md5_t hasher;
	// Подачу целого сообщения
	hasher.update(data);
	// Выводим итог снятия хеша
	return hasher.finish(result, size);
}
