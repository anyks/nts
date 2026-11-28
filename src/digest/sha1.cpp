/**
 * @file sha1.cpp
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
 * @brief Модуль хеширования SHA-1 по FIPS 180-4
 *
 * @details Преобразование над пятью словами в 32 разряда с блоком в 64 байта и 80
 *          кругами; слова читаются и пишутся от старшего байта
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочный файл проекта
 */
#include "sys/wipe.hpp"

/**
 * Подключаем заголовочный файл модуля
 */
#include "digest/sha1.hpp"

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

	/**
	 * Затирание областей памяти берётся из открытого API библиотеки
	 */
	using nts::sys::wipe;

	/**
	 * @brief Начальные значения хеша
	 *
	 * @details Раздел 5.3.1 FIPS 180-4.
	 *
	 */
	static constexpr uint32_t H[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};

	/**
	 * @brief Функция кругового сдвига слова влево
	 *
	 * @param value сдвигаемое слово
	 * @param count количество разрядов сдвига
	 * @return      сдвинутое слово
	 *
	 */
	static constexpr uint32_t __nts_rotl__(const uint32_t value, const unsigned count) noexcept {
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
	static __NTS_INLINE__ uint32_t __nts_load__(const uint8_t * data) noexcept {
		// Выводим слово, собранное от старшего байта
		return (
			(static_cast <uint32_t> (data[0]) << 24) | (static_cast <uint32_t> (data[1]) << 16) |
			(static_cast <uint32_t> (data[2]) << 8) | static_cast <uint32_t> (data[3])
		);
	}
	/**
	 * @brief Функция записи слова от старшего байта
	 *
	 * @param value записываемое слово
	 * @param data  место, в которое записываются байты
	 *
	 */
	static __NTS_INLINE__ void __nts_store__(const uint32_t value, uint8_t * data) noexcept {
		// Записываем старший байт слова
		data[0] = static_cast <uint8_t> (value >> 24);
		// Записываем второй байт слова
		data[1] = static_cast <uint8_t> (value >> 16);
		// Записываем третий байт слова
		data[2] = static_cast <uint8_t> (value >> 8);
		// Записываем младший байт слова
		data[3] = static_cast <uint8_t> (value);
	}
};

/**
 * @brief Метод разбора блока сообщения
 *
 * @param block разбираемый блок: накопитель либо сам кусок сообщения
 *
 */
void nts::digest::Sha1::compress(const uint8_t * block) noexcept {
	// Расписание из восьмидесяти слов сообщения
	uint32_t schedule[80];
	/**
	 * Разбираем блок на шестнадцать слов
	 */
	for(size_t i = 0; i < 16; i++)
		// Читаем очередное слово блока от старшего байта
		schedule[i] = ::__nts_load__(block + (i * 4));
	/**
	 * Расширяем расписание до 80 слов
	 */
	for(size_t i = 16; i < 80; i++)
		// Вычисляем слово из четырёх прежних и сдвигаем влево на 1
		schedule[i] = ::__nts_rotl__((schedule[i - 3] ^ schedule[i - 8] ^ schedule[i - 14] ^ schedule[i - 16]), 1);
	// Рабочие регистры круга из текущего значения хеша
	uint32_t regA = this->_hash[0], regB = this->_hash[1], regC = this->_hash[2], regD = this->_hash[3], regE = this->_hash[4];
	/**
	 * Проходим 80 кругов преобразования
	 */
	for(size_t i = 0; i < 80; i++){
		// Значение булевой функции круга
		uint32_t roundFunction = 0;
		// Круговая постоянная
		uint32_t roundConstant = 0;
		// Если идёт первая двадцатка кругов
		if(i < 20){
			// Функция F: по маске b берём c, иначе d
			roundFunction = ((regB & regC) | ((~regB) & regD));
			// Постоянная первой двадцатки кругов
			roundConstant = 0x5A827999;
		// Если идёт вторая двадцатка кругов
		} else if(i < 40) {
			// Функция G: исключающее или регистров b, c, d
			roundFunction = (regB ^ regC ^ regD);
			// Постоянная второй двадцатки кругов
			roundConstant = 0x6ED9EBA1;
		// Если идёт третья двадцатка кругов
		} else if(i < 60) {
			// Функция H: большинство из регистров b, c, d
			roundFunction = ((regB & regC) | (regB & regD) | (regC & regD));
			// Постоянная третьей двадцатки кругов
			roundConstant = 0x8F1BBCDC;
		// Если идёт последняя двадцатка кругов
		} else {
			// Функция I: исключающее или регистров b, c, d
			roundFunction = (regB ^ regC ^ regD);
			// Постоянная последней двадцатки кругов
			roundConstant = 0xCA62C1D6;
		}
		// Сумма круга: сдвинутый a, функция, e, постоянная и слово расписания
		const uint32_t roundSum = (::__nts_rotl__(regA, 5) + roundFunction + regE + roundConstant + schedule[i]);
		// Переносим прежний регистр d в e
		regE = regD;
		// Переносим прежний регистр c в d
		regD = regC;
		// Новое c — прежний регистр b со сдвигом влево на 30
		regC = ::__nts_rotl__(regB, 30);
		// Переносим прежний регистр a в b
		regB = regA;
		// Новое a — сумма круга
		regA = roundSum;
	}
	// Прибавляем регистр a к первому слову хеша
	this->_hash[0] += regA;
	// Прибавляем регистр b ко второму слову хеша
	this->_hash[1] += regB;
	// Прибавляем регистр c к третьему слову хеша
	this->_hash[2] += regC;
	// Прибавляем регистр d к четвёртому слову хеша
	this->_hash[3] += regD;
	// Прибавляем регистр e к пятому слову хеша
	this->_hash[4] += regE;
}
/**
 * @brief Метод сброса состояния хеширования
 *
 */
void nts::digest::Sha1::reset() noexcept {
	// Сбрасываем количество байтов незавершённого блока
	this->_size = 0;
	// Сбрасываем количество разобранных байтов
	this->_count = 0;
	// Сбрасываем признак снятого хеша
	this->_finished = false;
	/**
	 * Переносим начальные значения хеша
	 */
	for(size_t i = 0; i < 5; i++)
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
void nts::digest::Sha1::update(const view_t & data) noexcept {
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
		// Количество байтов, которых накопителю не хватает до целого блока
		const size_t needed = (64 - this->_size);
		// Количество байтов, переносимых в накопитель из куска
		const size_t taken = ((left < needed) ? left : needed);
		/**
		 * Переносим байты куска в накопитель
		 */
		for(size_t i = 0; i < taken; i++)
			// Переносим очередной байт куска
			this->_block[this->_size + i] = cursor[i];
		// Считаем перенесённые байты
		this->_size += taken;
		// Сдвигаем позицию чтения куска
		cursor += taken;
		// Уменьшаем количество не разобранных байтов
		left -= taken;
		// Если блок набрался целиком
		if(this->_size == 64){
			// Разбор накопленного блока
			this->compress(this->_block);
			// Сбрасываем количество байтов незавершённого блока
			this->_size = 0;
		// Иначе весь кусок ушёл в накопитель, и блок ещё не полон
		} else return;
	}
	/**
	 * Разбираем целые блоки куска прямо из него
	 */
	while(left >= 64){
		// Разбор очередного блока куска
		this->compress(cursor);
		// Сдвигаем позицию чтения куска
		cursor += 64;
		// Уменьшаем количество не разобранных байтов
		left -= 64;
	}
	/**
	 * Переносим хвост куска в накопитель
	 */
	for(size_t i = 0; i < left; i++)
		// Переносим очередной байт хвоста
		this->_block[i] = cursor[i];
	// Запоминаем количество байтов незавершённого блока
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
bool nts::digest::Sha1::finish(uint8_t * result, const size_t size) noexcept {
	// Если хеш уже снят, либо места под него нет, либо оно мало
	if(this->_finished || (result == nullptr) || (size < 20))
		// Выводим отказ снятия хеша
		return false;
	// Количество разобранных разрядов сообщения
	const uint64_t bits = (this->_count << 3);
	// Записываем байт-отделитель за последним байтом сообщения
	this->_block[this->_size++] = 0x80;
	// Если места под поле длины в этом блоке не осталось
	if(this->_size > 56){
		/**
		 * Дополняем блок нулями до конца
		 */
		for(size_t i = this->_size; i < 64; i++)
			// Записываем очередной нулевой байт
			this->_block[i] = 0;
		// Разбор дополненного блока
		this->compress(this->_block);
		// Сбрасываем количество байтов незавершённого блока
		this->_size = 0;
	}
	/**
	 * Дополняем блок нулями до поля длины
	 */
	for(size_t i = this->_size; i < 56; i++)
		// Записываем очередной нулевой байт
		this->_block[i] = 0;
	// Записываем старшую половину длины сообщения
	::__nts_store__(static_cast <uint32_t> (bits >> 32), this->_block + 56);
	// Записываем младшую половину длины сообщения
	::__nts_store__(static_cast <uint32_t> (bits), this->_block + 60);
	// Разбор последнего блока
	this->compress(this->_block);
	/**
	 * Записываем слова хеша от старшего байта
	 */
	for(size_t i = 0; i < 5; i++)
		// Записываем очередное слово хеша
		::__nts_store__(this->_hash[i], result + (i * 4));
	// Затирание значения хеша
	wipe(this->_hash, sizeof(this->_hash));
	// Затирание накопителя незавершённого блока
	wipe(this->_block, sizeof(this->_block));
	// Сбрасываем количество байтов незавершённого блока
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
nts::digest::Sha1::Sha1() noexcept : _finished(true), _size(0), _count(0) {
	// Сброс состояния хеширования
	this->reset();
}
/**
 * @brief Деструктор
 *
 */
nts::digest::Sha1::~Sha1() noexcept {
	// Затирание значения хеша
	wipe(this->_hash, sizeof(this->_hash));
	// Затирание накопителя незавершённого блока
	wipe(this->_block, sizeof(this->_block));
}
/**
 * @brief Функция выработки хеша SHA-1 целого сообщения
 *
 * @param data   хешируемое сообщение
 * @param result место, в которое записывается хеш
 * @param size   размер места в байтах, не меньше длины хеша
 * @return       признак успешности выработки хеша
 *
 */
bool nts::digest::sha1(const view_t & data, uint8_t * result, const size_t size) noexcept {
	// Объект хеширования
	sha1_t hasher;
	// Подачу целого сообщения
	hasher.update(data);
	// Выводим итог снятия хеша
	return hasher.finish(result, size);
}
