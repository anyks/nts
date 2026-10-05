/**
 * @file ccm.cpp
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
 * @brief Модуль режима шифрования с проверкой целостности CCM по RFC 3610
 *
 * @details Метка целостности вырабатывается имитовставкой CBC-MAC над блоком B0,
 *          связанными данными и открытым текстом; зашифрование идёт гаммированием
 *          со счётчиком A_i, а метка накладывается суммой с гаммой блока A_0
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <cipher/ccm.hpp>
#include <sys/wipe.hpp>

/**
 * Стандартные заголовочные файлы
 */
#include <cstring>

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
	 * @brief Метод сложения блоков по модулю два
	 *
	 * @param first  первое слагаемое
	 * @param second второе слагаемое
	 * @param result место, в которое помещается сумма
	 * @param size   размер складываемых блоков
	 *
	 */
	static void add(const uint8_t * first, const uint8_t * second, uint8_t * result, const size_t size) noexcept {
		/**
		 * Выполняем перебор байтов складываемых блоков
		 */
		for(size_t i = 0; i < size; i++)
			// Складываем очередные байты блоков по модулю два
			result[i] = static_cast <uint8_t> (first[i] ^ second[i]);
	}

	/**
	 * @brief Метод сборки блока счётчика A_i
	 *
	 * @details Раздел 5.3 RFC 3610: признаки (L-1), одноразовое значение и номер
	 *          блока длиной L от старшего байта
	 *
	 * @param nonce  одноразовое значение режима
	 * @param length длина одноразового значения
	 * @param width  длина поля номера блока в байтах
	 * @param number номер блока счётчика
	 * @param result место, в которое помещается блок счётчика
	 *
	 */
	static void counter(const uint8_t * nonce, const size_t length, const size_t width, const uint64_t number, uint8_t * result) noexcept {
		// Записываем признаки блока счётчика: длина поля номера без единицы
		result[0] = static_cast <uint8_t> (width - 1);
		// Переносим одноразовое значение
		::memcpy(result + 1, nonce, length);
		// Записываем номер блока от старшего байта
		for(size_t i = 0; i < width; i++)
			// Записываем очередной байт номера блока
			result[15 - i] = static_cast <uint8_t> ((number >> (i * 8)) & 0xFF);
	}

	/**
	 * @brief Метод выработки имитовставки CBC-MAC над форматированным сообщением
	 *
	 * @details Раздел 5.2 RFC 3610: блок B0 с признаками и длиной сообщения, затем
	 *          связанные данные с их длиной, затем открытый текст; всякий кусок
	 *          дополняется нулями до блока
	 *
	 * @param block      базовый алгоритм блочного шифрования
	 * @param nonce      одноразовое значение режима
	 * @param length     длина одноразового значения
	 * @param width      длина поля длины сообщения в байтах
	 * @param size       длина метки целостности в байтах
	 * @param associated связанные данные
	 * @param source     открытый текст
	 * @param result     место, в которое помещается значение имитовставки
	 *
	 * @return признак успешности выработки имитовставки
	 *
	 */
	static bool mac(const block_t & block, const uint8_t * nonce, const size_t length, const size_t width, const size_t size, const view_t & associated, const view_t & source, uint8_t * result) noexcept {
		// Накопитель имитовставки
		uint8_t accumulator[16];
		// Текущий блок форматированного сообщения
		uint8_t item[16];
		// Записываем признаки блока B0: связанные данные, длина метки и длина поля длины
		item[0] = static_cast <uint8_t> ((((associated.size > 0) ? 1 : 0) << 6) | (((size - 2) / 2) << 3) | (width - 1));
		// Переносим одноразовое значение
		::memcpy(item + 1, nonce, length);
		// Записываем длину сообщения от старшего байта
		for(size_t i = 0; i < width; i++)
			// Записываем очередной байт длины сообщения
			item[15 - i] = static_cast <uint8_t> ((source.size >> (i * 8)) & 0xFF);
		// Первый блок идёт в накопитель напрямую
		if(!block.encrypt(block.cipher, item, accumulator)){
			// Выполняем затирание текущего блока
			wipe(item, sizeof(item));
			// Выводим отказ выработки имитовставки
			return false;
		}
		// Если связанные данные заданы
		if(associated.size > 0){
			// Длина записи длины связанных данных
			size_t prefix = 0;
			// Если длина связанных данных укладывается в короткую форму
			if(associated.size < 0xFF00){
				// Записываем длину двумя байтами от старшего
				item[0] = static_cast <uint8_t> ((associated.size >> 8) & 0xFF);
				// Записываем младший байт длины
				item[1] = static_cast <uint8_t> (associated.size & 0xFF);
				// Запоминаем длину короткой записи
				prefix = 2;
			// Иначе длина связанных данных идёт длинной формой
			} else {
				// Записываем признак длинной формы
				item[0] = 0xFF;
				// Записываем второй байт признака
				item[1] = 0xFE;
				// Записываем длину четырьмя байтами от старшего
				for(size_t i = 0; i < 4; i++)
					// Записываем очередной байт длины
					item[2 + i] = static_cast <uint8_t> ((associated.size >> ((3 - i) * 8)) & 0xFF);
				// Запоминаем длину длинной записи
				prefix = 6;
			}
			// Число байтов связанных данных в первом блоке
			const size_t taken = ((associated.size < (16 - prefix)) ? associated.size : (16 - prefix));
			// Переносим начало связанных данных в первый блок
			::memcpy(item + prefix, associated.data, taken);
			// Дополняем первый блок нулями
			if((prefix + taken) < 16)
				// Выполняем обнуление остатка первого блока
				::memset(item + prefix + taken, 0, 16 - prefix - taken);
			// Складываем первый блок с накопителем и зашифровываем
			add(accumulator, item, item, 16);
			// Если очередной блок зашифровать не удалось
			if(!block.encrypt(block.cipher, item, accumulator)){
				// Выполняем затирание текущего блока
				wipe(item, sizeof(item));
				// Выводим отказ выработки имитовставки
				return false;
			}
			// Позиция чтения связанных данных
			size_t offset = taken;
			/**
			 * Выполняем разбор целых блоков связанных данных
			 */
			while((associated.size - offset) >= 16){
				// Складываем очередной блок с накопителем
				add(accumulator, associated.data + offset, item, 16);
				// Если очередной блок зашифровать не удалось
				if(!block.encrypt(block.cipher, item, accumulator)){
					// Выполняем затирание текущего блока
					wipe(item, sizeof(item));
					// Выводим отказ выработки имитовставки
					return false;
				}
				// Сдвигаем позицию чтения связанных данных
				offset += 16;
			}
			// Если остался неполный блок связанных данных
			if(offset < associated.size){
				// Число оставшихся байтов связанных данных
				const size_t rest = (associated.size - offset);
				// Переносим остаток связанных данных в блок
				::memcpy(item, associated.data + offset, rest);
				// Дополняем блок нулями
				::memset(item + rest, 0, 16 - rest);
				// Складываем блок с накопителем
				add(accumulator, item, item, 16);
				// Если последний блок зашифровать не удалось
				if(!block.encrypt(block.cipher, item, accumulator)){
					// Выполняем затирание текущего блока
					wipe(item, sizeof(item));
					// Выводим отказ выработки имитовставки
					return false;
				}
			}
		}
		// Позиция чтения открытого текста
		size_t offset = 0;
		/**
		 * Выполняем разбор целых блоков открытого текста
		 */
		while((source.size - offset) >= 16){
			// Складываем очередной блок с накопителем
			add(accumulator, source.data + offset, item, 16);
			// Если очередной блок зашифровать не удалось
			if(!block.encrypt(block.cipher, item, accumulator)){
				// Выполняем затирание текущего блока
				wipe(item, sizeof(item));
				// Выводим отказ выработки имитовставки
				return false;
			}
			// Сдвигаем позицию чтения открытого текста
			offset += 16;
		}
		// Если остался неполный блок открытого текста
		if(offset < source.size){
			// Число оставшихся байтов открытого текста
			const size_t rest = (source.size - offset);
			// Переносим остаток открытого текста в блок
			::memcpy(item, source.data + offset, rest);
			// Дополняем блок нулями
			::memset(item + rest, 0, 16 - rest);
			// Складываем блок с накопителем
			add(accumulator, item, item, 16);
			// Если последний блок зашифровать не удалось
			if(!block.encrypt(block.cipher, item, accumulator)){
				// Выполняем затирание текущего блока
				wipe(item, sizeof(item));
				// Выводим отказ выработки имитовставки
				return false;
			}
		}
		// Переносим значение имитовставки на место итога
		::memcpy(result, accumulator, 16);
		// Выполняем затирание накопителя имитовставки
		wipe(accumulator, sizeof(accumulator));
		// Выполняем затирание текущего блока
		wipe(item, sizeof(item));
		// Выводим успешность выработки имитовставки
		return true;
	}

	/**
	 * @brief Метод наложения гаммы счётчика на сообщение
	 *
	 * @details Раздел 5.3 RFC 3610: блоки A_1, A_2, … зашифровываются, и гамма
	 *          складывается с сообщением по модулю два
	 *
	 * @param block  базовый алгоритм блочного шифрования
	 * @param nonce  одноразовое значение режима
	 * @param length длина одноразового значения
	 * @param width  длина поля номера блока в байтах
	 * @param source сообщение, на которое накладывается гамма
	 * @param result место, в которое помещается итог наложения
	 *
	 * @return признак успешности наложения гаммы
	 *
	 */
	static bool gamma(const block_t & block, const uint8_t * nonce, const size_t length, const size_t width, const view_t & source, uint8_t * result) noexcept {
		// Текущий блок счётчика
		uint8_t item[16];
		// Текущий блок гаммы
		uint8_t stream[16];
		// Номер текущего блока счётчика
		uint64_t number = 1;
		// Позиция чтения сообщения
		size_t offset = 0;
		/**
		 * Выполняем наложение гаммы по блокам сообщения
		 */
		while(offset < source.size){
			// Собираем очередной блок счётчика
			counter(nonce, length, width, number, item);
			// Если блок гаммы выработать не удалось
			if(!block.encrypt(block.cipher, item, stream)){
				// Выполняем затирание текущего блока счётчика
				wipe(item, sizeof(item));
				// Выводим отказ наложения гаммы
				return false;
			}
			// Число байтов сообщения в очередном блоке
			const size_t taken = (((source.size - offset) < 16) ? (source.size - offset) : 16);
			/**
			 * Выполняем наложение гаммы на очередной кусок сообщения
			 */
			for(size_t i = 0; i < taken; i++)
				// Накладываем очередной байт гаммы
				result[offset + i] = static_cast <uint8_t> (source.data[offset + i] ^ stream[i]);
			// Сдвигаем позицию чтения сообщения
			offset += taken;
			// Увеличиваем номер блока счётчика
			number++;
		}
		// Выполняем затирание текущего блока счётчика
		wipe(item, sizeof(item));
		// Выполняем затирание текущего блока гаммы
		wipe(stream, sizeof(stream));
		// Выводим успешность наложения гаммы
		return true;
	}
};

/**
 * @brief Метод проверки готовности режима к работе
 *
 * @return признак готовности режима к работе
 *
 */
bool nts::cipher::Ccm::ready() const noexcept {
	// Выводим признак готовности режима к работе
	return this->_ready;
}
/**
 * @brief Метод запуска режима работы
 *
 * @param block базовый алгоритм блочного шифрования
 * @param nonce начальное заполнение режима
 * @param size  длина метки целостности в байтах: чётная, от 4 до 16
 *
 * @return      признак успешности запуска режима работы
 *
 */
bool nts::cipher::Ccm::start(const block_t & block, const view_t & nonce, const size_t size) noexcept {
	// Выполняем сброс прежнего состояния режима работы
	this->clear();
	// Если базовый шифр непригоден либо блок его не в 16 байтов
	if((block.cipher == nullptr) || (block.encrypt == nullptr) || (block.size != 16))
		// Выводим отказ запуска режима работы
		return false;
	// Если одноразовое значение не задано либо длины не той: от 7 до 13 байтов по разделу 4 RFC 3610
	if((nonce.data == nullptr) || (nonce.size < 7) || (nonce.size > 13))
		// Выводим отказ запуска режима работы
		return false;
	// Если длина метки целостности нечётна либо вне отрезка [4, 16]
	if(((size % 2) != 0) || (size < 4) || (size > 16))
		// Выводим отказ запуска режима работы
		return false;
	// Запоминаем базовый алгоритм блочного шифрования
	this->_block = block;
	// Запоминаем длину метки целостности
	this->_size = size;
	// Запоминаем длину поля длины сообщения: L = 15 - nonce
	this->_width = (15 - nonce.size);
	// Запоминаем длину начального заполнения
	this->_length = nonce.size;
	// Переносим начальное заполнение режима
	::memcpy(this->_nonce, nonce.data, nonce.size);
	// Устанавливаем признак готовности режима к работе
	this->_ready = true;
	// Выводим успешность запуска режима работы
	return true;
}
/**
 * @brief Метод смены начального заполнения режима
 *
 * @param nonce новое начальное заполнение режима
 *
 * @return      признак успешности смены начального заполнения
 *
 */
bool nts::cipher::Ccm::restart(const view_t & nonce) noexcept {
	// Если режим не запущен либо одноразовое значение не той длины
	if(!this->_ready || (nonce.data == nullptr) || (nonce.size < 7) || (nonce.size > 13))
		// Выводим отказ смены заполнения
		return false;
	// Запоминаем длину поля длины сообщения: L = 15 - nonce
	this->_width = (15 - nonce.size);
	// Запоминаем длину начального заполнения
	this->_length = nonce.size;
	// Переносим начальное заполнение режима
	::memcpy(this->_nonce, nonce.data, nonce.size);
	// Выводим успешность смены заполнения
	return true;
}
/**
 * @brief Метод сброса состояния режима работы
 *
 */
void nts::cipher::Ccm::clear() noexcept {
	// Сбрасываем признак готовности режима к работе
	this->_ready = false;
	// Сбрасываем длину метки целостности
	this->_size = 0;
	// Сбрасываем длину поля длины сообщения
	this->_width = 0;
	// Сбрасываем длину начального заполнения
	this->_length = 0;
	// Сбрасываем базовый алгоритм блочного шифрования
	this->_block = block_t();
	// Выполняем затирание начального заполнения режима
	wipe(this->_nonce, sizeof(this->_nonce));
}
/**
 * @brief Метод зашифрования сообщения с выработкой метки целостности
 *
 * @param associated связанные данные
 * @param source     зашифровываемое сообщение
 * @param result     место, в которое помещается зашифрованное сообщение
 * @param tag        место, в которое помещается метка целостности
 *
 * @return признак успешности зашифрования
 *
 */
bool nts::cipher::Ccm::encrypt(const view_t & associated, const view_t & source, uint8_t * result, uint8_t * tag) noexcept {
	// Если режим не готов, либо сообщение не задано, либо места итогов не заданы
	if(!this->_ready || ((source.data == nullptr) && (source.size > 0)) || (result == nullptr) || (tag == nullptr))
		// Выводим отказ зашифрования
		return false;
	// Если сообщение не укладывается в поле длины
	if((this->_width < 8) && (source.size >= (1ULL << (this->_width * 8))))
		// Выводим отказ зашифрования
		return false;
	// Значение имитовставки сообщения
	uint8_t value[16];
	// Если имитовставку выработать не удалось
	if(!mac(this->_block, this->_nonce, this->_length, this->_width, this->_size, associated, source, value))
		// Выводим отказ зашифрования
		return false;
	// Если гамму на сообщение наложить не удалось
	if(!gamma(this->_block, this->_nonce, this->_length, this->_width, source, result)){
		// Выполняем затирание значения имитовставки
		wipe(value, sizeof(value));
		// Выводим отказ зашифрования
		return false;
	}
	// Блок счётчика A_0
	uint8_t item[16];
	// Гамма блока A_0
	uint8_t stream[16];
	// Собираем блок счётчика A_0
	counter(this->_nonce, this->_length, this->_width, 0, item);
	// Если гамму блока A_0 выработать не удалось
	if(!this->_block.encrypt(this->_block.cipher, item, stream)){
		// Выполняем затирание значения имитовставки
		wipe(value, sizeof(value));
		// Выполняем затирание блока счётчика
		wipe(item, sizeof(item));
		// Выводим отказ зашифрования
		return false;
	}
	/**
	 * Выполняем наложение гаммы блока A_0 на метку целостности
	 */
	for(size_t i = 0; i < this->_size; i++)
		// Накладываем очередной байт гаммы на метку
		tag[i] = static_cast <uint8_t> (value[i] ^ stream[i]);
	// Выполняем затирание значения имитовставки
	wipe(value, sizeof(value));
	// Выполняем затирание блока счётчика
	wipe(item, sizeof(item));
	// Выполняем затирание гаммы блока
	wipe(stream, sizeof(stream));
	// Выводим успешность зашифрования
	return true;
}
/**
 * @brief Метод расшифрования сообщения с проверкой метки целостности
 *
 * @param associated связанные данные
 * @param source     расшифровываемое сообщение
 * @param tag        проверяемая метка целостности
 * @param result     место, в которое помещается расшифрованное сообщение
 *
 * @return признак того, что метка целостности сошлась
 *
 */
bool nts::cipher::Ccm::decrypt(const view_t & associated, const view_t & source, const view_t & tag, uint8_t * result) noexcept {
	// Если режим не готов, либо сообщение не задано, либо метка не той длины, либо место итога не задано
	if(!this->_ready || ((source.data == nullptr) && (source.size > 0)) || (tag.data == nullptr) || (tag.size != this->_size) || (result == nullptr))
		// Выводим отказ расшифрования
		return false;
	// Если сообщение не укладывается в поле длины
	if((this->_width < 8) && (source.size >= (1ULL << (this->_width * 8))))
		// Выводим отказ расшифрования
		return false;
	// Если гамму на сообщение наложить не удалось
	if(!gamma(this->_block, this->_nonce, this->_length, this->_width, source, result))
		// Выводим отказ расшифрования
		return false;
	// Значение имитовставки расшифрованного сообщения
	uint8_t value[16];
	// Если имитовставку выработать не удалось
	if(!mac(this->_block, this->_nonce, this->_length, this->_width, this->_size, associated, view_t(result, source.size), value)){
		// Выполняем затирание расшифрованного сообщения
		wipe(result, source.size);
		// Выводим отказ расшифрования
		return false;
	}
	// Блок счётчика A_0
	uint8_t item[16];
	// Гамма блока A_0
	uint8_t stream[16];
	// Собираем блок счётчика A_0
	counter(this->_nonce, this->_length, this->_width, 0, item);
	// Если гамму блока A_0 выработать не удалось
	if(!this->_block.encrypt(this->_block.cipher, item, stream)){
		// Выполняем затирание расшифрованного сообщения
		wipe(result, source.size);
		// Выполняем затирание значения имитовставки
		wipe(value, sizeof(value));
		// Выполняем затирание блока счётчика
		wipe(item, sizeof(item));
		// Выводим отказ расшифрования
		return false;
	}
	// Накопленное различие метки целостности
	uint8_t difference = 0;
	/**
	 * Выполняем сличение метки целостности за постоянное время
	 */
	for(size_t i = 0; i < this->_size; i++)
		// Накапливаем различие очередных байтов метки
		difference |= static_cast <uint8_t> (tag.data[i] ^ (value[i] ^ stream[i]));
	// Выполняем затирание значения имитовставки
	wipe(value, sizeof(value));
	// Выполняем затирание блока счётчика
	wipe(item, sizeof(item));
	// Выполняем затирание гаммы блока
	wipe(stream, sizeof(stream));
	// Если метка целостности не сошлась
	if(difference != 0){
		// Выполняем затирание расшифрованного сообщения
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
nts::cipher::Ccm::Ccm() noexcept : _ready(false), _size(0), _width(0), _length(0) {
	// Выполняем затирание начального заполнения режима
	wipe(this->_nonce, sizeof(this->_nonce));
}
/**
 * @brief Деструктор
 *
 */
nts::cipher::Ccm::~Ccm() noexcept {
	// Выполняем затирание начального заполнения режима
	wipe(this->_nonce, sizeof(this->_nonce));
}
