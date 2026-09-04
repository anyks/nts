/**
 * @file chacha.cpp
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
 * @brief Поточный шифр ChaCha20 по RFC 8439
 *
 * @details Блочная функция раздела 2.3: состояние в шестнадцать слов копируется в
 *          рабочее, над рабочим проводятся десять двойных раундов - по четыре
 *          четвертьраунда столбцами и по четыре диагоналями, - и рабочее слово за
 *          словом складывается с исходным. Слова читаются и пишутся от младшего
 *          байта, как велит стандарт. Гамма накладывается на данные сложением по
 *          модулю два; остаток неполного блока хранится до следующего куска
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
#include <cipher/chacha.hpp>
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
	using namespace nts::cipher;

	/**
	 * @brief Постоянные слова состояния: запись «expand 32-byte k» от младшего байта
	 *
	 */
	static constexpr uint32_t CONSTANTS[4] = {0x61707865, 0x3320646E, 0x79622D32, 0x6B206574};

	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;
	/**
	 * @brief Метод чтения слова в 32 разряда от младшего байта
	 *
	 * @param data читаемые байты
	 *
	 * @return     прочитанное слово
	 *
	 */
	static inline uint32_t load(const uint8_t * data) noexcept {
		// Выводим слово, собранное от младшего байта
		return (static_cast <uint32_t> (data[0]) | (static_cast <uint32_t> (data[1]) << 8) | (static_cast <uint32_t> (data[2]) << 16) | (static_cast <uint32_t> (data[3]) << 24));
	}
	/**
	 * @brief Метод записи слова в 32 разряда от младшего байта
	 *
	 * @param value записываемое слово
	 * @param data  место, в которое записываются байты
	 *
	 */
	static inline void store(const uint32_t value, uint8_t * data) noexcept {
		// Записываем младший байт
		data[0] = static_cast <uint8_t> (value);
		// Записываем второй байт
		data[1] = static_cast <uint8_t> (value >> 8);
		// Записываем третий байт
		data[2] = static_cast <uint8_t> (value >> 16);
		// Записываем старший байт
		data[3] = static_cast <uint8_t> (value >> 24);
	}
	/**
	 * @brief Метод циклического вращения слова влево
	 *
	 * @param value вращаемое слово
	 * @param count число разрядов вращения от одного до тридцати одного
	 *
	 * @return      вращённое слово
	 *
	 */
	static inline uint32_t rotate(const uint32_t value, const unsigned count) noexcept {
		// Выводим слово, вращённое влево
		return ((value << count) | (value >> (32 - count)));
	}
};

/**
 * @brief Метод четвертьраунда ChaCha20
 *
 * @param a первое слово, заменяемое итогом
 * @param b второе слово, заменяемое итогом
 * @param c третье слово, заменяемое итогом
 * @param d четвёртое слово, заменяемое итогом
 *
 */
void nts::cipher::Chacha::quarter(uint32_t & a, uint32_t & b, uint32_t & c, uint32_t & d) noexcept {
	// Складываем первое слово со вторым
	a += b;
	// Складываем четвёртое слово с первым по модулю два
	d ^= a;
	// Вращаем четвёртое слово на шестнадцать разрядов
	d = rotate(d, 16);
	// Складываем третье слово с четвёртым
	c += d;
	// Складываем второе слово с третьим по модулю два
	b ^= c;
	// Вращаем второе слово на двенадцать разрядов
	b = rotate(b, 12);
	// Складываем первое слово со вторым
	a += b;
	// Складываем четвёртое слово с первым по модулю два
	d ^= a;
	// Вращаем четвёртое слово на восемь разрядов
	d = rotate(d, 8);
	// Складываем третье слово с четвёртым
	c += d;
	// Складываем второе слово с третьим по модулю два
	b ^= c;
	// Вращаем второе слово на семь разрядов
	b = rotate(b, 7);
}
/**
 * @brief Метод выработки блока гаммы на текущем счётчике
 *
 * @param result место в 64 байта, в которое записывается блок гаммы
 *
 */
void nts::cipher::Chacha::generate(uint8_t * result) const noexcept {
	// Рабочее состояние
	uint32_t work[16];
	// Переносим состояние в рабочее
	::memcpy(work, this->_state, sizeof(work));
	/**
	 * Выполняем десять двойных раундов: столбцами и диагоналями
	 */
	for(size_t i = 0; i < 10; i++){
		// Четвертьраунд первого столбца
		quarter(work[0], work[4], work[8], work[12]);
		// Четвертьраунд второго столбца
		quarter(work[1], work[5], work[9], work[13]);
		// Четвертьраунд третьего столбца
		quarter(work[2], work[6], work[10], work[14]);
		// Четвертьраунд четвёртого столбца
		quarter(work[3], work[7], work[11], work[15]);
		// Четвертьраунд первой диагонали
		quarter(work[0], work[5], work[10], work[15]);
		// Четвертьраунд второй диагонали
		quarter(work[1], work[6], work[11], work[12]);
		// Четвертьраунд третьей диагонали
		quarter(work[2], work[7], work[8], work[13]);
		// Четвертьраунд четвёртой диагонали
		quarter(work[3], work[4], work[9], work[14]);
	}
	/**
	 * Выполняем сложение рабочего состояния с исходным и запись от младшего байта
	 */
	for(size_t i = 0; i < 16; i++)
		// Записываем очередное слово блока гаммы
		store(work[i] + this->_state[i], result + (i * 4));
	// Выполняем затирание рабочего состояния
	wipe(work, sizeof(work));
}
/**
 * @brief Метод продвижения счётчика блока
 *
 * @return признак того, что счётчик не переполнился
 *
 */
bool nts::cipher::Chacha::advance() noexcept {
	// Увеличиваем счётчик блока
	this->_state[12]++;
	// Если счётчик обратился в ноль
	if(this->_state[12] == 0)
		// Запоминаем переполнение счётчика
		this->_exhausted = true;
	// Выводим признак отсутствия переполнения
	return !this->_exhausted;
}
/**
 * @brief Метод проверки готовности шифра к работе
 *
 * @return признак готовности шифра
 *
 */
bool nts::cipher::Chacha::ready() const noexcept {
	// Выводим признак готовности шифра
	return this->_ready;
}
/**
 * @brief Метод получения текущего счётчика блока
 *
 * @return счётчик блока, который выработает следующий блок гаммы
 *
 */
uint32_t nts::cipher::Chacha::counter() const noexcept {
	// Выводим счётчик блока
	return this->_state[12];
}
/**
 * @brief Метод запуска шифра
 *
 * @param key     ключ в 32 байта
 * @param nonce   начальное заполнение в 12 байтов
 * @param counter начальное значение счётчика блока
 *
 * @return        признак успешности запуска
 *
 */
bool nts::cipher::Chacha::start(const view_t & key, const view_t & nonce, const uint32_t counter) noexcept {
	// Выполняем сброс прежнего состояния
	this->clear();
	// Если ключ либо заполнение не той длины либо не переданы
	if((key.data == nullptr) || (key.size != CHACHA_KEY) || (nonce.data == nullptr) || (nonce.size != CHACHA_NONCE))
		// Выводим отказ запуска
		return false;
	/**
	 * Выполняем запись постоянных слов состояния
	 */
	for(size_t i = 0; i < 4; i++)
		// Записываем очередное постоянное слово
		this->_state[i] = CONSTANTS[i];
	/**
	 * Выполняем запись слов ключа от младшего байта
	 */
	for(size_t i = 0; i < 8; i++)
		// Записываем очередное слово ключа
		this->_state[4 + i] = load(key.data + (i * 4));
	// Записываем счётчик блока
	this->_state[12] = counter;
	/**
	 * Выполняем запись слов заполнения от младшего байта
	 */
	for(size_t i = 0; i < 3; i++)
		// Записываем очередное слово заполнения
		this->_state[13 + i] = load(nonce.data + (i * 4));
	// Запоминаем готовность шифра
	this->_ready = true;
	// Выводим успешность запуска
	return true;
}
/**
 * @brief Метод сброса шифра с затиранием состояния
 *
 */
void nts::cipher::Chacha::clear() noexcept {
	// Сбрасываем признак готовности
	this->_ready = false;
	// Сбрасываем признак переполнения счётчика
	this->_exhausted = false;
	// Сбрасываем остаток блока гаммы
	this->_rest = 0;
	// Выполняем затирание состояния
	wipe(this->_state, sizeof(this->_state));
	// Выполняем затирание остатка блока гаммы
	wipe(this->_gamma, sizeof(this->_gamma));
}
/**
 * @brief Метод выработки целого блока гаммы
 *
 * @param result место в 64 байта, в которое записывается блок гаммы
 *
 * @return       признак успешности выработки
 *
 */
bool nts::cipher::Chacha::block(uint8_t * result) noexcept {
	// Если шифр не готов, места под блок нет либо счётчик переполнен
	if(!this->_ready || (result == nullptr) || this->_exhausted)
		// Выводим отказ выработки
		return false;
	// Отбрасываем неизрасходованный остаток прежнего блока
	this->_rest = 0;
	// Выполняем затирание остатка блока гаммы
	wipe(this->_gamma, sizeof(this->_gamma));
	// Выполняем выработку блока гаммы
	this->generate(result);
	// Продвигаем счётчик блока: переполнение закрывает лишь следующий блок
	this->advance();
	// Выводим успешность выработки
	return true;
}
/**
 * @brief Метод поточного зашифрования куска
 *
 * @param source открытый текст любой длины, включая пустой
 * @param result место, в которое записывается шифртекст той же длины
 *
 * @return       признак успешности зашифрования
 *
 */
bool nts::cipher::Chacha::encrypt(const view_t & source, uint8_t * result) noexcept {
	// Если шифр не готов
	if(!this->_ready)
		// Выводим отказ зашифрования
		return false;
	// Если текст объявлен непустым, но не передан
	if((source.size > 0) && ((source.data == nullptr) || (result == nullptr)))
		// Выводим отказ зашифрования
		return false;
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
		const size_t index = (CHACHA_BLOCK - this->_rest);
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
	 * Выполняем покрытие данных гаммой по блокам
	 */
	while(left > 0){
		// Если счётчик блока переполнен
		if(this->_exhausted)
			// Выводим отказ зашифрования: гаммы больше нет
			return false;
		// Выполняем выработку блока гаммы
		this->generate(this->_gamma);
		// Продвигаем счётчик блока
		this->advance();
		// Число байтов, покрываемых выработанным блоком
		const size_t taken = ((left < CHACHA_BLOCK) ? left : CHACHA_BLOCK);
		/**
		 * Выполняем наложение гаммы
		 */
		for(size_t i = 0; i < taken; i++)
			// Складываем очередной байт с гаммой
			output[i] = static_cast <uint8_t> (cursor[i] ^ this->_gamma[i]);
		// Запоминаем число неизрасходованных байтов остатка
		this->_rest = (CHACHA_BLOCK - taken);
		// Сдвигаем позицию чтения
		cursor += taken;
		// Сдвигаем позицию записи
		output += taken;
		// Уменьшаем число не покрытых байтов
		left -= taken;
	}
	// Выводим успешность зашифрования
	return true;
}
/**
 * @brief Метод поточного расшифрования куска
 *
 * @param source шифртекст любой длины, включая пустой
 * @param result место, в которое записывается открытый текст той же длины
 *
 * @return       признак успешности расшифрования
 *
 */
bool nts::cipher::Chacha::decrypt(const view_t & source, uint8_t * result) noexcept {
	// Гамма снимается тем же сложением, которым накладывается
	return this->encrypt(source, result);
}
/**
 * @brief Конструктор
 *
 */
nts::cipher::Chacha::Chacha() noexcept : _ready(false), _exhausted(false), _rest(0) {
	// Выполняем затирание состояния
	wipe(this->_state, sizeof(this->_state));
	// Выполняем затирание остатка блока гаммы
	wipe(this->_gamma, sizeof(this->_gamma));
}
/**
 * @brief Деструктор
 *
 */
nts::cipher::Chacha::~Chacha() noexcept {
	// Выполняем сброс шифра
	this->clear();
}
