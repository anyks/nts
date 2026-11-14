/**
 * @file sm4.cpp
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
 * @brief Модуль блочного шифра SM4 по GB/T 32907-2016
 *
 * @details Блок и ключ по 128 разрядов, 32 круга сети Фейстеля над словами в 32
 *          разряда; слова читаются и пишутся от старшего байта. Расшифрование идёт
 *          тем же преобразованием с раундовыми ключами в обратном порядке
 *
 * @note Постоянного времени работы шифр пока не обеспечивает: обращение к
 *       подстановке идёт по секретному значению. Устранение этого требует
 *       поразрядной реализации и вынесено отдельной работой
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <cipher/sm4.hpp>
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

	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;

	/**
	 * @brief Нелинейная подстановка байтов
	 *
	 * @details Раздел 6.2 GB/T 32907-2016
	 *
	 */
	static constexpr uint8_t SBOX[256] = {
		// Значения подстановки с 0 по 21
		0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
		0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
		0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
		0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
		0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
		0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
		0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
		0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
		0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
		0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
		0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
		0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
		0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
		0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
		0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
		0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
	};

	/**
	 * @brief Постоянные развёртывания ключа
	 *
	 * @details Раздел 7.3 GB/T 32907-2016
	 *
	 */
	static constexpr uint32_t FK[4] = {0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC};

	/**
	 * @brief Постоянные раундов развёртывания ключа
	 *
	 * @details Раздел 7.3 GB/T 32907-2016
	 *
	 */
	static constexpr uint32_t CK[32] = {
		// Первые четыре постоянные раундов развёртывания ключа
		0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
		0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
		0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
		0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
		0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
		0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
		0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
		0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
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
	 * @brief Функция нелинейного преобразования слова
	 *
	 * @details Подстановка tau по разделу 6.2 GB/T 32907-2016: каждый байт слова
	 *          заменяется по таблице
	 *
	 * @param value преобразуемое слово
	 * @return      преобразованное слово
	 *
	 */
	static __ANTS_INLINE__ uint32_t tau(const uint32_t value) noexcept {
		// Выводим слово с подставленными байтами
		return ((static_cast <uint32_t> (SBOX[(value >> 24) & 0xFF]) << 24) |
		        (static_cast <uint32_t> (SBOX[(value >> 16) & 0xFF]) << 16) |
		        (static_cast <uint32_t> (SBOX[(value >> 8) & 0xFF]) << 8) |
		        static_cast <uint32_t> (SBOX[value & 0xFF]));
	}

	/**
	 * @brief Функция линейного преобразования L шифрования
	 *
	 * @details Раздел 6.2 GB/T 32907-2016
	 *
	 * @param value преобразуемое слово
	 * @return      преобразованное слово
	 *
	 */
	static __ANTS_INLINE__ uint32_t linear(const uint32_t value) noexcept {
		// Выводим слово, преобразованное по правилу L
		return (value ^ rotl(value, 2) ^ rotl(value, 10) ^ rotl(value, 18) ^ rotl(value, 24));
	}

	/**
	 * @brief Функция линейного преобразования L' развёртывания ключа
	 *
	 * @details Раздел 7.3 GB/T 32907-2016
	 *
	 * @param value преобразуемое слово
	 * @return      преобразованное слово
	 *
	 */
	static __ANTS_INLINE__ uint32_t linearKey(const uint32_t value) noexcept {
		// Выводим слово, преобразованное по правилу L'
		return (value ^ rotl(value, 13) ^ rotl(value, 23));
	}

	/**
	 * @brief Функция совмещённого раундового преобразования T шифрования
	 *
	 * @param value преобразуемое слово
	 * @return      итог раундового преобразования
	 *
	 */
	static __ANTS_INLINE__ uint32_t round(const uint32_t value) noexcept {
		// Выводим итог совмещённого преобразования: подстановка и линейная часть
		return linear(tau(value));
	}

	/**
	 * @brief Функция совмещённого раундового преобразования T' развёртывания ключа
	 *
	 * @param value преобразуемое слово
	 * @return      итог раундового преобразования
	 *
	 */
	static __ANTS_INLINE__ uint32_t roundKey(const uint32_t value) noexcept {
		// Выводим итог совмещённого преобразования: подстановка и линейная часть
		return linearKey(tau(value));
	}
};

/**
 * @brief Метод проверки готовности шифра к работе
 *
 * @return признак того, что ключ установлен
 *
 */
bool nts::cipher::Sm4::ready() const noexcept {
	// Выводим признак того, что ключ установлен
	return this->_ready;
}
/**
 * @brief Метод установки ключа шифрования
 *
 * @param key устанавливаемый ключ шифрования
 * @return    признак успешности установки ключа
 *
 */
bool nts::cipher::Sm4::key(const view_t & key) noexcept {
	// Если ключ не передан либо его длина не та
	if((key.data == nullptr) || (key.size != SM4_KEY)){
		// Затирание раундовых ключей
		this->clear();
		// Выводим отказ установки ключа
		return false;
	}
	// Промежуточные слова развёртывания
	uint32_t k[36];
	/**
	 * Выполняем чтение четырёх слов ключа с постоянными развёртывания
	 */
	for(size_t i = 0; i < 4; i++)
		// Читаем очередное слово ключа и складываем с постоянной
		k[i] = (load(key.data + (i * 4)) ^ FK[i]);
	/**
	 * Выполняем выработку 32 раундовых ключей
	 */
	for(size_t i = 0; i < 32; i++){
		// Вырабатываем очередное промежуточное слово
		k[i + 4] = (k[i] ^ roundKey(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]));
		// Запоминаем очередной раундовый ключ
		this->_keys[i] = k[i + 4];
	}
	// Затирание промежуточных слов развёртывания
	wipe(k, sizeof(k));
	// Запоминаем, что ключ установлен
	this->_ready = true;
	// Выводим успешность установки ключа
	return true;
}
/**
 * @brief Метод затирания раундовых ключей
 *
 */
void nts::cipher::Sm4::clear() noexcept {
	// Сбрасываем признак установленного ключа
	this->_ready = false;
	// Затирание раундовых ключей
	wipe(this->_keys, sizeof(this->_keys));
}
/**
 * @brief Метод зашифрования блока
 *
 * @param source зашифровываемый блок
 * @param result место, в которое помещается зашифрованный блок
 * @return       признак успешности зашифрования
 *
 */
bool nts::cipher::Sm4::encrypt(const uint8_t * source, uint8_t * result) const noexcept {
	// Если ключ не установлен, либо блок не передан, либо место итога не передано
	if(!this->_ready || (source == nullptr) || (result == nullptr))
		// Выводим отказ зашифрования
		return false;
	// Рабочие слова преобразования
	uint32_t x[36];
	/**
	 * Выполняем чтение четырёх слов блока
	 */
	for(size_t i = 0; i < 4; i++)
		// Читаем очередное слово блока от старшего байта
		x[i] = load(source + (i * 4));
	/**
	 * Выполняем 32 круга преобразования
	 */
	for(size_t i = 0; i < 32; i++)
		// Складываем очередное рабочее слово круга
		x[i + 4] = (x[i] ^ round(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ this->_keys[i]));
	/**
	 * Выполняем запись слов итога в обратном порядке
	 */
	for(size_t i = 0; i < 4; i++)
		// Записываем очередное слово итога от старшего байта
		store(x[35 - i], result + (i * 4));
	// Затирание рабочих слов преобразования
	wipe(x, sizeof(x));
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
bool nts::cipher::Sm4::decrypt(const uint8_t * source, uint8_t * result) const noexcept {
	// Если ключ не установлен, либо блок не передан, либо место итога не передано
	if(!this->_ready || (source == nullptr) || (result == nullptr))
		// Выводим отказ расшифрования
		return false;
	// Рабочие слова преобразования
	uint32_t x[36];
	/**
	 * Выполняем чтение четырёх слов блока
	 */
	for(size_t i = 0; i < 4; i++)
		// Читаем очередное слово блока от старшего байта
		x[i] = load(source + (i * 4));
	/**
	 * Выполняем 32 круга преобразования с ключами в обратном порядке
	 */
	for(size_t i = 0; i < 32; i++)
		// Складываем очередное рабочее слово круга
		x[i + 4] = (x[i] ^ round(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ this->_keys[31 - i]));
	/**
	 * Выполняем запись слов итога в обратном порядке
	 */
	for(size_t i = 0; i < 4; i++)
		// Записываем очередное слово итога от старшего байта
		store(x[35 - i], result + (i * 4));
	// Затирание рабочих слов преобразования
	wipe(x, sizeof(x));
	// Выводим успешность расшифрования
	return true;
}
/**
 * @brief Конструктор
 *
 */
nts::cipher::Sm4::Sm4() noexcept : _ready(false) {
	// Затирание раундовых ключей
	wipe(this->_keys, sizeof(this->_keys));
}
/**
 * @brief Деструктор
 *
 */
nts::cipher::Sm4::~Sm4() noexcept {
	// Затирание раундовых ключей
	wipe(this->_keys, sizeof(this->_keys));
}
