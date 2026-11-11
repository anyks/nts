/**
 * @file mode.cpp
 * @date 2026-08-29
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
 * @brief Исходный файл модуля режимов работы блочных шифров — реализация по
 *        ГОСТ Р 34.13-2015
 *
 * @note Величины s и m стандарт задаёт в разрядах, здесь же они задаются в байтах:
 *       разрядная величина s потребовала бы сдвига всего потока на неполный байт,
 *       чего ни один применяемый на деле протокол не просит. Все контрольные
 *       примеры приложения А стандарта укладываются в целое число байтов
 *
 * @note Постоянного времени работы режимы не обеспечивают ровно в той мере, в
 *       какой его не обеспечивает базовый алгоритм блочного шифрования: сами
 *       режимы по секретным значениям не ветвятся и в память по ним не обращаются
 *
 * @note Режим счётчика шифрует счётчики по четыре разом через `block_t::batch`, где
 *       шифр её даёт (AES, «Кузнечик», «Магма»): блоки гаммы независимы, и шифр ведёт
 *       их одним телом; хвост короче четырёх идёт по блоку. Сам счётчик и наложение
 *       гаммы устройством не меняются - пачка лишь переставляет порядок шифрования
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
#include <cipher/mode.hpp>
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
	 * @brief Функция зашифрования блока шифром «Магма»
	 *
	 * @param cipher объект блочного шифра
	 * @param source зашифровываемый блок
	 * @param result место, в которое помещается зашифрованный блок
	 * @return       признак успешности зашифрования
	 *
	 */
	static bool encryptMagma(const void * cipher, const uint8_t * source, uint8_t * result) noexcept {
		// Выполняем зашифрование блока шифром «Магма»
		return reinterpret_cast <const magma_t *> (cipher)->encrypt(source, result);
	}
	/**
	 * @brief Функция расшифрования блока шифром «Магма»
	 *
	 * @param cipher объект блочного шифра
	 * @param source расшифровываемый блок
	 * @param result место, в которое помещается расшифрованный блок
	 * @return       признак успешности расшифрования
	 *
	 */
	static bool decryptMagma(const void * cipher, const uint8_t * source, uint8_t * result) noexcept {
		// Выполняем расшифрование блока шифром «Магма»
		return reinterpret_cast <const magma_t *> (cipher)->decrypt(source, result);
	}
	/**
	 * @brief Функция зашифрования блока шифром «Кузнечик»
	 *
	 * @param cipher объект блочного шифра
	 * @param source зашифровываемый блок
	 * @param result место, в которое помещается зашифрованный блок
	 * @return       признак успешности зашифрования
	 *
	 */
	static bool encryptKuznyechik(const void * cipher, const uint8_t * source, uint8_t * result) noexcept {
		// Выполняем зашифрование блока шифром «Кузнечик»
		return reinterpret_cast <const kuznyechik_t *> (cipher)->encrypt(source, result);
	}
	/**
	 * @brief Функция расшифрования блока шифром «Кузнечик»
	 *
	 * @param cipher объект блочного шифра
	 * @param source расшифровываемый блок
	 * @param result место, в которое помещается расшифрованный блок
	 * @return       признак успешности расшифрования
	 *
	 */
	static bool decryptKuznyechik(const void * cipher, const uint8_t * source, uint8_t * result) noexcept {
		// Выполняем расшифрование блока шифром «Кузнечик»
		return reinterpret_cast <const kuznyechik_t *> (cipher)->decrypt(source, result);
	}
	/**
	 * @brief Функция зашифрования блока шифром AES
	 *
	 * @param cipher объект блочного шифра
	 * @param source зашифровываемый блок
	 * @param result место, в которое помещается зашифрованный блок
	 * @return       признак успешности зашифрования
	 *
	 */
	static bool encryptAes(const void * cipher, const uint8_t * source, uint8_t * result) noexcept {
		// Выполняем зашифрование блока шифром AES
		return reinterpret_cast <const aes_t *> (cipher)->encrypt(source, result);
	}
	/**
	 * @brief Функция расшифрования блока шифром AES
	 *
	 * @param cipher объект блочного шифра
	 * @param source расшифровываемый блок
	 * @param result место, в которое помещается расшифрованный блок
	 * @return       признак успешности расшифрования
	 *
	 */
	static bool decryptAes(const void * cipher, const uint8_t * source, uint8_t * result) noexcept {
		// Выполняем расшифрование блока шифром AES
		return reinterpret_cast <const aes_t *> (cipher)->decrypt(source, result);
	}
	/**
	 * @brief Функция зашифрования нескольких блоков разом шифром «Магма»
	 *
	 * @param cipher  объект блочного шифра
	 * @param sources зашифровываемые блоки подряд
	 * @param blocks  число блоков
	 * @param results место, в которое помещаются зашифрованные блоки
	 * @return        признак успешности зашифрования
	 *
	 */
	static bool batchMagma(const void * cipher, const uint8_t * sources, const size_t blocks, uint8_t * results) noexcept {
		// Выполняем зашифрование блоков шифром «Магма»
		return reinterpret_cast <const magma_t *> (cipher)->batch(sources, blocks, results);
	}
	/**
	 * @brief Функция зашифрования нескольких блоков разом шифром «Кузнечик»
	 *
	 * @param cipher  объект блочного шифра
	 * @param sources зашифровываемые блоки подряд
	 * @param blocks  число блоков
	 * @param results место, в которое помещаются зашифрованные блоки
	 * @return        признак успешности зашифрования
	 *
	 */
	static bool batchKuznyechik(const void * cipher, const uint8_t * sources, const size_t blocks, uint8_t * results) noexcept {
		// Выполняем зашифрование блоков шифром «Кузнечик»
		return reinterpret_cast <const kuznyechik_t *> (cipher)->batch(sources, blocks, results);
	}
	/**
	 * @brief Функция зашифрования нескольких блоков разом шифром AES
	 *
	 * @param cipher  объект блочного шифра
	 * @param sources зашифровываемые блоки подряд
	 * @param blocks  число блоков
	 * @param results место, в которое помещаются зашифрованные блоки
	 * @return        признак успешности зашифрования
	 *
	 */
	static bool batchAes(const void * cipher, const uint8_t * sources, const size_t blocks, uint8_t * results) noexcept {
		// Выполняем зашифрование блоков шифром AES
		return reinterpret_cast <const aes_t *> (cipher)->batch(sources, blocks, results);
	}
	/**
	 * @brief Функция выработки гаммы счётчика шифром AES
	 *
	 * @param cipher  объект блочного шифра
	 * @param counter начальный блок счётчика
	 * @param blocks  число блоков гаммы
	 * @param source  исходные данные, на которые гамма накладывается: пусто, если нужна сама гамма
	 * @param result  место, в которое помещается гамма либо исходные данные под ней
	 * @return        признак успешности выработки
	 *
	 */
	static bool streamAes(const void * cipher, const uint8_t * counter, const size_t blocks, const uint8_t * source, uint8_t * result) noexcept {
		// Выполняем выработку гаммы шифром AES
		return reinterpret_cast <const aes_t *> (cipher)->stream(counter, blocks, source, result);
	}
	/**
	 * @brief Функция зашифрования сообщения цепочкой сцепления шифром AES
	 *
	 * @param cipher объект блочного шифра
	 * @param record регистр сдвига
	 * @param source зашифровываемое сообщение
	 * @param size   длина сообщения в байтах
	 * @param result место, в которое помещается шифртекст
	 * @return       признак успешности зашифрования
	 *
	 */
	static bool chainAes(const void * cipher, uint8_t * record, const uint8_t * source, const size_t size, uint8_t * result) noexcept {
		// Выполняем зашифрование цепочкой сцепления шифром AES
		return reinterpret_cast <const aes_t *> (cipher)->chain(record, source, size, result);
	}
	/**
	 * @brief Функция зашифрования блока шифром SM4
	 *
	 * @param cipher объект блочного шифра
	 * @param source зашифровываемый блок
	 * @param result место, в которое помещается зашифрованный блок
	 * @return       признак успешности зашифрования
	 *
	 */
	static bool encryptSm4(const void * cipher, const uint8_t * source, uint8_t * result) noexcept {
		// Выполняем зашифрование блока шифром SM4
		return reinterpret_cast <const sm4_t *> (cipher)->encrypt(source, result);
	}
	/**
	 * @brief Функция расшифрования блока шифром SM4
	 *
	 * @param cipher объект блочного шифра
	 * @param source расшифровываемый блок
	 * @param result место, в которое помещается расшифрованный блок
	 * @return       признак успешности расшифрования
	 *
	 */
	static bool decryptSm4(const void * cipher, const uint8_t * source, uint8_t * result) noexcept {
		// Выполняем расшифрование блока шифром SM4
		return reinterpret_cast <const sm4_t *> (cipher)->decrypt(source, result);
	}
	/**
	 * @brief Функция зашифрования блока шифром DES и 3DES
	 *
	 * @param cipher объект блочного шифра
	 * @param source зашифровываемый блок
	 * @param result место, в которое помещается зашифрованный блок
	 * @return       признак успешности зашифрования
	 *
	 */
	static bool encryptDes(const void * cipher, const uint8_t * source, uint8_t * result) noexcept {
		// Выполняем зашифрование блока шифром DES и 3DES
		return reinterpret_cast <const des_t *> (cipher)->encrypt(source, result);
	}
	/**
	 * @brief Функция расшифрования блока шифром DES и 3DES
	 *
	 * @param cipher объект блочного шифра
	 * @param source расшифровываемый блок
	 * @param result место, в которое помещается расшифрованный блок
	 * @return       признак успешности расшифрования
	 *
	 */
	static bool decryptDes(const void * cipher, const uint8_t * source, uint8_t * result) noexcept {
		// Выполняем расшифрование блока шифром DES и 3DES
		return reinterpret_cast <const des_t *> (cipher)->decrypt(source, result);
	}
	/**
	 * @brief Функция разбора блока Blowfish на две половины словами от старшего байта
	 *
	 * @param source разбираемый блок в восемь байтов
	 * @param left   место левой половины блока
	 * @param right  место правой половины блока
	 *
	 */
	static void fetchBlowfish(const uint8_t * source, uint32_t * left, uint32_t * right) noexcept {
		/**
		 * Выполняем разбор обеих половин блока от старшего байта к младшему
		 */
		for(size_t i = 0; i < 4; i++){
			// Сдвигаем левую половину на байт и дополняем очередным байтом блока
			*left = static_cast <uint32_t> ((*left << 8) | source[i]);
			// Сдвигаем правую половину на байт и дополняем очередным байтом блока
			*right = static_cast <uint32_t> ((*right << 8) | source[i + 4]);
		}
	}
	/**
	 * @brief Функция записи двух половин блока Blowfish байтами от старшего
	 *
	 * @param left   левая половина блока
	 * @param right  правая половина блока
	 * @param result место, в которое записывается блок в восемь байтов
	 *
	 */
	static void storeBlowfish(const uint32_t left, const uint32_t right, uint8_t * result) noexcept {
		/**
		 * Выполняем запись обеих половин блока от старшего байта к младшему
		 */
		for(size_t i = 0; i < 4; i++){
			// Записываем очередной байт левой половины
			result[i] = static_cast <uint8_t> (left >> (24 - (i * 8)));
			// Записываем очередной байт правой половины
			result[i + 4] = static_cast <uint8_t> (right >> (24 - (i * 8)));
		}
	}
	/**
	 * @brief Функция зашифрования блока шифром Blowfish
	 *
	 * @param cipher объект блочного шифра
	 * @param source зашифровываемый блок
	 * @param result место, в которое помещается зашифрованный блок
	 * @return       признак успешности зашифрования
	 *
	 */
	static bool encryptBlowfish(const void * cipher, const uint8_t * source, uint8_t * result) noexcept {
		// Левая половина зашифровываемого блока
		uint32_t left = 0;
		// Правая половина зашифровываемого блока
		uint32_t right = 0;
		// Выполняем разбор зашифровываемого блока на две половины
		fetchBlowfish(source, &left, &right);
		// Выполняем зашифрование блока шифром Blowfish
		encipher(reinterpret_cast <const blowfish_t *> (cipher), &left, &right);
		// Выполняем запись зашифрованного блока байтами
		storeBlowfish(left, right, result);
		// Выводим успешность зашифрования
		return true;
	}
	/**
	 * @brief Функция расшифрования блока шифром Blowfish
	 *
	 * @param cipher объект блочного шифра
	 * @param source расшифровываемый блок
	 * @param result место, в которое помещается расшифрованный блок
	 * @return       признак успешности расшифрования
	 *
	 */
	static bool decryptBlowfish(const void * cipher, const uint8_t * source, uint8_t * result) noexcept {
		// Левая половина расшифровываемого блока
		uint32_t left = 0;
		// Правая половина расшифровываемого блока
		uint32_t right = 0;
		// Выполняем разбор расшифровываемого блока на две половины
		fetchBlowfish(source, &left, &right);
		// Выполняем расшифрование блока шифром Blowfish
		decipher(reinterpret_cast <const blowfish_t *> (cipher), &left, &right);
		// Выполняем запись расшифрованного блока байтами
		storeBlowfish(left, right, result);
		// Выводим успешность расшифрования
		return true;
	}
	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;
	/**
	 * @brief Функция проверки пригодности базового алгоритма блочного шифрования
	 *
	 * @param block проверяемый базовый алгоритм блочного шифрования
	 * @return      признак пригодности базового алгоритма блочного шифрования
	 *
	 */
	static bool suitable(const block_t & block) noexcept {
		// Выводим признак пригодности базового алгоритма блочного шифрования
		return (
			(block.cipher != nullptr) && (block.encrypt != nullptr) &&
			(block.decrypt != nullptr) && (block.size > 0) && (block.size <= MODE_BLOCK)
		);
	}
	/**
	 * @brief Функция сдвига заполнения регистра
	 *
	 * @details Сдвиг ведётся в сторону разрядов с большими номерами, в разряды с
	 *          меньшими номерами записывается переданное значение
	 *
	 * @param data   заполнение регистра сдвига
	 * @param length длина регистра сдвига
	 * @param value  записываемое в регистр значение
	 * @param size   размер записываемого в регистр значения
	 *
	 */
	static void shift(uint8_t * data, const size_t length, const uint8_t * value, const size_t size) noexcept {
		// Если сдвиг не занимает регистр целиком
		if(size < length)
			// Выполняем сдвиг оставшегося заполнения регистра
			::memmove(data, data + size, length - size);
		// Записываем переданное значение в разряды регистра с меньшими номерами
		::memcpy(data + (length - size), value, size);
	}
	/**
	 * @brief Функция сложения блоков по модулю два
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
};

/**
 * @brief Конструктор
 * @param cipher объект блочного шифра DES и 3DES
 *
 */
nts::cipher::Block::Block() noexcept :
	size(0), cipher(nullptr), encrypt(nullptr), decrypt(nullptr), stream(nullptr), batch(nullptr), chain(nullptr), schedule(nullptr), rounds(0) {}
/**
 * @brief Конструктор
 *
 * @param cipher объект блочного шифра «Магма»
 *
 */
nts::cipher::Block::Block(const magma_t & cipher) noexcept :
	size(MAGMA_BLOCK), cipher(&cipher), encrypt(&encryptMagma), decrypt(&decryptMagma), stream(nullptr), batch(&batchMagma), chain(nullptr), schedule(nullptr), rounds(0) {}
/**
 * @brief Конструктор
 *
 * @param cipher объект блочного шифра «Кузнечик»
 *
 */
nts::cipher::Block::Block(const kuznyechik_t & cipher) noexcept :
	size(KUZNYECHIK_BLOCK), cipher(&cipher), encrypt(&encryptKuznyechik), decrypt(&decryptKuznyechik), stream(nullptr), batch(&batchKuznyechik), chain(nullptr), schedule(nullptr), rounds(0) {}
/**
 * @brief Конструктор
 *
 * @param cipher объект блочного шифра AES
 *
 */
nts::cipher::Block::Block(const aes_t & cipher) noexcept :
	size(AES_BLOCK), cipher(&cipher), encrypt(&encryptAes), decrypt(&decryptAes), stream(&streamAes), batch(&batchAes), chain(&chainAes), schedule(cipher.schedule()), rounds(cipher.rounds()) {}
/**
 * @brief Конструктор
 *
 * @param cipher объект блочного шифра SM4
 *
 */
nts::cipher::Block::Block(const sm4_t & cipher) noexcept :
	size(SM4_BLOCK), cipher(&cipher), encrypt(&encryptSm4), decrypt(&decryptSm4), stream(nullptr), batch(nullptr), chain(nullptr), schedule(nullptr), rounds(0) {}
/**
 * @brief Конструктор
 *
 * @param cipher объект блочного шифра DES и 3DES
 *
 */
nts::cipher::Block::Block(const des_t & cipher) noexcept :
	size(DES_BLOCK), cipher(&cipher), encrypt(&encryptDes), decrypt(&decryptDes), stream(nullptr), batch(nullptr), chain(nullptr), schedule(nullptr), rounds(0) {}
/**
 * @brief Конструктор
 *
 * @param cipher объект блочного шифра Blowfish
 *
 */
nts::cipher::Block::Block(const blowfish_t & cipher) noexcept :
	size(BLOWFISH_BLOCK), cipher(&cipher), encrypt(&encryptBlowfish), decrypt(&decryptBlowfish), stream(nullptr), batch(nullptr), chain(nullptr), schedule(nullptr), rounds(0) {}
/**
 * @brief Метод проверки готовности режима к работе
 *
 * @return признак готовности режима к работе
 *
 */
bool nts::cipher::Codebook::ready() const noexcept {
	// Выводим признак готовности режима к работе
	return this->_ready;
}
/**
 * @brief Метод запуска режима работы
 *
 * @param block базовый алгоритм блочного шифрования
 * @return      признак успешности запуска режима работы
 *
 */
bool nts::cipher::Codebook::start(const block_t & block) noexcept {
	// Выполняем сброс прежнего состояния режима работы
	this->clear();
	// Если базовый алгоритм блочного шифрования непригоден
	if(!suitable(block))
		// Выводим отказ запуска режима работы
		return false;
	// Запоминаем базовый алгоритм блочного шифрования
	this->_block = block;
	// Устанавливаем признак готовности режима к работе
	this->_ready = true;
	// Выводим успешность запуска режима работы
	return true;
}
/**
 * @brief Метод сброса состояния режима работы
 *
 */
void nts::cipher::Codebook::clear() noexcept {
	// Сбрасываем базовый алгоритм блочного шифрования
	this->_block = block_t();
	// Снимаем признак готовности режима к работе
	this->_ready = false;
}
/**
 * @brief Метод зашифрования сообщения
 *
 * @param source зашифровываемое сообщение
 * @param result место, в которое помещается шифртекст
 * @return       признак успешности зашифрования
 *
 */
bool nts::cipher::Codebook::encrypt(const view_t & source, uint8_t * result) noexcept {
	// Если режим не готов к работе либо места не переданы
	if(!this->_ready || ((source.size > 0) && ((source.data == nullptr) || (result == nullptr))))
		// Выводим отказ зашифрования
		return false;
	// Если длина сообщения не кратна длине блока шифра
	if((source.size % this->_block.size) != 0)
		// Выводим отказ зашифрования
		return false;
	/**
	 * Выполняем перебор блоков зашифровываемого сообщения
	 */
	for(size_t offset = 0; offset < source.size; offset += this->_block.size){
		// Выполняем зашифрование очередного блока сообщения
		if(!this->_block.encrypt(this->_block.cipher, source.data + offset, result + offset))
			// Выводим отказ зашифрования
			return false;
	}
	// Выводим успешность зашифрования
	return true;
}
/**
 * @brief Метод расшифрования сообщения
 *
 * @param source расшифровываемый шифртекст
 * @param result место, в которое помещается открытый текст
 * @return       признак успешности расшифрования
 *
 */
bool nts::cipher::Codebook::decrypt(const view_t & source, uint8_t * result) noexcept {
	// Если режим не готов к работе либо места не переданы
	if(!this->_ready || ((source.size > 0) && ((source.data == nullptr) || (result == nullptr))))
		// Выводим отказ расшифрования
		return false;
	// Если длина шифртекста не кратна длине блока шифра
	if((source.size % this->_block.size) != 0)
		// Выводим отказ расшифрования
		return false;
	/**
	 * Выполняем перебор блоков расшифровываемого шифртекста
	 */
	for(size_t offset = 0; offset < source.size; offset += this->_block.size){
		// Выполняем расшифрование очередного блока шифртекста
		if(!this->_block.decrypt(this->_block.cipher, source.data + offset, result + offset))
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
nts::cipher::Codebook::Codebook() noexcept : _ready(false) {}
/**
 * @brief Деструктор
 *
 */
nts::cipher::Codebook::~Codebook() noexcept {
	// Выполняем сброс состояния режима работы
	this->clear();
}
/**
 * @brief Метод проверки готовности режима к работе
 *
 * @return признак готовности режима к работе
 *
 */
bool nts::cipher::Counter::ready() const noexcept {
	// Выводим признак готовности режима к работе
	return this->_ready;
}
/**
 * @brief Метод запуска режима работы
 *
 * @param block базовый алгоритм блочного шифрования
 * @param iv    синхропосылка длиной в половину блока шифра
 * @param size  размер блока гаммы в байтах, ноль означает длину блока шифра
 * @return      признак успешности запуска режима работы
 *
 */
bool nts::cipher::Counter::start(const block_t & block, const view_t & iv, const size_t size) noexcept {
	// Выполняем сброс прежнего состояния режима работы
	this->clear();
	// Если базовый алгоритм блочного шифрования непригоден
	if(!suitable(block))
		// Выводим отказ запуска режима работы
		return false;
	// Определяем требуемый размер блока гаммы
	const size_t gamma = (size > 0 ? size : block.size);
	// Если размер блока гаммы превышает длину блока шифра
	if(gamma > block.size)
		// Выводим отказ запуска режима работы
		return false;
	// Если синхропосылка не занимает половину блока шифра
	if((iv.data == nullptr) || (iv.size != (block.size / 2)))
		// Выводим отказ запуска режима работы
		return false;
	// Запоминаем базовый алгоритм блочного шифрования
	this->_block = block;
	// Запоминаем размер блока гаммы
	this->_size = gamma;
	/**
	 * Начальным значением счётчика служит синхропосылка, дополненная нулями до
	 * длины блока шифра: это и есть процедура инициализации In раздела 5.2
	 */
	::memcpy(this->_counter, iv.data, iv.size);
	// Устанавливаем признак готовности режима к работе
	this->_ready = true;
	// Выводим успешность запуска режима работы
	return true;
}
/**
 * @brief Метод сброса состояния режима работы
 *
 */
void nts::cipher::Counter::clear() noexcept {
	// Выполняем затирание текущего блока гаммы шифра
	wipe(this->_gamma, sizeof(this->_gamma));
	// Выполняем затирание текущего значения счётчика
	wipe(this->_counter, sizeof(this->_counter));
	// Сбрасываем базовый алгоритм блочного шифрования
	this->_block = block_t();
	// Сбрасываем количество неизрасходованных байтов блока гаммы
	this->_rest = 0;
	// Сбрасываем размер блока гаммы
	this->_size = 0;
	// Снимаем признак готовности режима к работе
	this->_ready = false;
}
/**
 * @brief Метод зашифрования сообщения
 *
 * @param source зашифровываемое сообщение
 * @param result место, в которое помещается шифртекст
 * @return       признак успешности зашифрования
 *
 */
bool nts::cipher::Counter::encrypt(const view_t & source, uint8_t * result) noexcept {
	// Если режим не готов к работе либо места не переданы
	if(!this->_ready || ((source.size > 0) && ((source.data == nullptr) || (result == nullptr))))
		// Выводим отказ зашифрования
		return false;
	// Количество уже обработанных байтов сообщения
	size_t offset = 0;
	/**
	 * Если гамма израсходована, блок гаммы равен блоку шифра в шестнадцать байтов, а шифр
	 * умеет вырабатывать гамму по многу блоков разом (AES), целые блоки идут ядром шифра
	 * одним вызовом, и гамму на них накладывает само ядро: буфер гаммы по сто двадцать
	 * восемь блоков с наложением по словам стоил на Xeon E5-2630 v4 четверть времени
	 * ядра (круг 38, 23.09.2026). Ядро продвигает лишь младшие четыре байта счётчика
	 * по кругу, оттого вызов берёт блоки, лишь пока они не переполняются, а перенос в
	 * старшие байты делается здесь как у числа от старшего байта; хвост короче блока
	 * идёт прежним путём
	 */
	if((this->_rest == 0) && (this->_block.stream != nullptr) && (this->_size == 16) && (this->_block.size == 16)){
		// Основание счётчика для ядра: ядро начинает с приращения, оттого младшие четыре байта на единицу меньше
		uint8_t base[16];
		/**
		 * Выполняем покрытие целых блоков вызовами ядра
		 */
		while((source.size - offset) >= 16){
			// Младшие 32 разряда счётчика от старшего байта
			const uint32_t tail = ((static_cast <uint32_t> (this->_counter[12]) << 24) | (static_cast <uint32_t> (this->_counter[13]) << 16) | (static_cast <uint32_t> (this->_counter[14]) << 8) | static_cast <uint32_t> (this->_counter[15]));
			// Число блоков до переполнения младших четырёх байтов
			const uint64_t room = ((static_cast <uint64_t> (UINT32_MAX) - tail) + 1);
			// Число блоков вызова: целые блоки сообщения
			size_t count = ((source.size - offset) / 16);
			// Если вызов дошёл бы до переполнения младших байтов
			if(static_cast <uint64_t> (count) > room)
				// Ограничиваем вызов блоками до переполнения
				count = static_cast <size_t> (room);
			// Младшие четыре байта основания: на единицу меньше по кругу
			const uint32_t previous = (tail - 1);
			// Копируем старшие байты счётчика в основание
			::memcpy(base, this->_counter, 12);
			// Записываем младшие четыре байта основания от старшего
			base[12] = static_cast <uint8_t> (previous >> 24);
			// Записываем второй байт основания от старшего
			base[13] = static_cast <uint8_t> (previous >> 16);
			// Записываем третий байт основания от старшего
			base[14] = static_cast <uint8_t> (previous >> 8);
			// Записываем младший байт основания
			base[15] = static_cast <uint8_t> (previous);
			// Если наложить гамму ядром не удалось
			if(!this->_block.stream(this->_block.cipher, base, count, source.data + offset, result + offset)){
				// Выполняем затирание основания
				wipe(base, sizeof(base));
				// Выводим отказ зашифрования
				return false;
			}
			// Перенос при продвижении счётчика на выработанные блоки
			uint64_t carry = static_cast <uint64_t> (count);
			/**
			 * Выполняем продвижение счётчика как числа от старшего байта с переносом через все байты
			 */
			for(size_t i = 16; (i > 0) && (carry > 0); i--){
				// Складываем очередной байт с переносом
				carry += this->_counter[i - 1];
				// Записываем младший байт суммы
				this->_counter[i - 1] = static_cast <uint8_t> (carry);
				// Оставляем перенос в следующий байт
				carry >>= 8;
			}
			// Увеличиваем количество обработанных байтов сообщения
			offset += (count * 16);
		}
		// Выполняем затирание основания
		wipe(base, sizeof(base));
	}
	/**
	 * Пока гамма израсходована, а впереди не меньше четырёх её блоков, счётчики
	 * шифруются по четыре разом: блоки независимы, и шифр ведёт их одним телом
	 */
	while((this->_rest == 0) && (this->_block.batch != nullptr) && ((source.size - offset) >= (4 * this->_size))){
		// Четыре очередных значения счётчика
		uint8_t counters[4 * MODE_BLOCK];
		// Четыре выхода базового алгоритма блочного шифрования
		uint8_t buffer[4 * MODE_BLOCK];
		/**
		 * Выполняем заполнение четырёх счётчиков
		 */
		for(size_t k = 0; k < 4; k++){
			// Записываем текущее значение счётчика
			::memcpy(counters + (k * this->_block.size), this->_counter, this->_block.size);
			/**
			 * Выполняем увеличение счётчика на единицу от младшего байта
			 */
			for(size_t i = this->_block.size; i > 0; i--){
				// Если очередной байт счётчика переполнения не даёт
				if(++this->_counter[i - 1] != 0)
					// Выходим из увеличения счётчика
					break;
			}
		}
		// Если зашифровать счётчики не удалось
		if(!this->_block.batch(this->_block.cipher, counters, 4, buffer)){
			// Выполняем затирание счётчиков и выходов шифра
			wipe(counters, sizeof(counters));
			wipe(buffer, sizeof(buffer));
			// Выводим отказ зашифрования
			return false;
		}
		/**
		 * Выполняем наложение четырёх блоков гаммы: от всякого выхода шифра берётся
		 * усечение до размера блока гаммы
		 */
		for(size_t k = 0; k < 4; k++){
			// Выход шифра очередного счётчика
			const uint8_t * gamma = (buffer + (k * this->_block.size));
			/**
			 * Выполняем наложение блока гаммы
			 */
			for(size_t i = 0; i < this->_size; i++)
				// Складываем очередные байты по модулю два
				result[offset + i] = static_cast <uint8_t> (source.data[offset + i] ^ gamma[i]);
			// Сдвигаем количество обработанных байтов
			offset += this->_size;
		}
		// Выполняем затирание счётчиков и выходов шифра
		wipe(counters, sizeof(counters));
		wipe(buffer, sizeof(buffer));
	}
	/**
	 * Выполняем обработку сообщения до его исчерпания
	 */
	while(offset < source.size){
		// Если блок гаммы шифра израсходован
		if(this->_rest == 0){
			// Блок, в который помещается выход базового алгоритма блочного шифрования
			uint8_t buffer[MODE_BLOCK];
			// Выполняем зашифрование текущего значения счётчика
			if(!this->_block.encrypt(this->_block.cipher, this->_counter, buffer))
				// Выводим отказ зашифрования
				return false;
			// Выполняем усечение выхода шифра до размера блока гаммы
			::memcpy(this->_gamma, buffer, this->_size);
			// Выполняем затирание выхода базового алгоритма блочного шифрования
			wipe(buffer, sizeof(buffer));
			// Восстанавливаем количество неизрасходованных байтов блока гаммы
			this->_rest = this->_size;
			/**
			 * Выполняем увеличение счётчика на единицу как числа, записанного от
			 * старшего байта к младшему
			 */
			for(size_t i = this->_block.size; i > 0; i--){
				// Если очередной байт счётчика переполнения не даёт
				if(++this->_counter[i - 1] != 0)
					// Выходим из увеличения счётчика
					break;
			}
		}
		// Определяем количество байтов, обрабатываемых текущим блоком гаммы
		const size_t count = ((source.size - offset) < this->_rest ? (source.size - offset) : this->_rest);
		// Выполняем сложение куска сообщения с гаммой шифра
		add(source.data + offset, this->_gamma + (this->_size - this->_rest), result + offset, count);
		// Уменьшаем количество неизрасходованных байтов блока гаммы
		this->_rest -= count;
		// Увеличиваем количество обработанных байтов сообщения
		offset += count;
	}
	// Выводим успешность зашифрования
	return true;
}
/**
 * @brief Метод расшифрования сообщения
 *
 * @param source расшифровываемый шифртекст
 * @param result место, в которое помещается открытый текст
 * @return       признак успешности расшифрования
 *
 */
bool nts::cipher::Counter::decrypt(const view_t & source, uint8_t * result) noexcept {
	// Выводим итог зашифрования: расшифрование от зашифрования в режиме гаммирования не отличается
	return this->encrypt(source, result);
}
/**
 * @brief Конструктор
 *
 */
nts::cipher::Counter::Counter() noexcept : _ready(false), _size(0), _rest(0) {
	// Выполняем затирание текущего значения счётчика
	wipe(this->_counter, sizeof(this->_counter));
	// Выполняем затирание текущего блока гаммы шифра
	wipe(this->_gamma, sizeof(this->_gamma));
}
/**
 * @brief Деструктор
 *
 */
nts::cipher::Counter::~Counter() noexcept {
	// Выполняем сброс состояния режима работы
	this->clear();
}
/**
 * @brief Метод проверки готовности режима к работе
 *
 * @return признак готовности режима к работе
 *
 */
bool nts::cipher::Output::ready() const noexcept {
	// Выводим признак готовности режима к работе
	return this->_ready;
}
/**
 * @brief Метод запуска режима работы
 *
 * @param block базовый алгоритм блочного шифрования
 * @param iv    синхропосылка длиной в целое число блоков шифра
 * @param size  размер блока гаммы в байтах, ноль означает длину блока шифра
 * @return      признак успешности запуска режима работы
 *
 */
bool nts::cipher::Output::start(const block_t & block, const view_t & iv, const size_t size) noexcept {
	// Выполняем сброс прежнего состояния режима работы
	this->clear();
	// Если базовый алгоритм блочного шифрования непригоден
	if(!suitable(block))
		// Выводим отказ запуска режима работы
		return false;
	// Определяем требуемый размер блока гаммы
	const size_t gamma = (size > 0 ? size : block.size);
	// Если размер блока гаммы превышает длину блока шифра
	if(gamma > block.size)
		// Выводим отказ запуска режима работы
		return false;
	// Если синхропосылка не занимает целого числа блоков шифра
	if((iv.data == nullptr) || (iv.size < block.size) || ((iv.size % block.size) != 0) || (iv.size > MODE_REGISTER))
		// Выводим отказ запуска режима работы
		return false;
	// Запоминаем базовый алгоритм блочного шифрования
	this->_block = block;
	// Запоминаем размер блока гаммы
	this->_size = gamma;
	// Запоминаем длину регистра сдвига
	this->_length = iv.size;
	// Начальным заполнением регистра сдвига служит синхропосылка
	::memcpy(this->_register, iv.data, iv.size);
	// Устанавливаем признак готовности режима к работе
	this->_ready = true;
	// Выводим успешность запуска режима работы
	return true;
}
/**
 * @brief Метод сброса состояния режима работы
 *
 */
void nts::cipher::Output::clear() noexcept {
	// Выполняем затирание текущего блока гаммы шифра
	wipe(this->_gamma, sizeof(this->_gamma));
	// Выполняем затирание заполнения регистра сдвига
	wipe(this->_register, sizeof(this->_register));
	// Сбрасываем базовый алгоритм блочного шифрования
	this->_block = block_t();
	// Сбрасываем длину регистра сдвига
	this->_length = 0;
	// Сбрасываем количество неизрасходованных байтов блока гаммы
	this->_rest = 0;
	// Сбрасываем размер блока гаммы
	this->_size = 0;
	// Снимаем признак готовности режима к работе
	this->_ready = false;
}
/**
 * @brief Метод зашифрования сообщения
 *
 * @param source зашифровываемое сообщение
 * @param result место, в которое помещается шифртекст
 * @return       признак успешности зашифрования
 *
 */
bool nts::cipher::Output::encrypt(const view_t & source, uint8_t * result) noexcept {
	// Если режим не готов к работе либо места не переданы
	if(!this->_ready || ((source.size > 0) && ((source.data == nullptr) || (result == nullptr))))
		// Выводим отказ зашифрования
		return false;
	// Количество уже обработанных байтов сообщения
	size_t offset = 0;
	/**
	 * Выполняем обработку сообщения до его исчерпания
	 */
	while(offset < source.size){
		// Если блок гаммы шифра израсходован
		if(this->_rest == 0){
			// Блок, в который помещается выход базового алгоритма блочного шифрования
			uint8_t buffer[MODE_BLOCK];
			// Выполняем зашифрование старших разрядов регистра сдвига
			if(!this->_block.encrypt(this->_block.cipher, this->_register, buffer))
				// Выводим отказ зашифрования
				return false;
			// Выполняем усечение выхода шифра до размера блока гаммы
			::memcpy(this->_gamma, buffer, this->_size);
			// Записываем выход шифра в разряды регистра с меньшими номерами
			shift(this->_register, this->_length, buffer, this->_block.size);
			// Выполняем затирание выхода базового алгоритма блочного шифрования
			wipe(buffer, sizeof(buffer));
			// Восстанавливаем количество неизрасходованных байтов блока гаммы
			this->_rest = this->_size;
		}
		// Определяем количество байтов, обрабатываемых текущим блоком гаммы
		const size_t count = ((source.size - offset) < this->_rest ? (source.size - offset) : this->_rest);
		// Выполняем сложение куска сообщения с гаммой шифра
		add(source.data + offset, this->_gamma + (this->_size - this->_rest), result + offset, count);
		// Уменьшаем количество неизрасходованных байтов блока гаммы
		this->_rest -= count;
		// Увеличиваем количество обработанных байтов сообщения
		offset += count;
	}
	// Выводим успешность зашифрования
	return true;
}
/**
 * @brief Метод расшифрования сообщения
 *
 * @param source расшифровываемый шифртекст
 * @param result место, в которое помещается открытый текст
 * @return       признак успешности расшифрования
 *
 */
bool nts::cipher::Output::decrypt(const view_t & source, uint8_t * result) noexcept {
	// Выводим итог зашифрования: гамма от содержимого сообщения не зависит
	return this->encrypt(source, result);
}
/**
 * @brief Конструктор
 *
 */
nts::cipher::Output::Output() noexcept : _ready(false), _size(0), _rest(0), _length(0) {
	// Выполняем затирание заполнения регистра сдвига
	wipe(this->_register, sizeof(this->_register));
	// Выполняем затирание текущего блока гаммы шифра
	wipe(this->_gamma, sizeof(this->_gamma));
}
/**
 * @brief Деструктор
 *
 */
nts::cipher::Output::~Output() noexcept {
	// Выполняем сброс состояния режима работы
	this->clear();
}
/**
 * @brief Метод проверки готовности режима к работе
 *
 * @return признак готовности режима к работе
 *
 */
bool nts::cipher::Chaining::ready() const noexcept {
	// Выводим признак готовности режима к работе
	return this->_ready;
}
/**
 * @brief Метод запуска режима работы
 *
 * @param block базовый алгоритм блочного шифрования
 * @param iv    синхропосылка длиной в целое число блоков шифра
 * @return      признак успешности запуска режима работы
 *
 */
bool nts::cipher::Chaining::start(const block_t & block, const view_t & iv) noexcept {
	// Выполняем сброс прежнего состояния режима работы
	this->clear();
	// Если базовый алгоритм блочного шифрования непригоден
	if(!suitable(block))
		// Выводим отказ запуска режима работы
		return false;
	// Если синхропосылка не занимает целого числа блоков шифра
	if((iv.data == nullptr) || (iv.size < block.size) || ((iv.size % block.size) != 0) || (iv.size > MODE_REGISTER))
		// Выводим отказ запуска режима работы
		return false;
	// Запоминаем базовый алгоритм блочного шифрования
	this->_block = block;
	// Запоминаем длину регистра сдвига
	this->_length = iv.size;
	// Начальным заполнением регистра сдвига служит синхропосылка
	::memcpy(this->_register, iv.data, iv.size);
	// Устанавливаем признак готовности режима к работе
	this->_ready = true;
	// Выводим успешность запуска режима работы
	return true;
}
/**
 * @brief Метод сброса состояния режима работы
 *
 */
void nts::cipher::Chaining::clear() noexcept {
	// Выполняем затирание заполнения регистра сдвига
	wipe(this->_register, sizeof(this->_register));
	// Сбрасываем базовый алгоритм блочного шифрования
	this->_block = block_t();
	// Сбрасываем длину регистра сдвига
	this->_length = 0;
	// Снимаем признак готовности режима к работе
	this->_ready = false;
}
/**
 * @brief Метод зашифрования сообщения
 *
 * @param source зашифровываемое сообщение
 * @param result место, в которое помещается шифртекст
 * @return       признак успешности зашифрования
 *
 */
bool nts::cipher::Chaining::encrypt(const view_t & source, uint8_t * result) noexcept {
	// Если режим не готов к работе либо места не переданы
	if(!this->_ready || ((source.size > 0) && ((source.data == nullptr) || (result == nullptr))))
		// Выводим отказ зашифрования
		return false;
	// Если длина сообщения не кратна длине блока шифра
	if((source.size % this->_block.size) != 0)
		// Выводим отказ зашифрования
		return false;
	// Если базовый шифр несёт цепочку сцепления целиком и она прошла
	if((this->_block.chain != nullptr) && this->_block.chain(this->_block.cipher, this->_register, source.data, source.size, result))
		// Выводим успешность зашифрования
		return true;
	/**
	 * Выполняем перебор блоков зашифровываемого сообщения
	 */
	for(size_t offset = 0; offset < source.size; offset += this->_block.size){
		// Блок, подаваемый базовому алгоритму блочного шифрования
		uint8_t buffer[MODE_BLOCK];
		// Складываем блок сообщения со старшими разрядами регистра сдвига
		add(source.data + offset, this->_register, buffer, this->_block.size);
		// Выполняем зашифрование полученного блока
		if(!this->_block.encrypt(this->_block.cipher, buffer, buffer)){
			// Выполняем затирание блока, подаваемого базовому алгоритму
			wipe(buffer, sizeof(buffer));
			// Выводим отказ зашифрования
			return false;
		}
		// Записываем блок шифртекста в разряды регистра с меньшими номерами
		shift(this->_register, this->_length, buffer, this->_block.size);
		// Записываем блок шифртекста в место итога
		::memcpy(result + offset, buffer, this->_block.size);
		// Выполняем затирание блока, подаваемого базовому алгоритму
		wipe(buffer, sizeof(buffer));
	}
	// Выводим успешность зашифрования
	return true;
}
/**
 * @brief Метод расшифрования сообщения
 *
 * @param source расшифровываемый шифртекст
 * @param result место, в которое помещается открытый текст
 * @return       признак успешности расшифрования
 *
 */
bool nts::cipher::Chaining::decrypt(const view_t & source, uint8_t * result) noexcept {
	// Если режим не готов к работе либо места не переданы
	if(!this->_ready || ((source.size > 0) && ((source.data == nullptr) || (result == nullptr))))
		// Выводим отказ расшифрования
		return false;
	// Если длина шифртекста не кратна длине блока шифра
	if((source.size % this->_block.size) != 0)
		// Выводим отказ расшифрования
		return false;
	/**
	 * Выполняем перебор блоков расшифровываемого шифртекста
	 */
	for(size_t offset = 0; offset < source.size; offset += this->_block.size){
		// Блок, в который помещается выход базового алгоритма блочного шифрования
		uint8_t buffer[MODE_BLOCK];
		// Блок шифртекста, записываемый в регистр сдвига
		uint8_t item[MODE_BLOCK];
		/**
		 * Запоминаем блок шифртекста: место итога вправе совпадать с местом
		 * исходного сообщения, оттого к моменту сдвига регистра его уже не прочесть
		 */
		::memcpy(item, source.data + offset, this->_block.size);
		// Выполняем расшифрование очередного блока шифртекста
		if(!this->_block.decrypt(this->_block.cipher, item, buffer)){
			// Выполняем затирание блока шифртекста
			wipe(item, sizeof(item));
			// Выполняем затирание выхода базового алгоритма блочного шифрования
			wipe(buffer, sizeof(buffer));
			// Выводим отказ расшифрования
			return false;
		}
		// Складываем выход шифра со старшими разрядами регистра сдвига
		add(buffer, this->_register, result + offset, this->_block.size);
		// Записываем блок шифртекста в разряды регистра с меньшими номерами
		shift(this->_register, this->_length, item, this->_block.size);
		// Выполняем затирание блока шифртекста
		wipe(item, sizeof(item));
		// Выполняем затирание выхода базового алгоритма блочного шифрования
		wipe(buffer, sizeof(buffer));
	}
	// Выводим успешность расшифрования
	return true;
}
/**
 * @brief Конструктор
 *
 */
nts::cipher::Chaining::Chaining() noexcept : _ready(false), _length(0) {
	// Выполняем затирание заполнения регистра сдвига
	wipe(this->_register, sizeof(this->_register));
}
/**
 * @brief Деструктор
 *
 */
nts::cipher::Chaining::~Chaining() noexcept {
	// Выполняем сброс состояния режима работы
	this->clear();
}
/**
 * @brief Метод проверки готовности режима к работе
 *
 * @return признак готовности режима к работе
 *
 */
bool nts::cipher::Feedback::ready() const noexcept {
	// Выводим признак готовности режима к работе
	return this->_ready;
}
/**
 * @brief Метод запуска режима работы
 *
 * @param block базовый алгоритм блочного шифрования
 * @param iv    синхропосылка длиной не менее длины блока шифра
 * @param size  размер блока гаммы в байтах, ноль означает длину блока шифра
 * @return      признак успешности запуска режима работы
 *
 */
bool nts::cipher::Feedback::start(const block_t & block, const view_t & iv, const size_t size) noexcept {
	// Выполняем сброс прежнего состояния режима работы
	this->clear();
	// Если базовый алгоритм блочного шифрования непригоден
	if(!suitable(block))
		// Выводим отказ запуска режима работы
		return false;
	// Определяем требуемый размер блока гаммы
	const size_t gamma = (size > 0 ? size : block.size);
	// Если размер блока гаммы превышает длину блока шифра
	if(gamma > block.size)
		// Выводим отказ запуска режима работы
		return false;
	// Если синхропосылка короче длины блока шифра
	if((iv.data == nullptr) || (iv.size < block.size) || (iv.size > MODE_REGISTER))
		// Выводим отказ запуска режима работы
		return false;
	// Запоминаем базовый алгоритм блочного шифрования
	this->_block = block;
	// Запоминаем размер блока гаммы
	this->_size = gamma;
	// Запоминаем длину регистра сдвига
	this->_length = iv.size;
	// Начальным заполнением регистра сдвига служит синхропосылка
	::memcpy(this->_register, iv.data, iv.size);
	// Устанавливаем признак готовности режима к работе
	this->_ready = true;
	// Выводим успешность запуска режима работы
	return true;
}
/**
 * @brief Метод сброса состояния режима работы
 *
 */
void nts::cipher::Feedback::clear() noexcept {
	// Выполняем затирание накапливаемого блока шифртекста обратной связи
	wipe(this->_feedback, sizeof(this->_feedback));
	// Выполняем затирание текущего блока гаммы шифра
	wipe(this->_gamma, sizeof(this->_gamma));
	// Выполняем затирание заполнения регистра сдвига
	wipe(this->_register, sizeof(this->_register));
	// Сбрасываем базовый алгоритм блочного шифрования
	this->_block = block_t();
	// Сбрасываем длину регистра сдвига
	this->_length = 0;
	// Сбрасываем количество неизрасходованных байтов блока гаммы
	this->_rest = 0;
	// Сбрасываем размер блока гаммы
	this->_size = 0;
	// Снимаем признак готовности режима к работе
	this->_ready = false;
}
/**
 * @brief Метод зашифрования сообщения
 *
 * @param source зашифровываемое сообщение
 * @param result место, в которое помещается шифртекст
 * @return       признак успешности зашифрования
 *
 */
bool nts::cipher::Feedback::encrypt(const view_t & source, uint8_t * result) noexcept {
	// Если режим не готов к работе либо места не переданы
	if(!this->_ready || ((source.size > 0) && ((source.data == nullptr) || (result == nullptr))))
		// Выводим отказ зашифрования
		return false;
	/**
	 * Выполняем перебор байтов зашифровываемого сообщения
	 */
	for(size_t offset = 0; offset < source.size; offset++){
		// Если блок гаммы шифра израсходован
		if(this->_rest == 0){
			// Блок, в который помещается выход базового алгоритма блочного шифрования
			uint8_t buffer[MODE_BLOCK];
			// Выполняем зашифрование старших разрядов регистра сдвига
			if(!this->_block.encrypt(this->_block.cipher, this->_register, buffer))
				// Выводим отказ зашифрования
				return false;
			// Выполняем усечение выхода шифра до размера блока гаммы
			::memcpy(this->_gamma, buffer, this->_size);
			// Выполняем затирание выхода базового алгоритма блочного шифрования
			wipe(buffer, sizeof(buffer));
			// Восстанавливаем количество неизрасходованных байтов блока гаммы
			this->_rest = this->_size;
		}
		// Определяем место очередного байта внутри блока гаммы
		const size_t index = (this->_size - this->_rest);
		// Складываем очередной байт сообщения с гаммой шифра
		const uint8_t item = static_cast <uint8_t> (source.data[offset] ^ this->_gamma[index]);
		// Запоминаем байт шифртекста для обратной связи
		this->_feedback[index] = item;
		// Записываем байт шифртекста в место итога
		result[offset] = item;
		// Уменьшаем количество неизрасходованных байтов блока гаммы
		this->_rest--;
		// Если блок шифртекста собран целиком
		if(this->_rest == 0)
			// Записываем блок шифртекста в разряды регистра с меньшими номерами
			shift(this->_register, this->_length, this->_feedback, this->_size);
	}
	// Выводим успешность зашифрования
	return true;
}
/**
 * @brief Метод расшифрования сообщения
 *
 * @param source расшифровываемый шифртекст
 * @param result место, в которое помещается открытый текст
 * @return       признак успешности расшифрования
 *
 */
bool nts::cipher::Feedback::decrypt(const view_t & source, uint8_t * result) noexcept {
	// Если режим не готов к работе либо места не переданы
	if(!this->_ready || ((source.size > 0) && ((source.data == nullptr) || (result == nullptr))))
		// Выводим отказ расшифрования
		return false;
	/**
	 * Выполняем перебор байтов расшифровываемого шифртекста
	 */
	for(size_t offset = 0; offset < source.size; offset++){
		// Если блок гаммы шифра израсходован
		if(this->_rest == 0){
			// Блок, в который помещается выход базового алгоритма блочного шифрования
			uint8_t buffer[MODE_BLOCK];
			// Выполняем зашифрование старших разрядов регистра сдвига
			if(!this->_block.encrypt(this->_block.cipher, this->_register, buffer))
				// Выводим отказ расшифрования
				return false;
			// Выполняем усечение выхода шифра до размера блока гаммы
			::memcpy(this->_gamma, buffer, this->_size);
			// Выполняем затирание выхода базового алгоритма блочного шифрования
			wipe(buffer, sizeof(buffer));
			// Восстанавливаем количество неизрасходованных байтов блока гаммы
			this->_rest = this->_size;
		}
		// Определяем место очередного байта внутри блока гаммы
		const size_t index = (this->_size - this->_rest);
		// Запоминаем байт шифртекста для обратной связи
		this->_feedback[index] = source.data[offset];
		// Складываем очередной байт шифртекста с гаммой шифра
		result[offset] = static_cast <uint8_t> (this->_feedback[index] ^ this->_gamma[index]);
		// Уменьшаем количество неизрасходованных байтов блока гаммы
		this->_rest--;
		// Если блок шифртекста собран целиком
		if(this->_rest == 0)
			// Записываем блок шифртекста в разряды регистра с меньшими номерами
			shift(this->_register, this->_length, this->_feedback, this->_size);
	}
	// Выводим успешность расшифрования
	return true;
}
/**
 * @brief Конструктор
 *
 */
nts::cipher::Feedback::Feedback() noexcept : _ready(false), _size(0), _rest(0), _length(0) {
	// Выполняем затирание заполнения регистра сдвига
	wipe(this->_register, sizeof(this->_register));
	// Выполняем затирание текущего блока гаммы шифра
	wipe(this->_gamma, sizeof(this->_gamma));
	// Выполняем затирание накапливаемого блока шифртекста обратной связи
	wipe(this->_feedback, sizeof(this->_feedback));
}
/**
 * @brief Деструктор
 *
 */
nts::cipher::Feedback::~Feedback() noexcept {
	// Выполняем сброс состояния режима работы
	this->clear();
}
/**
 * @brief Метод проверки готовности режима к работе
 *
 * @return признак готовности режима к работе
 *
 */
bool nts::cipher::Imitation::ready() const noexcept {
	// Выводим признак готовности режима к работе
	return this->_ready;
}
/**
 * @brief Метод запуска режима работы
 *
 * @param block базовый алгоритм блочного шифрования
 * @return      признак успешности запуска режима работы
 *
 */
bool nts::cipher::Imitation::start(const block_t & block) noexcept {
	// Выполняем сброс прежнего состояния режима работы
	this->clear();
	// Если базовый алгоритм блочного шифрования непригоден
	if(!suitable(block))
		// Выводим отказ запуска режима работы
		return false;
	/**
	 * Константа Bn задана стандартом лишь для блоков длиной 64 и 128 разрядов, для
	 * прочих длин её пришлось бы искать перебором примитивных многочленов
	 */
	uint8_t constant = 0;
	/**
	 * Выполняем выбор константы Bn по длине блока шифра
	 */
	switch(block.size){
		// Если длина блока шифра составляет 64 разряда
		case 8:
			// Устанавливаем младшие разряды константы B64
			constant = 0x1B;
		break;
		// Если длина блока шифра составляет 128 разрядов
		case 16:
			// Устанавливаем младшие разряды константы B128
			constant = 0x87;
		break;
		// Если длина блока шифра иная
		default:
			// Выводим отказ запуска режима работы
			return false;
	}
	// Промежуточное значение R выработки вспомогательных ключей
	uint8_t buffer[MODE_BLOCK];
	// Выполняем затирание промежуточного значения выработки вспомогательных ключей
	wipe(buffer, sizeof(buffer));
	// Выполняем зашифрование нулевого блока
	if(!block.encrypt(block.cipher, buffer, buffer)){
		// Выполняем затирание промежуточного значения выработки вспомогательных ключей
		wipe(buffer, sizeof(buffer));
		// Выводим отказ запуска режима работы
		return false;
	}
	/**
	 * Выполняем выработку обоих вспомогательных ключей: каждый следующий получается
	 * сдвигом предыдущего на один разряд влево со сложением с константой Bn, если
	 * старший разряд сдвигаемого значения был единичным
	 */
	for(size_t i = 0; i < 2; i++){
		// Запоминаем старший разряд сдвигаемого значения
		const uint8_t senior = static_cast <uint8_t> (buffer[0] >> 7);
		/**
		 * Выполняем сдвиг значения на один разряд влево
		 */
		for(size_t j = 0; j < block.size; j++){
			// Сдвигаем очередной байт значения, перенося старший разряд следующего байта
			buffer[j] = static_cast <uint8_t> ((buffer[j] << 1) | ((j + 1) < block.size ? (buffer[j + 1] >> 7) : 0));
		}
		// Если старший разряд сдвигаемого значения был единичным
		if(senior != 0)
			// Складываем сдвинутое значение с константой Bn
			buffer[block.size - 1] = static_cast <uint8_t> (buffer[block.size - 1] ^ constant);
		// Запоминаем выработанный вспомогательный ключ
		::memcpy((i == 0 ? this->_first : this->_second), buffer, block.size);
	}
	// Выполняем затирание промежуточного значения выработки вспомогательных ключей
	wipe(buffer, sizeof(buffer));
	// Запоминаем базовый алгоритм блочного шифрования
	this->_block = block;
	// Устанавливаем признак готовности режима к работе
	this->_ready = true;
	// Выводим успешность запуска режима работы
	return true;
}
/**
 * @brief Метод сброса состояния режима работы
 *
 */
void nts::cipher::Imitation::clear() noexcept {
	// Выполняем затирание результата зашифрования на предыдущем шаге
	wipe(this->_state, sizeof(this->_state));
	// Выполняем затирание накопленного блока сообщения
	wipe(this->_buffer, sizeof(this->_buffer));
	// Выполняем затирание второго вспомогательного ключа
	wipe(this->_second, sizeof(this->_second));
	// Выполняем затирание первого вспомогательного ключа
	wipe(this->_first, sizeof(this->_first));
	// Сбрасываем базовый алгоритм блочного шифрования
	this->_block = block_t();
	// Сбрасываем количество накопленных байтов текущего блока сообщения
	this->_size = 0;
	// Снимаем признак готовности режима к работе
	this->_ready = false;
}
/**
 * @brief Метод добавления куска сообщения
 *
 * @param source добавляемый кусок сообщения
 * @return       признак успешности добавления куска сообщения
 *
 */
bool nts::cipher::Imitation::update(const view_t & source) noexcept {
	// Если режим не готов к работе либо кусок сообщения не передан
	if(!this->_ready || ((source.size > 0) && (source.data == nullptr)))
		// Выводим отказ добавления куска сообщения
		return false;
	// Количество уже добавленных байтов куска сообщения
	size_t offset = 0;
	/**
	 * Выполняем добавление куска сообщения до его исчерпания
	 */
	while(offset < source.size){
		/**
		 * Накопленный блок обрабатывается лишь тогда, когда за ним пришли ещё байты:
		 * последний блок сообщения обрабатывается иначе и до вызова finish о том,
		 * последний ли он, узнать неоткуда
		 */
		if(this->_size == this->_block.size){
			// Складываем накопленный блок с результатом зашифрования на предыдущем шаге
			add(this->_buffer, this->_state, this->_buffer, this->_block.size);
			// Выполняем зашифрование полученного блока
			if(!this->_block.encrypt(this->_block.cipher, this->_buffer, this->_state))
				// Выводим отказ добавления куска сообщения
				return false;
			// Сбрасываем количество накопленных байтов текущего блока сообщения
			this->_size = 0;
		}
		// Определяем количество байтов, добавляемых в накопленный блок сообщения
		const size_t count = ((source.size - offset) < (this->_block.size - this->_size) ? (source.size - offset) : (this->_block.size - this->_size));
		// Добавляем очередные байты куска сообщения в накопленный блок
		::memcpy(this->_buffer + this->_size, source.data + offset, count);
		// Увеличиваем количество накопленных байтов текущего блока сообщения
		this->_size += count;
		// Увеличиваем количество добавленных байтов куска сообщения
		offset += count;
	}
	// Выводим успешность добавления куска сообщения
	return true;
}
/**
 * @brief Метод снятия имитовставки
 *
 * @param result место, в которое помещается имитовставка
 * @param size   требуемая длина имитовставки в байтах
 * @return       признак успешности снятия имитовставки
 *
 */
bool nts::cipher::Imitation::finish(uint8_t * result, const size_t size) noexcept {
	// Если режим не готов к работе либо место итога не передано
	if(!this->_ready || (result == nullptr) || (size == 0) || (size > this->_block.size))
		// Выводим отказ снятия имитовставки
		return false;
	// Если последний блок сообщения оказался неполным
	if(this->_size < this->_block.size){
		/**
		 * Выполняем дополнение последнего блока по процедуре 3 раздела 4.1.3: за
		 * последним байтом сообщения ставится единичный разряд, а остаток блока
		 * заполняется нулями
		 */
		this->_buffer[this->_size] = 0x80;
		// Заполняем нулями остаток последнего блока сообщения
		::memset(this->_buffer + this->_size + 1, 0, this->_block.size - this->_size - 1);
		// Складываем последний блок со вторым вспомогательным ключом
		add(this->_buffer, this->_second, this->_buffer, this->_block.size);
	// Если последний блок сообщения оказался полным
	} else
		// Складываем последний блок с первым вспомогательным ключом
		add(this->_buffer, this->_first, this->_buffer, this->_block.size);
	// Складываем последний блок с результатом зашифрования на предыдущем шаге
	add(this->_buffer, this->_state, this->_buffer, this->_block.size);
	// Выполняем зашифрование последнего блока сообщения
	if(!this->_block.encrypt(this->_block.cipher, this->_buffer, this->_state))
		// Выводим отказ снятия имитовставки
		return false;
	// Выполняем усечение выхода шифра до требуемой длины имитовставки
	::memcpy(result, this->_state, size);
	// Имитовставка снята: объект закрывается, повторные снятие и подача отвергаются, как у прочих режимов
	this->clear();
	// Выводим успешность снятия имитовставки
	return true;
}
/**
 * @brief Конструктор
 *
 */
nts::cipher::Imitation::Imitation() noexcept : _ready(false), _size(0) {
	// Выполняем затирание первого вспомогательного ключа
	wipe(this->_first, sizeof(this->_first));
	// Выполняем затирание второго вспомогательного ключа
	wipe(this->_second, sizeof(this->_second));
	// Выполняем затирание накопленного блока сообщения
	wipe(this->_buffer, sizeof(this->_buffer));
	// Выполняем затирание результата зашифрования на предыдущем шаге
	wipe(this->_state, sizeof(this->_state));
}
/**
 * @brief Деструктор
 *
 */
nts::cipher::Imitation::~Imitation() noexcept {
	// Выполняем сброс состояния режима работы
	this->clear();
}
