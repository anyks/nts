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
 * Стандартный заголовочный файл
 */
#include <cstring>

/**
 * Подключаем заголовочный файл проекта
 */
#include "sys/wipe.hpp"

/**
 * Подключаем заголовочный файл модуля
 */
#include "cipher/mode.hpp"

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
	 * Затирание областей памяти берётся из открытого API библиотеки
	 */
	using nts::sys::wipe;

	/**
	 * @brief Функция зашифрования блока шифром «Магма»
	 *
	 * @param cipher объект блочного шифра
	 * @param source зашифровываемый блок
	 * @param result место, в которое помещается зашифрованный блок
	 * @return       признак успешности зашифрования
	 *
	 */
	static __NTS_INLINE__ bool __nts_encrypt_magma__(const void * cipher, const uint8_t * source, uint8_t * result) noexcept {
		// Зашифрование блока шифром «Магма»
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
	static __NTS_INLINE__ bool __nts_decrypt_magma__(const void * cipher, const uint8_t * source, uint8_t * result) noexcept {
		// Расшифрование блока шифром «Магма»
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
	static __NTS_INLINE__ bool __nts_encrypt_kuznyechik__(const void * cipher, const uint8_t * source, uint8_t * result) noexcept {
		// Зашифрование блока шифром «Кузнечик»
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
	static __NTS_INLINE__ bool __nts_decrypt_kuznyechik__(const void * cipher, const uint8_t * source, uint8_t * result) noexcept {
		// Расшифрование блока шифром «Кузнечик»
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
	static __NTS_INLINE__ bool __nts_encrypt_aes__(const void * cipher, const uint8_t * source, uint8_t * result) noexcept {
		// Зашифрование блока шифром AES
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
	static __NTS_INLINE__ bool __nts_decrypt_aes__(const void * cipher, const uint8_t * source, uint8_t * result) noexcept {
		// Расшифрование блока шифром AES
		return reinterpret_cast <const aes_t *> (cipher)->decrypt(source, result);
	}
	/**
	 * @brief Функция зашифрования нескольких блоков разом шифром «Магма»
	 *
	 * @param cipher  объект блочного шифра
	 * @param sources зашифровываемые блоки подряд
	 * @param blocks  количество блоков
	 * @param results место, в которое помещаются зашифрованные блоки
	 * @return        признак успешности зашифрования
	 *
	 */
	static __NTS_INLINE__ bool __nts_batch_magma__(const void * cipher, const uint8_t * sources, const size_t blocks, uint8_t * results) noexcept {
		// Зашифрование блоков шифром «Магма»
		return reinterpret_cast <const magma_t *> (cipher)->batch(sources, blocks, results);
	}
	/**
	 * @brief Функция зашифрования нескольких блоков разом шифром «Кузнечик»
	 *
	 * @param cipher  объект блочного шифра
	 * @param sources зашифровываемые блоки подряд
	 * @param blocks  количество блоков
	 * @param results место, в которое помещаются зашифрованные блоки
	 * @return        признак успешности зашифрования
	 *
	 */
	static __NTS_INLINE__ bool __nts_batch_kuznyechik__(const void * cipher, const uint8_t * sources, const size_t blocks, uint8_t * results) noexcept {
		// Зашифрование блоков шифром «Кузнечик»
		return reinterpret_cast <const kuznyechik_t *> (cipher)->batch(sources, blocks, results);
	}
	/**
	 * @brief Функция зашифрования нескольких блоков разом шифром AES
	 *
	 * @param cipher  объект блочного шифра
	 * @param sources зашифровываемые блоки подряд
	 * @param blocks  количество блоков
	 * @param results место, в которое помещаются зашифрованные блоки
	 * @return        признак успешности зашифрования
	 *
	 */
	static __NTS_INLINE__ bool __nts_batch_aes__(const void * cipher, const uint8_t * sources, const size_t blocks, uint8_t * results) noexcept {
		// Зашифрование блоков шифром AES
		return reinterpret_cast <const aes_t *> (cipher)->batch(sources, blocks, results);
	}
	/**
	 * @brief Функция выработки гаммы счётчика шифром AES
	 *
	 * @param cipher  объект блочного шифра
	 * @param counter начальный блок счётчика
	 * @param blocks  количество блоков гаммы
	 * @param source  исходные данные, на которые гамма накладывается: пусто, если нужна сама гамма
	 * @param result  место, в которое помещается гамма либо исходные данные под ней
	 * @return        признак успешности выработки
	 *
	 */
	static __NTS_INLINE__ bool __nts_stream_aes__(const void * cipher, const uint8_t * counter, const size_t blocks, const uint8_t * source, uint8_t * result) noexcept {
		// Выработка гаммы шифром AES
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
	static __NTS_INLINE__ bool __nts_chain_aes__(const void * cipher, uint8_t * record, const uint8_t * source, const size_t size, uint8_t * result) noexcept {
		// Зашифрование цепочкой сцепления шифром AES
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
	static __NTS_INLINE__ bool __nts_encrypt_sm4__(const void * cipher, const uint8_t * source, uint8_t * result) noexcept {
		// Зашифрование блока шифром SM4
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
	static __NTS_INLINE__ bool __nts_decrypt_sm4__(const void * cipher, const uint8_t * source, uint8_t * result) noexcept {
		// Расшифрование блока шифром SM4
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
	static __NTS_INLINE__ bool __nts_encrypt_des__(const void * cipher, const uint8_t * source, uint8_t * result) noexcept {
		// Зашифрование блока шифром DES и 3DES
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
	static __NTS_INLINE__ bool __nts_decrypt_des__(const void * cipher, const uint8_t * source, uint8_t * result) noexcept {
		// Расшифрование блока шифром DES и 3DES
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
	static __NTS_INLINE__ void __nts_fetch_blowfish__(const uint8_t * source, uint32_t * left, uint32_t * right) noexcept {
		/**
		 * Разбираем обе половины блока от старшего байта к младшему
		 */
		for(size_t i = 0; i < 4; i++){
			// Сдвигаем левую половину на байт и дополняем очередным байтом блока
			(* left) = static_cast <uint32_t> (((* left) << 8) | source[i]);
			// Сдвигаем правую половину на байт и дополняем очередным байтом блока
			(* right) = static_cast <uint32_t> (((* right) << 8) | source[i + 4]);
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
	static __NTS_INLINE__ void __nts_store_blowfish__(const uint32_t left, const uint32_t right, uint8_t * result) noexcept {
		/**
		 * Записываем обе половины блока от старшего байта к младшему
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
	static __NTS_INLINE__ bool __nts_encrypt_blowfish__(const void * cipher, const uint8_t * source, uint8_t * result) noexcept {
		// Левая половина зашифровываемого блока
		uint32_t left = 0;
		// Правая половина зашифровываемого блока
		uint32_t right = 0;
		// Разбор зашифровываемого блока на две половины
		__nts_fetch_blowfish__(source, &left, &right);
		// Зашифрование блока шифром Blowfish
		encipher(reinterpret_cast <const blowfish_t *> (cipher), &left, &right);
		// Запись зашифрованного блока байтами
		__nts_store_blowfish__(left, right, result);
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
	static __NTS_INLINE__ bool __nts_decrypt_blowfish__(const void * cipher, const uint8_t * source, uint8_t * result) noexcept {
		// Левая половина расшифровываемого блока
		uint32_t left = 0;
		// Правая половина расшифровываемого блока
		uint32_t right = 0;
		// Разбор расшифровываемого блока на две половины
		__nts_fetch_blowfish__(source, &left, &right);
		// Расшифрование блока шифром Blowfish
		decipher(reinterpret_cast <const blowfish_t *> (cipher), &left, &right);
		// Запись расшифрованного блока байтами
		__nts_store_blowfish__(left, right, result);
		// Выводим успешность расшифрования
		return true;
	}
	/**
	 * @brief Функция проверки пригодности базового алгоритма блочного шифрования
	 *
	 * @param block проверяемый базовый алгоритм блочного шифрования
	 * @return      признак пригодности базового алгоритма блочного шифрования
	 *
	 */
	static __NTS_INLINE__ bool __nts_suitable__(const block_t & block) noexcept {
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
	static __NTS_INLINE__ void __nts_shift__(uint8_t * data, const size_t length, const uint8_t * value, const size_t size) noexcept {
		// Если сдвиг не занимает регистр целиком
		if(size < length)
			// Сдвиг оставшегося заполнения регистра
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
	static __NTS_INLINE__ void __nts_add__(const uint8_t * first, const uint8_t * second, uint8_t * result, const size_t size) noexcept {
		/**
		 * Перебираем байты складываемых блоков
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
 size(0), cipher(nullptr), encrypt(nullptr), decrypt(nullptr),
 stream(nullptr), batch(nullptr), chain(nullptr), schedule(nullptr), rounds(0) {}
/**
 * @brief Конструктор
 *
 * @param cipher объект блочного шифра «Магма»
 *
 */
nts::cipher::Block::Block(const magma_t & cipher) noexcept :
 size(MAGMA_BLOCK), cipher(&cipher), encrypt(&__nts_encrypt_magma__), decrypt(&__nts_decrypt_magma__),
 stream(nullptr), batch(&__nts_batch_magma__), chain(nullptr), schedule(nullptr), rounds(0) {}
/**
 * @brief Конструктор
 *
 * @param cipher объект блочного шифра «Кузнечик»
 *
 */
nts::cipher::Block::Block(const kuznyechik_t & cipher) noexcept :
 size(KUZNYECHIK_BLOCK), cipher(&cipher), encrypt(&__nts_encrypt_kuznyechik__), decrypt(&__nts_decrypt_kuznyechik__),
 stream(nullptr), batch(&__nts_batch_kuznyechik__), chain(nullptr), schedule(nullptr), rounds(0) {}
/**
 * @brief Конструктор
 *
 * @param cipher объект блочного шифра AES
 *
 */
nts::cipher::Block::Block(const aes_t & cipher) noexcept :
 size(AES_BLOCK), cipher(&cipher), encrypt(&__nts_encrypt_aes__),
 decrypt(&__nts_decrypt_aes__), stream(&__nts_stream_aes__), batch(&__nts_batch_aes__),
 chain(&__nts_chain_aes__), schedule(cipher.schedule()), rounds(cipher.rounds()) {}
/**
 * @brief Конструктор
 *
 * @param cipher объект блочного шифра SM4
 *
 */
nts::cipher::Block::Block(const sm4_t & cipher) noexcept :
 size(SM4_BLOCK), cipher(&cipher), encrypt(&__nts_encrypt_sm4__), decrypt(&__nts_decrypt_sm4__),
 stream(nullptr), batch(nullptr), chain(nullptr), schedule(nullptr), rounds(0) {}
/**
 * @brief Конструктор
 *
 * @param cipher объект блочного шифра DES и 3DES
 *
 */
nts::cipher::Block::Block(const des_t & cipher) noexcept :
 size(DES_BLOCK), cipher(&cipher), encrypt(&__nts_encrypt_des__), decrypt(&__nts_decrypt_des__),
 stream(nullptr), batch(nullptr), chain(nullptr), schedule(nullptr), rounds(0) {}
/**
 * @brief Конструктор
 *
 * @param cipher объект блочного шифра Blowfish
 *
 */
nts::cipher::Block::Block(const blowfish_t & cipher) noexcept :
 size(BLOWFISH_BLOCK), cipher(&cipher), encrypt(&__nts_encrypt_blowfish__), decrypt(&__nts_decrypt_blowfish__),
 stream(nullptr), batch(nullptr), chain(nullptr), schedule(nullptr), rounds(0) {}
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
	// Сброс прежнего состояния режима работы
	this->clear();
	// Если базовый алгоритм блочного шифрования непригоден
	if(!::__nts_suitable__(block))
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
	 * Перебираем блоки зашифровываемого сообщения
	 */
	for(size_t offset = 0; offset < source.size; offset += this->_block.size){
		// Зашифрование очередного блока сообщения
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
	 * Перебираем блоки расшифровываемого шифртекста
	 */
	for(size_t offset = 0; offset < source.size; offset += this->_block.size){
		// Расшифрование очередного блока шифртекста
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
	// Сброс состояния режима работы
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
 * @param initVector    синхропосылка длиной в половину блока шифра
 * @param size  размер блока гаммы в байтах, ноль означает длину блока шифра
 * @return      признак успешности запуска режима работы
 *
 */
bool nts::cipher::Counter::start(const block_t & block, const view_t & initVector, const size_t size) noexcept {
	// Сброс прежнего состояния режима работы
	this->clear();
	// Если базовый алгоритм блочного шифрования непригоден
	if(!::__nts_suitable__(block))
		// Выводим отказ запуска режима работы
		return false;
	// Определяем требуемый размер блока гаммы
	const size_t gamma = (size > 0 ? size : block.size);
	// Если размер блока гаммы превышает длину блока шифра
	if(gamma > block.size)
		// Выводим отказ запуска режима работы
		return false;
	// Если синхропосылка не занимает половину блока шифра
	if((initVector.data == nullptr) || (initVector.size != (block.size / 2)))
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
	::memcpy(this->_counter, initVector.data, initVector.size);
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
	// Затирание текущего блока гаммы шифра
	wipe(this->_gamma, sizeof(this->_gamma));
	// Затирание текущего значения счётчика
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
		 * Покрываем целые блоки вызовами ядра
		 */
		while((source.size - offset) >= 16){
			// Младшие 32 разряда счётчика от старшего байта
			const uint32_t tail = ((static_cast <uint32_t> (this->_counter[12]) << 24) | (static_cast <uint32_t> (this->_counter[13]) << 16) | (static_cast <uint32_t> (this->_counter[14]) << 8) | static_cast <uint32_t> (this->_counter[15]));
			// Количество блоков до переполнения младших четырёх байтов
			const uint64_t room = ((static_cast <uint64_t> (UINT32_MAX) - tail) + 1);
			// Количество блоков вызова: целые блоки сообщения
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
				// Затирание основания
				wipe(base, sizeof(base));
				// Выводим отказ зашифрования
				return false;
			}
			// Перенос при продвижении счётчика на выработанные блоки
			uint64_t carry = static_cast <uint64_t> (count);
			/**
			 * Продвигаем счётчик как число от старшего байта с переносом через все байты
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
		// Затирание основания
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
		 * Заполняем четыре счётчика
		 */
		for(size_t k = 0; k < 4; k++){
			// Записываем текущее значение счётчика
			::memcpy(counters + (k * this->_block.size), this->_counter, this->_block.size);
			/**
			 * Увеличиваем счётчик на единицу от младшего байта
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
			// Затирание счётчиков и выходов шифра
			wipe(counters, sizeof(counters));
			wipe(buffer, sizeof(buffer));
			// Выводим отказ зашифрования
			return false;
		}
		/**
		 * Накладываем четыре блока гаммы: от всякого выхода шифра берётся
		 * усечение до размера блока гаммы
		 */
		for(size_t k = 0; k < 4; k++){
			// Выход шифра очередного счётчика
			const uint8_t * gamma = (buffer + (k * this->_block.size));
			/**
			 * Накладываем блок гаммы
			 */
			for(size_t i = 0; i < this->_size; i++)
				// Складываем очередные байты по модулю два
				result[offset + i] = static_cast <uint8_t> (source.data[offset + i] ^ gamma[i]);
			// Сдвигаем количество обработанных байтов
			offset += this->_size;
		}
		// Затирание счётчиков и выходов шифра
		wipe(counters, sizeof(counters));
		wipe(buffer, sizeof(buffer));
	}
	/**
	 * Обрабатываем сообщение до его исчерпания
	 */
	while(offset < source.size){
		// Если блок гаммы шифра израсходован
		if(this->_rest == 0){
			// Блок, в который помещается выход базового алгоритма блочного шифрования
			uint8_t buffer[MODE_BLOCK];
			// Зашифрование текущего значения счётчика
			if(!this->_block.encrypt(this->_block.cipher, this->_counter, buffer))
				// Выводим отказ зашифрования
				return false;
			// Усечение выхода шифра до размера блока гаммы
			::memcpy(this->_gamma, buffer, this->_size);
			// Затирание выхода базового алгоритма блочного шифрования
			wipe(buffer, sizeof(buffer));
			// Восстанавливаем количество неизрасходованных байтов блока гаммы
			this->_rest = this->_size;
			/**
			 * Увеличиваем счётчик на единицу как числа, записанного от
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
		// Сложение куска сообщения с гаммой шифра
		::__nts_add__(source.data + offset, this->_gamma + (this->_size - this->_rest), result + offset, count);
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
	// Затирание текущего значения счётчика
	wipe(this->_counter, sizeof(this->_counter));
	// Затирание текущего блока гаммы шифра
	wipe(this->_gamma, sizeof(this->_gamma));
}
/**
 * @brief Деструктор
 *
 */
nts::cipher::Counter::~Counter() noexcept {
	// Сброс состояния режима работы
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
 * @param initVector    синхропосылка длиной в целое число блоков шифра
 * @param size  размер блока гаммы в байтах, ноль означает длину блока шифра
 * @return      признак успешности запуска режима работы
 *
 */
bool nts::cipher::Output::start(const block_t & block, const view_t & initVector, const size_t size) noexcept {
	// Сброс прежнего состояния режима работы
	this->clear();
	// Если базовый алгоритм блочного шифрования непригоден
	if(!::__nts_suitable__(block))
		// Выводим отказ запуска режима работы
		return false;
	// Определяем требуемый размер блока гаммы
	const size_t gamma = (size > 0 ? size : block.size);
	// Если размер блока гаммы превышает длину блока шифра
	if(gamma > block.size)
		// Выводим отказ запуска режима работы
		return false;
	// Если синхропосылка не занимает целого количества блоков шифра
	if((initVector.data == nullptr) || (initVector.size < block.size) ||
	  ((initVector.size % block.size) != 0) || (initVector.size > MODE_REGISTER))
		// Выводим отказ запуска режима работы
		return false;
	// Запоминаем базовый алгоритм блочного шифрования
	this->_block = block;
	// Запоминаем размер блока гаммы
	this->_size = gamma;
	// Запоминаем длину регистра сдвига
	this->_length = initVector.size;
	// Начальным заполнением регистра сдвига служит синхропосылка
	::memcpy(this->_register, initVector.data, initVector.size);
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
	// Затирание текущего блока гаммы шифра
	wipe(this->_gamma, sizeof(this->_gamma));
	// Затирание заполнения регистра сдвига
	wipe(this->_register, sizeof(this->_register));
	// Сбрасываем базовый алгоритм блочного шифрования
	this->_block = block_t();
	// Сбрасываем количество неизрасходованных байтов блока гаммы
	this->_rest = 0;
	// Сбрасываем размер блока гаммы
	this->_size = 0;
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
bool nts::cipher::Output::encrypt(const view_t & source, uint8_t * result) noexcept {
	// Если режим не готов к работе либо места не переданы
	if(!this->_ready || ((source.size > 0) && ((source.data == nullptr) || (result == nullptr))))
		// Выводим отказ зашифрования
		return false;
	// Количество уже обработанных байтов сообщения
	size_t offset = 0;
	/**
	 * Обрабатываем сообщение до его исчерпания
	 */
	while(offset < source.size){
		// Если блок гаммы шифра израсходован
		if(this->_rest == 0){
			// Блок, в который помещается выход базового алгоритма блочного шифрования
			uint8_t buffer[MODE_BLOCK];
			// Зашифрование старших разрядов регистра сдвига
			if(!this->_block.encrypt(this->_block.cipher, this->_register, buffer))
				// Выводим отказ зашифрования
				return false;
			// Усечение выхода шифра до размера блока гаммы
			::memcpy(this->_gamma, buffer, this->_size);
			// Записываем выход шифра в разряды регистра с меньшими номерами
			::__nts_shift__(this->_register, this->_length, buffer, this->_block.size);
			// Затирание выхода базового алгоритма блочного шифрования
			wipe(buffer, sizeof(buffer));
			// Восстанавливаем количество неизрасходованных байтов блока гаммы
			this->_rest = this->_size;
		}
		// Определяем количество байтов, обрабатываемых текущим блоком гаммы
		const size_t count = ((source.size - offset) < this->_rest ? (source.size - offset) : this->_rest);
		// Сложение куска сообщения с гаммой шифра
		::__nts_add__(source.data + offset, this->_gamma + (this->_size - this->_rest), result + offset, count);
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
	// Затирание заполнения регистра сдвига
	wipe(this->_register, sizeof(this->_register));
	// Затирание текущего блока гаммы шифра
	wipe(this->_gamma, sizeof(this->_gamma));
}
/**
 * @brief Деструктор
 *
 */
nts::cipher::Output::~Output() noexcept {
	// Сброс состояния режима работы
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
 * @param initVector    синхропосылка длиной в целое число блоков шифра
 * @return      признак успешности запуска режима работы
 *
 */
bool nts::cipher::Chaining::start(const block_t & block, const view_t & initVector) noexcept {
	// Сброс прежнего состояния режима работы
	this->clear();
	// Если базовый алгоритм блочного шифрования непригоден
	if(!::__nts_suitable__(block))
		// Выводим отказ запуска режима работы
		return false;
	// Если синхропосылка не занимает целого количества блоков шифра
	if((initVector.data == nullptr) || (initVector.size < block.size) ||
	  ((initVector.size % block.size) != 0) || (initVector.size > MODE_REGISTER))
		// Выводим отказ запуска режима работы
		return false;
	// Запоминаем базовый алгоритм блочного шифрования
	this->_block = block;
	// Запоминаем длину регистра сдвига
	this->_length = initVector.size;
	// Начальным заполнением регистра сдвига служит синхропосылка
	::memcpy(this->_register, initVector.data, initVector.size);
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
	// Затирание заполнения регистра сдвига
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
	 * Перебираем блоки зашифровываемого сообщения
	 */
	for(size_t offset = 0; offset < source.size; offset += this->_block.size){
		// Блок, подаваемый базовому алгоритму блочного шифрования
		uint8_t buffer[MODE_BLOCK];
		// Складываем блок сообщения со старшими разрядами регистра сдвига
		::__nts_add__(source.data + offset, this->_register, buffer, this->_block.size);
		// Зашифрование полученного блока
		if(!this->_block.encrypt(this->_block.cipher, buffer, buffer)){
			// Затирание блока, подаваемого базовому алгоритму
			wipe(buffer, sizeof(buffer));
			// Выводим отказ зашифрования
			return false;
		}
		// Записываем блок шифртекста в разряды регистра с меньшими номерами
		::__nts_shift__(this->_register, this->_length, buffer, this->_block.size);
		// Записываем блок шифртекста в место итога
		::memcpy(result + offset, buffer, this->_block.size);
		// Затирание блока, подаваемого базовому алгоритму
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
	 * Перебираем блоки расшифровываемого шифртекста
	 */
	for(size_t offset = 0; offset < source.size; offset += this->_block.size){
		// Блок шифртекста, записываемый в регистр сдвига
		uint8_t item[MODE_BLOCK];
		// Блок, в который помещается выход базового алгоритма блочного шифрования
		uint8_t buffer[MODE_BLOCK];
		/**
		 * Запоминаем блок шифртекста: место итога вправе совпадать с местом
		 * исходного сообщения, оттого к моменту сдвига регистра его уже не прочесть
		 */
		::memcpy(item, source.data + offset, this->_block.size);
		// Расшифрование очередного блока шифртекста
		if(!this->_block.decrypt(this->_block.cipher, item, buffer)){
			// Затирание блока шифртекста
			wipe(item, sizeof(item));
			// Затирание выхода базового алгоритма блочного шифрования
			wipe(buffer, sizeof(buffer));
			// Выводим отказ расшифрования
			return false;
		}
		// Складываем выход шифра со старшими разрядами регистра сдвига
		::__nts_add__(buffer, this->_register, result + offset, this->_block.size);
		// Записываем блок шифртекста в разряды регистра с меньшими номерами
		::__nts_shift__(this->_register, this->_length, item, this->_block.size);
		// Затирание блока шифртекста
		wipe(item, sizeof(item));
		// Затирание выхода базового алгоритма блочного шифрования
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
	// Затирание заполнения регистра сдвига
	wipe(this->_register, sizeof(this->_register));
}
/**
 * @brief Деструктор
 *
 */
nts::cipher::Chaining::~Chaining() noexcept {
	// Сброс состояния режима работы
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
 * @param initVector    синхропосылка длиной не менее длины блока шифра
 * @param size  размер блока гаммы в байтах, ноль означает длину блока шифра
 * @return      признак успешности запуска режима работы
 *
 */
bool nts::cipher::Feedback::start(const block_t & block, const view_t & initVector, const size_t size) noexcept {
	// Сброс прежнего состояния режима работы
	this->clear();
	// Если базовый алгоритм блочного шифрования непригоден
	if(!::__nts_suitable__(block))
		// Выводим отказ запуска режима работы
		return false;
	// Определяем требуемый размер блока гаммы
	const size_t gamma = (size > 0 ? size : block.size);
	// Если размер блока гаммы превышает длину блока шифра
	if(gamma > block.size)
		// Выводим отказ запуска режима работы
		return false;
	// Если синхропосылка короче длины блока шифра
	if((initVector.data == nullptr) || (initVector.size < block.size) || (initVector.size > MODE_REGISTER))
		// Выводим отказ запуска режима работы
		return false;
	// Запоминаем базовый алгоритм блочного шифрования
	this->_block = block;
	// Запоминаем размер блока гаммы
	this->_size = gamma;
	// Запоминаем длину регистра сдвига
	this->_length = initVector.size;
	// Начальным заполнением регистра сдвига служит синхропосылка
	::memcpy(this->_register, initVector.data, initVector.size);
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
	// Затирание накапливаемого блока шифртекста обратной связи
	wipe(this->_feedback, sizeof(this->_feedback));
	// Затирание текущего блока гаммы шифра
	wipe(this->_gamma, sizeof(this->_gamma));
	// Затирание заполнения регистра сдвига
	wipe(this->_register, sizeof(this->_register));
	// Сбрасываем базовый алгоритм блочного шифрования
	this->_block = block_t();
	// Сбрасываем количество неизрасходованных байтов блока гаммы
	this->_rest = 0;
	// Сбрасываем размер блока гаммы
	this->_size = 0;
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
bool nts::cipher::Feedback::encrypt(const view_t & source, uint8_t * result) noexcept {
	// Если режим не готов к работе либо места не переданы
	if(!this->_ready || ((source.size > 0) && ((source.data == nullptr) || (result == nullptr))))
		// Выводим отказ зашифрования
		return false;
	/**
	 * Перебираем байты зашифровываемого сообщения
	 */
	for(size_t offset = 0; offset < source.size; offset++){
		// Если блок гаммы шифра израсходован
		if(this->_rest == 0){
			// Блок, в который помещается выход базового алгоритма блочного шифрования
			uint8_t buffer[MODE_BLOCK];
			// Зашифрование старших разрядов регистра сдвига
			if(!this->_block.encrypt(this->_block.cipher, this->_register, buffer))
				// Выводим отказ зашифрования
				return false;
			// Усечение выхода шифра до размера блока гаммы
			::memcpy(this->_gamma, buffer, this->_size);
			// Затирание выхода базового алгоритма блочного шифрования
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
			::__nts_shift__(this->_register, this->_length, this->_feedback, this->_size);
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
	 * Перебираем байты расшифровываемого шифртекста
	 */
	for(size_t offset = 0; offset < source.size; offset++){
		// Если блок гаммы шифра израсходован
		if(this->_rest == 0){
			// Блок, в который помещается выход базового алгоритма блочного шифрования
			uint8_t buffer[MODE_BLOCK];
			// Зашифрование старших разрядов регистра сдвига
			if(!this->_block.encrypt(this->_block.cipher, this->_register, buffer))
				// Выводим отказ расшифрования
				return false;
			// Усечение выхода шифра до размера блока гаммы
			::memcpy(this->_gamma, buffer, this->_size);
			// Затирание выхода базового алгоритма блочного шифрования
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
			::__nts_shift__(this->_register, this->_length, this->_feedback, this->_size);
	}
	// Выводим успешность расшифрования
	return true;
}
/**
 * @brief Конструктор
 *
 */
nts::cipher::Feedback::Feedback() noexcept : _ready(false), _size(0), _rest(0), _length(0) {
	// Затирание заполнения регистра сдвига
	wipe(this->_register, sizeof(this->_register));
	// Затирание текущего блока гаммы шифра
	wipe(this->_gamma, sizeof(this->_gamma));
	// Затирание накапливаемого блока шифртекста обратной связи
	wipe(this->_feedback, sizeof(this->_feedback));
}
/**
 * @brief Деструктор
 *
 */
nts::cipher::Feedback::~Feedback() noexcept {
	// Сброс состояния режима работы
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
	// Сброс прежнего состояния режима работы
	this->clear();
	// Если базовый алгоритм блочного шифрования непригоден
	if(!::__nts_suitable__(block))
		// Выводим отказ запуска режима работы
		return false;
	/**
	 * Константа Bn задана стандартом лишь для блоков длиной 64 и 128 разрядов, для
	 * прочих длин её пришлось бы искать перебором примитивных многочленов
	 */
	uint8_t constant = 0;
	/**
	 * Выбираем константу Bn по длине блока шифра
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
	// Затирание промежуточного значения выработки вспомогательных ключей
	wipe(buffer, sizeof(buffer));
	// Зашифрование нулевого блока
	if(!block.encrypt(block.cipher, buffer, buffer)){
		// Затирание промежуточного значения выработки вспомогательных ключей
		wipe(buffer, sizeof(buffer));
		// Выводим отказ запуска режима работы
		return false;
	}
	/**
	 * Вырабатываем оба вспомогательных ключа: каждый следующий получается
	 * сдвигом предыдущего на один разряд влево со сложением с константой Bn, если
	 * старший разряд сдвигаемого значения был единичным
	 */
	for(size_t i = 0; i < 2; i++){
		// Запоминаем старший разряд сдвигаемого значения
		const uint8_t senior = static_cast <uint8_t> (buffer[0] >> 7);
		/**
		 * Сдвигаем значение на один разряд влево
		 */
		for(size_t j = 0; j < block.size; j++)
			// Сдвигаем очередной байт значения, перенося старший разряд следующего байта
			buffer[j] = static_cast <uint8_t> ((buffer[j] << 1) | ((j + 1) < block.size ? (buffer[j + 1] >> 7) : 0));
		// Если старший разряд сдвигаемого значения был единичным
		if(senior != 0)
			// Складываем сдвинутое значение с константой Bn
			buffer[block.size - 1] = static_cast <uint8_t> (buffer[block.size - 1] ^ constant);
		// Запоминаем выработанный вспомогательный ключ
		::memcpy((i == 0 ? this->_first : this->_second), buffer, block.size);
	}
	// Затирание промежуточного значения выработки вспомогательных ключей
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
	// Затирание результата зашифрования на предыдущем шаге
	wipe(this->_state, sizeof(this->_state));
	// Затирание накопленного блока сообщения
	wipe(this->_buffer, sizeof(this->_buffer));
	// Затирание второго вспомогательного ключа
	wipe(this->_second, sizeof(this->_second));
	// Затирание первого вспомогательного ключа
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
	 * Добавляем кусок сообщения до его исчерпания
	 */
	while(offset < source.size){
		/**
		 * Накопленный блок обрабатывается лишь тогда, когда за ним пришли ещё байты:
		 * последний блок сообщения обрабатывается иначе и до вызова finish о том,
		 * последний ли он, узнать неоткуда
		 */
		if(this->_size == this->_block.size){
			// Складываем накопленный блок с результатом зашифрования на предыдущем шаге
			::__nts_add__(this->_buffer, this->_state, this->_buffer, this->_block.size);
			// Зашифрование полученного блока
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
		 * Дополняем последний блок по процедуре 3 раздела 4.1.3: за
		 * последним байтом сообщения ставится единичный разряд, а остаток блока
		 * заполняется нулями
		 */
		this->_buffer[this->_size] = 0x80;
		// Заполняем нулями остаток последнего блока сообщения
		::memset(this->_buffer + this->_size + 1, 0, this->_block.size - this->_size - 1);
		// Складываем последний блок со вторым вспомогательным ключом
		::__nts_add__(this->_buffer, this->_second, this->_buffer, this->_block.size);
	// Если последний блок сообщения оказался полным
	} else
		// Складываем последний блок с первым вспомогательным ключом
		::__nts_add__(this->_buffer, this->_first, this->_buffer, this->_block.size);
	// Складываем последний блок с результатом зашифрования на предыдущем шаге
	::__nts_add__(this->_buffer, this->_state, this->_buffer, this->_block.size);
	// Зашифрование последнего блока сообщения
	if(!this->_block.encrypt(this->_block.cipher, this->_buffer, this->_state))
		// Выводим отказ снятия имитовставки
		return false;
	// Усечение выхода шифра до требуемой длины имитовставки
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
	// Затирание первого вспомогательного ключа
	wipe(this->_first, sizeof(this->_first));
	// Затирание второго вспомогательного ключа
	wipe(this->_second, sizeof(this->_second));
	// Затирание накопленного блока сообщения
	wipe(this->_buffer, sizeof(this->_buffer));
	// Затирание результата зашифрования на предыдущем шаге
	wipe(this->_state, sizeof(this->_state));
}
/**
 * @brief Деструктор
 *
 */
nts::cipher::Imitation::~Imitation() noexcept {
	// Сброс состояния режима работы
	this->clear();
}
