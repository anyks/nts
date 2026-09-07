/**
 * @file hash.cpp
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
 * @brief Модуль общего хеширования: один договор над всеми алгоритмами хеша
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <digest/hash.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * @brief Метод получения длины хеша алгоритма
 *
 * @param algorithm алгоритм хеширования
 *
 * @return          длина хеша в байтах, ноль у неустановленного алгоритма
 *
 */
size_t nts::digest::length(const hash_t algorithm) noexcept {
	/**
	 * Выполняем определение длины хеша по алгоритму
	 */
	switch(static_cast <uint8_t> (algorithm)){
		// Если выбран MD5
		case static_cast <uint8_t> (hash_t::MD5): return 16;
		// Если выбран SHA-1
		case static_cast <uint8_t> (hash_t::SHA1): return 20;
		// Если выбран SHA-224
		case static_cast <uint8_t> (hash_t::SHA224): return 28;
		// Если выбран SHA-256 либо «Стрибог» длиной 256 разрядов
		case static_cast <uint8_t> (hash_t::SHA256):
		case static_cast <uint8_t> (hash_t::STREEBOG256): return 32;
		// Если выбран SHA-384
		case static_cast <uint8_t> (hash_t::SHA384): return 48;
		// Если выбран SHA-512 либо «Стрибог» длиной 512 разрядов
		case static_cast <uint8_t> (hash_t::SHA512):
		case static_cast <uint8_t> (hash_t::STREEBOG512): return 64;
		// BLAKE2s-256 и BLAKE2b-512
		case static_cast <uint8_t> (hash_t::BLAKE2S256): return 32;
		case static_cast <uint8_t> (hash_t::BLAKE2B512): return 64;
		// Если алгоритм не установлен
		default: return 0;
	}
}
/**
 * @brief Метод получения размера блока сжатия алгоритма
 *
 * @param algorithm алгоритм хеширования
 *
 * @return          размер блока в байтах, ноль у неустановленного алгоритма
 *
 */
size_t nts::digest::block(const hash_t algorithm) noexcept {
	/**
	 * Выполняем определение размера блока по алгоритму
	 */
	switch(static_cast <uint8_t> (algorithm)){
		// Если выбран алгоритм с блоком в 64 байта
		case static_cast <uint8_t> (hash_t::MD5):
		case static_cast <uint8_t> (hash_t::SHA1):
		case static_cast <uint8_t> (hash_t::SHA224):
		case static_cast <uint8_t> (hash_t::SHA256):
		case static_cast <uint8_t> (hash_t::STREEBOG256):
		case static_cast <uint8_t> (hash_t::STREEBOG512): return 64;
		// Блоки BLAKE2s и BLAKE2b
		case static_cast <uint8_t> (hash_t::BLAKE2S256): return 64;
		case static_cast <uint8_t> (hash_t::BLAKE2B512): return 128;
		// Если выбран алгоритм с блоком в 128 байтов
		case static_cast <uint8_t> (hash_t::SHA384):
		case static_cast <uint8_t> (hash_t::SHA512): return 128;
		// Если алгоритм не установлен
		default: return 0;
	}
}
/**
 * @brief Метод получения выбранного алгоритма хеширования
 *
 * @return выбранный алгоритм хеширования
 *
 */
nts::digest::hash_t nts::digest::Hasher::type() const noexcept {
	// Выводим выбранный алгоритм хеширования
	return this->_type;
}
/**
 * @brief Метод сброса состояния хеширования
 *
 * @param algorithm алгоритм хеширования
 *
 */
void nts::digest::Hasher::reset(const hash_t algorithm) noexcept {
	// Запоминаем выбранный алгоритм хеширования
	this->_type = algorithm;
	/**
	 * Выполняем сброс объекта выбранного алгоритма
	 */
	switch(static_cast <uint8_t> (algorithm)){
		// Если выбран MD5
		case static_cast <uint8_t> (hash_t::MD5): this->_md5.reset(); break;
		// Если выбран SHA-1
		case static_cast <uint8_t> (hash_t::SHA1): this->_sha1.reset(); break;
		// Если выбран SHA-224
		case static_cast <uint8_t> (hash_t::SHA224): this->_sha2.reset(sha_t::SHA224); break;
		// Если выбран SHA-256
		case static_cast <uint8_t> (hash_t::SHA256): this->_sha2.reset(sha_t::SHA256); break;
		// Если выбран SHA-384
		case static_cast <uint8_t> (hash_t::SHA384): this->_sha2.reset(sha_t::SHA384); break;
		// Если выбран SHA-512
		case static_cast <uint8_t> (hash_t::SHA512): this->_sha2.reset(sha_t::SHA512); break;
		// Если выбран «Стрибог» длиной 256 разрядов
		case static_cast <uint8_t> (hash_t::STREEBOG256): this->_streebog.reset(type_t::SHORT); break;
		// Если выбран «Стрибог» длиной 512 разрядов
		case static_cast <uint8_t> (hash_t::STREEBOG512): this->_streebog.reset(type_t::LONG); break;
		// BLAKE2 заводится без ключа на полную длину
		case static_cast <uint8_t> (hash_t::BLAKE2S256): this->_blake2.start(blake_t::BLAKE2S, BLAKE2S_LENGTH, view_t()); break;
		case static_cast <uint8_t> (hash_t::BLAKE2B512): this->_blake2.start(blake_t::BLAKE2B, BLAKE2B_LENGTH, view_t()); break;
		// Если алгоритм не установлен
		default: this->_type = hash_t::NONE;
	}
}
/**
 * @brief Метод подачи куска сообщения
 *
 * @param data подаваемый кусок сообщения
 *
 */
void nts::digest::Hasher::update(const view_t & data) noexcept {
	/**
	 * Выполняем передачу куска объекту выбранного алгоритма
	 */
	switch(static_cast <uint8_t> (this->_type)){
		// Если выбран MD5
		case static_cast <uint8_t> (hash_t::MD5): this->_md5.update(data); break;
		// Если выбран SHA-1
		case static_cast <uint8_t> (hash_t::SHA1): this->_sha1.update(data); break;
		// Если выбран любой из SHA-2
		case static_cast <uint8_t> (hash_t::SHA224):
		case static_cast <uint8_t> (hash_t::SHA256):
		case static_cast <uint8_t> (hash_t::SHA384):
		case static_cast <uint8_t> (hash_t::SHA512): this->_sha2.update(data); break;
		// Если выбран «Стрибог»
		case static_cast <uint8_t> (hash_t::STREEBOG256):
		case static_cast <uint8_t> (hash_t::STREEBOG512): this->_streebog.update(data); break;
		// BLAKE2
		case static_cast <uint8_t> (hash_t::BLAKE2S256):
		case static_cast <uint8_t> (hash_t::BLAKE2B512): this->_blake2.update(data); break;
		// Если алгоритм не установлен
		default: break;
	}
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
bool nts::digest::Hasher::finish(uint8_t * result, const size_t size) noexcept {
	/**
	 * Выполняем снятие хеша с объекта выбранного алгоритма
	 */
	switch(static_cast <uint8_t> (this->_type)){
		// Если выбран MD5
		case static_cast <uint8_t> (hash_t::MD5): return this->_md5.finish(result, size);
		// Если выбран SHA-1
		case static_cast <uint8_t> (hash_t::SHA1): return this->_sha1.finish(result, size);
		// Если выбран любой из SHA-2
		case static_cast <uint8_t> (hash_t::SHA224):
		case static_cast <uint8_t> (hash_t::SHA256):
		case static_cast <uint8_t> (hash_t::SHA384):
		case static_cast <uint8_t> (hash_t::SHA512): return this->_sha2.finish(result, size);
		/**
		 * «Стрибог» требует места ровно под свой хеш, а общий договор дозволяет место
		 * шире: хеш снимается в свою длину, и лишнее место не трогается
		 */
		case static_cast <uint8_t> (hash_t::STREEBOG256):
		case static_cast <uint8_t> (hash_t::STREEBOG512): {
			// Длина хеша «Стрибог»
			const size_t needed = static_cast <size_t> (this->_streebog.type());
			// Если места под хеш не хватает
			if((result == nullptr) || (size < needed))
				// Выводим отказ снятия хеша
				return false;
			// Выводим итог снятия хеша в его длину
			return this->_streebog.finish(result, needed);
		}
		// BLAKE2: итог ровно длины разновидности
		case static_cast <uint8_t> (hash_t::BLAKE2S256):
		case static_cast <uint8_t> (hash_t::BLAKE2B512): {
			// Длина итога
			const size_t needed = this->_blake2.length();
			// Если место не передано либо короче итога
			if((result == nullptr) || (size < needed))
				// Выводим отказ
				return false;
			// Выводим итог снятия
			return this->_blake2.finish(result, needed);
		}
		// Если алгоритм не установлен
		default: return false;
	}
}
/**
 * @brief Конструктор
 *
 * @param algorithm алгоритм хеширования
 *
 */
nts::digest::Hasher::Hasher(const hash_t algorithm) noexcept : _type(hash_t::NONE) {
	// Выполняем сброс состояния под выбранный алгоритм
	this->reset(algorithm);
}
/**
 * @brief Метод выработки хеша целого сообщения выбранным алгоритмом
 *
 * @param algorithm алгоритм хеширования
 * @param data      хешируемое сообщение
 * @param result    место, в которое записывается хеш
 * @param size      размер места в байтах, не меньше длины хеша
 *
 * @return          признак успешности выработки хеша
 *
 */
bool nts::digest::hash(const hash_t algorithm, const view_t & data, uint8_t * result, const size_t size) noexcept {
	// Объект хеширования выбранным алгоритмом
	hasher_t hasher(algorithm);
	// Выполняем подачу целого сообщения
	hasher.update(data);
	// Выводим итог снятия хеша
	return hasher.finish(result, size);
}
