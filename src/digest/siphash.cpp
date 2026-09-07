/**
 * @file siphash.cpp
 * @date 2026-09-07
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
 * @brief Модуль ключевой хеш-функции SipHash-2-4
 *
 * @details Четыре слова состояния из ключа и констант «somepseudorandomlygeneratedbytes»,
 *          сообщение словами по восемь байтов от младшего, последнее слово несёт длину
 *          сообщения в старшем байте; у итога в 128 разрядов второе слово состояния
 *          складывается с 0xEE, а перед вторым завершением первое - с 0xDD
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <digest/siphash.hpp>
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
	 * @brief Метод кругового сдвига влево
	 *
	 * @param word  слово
	 * @param count число разрядов
	 *
	 * @return      сдвинутое слово
	 *
	 */
	static inline uint64_t spin(const uint64_t word, const size_t count) noexcept {
		// Выводим сдвиг
		return ((word << count) | (word >> (64 - count)));
	}
	/**
	 * @brief Круг SipHash
	 *
	 * @param v состояние из четырёх слов
	 *
	 */
	static inline void round(uint64_t * v) noexcept {
		v[0] += v[1]; v[1] = spin(v[1], 13); v[1] ^= v[0]; v[0] = spin(v[0], 32);
		v[2] += v[3]; v[3] = spin(v[3], 16); v[3] ^= v[2];
		v[0] += v[3]; v[3] = spin(v[3], 21); v[3] ^= v[0];
		v[2] += v[1]; v[1] = spin(v[1], 17); v[1] ^= v[2]; v[2] = spin(v[2], 32);
	}
	/**
	 * @brief Метод чтения слова от младшего байта
	 *
	 * @param data байты
	 * @param size число байтов (до восьми)
	 *
	 * @return     слово
	 *
	 */
	static inline uint64_t octet(const uint8_t * data, const size_t size) noexcept {
		// Собираемое слово
		uint64_t result = 0;
		/**
		 * Выполняем перебор байтов
		 */
		for(size_t i = 0; i < size; i++)
			// Складываем байт
			result |= (static_cast <uint64_t> (data[i]) << (8 * i));
		// Выводим слово
		return result;
	}
};

/**
 * \~russian
 * @brief Метод вычисления SipHash-2-4
 *
 * @param key    ключ в шестнадцать байтов
 * @param data   сообщение
 * @param result место итога
 * @param size   длина итога: 8 либо 16
 *
 * @return       признак того, что итог вычислен
 *
 * \~english
 * @brief Method of the computation of SipHash-2-4
 *
 * @param key    key of sixteen bytes
 * @param data   message
 * @param result place of the result
 * @param size   length of the result: 8 or 16
 *
 * @return       sign that the result is computed
 *
 * \~
 */
bool nts::digest::siphash(const view_t & key, const view_t & data, uint8_t * result, const size_t size) noexcept {
	// Если ключ, место либо длина итога негодны
	if((key.data == nullptr) || (key.size != SIPHASH_KEY) || (result == nullptr) || ((size != 8) && (size != 16)) || ((data.size > 0) && (data.data == nullptr)))
		// Выводим отказ
		return false;
	// Слова ключа
	const uint64_t k0 = octet(key.data, 8), k1 = octet(key.data + 8, 8);
	// Состояние: константы «somepseudorandomlygeneratedbytes», сложенные с ключом
	uint64_t v[4] = {
		(0x736F6D6570736575ULL ^ k0), (0x646F72616E646F6DULL ^ k1),
		(0x6C7967656E657261ULL ^ k0), (0x7465646279746573ULL ^ k1)
	};
	// У итога в 128 разрядов второе слово складывается с 0xEE
	if(size == 16)
		// Складываем
		v[1] ^= 0xEE;
	// Число полных слов сообщения
	const size_t whole = (data.size / 8);
	/**
	 * Выполняем перебор полных слов сообщения
	 */
	for(size_t i = 0; i < whole; i++){
		// Слово сообщения
		const uint64_t m = octet(data.data + (i * 8), 8);
		// Складываем со четвёртым словом
		v[3] ^= m;
		// Два круга сжатия
		round(v);
		round(v);
		// Складываем с первым словом
		v[0] ^= m;
	}
	// Последнее слово: остаток и длина сообщения в старшем байте
	const uint64_t last = (octet(data.data + (whole * 8), data.size - (whole * 8)) | (static_cast <uint64_t> (data.size & 0xFF) << 56));
	// Складываем последнее слово
	v[3] ^= last;
	// Два круга сжатия
	round(v);
	round(v);
	// Складываем с первым словом
	v[0] ^= last;
	// Завершение: третье слово складывается с 0xFF (64) либо 0xEE (128)
	v[2] ^= ((size == 16) ? 0xEE : 0xFF);
	// Четыре круга завершения
	round(v); round(v); round(v); round(v);
	// Первое слово итога
	uint64_t first = (v[0] ^ v[1] ^ v[2] ^ v[3]);
	/**
	 * Выполняем запись первого слова от младшего байта
	 */
	for(size_t i = 0; i < 8; i++)
		// Байт итога
		result[i] = static_cast <uint8_t> (first >> (8 * i));
	// Если итог в 128 разрядов
	if(size == 16){
		// Второе слово складывается с 0xDD
		v[1] ^= 0xDD;
		// Четыре круга завершения
		round(v); round(v); round(v); round(v);
		// Второе слово итога
		const uint64_t second = (v[0] ^ v[1] ^ v[2] ^ v[3]);
		/**
		 * Выполняем запись второго слова
		 */
		for(size_t i = 0; i < 8; i++)
			// Байт итога
			result[8 + i] = static_cast <uint8_t> (second >> (8 * i));
	}
	// Выполняем затирание состояния
	wipe(v, sizeof(v));
	// Выполняем затирание первого слова
	first = 0;
	// Выводим успешность
	return true;
}
/**
 * \~russian
 * @brief Метод вычисления SipHash-2-4 числом
 *
 * @param key    ключ в шестнадцать байтов
 * @param data   сообщение
 * @param result 64-разрядный итог
 *
 * @return       признак того, что итог вычислен
 *
 * \~english
 * @brief Method of the computation of SipHash-2-4 as a number
 *
 * @param key    key of sixteen bytes
 * @param data   message
 * @param result 64-bit result
 *
 * @return       sign that the result is computed
 *
 * \~
 */
bool nts::digest::siphash(const view_t & key, const view_t & data, uint64_t & result) noexcept {
	// Байты итога
	uint8_t bytes[8];
	// Если итог вычислить не удалось
	if(!siphash(key, data, bytes, sizeof(bytes)))
		// Выводим отказ
		return false;
	// Собираем число от младшего байта
	result = 0;
	for(size_t i = 0; i < 8; i++)
		result |= (static_cast <uint64_t> (bytes[i]) << (8 * i));
	// Выводим успешность
	return true;
}
