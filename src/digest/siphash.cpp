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
 * Подключаем заголовочный файл проекта
 */
#include "sys/wipe.hpp"

/**
 * Подключаем заголовочный файл модуля
 */
#include "digest/siphash.hpp"

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
	 * @brief Функция кругового сдвига влево
	 *
	 * @param word  слово
	 * @param count количество разрядов
	 * @return      сдвинутое слово
	 *
	 */
	static constexpr uint64_t __nts_spin__(const uint64_t word, const size_t count) noexcept {
		// Выводим сдвиг
		return ((word << count) | (word >> (64 - count)));
	}
	/**
	 * @brief Функция Круг SipHash
	 *
	 * @param v состояние из четырёх слов
	 *
	 */
	static __NTS_INLINE__ void __nts_round__(uint64_t * v) noexcept {
		// Первое слово складывается со вторым, второе сдвигается и складывается по модулю два с первым, первое сдвигается
		v[0] += v[1]; v[1] = __nts_spin__(v[1], 13); v[1] ^= v[0]; v[0] = __nts_spin__(v[0], 32);
		// Третье слово складывается с четвёртым, четвёртое сдвигается и складывается по модулю два с третьим
		v[2] += v[3]; v[3] = __nts_spin__(v[3], 16); v[3] ^= v[2];
		// Первое слово складывается с четвёртым, четвёртое сдвигается и складывается по модулю два с первым
		v[0] += v[3]; v[3] = __nts_spin__(v[3], 21); v[3] ^= v[0];
		// Третье слово складывается со вторым, второе сдвигается и складывается по модулю два с третьим, третье сдвигается
		v[2] += v[1]; v[1] = __nts_spin__(v[1], 17); v[1] ^= v[2]; v[2] = __nts_spin__(v[2], 32);
	}
	/**
	 * @brief Функция чтения слова от младшего байта
	 *
	 * @param data байты
	 * @param size количество байтов (до восьми)
	 * @return     слово
	 *
	 */
	static __NTS_INLINE__ uint64_t __nts_octet__(const uint8_t * data, const size_t size) noexcept {
		// Собираемое слово
		uint64_t result = 0;
		/**
		 * Перебираем байты
		 */
		for(size_t i = 0; i < size; i++)
			// Складываем байт
			result |= (static_cast <uint64_t> (data[i]) << (8 * i));
		// Выводим слово
		return result;
	}
};

/**
 * @brief Функция вычисления SipHash-2-4
 *
 * @param key    ключ в шестнадцать байтов
 * @param data   сообщение любой длины
 * @param result место, в которое помещается итог
 * @param size   длина итога: 8 либо 16
 * @return       признак того, что итог вычислен
 *
 */
bool nts::digest::siphash(const view_t & key, const view_t & data, uint8_t * result, const size_t size) noexcept {
	// Если ключ, место либо длина итога негодны
	if((key.data == nullptr) || (key.size != SIPHASH_KEY) || (result == nullptr) || ((size != 8) && (size != 16)) || ((data.size > 0) && (data.data == nullptr)))
		// Выводим отрицательный результат - ключ, место либо длина итога негодны
		return false;
	// Слова ключа
	const uint64_t k0 = ::__nts_octet__(key.data, 8), k1 = ::__nts_octet__(key.data + 8, 8);
	// Состояние: константы «somepseudorandomlygeneratedbytes», сложенные с ключом
	uint64_t v[4] = {
		// Константы, сложенные с парами слов ключа
		(0x736F6D6570736575ULL ^ k0), (0x646F72616E646F6DULL ^ k1),
		(0x6C7967656E657261ULL ^ k0), (0x7465646279746573ULL ^ k1)
	};
	// У итога в 128 разрядов второе слово складывается с 0xEE
	if(size == 16)
		// Складываем признак длины 128 разрядов
		v[1] ^= 0xEE;
	// Количество полных слов сообщения
	const size_t whole = (data.size / 8);
	/**
	 * Перебираем полные слова сообщения
	 */
	for(size_t i = 0; i < whole; i++){
		// Слово сообщения
		const uint64_t m = ::__nts_octet__(data.data + (i * 8), 8);
		// Складываем со четвёртым словом
		v[3] ^= m;
		// Два круга сжатия
		::__nts_round__(v);
		::__nts_round__(v);
		// Складываем с первым словом
		v[0] ^= m;
	}
	// Последнее слово: остаток и длина сообщения в старшем байте
	const uint64_t last = (::__nts_octet__(data.data + (whole * 8), data.size - (whole * 8)) | (static_cast <uint64_t> (data.size & 0xFF) << 56));
	// Складываем последнее слово
	v[3] ^= last;
	// Два круга сжатия
	::__nts_round__(v);
	::__nts_round__(v);
	// Складываем с первым словом
	v[0] ^= last;
	// Завершение: третье слово складывается с 0xFF (64) либо 0xEE (128)
	v[2] ^= ((size == 16) ? 0xEE : 0xFF);
	// Четыре круга завершения
	::__nts_round__(v); ::__nts_round__(v); ::__nts_round__(v); ::__nts_round__(v);
	// Первое слово итога
	uint64_t first = (v[0] ^ v[1] ^ v[2] ^ v[3]);
	/**
	 * Записываем первое слово от младшего байта
	 */
	for(size_t i = 0; i < 8; i++)
		// Байт итога
		result[i] = static_cast <uint8_t> (first >> (8 * i));
	// Если итог в 128 разрядов
	if(size == 16){
		// Второе слово складывается с 0xDD
		v[1] ^= 0xDD;
		// Четыре круга завершения
		::__nts_round__(v); ::__nts_round__(v); ::__nts_round__(v); ::__nts_round__(v);
		// Второе слово итога
		const uint64_t second = (v[0] ^ v[1] ^ v[2] ^ v[3]);
		/**
		 * Записываем второе слово
		 */
		for(size_t i = 0; i < 8; i++)
			// Байт итога
			result[8 + i] = static_cast <uint8_t> (second >> (8 * i));
	}
	// Затирание состояния
	wipe(v, sizeof(v));
	// Затирание первого слова
	first = 0;
	// Сообщаем об успешном снятии итога
	return true;
}
/**
 * @brief Функция вычисления SipHash-2-4 числом
 *
 * @param key    ключ в шестнадцать байтов
 * @param data   сообщение любой длины
 * @param result число, в которое помещается 64-разрядный итог
 * @return       признак того, что итог вычислен
 *
 */
bool nts::digest::siphash(const view_t & key, const view_t & data, uint64_t & result) noexcept {
	// Байты итога
	uint8_t bytes[8];
	// Если итог вычислить не удалось
	if(!siphash(key, data, bytes, sizeof(bytes)))
		// Выводим отрицательный результат - итог вычислить не удалось
		return false;
	// Собираем число от младшего байта
	result = 0;
	/**
	 * Перебираем байты итога
	 */
	for(size_t i = 0; i < 8; i++)
		// Присоединяем очередной байт итога
		result |= (static_cast <uint64_t> (bytes[i]) << (8 * i));
	// Сообщаем об успешном собирании числа
	return true;
}
