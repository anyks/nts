/**
 * @file cshake.cpp
 * @date 2026-10-05
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
 * @brief Исходный файл модуля настраиваемых функций переменного выхода cSHAKE
 *        и имитовставок KMAC по SP 800-185
 *
 * @section Намеренные решения
 *
 * 1. Модуль стоит поверх губки Keccak (digest::sha3): записи кодирования SP 800-185
 *    собираются в накопитель и поглощаются как обычное сообщение, а отличие cSHAKE
 *    от SHAKE - одним байтом начала дополнения (0x04 вместо 0x1F), который губка
 *    ставит по разновидности CSHAKE128/CSHAKE256. Своей перестановки здесь нет и
 *    быть не может.
 *
 * 2. Записи собираются целиком в накопитель до поглощения: их части коротки
 *    (имя, настройка, ключ), а сбор по кускам размазал бы кодирование длин по
 *    нескольким вызовам update без выигрыша ни в памяти, ни в ходе.
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
#include <digest/cshake.hpp>
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
	 * Затирание областей памяти берётся из открытого API библиотеки
	 */
	using nts::sys::wipe;

	/**
	 * Имя функции имитовставки: раздел 4 SP 800-185
	 */
	static const char * KMAC = "KMAC";

	/**
	 * @brief Функция записи числа кодированием left_encode
	 *
	 * @param value  записываемое число: длина строки в разрядах либо скорость в байтах
	 * @param result накопитель, в конец которого дописывается запись
	 *
	 * @details Раздел 2.2 SP 800-185: запись есть n ‖ x, где n - длина записи числа
	 *          одним байтом, а x - само число от старшего байта к младшему
	 *
	 */
	void __ants_left_encode__(const uint64_t value, vector <uint8_t> & result) {
		// Число значащих байтов записываемого числа
		size_t width = 1;
		/**
		 * Считаем значащие байты записываемого числа
		 */
		for(uint64_t rest = (value >> 8); rest != 0; rest >>= 8)
			// Учитываем очередной значащий байт
			width++;
		// Записываем длину записи числа
		result.push_back(static_cast <uint8_t> (width));
		/**
		 * Выполняем перебор байтов числа от старшего к младшему
		 */
		for(size_t i = width; i > 0; i--)
			// Записываем очередной байт числа
			result.push_back(static_cast <uint8_t> (value >> ((i - 1) * 8)));
	}
	/**
	 * @brief Функция записи числа кодированием right_encode
	 *
	 * @param value  записываемое число: длина итога в разрядах
	 * @param result накопитель, в конец которого дописывается запись
	 *
	 * @details Раздел 2.2 SP 800-185: запись есть x ‖ n, где x - число от старшего
	 *          байта к младшему, а n - длина записи числа одним байтом
	 *
	 */
	void __ants_right_encode__(const uint64_t value, vector <uint8_t> & result) {
		// Число значащих байтов записываемого числа
		size_t width = 1;
		/**
		 * Считаем значащие байты записываемого числа
		 */
		for(uint64_t rest = (value >> 8); rest != 0; rest >>= 8)
			// Учитываем очередной значащий байт
			width++;
		/**
		 * Выполняем перебор байтов числа от старшего к младшему
		 */
		for(size_t i = width; i > 0; i--)
			// Записываем очередной байт числа
			result.push_back(static_cast <uint8_t> (value >> ((i - 1) * 8)));
		// Записываем длину записи числа
		result.push_back(static_cast <uint8_t> (width));
	}
	/**
	 * @brief Функция записи строки кодированием encode_string
	 *
	 * @param data   записываемая строка
	 * @param result накопитель, в конец которого дописывается запись
	 *
	 * @details Раздел 2.2 SP 800-185: запись есть left_encode(длина в разрядах) ‖ строка
	 *
	 */
	void __ants_encode_string__(const view_t & data, vector <uint8_t> & result) {
		// Записываем длину строки в разрядах
		__ants_left_encode__(static_cast <uint64_t> (data.size) * 8, result);
		// Записываем саму строку
		result.insert(result.end(), data.data, data.data + data.size);
	}
	/**
	 * @brief Функция записи строки дополнением до кратности скорости
	 *
	 * @param data   записываемая строка
	 * @param rate   скорость разновидности в байтах
	 * @param result накопитель, в конец которого дописывается запись
	 *
	 * @details Раздел 2.2 SP 800-185: запись есть left_encode(rate) ‖ строка ‖ нули
	 *          до длины, кратной скорости
	 *
	 */
	void bytepad(const view_t & data, const size_t rate, vector <uint8_t> & result) {
		// Длина записи до дополнения: длина префикса скорости и длина строки
		const size_t before = (result.size() + 2 + data.size);
		// Записываем скорость разновидности: у скоростей Keccak запись всегда двухбайтовая
		__ants_left_encode__(static_cast <uint64_t> (rate), result);
		// Записываем саму строку
		result.insert(result.end(), data.data, data.data + data.size);
		// Дописываем нули до длины записи, кратной скорости
		result.insert(result.end(), ((rate - (before % rate)) % rate), 0);
	}
	/**
	 * @brief Функция получения разновидности cSHAKE по разновидности SHAKE
	 *
	 * @param type разновидность функции: SHAKE128 либо SHAKE256
	 * @return     разновидность cSHAKE той же скорости либо NONE у чужой разновидности
	 *
	 */
	digest::sha3_t customized(const digest::sha3_t type) noexcept {
		// Если разновидность - SHAKE128
		if(type == digest::sha3_t::SHAKE128)
			// Выводим разновидность cSHAKE128
			return digest::sha3_t::CSHAKE128;
		// Если разновидность - SHAKE256
		if(type == digest::sha3_t::SHAKE256)
			// Выводим разновидность cSHAKE256
			return digest::sha3_t::CSHAKE256;
		// Выводим отсутствие разновидности у чужой функции
		return digest::sha3_t::NONE;
	}
};

/**
 * @brief Функция вычисления cSHAKE за один вызов
 *
 * @param type   разновидность функции: SHAKE128 либо SHAKE256
 * @param data   сообщение
 * @param name   имя функции N; пустое вместе с пустой настройкой даёт ровно SHAKE
 * @param custom настройка S, задаваемая потребителем
 * @param result место, в которое помещается итог
 * @param size   длина итога в байтах
 * @return       признак того, что итог вычислен
 *
 */
bool nts::digest::cshake(const sha3_t type, const view_t & data, const view_t & name, const view_t & custom, uint8_t * result, const size_t size) noexcept {
	// Если место итога не передано
	if((result == nullptr) || (size == 0))
		// Выводим отказ вычисления итога
		return false;
	// Если имя и настройка пусты, функция есть ровно SHAKE той же разновидности (раздел 3.1 SP 800-185)
	if(((name.data == nullptr) || (name.size == 0)) && ((custom.data == nullptr) || (custom.size == 0)))
		// Выводим итог вычисления SHAKE
		return nts::digest::sha3(type, data, result, size);
	// Разновидность cSHAKE той же скорости
	const sha3_t kind = ::customized(type);
	// Если разновидность чужая
	if(kind == sha3_t::NONE)
		// Выводим отказ вычисления итога
		return false;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Накопитель записи bytepad(encode_string(N) ‖ encode_string(S), rate)
		vector <uint8_t> prefix;
		// Накопитель записи имени и настройки
		vector <uint8_t> both;
		// Записываем имя функции
		::__ants_encode_string__(name, both);
		// Записываем настройку потребителя
		::__ants_encode_string__(custom, both);
		// Записываем строку имени и настройки дополнением до кратности скорости
		::bytepad(view_t(both.data(), both.size()), rate(kind), prefix);
		// Объект губки настраиваемой разновидности
		keccak_t sponge(kind);
		// Поглощаем запись кодирования и сообщение, выжимаем итог запрошенной длины
		return (sponge.update(view_t(prefix.data(), prefix.size())) && sponge.update(data) && sponge.finish(result, size));
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ вычисления итога
		return false;
	}
}
/**
 * @brief Функция вычисления имитовставки KMAC за один вызов
 *
 * @param type   разновидность функции: SHAKE128 либо SHAKE256
 * @param key    ключ имитовставки
 * @param data   сообщение
 * @param custom настройка S, задаваемая потребителем
 * @param result место, в которое помещается имитовставка
 * @param size   длина имитовставки в байтах
 * @return       признак того, что имитовставка вычислена
 *
 */
bool nts::digest::kmac(const sha3_t type, const view_t & key, const view_t & data, const view_t & custom, uint8_t * result, const size_t size) noexcept {
	// Если ключа либо места итога нет
	if((key.data == nullptr) || (key.size == 0) || (result == nullptr) || (size == 0))
		// Выводим отказ вычисления имитовставки
		return false;
	// Разновидность cSHAKE той же скорости
	const sha3_t kind = ::customized(type);
	// Если разновидность чужая
	if(kind == sha3_t::NONE)
		// Выводим отказ вычисления имитовставки
		return false;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Накопитель записи bytepad(encode_string(K), rate) ‖ X ‖ right_encode(L)
		vector <uint8_t> message;
		// Накопитель записи ключа
		vector <uint8_t> encoded;
		// Записываем ключ имитовставки
		::__ants_encode_string__(key, encoded);
		// Записываем строку ключа дополнением до кратности скорости
		::bytepad(view_t(encoded.data(), encoded.size()), rate(kind), message);
		// Записываем сообщение
		message.insert(message.end(), data.data, data.data + data.size);
		// Записываем длину имитовставки в разрядах
		::__ants_right_encode__(static_cast <uint64_t> (size) * 8, message);
		// Имя функции имитовставки
		const view_t naming(reinterpret_cast <const uint8_t *> (::KMAC), ::strlen(::KMAC));
		// Выводим итог вычисления cSHAKE с именем «KMAC»
		return nts::digest::cshake(type, view_t(message.data(), message.size()), naming, custom, result, size);
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ вычисления имитовставки
		return false;
	}
}
/**
 * @brief Функция вычисления имитовставки KMAC переменной длины за один вызов
 *
 * @param type   разновидность функции: SHAKE128 либо SHAKE256
 * @param key    ключ имитовставки
 * @param data   сообщение
 * @param custom настройка S, задаваемая потребителем
 * @param result место, в которое помещается имитовставка
 * @param size   длина имитовставки в байтах
 * @return       признак того, что имитовставка вычислена
 *
 */
bool nts::digest::kmacxof(const sha3_t type, const view_t & key, const view_t & data, const view_t & custom, uint8_t * result, const size_t size) noexcept {
	// Если ключа либо места итога нет
	if((key.data == nullptr) || (key.size == 0) || (result == nullptr) || (size == 0))
		// Выводим отказ вычисления имитовставки
		return false;
	// Разновидность cSHAKE той же скорости
	const sha3_t kind = ::customized(type);
	// Если разновидность чужая
	if(kind == sha3_t::NONE)
		// Выводим отказ вычисления имитовставки
		return false;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Накопитель записи bytepad(encode_string(K), rate) ‖ X ‖ right_encode(0)
		vector <uint8_t> message;
		// Накопитель записи ключа
		vector <uint8_t> encoded;
		// Записываем ключ имитовставки
		::__ants_encode_string__(key, encoded);
		// Записываем строку ключа дополнением до кратности скорости
		::bytepad(view_t(encoded.data(), encoded.size()), rate(kind), message);
		// Записываем сообщение
		message.insert(message.end(), data.data, data.data + data.size);
		// Записываем нулевую длину итога: раздел 4.3.1 SP 800-185
		::__ants_right_encode__(0, message);
		// Имя функции имитовставки
		const view_t naming(reinterpret_cast <const uint8_t *> (::KMAC), ::strlen(::KMAC));
		// Выводим итог вычисления cSHAKE с именем «KMAC»
		return nts::digest::cshake(type, view_t(message.data(), message.size()), naming, custom, result, size);
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ вычисления имитовставки
		return false;
	}
}
