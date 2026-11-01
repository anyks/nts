/**
 * @file kdf.cpp
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
 * @brief Исходный файл модуля функции выработки производного ключа по RFC 7836
 *
 * @note Слитная строка складывается на стеке и затирается: через неё проходит затравка
 *       выработки ключа, а у протокола TLS затравкой служит порядковый номер записи
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
#include <digest/kdf.hpp>
#include <digest/hmac.hpp>
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

	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;
};

/**
 * @brief Функция выработки производного ключа
 *
 * @param key    ключ выработки производного ключа
 * @param label  метка назначения производного ключа
 * @param seed   затравка выработки производного ключа
 * @param result место, в которое помещается производный ключ
 * @return       признак успешности выработки производного ключа
 *
 */
bool nts::digest::kdf(const view_t & key, const view_t & label, const view_t & seed, uint8_t * result) noexcept {
	// Если место для производного ключа не передано
	if(result == nullptr)
		// Выводим отказ выработки производного ключа
		return false;
	// Если метка либо затравка объявлены непустыми, но не переданы
	if(((label.size > 0) && (label.data == nullptr)) || ((seed.size > 0) && (seed.data == nullptr)))
		// Выводим отказ выработки производного ключа
		return false;
	// Если метка или затравка выработки ключа длиннее дозволенного
	if((label.size > KDF_LIMIT) || (seed.size > KDF_LIMIT))
		// Выводим отказ выработки производного ключа
		return false;
	// Слитная строка, на которой вырабатывается производный ключ
	uint8_t buffer[(KDF_LIMIT * 2) + 4];
	// Число уже записанных байтов слитной строки
	size_t offset = 0;
	// Записываем порядковый номер части производного ключа
	buffer[offset++] = 0x01;
	// Если метка назначения производного ключа передана
	if((label.data != nullptr) && (label.size > 0)){
		// Записываем метку назначения производного ключа
		::memcpy(buffer + offset, label.data, label.size);
		// Увеличиваем число записанных байтов слитной строки
		offset += label.size;
	}
	// Записываем разделитель метки и затравки
	buffer[offset++] = 0x00;
	// Если затравка выработки производного ключа передана
	if((seed.data != nullptr) && (seed.size > 0)){
		// Записываем затравку выработки производного ключа
		::memcpy(buffer + offset, seed.data, seed.size);
		// Увеличиваем число записанных байтов слитной строки
		offset += seed.size;
	}
	// Записываем старший байт длины вырабатываемого ключа в разрядах
	buffer[offset++] = 0x01;
	// Записываем младший байт длины вырабатываемого ключа в разрядах
	buffer[offset++] = 0x00;
	// Выполняем выработку производного ключа
	const bool ok = nts::digest::hmac(type_t::SHORT, key, view_t(buffer, offset), result, KDF_KEY);
	// Выполняем затирание слитной строки выработки ключа
	wipe(buffer, sizeof(buffer));
	// Выводим признак успешности выработки производного ключа
	return ok;
}

/**
 * @brief Функция выработки ключа пользователя SNMPv3 из пароля
 *
 * @param algorithm алгоритм хеша: MD5, SHA-1 либо SHA-2 по RFC 7860
 * @param password  пароль пользователя
 * @param engine    опознаватель полномочного движка SNMP (snmpEngineID)
 * @param result    место, в которое помещается локализованный ключ
 * @return          признак успешности выработки ключа
 *
 */
bool nts::digest::snmpv3(const hash_t algorithm, const view_t & password, const view_t & engine, uint8_t * result) noexcept {
	// Длина хеша алгоритма
	const size_t width = nts::digest::length(algorithm);
	// Если алгоритм неизвестен, пароль пуст либо место итога не передано
	if((width == 0) || (password.data == nullptr) || (password.size == 0) || (engine.data == nullptr) || (result == nullptr))
		// Выводим отказ выработки ключа
		return false;
	// Объект хеширования
	nts::digest::hasher_t hasher(algorithm);
	// Буфер повторов пароля: 64 байта за подачу
	uint8_t buffer[64];
	// Место пароля в очередном повторе
	size_t index = 0;
	// Число уже поданных байтов
	size_t count = 0;
	/**
	 * Приложение A.2 RFC 3414: пароль повторяется до одного мегабайта и хешируется
	 */
	while(count < 1048576){
		/**
		 * Заполняем буфер очередными байтами пароля с переходом к его началу
		 */
		for(size_t i = 0; i < sizeof(buffer); i++)
			// Байт пароля по кругу
			buffer[i] = password.data[index++ % password.size];
		// Подаём буфер в хеш
		hasher.update(view_t(buffer, sizeof(buffer)));
		// Считаем поданные байты
		count += sizeof(buffer);
	}
	// Место, в которое помещается ключ Ku
	uint8_t key[64];
	// Если ключ Ku снять не удалось
	if(!hasher.finish(key, width)){
		// Выполняем затирание буфера
		wipe(buffer, sizeof(buffer));
		// Выводим отказ выработки ключа
		return false;
	}
	// Сбрасываем состояние хеширования
	hasher.reset(algorithm);
	// Подаём ключ Ku
	hasher.update(view_t(key, width));
	// Подаём опознаватель движка
	hasher.update(engine);
	// Подаём ключ Ku повторно
	hasher.update(view_t(key, width));
	// Если локализованный ключ Kul снять не удалось
	if(!hasher.finish(result, width)){
		// Выполняем затирание рабочих областей
		wipe(key, sizeof(key));
		wipe(buffer, sizeof(buffer));
		// Выводим отказ выработки ключа
		return false;
	}
	// Выполняем затирание рабочих областей
	wipe(key, sizeof(key));
	wipe(buffer, sizeof(buffer));
	// Выводим признак успешности выработки ключа
	return true;
}

/**
 * @brief Функция выработки ключевого материала prf+ протокола IKEv2
 *
 * @param algorithm алгоритм хеша псевдослучайной функции
 * @param key       ключ псевдослучайной функции
 * @param seed      затравка выработки
 * @param result    место, в которое помещается ключевой материал
 * @param size      требуемая длина ключевого материала в байтах
 * @return          признак успешности выработки ключевого материала
 *
 */
bool nts::digest::prfplus(const hash_t algorithm, const view_t & key, const view_t & seed, uint8_t * result, const size_t size) noexcept {
	// Длина хеша алгоритма
	const size_t width = nts::digest::length(algorithm);
	// Если алгоритм неизвестен, ключ либо затравка не переданы, место итога пусто
	if((width == 0) || (key.data == nullptr) || (seed.data == nullptr) || (result == nullptr) || (size == 0))
		// Выводим отказ выработки ключевого материала
		return false;
	// Место звена цепочки T
	uint8_t link[64];
	// Число уже выработанных байтов итога
	size_t offset = 0;
	// Порядковый номер звена цепочки
	uint8_t round = 1;
	// Признак первого звена: оно хеширует затравку без прежнего звена
	bool first = true;
	/**
	 * Раздел 2.13 RFC 7296: T1 = prf(K, S ‖ 0x01), T2 = prf(K, T1 ‖ S ‖ 0x02), ...
	 */
	while(offset < size){
		// Объект имитовставки
		nts::digest::mac_t mac;
		// Если ключ имитовставки установить не удалось
		if(!mac.start(algorithm, key)){
			// Выполняем затирание звена
			wipe(link, sizeof(link));
			// Выводим отказ выработки ключевого материала
			return false;
		}
		// Если звено не первое, подаём прежнее звено
		if(!first)
			// Подача прежнего звена цепочки
			mac.update(view_t(link, width));
		// Подаём затравку
		mac.update(seed);
		// Подаём порядковый номер звена
		mac.update(view_t(&round, 1));
		// Если звено цепочки снять не удалось
		if(!mac.finish(link, width)){
			// Выполняем затирание звена
			wipe(link, sizeof(link));
			// Выводим отказ выработки ключевого материала
			return false;
		}
		// Длина куска итога из этого звена
		const size_t chunk = ((size - offset) < width) ? (size - offset) : width;
		// Переносим кусок звена в итог
		::memcpy(result + offset, link, chunk);
		// Считаем выработанные байты
		offset += chunk;
		// Следующее звено уже не первое
		first = false;
		// Наращиваем порядковый номер звена
		round++;
	}
	// Выполняем затирание звена цепочки
	wipe(link, sizeof(link));
	// Выводим признак успешности выработки ключевого материала
	return true;
}
