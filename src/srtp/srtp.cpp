/**
 * @file srtp.cpp
 * @date 2026-10-06
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
 * \~russian
 * @brief Модуль защиты транспорта реального времени —
 *        защищённые пакеты RTP и RTCP по RFC 3711,
 *        режим AES-GCM по RFC 7714
 *
 * \~english
 * @brief The secure real-time transport module —
 *        the protected RTP and RTCP packets according to RFC 3711,
 *        the AES-GCM mode according to RFC 7714
 *
 * \~
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <srtp/srtp.hpp>
#include <cipher/aes.hpp>
#include <cipher/gcm.hpp>
#include <digest/hmac.hpp>
#include <sys/wipe.hpp>

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
	 * Размер блока шифра AES в байтах
	 */
	static constexpr size_t BLOCK = 16;

	/**
	 * Длина заголовка пакета RTP без расширений в байтах
	 */
	static constexpr size_t RTP_HEADER = 12;

	/**
	 * Длина метки AEAD в байтах
	 */
	static constexpr size_t AEAD_TAG = 16;

	/**
	 * Разрядность окна приёма против повторов
	 */
	static constexpr uint8_t WINDOW = 64;

	/**
	 * @brief Метод получения длины метки имитовставки профиля в байтах
	 *
	 * @param profile профиль защиты
	 *
	 * @return        длина метки: 10, 4 либо 16 у AEAD; ноль у неизвестного профиля
	 *
	 */
	static size_t tagLength(const nts::srtp::profile_t profile) noexcept {
		// По профилю защиты
		switch(profile){
			// AES-CM со имитовставкой HMAC-SHA1-80
			case nts::srtp::profile_t::AES128_CM_SHA1_80:
				// Метка в десять байтов
				return 10;
			// AES-CM со имитовставкой HMAC-SHA1-32
			case nts::srtp::profile_t::AES128_CM_SHA1_32:
				// Метка в четыре байта
				return 4;
			// Профили AES-GCM
			case nts::srtp::profile_t::AEAD_AES_128_GCM:
			case nts::srtp::profile_t::AEAD_AES_256_GCM:
				// Метка AEAD в шестнадцать байтов
				return AEAD_TAG;
			// Профиль неизвестен
			default:
				// Выводим ноль
				return 0;
		}
	}

	/**
	 * @brief Метод вывода ключевого потока PRF по разделу 4.3 RFC 3711
	 *
	 * @param key    мастер-ключ
	 * @param salt   мастер-соль (14 либо 12 байтов)
	 * @param label  метка выводимого ключа (0x00..0x02)
	 * @param result место, в которое записывается ключевой поток
	 * @param size   длина ключевого потока в байтах
	 *
	 * @return       отказ вывода
	 *
	 * @details Вход PRF: x = (метка ‖ index DIV kdr) XOR мастер-соль,
	 *          дополненный двумя нулевыми байтами; частота вывода нулевая,
	 *          потому index DIV kdr - шесть нулевых байтов. PRF - AES-CM:
	 *          блоки E(x·2^16 + i) под мастер-ключом.
	 *
	 */
	static nts::srtp::error_t prf(const view_t & key, const view_t & salt, const uint8_t label, uint8_t * result, const size_t size) noexcept {
		// Шифр AES
		cipher::aes_t aes;
		// Если мастер-ключ установить не удалось
		if(!aes.key(key))
			// Выводим отказ ключа
			return nts::srtp::error_t::KEY;
		// Входной блок PRF: мастер-соль, выровненная влево, с меткой на месте седьмого байта
		uint8_t counter[BLOCK];
		// Зануляем блок целиком
		::memset(counter, 0, BLOCK);
		// Переносим мастер-соль в начало блока
		::memcpy(counter, salt.data, salt.size);
		// Накладываем метку на седьмой байт (метка ‖ шесть нулевых байтов индекса)
		counter[7] ^= label;
		// Число блоков ключевого потока
		const size_t blocks = (size + BLOCK - 1) / BLOCK;
		// Блок гаммы
		uint8_t gamma[BLOCK];
		// Проходим по блокам потока
		for(size_t i = 0; i < blocks; i++){
			// Если блок гаммы выработать не удалось
			if(!aes.encrypt(counter, gamma)){
				// Выполняем затирание блока
				nts::sys::wipe(gamma, BLOCK);
				// Выводим отказ ключа
				return nts::srtp::error_t::KEY;
			}
			// Длина куска потока в этом блоке
			const size_t chunk = ((size - i * BLOCK) < BLOCK) ? (size - i * BLOCK) : BLOCK;
			// Переносим кусок гаммы в итог
			::memcpy(result + i * BLOCK, gamma, chunk);
			// Наращиваем младшие шестнадцать разрядов счётчика
			if(++counter[BLOCK - 1] == 0)
				// Переносим перенос в старший байт
				++counter[BLOCK - 2];
		}
		// Выполняем затирание рабочих блоков
		nts::sys::wipe(gamma, BLOCK);
		nts::sys::wipe(counter, BLOCK);
		// Выводим признак успеха
		return nts::srtp::error_t::NONE;
	}

	/**
	 * @brief Метод сборки синхропосылки AES-CM пакета RTP по разделу 4.1.1 RFC 3711
	 *
	 * @param salt  сессионная соль (14 байтов)
	 * @param ssrc  опознаватель источника
	 * @param roc   счётчик переполнений
	 * @param seq   порядковый номер пакета
	 * @param iv    место, в которое записывается синхропосылка (16 байтов)
	 *
	 * @details IV = (k_s·2^16) XOR (SSRC·2^64) XOR (i·2^16): соль в байтах
	 *          0..13, SSRC в байтах 4..7, ROC в байтах 8..11, номер в байтах
	 *          12..13, младшие два байта нулевые под счётчик блоков.
	 *
	 */
	static void ivRtp(const view_t & salt, const uint32_t ssrc, const uint32_t roc, const uint16_t seq, uint8_t * iv) noexcept {
		// Зануляем синхропосылку целиком
		::memset(iv, 0, BLOCK);
		// Переносим соль в начало блока
		::memcpy(iv, salt.data, salt.size);
		// Накладываем опознаватель источника
		iv[4] ^= static_cast <uint8_t> (ssrc >> 24);
		iv[5] ^= static_cast <uint8_t> (ssrc >> 16);
		iv[6] ^= static_cast <uint8_t> (ssrc >> 8);
		iv[7] ^= static_cast <uint8_t> (ssrc);
		// Накладываем счётчик переполнений
		iv[8]  ^= static_cast <uint8_t> (roc >> 24);
		iv[9]  ^= static_cast <uint8_t> (roc >> 16);
		iv[10] ^= static_cast <uint8_t> (roc >> 8);
		iv[11] ^= static_cast <uint8_t> (roc);
		// Накладываем порядковый номер
		iv[12] ^= static_cast <uint8_t> (seq >> 8);
		iv[13] ^= static_cast <uint8_t> (seq);
	}

	/**
	 * @brief Метод сборки синхропосылки AES-CM пакета SRTCP по разделу 3.4 RFC 3711
	 *
	 * @param salt  сессионная соль (14 байтов)
	 * @param ssrc  опознаватель источника
	 * @param index индекс SRTCP (31 разряд)
	 * @param iv    место, в которое записывается синхропосылка (16 байтов)
	 *
	 */
	static void ivRtcp(const view_t & salt, const uint32_t ssrc, const uint32_t index, uint8_t * iv) noexcept {
		// Зануляем синхропосылку целиком
		::memset(iv, 0, BLOCK);
		// Переносим соль в начало блока
		::memcpy(iv, salt.data, salt.size);
		// Накладываем опознаватель источника
		iv[4] ^= static_cast <uint8_t> (ssrc >> 24);
		iv[5] ^= static_cast <uint8_t> (ssrc >> 16);
		iv[6] ^= static_cast <uint8_t> (ssrc >> 8);
		iv[7] ^= static_cast <uint8_t> (ssrc);
		// Накладываем индекс SRTCP (i·2^16: индекс в байтах 10..13)
		iv[10] ^= static_cast <uint8_t> (index >> 24);
		iv[11] ^= static_cast <uint8_t> (index >> 16);
		iv[12] ^= static_cast <uint8_t> (index >> 8);
		iv[13] ^= static_cast <uint8_t> (index);
	}

	/**
	 * @brief Метод сборки одноразового числа AEAD пакета RTP по разделу 8.1 RFC 7714
	 *
	 * @param salt сессионная соль (12 байтов)
	 * @param ssrc опознаватель источника
	 * @param roc  счётчик переполнений
	 * @param seq  порядковый номер пакета
	 * @param iv   место, в которое записывается одноразовое число (12 байтов)
	 *
	 */
	static void ivRtpAead(const view_t & salt, const uint32_t ssrc, const uint32_t roc, const uint16_t seq, uint8_t * iv) noexcept {
		// Переносим соль целиком
		::memcpy(iv, salt.data, 12);
		// Накладываем опознаватель источника
		iv[2] ^= static_cast <uint8_t> (ssrc >> 24);
		iv[3] ^= static_cast <uint8_t> (ssrc >> 16);
		iv[4] ^= static_cast <uint8_t> (ssrc >> 8);
		iv[5] ^= static_cast <uint8_t> (ssrc);
		// Накладываем счётчик переполнений
		iv[6]  ^= static_cast <uint8_t> (roc >> 24);
		iv[7]  ^= static_cast <uint8_t> (roc >> 16);
		iv[8]  ^= static_cast <uint8_t> (roc >> 8);
		iv[9]  ^= static_cast <uint8_t> (roc);
		// Накладываем порядковый номер
		iv[10] ^= static_cast <uint8_t> (seq >> 8);
		iv[11] ^= static_cast <uint8_t> (seq);
	}

	/**
	 * @brief Метод сборки одноразового числа AEAD пакета SRTCP по разделу 9.1 RFC 7714
	 *
	 * @param salt  сессионная соль (12 байтов)
	 * @param ssrc  опознаватель источника
	 * @param index индекс SRTCP (31 разряд)
	 * @param iv    место, в которое записывается одноразовое число (12 байтов)
	 *
	 */
	static void ivRtcpAead(const view_t & salt, const uint32_t ssrc, const uint32_t index, uint8_t * iv) noexcept {
		// Переносим соль целиком
		::memcpy(iv, salt.data, 12);
		// Накладываем опознаватель источника
		iv[2] ^= static_cast <uint8_t> (ssrc >> 24);
		iv[3] ^= static_cast <uint8_t> (ssrc >> 16);
		iv[4] ^= static_cast <uint8_t> (ssrc >> 8);
		iv[5] ^= static_cast <uint8_t> (ssrc);
		// Накладываем индекс SRTCP (32-разрядное поле 0+индекс)
		iv[8]  ^= static_cast <uint8_t> (index >> 24);
		iv[9]  ^= static_cast <uint8_t> (index >> 16);
		iv[10] ^= static_cast <uint8_t> (index >> 8);
		iv[11] ^= static_cast <uint8_t> (index);
	}

	/**
	 * @brief Метод наложения гаммы AES-CM на содержимое
	 *
	 * @param key    сессионный ключ шифрования
	 * @param iv     синхропосылка (младшие шестнадцать разрядов нулевые)
	 * @param source исходные данные
	 * @param result место, в которое записываются данные под гаммой
	 *
	 * @return       отказ шифрования
	 *
	 * @details Гамма счётчика: блоки E(IV + i) с наращиванием младших
	 *          шестнадцати разрядов; хвост короче блока накрывается старшими
	 *          байтами последнего блока гаммы.
	 *
	 */
	static nts::srtp::error_t applyCm(const view_t & key, const uint8_t * iv, const view_t & source, uint8_t * result) noexcept {
		// Шифр AES
		cipher::aes_t aes;
		// Если ключ установить не удалось
		if(!aes.key(key))
			// Выводим отказ ключа
			return nts::srtp::error_t::KEY;
		// Счётчик блоков гаммы
		uint8_t counter[BLOCK];
		// Переносим синхропосылку в счётчик
		::memcpy(counter, iv, BLOCK);
		// Блок гаммы
		uint8_t gamma[BLOCK];
		// Число полных блоков содержимого
		const size_t whole = source.size / BLOCK;
		// Проходим по полным блокам
		for(size_t i = 0; i < whole; i++){
			// Если блок гаммы выработать не удалось
			if(!aes.encrypt(counter, gamma)){
				// Выполняем затирание блока
				nts::sys::wipe(gamma, BLOCK);
				// Выводим отказ ключа
				return nts::srtp::error_t::KEY;
			}
			// Накладываем гамму на блок
			for(size_t j = 0; j < BLOCK; j++)
				// Байт итога под гаммой
				result[i * BLOCK + j] = static_cast <uint8_t> (source.data[i * BLOCK + j] ^ gamma[j]);
			// Наращиваем младшие шестнадцать разрядов счётчика
			if(++counter[BLOCK - 1] == 0)
				// Переносим перенос в старший байт
				++counter[BLOCK - 2];
		}
		// Если есть хвост короче блока
		if((source.size % BLOCK) != 0){
			// Если блок гаммы выработать не удалось
			if(!aes.encrypt(counter, gamma)){
				// Выполняем затирание блока
				nts::sys::wipe(gamma, BLOCK);
				// Выводим отказ ключа
				return nts::srtp::error_t::KEY;
			}
			// Накладываем гамму на хвост
			for(size_t j = 0; j < (source.size % BLOCK); j++)
				// Байт итога под гаммой
				result[whole * BLOCK + j] = static_cast <uint8_t> (source.data[whole * BLOCK + j] ^ gamma[j]);
		}
		// Выполняем затирание рабочих блоков
		nts::sys::wipe(gamma, BLOCK);
		nts::sys::wipe(counter, BLOCK);
		// Выводим признак успеха
		return nts::srtp::error_t::NONE;
	}

	/**
	 * @brief Метод постоянной сверки двух меток
	 *
	 * @param first  первая метка
	 * @param second вторая метка
	 *
	 * @return       признак совпадения
	 *
	 */
	static bool equal(const view_t & first, const view_t & second) noexcept {
		// Если длины различны
		if(first.size != second.size)
			// Метки не совпадают
			return false;
		// Накопитель расхождения
		uint8_t diff = 0;
		// Проходим по байтам меток без раннего выхода
		for(size_t i = 0; i < first.size; i++)
			// Накапливаем расхождение
			diff |= static_cast <uint8_t> (first.data[i] ^ second.data[i]);
		// Метки совпадают при нулевом расхождении
		return (diff == 0);
	}

	/**
	 * @brief Метод вычисления длины заголовка пакета RTP с учётом CSRC и расширения
	 *
	 * @param packet пакет RTP
	 *
	 * @return       длина заголовка в байтах, ноль при негодном пакете
	 *
	 */
	static size_t headerLength(const view_t & packet) noexcept {
		// Если пакет короче минимального заголовка
		if(packet.size < RTP_HEADER)
			// Выводим ноль
			return 0;
		// Число опознавателей CSRC
		const size_t cc = (packet.data[0] & 0x0F);
		// Длина заголовка с опознавателями
		size_t header = RTP_HEADER + cc * 4;
		// Если пакет короче заголовка
		if(packet.size < header)
			// Выводим ноль
			return 0;
		// Если установлен признак расширения заголовка
		if((packet.data[0] & 0x10) != 0){
			// Если под расширение нет четырёх байтов
			if(packet.size < header + 4)
				// Выводим ноль
				return 0;
			// Длина расширения в словах по четыре байта
			const size_t words = (static_cast <size_t> (packet.data[header + 2]) << 8) | packet.data[header + 3];
			// Длина заголовка с расширением
			header += 4 + words * 4;
			// Если пакет короче заголовка
			if(packet.size < header)
				// Выводим ноль
				return 0;
		}
		// Выводим длину заголовка
		return header;
	}
}

/**
 * \~russian
 * @brief Метод получения длин ключевого материала профиля
 *
 * @param profile профиль защиты
 * @param key     место, в которое записывается длина ключа шифрования в байтах
 * @param salt    место, в которое записывается длина соли в байтах
 *
 * @return        отказ неизвестного профиля
 *
 * \~english
 * @brief Method of getting the key material lengths of the profile
 * @param profile the protection profile
 * @param key     the place the encryption key length in bytes is written into
 * @param salt    the place the salt length in bytes is written into
 * @return        the failure of an unknown profile
 *
 * \~
 *
 */
nts::srtp::error_t nts::srtp::lengths(const profile_t profile, size_t & key, size_t & salt) noexcept {
	// По профилю защиты
	switch(profile){
		// Профили AES-CM
		case profile_t::AES128_CM_SHA1_80:
		case profile_t::AES128_CM_SHA1_32:
			// Ключ в шестнадцать байтов, соль в четырнадцать
			key = 16;
			salt = 14;
			// Выводим признак успеха
			return error_t::NONE;
		// Профиль AES-128-GCM
		case profile_t::AEAD_AES_128_GCM:
			// Ключ в шестнадцать байтов, соль в двенадцать
			key = 16;
			salt = 12;
			// Выводим признак успеха
			return error_t::NONE;
		// Профиль AES-256-GCM
		case profile_t::AEAD_AES_256_GCM:
			// Ключ в тридцать два байта, соль в двенадцать
			key = 32;
			salt = 12;
			// Выводим признак успеха
			return error_t::NONE;
		// Профиль неизвестен
		default:
			// Выводим отказ алгоритма
			return error_t::ALGORITHM;
	}
}

/**
 * \~russian
 * @brief Метод вывода сессионных ключей из мастер-ключа и мастер-соли
 *
 * @param profile профиль защиты
 * @param key     мастер-ключ (16 байтов у AES-CM и AES-128-GCM, 32 у AES-256-GCM)
 * @param salt    мастер-соль (14 байтов у AES-CM, 12 у AES-GCM)
 * @param result  место, в которое помещаются сессионные ключи
 *
 * @return        отказ вывода
 *
 * \~english
 * @brief Method of deriving the session keys from the master key and the master salt
 * @param profile the protection profile
 * @param key     the master key (16 bytes at AES-CM and AES-128-GCM, 32 at AES-256-GCM)
 * @param salt    the master salt (14 bytes at AES-CM, 12 at AES-GCM)
 * @param result  the place the session keys are put into
 * @return        the derivation failure
 *
 * \~
 *
 */
nts::srtp::error_t nts::srtp::keys(const profile_t profile, const view_t & key, const view_t & salt, keys_t & result) noexcept {
	// Длины ключевого материала профиля
	size_t keySize = 0, saltSize = 0;
	// Если профиль неизвестен
	if(lengths(profile, keySize, saltSize) != error_t::NONE)
		// Выводим отказ алгоритма
		return error_t::ALGORITHM;
	// Если мастер-ключ либо мастер-соль неверной длины
	if((key.size != keySize) || (salt.size != saltSize))
		// Выводим отказ ключа
		return error_t::KEY;
	/**
	 * Вывод выделяет память: нехватка её отдаётся отказом, а не завершением процесса
	 */
	try {
		// Занимаем место под ключ шифрования и соль
		result.cipher.assign(keySize, 0);
		result.salt.assign(saltSize, 0);
		// Если вывод ключа шифрования не удался
		if(prf(key, salt, 0x00, result.cipher.data(), keySize) != error_t::NONE)
			// Выводим отказ ключа
			return error_t::KEY;
		// Если вывод соли не удался
		if(prf(key, salt, 0x02, result.salt.data(), saltSize) != error_t::NONE)
			// Выводим отказ ключа
			return error_t::KEY;
		// Если профиль несёт имитовставку HMAC
		if((profile == profile_t::AES128_CM_SHA1_80) || (profile == profile_t::AES128_CM_SHA1_32)){
			// Занимаем место под ключ имитовставки (двадцать байтов HMAC-SHA1)
			result.auth.assign(20, 0);
			// Если вывод ключа имитовставки не удался
			if(prf(key, salt, 0x01, result.auth.data(), 20) != error_t::NONE)
				// Выводим отказ ключа
				return error_t::KEY;
		// У профилей AES-GCM ключа имитовставки нет
		} else
			// Опустошаем ключ имитовставки
			result.auth.clear();
	// Если память выделить не удалось
	} catch(const std::bad_alloc &) {
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Выводим признак успеха
	return error_t::NONE;
}

/**
 * \~russian
 * @brief Метод раскладки ключевого материала экспорта связи DTLS
 *
 * @param profile  профиль защиты
 * @param material ключевой материал экспорта (метка EXTRACTOR-dtls_srtp, 2 × (ключ + соль) байтов)
 * @param client   место, в которое помещаются мастер-ключ и мастер-соль клиента
 * @param server   место, в которое помещаются мастер-ключ и мастер-соль сервера
 *
 * @return         отказ раскладки
 *
 * \~english
 * @brief Method of laying out the DTLS connection export key material
 * @param profile  the protection profile
 * @param material the export key material (the EXTRACTOR-dtls_srtp label, 2 × (key + salt) bytes)
 * @param client   the place the client master key and master salt are put into
 * @param server   the place the server master key and master salt are put into
 * @return         the layout failure
 *
 * \~
 *
 */
nts::srtp::error_t nts::srtp::pair(const profile_t profile, const view_t & material, keys_t & client, keys_t & server) noexcept {
	// Длины ключевого материала профиля
	size_t keySize = 0, saltSize = 0;
	// Если профиль неизвестен
	if(lengths(profile, keySize, saltSize) != error_t::NONE)
		// Выводим отказ алгоритма
		return error_t::ALGORITHM;
	// Если материал неверной длины
	if(material.size != 2 * (keySize + saltSize))
		// Выводим отказ устройства записи
		return error_t::STRUCTURE;
	/**
	 * Раскладка выделяет память: нехватка её отдаётся отказом, а не завершением процесса
	 */
	try {
		// Раскладываем ключ клиента
		client.cipher.assign(material.data, material.data + keySize);
		// Раскладываем ключ сервера
		server.cipher.assign(material.data + keySize, material.data + 2 * keySize);
		// Раскладываем соль клиента
		client.salt.assign(material.data + 2 * keySize, material.data + 2 * keySize + saltSize);
		// Раскладываем соль сервера
		server.salt.assign(material.data + 2 * keySize + saltSize, material.data + 2 * (keySize + saltSize));
		// Поля имитовставки пусты: раскладка несёт мастер-ключ и мастер-соль
		client.auth.clear();
		server.auth.clear();
	// Если память выделить не удалось
	} catch(const std::bad_alloc &) {
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Выводим признак успеха
	return error_t::NONE;
}

/**
 * \~russian
 * @brief Метод установки сессионных ключей направления
 *
 * @param profile профиль защиты
 * @param keys    сессионные ключи вызова keys
 *
 * @return        отказ установки
 *
 * \~english
 * @brief Method of setting the session keys of the direction
 * @param profile the protection profile
 * @param keys    the session keys of the keys call
 * @return        the setting failure
 *
 * \~
 *
 */
bool nts::srtp::Session::start(const profile_t profile, const keys_t & keys) noexcept {
	// Длины ключевого материала профиля
	size_t keySize = 0, saltSize = 0;
	// Если профиль неизвестен
	if(lengths(profile, keySize, saltSize) != error_t::NONE)
		// Выводим отказ
		return false;
	// Если ключ либо соль неверной длины
	if((keys.cipher.size() != keySize) || (keys.salt.size() != saltSize))
		// Выводим отказ
		return false;
	// Если профиль несёт имитовставку HMAC, а ключ её пуст либо неверной длины
	if(((profile == profile_t::AES128_CM_SHA1_80) || (profile == profile_t::AES128_CM_SHA1_32)) && (keys.auth.size() != 20))
		// Выводим отказ
		return false;
	/**
	 * Установка выделяет память: нехватка её отдаётся отказом, а не завершением процесса
	 */
	try {
		// Запоминаем профиль
		this->_profile = profile;
		// Запоминаем сессионные ключи
		this->_cipher = keys.cipher;
		this->_auth = keys.auth;
		this->_salt = keys.salt;
	// Если память выделить не удалось
	} catch(const std::bad_alloc &) {
		// Выводим отказ
		return false;
	}
	// Сбрасываем состояние приёма и передачи
	this->_sl = 0;
	this->_roc = 0;
	this->_started = false;
	this->_window = 0;
	this->_top = 0;
	this->_srtcp = 0;
	this->_srtcpTop = 0;
	this->_srtcpWindow = 0;
	this->_srtcpStarted = false;
	// Устанавливаем признак готовности
	this->_ready = true;
	// Выводим признак успеха
	return true;
}

/**
 * \~russian
 * @brief Метод сброса состояния направления
 *
 *
 * \~english
 * @brief Method of resetting the direction state
 *
 * \~
 *
 */
void nts::srtp::Session::clear() noexcept {
	// Затираем сессионные ключи
	if(!this->_cipher.empty())
		// Затирание ключа шифрования
		nts::sys::wipe(this->_cipher.data(), this->_cipher.size());
	// Затираем ключ имитовставки
	if(!this->_auth.empty())
		// Затирание ключа имитовставки
		nts::sys::wipe(this->_auth.data(), this->_auth.size());
	// Затираем соль
	if(!this->_salt.empty())
		// Затирание соли
		nts::sys::wipe(this->_salt.data(), this->_salt.size());
	// Опустошаем наборы
	this->_cipher.clear();
	this->_auth.clear();
	this->_salt.clear();
	// Сбрасываем состояние
	this->_ready = false;
	this->_sl = 0;
	this->_roc = 0;
	this->_started = false;
	this->_window = 0;
	this->_top = 0;
	this->_srtcp = 0;
	this->_srtcpTop = 0;
	this->_srtcpWindow = 0;
	this->_srtcpStarted = false;
}

/**
 * \~russian
 * @brief Метод защиты пакета RTP отправителем
 *
 * @param packet пакет RTP целиком (заголовок и полезная нагрузка)
 * @param result место, в которое помещается защищённый пакет
 *
 * @return       отказ защиты
 *
 * \~english
 * @brief Method of protecting an RTP packet at the sender
 * @param packet the whole RTP packet (the header and the payload)
 * @param result the place the protected packet is put into
 * @return       the protection failure
 *
 * \~
 *
 */
nts::srtp::error_t nts::srtp::Session::protect(const view_t & packet, vector <uint8_t> & result) noexcept {
	// Если ключи не установлены
	if(!this->_ready)
		// Выводим отказ пустого объекта
		return error_t::EMPTY;
	// Длина заголовка пакета
	const size_t header = headerLength(packet);
	// Если пакет негоден
	if(header == 0)
		// Выводим отказ устройства записи
		return error_t::STRUCTURE;
	// Порядковый номер пакета
	const uint16_t seq = static_cast <uint16_t> ((static_cast <uint16_t> (packet.data[2]) << 8) | packet.data[3]);
	// Опознаватель источника
	const uint32_t ssrc = (static_cast <uint32_t> (packet.data[8]) << 24) | (static_cast <uint32_t> (packet.data[9]) << 16) | (static_cast <uint32_t> (packet.data[10]) << 8) | packet.data[11];
	// Если пакет не первый и номер переполнился (отправитель шлёт номера подряд)
	if(this->_started && (seq < this->_sl) && ((this->_sl - seq) > 0x8000))
		// Наращиваем счётчик переполнений
		this->_roc++;
	// Запоминаем номер последнего пакета и признак начала
	this->_sl = seq;
	// Признак начала потока
	this->_started = true;
	// Длина метки профиля
	const size_t tag = tagLength(this->_profile);
	/**
	 * Защита выделяет память: нехватка её отдаётся отказом, а не завершением процесса
	 */
	try {
		// Занимаем место под итог: пакет и метка
		result.assign(packet.size + tag, 0);
		// Переносим заголовок открытым
		::memcpy(result.data(), packet.data, header);
	// Если память выделить не удалось
	} catch(const std::bad_alloc &) {
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Просмотр полезной нагрузки
	const view_t payload(packet.data + header, packet.size - header);
	// Если профиль AES-GCM
	if((this->_profile == profile_t::AEAD_AES_128_GCM) || (this->_profile == profile_t::AEAD_AES_256_GCM)){
		// Одноразовое число AEAD
		uint8_t iv[12];
		// Собираем одноразовое число пакета
		ivRtpAead(view_t(this->_salt.data(), this->_salt.size()), ssrc, this->_roc, seq, iv);
		// Режим GCM
		cipher::gcm_t gcm;
		// Шифр AES
		cipher::aes_t aes;
		// Если ключ либо режим установить не удалось
		if(!aes.key(view_t(this->_cipher.data(), this->_cipher.size())) || !gcm.start(cipher::block_t(aes), view_t(iv, 12), AEAD_TAG)){
			// Выполняем затирание одноразового числа
			nts::sys::wipe(iv, 12);
			// Выводим отказ ключа
			return error_t::KEY;
		}
		// Сопутствующие данные - заголовок пакета
		if(!gcm.associate(view_t(packet.data, header)) || !gcm.encrypt(payload, result.data() + header) || !gcm.finish(result.data() + packet.size)){
			// Выполняем затирание одноразового числа
			nts::sys::wipe(iv, 12);
			// Выводим отказ ключа
			return error_t::KEY;
		}
		// Выполняем затирание одноразового числа
		nts::sys::wipe(iv, 12);
	// Профиль AES-CM
	} else {
		// Синхропосылка пакета
		uint8_t iv[BLOCK];
		// Собираем синхропосылку пакета
		ivRtp(view_t(this->_salt.data(), this->_salt.size()), ssrc, this->_roc, seq, iv);
		// Если наложение гаммы не удалось
		if(applyCm(view_t(this->_cipher.data(), this->_cipher.size()), iv, payload, result.data() + header) != error_t::NONE){
			// Выполняем затирание синхропосылки
			nts::sys::wipe(iv, BLOCK);
			// Выводим отказ ключа
			return error_t::KEY;
		}
		// Выполняем затирание синхропосылки
		nts::sys::wipe(iv, BLOCK);
		// Буфер имитовставки: пакет и счётчик переполнений
		vector <uint8_t> mac;
		/**
		 * Имитовставка выделяет память: нехватка её отдаётся отказом, а не завершением процесса
		 */
		try {
			// Занимаем место под пакет и счётчик
			mac.assign(packet.size + 4, 0);
			// Переносим защищённый пакет без метки
			::memcpy(mac.data(), result.data(), packet.size);
			// Приписываем счётчик переполнений старшим байтом вперёд
			mac[packet.size]     = static_cast <uint8_t> (this->_roc >> 24);
			mac[packet.size + 1] = static_cast <uint8_t> (this->_roc >> 16);
			mac[packet.size + 2] = static_cast <uint8_t> (this->_roc >> 8);
			mac[packet.size + 3] = static_cast <uint8_t> (this->_roc);
		// Если память выделить не удалось
		} catch(const std::bad_alloc &) {
			// Выводим отказ памяти
			return error_t::MEMORY;
		}
		// Если имитовставку вычислить не удалось
		if(!digest::hmac(digest::hash_t::SHA1, view_t(this->_auth.data(), this->_auth.size()), view_t(mac.data(), mac.size()), result.data() + packet.size, tag)){
			// Выполняем затирание буфера
			nts::sys::wipe(mac.data(), mac.size());
			// Выводим отказ ключа
			return error_t::KEY;
		}
		// Выполняем затирание буфера
		nts::sys::wipe(mac.data(), mac.size());
	}
	// Выводим признак успеха
	return error_t::NONE;
}

/**
 * \~russian
 * @brief Метод снятия защиты пакета RTP получателем
 *
 * @param packet защищённый пакет RTP целиком
 * @param result место, в которое помещается открытый пакет
 *
 * @return       отказ снятия защиты
 *
 * \~english
 * @brief Method of unprotecting an RTP packet at the receiver
 * @param packet the whole protected RTP packet
 * @param result the place the plain packet is put into
 * @return       the unprotection failure
 *
 * \~
 *
 */
nts::srtp::error_t nts::srtp::Session::unprotect(const view_t & packet, vector <uint8_t> & result) noexcept {
	// Если ключи не установлены
	if(!this->_ready)
		// Выводим отказ пустого объекта
		return error_t::EMPTY;
	// Длина метки профиля
	const size_t tag = tagLength(this->_profile);
	// Если пакет короче метки
	if(packet.size <= tag)
		// Выводим отказ устройства записи
		return error_t::STRUCTURE;
	// Просмотр пакета без метки
	const view_t body(packet.data, packet.size - tag);
	// Длина заголовка пакета
	const size_t header = headerLength(body);
	// Если пакет негоден
	if(header == 0)
		// Выводим отказ устройства записи
		return error_t::STRUCTURE;
	// Порядковый номер пакета
	const uint16_t seq = static_cast <uint16_t> ((static_cast <uint16_t> (body.data[2]) << 8) | body.data[3]);
	// Опознаватель источника
	const uint32_t ssrc = (static_cast <uint32_t> (body.data[8]) << 24) | (static_cast <uint32_t> (body.data[9]) << 16) | (static_cast <uint32_t> (body.data[10]) << 8) | body.data[11];
	// Оценка счётчика переполнений по разделу 3.3.1 RFC 3711
	uint32_t roc = this->_roc;
	// Если первый пакет потока
	if(!this->_started){
		// Счётчик нулевой
		roc = 0;
	// Иначе оцениваем по псевдокоду приложения A RFC 3711 (арифметика знаковая)
	} else {
		// Если старший номер в младшей половине
		if(this->_sl < 0x8000){
			// Если номер пакета далеко впереди - пакет предыдущего круга
			if((static_cast <int32_t> (seq) - static_cast <int32_t> (this->_sl)) > 0x8000)
				// Пакет предыдущего круга
				roc = this->_roc - 1;
		// Старший номер в старшей половине
		} else {
			// Если номер пакета далеко позади - пакет следующего круга
			if((static_cast <int32_t> (this->_sl) - 0x8000) > static_cast <int32_t> (seq))
				// Пакет следующего круга
				roc = this->_roc + 1;
		}
	}
	// Индекс пакета
	const uint64_t index = (static_cast <uint64_t> (roc) << 16) | seq;
	// Если поток начат и индекс не выше старшего принятого
	if(this->_started && (index <= this->_top)){
		// Если индекс старше окна приёма
		if(this->_top - index >= WINDOW)
			// Выводим отказ повтора
			return error_t::REPLAY;
		// Если бит индекса уже установлен
		if((this->_window & (static_cast <uint64_t> (1) << (this->_top - index))) != 0)
			// Выводим отказ повтора
			return error_t::REPLAY;
	}
	// Если профиль AES-GCM
	if((this->_profile == profile_t::AEAD_AES_128_GCM) || (this->_profile == profile_t::AEAD_AES_256_GCM)){
		// Одноразовое число AEAD
		uint8_t iv[12];
		// Собираем одноразовое число пакета
		ivRtpAead(view_t(this->_salt.data(), this->_salt.size()), ssrc, roc, seq, iv);
		// Режим GCM
		cipher::gcm_t gcm;
		// Шифр AES
		cipher::aes_t aes;
		// Если ключ либо режим установить не удалось
		if(!aes.key(view_t(this->_cipher.data(), this->_cipher.size())) || !gcm.start(cipher::block_t(aes), view_t(iv, 12), AEAD_TAG)){
			// Выполняем затирание одноразового числа
			nts::sys::wipe(iv, 12);
			// Выводим отказ ключа
			return error_t::KEY;
		}
		/**
		 * Расшифрование выделяет память: нехватка её отдаётся отказом, а не завершением процесса
		 */
		try {
			// Занимаем место под открытый пакет
			result.assign(body.size, 0);
			// Переносим заголовок открытым
			::memcpy(result.data(), body.data, header);
		// Если память выделить не удалось
		} catch(const std::bad_alloc &) {
			// Выполняем затирание одноразового числа
			nts::sys::wipe(iv, 12);
			// Выводим отказ памяти
			return error_t::MEMORY;
		}
		// Сопутствующие данные - заголовок; расшифрование со сверкой метки
		if(!gcm.associate(view_t(body.data, header)) || !gcm.decrypt(view_t(body.data + header, body.size - header), result.data() + header) || !gcm.verify(view_t(packet.data + body.size, tag))){
			// Выполняем затирание итога и одноразового числа
			nts::sys::wipe(result.data(), result.size());
			nts::sys::wipe(iv, 12);
			// Выводим отказ имитовставки
			return error_t::SIGNATURE;
		}
		// Выполняем затирание одноразового числа
		nts::sys::wipe(iv, 12);
	// Профиль AES-CM
	} else {
		// Буфер имитовставки: пакет и счётчик переполнений
		vector <uint8_t> mac;
		// Метка вычисленная
		uint8_t computed[10];
		/**
		 * Имитовставка выделяет память: нехватка её отдаётся отказом, а не завершением процесса
		 */
		try {
			// Занимаем место под пакет и счётчик
			mac.assign(body.size + 4, 0);
			// Переносим пакет без метки
			::memcpy(mac.data(), body.data, body.size);
			// Приписываем счётчик переполнений старшим байтом вперёд
			mac[body.size]     = static_cast <uint8_t> (roc >> 24);
			mac[body.size + 1] = static_cast <uint8_t> (roc >> 16);
			mac[body.size + 2] = static_cast <uint8_t> (roc >> 8);
			mac[body.size + 3] = static_cast <uint8_t> (roc);
		// Если память выделить не удалось
		} catch(const std::bad_alloc &) {
			// Выводим отказ памяти
			return error_t::MEMORY;
		}
		// Если имитовставку вычислить не удалось
		if(!digest::hmac(digest::hash_t::SHA1, view_t(this->_auth.data(), this->_auth.size()), view_t(mac.data(), mac.size()), computed, tag)){
			// Выполняем затирание буфера
			nts::sys::wipe(mac.data(), mac.size());
			// Выводим отказ ключа
			return error_t::KEY;
		}
		// Выполняем затирание буфера
		nts::sys::wipe(mac.data(), mac.size());
		// Если метки не сошлись постоянной сверкой
		if(!equal(view_t(computed, tag), view_t(packet.data + body.size, tag))){
			// Выполняем затирание метки
			nts::sys::wipe(computed, 10);
			// Выводим отказ имитовставки
			return error_t::SIGNATURE;
		}
		// Выполняем затирание метки
		nts::sys::wipe(computed, 10);
		// Синхропосылка пакета
		uint8_t iv[BLOCK];
		// Собираем синхропосылку пакета
		ivRtp(view_t(this->_salt.data(), this->_salt.size()), ssrc, roc, seq, iv);
		/**
		 * Расшифрование выделяет память: нехватка её отдаётся отказом, а не завершением процесса
		 */
		try {
			// Занимаем место под открытый пакет
			result.assign(body.size, 0);
			// Переносим заголовок открытым
			::memcpy(result.data(), body.data, header);
		// Если память выделить не удалось
		} catch(const std::bad_alloc &) {
			// Выполняем затирание синхропосылки
			nts::sys::wipe(iv, BLOCK);
			// Выводим отказ памяти
			return error_t::MEMORY;
		}
		// Если наложение гаммы не удалось
		if(applyCm(view_t(this->_cipher.data(), this->_cipher.size()), iv, view_t(body.data + header, body.size - header), result.data() + header) != error_t::NONE){
			// Выполняем затирание итога и синхропосылки
			nts::sys::wipe(result.data(), result.size());
			nts::sys::wipe(iv, BLOCK);
			// Выводим отказ ключа
			return error_t::KEY;
		}
		// Выполняем затирание синхропосылки
		nts::sys::wipe(iv, BLOCK);
	}
	// Обновляем состояние приёма по разделу 3.3.1 RFC 3711
	if(!this->_started){
		// Запоминаем первый номер
		this->_sl = seq;
		this->_roc = 0;
		this->_started = true;
		this->_top = index;
		this->_window = 1;
	// Пакет следующего круга
	} else if(roc == this->_roc + 1){
		// Счётчик и старший номер обновляются
		this->_roc = roc;
		this->_sl = seq;
		// Сдвигаем окно
		const uint64_t shift = index - this->_top;
		// Если сдвиг больше размера окна
		if(shift >= WINDOW)
			// Окно заново
			this->_window = 1;
		// Иначе сдвигаем и ставим бит
		else
			// Сдвиг и установка бита
			this->_window = (this->_window << shift) | 1;
		// Старший индекс обновляется
		this->_top = index;
	// Пакет текущего круга
	} else if(roc == this->_roc){
		// Если номер старше старшего
		if(static_cast <int32_t> (seq - this->_sl) > 0)
			// Старший номер обновляется
			this->_sl = seq;
		// Если индекс выше старшего
		if(index > this->_top){
			// Сдвигаем окно
			const uint64_t shift = index - this->_top;
			// Если сдвиг больше размера окна
			if(shift >= WINDOW)
				// Окно заново
				this->_window = 1;
			// Иначе сдвигаем и ставим бит
			else
				// Сдвиг и установка бита
				this->_window = (this->_window << shift) | 1;
			// Старший индекс обновляется
			this->_top = index;
		// Индекс внутри окна
		} else
			// Установка бита индекса
			this->_window |= (static_cast <uint64_t> (1) << (this->_top - index));
	}
	// Выводим признак успеха
	return error_t::NONE;
}

/**
 * \~russian
 * @brief Метод защиты пакета RTCP отправителем
 *
 * @param packet пакет RTCP целиком
 * @param result место, в которое помещается защищённый пакет SRTCP
 *
 * @return       отказ защиты
 *
 * \~english
 * @brief Method of protecting an RTCP packet at the sender
 * @param packet the whole RTCP packet
 * @param result the place the protected SRTCP packet is put into
 * @return       the protection failure
 *
 * \~
 *
 */
nts::srtp::error_t nts::srtp::Session::protectControl(const view_t & packet, vector <uint8_t> & result) noexcept {
	// Если ключи не установлены
	if(!this->_ready)
		// Выводим отказ пустого объекта
		return error_t::EMPTY;
	// Если пакет короче заголовка RTCP
	if(packet.size < 8)
		// Выводим отказ устройства записи
		return error_t::STRUCTURE;
	// Опознаватель источника
	const uint32_t ssrc = (static_cast <uint32_t> (packet.data[4]) << 24) | (static_cast <uint32_t> (packet.data[5]) << 16) | (static_cast <uint32_t> (packet.data[6]) << 8) | packet.data[7];
	// Индекс защищаемого пакета
	const uint32_t index = this->_srtcp;
	// Слово ESRTCP: флаг шифрования и индекс
	const uint32_t esrtcp = 0x80000000U | index;
	// Длина метки профиля
	const size_t tag = tagLength(this->_profile);
	// Если профиль AES-GCM
	const bool aead = ((this->_profile == profile_t::AEAD_AES_128_GCM) || (this->_profile == profile_t::AEAD_AES_256_GCM));
	/**
	 * Защита выделяет память: нехватка её отдаётся отказом, а не завершением процесса
	 */
	try {
		// Занимаем место под итог: пакет, метка и слово ESRTCP
		result.assign(packet.size + tag + 4, 0);
		// Переносим первые восемь байтов открытыми
		::memcpy(result.data(), packet.data, 8);
	// Если память выделить не удалось
	} catch(const std::bad_alloc &) {
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
	// Просмотр шифруемой части: с девятого байта до конца пакета
	const view_t payload(packet.data + 8, packet.size - 8);
	// Если профиль AES-GCM
	if(aead){
		// Одноразовое число AEAD
		uint8_t iv[12];
		// Собираем одноразовое число пакета
		ivRtcpAead(view_t(this->_salt.data(), this->_salt.size()), ssrc, index, iv);
		// Режим GCM
		cipher::gcm_t gcm;
		// Шифр AES
		cipher::aes_t aes;
		// Если ключ либо режим установить не удалось
		if(!aes.key(view_t(this->_cipher.data(), this->_cipher.size())) || !gcm.start(cipher::block_t(aes), view_t(iv, 12), AEAD_TAG)){
			// Выполняем затирание одноразового числа
			nts::sys::wipe(iv, 12);
			// Выводим отказ ключа
			return error_t::KEY;
		}
		// Сопутствующие данные: первые восемь байтов и слово ESRTCP
		uint8_t aad[12];
		// Переносим заголовок
		::memcpy(aad, packet.data, 8);
		// Приписываем слово ESRTCP старшим байтом вперёд
		aad[8]  = static_cast <uint8_t> (esrtcp >> 24);
		aad[9]  = static_cast <uint8_t> (esrtcp >> 16);
		aad[10] = static_cast <uint8_t> (esrtcp >> 8);
		aad[11] = static_cast <uint8_t> (esrtcp);
		// Шифрование с меткой
		if(!gcm.associate(view_t(aad, 12)) || !gcm.encrypt(payload, result.data() + 8) || !gcm.finish(result.data() + packet.size)){
			// Выполняем затирание рабочих буферов
			nts::sys::wipe(aad, 12);
			nts::sys::wipe(iv, 12);
			// Выводим отказ ключа
			return error_t::KEY;
		}
		// Выполняем затирание рабочих буферов
		nts::sys::wipe(aad, 12);
		nts::sys::wipe(iv, 12);
	// Профиль AES-CM
	} else {
		// Синхропосылка пакета
		uint8_t iv[BLOCK];
		// Собираем синхропосылку пакета
		ivRtcp(view_t(this->_salt.data(), this->_salt.size()), ssrc, index, iv);
		// Если наложение гаммы не удалось
		if(applyCm(view_t(this->_cipher.data(), this->_cipher.size()), iv, payload, result.data() + 8) != error_t::NONE){
			// Выполняем затирание синхропосылки
			nts::sys::wipe(iv, BLOCK);
			// Выводим отказ ключа
			return error_t::KEY;
		}
		// Выполняем затирание синхропосылки
		nts::sys::wipe(iv, BLOCK);
	}
	// Место слова ESRTCP в итоге: у AES-GCM за меткой, у AES-CM за пакетом до метки
	const size_t word = aead ? (packet.size + tag) : packet.size;
	// Приписываем слово ESRTCP старшим байтом вперёд
	result[word]     = static_cast <uint8_t> (esrtcp >> 24);
	result[word + 1] = static_cast <uint8_t> (esrtcp >> 16);
	result[word + 2] = static_cast <uint8_t> (esrtcp >> 8);
	result[word + 3] = static_cast <uint8_t> (esrtcp);
	// Если профиль несёт имитовставку HMAC
	if(!aead){
		// Если имитовставку над пакетом со словом вычислить не удалось
		if(!digest::hmac(digest::hash_t::SHA1, view_t(this->_auth.data(), this->_auth.size()), view_t(result.data(), word + 4), result.data() + word + 4, tag))
			// Выводим отказ ключа
			return error_t::KEY;
	}
	// Наращиваем счётчик отправленных пакетов по модулю 2^31
	this->_srtcp = (this->_srtcp + 1) & 0x7FFFFFFFU;
	// Выводим признак успеха
	return error_t::NONE;
}

/**
 * \~russian
 * @brief Метод снятия защиты пакета SRTCP получателем
 *
 * @param packet защищённый пакет SRTCP целиком
 * @param result место, в которое помещается открытый пакет RTCP
 *
 * @return       отказ снятия защиты
 *
 * \~english
 * @brief Method of unprotecting an SRTCP packet at the receiver
 * @param packet the whole protected SRTCP packet
 * @param result the place the plain RTCP packet is put into
 * @return       the unprotection failure
 *
 * \~
 *
 */
nts::srtp::error_t nts::srtp::Session::unprotectControl(const view_t & packet, vector <uint8_t> & result) noexcept {
	// Если ключи не установлены
	if(!this->_ready)
		// Выводим отказ пустого объекта
		return error_t::EMPTY;
	// Длина метки профиля
	const size_t tag = tagLength(this->_profile);
	// Если пакет короче заголовка, слова ESRTCP и метки
	if(packet.size < 8 + 4 + tag)
		// Выводим отказ устройства записи
		return error_t::STRUCTURE;
	// Если профиль AES-GCM
	const bool aead = ((this->_profile == profile_t::AEAD_AES_128_GCM) || (this->_profile == profile_t::AEAD_AES_256_GCM));
	// Место слова ESRTCP: у AES-GCM последние четыре байта, у AES-CM перед меткой
	const size_t word = aead ? (packet.size - 4) : (packet.size - tag - 4);
	// Слово ESRTCP пакета
	const uint32_t esrtcp = (static_cast <uint32_t> (packet.data[word]) << 24) | (static_cast <uint32_t> (packet.data[word + 1]) << 16) | (static_cast <uint32_t> (packet.data[word + 2]) << 8) | packet.data[word + 3];
	// Индекс SRTCP без флага шифрования
	const uint32_t index = esrtcp & 0x7FFFFFFFU;
	// Опознаватель источника
	const uint32_t ssrc = (static_cast <uint32_t> (packet.data[4]) << 24) | (static_cast <uint32_t> (packet.data[5]) << 16) | (static_cast <uint32_t> (packet.data[6]) << 8) | packet.data[7];
	// Если приём начат
	if(this->_srtcpStarted){
		// Если индекс не выше старшего принятого
		if(index <= this->_srtcpTop){
			// Если индекс старше окна приёма
			if(this->_srtcpTop - index >= WINDOW)
				// Выводим отказ повтора
				return error_t::REPLAY;
			// Если бит индекса уже установлен
			if((this->_srtcpWindow & (static_cast <uint64_t> (1) << (this->_srtcpTop - index))) != 0)
				// Выводим отказ повтора
				return error_t::REPLAY;
		}
	}
	// Если профиль AES-GCM
	if(aead){
		// Одноразовое число AEAD
		uint8_t iv[12];
		// Собираем одноразовое число пакета
		ivRtcpAead(view_t(this->_salt.data(), this->_salt.size()), ssrc, index, iv);
		// Режим GCM
		cipher::gcm_t gcm;
		// Шифр AES
		cipher::aes_t aes;
		// Если ключ либо режим установить не удалось
		if(!aes.key(view_t(this->_cipher.data(), this->_cipher.size())) || !gcm.start(cipher::block_t(aes), view_t(iv, 12), AEAD_TAG)){
			// Выполняем затирание одноразового числа
			nts::sys::wipe(iv, 12);
			// Выводим отказ ключа
			return error_t::KEY;
		}
		// Сопутствующие данные: первые восемь байтов и слово ESRTCP
		uint8_t aad[12];
		// Переносим заголовок
		::memcpy(aad, packet.data, 8);
		// Приписываем слово ESRTCP
		::memcpy(aad + 8, packet.data + word, 4);
		/**
		 * Расшифрование выделяет память: нехватка её отдаётся отказом, а не завершением процесса
		 */
		try {
			// Занимаем место под открытый пакет: без метки и слова
			result.assign(packet.size - tag - 4, 0);
			// Переносим первые восемь байтов открытыми
			::memcpy(result.data(), packet.data, 8);
		// Если память выделить не удалось
		} catch(const std::bad_alloc &) {
			// Выполняем затирание рабочих буферов
			nts::sys::wipe(aad, 12);
			nts::sys::wipe(iv, 12);
			// Выводим отказ памяти
			return error_t::MEMORY;
		}
		// Расшифрование со сверкой метки
		if(!gcm.associate(view_t(aad, 12)) || !gcm.decrypt(view_t(packet.data + 8, packet.size - tag - 4 - 8), result.data() + 8) || !gcm.verify(view_t(packet.data + packet.size - tag - 4, tag))){
			// Выполняем затирание итога и рабочих буферов
			nts::sys::wipe(result.data(), result.size());
			nts::sys::wipe(aad, 12);
			nts::sys::wipe(iv, 12);
			// Выводим отказ имитовставки
			return error_t::SIGNATURE;
		}
		// Выполняем затирание рабочих буферов
		nts::sys::wipe(aad, 12);
		nts::sys::wipe(iv, 12);
	// Профиль AES-CM
	} else {
		// Метка вычисленная
		uint8_t computed[10];
		// Если имитовставку над пакетом до метки вычислить не удалось
		if(!digest::hmac(digest::hash_t::SHA1, view_t(this->_auth.data(), this->_auth.size()), view_t(packet.data, word + 4), computed, tag))
			// Выводим отказ ключа
			return error_t::KEY;
		// Если метки не сошлись постоянной сверкой
		if(!equal(view_t(computed, tag), view_t(packet.data + word + 4, tag))){
			// Выполняем затирание метки
			nts::sys::wipe(computed, 10);
			// Выводим отказ имитовставки
			return error_t::SIGNATURE;
		}
		// Выполняем затирание метки
		nts::sys::wipe(computed, 10);
		// Синхропосылка пакета
		uint8_t iv[BLOCK];
		// Собираем синхропосылку пакета
		ivRtcp(view_t(this->_salt.data(), this->_salt.size()), ssrc, index, iv);
		/**
		 * Расшифрование выделяет память: нехватка её отдаётся отказом, а не завершением процесса
		 */
		try {
			// Занимаем место под открытый пакет: без метки и слова
			result.assign(packet.size - tag - 4, 0);
			// Переносим первые восемь байтов открытыми
			::memcpy(result.data(), packet.data, 8);
		// Если память выделить не удалось
		} catch(const std::bad_alloc &) {
			// Выполняем затирание синхропосылки
			nts::sys::wipe(iv, BLOCK);
			// Выводим отказ памяти
			return error_t::MEMORY;
		}
		// Если наложение гаммы не удалось
		if(applyCm(view_t(this->_cipher.data(), this->_cipher.size()), iv, view_t(packet.data + 8, packet.size - tag - 4 - 8), result.data() + 8) != error_t::NONE){
			// Выполняем затирание итога и синхропосылки
			nts::sys::wipe(result.data(), result.size());
			nts::sys::wipe(iv, BLOCK);
			// Выводим отказ ключа
			return error_t::KEY;
		}
		// Выполняем затирание синхропосылки
		nts::sys::wipe(iv, BLOCK);
	}
	// Обновляем состояние приёма SRTCP
	if(!this->_srtcpStarted){
		// Запоминаем первый индекс
		this->_srtcpTop = index;
		this->_srtcpWindow = 1;
		this->_srtcpStarted = true;
	// Если индекс выше старшего
	} else if(index > this->_srtcpTop){
		// Сдвигаем окно
		const uint32_t shift = index - this->_srtcpTop;
		// Если сдвиг больше размера окна
		if(shift >= WINDOW)
			// Окно заново
			this->_srtcpWindow = 1;
		// Иначе сдвигаем и ставим бит
		else
			// Сдвиг и установка бита
			this->_srtcpWindow = (this->_srtcpWindow << shift) | 1;
		// Старший индекс обновляется
		this->_srtcpTop = index;
	// Индекс внутри окна
	} else
		// Установка бита индекса
		this->_srtcpWindow |= (static_cast <uint64_t> (1) << (this->_srtcpTop - index));
	// Выводим признак успеха
	return error_t::NONE;
}

/**
 * \~russian
 * @brief Конструктор
 *
 *
 * \~english
 * @brief Constructor
 *
 * \~
 *
 */
nts::srtp::Session::Session() noexcept :
	_ready(false),
	_profile(profile_t::AES128_CM_SHA1_80),
	_sl(0), _roc(0), _started(false), _window(0), _top(0),
	_srtcp(0), _srtcpTop(0), _srtcpWindow(0), _srtcpStarted(false) {}

/**
 * \~russian
 * @brief Деструктор
 *
 *
 * \~english
 * @brief Destructor
 *
 * \~
 *
 */
nts::srtp::Session::~Session() noexcept {
	// Затираем сессионные ключи
	if(!this->_cipher.empty())
		// Затирание ключа шифрования
		nts::sys::wipe(this->_cipher.data(), this->_cipher.size());
	// Затираем ключ имитовставки
	if(!this->_auth.empty())
		// Затирание ключа имитовставки
		nts::sys::wipe(this->_auth.data(), this->_auth.size());
	// Затираем соль
	if(!this->_salt.empty())
		// Затирание соли
		nts::sys::wipe(this->_salt.data(), this->_salt.size());
}
