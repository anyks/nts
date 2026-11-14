/**
 * @file fingerprint.cpp
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
 * @brief Реализация модуля отпечатков приветствия клиента: разбор приветствия в профиль,
 *        отпечатки JA3, JA4 и PeetPrint, отпечаток Akamai по HTTP/2, снимок профиля и хранилище
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <new>
#include <string>
#include <vector>
#include <cstdio>
#include <cctype>
#include <cstring>
#include <sstream>
#include <algorithm>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <hello/hello.hpp>
#include <digest/hash.hpp>
#include <fingerprint/fingerprint.hpp>

/**
 * Подписываемся на стандартное пространство имён
 */
using namespace std;

/**
 * @brief Служебные объекты модуля
 *
 */
namespace {
	/**
	 * Пространство имён библиотеки
	 */
	using namespace nts;

	/**
	 * Намеренные решения модуля
	 *
	 * 1. Тело приветствия разбирается модулем hello: правила разбора приветствия у
	 *    библиотеки одни, и отпечаток снимается с того же разбора, что ведёт рукопожатие.
	 * 2. Отпечатки JA3 и PeetPrint считаются хешем MD5 по их описаниям; отпечаток JA4
	 *    считается хешем SHA-256 по описанию FoxIO (у AWH JA4 считался MD5 - расхождение
	 *    с описанием, здесь исправлено).
	 * 3. Снимок профиля переносим: старший байт вперёд, поле издания, фиксированные
	 *    ширины; разобранные поля расширений в снимок не входят и выводятся заново из
	 *    сырых тел при загрузке.
	 * 4. Хранилище без охраны потоков: охрана - дело потребителя.
	 */

	/**
	 * Виды расширений по проводу, которых нет в extension::type_t
	 */
	static constexpr uint16_t WIRE_FRAGMENT  = 0x0001; // max_fragment_length (RFC 6066)
	static constexpr uint16_t WIRE_SRTP      = 0x000E; // use_srtp (RFC 5764)
	static constexpr uint16_t WIRE_HEARTBEAT = 0x000F; // heartbeat (RFC 6520)
	static constexpr uint16_t WIRE_PADDING   = 0x0015; // padding (RFC 7685)
	static constexpr uint16_t WIRE_LIMIT     = 0x001C; // record_size_limit (RFC 8449)
	static constexpr uint16_t WIRE_DELEGATED = 0x0022; // delegated_credential (RFC 9345)
	static constexpr uint16_t WIRE_CERTIFIED = 0x0032; // signature_algorithms_cert (RFC 8446)
	static constexpr uint16_t WIRE_OUTER     = 0xFD00; // ech_outer_extensions

	/**
	 * Издания протокола по проводу
	 */
	static constexpr uint16_t EDITION_TLS13  = 0x0304; // TLS 1.3
	static constexpr uint16_t EDITION_DTLS10 = 0xFEFF; // DTLS 1.0
	static constexpr uint16_t EDITION_DTLS12 = 0xFEFD; // DTLS 1.2
	static constexpr uint16_t EDITION_DTLS13 = 0xFEFC; // DTLS 1.3

	/**
	 * Размеры заголовков записи и сообщения рукопожатия
	 */
	static constexpr size_t RECORD_STREAM   = 5;  // Заголовок записи потокового устройства
	static constexpr size_t RECORD_DATAGRAM = 13; // Заголовок записи дейтаграммного устройства
	static constexpr size_t HEADER_STREAM   = 4;  // Заголовок сообщения потокового устройства
	static constexpr size_t HEADER_DATAGRAM = 12; // Заголовок сообщения дейтаграммного устройства

	/**
	 * Вид сообщения рукопожатия: приветствие клиента
	 */
	static constexpr uint8_t GREETING = 0x01;

	/**
	 * Вид записи: рукопожатие
	 */
	static constexpr uint8_t HANDSHAKE = 0x16;

	/**
	 * Метка и издание снимка профиля
	 */
	static const uint8_t STAMP[] = {'A', 'N', 'T', 'S', 'F', 'P'};

	/**
	 * Предисловие потока HTTP/2
	 */
	static const uint8_t PREFACE[] = {
		// Магия предисловия протокола HTTP/2
		'P', 'R', 'I', ' ', '*', ' ', 'H', 'T', 'T', 'P', '/', '2', '.', '0',
		'\r', '\n', '\r', '\n', 'S', 'M', '\r', '\n', '\r', '\n'
	};

	/**
	 * Виды кадров HTTP/2
	 */
	static constexpr uint8_t FRAME_HEADERS  = 0x01; // Кадр заголовков
	static constexpr uint8_t FRAME_PRIORITY = 0x02; // Кадр приоритета
	static constexpr uint8_t FRAME_SETTINGS = 0x04; // Кадр параметров
	static constexpr uint8_t FRAME_WINDOW   = 0x08; // Кадр обновления окна

	/**
	 * @brief Функция чтения числа в два байта старшим байтом вперёд
	 *
	 * @param data указатель на байты
	 * @return     прочитанное число
	 *
	 */
	static uint16_t twain(const uint8_t * data) noexcept {
		// Выводим число из двух байтов
		return static_cast <uint16_t> ((static_cast <uint16_t> (data[0]) << 8) | static_cast <uint16_t> (data[1]));
	}
	/**
	 * @brief Функция чтения числа в три байта старшим байтом вперёд
	 *
	 * @param data указатель на байты
	 * @return     прочитанное число
	 *
	 */
	static uint32_t triad(const uint8_t * data) noexcept {
		// Выводим число из трёх байтов
		return ((static_cast <uint32_t> (data[0]) << 16) | (static_cast <uint32_t> (data[1]) << 8) | static_cast <uint32_t> (data[2]));
	}
	/**
	 * @brief Функция чтения числа в четыре байта старшим байтом вперёд
	 *
	 * @param data указатель на байты
	 * @return     прочитанное число
	 *
	 */
	static uint32_t tetrad(const uint8_t * data) noexcept {
		// Выводим число из четырёх байтов
		return ((static_cast <uint32_t> (data[0]) << 24) | (static_cast <uint32_t> (data[1]) << 16) | (static_cast <uint32_t> (data[2]) << 8) | static_cast <uint32_t> (data[3]));
	}
	/**
	 * @brief Функция чтения числа в восемь байтов старшим байтом вперёд
	 *
	 * @param data указатель на байты
	 * @return     прочитанное число
	 *
	 */
	static uint64_t octet(const uint8_t * data) noexcept {
		// Выводим число из восьми байтов
		return ((static_cast <uint64_t> (tetrad(data)) << 32) | static_cast <uint64_t> (tetrad(data + 4)));
	}
	/**
	 * @brief Функция дописывания числа старшим байтом вперёд в накопитель
	 *
	 * @param value  дописываемое число
	 * @param width  ширина числа в байтах
	 * @param result накопитель
	 *
	 */
	static void inscribe(const uint64_t value, const size_t width, vector <uint8_t> & result) {
		/**
		 * Выполняем перебор байтов числа от старшего к младшему
		 */
		for(size_t i = width; i > 0; i--)
			// Дописываем очередной байт числа
			result.push_back(static_cast <uint8_t> (value >> ((i - 1) * 8)));
	}
	/**
	 * @brief Функция дописывания десятичной записи числа к строке
	 *
	 * @param value  записываемое число
	 * @param result строка, к которой дописывается запись
	 *
	 */
	static void decimal(const uint64_t value, string & result) {
		// Место, в которое помещается запись числа
		char buffer[24];
		// Составляем десятичную запись числа
		const int32_t written = ::snprintf(buffer, sizeof(buffer), "%llu", static_cast <unsigned long long> (value));
		// Если запись составлена
		if(written > 0)
			// Дописываем запись к строке
			result.append(buffer, static_cast <size_t> (written));
	}
	/**
	 * @brief Функция дописывания шестнадцатеричной записи числа в четыре знака к строке
	 *
	 * @param value  записываемое число
	 * @param result строка, к которой дописывается запись
	 *
	 */
	static void quartet(const uint16_t value, string & result) {
		// Место, в которое помещается запись числа
		char buffer[8];
		// Составляем шестнадцатеричную запись числа
		const int32_t written = ::snprintf(buffer, sizeof(buffer), "%04x", static_cast <uint32_t> (value));
		// Если запись составлена
		if(written > 0)
			// Дописываем запись к строке
			result.append(buffer, static_cast <size_t> (written));
	}
	/**
	 * @brief Функция дописывания шестнадцатеричной записи байтов к строке
	 *
	 * @param data   записываемые байты
	 * @param size   число байтов
	 * @param result строка, к которой дописывается запись
	 *
	 */
	static void hexed(const uint8_t * data, const size_t size, string & result) {
		// Знаки шестнадцатеричной записи
		static const char DIGITS[] = "0123456789abcdef";
		/**
		 * Выполняем перебор байтов
		 */
		for(size_t i = 0; i < size; i++){
			// Дописываем старшую половину байта
			result.push_back(DIGITS[data[i] >> 4]);
			// Дописываем младшую половину байта
			result.push_back(DIGITS[data[i] & 0x0F]);
		}
	}
	/**
	 * @brief Функция хеширования строки с выдачей шестнадцатеричной записи
	 *
	 * @param algorithm алгоритм хеширования
	 * @param text      хешируемая строка
	 * @param count     число байтов хеша, выдаваемых записью (ноль - все)
	 * @param result    строка, к которой дописывается запись хеша
	 * @return          результат хеширования
	 *
	 */
	static bool digesting(const digest::hash_t algorithm, const string & text, const size_t count, string & result) {
		// Место, в которое помещается хеш
		uint8_t hash[64];
		// Размер хеша алгоритма
		const size_t size = digest::length(algorithm);
		// Если хеш выработать не удалось
		if((size == 0) || (size > sizeof(hash)) || !digest::hash(algorithm, view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size()), hash, size))
			// Выводим отказ хеширования
			return false;
		// Дописываем запись хеша
		hexed(hash, ((count == 0) || (count > size)) ? size : count, result);
		// Выводим успешность хеширования
		return true;
	}
	/**
	 * @brief Функция дописывания перечня чисел через разделитель
	 *
	 * @param values    перечень чисел
	 * @param separator разделитель
	 * @param wide      признак шестнадцатеричной записи в четыре знака (иначе десятичная)
	 * @param result    строка, к которой дописывается перечень
	 *
	 */
	static void listing(const vector <uint16_t> & values, const char separator, const bool wide, string & result) {
		/**
		 * Выполняем перебор чисел
		 */
		for(size_t i = 0; i < values.size(); i++){
			// Если число не первое
			if(i > 0)
				// Дописываем разделитель
				result.push_back(separator);
			// Если запись шестнадцатеричная
			if(wide)
				// Дописываем шестнадцатеричную запись числа
				quartet(values[i], result);
			// Если запись десятичная
			else decimal(values[i], result);
		}
	}
	/**
	 * @brief Функция дописывания перечня значений с пометкой GREASE
	 *
	 * @param values перечень значений
	 * @param result строка, к которой дописывается перечень
	 *
	 */
	static void marking(const vector <uint16_t> & values, string & result) {
		/**
		 * Выполняем перебор значений
		 */
		for(size_t i = 0; i < values.size(); i++){
			// Если значение не первое
			if(i > 0)
				// Дописываем разделитель
				result.push_back('-');
			// Если значение есть значение GREASE
			if(fingerprint::grease(values[i]))
				// Дописываем пометку GREASE
				result.append("GREASE");
			// Если значение обычное
			else decimal(values[i], result);
		}
	}
	/**
	 * @brief Функция поиска расширения профиля по виду
	 *
	 * @param profile профиль приветствия
	 * @param type    вид расширения по проводу
	 * @return        найденное расширение либо nullptr
	 *
	 */
	static const fingerprint::extension_t * seek(const fingerprint::profile_t & profile, const uint16_t type) noexcept {
		/**
		 * Выполняем перебор расширений профиля
		 */
		for(size_t i = 0; i < profile.extensions.size(); i++){
			// Если вид расширения совпал
			if(profile.extensions[i].type == type)
				// Выводим найденное расширение
				return &profile.extensions[i];
		}
		// Выводим отсутствие расширения
		return nullptr;
	}
	/**
	 * @brief Функция составления шестнадцатеричной записи числа с шириной четыре знака
	 *
	 * @param value записываемое число
	 * @return      запись вида "0x%04X"
	 *
	 */
	static string __ants_hex16__(const uint16_t value) noexcept {
		// Место записи числа
		char buffer[8];
		// Составляем запись числа
		const int32_t written = ::snprintf(buffer, sizeof(buffer), "0x%04X", value);
		// Выводим запись числа
		return ((written > 0) ? string(buffer, static_cast <size_t> (written)) : string());
	}
	/**
	 * @brief Функция составления шестнадцатеричной записи числа с шириной два знака
	 *
	 * @param value записываемое число
	 * @return      запись вида "0x%02X"
	 *
	 */
	static string __ants_hex8__(const uint8_t value) noexcept {
		// Место записи числа
		char buffer[6];
		// Составляем запись числа
		const int32_t written = ::snprintf(buffer, sizeof(buffer), "0x%02X", value);
		// Выводим запись числа
		return ((written > 0) ? string(buffer, static_cast <size_t> (written)) : string());
	}
	/**
	 * @brief Функция возвращения имени алгоритма сжатия по его коду (как в AWH)
	 *
	 * @param id код алгоритма сжатия
	 * @return   имя алгоритма сжатия
	 *
	 */
	static const char * __ants_compress_alg_name__(const uint8_t id) noexcept {
		/**
		 * Определяем имя для кода алгоритма сжатия
		 */
		switch(id){
			// Если код алгоритма сжатия соответствует Zlib
			case 0x01: return "Zlib";
			// Если код алгоритма сжатия соответствует Brotli
			case 0x02: return "Brotli";
			// Если код алгоритма сжатия соответствует ZStandard (Zstd)
			case 0x03: return "Zstandard (ZSTD)";
			// Если код алгоритма сжатия не распознан, возвращаем "UNKNOWN"
			default: return "UNKNOWN";
		}
	}
	/**
	 * @brief Функция возвращения имени издания протокола по его коду (как в AWH)
	 *
	 * @param version код издания протокола
	 * @return        имя издания протокола
	 *
	 */
	static const char * __ants_tls_version_name__(const uint16_t version) noexcept {
		// Если версия является GREASE, возвращаем "GREASE"
		if(fingerprint::grease(version))
			// Возвращаем строку "GREASE" для GREASE версий
			return "[GREASE]";
		/**
		 * Определяем имя для кода версии TLS
		 */
		switch(version){
			// Если код версии соответствует SSL 3.0, возвращаем "SSLv3"
			case 0x0300: return "SSLv3";
			// Если код версии соответствует TLS 1.0, возвращаем "TLSv1.0"
			case 0x0301: return "TLSv1.0";
			// Если код версии соответствует TLS 1.1, возвращаем "TLSv1.1"
			case 0x0302: return "TLSv1.1";
			// Если код версии соответствует TLS 1.2, возвращаем "TLSv1.2"
			case 0x0303: return "TLSv1.2";
			// Если код версии соответствует TLS 1.3, возвращаем "TLSv1.3"
			case 0x0304: return "TLSv1.3";
			// Если код версии соответствует DTLS 1.0, возвращаем "DTLSv1.0"
			case EDITION_DTLS10: return "DTLSv1.0";
			// Если код версии соответствует DTLS 1.2, возвращаем "DTLSv1.2"
			case EDITION_DTLS12: return "DTLSv1.2";
			// Если код версии соответствует DTLS 1.3, возвращаем "DTLSv1.3"
			case EDITION_DTLS13: return "DTLSv1.3";
			// Если код версии не распознан, возвращаем "UNKNOWN"
			default: return "UNKNOWN";
		}
	}
	/**
	 * @brief Функция возвращения имени группы обмена ключами по её коду (как в AWH)
	 *
	 * @param gid код группы обмена ключами
	 * @return    имя группы обмена ключами
	 *
	 */
	static const char * __ants_group_name__(const uint16_t gid) noexcept {
		// Если код группы является GREASE, возвращаем "GREASE"
		if(fingerprint::grease(gid))
			// Возвращаем строку "GREASE" для GREASE кодов групп
			return "[GREASE]";
		/**
		 * Определяем код группы
		 */
		switch(gid){
			// Если группа соответствует secp256k1
			case 0x001C: return "secp256k1";
			// Если группа соответствует P-256 (secp256r1)
			case 0x0017: return "P-256 (secp256r1)";
			// Если группа соответствует P-384 (secp384r1)
			case 0x0018: return "P-384 (secp384r1)";
			// Если группа соответствует P-521 (secp521r1)
			case 0x0019: return "P-521 (secp521r1)";
			// Если группа соответствует X25519
			case 0x001D: return "X25519";
			// Если группа соответствует X448
			case 0x001E: return "X448";
			// Если группа соответствует FFDHE 2048
			case 0x0100: return "ffdhe2048";
			// Если группа соответствует FFDHE 3072
			case 0x0101: return "ffdhe3072";
			// Если группа соответствует FFDHE 4096
			case 0x0102: return "ffdhe4096";
			// Если группа соответствует FFDHE 6144
			case 0x0103: return "ffdhe6144";
			// Если группа соответствует FFDHE 8192
			case 0x0104: return "ffdhe8192";
			// Если группа соответствует MLKEM 1024
			case 0x0202: return "mlkem1024";
			// Если группа соответствует X25519Kyber768Draft00
			case 0x6399: return "X25519Kyber768Draft00";
			// Если группа соответствует X25519MLKEM768
			case 0x11EC: return "X25519MLKEM768";
			// Если группа не соответствует ни одной из известных
			default: return "UNKNOWN";
		}
	}
	/**
	 * @brief Функция возвращения имени схемы подписи по её коду (как в AWH)
	 *
	 * @param id код схемы подписи
	 * @return   имя схемы подписи
	 *
	 */
	static const char * __ants_signature_name__(const uint16_t id) noexcept {
		// Если код схемы подписи является GREASE, возвращаем "GREASE"
		if(fingerprint::grease(id))
			// Возвращаем строку "GREASE" для GREASE кодов схем подписи
			return "[GREASE]";
		/**
		 * Определяем имя для кода схемы подписи
		 */
		switch(id){
			// Если код схемы подписи соответствует DSA_SHA1
			case 0x0202: return "dsa_sha1";
			// Если код схемы подписи соответствует RSA_PKCS1_SHA1
			case 0x0201: return "rsa_pkcs1_sha1";
			// Если код схемы подписи соответствует ECDSA_SHA1
			case 0x0203: return "ecdsa_sha1";
			// Если код схемы подписи соответствует RSA_PKCS1_SHA256_LEGACY
			case 0x0420: return "rsa_pkcs1_sha256_legacy";
			// Если код схемы подписи соответствует RSA_PKCS1_SHA256
			case 0x0401: return "rsa_pkcs1_sha256";
			// Если код схемы подписи соответствует ECDSA_SECP256R1_SHA256
			case 0x0403: return "ecdsa_secp256r1_sha256";
			// Если код схемы подписи соответствует RSA_PKCS1_SHA384
			case 0x0501: return "rsa_pkcs1_sha384";
			// Если код схемы подписи соответствует ECDSA_SECP384R1_SHA384
			case 0x0503: return "ecdsa_secp384r1_sha384";
			// Если код схемы подписи соответствует RSA_PKCS1_SHA512
			case 0x0601: return "rsa_pkcs1_sha512";
			// Если код схемы подписи соответствует ECDSA_SECP521R1_SHA512
			case 0x0603: return "ecdsa_secp521r1_sha512";
			// Если код схемы подписи соответствует RSA_PSS_RSAE_SHA256
			case 0x0804: return "rsa_pss_rsae_sha256";
			// Если код схемы подписи соответствует RSA_PSS_RSAE_SHA384
			case 0x0805: return "rsa_pss_rsae_sha384";
			// Если код схемы подписи соответствует RSA_PSS_RSAE_SHA512
			case 0x0806: return "rsa_pss_rsae_sha512";
			// Если код схемы подписи соответствует EdDSA-25519
			case 0x0807: return "ed25519";
			// Если код схемы подписи соответствует EdDSA-448
			case 0x0808: return "ed448";
			// Если код схемы подписи соответствует RSA_PSS_PSS_SHA256
			case 0x0809: return "rsa_pss_pss_sha256";
			// Если код схемы подписи соответствует RSA_PSS_PSS_SHA384
			case 0x080A: return "rsa_pss_pss_sha384";
			// Если код схемы подписи соответствует RSA_PSS_PSS_SHA512
			case 0x080B: return "rsa_pss_pss_sha512";
			// Если код схемы подписи соответствует RSA_PKCS1_MD5_SHA1
			case 0xFF01: return "rsa_pkcs1_md5_sha1";
			// Если код схемы подписи не распознан, возвращаем "UNKNOWN"
			default: return "UNKNOWN";
		}
	}
	/**
	 * @brief Функция возвращения имени набора шифрования по его коду (как в AWH)
	 *
	 * @param id код набора шифрования
	 * @return   имя набора шифрования
	 *
	 */
	static const char * __ants_cipher_name__(const uint16_t id) noexcept {
		// Если код набора является GREASE, возвращаем "GREASE"
		if(fingerprint::grease(id))
			// Возвращаем строку "GREASE" для GREASE кодов наборов
			return "[GREASE]";
		/**
		 * Определяем код набора
		 */
		switch(id){
			// Если код набора соответствует AES128-SHA
			case 0x002F: return "AES128-SHA";
			// Если код набора соответствует AES256-SHA
			case 0x0035: return "AES256-SHA";
			// Если код набора соответствует PSK-AES128-CBC-SHA
			case 0x008C: return "PSK-AES128-CBC-SHA";
			// Если код набора соответствует PSK-AES256-CBC-SHA
			case 0x008D: return "PSK-AES256-CBC-SHA";
			// Если код набора соответствует AES128-GCM-SHA256
			case 0x009C: return "AES128-GCM-SHA256";
			// Если код набора соответствует AES256-GCM-SHA384
			case 0x009D: return "AES256-GCM-SHA384";
			// Если код набора соответствует ECDHE-ECDSA-AES128-SHA
			case 0xC009: return "ECDHE-ECDSA-AES128-SHA";
			// Если код набора соответствует ECDHE-ECDSA-AES256-SHA
			case 0xC00A: return "ECDHE-ECDSA-AES256-SHA";
			// Если код набора соответствует ECDHE-RSA-AES128-SHA
			case 0xC013: return "ECDHE-RSA-AES128-SHA";
			// Если код набора соответствует ECDHE-RSA-AES256-SHA
			case 0xC014: return "ECDHE-RSA-AES256-SHA";
			// Если код набора соответствует ECDHE-ECDSA-AES128-SHA256
			case 0xC023: return "ECDHE-ECDSA-AES128-SHA256";
			// Если код набора соответствует ECDHE-RSA-AES128-SHA256
			case 0xC027: return "ECDHE-RSA-AES128-SHA256";
			// Если код набора соответствует ECDHE-RSA-AES128-GCM-SHA256
			case 0xC02F: return "ECDHE-RSA-AES128-GCM-SHA256";
			// Если код набора соответствует ECDHE-ECDSA-AES128-GCM-SHA256
			case 0xC02B: return "ECDHE-ECDSA-AES128-GCM-SHA256";
			// Если код набора соответствует ECDHE-RSA-AES256-GCM-SHA384
			case 0xC030: return "ECDHE-RSA-AES256-GCM-SHA384";
			// Если код набора соответствует ECDHE-ECDSA-AES256-GCM-SHA384
			case 0xC02C: return "ECDHE-ECDSA-AES256-GCM-SHA384";
			// Если код набора соответствует ECDHE-RSA-CHACHA20-POLY1305
			case 0xCCA8: return "ECDHE-RSA-CHACHA20-POLY1305";
			// Если код набора соответствует ECDHE-ECDSA-CHACHA20-POLY1305
			case 0xCCA9: return "ECDHE-ECDSA-CHACHA20-POLY1305";
			// Если код набора соответствует ECDHE-PSK-AES128-CBC-SHA
			case 0xC035: return "ECDHE-PSK-AES128-CBC-SHA";
			// Если код набора соответствует ECDHE-PSK-AES256-CBC-SHA
			case 0xC036: return "ECDHE-PSK-AES256-CBC-SHA";
			// Если код набора соответствует ECDHE-PSK-CHACHA20-POLY1305
			case 0xCCAC: return "ECDHE-PSK-CHACHA20-POLY1305";
			// Если код набора соответствует TLS_AES_128_GCM_SHA256
			case 0x1301: return "TLS_AES_128_GCM_SHA256";
			// Если код набора соответствует TLS_AES_256_GCM_SHA384
			case 0x1302: return "TLS_AES_256_GCM_SHA384";
			// Если код набора соответствует TLS_CHACHA20_POLY1305_SHA256
			case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256";
			// Если код набора не соответствует ни одному из известных
			default: return "UNKNOWN";
		}
	}
	/**
	 * @brief Функция возвращения имени расширения по его коду (как в AWH)
	 *
	 * @param type код расширения по проводу
	 * @return     имя расширения
	 *
	 */
	static const char * __ants_extension_name__(const uint16_t type) noexcept {
		// Если код расширения является GREASE, возвращаем "GREASE"
		if(fingerprint::grease(type))
			// Возвращаем строку "GREASE" для GREASE кодов расширений
			return "[GREASE]";
		/**
		 * Определяем имя для кода расширения
		 */
		switch(type){
			// Если код расширения соответствует server_name (RFC 6066)
			case 0x0000: return "server_name";
			// Если код расширения соответствует max_fragment_length (RFC 6066)
			case 0x0001: return "max_fragment_length";
			// Если код расширения соответствует status_request (RFC 6066) (OCSP)
			case 0x0005: return "status_request";
			// Если код расширения соответствует supported_groups (RFC 8422)
			case 0x000A: return "supported_groups";
			// Если код расширения соответствует ec_point_formats (RFC 8422)
			case 0x000B: return "ec_point_formats";
			// Если код расширения соответствует signature_algorithms (RFC 8446)
			case 0x000D: return "signature_algorithms";
			// Если код расширения соответствует use_srtp (RFC 5764)
			case 0x000E: return "use_srtp";
			// Если код расширения соответствует heartbeat (RFC 6520)
			case 0x000F: return "heartbeat";
			// Если код расширения соответствует application_layer_protocol_negotiation (RFC 7301)
			case 0x0010: return "application_layer_protocol_negotiation";
			// Если код расширения соответствует signed_certificate_timestamp (RFC 6962)
			case 0x0012: return "signed_certificate_timestamp";
			// Если код расширения соответствует client_certificate_type (RFC 7250)
			case 0x0013: return "client_certificate_type";
			// Если код расширения соответствует server_certificate_type (RFC 7250)
			case 0x0014: return "server_certificate_type";
			// Если код расширения соответствует padding (RFC 7685)
			case 0x0015: return "padding";
			// Если код расширения соответствует encrypt_then_mac (RFC 7366)
			case 0x0016: return "encrypt_then_mac";
			// Если код расширения соответствует extended_master_secret (RFC 7627)
			case 0x0017: return "extended_master_secret";
			// Если код расширения соответствует compress_certificate (RFC 8879)
			case 0x001B: return "compress_certificate";
			// Если код расширения соответствует record_size_limit (RFC 8449)
			case 0x001C: return "record_size_limit";
			// Если код расширения соответствует delegated_credential (RFC 9345)
			case 0x0022: return "delegated_credential";
			// Если код расширения соответствует session_ticket (RFC 5077)
			case 0x0023: return "session_ticket";
			// Если код расширения соответствует pre_shared_key (RFC 8446)
			case 0x0029: return "pre_shared_key";
			// Если код расширения соответствует early_data (RFC 8446)
			case 0x002A: return "early_data";
			// Если код расширения соответствует supported_versions (RFC 8446)
			case 0x002B: return "supported_versions";
			// Если код расширения соответствует cookie (RFC 8446)
			case 0x002C: return "cookie";
			// Если код расширения соответствует psk_key_exchange_modes (RFC 8446)
			case 0x002D: return "psk_key_exchange_modes";
			// Если код расширения соответствует certificate_authorities (RFC 8446)
			case 0x002F: return "certificate_authorities";
			// Если код расширения соответствует oid_filters (RFC 8446)
			case 0x0030: return "oid_filters";
			// Если код расширения соответствует post_handshake_auth (RFC 8446)
			case 0x0031: return "post_handshake_auth";
			// Если код расширения соответствует signature_algorithms_cert (RFC 8446)
			case 0x0032: return "signature_algorithms_cert";
			// Если код расширения соответствует key_share (RFC 8446)
			case 0x0033: return "key_share";
			// Если код расширения соответствует transparency_info (редко)
			case 0x0035: return "transparency_info";
			// Если код расширения соответствует quic_transport_parameters (RFC 9001)
			case 0x0039: return "quic_transport_parameters";
			// Если код расширения соответствует tls_flags (draft)
			case 0x003E: return "tls_flags";
			// Если код расширения соответствует next_proto_neg (NPN, предшественник ALPN)
			case 0x3374: return "next_proto_neg";
			// Если код расширения соответствует application_settings_old (Chrome legacy ALPS)
			case 0x4469: return "application_settings_old";
			// Если код расширения соответствует application_settings (ALPS новый стандарт)
			case 0x44CD: return "application_settings";
			// Если код расширения соответствует channel_id (BoringSSL)
			case 0x7550: return "channel_id";
			// Если код расширения соответствует trust_anchors (BoringSSL draft)
			case 0xCA34: return "trust_anchors";
			// Если код расширения соответствует ech_outer_extensions (ECH outer)
			case 0xFD00: return "ech_outer_extensions";
			// Если код расширения соответствует extensionEncryptedClientHello (ECH / GREASE)
			case 0xFE0D: return "extensionEncryptedClientHello";
			// Если код расширения соответствует extensionRenegotiationInfo (RFC 5746)
			case 0xFF01: return "extensionRenegotiationInfo";
			// Если код расширения соответствует quic_transport_parameters_legacy (BoringSSL legacy QUIC)
			case 0xFFA5: return "quic_transport_parameters_legacy";
			// Если код расширения не соответствует ни одному из известных
			default: return "UNKNOWN";
		}
	}
	/**
	 * @brief Функция подсчёта доверенных центров в теле certificate_authorities
	 *
	 * @param data тело расширения: двухбайтовая длина перечня, далее имена с двухбайтовыми длинами
	 * @return     число доверенных центров
	 *
	 */
	static size_t __ants_ca_count__(const vector <uint8_t> & data) noexcept {
		// Если тело короче длины перечня
		if(data.size() < 2)
			// Выводим отсутствие центров
			return 0;
		// Смещение внутри тела: за двухбайтовой длиной перечня
		size_t offset = 2;
		// Число доверенных центров
		size_t count = 0;
		/**
		 * Выполняем обход перечня имен
		 */
		while(offset < data.size()){
			// Если длина имени оборвана
			if((offset + 2) > data.size())
				// Обрыв: возвращаем то, что насчитано
				return count;
			// Длина имени
			const size_t length = twain(data.data() + offset);
			// Переходим к имени
			offset += 2;
			// Если имя оборвано
			if((offset + length) > data.size())
				// Обрыв: возвращаем то, что насчитано
				return count;
			// Переходим за имя
			offset += length;
			// Считаем центр
			count++;
		}
		// Выводим число доверенных центров
		return count;
	}
	/**
	 * @brief Функция разбора перечня строк с однобайтовыми длинами и двухбайтовой длиной перечня
	 *
	 * @param data   тело расширения
	 * @param result перечень строк
	 * @return       результат разбора
	 *
	 */
	static bool naming(const view_t & data, vector <string> & result) {
		// Если тело короче длины перечня
		if(data.size < 2)
			// Выводим отказ разбора
			return false;
		// Длина перечня
		const size_t length = twain(data.data);
		// Если перечень в тело не входит либо за ним идут лишние байты
		if((length + 2) != data.size)
			// Выводим отказ разбора
			return false;
		// Смещение внутри перечня
		size_t offset = 2;
		/**
		 * Выполняем перебор строк перечня
		 */
		while(offset < data.size){
			// Длина очередной строки
			const size_t size = data.data[offset++];
			// Если строка в перечень не входит
			if((offset + size) > data.size)
				// Выводим отказ разбора
				return false;
			// Добавляем строку в перечень
			result.push_back(string(reinterpret_cast <const char *> (data.data + offset), size));
			// Переходим к следующей строке
			offset += size;
		}
		// Выводим успешность разбора
		return true;
	}
	/**
	 * @brief Функция разбора перечня двухбайтовых значений с двухбайтовой длиной перечня
	 *
	 * @param data   тело расширения
	 * @param tail   допустимость хвоста за перечнем (например MKI у use_srtp)
	 * @param result перечень значений
	 * @return       результат разбора
	 *
	 */
	static bool valuing(const view_t & data, const bool tail, vector <uint16_t> & result) {
		// Если тело короче длины перечня
		if(data.size < 2)
			// Выводим отказ разбора
			return false;
		// Длина перечня
		const size_t length = twain(data.data);
		// Если перечень в тело не входит, длина нечётна либо за ним недопустимые байты
		if(((length + 2) > data.size) || ((length % 2) != 0) || (!tail && ((length + 2) != data.size)))
			// Выводим отказ разбора
			return false;
		/**
		 * Выполняем перебор значений перечня
		 */
		for(size_t i = 0; i < length; i += 2)
			// Добавляем значение в перечень
			result.push_back(twain(data.data + 2 + i));
		// Выводим успешность разбора
		return true;
	}
	/**
	 * @brief Функция перевода отказа разбора расширения в отказ модуля
	 *
	 * @param error отказ разбора расширения
	 * @return      отказ модуля
	 *
	 */
	static fingerprint::error_t rendered(const extension::error_t error) noexcept {
		// Нехватка памяти передаётся своим кодом, прочие отказы означают порченое расширение
		return ((error == extension::error_t::NONE) ? fingerprint::error_t::NONE : ((error == extension::error_t::MEMORY) ? fingerprint::error_t::MEMORY : fingerprint::error_t::EXTENSION));
	}
	/**
	 * @brief Функция разбора тела расширения в поля профиля
	 *
	 * @param extension расширение с заполненными видом и телом
	 * @return          отказ разбора: NONE, EXTENSION либо MEMORY
	 *
	 */
	static fingerprint::error_t decode(fingerprint::extension_t & extension) {
		// Тело расширения
		const view_t data(extension.data.data(), extension.data.size());
		// Признак того, что вид расширения есть значение GREASE
		extension.grease = fingerprint::grease(extension.type);
		// Если расширение есть значение GREASE: тело его произвольно
		if(extension.grease)
			// Выводим успешность разбора
			return fingerprint::error_t::NONE;
		/**
		 * Определяем вид расширения
		 */
		switch(extension.type){
			// Имя запрашиваемого узла
			case static_cast <uint16_t> (extension::type_t::NAME): {
				// Имя узла
				view_t name;
				// Если имя узла разобрать не удалось
				if(extension::name(data, name) != extension::error_t::NONE)
					// Выводим отказ разбора
					return rendered(extension::name(data, name));
				// Добавляем имя узла в перечень
				extension.names.push_back(string(reinterpret_cast <const char *> (name.data), name.size));
			} break;
			// Запрос состояния сертификата: первый байт есть вид состояния
			case static_cast <uint16_t> (extension::type_t::STATUS): {
				// Если тело пусто
				if(data.size < 1)
					// Выводим отказ разбора
					return fingerprint::error_t::EXTENSION;
				// Запоминаем вид состояния
				extension.value = data.data[0];
			} break;
			// Группы обмена ключами
			case static_cast <uint16_t> (extension::type_t::GROUPS):
				// Выводим итог разбора перечня групп
				return rendered(extension::groups(data, extension.groups));
			// Записи точек кривой
			case static_cast <uint16_t> (extension::type_t::FORMATS):
				// Выводим итог разбора перечня записей точек
				return rendered(extension::formats(data, extension.formats));
			// Схемы подписи
			case static_cast <uint16_t> (extension::type_t::SCHEMES):
			// Схемы подписи сертификата
			case WIRE_CERTIFIED:
			// Схемы подписи делегированных полномочий
			case WIRE_DELEGATED:
				// Выводим итог разбора перечня схем
				return rendered(extension::schemes(data, extension.schemes));
			// Прикладные протоколы
			case static_cast <uint16_t> (extension::type_t::PROTOCOLS):
			// Прикладные настройки ALPS новой точкой кода
			case static_cast <uint16_t> (extension::type_t::SETTINGS):
			// Прикладные настройки ALPS прежней точкой кода
			case static_cast <uint16_t> (extension::type_t::SETTINGS_OLD):
				// Выводим итог разбора перечня протоколов
				return (naming(data, extension.protocols) ? fingerprint::error_t::NONE : fingerprint::error_t::EXTENSION);
			// Выработка следующего протокола: тело того же вида, что у прикладных протоколов,
			// но пустое тело допустимо - клиент лишь заявляет о поддержке выработки
			case static_cast <uint16_t> (extension::type_t::NEGOTIATION): {
				// Если тело пусто: заявление о поддержке, перечня нет
				if(data.size == 0)
					// Выводим успешность разбора
					return fingerprint::error_t::NONE;
				// Выводим итог разбора перечня протоколов
				return (naming(data, extension.protocols) ? fingerprint::error_t::NONE : fingerprint::error_t::EXTENSION);
			}
			// Алгоритмы сжатия цепочки
			case static_cast <uint16_t> (extension::type_t::COMPRESS): {
				// Перечень опознавателей алгоритмов
				vector <uint16_t> list;
				// Если перечень алгоритмов разобрать не удалось
				if(extension::algorithms(data, list) != extension::error_t::NONE)
					// Выводим отказ разбора
					return rendered(extension::algorithms(data, list));
				/**
				 * Выполняем перебор опознавателей алгоритмов
				 */
				for(size_t i = 0; i < list.size(); i++)
					// Добавляем алгоритм в перечень
					extension.algorithms.push_back(static_cast <extension::compression_t> (list[i]));
			} break;
			// Заранее разделённые ключи
			case static_cast <uint16_t> (extension::type_t::SECRET): {
				// Опознаватели ключей
				vector <extension::identity_t> identities;
				// Привязки ключей
				vector <view_t> binders;
				// Длина усечения переписки
				size_t truncation = 0;
				// Если опознаватели разобрать не удалось
				if(extension::identities(data, identities, binders, truncation) != extension::error_t::NONE)
					// Выводим отказ разбора
					return rendered(extension::identities(data, identities, binders, truncation));
				/**
				 * Выполняем перебор опознавателей ключей
				 */
				for(size_t i = 0; i < identities.size(); i++){
					// Опознаватель ключа профиля
					fingerprint::identity_t identity;
					// Переносим скрытый возраст билета
					identity.age = identities[i].age;
					// Переносим опознаватель ключа
					identity.identity.assign(identities[i].identity.data, identities[i].identity.data + identities[i].identity.size);
					// Добавляем опознаватель в перечень
					extension.identities.push_back(identity);
				}
			} break;
			// Упреждающие данные: в приветствии клиента тело пусто, в билете - предел
			case static_cast <uint16_t> (extension::type_t::EARLY): {
				// Если тело несёт предел упреждения
				if(data.size == 4)
					// Запоминаем предел упреждения
					extension.value = tetrad(data.data);
				// Если тело не пусто и не предел
				else if(data.size != 0)
					// Выводим отказ разбора
					return fingerprint::error_t::EXTENSION;
			} break;
			// Издания протокола
			case static_cast <uint16_t> (extension::type_t::VERSIONS):
				// Выводим итог разбора перечня изданий
				return rendered(extension::versions(data, extension.versions));
			// Способы обмена заранее разделённым ключом
			case static_cast <uint16_t> (extension::type_t::MODES):
				// Выводим итог разбора перечня способов
				return rendered(extension::modes(data, extension.modes));
			// Открытые части ключей обмена
			case static_cast <uint16_t> (extension::type_t::SHARE): {
				// Доли ключей
				vector <extension::share_t> shares;
				// Если доли разобрать не удалось
				if(extension::shares(data, shares) != extension::error_t::NONE)
					// Выводим отказ разбора
					return rendered(extension::shares(data, shares));
				/**
				 * Выполняем перебор долей ключей
				 */
				for(size_t i = 0; i < shares.size(); i++){
					// Доля ключа профиля
					fingerprint::share_t share;
					// Переносим группу доли
					share.group = shares[i].group;
					// Переносим открытую часть ключа
					share.key.assign(shares[i].key.data, shares[i].key.data + shares[i].key.size);
					// Добавляем долю в перечень
					extension.shares.push_back(share);
				}
			} break;
			// Предел длины куска: один байт кода
			case WIRE_FRAGMENT:
			// Сердцебиение: один байт режима
			case WIRE_HEARTBEAT: {
				// Если тело не в один байт
				if(data.size != 1)
					// Выводим отказ разбора
					return fingerprint::error_t::EXTENSION;
				// Запоминаем байт тела: код предела либо режим сердцебиения
				extension.value = data.data[0];
			} break;
			// Профили SRTP: перечень с двухбайтовой длиной и MKI следом
			case WIRE_SRTP:
				// Выводим итог разбора перечня профилей
				return (valuing(data, true, extension.values) ? fingerprint::error_t::NONE : fingerprint::error_t::EXTENSION);
			// Заполнение: значимо лишь длиной
			case WIRE_PADDING:
				// Запоминаем длину заполнения
				extension.value = static_cast <uint32_t> (data.size);
			break;
			// Предел размера записи: два байта
			case WIRE_LIMIT: {
				// Если тело не в два байта
				if(data.size != 2)
					// Выводим отказ разбора
					return fingerprint::error_t::EXTENSION;
				// Запоминаем предел записи
				extension.value = twain(data.data);
			} break;
			// Виды расширений, вынесенных наружу ECH: перечень с однобайтовой длиной
			case WIRE_OUTER: {
				// Если тело короче длины перечня
				if(data.size < 1)
					// Выводим отказ разбора
					return fingerprint::error_t::EXTENSION;
				// Длина перечня
				const size_t length = data.data[0];
				// Если перечень в тело не входит либо длина нечётна
				if(((length + 1) != data.size) || ((length % 2) != 0))
					// Выводим отказ разбора
					return fingerprint::error_t::EXTENSION;
				/**
				 * Выполняем перебор видов расширений
				 */
				for(size_t i = 0; i < length; i += 2)
					// Добавляем вид расширения в перечень
					extension.values.push_back(twain(data.data + 1 + i));
			} break;
			// Прочие расширения хранятся сырым телом
			default: break;
		}
		// Выводим успешность разбора
		return fingerprint::error_t::NONE;
	}
	/**
	 * @brief Функция переноса разобранного приветствия в профиль
	 *
	 * @param greeting разобранное приветствие клиента
	 * @param profile  заполняемый профиль
	 * @return         отказ переноса
	 *
	 */
	static fingerprint::error_t transfer(const hello::client_t & greeting, fingerprint::profile_t & profile) {
		// Переносим издание приветствия
		profile.version = greeting.version;
		// Переносим случайное значение приветствия
		::memcpy(profile.random, greeting.random, fingerprint::FINGERPRINT_RANDOM);
		// Переносим опознаватель связи
		profile.session = greeting.session;
		// Переносим метку возврата состояния
		profile.cookie = greeting.cookie;
		// Переносим способы сжатия
		profile.methods = greeting.methods;
		/**
		 * Выполняем перебор наборов шифрования
		 */
		for(size_t i = 0; i < greeting.suites.size(); i++){
			// Если набор есть значение GREASE
			if(fingerprint::grease(greeting.suites[i]))
				// Отмечаем, что приветствие несёт значения GREASE
				profile.grease = true;
			// Добавляем набор в профиль числом по проводу
			profile.suites.push_back(static_cast <protect::suite_t> (greeting.suites[i]));
		}
		/**
		 * Выполняем перебор расширений приветствия
		 */
		for(size_t i = 0; i < greeting.extensions.size(); i++){
			// Расширение профиля
			fingerprint::extension_t extension;
			// Переносим вид расширения
			extension.type = greeting.extensions[i].type;
			// Переносим тело расширения
			extension.data.assign(greeting.extensions[i].data.data, greeting.extensions[i].data.data + greeting.extensions[i].data.size);
			// Отказ разбора тела расширения
			const fingerprint::error_t failure = decode(extension);
			// Если тело расширения разобрать не удалось
			if(failure != fingerprint::error_t::NONE)
				// Выводим отказ разбора расширения
				return failure;
			// Если расширение есть значение GREASE
			if(extension.grease)
				// Отмечаем, что приветствие несёт значения GREASE
				profile.grease = true;
			// Добавляем расширение в профиль
			profile.extensions.push_back(extension);
		}
		// Выводим успешность переноса
		return fingerprint::error_t::NONE;
	}
	/**
	 * @brief Функция перевода отказа разбора приветствия в отказ модуля
	 *
	 * @param error отказ разбора приветствия
	 * @return      отказ модуля
	 *
	 */
	static fingerprint::error_t translate(const hello::error_t error) noexcept {
		/**
		 * Определяем отказ разбора приветствия
		 */
		switch(error){
			// Отказа нет
			case hello::error_t::NONE:
				// Выводим отсутствие отказа
				return fingerprint::error_t::NONE;
			// Тело оборвано
			case hello::error_t::HUNGRY:
				// Выводим отказ обрыва
				return fingerprint::error_t::HUNGRY;
			// Опознаватель связи длиннее дозволенного
			case hello::error_t::SESSION:
				// Выводим отказ опознавателя
				return fingerprint::error_t::SESSION;
			// Перечень наборов сложен не по правилам
			case hello::error_t::SUITE:
				// Выводим отказ перечня наборов
				return fingerprint::error_t::SUITE;
			// Перечень способов сжатия пуст
			case hello::error_t::METHOD:
				// Выводим отказ способов сжатия
				return fingerprint::error_t::METHOD;
			// Расширение оборвано либо повторено
			case hello::error_t::EXTENSION:
				// Выводим отказ расширения
				return fingerprint::error_t::EXTENSION;
			// За телом идут лишние байты
			case hello::error_t::TRAILING:
				// Выводим отказ лишних байтов
				return fingerprint::error_t::TRAILING;
			// Памяти не хватило
			case hello::error_t::MEMORY:
				// Выводим отказ памяти
				return fingerprint::error_t::MEMORY;
			// Прочие отказы означают порченое сообщение
			default:
				// Выводим отказ сообщения
				return fingerprint::error_t::MESSAGE;
		}
	}
	/**
	 * @brief Функция разбора приветствия с заданным устройством заголовков
	 *
	 * @param data     разбираемые байты
	 * @param datagram признак заголовков поверх дейтаграмм
	 * @param result   заполняемый профиль
	 * @return         отказ разбора
	 *
	 */
	static fingerprint::error_t examine(const view_t & data, const bool datagram, fingerprint::profile_t & result) {
		// Сбрасываем профиль
		result = fingerprint::profile_t();
		// Запоминаем устройство заголовков
		result.datagram = datagram;
		// Смещение внутри разбираемых байтов
		size_t offset = 0;
		// Если байтов нет вовсе
		if((data.data == nullptr) || (data.size == 0))
			// Выводим отказ обрыва
			return fingerprint::error_t::HUNGRY;
		// Если байты начинаются записью рукопожатия
		if(data.data[0] == HANDSHAKE){
			// Размер заголовка записи
			const size_t header = (datagram ? RECORD_DATAGRAM : RECORD_STREAM);
			// Если заголовок записи оборван
			if(data.size < header)
				// Выводим отказ обрыва
				return fingerprint::error_t::HUNGRY;
			// Запоминаем издание слоя записей
			result.record = twain(data.data + 1);
			// Если издание записи не отвечает устройству заголовков
			if(datagram != ((result.record == EDITION_DTLS10) || (result.record == EDITION_DTLS12) || (result.record == EDITION_DTLS13)))
				// Выводим отказ записи
				return fingerprint::error_t::RECORD;
			// Длина записи
			size_t length = 0;
			// Если запись идёт поверх дейтаграмм
			if(datagram){
				// Запоминаем пору записи
				result.epoch = twain(data.data + 3);
				// Запоминаем порядковый номер записи
				result.sequence = ((static_cast <uint64_t> (twain(data.data + 5)) << 32) | static_cast <uint64_t> (tetrad(data.data + 7)));
				// Запоминаем длину записи
				length = twain(data.data + 11);
			// Если запись идёт потоком
			} else length = twain(data.data + 3);
			// Если тело записи оборвано
			if((header + length) > data.size)
				// Выводим отказ обрыва
				return fingerprint::error_t::HUNGRY;
			// Если за записью идут лишние байты: запись обязана нести приветствие целиком
			if((header + length) < data.size)
				// Выводим отказ лишних байтов
				return fingerprint::error_t::TRAILING;
			// Переходим к сообщению рукопожатия
			offset = header;
		// Если байты начинаются не сообщением рукопожатия
		} else if(data.data[0] != GREETING)
			// Выводим отказ записи
			return fingerprint::error_t::RECORD;
		/**
		 * Размер обвязки сообщения рукопожатия: внутри записи дейтаграммы - в 12 байтов, у
		 * голого сообщения - в 4 при любом переносе (так его держит связь сервера после сборки)
		 */
		const size_t header = ((datagram && (offset > 0)) ? HEADER_DATAGRAM : HEADER_STREAM);
		// Если заголовок сообщения оборван
		if((offset + header) > data.size)
			// Выводим отказ обрыва
			return fingerprint::error_t::HUNGRY;
		// Если сообщение не есть приветствие клиента
		if(data.data[offset] != GREETING)
			// Выводим отказ сообщения
			return fingerprint::error_t::MESSAGE;
		// Запоминаем длину тела приветствия
		result.length = triad(data.data + offset + 1);
		// Если сообщение идёт внутри записи дейтаграммы
		if(header == HEADER_DATAGRAM){
			// Запоминаем порядковый номер сообщения
			result.message = twain(data.data + offset + 4);
			// Если сообщение нарезано на куски: отпечаток снимается лишь с цельного
			if((triad(data.data + offset + 6) != 0) || (triad(data.data + offset + 9) != result.length))
				// Выводим отказ обрыва
				return fingerprint::error_t::HUNGRY;
		}
		// Переходим к телу приветствия
		offset += header;
		// Если тело приветствия оборвано
		if((offset + result.length) > data.size)
			// Выводим отказ обрыва
			return fingerprint::error_t::HUNGRY;
		// Если за телом приветствия идут лишние байты
		if((offset + result.length) < data.size)
			// Выводим отказ лишних байтов
			return fingerprint::error_t::TRAILING;
		// Разобранное приветствие клиента
		hello::client_t greeting;
		// Отказ разбора приветствия
		const fingerprint::error_t failure = translate(hello::parse(view_t(data.data + offset, result.length), greeting, datagram));
		// Если приветствие разобрать не удалось
		if(failure != fingerprint::error_t::NONE)
			// Выводим отказ разбора
			return failure;
		// Выводим итог переноса приветствия в профиль
		return transfer(greeting, result);
	}
	/**
	 * @brief Функция подсчёта старшего издания протокола профиля
	 *
	 * @param profile профиль приветствия
	 * @return        старшее издание из supported_versions без GREASE либо издание приветствия
	 *
	 */
	static uint16_t eldest(const fingerprint::profile_t & profile) noexcept {
		// Старшее издание
		uint16_t result = profile.version;
		// Расширение изданий протокола
		const fingerprint::extension_t * extension = seek(profile, static_cast <uint16_t> (extension::type_t::VERSIONS));
		// Если расширение изданий есть
		if(extension != nullptr){
			/**
			 * Выполняем перебор изданий
			 */
			for(size_t i = 0; i < extension->versions.size(); i++){
				// Если издание не GREASE и старше найденного
				if(!fingerprint::grease(extension->versions[i]) && (extension->versions[i] > result))
					// Запоминаем издание
					result = extension->versions[i];
			}
		}
		// Выводим старшее издание
		return result;
	}
	/**
	 * @brief Функция составления двух знаков издания протокола отпечатка JA4
	 *
	 * @param edition издание протокола по проводу
	 * @return        два знака издания
	 *
	 */
	static const char * lettered(const uint16_t edition) noexcept {
		/**
		 * Определяем издание протокола
		 */
		switch(edition){
			// SSL 3.0
			case 0x0300: return "s3";
			// TLS 1.0
			case 0x0301: return "10";
			// TLS 1.1
			case 0x0302: return "11";
			// TLS 1.2
			case 0x0303: return "12";
			// TLS 1.3
			case 0x0304: return "13";
			// DTLS 1.0
			case EDITION_DTLS10: return "d1";
			// DTLS 1.2
			case EDITION_DTLS12: return "d2";
			// DTLS 1.3
			case EDITION_DTLS13: return "d3";
			// Издание неведомо
			default: return "00";
		}
	}
	/**
	 * @brief Функция составления двух знаков прикладного протокола отпечатка JA4
	 *
	 * @param protocol первый прикладной протокол
	 * @param result   строка, к которой дописываются знаки
	 *
	 */
	static void abbreviated(const string & protocol, string & result) {
		// Если протокола нет
		if(protocol.empty()){
			// Дописываем знаки отсутствия
			result.append("00");
			// Выходим: отсутствие протокола записано
			return;
		}
		// Первый и последний знаки протокола
		const uint8_t first = static_cast <uint8_t> (protocol.front()), last = static_cast <uint8_t> (protocol.back());
		// Если оба знака буквенно-цифровые
		if(::isalnum(first) && ::isalnum(last)){
			// Дописываем первый знак
			result.push_back(static_cast <char> (first));
			// Дописываем последний знак
			result.push_back(static_cast <char> (last));
		// Если знаки не буквенно-цифровые: по описанию FoxIO берутся половины их шестнадцатеричной записи
		} else {
			// Знаки шестнадцатеричной записи
			static const char DIGITS[] = "0123456789abcdef";
			// Дописываем старшую половину первого байта
			result.push_back(DIGITS[first >> 4]);
			// Дописываем младшую половину последнего байта
			result.push_back(DIGITS[last & 0x0F]);
		}
	}
	/**
	 * @brief Функция дописывания счётчика в два знака с пределом 99
	 *
	 * @param count  счётчик
	 * @param result строка, к которой дописывается счётчик
	 *
	 */
	static void counted(const size_t count, string & result) {
		// Место, в которое помещается запись счётчика
		char buffer[4];
		// Составляем запись счётчика с пределом
		const int32_t written = ::snprintf(buffer, sizeof(buffer), "%02u", static_cast <uint32_t> ((count > 99) ? 99 : count));
		// Если запись составлена
		if(written > 0)
			// Дописываем запись
			result.append(buffer, static_cast <size_t> (written));
	}
	/**
	 * @brief Функция чтения целого HPACK с заданной шириной префикса
	 *
	 * @param data   байты блока заголовков
	 * @param size   размер блока
	 * @param offset смещение внутри блока (сдвигается)
	 * @param width  ширина префикса в разрядах
	 * @return       прочитанное целое
	 *
	 */
	static uint32_t packed(const uint8_t * data, const size_t size, size_t & offset, const uint8_t width) noexcept {
		// Если блок кончился
		if(offset >= size)
			// Выводим ноль
			return 0;
		// Наибольшее значение префикса
		const uint32_t limit = ((1u << width) - 1u);
		// Значение префикса
		uint32_t result = (static_cast <uint32_t> (data[offset++]) & limit);
		// Если целое уместилось в префикс
		if(result < limit)
			// Выводим целое
			return result;
		// Сдвиг очередной семёрки разрядов
		uint32_t shift = 0;
		/**
		 * Выполняем перебор байтов продолжения
		 */
		while(offset < size){
			// Очередной байт продолжения
			const uint8_t byte = data[offset++];
			// Добавляем семёрку разрядов к целому
			result += (static_cast <uint32_t> (byte & 0x7F) << shift);
			// Сдвигаем позицию следующей семёрки
			shift += 7;
			// Если продолжения нет либо целое переполнилось
			if(((byte & 0x80) == 0) || (shift >= 28))
				// Выходим из перебора
				break;
		}
		// Выводим целое
		return result;
	}
	/**
	 * @brief Функция пропуска либо чтения строки HPACK
	 *
	 * @param data   байты блока заголовков
	 * @param size   размер блока
	 * @param offset смещение внутри блока (сдвигается)
	 * @param result строка, в которую помещается незакодированное значение (пусто при кодировании Хаффмана)
	 *
	 */
	static void worded(const uint8_t * data, const size_t size, size_t & offset, string & result) {
		// Сбрасываем строку
		result.clear();
		// Если блок кончился
		if(offset >= size)
			// Выходим: блок разобран
			return;
		// Признак кодирования Хаффмана
		const bool huffman = ((data[offset] & 0x80) != 0);
		// Длина строки
		const size_t length = packed(data, size, offset, 7);
		// Если строка в блок не входит
		if((offset + length) > size){
			// Переходим к концу блока
			offset = size;
			// Выходим: строка вне блока
			return;
		}
		// Если строка не закодирована Хаффманом
		if(!huffman)
			// Переносим строку
			result.assign(reinterpret_cast <const char *> (data + offset), length);
		// Переходим за строку
		offset += length;
	}
	/**
	 * @brief Функция определения буквы псевдозаголовка по индексу статической таблицы HPACK
	 *
	 * @param index индекс статической таблицы
	 * @return      буква псевдозаголовка либо ноль
	 *
	 */
	static char indexed(const uint32_t index) noexcept {
		/**
		 * Определяем индекс статической таблицы
		 */
		switch(index){
			// :authority
			case 1: return 'a';
			// :method
			case 2: case 3: return 'm';
			// :path
			case 4: case 5: return 'p';
			// :scheme
			case 6: case 7: return 's';
			// Не псевдозаголовок
			default: return '\0';
		}
	}
	/**
	 * @brief Функция определения буквы псевдозаголовка по имени
	 *
	 * @param name имя заголовка
	 * @return     буква псевдозаголовка либо ноль
	 *
	 */
	static char named(const string & name) noexcept {
		// Если имя есть :authority
		if(name.compare(":authority") == 0)
			// Выводим букву
			return 'a';
		// Если имя есть :method
		if(name.compare(":method") == 0)
			// Выводим букву
			return 'm';
		// Если имя есть :path
		if(name.compare(":path") == 0)
			// Выводим букву
			return 'p';
		// Если имя есть :scheme
		if(name.compare(":scheme") == 0)
			// Выводим букву
			return 's';
		// Выводим отсутствие буквы
		return '\0';
	}
	/**
	 * @brief Функция разбора блока заголовков HPACK в порядок псевдозаголовков
	 *
	 * @param data   байты блока заголовков
	 * @param size   размер блока
	 * @param result строка букв псевдозаголовков в порядке появления
	 *
	 */
	static void ordering(const uint8_t * data, const size_t size, string & result) {
		// Смещение внутри блока
		size_t offset = 0;
		// Имя заголовка
		string name;
		/**
		 * Выполняем перебор записей блока заголовков
		 */
		while(offset < size){
			// Первый байт записи
			const uint8_t lead = data[offset];
			// Буква псевдозаголовка
			char letter = '\0';
			// Если запись есть индексированное поле
			if((lead & 0x80) != 0)
				// Определяем букву по индексу
				letter = indexed(packed(data, size, offset, 7));
			// Если запись есть изменение размера таблицы
			else if((lead & 0xE0) == 0x20){
				// Пропускаем размер таблицы
				packed(data, size, offset, 5);
				// Переходим к следующей записи
				continue;
			// Если запись есть поле с буквальным значением
			} else {
				// Ширина префикса индекса имени
				const uint8_t width = (((lead & 0xC0) == 0x40) ? 6 : 4);
				// Индекс имени
				const uint32_t index = packed(data, size, offset, width);
				// Если имя задано индексом
				if(index > 0)
					// Определяем букву по индексу
					letter = indexed(index);
				// Если имя задано буквально
				else {
					// Читаем имя
					worded(data, size, offset, name);
					// Определяем букву по имени
					letter = named(name);
				}
				// Пропускаем тело значения, продвигая разбор за него
				worded(data, size, offset, name);
			}
			// Если запись не псевдозаголовок: псевдозаголовки идут первыми, дальше искать нечего
			if(letter == '\0')
				// Выходим из перебора
				break;
			// Если буква ещё не встречалась
			if(result.find(letter) == string::npos)
				// Дописываем букву
				result.push_back(letter);
		}
	}
	/**
	 * @brief Функция дописывания профиля в снимок
	 *
	 * @param profile профиль приветствия
	 * @param result  накопитель снимка
	 *
	 */
	static void packing(const fingerprint::profile_t & profile, vector <uint8_t> & result) {
		// Дописываем признаки профиля
		result.push_back(static_cast <uint8_t> ((profile.grease ? 0x01 : 0x00) | (profile.datagram ? 0x02 : 0x00)));
		// Дописываем издание слоя записей
		inscribe(profile.record, 2, result);
		// Дописываем издание приветствия
		inscribe(profile.version, 2, result);
		// Дописываем пору записи
		inscribe(profile.epoch, 2, result);
		// Дописываем порядковый номер записи
		inscribe(profile.sequence, 8, result);
		// Дописываем порядковый номер сообщения
		inscribe(profile.message, 2, result);
		// Дописываем длину тела приветствия
		inscribe(profile.length, 4, result);
		// Дописываем случайное значение приветствия
		result.insert(result.end(), profile.random, profile.random + fingerprint::FINGERPRINT_RANDOM);
		// Дописываем длину опознавателя связи
		inscribe(profile.session.size(), 1, result);
		// Дописываем опознаватель связи
		result.insert(result.end(), profile.session.begin(), profile.session.end());
		// Дописываем длину метки возврата
		inscribe(profile.cookie.size(), 1, result);
		// Дописываем метку возврата
		result.insert(result.end(), profile.cookie.begin(), profile.cookie.end());
		// Дописываем число наборов шифрования
		inscribe(profile.suites.size(), 2, result);
		/**
		 * Выполняем перебор наборов шифрования
		 */
		for(size_t i = 0; i < profile.suites.size(); i++)
			// Дописываем набор шифрования
			inscribe(static_cast <uint16_t> (profile.suites[i]), 2, result);
		// Дописываем число способов сжатия
		inscribe(profile.methods.size(), 1, result);
		// Дописываем способы сжатия
		result.insert(result.end(), profile.methods.begin(), profile.methods.end());
		// Дописываем число расширений
		inscribe(profile.extensions.size(), 2, result);
		/**
		 * Выполняем перебор расширений
		 */
		for(size_t i = 0; i < profile.extensions.size(); i++){
			// Дописываем вид расширения
			inscribe(profile.extensions[i].type, 2, result);
			// Дописываем длину тела расширения
			inscribe(profile.extensions[i].data.size(), 2, result);
			// Дописываем тело расширения
			result.insert(result.end(), profile.extensions[i].data.begin(), profile.extensions[i].data.end());
		}
	}
	/**
	 * @brief Функция чтения профиля из снимка
	 *
	 * @param data   байты снимка
	 * @param offset смещение внутри снимка (сдвигается)
	 * @param result заполняемый профиль
	 * @return       отказ чтения
	 *
	 */
	static fingerprint::error_t unpacking(const view_t & data, size_t & offset, fingerprint::profile_t & result) {
		// Сбрасываем профиль
		result = fingerprint::profile_t();
		// Размер неизменной части профиля
		static constexpr size_t FIXED = (1 + 2 + 2 + 2 + 8 + 2 + 4 + fingerprint::FINGERPRINT_RANDOM + 1);
		// Если неизменная часть в снимок не входит
		if((offset + FIXED) > data.size)
			// Выводим отказ снимка
			return fingerprint::error_t::FORMAT;
		// Если признаки профиля несут неведомые разряды
		if((data.data[offset] & ~0x03) != 0)
			// Выводим отказ снимка
			return fingerprint::error_t::FORMAT;
		// Читаем признак значений GREASE
		result.grease = ((data.data[offset] & 0x01) != 0);
		// Читаем признак дейтаграмм
		result.datagram = ((data.data[offset] & 0x02) != 0);
		// Переходим за признаки
		offset += 1;
		// Читаем издание слоя записей
		result.record = twain(data.data + offset);
		// Читаем издание приветствия
		result.version = twain(data.data + offset + 2);
		// Читаем пору записи
		result.epoch = twain(data.data + offset + 4);
		// Читаем порядковый номер записи
		result.sequence = octet(data.data + offset + 6);
		// Читаем порядковый номер сообщения
		result.message = twain(data.data + offset + 14);
		// Читаем длину тела приветствия
		result.length = tetrad(data.data + offset + 16);
		// Переходим к случайному значению
		offset += 20;
		// Читаем случайное значение приветствия
		::memcpy(result.random, data.data + offset, fingerprint::FINGERPRINT_RANDOM);
		// Переходим за случайное значение
		offset += fingerprint::FINGERPRINT_RANDOM;
		// Длина опознавателя связи
		size_t length = data.data[offset++];
		// Если опознаватель связи в снимок не входит либо длиннее дозволенного
		if((length > fingerprint::FINGERPRINT_SESSION) || ((offset + length + 1) > data.size))
			// Выводим отказ снимка
			return fingerprint::error_t::FORMAT;
		// Читаем опознаватель связи
		result.session.assign(data.data + offset, data.data + offset + length);
		// Переходим за опознаватель связи
		offset += length;
		// Длина метки возврата
		length = data.data[offset++];
		// Если метка возврата в снимок не входит
		if((offset + length + 2) > data.size)
			// Выводим отказ снимка
			return fingerprint::error_t::FORMAT;
		// Читаем метку возврата
		result.cookie.assign(data.data + offset, data.data + offset + length);
		// Переходим за метку возврата
		offset += length;
		// Число наборов шифрования
		size_t count = twain(data.data + offset);
		// Переходим за число наборов
		offset += 2;
		// Снимок без наборов негоден - зеркально dump() и Store::add
		if(count == 0)
			// Выводим отказ пустого профиля
			return fingerprint::error_t::EMPTY;
		// Если наборы в снимок не входят
		if((offset + (count * 2) + 1) > data.size)
			// Выводим отказ снимка
			return fingerprint::error_t::FORMAT;
		/**
		 * Выполняем перебор наборов шифрования
		 */
		for(size_t i = 0; i < count; i++, offset += 2)
			// Читаем набор шифрования
			result.suites.push_back(static_cast <protect::suite_t> (twain(data.data + offset)));
		// Число способов сжатия
		length = data.data[offset++];
		// Если способы сжатия в снимок не входят
		if((offset + length + 2) > data.size)
			// Выводим отказ снимка
			return fingerprint::error_t::FORMAT;
		// Читаем способы сжатия
		result.methods.assign(data.data + offset, data.data + offset + length);
		// Переходим за способы сжатия
		offset += length;
		// Число расширений
		count = twain(data.data + offset);
		// Переходим за число расширений
		offset += 2;
		/**
		 * Выполняем перебор расширений
		 */
		for(size_t i = 0; i < count; i++){
			// Если заголовок расширения в снимок не входит
			if((offset + 4) > data.size)
				// Выводим отказ снимка
				return fingerprint::error_t::FORMAT;
			// Расширение профиля
			fingerprint::extension_t extension;
			// Читаем вид расширения
			extension.type = twain(data.data + offset);
			// Длина тела расширения
			length = twain(data.data + offset + 2);
			// Переходим к телу расширения
			offset += 4;
			// Если тело расширения в снимок не входит
			if((offset + length) > data.size)
				// Выводим отказ снимка
				return fingerprint::error_t::FORMAT;
			// Читаем тело расширения
			extension.data.assign(data.data + offset, data.data + offset + length);
			// Переходим за тело расширения
			offset += length;
			// Отказ разбора тела расширения
			const fingerprint::error_t failure = decode(extension);
			// Если тело расширения разобрать не удалось
			if(failure != fingerprint::error_t::NONE)
				// Выводим отказ разбора расширения
				return failure;
			// Добавляем расширение в профиль
			result.extensions.push_back(extension);
		}
		// Выводим успешность чтения
		return fingerprint::error_t::NONE;
	}
};

/**
 * @brief Конструктор
 *
 */
nts::fingerprint::Share::Share() noexcept :
 group(extension::group_t::NONE) {}

/**
 * @brief Конструктор
 *
 */
nts::fingerprint::Identity::Identity() noexcept : age(0) {}

/**
 * @brief Конструктор
 *
 */
nts::fingerprint::Extension::Extension() noexcept :
 grease(false), type(0), value(0) {}

/**
 * @brief Конструктор
 *
 */
nts::fingerprint::Profile::Profile() noexcept :
 grease(false), datagram(false), epoch(0), length(0),
 record(0), version(0), message(0), sequence(0), random{0} {
	// Обнуление случайного значения приветствия
	::memset(this->random, 0, FINGERPRINT_RANDOM);
}

/**
 * @brief Конструктор
 *
 */
nts::fingerprint::Imprint::Imprint() noexcept : record(0), negotiated(0) {}

/**
 * @brief Конструктор
 *
 */
nts::fingerprint::Setting::Setting() noexcept : id(0), value(0) {}

/**
 * @brief Конструктор
 *
 */
nts::fingerprint::Priority::Priority() noexcept :
 exclusive(false), weight(0),
 stream(0), dependency(0) {}

/**
 * @brief Конструктор
 *
 */
nts::fingerprint::Stream::Stream() noexcept :
 pseudo{""}, window(0) {}

/**
 * @brief Конструктор
 *
 */
nts::fingerprint::Store::Entry::Entry() noexcept : id(0) {}

/**
 * @brief Функция проверки того, что значение есть значение GREASE
 *
 * @param value проверяемое значение по проводу
 * @return      признак значения GREASE
 *
 */
bool nts::fingerprint::grease(const uint16_t value) noexcept {
	// Раздел 2 RFC 8701: оба байта равны и младшая половина каждого есть 0xA
	return (((value & 0x0F0F) == 0x0A0A) && ((value >> 8) == (value & 0xFF)));
}
/**
 * @brief Функция разбора записи с приветствием клиента в профиль
 *
 * @param data   разбираемая запись: заголовок слоя записей TLS либо DTLS, обвязка сообщения рукопожатия и тело приветствия
 * @param result профиль, в который помещается итог разбора
 * @return       отказ разбора приветствия
 *
 */
nts::fingerprint::error_t nts::fingerprint::parse(const view_t & data, profile_t & result) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Если байты начинаются записью с изданием поверх дейтаграмм: устройство определяется по ней
		const bool datagram = ((data.data != nullptr) && (data.size >= 3) && (data.data[0] == HANDSHAKE) && ((twain(data.data + 1) == EDITION_DTLS10) || (twain(data.data + 1) == EDITION_DTLS12) || (twain(data.data + 1) == EDITION_DTLS13)));
		// Выводим итог разбора
		return examine(data, datagram, result);
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Сбрасываем профиль
		result = profile_t();
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
}
/**
 * @brief Функция разбора сообщения рукопожатия с приветствием клиента в профиль
 *
 * @param data     разбираемое сообщение: обвязка в 4 байта по разделу 4 RFC 8446 и тело приветствия
 * @param result   профиль, в который помещается итог разбора
 * @param datagram признак приветствия поверх дейтаграмм: за опознавателем связи идёт метка возврата состояния
 * @return         отказ разбора приветствия
 *
 */
nts::fingerprint::error_t nts::fingerprint::parse(const view_t & data, profile_t & result, const bool datagram) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Выводим итог разбора
		return examine(data, datagram, result);
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Сбрасываем профиль
		result = profile_t();
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
}
/**
 * @brief Функция вычисления отпечатков профиля
 *
 * @param profile профиль приветствия клиента
 * @param result  отпечатки, в которые помещается итог вычисления
 * @return        отказ вычисления отпечатков: EMPTY у профиля без наборов и расширений
 *
 */
nts::fingerprint::error_t nts::fingerprint::imprint(const profile_t & profile, imprint_t & result) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Сбрасываем отпечатки
		result = imprint_t();
		// Если профиль пуст
		if(profile.suites.empty())
			// Выводим отказ пустого профиля
			return error_t::EMPTY;
		// Переносим издание слоя записей
		result.record = profile.record;
		// Подсчитываем согласуемое издание
		result.negotiated = eldest(profile);
		// Составляем запись случайного значения
		hexed(profile.random, FINGERPRINT_RANDOM, result.random);
		// Составляем запись опознавателя связи
		hexed(profile.session.data(), profile.session.size(), result.session);
		// Расширение групп эллиптических кривых
		const extension_t * groups = seek(profile, static_cast <uint16_t> (extension::type_t::GROUPS));
		// Расширение форматов точек
		const extension_t * formats = seek(profile, static_cast <uint16_t> (extension::type_t::FORMATS));
		// Расширение схем подписи
		const extension_t * schemes = seek(profile, static_cast <uint16_t> (extension::type_t::SCHEMES));
		// Расширение прикладных протоколов
		const extension_t * protocols = seek(profile, static_cast <uint16_t> (extension::type_t::PROTOCOLS));
		// Расширение имени сервера
		const extension_t * name = seek(profile, static_cast <uint16_t> (extension::type_t::NAME));
		// Расширение поддерживаемых изданий
		const extension_t * versions = seek(profile, static_cast <uint16_t> (extension::type_t::VERSIONS));
		// Расширение режимов рукопожатия
		const extension_t * modes = seek(profile, static_cast <uint16_t> (extension::type_t::MODES));
		// Перечни чисел по проводу без GREASE и с GREASE
		vector <uint16_t> suites, suitesAll, extensions, extensionsAll, curves, curvesAll, signatures, signaturesAll, points, editions;
		/**
		 * Выполняем перебор наборов шифрования
		 */
		for(size_t i = 0; i < profile.suites.size(); i++){
			// Набор по проводу
			const uint16_t suite = static_cast <uint16_t> (profile.suites[i]);
			// Добавляем набор в полный перечень
			suitesAll.push_back(suite);
			// Если набор не GREASE
			if(!grease(suite))
				// Добавляем набор в перечень без GREASE
				suites.push_back(suite);
		}
		/**
		 * Выполняем перебор расширений
		 */
		for(size_t i = 0; i < profile.extensions.size(); i++){
			// Добавляем вид расширения в полный перечень
			extensionsAll.push_back(profile.extensions[i].type);
			// Если расширение не GREASE
			if(!profile.extensions[i].grease)
				// Добавляем вид расширения в перечень без GREASE
				extensions.push_back(profile.extensions[i].type);
		}
		// Если расширение групп есть
		if(groups != nullptr){
			/**
			 * Выполняем перебор групп
			 */
			for(size_t i = 0; i < groups->groups.size(); i++){
				// Группа по проводу
				const uint16_t group = static_cast <uint16_t> (groups->groups[i]);
				// Добавляем группу в полный перечень
				curvesAll.push_back(group);
				// Если группа не GREASE
				if(!grease(group))
					// Добавляем группу в перечень без GREASE
					curves.push_back(group);
			}
		}
		// Если расширение схем есть
		if(schemes != nullptr){
			/**
			 * Выполняем перебор схем
			 */
			for(size_t i = 0; i < schemes->schemes.size(); i++){
				// Схема по проводу
				const uint16_t scheme = static_cast <uint16_t> (schemes->schemes[i]);
				// Добавляем схему в полный перечень
				signaturesAll.push_back(scheme);
				// Если схема не GREASE
				if(!grease(scheme))
					// Добавляем схему в перечень без GREASE
					signatures.push_back(scheme);
			}
		}
		// Если расширение записей точек есть
		if(formats != nullptr){
			/**
			 * Выполняем перебор записей точек
			 */
			for(size_t i = 0; i < formats->formats.size(); i++)
				// Добавляем запись точки в перечень
				points.push_back(formats->formats[i]);
		}
		// Если расширение изданий есть
		if(versions != nullptr)
			// Переносим издания
			editions = versions->versions;
		/**
		 * JA3: издание приветствия, наборы, расширения, группы и записи точек без GREASE, десятично
		 */
		{
			// Дописываем издание приветствия
			decimal(profile.version, result.ja3);
			// Дописываем разделитель
			result.ja3.push_back(',');
			// Дописываем наборы
			listing(suites, '-', false, result.ja3);
			// Дописываем разделитель
			result.ja3.push_back(',');
			// Дописываем расширения
			listing(extensions, '-', false, result.ja3);
			// Дописываем разделитель
			result.ja3.push_back(',');
			// Дописываем группы
			listing(curves, '-', false, result.ja3);
			// Дописываем разделитель
			result.ja3.push_back(',');
			// Дописываем записи точек
			listing(points, '-', false, result.ja3);
			// Если хеш JA3 выработать не удалось
			if(!digesting(digest::hash_t::MD5, result.ja3, 0, result.ja3hash))
				// Выводим отказ памяти
				return error_t::MEMORY;
		}
		/**
		 * JA4 по описанию FoxIO: заголовок, хеш SHA-256 сортированных наборов, хеш SHA-256
		 * сортированных расширений без SNI и ALPN вместе со схемами в порядке провода
		 */
		{
			// Признак переноса QUIC: расширение параметров переноса
			const bool quic = ((seek(profile, 0x0039) != nullptr) || (seek(profile, 0xFFA5) != nullptr));
			// Заголовок отпечатка
			string prefix;
			// Дописываем букву переноса
			prefix.push_back(quic ? 'q' : (profile.datagram ? 'd' : 't'));
			// Дописываем издание протокола
			prefix.append(lettered(result.negotiated));
			// Дописываем признак имени узла
			prefix.push_back(((name != nullptr) && !name->names.empty()) ? 'd' : 'i');
			// Дописываем число наборов
			counted(suites.size(), prefix);
			// Дописываем число расширений
			counted(extensions.size(), prefix);
			// Дописываем знаки прикладного протокола
			abbreviated(((protocols != nullptr) && !protocols->protocols.empty()) ? protocols->protocols.front() : string(), prefix);
			// Сортированные наборы
			vector <uint16_t> sortedSuites = suites;
			// Сортируем наборы по значению
			::sort(sortedSuites.begin(), sortedSuites.end());
			// Сортированные расширения без имени узла и прикладных протоколов
			vector <uint16_t> sortedExtensions;
			/**
			 * Выполняем перебор расширений без GREASE
			 */
			for(size_t i = 0; i < extensions.size(); i++){
				// Если расширение не есть имя узла и не прикладные протоколы
				if((extensions[i] != static_cast <uint16_t> (extension::type_t::NAME)) && (extensions[i] != static_cast <uint16_t> (extension::type_t::PROTOCOLS)))
					// Добавляем расширение в сортируемый перечень
					sortedExtensions.push_back(extensions[i]);
			}
			// Сортируем расширения по значению
			::sort(sortedExtensions.begin(), sortedExtensions.end());
			// Записи перечней
			string suitesText, extensionsText, signaturesText, originalSuites, originalExtensions;
			// Составляем запись сортированных наборов
			listing(sortedSuites, ',', true, suitesText);
			// Составляем запись сортированных расширений
			listing(sortedExtensions, ',', true, extensionsText);
			// Составляем запись схем подписи в порядке провода
			listing(signatures, ',', true, signaturesText);
			// Составляем запись наборов в порядке провода
			listing(suites, ',', true, originalSuites);
			// Составляем запись расширений в порядке провода
			listing(extensions, ',', true, originalExtensions);
			// Запись расширений со схемами
			string combined = extensionsText;
			// Если схемы подписи есть
			if(!signatures.empty()){
				// Дописываем разделитель
				combined.push_back('_');
				// Дописываем схемы подписи
				combined.append(signaturesText);
			}
			// Составляем раскрытый отпечаток
			result.ja4r = (prefix + '_' + suitesText + '_' + combined);
			// Составляем раскрытый отпечаток в порядке провода
			result.ja4o = (prefix + '_' + originalSuites + '_' + originalExtensions);
			// Если схемы подписи есть
			if(!signatures.empty()){
				// Дописываем разделитель
				result.ja4o.push_back('_');
				// Дописываем схемы подписи
				result.ja4o.append(signaturesText);
			}
			// Начинаем отпечаток заголовком
			result.ja4 = (prefix + '_');
			// Если наборов нет
			if(sortedSuites.empty())
				// Дописываем нулевой хеш
				result.ja4.append("000000000000");
			// Если хеш наборов выработать не удалось
			else if(!digesting(digest::hash_t::SHA256, suitesText, 6, result.ja4))
				// Выводим отказ памяти
				return error_t::MEMORY;
			// Дописываем разделитель
			result.ja4.push_back('_');
			// Если расширений нет
			if(sortedExtensions.empty())
				// Дописываем нулевой хеш
				result.ja4.append("000000000000");
			// Если хеш расширений выработать не удалось
			else if(!digesting(digest::hash_t::SHA256, combined, 6, result.ja4))
				// Выводим отказ памяти
				return error_t::MEMORY;
		}
		/**
		 * PeetPrint: издания | сжатие | группы | схемы | число записей точек | число способов PSK | наборы | расширения, GREASE словом
		 */
		{
			// Дописываем издания протокола
			marking(editions, result.peetprint);
			// Дописываем разделитель
			result.peetprint.push_back('|');
			// Дописываем число способов сжатия с единицей
			decimal(profile.methods.size() + 1, result.peetprint);
			// Дописываем разделитель
			result.peetprint.push_back('-');
			// Дописываем число способов сжатия
			decimal(profile.methods.size(), result.peetprint);
			/**
			 * Выполняем перебор способов сжатия
			 */
			for(size_t i = 0; i < profile.methods.size(); i++){
				// Дописываем разделитель
				result.peetprint.push_back('.');
				// Дописываем способ сжатия
				decimal(profile.methods[i], result.peetprint);
			}
			// Дописываем разделитель
			result.peetprint.push_back('|');
			// Дописываем группы
			marking(curvesAll, result.peetprint);
			// Дописываем разделитель
			result.peetprint.push_back('|');
			// Дописываем схемы подписи
			marking(signaturesAll, result.peetprint);
			// Дописываем разделитель
			result.peetprint.push_back('|');
			// Дописываем число записей точек
			decimal(points.size(), result.peetprint);
			// Дописываем разделитель
			result.peetprint.push_back('|');
			// Дописываем число способов обмена ключом
			decimal((modes != nullptr) ? modes->modes.size() : 0, result.peetprint);
			// Дописываем разделитель
			result.peetprint.push_back('|');
			// Дописываем наборы
			marking(suitesAll, result.peetprint);
			// Дописываем разделитель
			result.peetprint.push_back('|');
			// Дописываем расширения
			marking(extensionsAll, result.peetprint);
			// Если хеш PeetPrint выработать не удалось
			if(!digesting(digest::hash_t::MD5, result.peetprint, 0, result.peethash))
				// Выводим отказ памяти
				return error_t::MEMORY;
		}
		// Выводим успешность вычисления
		return error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Сбрасываем отпечатки
		result = imprint_t();
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
}
/**
 * @brief Функция проверки того, что отпечатки похожи на отпечатки браузера
 *
 * @param imprint проверяемые отпечатки
 * @return        признак похожести на браузер: издание TLS 1.3, имя узла и непустой JA3
 *
 */
bool nts::fingerprint::browser(const imprint_t & imprint) noexcept {
	// Обозреватель предлагает TLS 1.3, запрашивает узел именем и имеет отпечаток
	return ((imprint.negotiated == EDITION_TLS13) && (imprint.ja4.size() >= 4) && (imprint.ja4[3] == 'd') && !imprint.ja3hash.empty());
}
/**
 * @brief Функция печати профиля человеку
 *
 * @param profile печатаемый профиль
 * @param result  строка, в которую помещается печать
 * @return        отказ печати
 *
 * @details Форма печати перенесена из AWH: слой записей, заголовок рукопожатия,
 *          приветствие, наборы, способы сжатия, расширения с подробностями
 *          по виду и вычисленные отпечатки с выводом «похож на обозреватель».
 *
 */
nts::fingerprint::error_t nts::fingerprint::print(const profile_t & profile, string & result) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Сбрасываем строку
		result.clear();
		// Если профиль пуст
		if(profile.suites.empty())
			// Выводим отказ пустого профиля
			return error_t::EMPTY;
		// Строковый поток для сборки результата
		ostringstream out;
		// Горизонтальная линия-разделитель (80 знаков)
		const string LINE(80, '=');
		/**
		 * @brief Лямбда секционного заголовка
		 *
		 * @param title название секции
		 *
		 */
		const auto section = [&out](const string & title) -> void {
			// Печатаем заголовок секции с отступами
			out << endl << "  [ " << title << " ]" << endl;
		};
		// Заголовок отпечатка
		out << endl << LINE << endl;
		// Печатаем название отпечатка
		out << "                  TLS ClientHello  -  Browser Fingerprint" << endl;
		// Печатаем нижнюю линию заголовка
		out << LINE << endl;
		/**
		 * Формируем секцию Record Layer
		 */
		section("Record Layer");
		{
			// Издание слоя записей: ноль, когда разбиралось голое сообщение рукопожатия
			const uint16_t wire = profile.record;
			// Возвращаем версию и её код
			out << "    Version  : " << ::__ants_tls_version_name__(wire) << "  (" << ::__ants_hex16__(wire) << ")" << endl;
			// Длина записи: длина тела приветствия плюс обвязка сообщения (12 байтов у дейтаграмм, 4 у потока)
			out << "    Length   : " << (profile.length + (profile.datagram ? 12 : 4)) << endl;
			// Поля дейтаграмм выводим всегда при дейтаграммном устройстве, иначе лишь когда они ненулевые
			if(profile.datagram || (profile.epoch != 0) || (profile.sequence != 0)){
				// Возвращаем поле эпохи
				out << "    Epoch    : " << profile.epoch << "  [DTLS]" << endl;
				// Возвращаем поле последовательности
				out << "    Sequence : " << profile.sequence << "  [DTLS]" << endl;
			}
		}
		/**
		 * Формируем секцию Handshake Header
		 */
		section("Handshake Header");
		// Длина приветствия как записана в заголовке сообщения
		out << "    Length       : " << profile.length << endl;
		// Порядковый номер сообщения: отличен от нуля лишь у дейтаграмм
		out << "    Sequence     : " << profile.message << endl;
		// Отпечаток снимается лишь с цельного сообщения: смещение фрагмента всегда ноль
		out << "    Frag. Offset : " << 0 << endl;
		// Длина фрагмента равна длине сообщения
		out << "    Frag. Length : " << profile.length << endl;
		/**
		 * Формируем секцию ClientHello
		 */
		section("ClientHello");
		{
			// Возвращаем издание приветствия и его код
			out << "    Legacy Version : " << ::__ants_tls_version_name__(profile.version) << "  (" << ::__ants_hex16__(profile.version) << ")" << endl;
			// Запись случайного значения
			string random;
			// Составляем запись случайного значения
			hexed(profile.random, FINGERPRINT_RANDOM, random);
			// Возвращаем случайное значение
			out << "    Random         : " << random << endl;
			// Если опознаватель связи есть
			if(!profile.session.empty()){
				// Запись опознавателя связи
				string session;
				// Составляем запись опознавателя связи
				hexed(profile.session.data(), profile.session.size(), session);
				// Возвращаем опознаватель связи
				out << "    Session ID     : " << session << endl;
			// Если опознавателя связи нет, выводим пометку
			} else out << "    Session ID     : (empty)" << endl;
			// Метка возврата состояния выводится лишь когда присутствует
			if(!profile.cookie.empty()){
				// Запись метки возврата
				string cookie;
				// Составляем запись метки возврата
				hexed(profile.cookie.data(), profile.cookie.size(), cookie);
				// Возвращаем метку возврата
				out << "    DTLS Cookie    : " << cookie << endl;
			}
			// Возвращаем наличие GREASE в приветствии
			out << "    GREASE Used    : " << (profile.grease ? "yes" : "no") << endl;
		}
		/**
		 * Формируем секцию Cipher Suites с количеством наборов
		 */
		{
			// Место заголовка секции
			char title[64];
			// Составляем заголовок секции с количеством наборов
			::snprintf(title, sizeof(title), "Cipher Suites (%zu)", profile.suites.size());
			// Печатаем заголовок секции
			section(title);
		}
		/**
		 * Перебираем наборы шифрования и выводим их имена с выравниванием и коды
		 */
		for(size_t i = 0; i < profile.suites.size(); i++){
			// Набор по проводу
			const uint16_t wire = static_cast <uint16_t> (profile.suites[i]);
			// Имя набора: GREASE или реальное название
			const char * name = ::__ants_cipher_name__(wire);
			// Место записи индекса набора
			char index[24];
			// Составляем запись индекса набора
			::snprintf(index, sizeof(index), "[%2zu]", i);
			// Печатаем индекс и имя набора
			out << "    " << index << "  " << name;
			// Вычисляем количество пробелов для выравнивания имён по столбцу 36
			const int32_t pad = (36 - static_cast <int32_t> (::strlen(name)));
			/**
			 * Печатаем пробелы для выравнивания
			 */
			for(int32_t j = 0; j < pad; ++j)
				// Печатаем пробел для выравнивания
				out << ' ';
			// Печатаем код набора
			out << "(" << ::__ants_hex16__(wire) << ")" << endl;
		}
		/**
		 * Формируем секцию Compression Methods с количеством способов
		 */
		{
			// Место заголовка секции
			char title[64];
			// Составляем заголовок секции с количеством способов сжатия
			::snprintf(title, sizeof(title), "Compression Methods (%zu)", profile.methods.size());
			// Печатаем заголовок секции
			section(title);
		}
		/**
		 * Перебираем способы сжатия и выводим их имена и коды
		 */
		for(size_t i = 0; i < profile.methods.size(); i++){
			// Способ сжатия по проводу
			const uint8_t wire = profile.methods[i];
			// Место записи индекса способа сжатия
			char index[24];
			// Составляем запись индекса способа сжатия
			::snprintf(index, sizeof(index), "[%2zu]", i);
			// Печатаем индекс, имя способа сжатия и его код
			out << "    " << index << "  " << ::__ants_compress_alg_name__(wire) << "  (" << ::__ants_hex8__(wire) << ")" << endl;
		}
		/**
		 * Формируем секцию Extensions с количеством расширений
		 */
		{
			// Место заголовка секции
			char title[64];
			// Составляем заголовок секции с количеством расширений
			::snprintf(title, sizeof(title), "Extensions (%zu)", profile.extensions.size());
			// Печатаем заголовок секции
			section(title);
		}
		/**
		 * Перебираем расширения и выводим их имена с выравниванием, коды и подробности
		 */
		for(size_t i = 0; i < profile.extensions.size(); i++){
			// Расширение профиля
			const extension_t & extension = profile.extensions[i];
			// Место записи индекса расширения
			char index[24];
			// Составляем запись индекса расширения
			::snprintf(index, sizeof(index), "[%2zu]", i);
			// GREASE расширение: выводим пометку и переходим к следующему
			if(extension.grease){
				// Печатаем индекс расширения и пометку
				out << "    " << index << "  [GREASE]" << endl;
				// Переходим к следующему расширению
				continue;
			}
			// Имя расширения
			const char * ename = ::__ants_extension_name__(extension.type);
			// Печатаем индекс и имя расширения
			out << "    " << index << "  " << ename;
			// Вычисляем количество пробелов для выравнивания имён по столбцу 46
			const int32_t pad = (46 - static_cast <int32_t> (::strlen(ename)));
			/**
			 * Печатаем пробелы для выравнивания
			 */
			for(int32_t j = 0; j < pad; ++j)
				// Печатаем пробел для выравнивания
				out << ' ';
			// Печатаем код расширения
			out << "(" << ::__ants_hex16__(extension.type) << ")";
			/**
			 * Подробности расширения в зависимости от его вида
			 */
			switch(extension.type){
				// Имя узла: выводим имена запрашиваемых узлов
				case static_cast <uint16_t> (extension::type_t::NAME): {
					// Если список имён не пустой, выводим его
					if(!extension.names.empty()){
						// Возвращаем первое имя с маркером
						out << "  ->  \"" << extension.names[0] << '"';
						/**
						 * Перебираем оставшиеся имена
						 */
						for(size_t j = 1; j < extension.names.size(); j++)
							// Возвращаем последующие имена, разделяя запятой
							out << ", \"" << extension.names[j] << '"';
					}
				} break;
				// Поддерживаемые издания: выводим список с GREASE-маркерами
				case static_cast <uint16_t> (extension::type_t::VERSIONS): {
					// Печатаем маркер перед списком изданий
					out << "  ->  ";
					/**
					 * Перебираем издания и выводим их, разделяя запятой
					 */
					for(size_t j = 0; j < extension.versions.size(); j++){
						// Если это не первое издание
						if(j > 0)
							// Печатаем запятую для разделения изданий
							out << ", ";
						// Если издание есть значение GREASE
						if(grease(extension.versions[j]))
							// Печатаем маркер GREASE-издания
							out << "[GREASE]";
						// Печатаем имя издания по его коду
						else out << ::__ants_tls_version_name__(extension.versions[j]);
					}
				} break;
				// Поддерживаемые группы: выводим список с GREASE-маркерами
				case static_cast <uint16_t> (extension::type_t::GROUPS): {
					// Печатаем маркер перед списком групп
					out << "  ->  ";
					/**
					 * Перебираем группы и выводим их, разделяя запятой
					 */
					for(size_t j = 0; j < extension.groups.size(); j++){
						// Группа по проводу
						const uint16_t wire = static_cast <uint16_t> (extension.groups[j]);
						// Если это не первая группа
						if(j > 0)
							// Печатаем запятую для разделения групп
							out << ", ";
						// Если группа есть значение GREASE
						if(grease(wire))
							// Печатаем маркер GREASE-группы
							out << "[GREASE]";
						// Печатаем имя группы по её коду
						else out << ::__ants_group_name__(wire);
					}
				} break;
				// Записи точек: выводим форматы точек кривой
				case static_cast <uint16_t> (extension::type_t::FORMATS): {
					// Печатаем маркер перед списком форматов точек
					out << "  ->  ";
					/**
					 * Перебираем форматы точек и выводим их, разделяя запятой
					 */
					for(size_t j = 0; j < extension.formats.size(); j++){
						// Формат точки по проводу
						const uint8_t wire = extension.formats[j];
						// Если это не первый формат точки
						if(j > 0)
							// Печатаем запятую для разделения форматов точек
							out << ", ";
						// Формат uncompressed
						if(wire == 0x00)
							// Печатаем имя формата точки
							out << "uncompressed";
						// Формат ansiX962_compressed_prime
						else if(wire == 0x01)
							// Печатаем имя формата точки
							out << "ansiX962_compressed_prime";
						// Формат ansiX962_compressed_char2
						else if(wire == 0x02)
							// Печатаем имя формата точки
							out << "ansiX962_compressed_char2";
						// Для остальных форматов выводим их коды
						else out << ::__ants_hex8__(wire);
					}
				} break;
				// Схемы подписи: каждая на отдельной строке
				case static_cast <uint16_t> (extension::type_t::SCHEMES):
				// Схемы подписи сертификата
				case WIRE_CERTIFIED:
				// Схемы подписи делегированных полномочий
				case WIRE_DELEGATED: {
					// Печатаем перевод строки
					out << endl;
					/**
					 * Перебираем схемы и выводим их на отдельных строках с отступами
					 */
					for(size_t j = 0; j < extension.schemes.size(); j++){
						// Схема по проводу
						const uint16_t wire = static_cast <uint16_t> (extension.schemes[j]);
						// Печатаем отступы для схем
						out << "              ";
						// Если схема есть значение GREASE
						if(grease(wire))
							// Печатаем маркер GREASE-схемы
							out << "[GREASE]";
						// Печатаем имя схемы и её код
						else out << ::__ants_signature_name__(wire) << "  (" << ::__ants_hex16__(wire) << ")";
						// Печатаем перевод строки после каждой схемы
						out << endl;
					}
					// Переходим к следующему расширению без добавления финального переноса строки
					continue;
				}
				// Прикладные протоколы, настройки ALPS и выработка следующего протокола: выводим список протоколов
				case static_cast <uint16_t> (extension::type_t::PROTOCOLS):
				// Настройки ALPS новой точкой кода
				case static_cast <uint16_t> (extension::type_t::SETTINGS):
				// Настройки ALPS прежней точкой кода
				case static_cast <uint16_t> (extension::type_t::SETTINGS_OLD):
				// Выработка следующего протокола
				case static_cast <uint16_t> (extension::type_t::NEGOTIATION): {
					// Печатаем маркер перед списком протоколов
					out << "  ->  ";
					/**
					 * Перебираем протоколы и выводим их, разделяя запятой
					 */
					for(size_t j = 0; j < extension.protocols.size(); j++){
						// Если это не первый протокол
						if(j > 0)
							// Печатаем запятую для разделения протоколов
							out << ", ";
						// Печатаем имя протокола в кавычках
						out << '"' << extension.protocols[j] << '"';
					}
				} break;
				// Открытые части ключей: выводим пары группа и размер ключа
				case static_cast <uint16_t> (extension::type_t::SHARE): {
					// Печатаем маркер перед списком групп и размеров ключей
					out << "  ->  ";
					/**
					 * Перебираем доли ключей и выводим их, разделяя запятой
					 */
					for(size_t j = 0; j < extension.shares.size(); j++){
						// Группа доли по проводу
						const uint16_t wire = static_cast <uint16_t> (extension.shares[j].group);
						// Если это не первая доля
						if(j > 0)
							// Печатаем запятую для разделения долей
							out << ", ";
						// Если группа есть значение GREASE
						if(grease(wire))
							// Печатаем маркер GREASE-группы и размер ключа
							out << "[GREASE](" << extension.shares[j].key.size() << "B)";
						// Печатаем имя группы и размер ключа
						else out << ::__ants_group_name__(wire) << "(" << extension.shares[j].key.size() << "B)";
					}
				} break;
				// Способы обмена заранее разделённым ключом
				case static_cast <uint16_t> (extension::type_t::MODES): {
					// Печатаем маркер перед списком способов
					out << "  ->  ";
					/**
					 * Перебираем способы обмена и выводим их, разделяя запятой
					 */
					for(size_t j = 0; j < extension.modes.size(); j++){
						// Если это не первый способ
						if(j > 0)
							// Печатаем запятую для разделения способов
							out << ", ";
						/**
						 * Печатаем имя способа обмена
						 */
						switch(static_cast <uint8_t> (extension.modes[j])){
							// Способ psk_ke (0x00)
							case 0x00:
								// Печатаем имя способа psk_ke
								out << "psk_ke(0x00)";
							break;
							// Способ psk_dhe_ke (0x01)
							case 0x01:
								// Печатаем имя способа psk_dhe_ke
								out << "psk_dhe_ke(0x01)";
							break;
							// Прочие способы
							default:
								// Печатаем неизвестный способ
								out << "UNKNOWN";
						}
					}
				} break;
				// Заранее разделённые ключи: выводим количество опознавателей
				case static_cast <uint16_t> (extension::type_t::SECRET):
					// Печатаем маркер перед количеством опознавателей и правильное склонение слова
					out << "  ->  " << extension.identities.size()
					    // Дописываем правильное склонение слова
					    << (extension.identities.size() == 1 ? " identity" : " identities");
				break;
				// Билет сеанса: выводим размер данных или пометку о запросе
				case static_cast <uint16_t> (extension::type_t::TICKET):
					// Если данные билета отсутствуют
					if(extension.data.empty())
						// Возвращаем пометку о том, что данные отсутствуют и это может быть запросом нового билета
						out << "  ->  (empty / request for new ticket)";
					// Если данные билета присутствуют, выводим их размер
					else out << "  ->  " << extension.data.size() << " bytes";
				break;
				// Запрос состояния сертификата: выводим вид состояния
				case static_cast <uint16_t> (extension::type_t::STATUS):
					// Если вид состояния задан, выводим его
					if(extension.value != 0)
						// Возвращаем вид состояния
						out << "  ->  type=" << extension.value;
				break;
				// Заполнение: выводим размер блока заполнения
				case WIRE_PADDING:
					// Печатаем маркер перед размером заполнения
					out << "  ->  " << extension.value << " bytes";
				break;
				// Предел размера записи: выводим предел
				case WIRE_LIMIT:
					// Печатаем маркер перед пределом записи
					out << "  ->  " << extension.value << " bytes";
				break;
				// Упреждающие данные: выводим предел упреждения
				case static_cast <uint16_t> (extension::type_t::EARLY):
					// Если предел упреждения задан
					if(extension.value > 0)
						// Печатаем маркер перед пределом упреждения
						out << "  ->  max=" << extension.value << " bytes";
				break;
				// Алгоритмы сжатия цепочки: выводим поддерживаемые алгоритмы
				case static_cast <uint16_t> (extension::type_t::COMPRESS): {
					// Печатаем маркер перед списком алгоритмов
					out << "  ->  ";
					/**
					 * Перебираем алгоритмы и выводим их, разделяя запятой
					 */
					for(size_t j = 0; j < extension.algorithms.size(); j++){
						// Если это не первый алгоритм
						if(j > 0)
							// Печатаем запятую для разделения алгоритмов
							out << ", ";
						// Печатаем имя алгоритма по его коду
						out << ::__ants_compress_alg_name__(static_cast <uint8_t> (static_cast <uint16_t> (extension.algorithms[j])));
					}
				} break;
				// Сердцебиение: выводим режим
				case WIRE_HEARTBEAT:
					/**
					 * Печатаем маркер перед режимом сердцебиения
					 */
					switch(extension.value){
						// Режим peer_allowed_to_send
						case 0x01:
							// Печатаем имя режима сердцебиения
							out << "  ->  peer_allowed_to_send";
						break;
						// Режим peer_not_allowed_to_send
						case 0x02:
							// Печатаем имя режима сердцебиения
							out << "  ->  peer_not_allowed_to_send";
						break;
					}
				break;
				// Признак безопасного пересогласования: выводим размер данных
				case static_cast <uint16_t> (extension::type_t::RENEGOTIATION):
					// Печатаем маркер перед размером данных пересогласования
					out << "  ->  " << extension.data.size() << " bytes";
				break;
				// Зашифрованное приветствие клиента: выводим размер зашифрованных данных
				case 0xFE0D:
					// Печатаем маркер перед размером зашифрованных данных
					out << "  ->  " << extension.data.size() << " bytes";
				break;
				// Виды расширений, вынесенных наружу ECH: выводим их количество
				case WIRE_OUTER:
					// Печатаем маркер перед количеством вложенных расширений
					out << "  ->  " << extension.values.size() << " extension(s)";
				break;
				// Доверенные центры: выводим их количество
				case static_cast <uint16_t> (extension::type_t::AUTHORITIES):
					// Печатаем маркер перед количеством доверенных центров
					out << "  ->  " << __ants_ca_count__(extension.data) << " CA(s)";
				break;
				// Предел длины куска: выводим код длины
				case WIRE_FRAGMENT:
					// Печатаем маркер перед кодом длины куска
					out << "  ->  " << extension.value;
				break;
			}
			// Печатаем перевод строки после каждого расширения
			out << endl;
		}
		/**
		 * Вычисленные отпечатки
		 */
		// Отпечатки профиля
		imprint_t imp;
		// Вычисляем отпечатки из профиля
		const bool hasImp = (imprint(profile, imp) == error_t::NONE);
		// Печатаем перевод строки перед секцией отпечатков
		out << endl;
		// Если вычисление отпечатков не удалось, выводим сообщение об ошибке
		if(!hasImp)
			// Вычисление отпечатков не удалось - сообщаем об ошибке
			out << "  [ Computed Fingerprints  (ERROR - computation failed) ]" << endl;
		// Если вычисление отпечатков прошло успешно, выводим их
		else {
			// Печатаем заголовок секции отпечатков
			out << "  [ Computed Fingerprints ]" << endl;
			// Десятичные записи изданий
			string recV, negV;
			// Составляем десятичную запись издания записи
			decimal(imp.record, recV);
			// Составляем десятичную запись согласуемого издания
			decimal(imp.negotiated, negV);
			// Издания протокола
			out << "    TLS Record Version     : " << recV << "  (" << ::__ants_hex16__(imp.record) << ")  =  " << ::__ants_tls_version_name__(imp.record) << endl;
			// Печатаем согласуемое издание протокола
			out << "    TLS Negotiated Version : " << negV << "  (" << ::__ants_hex16__(imp.negotiated) << ")  =  " << ::__ants_tls_version_name__(imp.negotiated) << endl;
			// Опознаватели соединения
			out << "    Client Random          : " << imp.random << endl;
			// Печатаем опознаватель связи
			out << "    Session ID             : " << (imp.session.empty() ? "(empty)" : imp.session) << endl;
			// JA3
			out << endl;
			// Печатаем строку JA3
			out << "    JA3        : " << imp.ja3 << endl;
			// Печатаем хеш JA3
			out << "    JA3 Hash   : " << imp.ja3hash << endl;
			// JA4
			out << endl;
			// Печатаем отпечаток JA4
			out << "    JA4        : " << imp.ja4 << endl;
			// Печатаем раскрытый отпечаток JA4_r
			out << "    JA4_r      : " << imp.ja4r << endl;
			// Раздел PeetPrint
			out << endl;
			// Печатаем строку PeetPrint
			out << "    PeetPrint  : " << imp.peetprint << endl;
			// Печатаем хеш PeetPrint
			out << "    PeetHash   : " << imp.peethash << endl;
			// Печатаем перевод строки после секции отпечатков
			out << endl;
			// Итоговый вывод: похож ли отпечаток на обозреватель
			out << "    Browser?   : " << (browser(imp) ? "YES (looks like a real browser)" : "NO  (does not look like a real browser)") << endl;
		}
		// Финальная строка-разделитель
		out << endl << LINE << endl;
		// Переносим собранную строку в результат
		result = out.str();
		// Выводим успешность печати
		return error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Сбрасываем строку
		result.clear();
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
}
/**
 * @brief Функция разбора начала связи протокола HTTP/2
 *
 * @param data   разбираемые байты: преамбула клиента и первые кадры
 * @param result начало связи, в которое помещается итог разбора
 * @return       отказ разбора: EMPTY без кадра SETTINGS
 *
 */
nts::fingerprint::error_t nts::fingerprint::parse(const view_t & data, stream_t & result) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Сбрасываем признаки потока
		result = stream_t();
		// Если предисловие не помещается
		if((data.data == nullptr) || (data.size < (sizeof(PREFACE) + 9)))
			// Выводим отказ обрыва
			return error_t::HUNGRY;
		// Если предисловие чужое
		if(::memcmp(data.data, PREFACE, sizeof(PREFACE)) != 0)
			// Выводим отказ записи
			return error_t::RECORD;
		// Смещение внутри потока
		size_t offset = sizeof(PREFACE);
		// Признаки встреченных кадров
		bool settled = false, headed = false;
		/**
		 * Выполняем перебор кадров потока
		 */
		while(((offset + 9) <= data.size) && !headed){
			// Длина тела кадра
			const size_t length = triad(data.data + offset);
			// Вид кадра
			const uint8_t type = data.data[offset + 3];
			// Признаки кадра
			const uint8_t flags = data.data[offset + 4];
			// Опознаватель потока кадра
			const uint32_t stream = (tetrad(data.data + offset + 5) & 0x7FFFFFFF);
			// Переходим к телу кадра
			offset += 9;
			// Если тело кадра в поток не входит
			if((offset + length) > data.size)
				// Выходим из перебора
				break;
			// Тело кадра
			const uint8_t * body = (data.data + offset);
			/**
			 * Определяем вид кадра
			 */
			switch(type){
				// Кадр настроек
				case FRAME_SETTINGS: {
					// Если кадр несёт настройки связи, а не подтверждение
					if((stream == 0) && ((flags & 0x01) == 0)){
						/**
						 * Выполняем перебор настроек
						 */
						for(size_t i = 0; (i + 6) <= length; i += 6){
							// Настройка согласования
							setting_t setting;
							// Читаем опознаватель настройки
							setting.id = twain(body + i);
							// Читаем значение настройки
							setting.value = tetrad(body + i + 2);
							// Добавляем настройку в перечень
							result.settings.push_back(setting);
						}
						// Отмечаем, что настройки встречены
						settled = true;
					}
				} break;
				// Кадр прибавки окна
				case FRAME_WINDOW: {
					// Если кадр относится к связи
					if((stream == 0) && (length >= 4))
						// Читаем прибавку окна
						result.window = (tetrad(body) & 0x7FFFFFFF);
				} break;
				// Кадр приоритета
				case FRAME_PRIORITY: {
					// Если тело кадра цело
					if(length >= 5){
						// Приоритет настройки
						priority_t priority;
						// Запоминаем поток
						priority.stream = stream;
						// Читаем признак исключительности
						priority.exclusive = ((body[0] & 0x80) != 0);
						// Читаем зависимость
						priority.dependency = (tetrad(body) & 0x7FFFFFFF);
						// Читаем вес
						priority.weight = body[4];
						// Добавляем приоритет в перечень
						result.priorities.push_back(priority);
					}
				} break;
				// Кадр заголовков
				case FRAME_HEADERS: {
					// Смещение блока заголовков внутри тела
					size_t start = 0;
					// Длина заполнения
					size_t padding = 0;
					// Если кадр несёт заполнение
					if(((flags & 0x08) != 0) && (length >= 1))
						// Читаем длину заполнения
						padding = body[start++];
					// Если кадр несёт приоритет
					if(((flags & 0x20) != 0) && ((start + 5) <= length))
						// Пропускаем приоритет
						start += 5;
					// Конец блока заголовков
					const size_t stop = ((length > padding) ? (length - padding) : length);
					// Если блок заголовков есть
					if(start < stop)
						// Разбираем порядок псевдозаголовков
						ordering(body + start, stop - start, result.pseudo);
					// Отмечаем, что заголовки встречены
					headed = true;
				} break;
				// Прочие кадры пропускаются
				default: break;
			}
			// Переходим за тело кадра
			offset += length;
		}
		// Выводим итог: без кадра настроек отпечатка нет
		return (settled ? error_t::NONE : error_t::EMPTY);
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Сбрасываем признаки потока
		result = stream_t();
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
}
/**
 * @brief Функция вычисления отпечатка Akamai HTTP/2
 *
 * @param stream начало связи протокола HTTP/2
 * @param result строка, в которую помещается отпечаток
 * @return       отказ вычисления: EMPTY без настроек
 *
 */
nts::fingerprint::error_t nts::fingerprint::akamai(const stream_t & stream, string & result) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Сбрасываем строку
		result.clear();
		// Если настроек нет
		if(stream.settings.empty())
			// Выводим отказ пустого профиля
			return error_t::EMPTY;
		/**
		 * Выполняем перебор настроек
		 */
		for(size_t i = 0; i < stream.settings.size(); i++){
			// Если настройка не первая
			if(i > 0)
				// Дописываем разделитель
				result.push_back(';');
			// Дописываем опознаватель настройки
			decimal(stream.settings[i].id, result);
			// Дописываем разделитель
			result.push_back(':');
			// Дописываем значение настройки
			decimal(stream.settings[i].value, result);
		}
		// Дописываем разделитель
		result.push_back('|');
		// Дописываем прибавку окна
		decimal(stream.window, result);
		// Дописываем разделитель
		result.push_back('|');
		/**
		 * Выполняем перебор приоритетов
		 */
		for(size_t i = 0; i < stream.priorities.size(); i++){
			// Если приоритет не первый
			if(i > 0)
				// Дописываем разделитель
				result.push_back(',');
			// Дописываем поток
			decimal(stream.priorities[i].stream, result);
			// Дописываем разделитель
			result.push_back(':');
			// Дописываем признак исключительности
			decimal(stream.priorities[i].exclusive ? 1 : 0, result);
			// Дописываем разделитель
			result.push_back(':');
			// Дописываем зависимость
			decimal(stream.priorities[i].dependency, result);
			// Дописываем разделитель
			result.push_back(':');
			// Дописываем настоящий вес
			decimal(static_cast <uint32_t> (stream.priorities[i].weight) + 1, result);
		}
		// Дописываем разделитель
		result.push_back('|');
		/**
		 * Выполняем перебор букв псевдозаголовков
		 */
		for(size_t i = 0; i < stream.pseudo.size(); i++){
			// Если буква не первая
			if(i > 0)
				// Дописываем разделитель
				result.push_back(',');
			// Дописываем букву
			result.push_back(stream.pseudo[i]);
		}
		// Выводим успешность вычисления
		return error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Сбрасываем строку
		result.clear();
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
}
/**
 * @brief Функция снятия переносимого снимка профиля
 *
 * @param profile снимаемый профиль
 * @param result  накопитель, в конец которого дописывается снимок
 * @return        отказ снятия снимка
 *
 */
nts::fingerprint::error_t nts::fingerprint::dump(const profile_t & profile, vector <uint8_t> & result) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Сбрасываем накопитель
		result.clear();
		// Если профиль пуст
		if(profile.suites.empty())
			// Выводим отказ пустого профиля
			return error_t::EMPTY;
		// Если перечни профиля в ширины снимка не входят
		if((profile.session.size() > FINGERPRINT_SESSION) || (profile.cookie.size() > 0xFF) || (profile.suites.size() > 0xFFFF) || (profile.methods.size() > 0xFF) || (profile.extensions.size() > 0xFFFF))
			// Выводим отказ снимка
			return error_t::FORMAT;
		/**
		 * Выполняем перебор расширений
		 */
		for(size_t i = 0; i < profile.extensions.size(); i++){
			// Если тело расширения в ширину снимка не входит
			if(profile.extensions[i].data.size() > 0xFFFF)
				// Выводим отказ снимка
				return error_t::FORMAT;
		}
		// Дописываем метку снимка
		result.insert(result.end(), STAMP, STAMP + sizeof(STAMP));
		// Дописываем издание снимка
		result.push_back(FINGERPRINT_EDITION);
		// Дописываем число профилей
		result.push_back(1);
		// Дописываем опознаватель профиля: у одиночного снимка ноль
		result.push_back(0);
		// Место длины профиля
		const size_t place = result.size();
		// Дописываем место под длину профиля
		inscribe(0, 4, result);
		// Дописываем профиль
		packing(profile, result);
		// Длина профиля
		const size_t length = (result.size() - place - 4);
		// Записываем длину профиля
		result[place] = static_cast <uint8_t> (length >> 24);
		// Записываем третий байт длины
		result[place + 1] = static_cast <uint8_t> (length >> 16);
		// Записываем второй байт длины
		result[place + 2] = static_cast <uint8_t> (length >> 8);
		// Записываем младший байт длины
		result[place + 3] = static_cast <uint8_t> (length);
		// Выводим успешность составления
		return error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Сбрасываем накопитель
		result.clear();
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
}
/**
 * @brief Функция подъёма профиля из переносимого снимка
 *
 * @param data   разбираемый снимок
 * @param result профиль, в который помещается итог подъёма
 * @return       отказ подъёма: VERSION у чужого издания, FORMAT у снимка не по правилам, TRAILING у лишних байтов
 *
 */
nts::fingerprint::error_t nts::fingerprint::load(const view_t & data, profile_t & result) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Сбрасываем профиль
		result = profile_t();
		// Если заголовок снимка не помещается
		if((data.data == nullptr) || (data.size < (sizeof(STAMP) + 3 + 4)))
			// Выводим отказ снимка
			return error_t::FORMAT;
		// Если метка снимка чужая
		if(::memcmp(data.data, STAMP, sizeof(STAMP)) != 0)
			// Выводим отказ снимка
			return error_t::FORMAT;
		// Если издание снимка неведомо
		if(data.data[sizeof(STAMP)] != FINGERPRINT_EDITION)
			// Выводим отказ издания
			return error_t::VERSION;
		// Если снимок несёт не один профиль
		if(data.data[sizeof(STAMP) + 1] != 1)
			// Выводим отказ снимка
			return error_t::FORMAT;
		// Смещение внутри снимка: за меткой, изданием, числом и опознавателем
		size_t offset = (sizeof(STAMP) + 3);
		// Длина профиля
		const size_t length = tetrad(data.data + offset);
		// Переходим к профилю
		offset += 4;
		// Если профиль в снимок не входит либо за ним идут лишние байты
		if((offset + length) != data.size)
			// Выводим отказ снимка
			return error_t::FORMAT;
		// Отказ чтения профиля
		const error_t failure = unpacking(data, offset, result);
		// Если профиль прочитать не удалось
		if(failure != error_t::NONE){
			// Сбрасываем профиль
			result = profile_t();
			// Выводим отказ чтения
			return failure;
		}
		// Если длина профиля не сошлась
		if(offset != data.size){
			// Сбрасываем профиль
			result = profile_t();
			// Выводим отказ снимка
			return error_t::FORMAT;
		}
		// Выводим успешность чтения
		return error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Сбрасываем профиль
		result = profile_t();
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
}
/**
 * @brief Метод добавления профиля в хранилище
 *
 * @param profile добавляемый профиль
 * @return        опознаватель профиля, ноль при полном хранилище либо нехватке памяти
 *
 */
nts::fingerprint::id_t nts::fingerprint::Store::add(const profile_t & profile) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Если профиль пуст либо хранилище полно
		if(profile.suites.empty() || (this->_entries.size() >= 0xFF))
			// Выводим отсутствие опознавателя
			return 0;
		// Запись хранилища
		entry_t entry;
		// Переносим профиль
		entry.profile = profile;
		/**
		 * Выполняем перебор возможных опознавателей
		 */
		for(id_t id = 1; id != 0; id++){
			// Если опознаватель свободен
			if(this->get(id) == nullptr){
				// Запоминаем опознаватель
				entry.id = id;
				// Выходим из перебора
				break;
			}
		}
		// Добавляем запись в хранилище
		this->_entries.push_back(entry);
		// Выводим опознаватель
		return entry.id;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отсутствие опознавателя
		return 0;
	}
}
/**
 * @brief Метод изъятия профиля из хранилища
 *
 * @param id опознаватель изымаемого профиля
 * @return   признак того, что профиль был и изъят
 *
 */
bool nts::fingerprint::Store::remove(const id_t id) noexcept {
	/**
	 * Выполняем перебор записей хранилища
	 */
	for(size_t i = 0; i < this->_entries.size(); i++){
		// Если опознаватель совпал
		if(this->_entries[i].id == id){
			// Удаляем найденную запись из хранилища
			this->_entries.erase(this->_entries.begin() + static_cast <ptrdiff_t> (i));
			// Выводим успешность удаления
			return true;
		}
	}
	// Выводим отсутствие профиля
	return false;
}
/**
 * @brief Метод розыска профиля по опознавателю
 *
 * @param id опознаватель разыскиваемого профиля
 * @return   найденный профиль либо nullptr
 *
 */
const nts::fingerprint::profile_t * nts::fingerprint::Store::get(const id_t id) const noexcept {
	/**
	 * Выполняем перебор записей хранилища
	 */
	for(size_t i = 0; i < this->_entries.size(); i++){
		// Если опознаватель совпал
		if(this->_entries[i].id == id)
			// Выводим профиль
			return &this->_entries[i].profile;
	}
	// Выводим отсутствие профиля
	return nullptr;
}
/**
 * @brief Метод получения перечня опознавателей хранилища
 *
 * @param result накопитель, в конец которого дописываются опознаватели в порядке добавления
 * @return       отказ получения перечня
 *
 */
nts::fingerprint::error_t nts::fingerprint::Store::list(vector <id_t> & result) const noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Сбрасываем перечень
		result.clear();
		/**
		 * Выполняем перебор записей хранилища
		 */
		for(size_t i = 0; i < this->_entries.size(); i++)
			// Добавляем опознаватель в перечень
			result.push_back(this->_entries[i].id);
		// Выводим успешность получения
		return error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Сбрасываем перечень
		result.clear();
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
}
/**
 * @brief Метод очистки хранилища
 *
 */
void nts::fingerprint::Store::clear() noexcept {
	// Удаляем все записи
	this->_entries.clear();
}
/**
 * @brief Метод проверки пустоты хранилища
 *
 * @return признак того, что профилей в хранилище нет
 *
 */
bool nts::fingerprint::Store::empty() const noexcept {
	// Выводим пустоту хранилища
	return this->_entries.empty();
}
/**
 * @brief Метод получения числа профилей хранилища
 *
 * @return число профилей хранилища
 *
 */
size_t nts::fingerprint::Store::size() const noexcept {
	// Выводим число записей
	return this->_entries.size();
}
/**
 * @brief Метод снятия переносимого снимка связки профилей
 *
 * @param result накопитель, в конец которого дописывается снимок связки
 * @return       отказ снятия снимка
 *
 */
nts::fingerprint::error_t nts::fingerprint::Store::dump(vector <uint8_t> & result) const noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Сбрасываем накопитель
		result.clear();
		// Если хранилище пусто
		if(this->_entries.empty())
			// Выводим отказ пустого профиля
			return error_t::EMPTY;
		// Дописываем метку снимка
		result.insert(result.end(), STAMP, STAMP + sizeof(STAMP));
		// Дописываем издание снимка
		result.push_back(FINGERPRINT_EDITION);
		// Дописываем число профилей
		result.push_back(static_cast <uint8_t> (this->_entries.size()));
		/**
		 * Выполняем перебор записей хранилища
		 */
		for(size_t i = 0; i < this->_entries.size(); i++){
			// Снимок одного профиля
			vector <uint8_t> single;
			// Отказ составления снимка профиля
			const error_t failure = fingerprint::dump(this->_entries[i].profile, single);
			// Если снимок профиля составить не удалось
			if(failure != error_t::NONE){
				// Сбрасываем накопитель
				result.clear();
				// Выводим отказ составления
				return failure;
			}
			// Дописываем опознаватель профиля
			result.push_back(this->_entries[i].id);
			// Дописываем длину и тело профиля из одиночного снимка: за меткой, изданием, числом и опознавателем
			result.insert(result.end(), single.begin() + static_cast <ptrdiff_t> (sizeof(STAMP) + 3), single.end());
		}
		// Выводим успешность составления
		return error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Сбрасываем накопитель
		result.clear();
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
}
/**
 * @brief Метод подъёма связки профилей из переносимого снимка
 *
 * @param data разбираемый снимок связки
 * @return     отказ подъёма
 *
 */
nts::fingerprint::error_t nts::fingerprint::Store::load(const view_t & data) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Если заголовок снимка не помещается
		if((data.data == nullptr) || (data.size < (sizeof(STAMP) + 2)))
			// Выводим отказ снимка
			return error_t::FORMAT;
		// Если метка снимка чужая
		if(::memcmp(data.data, STAMP, sizeof(STAMP)) != 0)
			// Выводим отказ снимка
			return error_t::FORMAT;
		// Если издание снимка неведомо
		if(data.data[sizeof(STAMP)] != FINGERPRINT_EDITION)
			// Выводим отказ издания
			return error_t::VERSION;
		// Число профилей
		const size_t count = data.data[sizeof(STAMP) + 1];
		// Смещение внутри снимка
		size_t offset = (sizeof(STAMP) + 2);
		// Читаемые записи
		vector <entry_t> entries;
		/**
		 * Выполняем перебор профилей снимка
		 */
		for(size_t i = 0; i < count; i++){
			// Если заголовок профиля в снимок не входит
			if((offset + 5) > data.size)
				// Выводим отказ снимка
				return error_t::FORMAT;
			// Запись хранилища
			entry_t entry;
			// Читаем опознаватель профиля
			entry.id = data.data[offset];
			// Длина профиля
			const size_t length = tetrad(data.data + offset + 1);
			// Переходим к профилю
			offset += 5;
			// Если профиль в снимок не входит либо опознаватель нулевой
			if(((offset + length) > data.size) || (entry.id == 0))
				// Выводим отказ снимка
				return error_t::FORMAT;
			// Конец профиля
			const size_t stop = (offset + length);
			// Отказ чтения профиля
			const error_t failure = unpacking(data, offset, entry.profile);
			// Если профиль прочитать не удалось
			if(failure != error_t::NONE)
				// Выводим отказ чтения
				return failure;
			// Если длина профиля не сошлась
			if(offset != stop)
				// Выводим отказ снимка
				return error_t::FORMAT;
			/**
			 * Выполняем перебор уже прочитанных записей
			 */
			for(size_t j = 0; j < entries.size(); j++){
				// Если опознаватель повторён
				if(entries[j].id == entry.id)
					// Выводим отказ снимка
					return error_t::FORMAT;
			}
			// Дописываем проверенную запись в набор прочитанных
			entries.push_back(entry);
		}
		// Если за профилями идут лишние байты
		if(offset != data.size)
			// Выводим отказ снимка
			return error_t::FORMAT;
		// Заменяем записи хранилища прочитанными
		this->_entries.swap(entries);
		// Выводим успешность чтения
		return error_t::NONE;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
}
/**
 * @brief Конструктор
 *
 */
nts::fingerprint::Store::Store() noexcept = default;
