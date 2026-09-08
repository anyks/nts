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
	static constexpr uint16_t EDITION_TLS13  = 0x0304;
	static constexpr uint16_t EDITION_DTLS10 = 0xFEFF;
	static constexpr uint16_t EDITION_DTLS12 = 0xFEFD;
	static constexpr uint16_t EDITION_DTLS13 = 0xFEFC;

	/**
	 * Размеры заголовков записи и сообщения рукопожатия
	 */
	static constexpr size_t RECORD_STREAM   = 5;
	static constexpr size_t RECORD_DATAGRAM = 13;
	static constexpr size_t HEADER_STREAM   = 4;
	static constexpr size_t HEADER_DATAGRAM = 12;

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
		'P', 'R', 'I', ' ', '*', ' ', 'H', 'T', 'T', 'P', '/', '2', '.', '0',
		'\r', '\n', '\r', '\n', 'S', 'M', '\r', '\n', '\r', '\n'
	};

	/**
	 * Виды кадров HTTP/2
	 */
	static constexpr uint8_t FRAME_HEADERS  = 0x01;
	static constexpr uint8_t FRAME_PRIORITY = 0x02;
	static constexpr uint8_t FRAME_SETTINGS = 0x04;
	static constexpr uint8_t FRAME_WINDOW   = 0x08;

	/**
	 * @brief Метод чтения числа в два байта старшим байтом вперёд
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
	 * @brief Метод чтения числа в три байта старшим байтом вперёд
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
	 * @brief Метод чтения числа в четыре байта старшим байтом вперёд
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
	 * @brief Метод чтения числа в восемь байтов старшим байтом вперёд
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
	 * @brief Метод дописывания числа старшим байтом вперёд в накопитель
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
	 * @brief Метод дописывания десятичной записи числа к строке
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
	 * @brief Метод дописывания шестнадцатеричной записи числа в четыре знака к строке
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
	 * @brief Метод дописывания шестнадцатеричной записи байтов к строке
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
	 * @brief Метод хеширования строки с выдачей шестнадцатеричной записи
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
	 * @brief Метод дописывания перечня чисел через разделитель
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
	 * @brief Метод дописывания перечня значений с пометкой GREASE
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
	 * @brief Метод поиска расширения профиля по виду
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
	 * @brief Метод разбора перечня строк с однобайтовыми длинами и двухбайтовой длиной перечня
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
	 * @brief Метод разбора перечня двухбайтовых значений с двухбайтовой длиной перечня
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
	 * @brief Метод перевода отказа разбора расширения в отказ модуля
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
	 * @brief Метод разбора тела расширения в поля профиля
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
				// Запоминаем значение
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
	 * @brief Метод переноса разобранного приветствия в профиль
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
	 * @brief Метод перевода отказа разбора приветствия в отказ модуля
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
	 * @brief Метод разбора приветствия с заданным устройством заголовков
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
			// Переходим к сообщению рукопожатия
			offset = header;
		// Если байты начинаются не сообщением рукопожатия
		} else if(data.data[0] != GREETING)
			// Выводим отказ записи
			return fingerprint::error_t::RECORD;
		// Размер заголовка сообщения рукопожатия
		const size_t header = (datagram ? HEADER_DATAGRAM : HEADER_STREAM);
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
		// Если сообщение идёт поверх дейтаграмм
		if(datagram){
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
	 * @brief Метод подсчёта старшего издания протокола профиля
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
	 * @brief Метод составления двух знаков издания протокола отпечатка JA4
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
	 * @brief Метод составления двух знаков прикладного протокола отпечатка JA4
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
			// Выходим
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
	 * @brief Метод дописывания счётчика в два знака с пределом 99
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
	 * @brief Метод чтения целого HPACK с заданной шириной префикса
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
	 * @brief Метод пропуска либо чтения строки HPACK
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
			// Выходим
			return;
		// Признак кодирования Хаффмана
		const bool huffman = ((data[offset] & 0x80) != 0);
		// Длина строки
		const size_t length = packed(data, size, offset, 7);
		// Если строка в блок не входит
		if((offset + length) > size){
			// Переходим к концу блока
			offset = size;
			// Выходим
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
	 * @brief Метод определения буквы псевдозаголовка по индексу статической таблицы HPACK
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
	 * @brief Метод определения буквы псевдозаголовка по имени
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
	 * @brief Метод разбора блока заголовков HPACK в порядок псевдозаголовков
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
				// Пропускаем значение
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
	 * @brief Метод дописывания профиля в снимок
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
	 * @brief Метод чтения профиля из снимка
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
 * @brief Конструктор профиля приветствия
 *
 */
nts::fingerprint::Profile::Profile() noexcept :
 grease(false), datagram(false), record(0), version(0), epoch(0), sequence(0), message(0), length(0) {
	// Выполняем обнуление случайного значения приветствия
	::memset(this->random, 0, FINGERPRINT_RANDOM);
}
/**
 * @brief Метод проверки значения на принадлежность к GREASE (RFC 8701)
 *
 * @param value проверяемое значение
 * @return      признак того, что значение есть значение GREASE
 *
 */
bool nts::fingerprint::grease(const uint16_t value) noexcept {
	// Раздел 2 RFC 8701: оба байта равны и младшая половина каждого есть 0xA
	return (((value & 0x0F0F) == 0x0A0A) && ((value >> 8) == (value & 0xFF)));
}
/**
 * @brief Метод разбора приветствия клиента в профиль
 *
 * @param data   разбираемые байты: запись рукопожатия либо голое сообщение потокового устройства
 * @param result заполняемый профиль
 * @return       отказ разбора
 *
 */
nts::fingerprint::error_t nts::fingerprint::parse(const view_t & data, profile_t & result) noexcept {
	/**
	 * Выполняем перехват нехватки памяти
	 */
	try {
		// Если байты начинаются записью с изданием поверх дейтаграмм: устройство определяется по ней
		const bool datagram = ((data.data != nullptr) && (data.size >= 3) && (data.data[0] == HANDSHAKE) && ((twain(data.data + 1) == EDITION_DTLS10) || (twain(data.data + 1) == EDITION_DTLS12) || (twain(data.data + 1) == EDITION_DTLS13)));
		// Выводим итог разбора
		return examine(data, datagram, result);
	/**
	 * Если памяти не хватило
	 */
	} catch(const bad_alloc &) {
		// Сбрасываем профиль
		result = profile_t();
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
}
/**
 * @brief Метод разбора приветствия клиента в профиль с заданным устройством заголовков
 *
 * @param data     разбираемые байты: запись рукопожатия либо голое сообщение
 * @param result   заполняемый профиль
 * @param datagram признак заголовков поверх дейтаграмм
 * @return         отказ разбора
 *
 */
nts::fingerprint::error_t nts::fingerprint::parse(const view_t & data, profile_t & result, const bool datagram) noexcept {
	/**
	 * Выполняем перехват нехватки памяти
	 */
	try {
		// Выводим итог разбора
		return examine(data, datagram, result);
	/**
	 * Если памяти не хватило
	 */
	} catch(const bad_alloc &) {
		// Сбрасываем профиль
		result = profile_t();
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
}
/**
 * @brief Метод вычисления отпечатков профиля
 *
 * @param profile профиль приветствия
 * @param result  заполняемые отпечатки
 * @return        отказ вычисления
 *
 */
nts::fingerprint::error_t nts::fingerprint::imprint(const profile_t & profile, imprint_t & result) noexcept {
	/**
	 * Выполняем перехват нехватки памяти
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
		// Расширения, участвующие в отпечатках
		const extension_t * groups = seek(profile, static_cast <uint16_t> (extension::type_t::GROUPS));
		const extension_t * formats = seek(profile, static_cast <uint16_t> (extension::type_t::FORMATS));
		const extension_t * schemes = seek(profile, static_cast <uint16_t> (extension::type_t::SCHEMES));
		const extension_t * protocols = seek(profile, static_cast <uint16_t> (extension::type_t::PROTOCOLS));
		const extension_t * name = seek(profile, static_cast <uint16_t> (extension::type_t::NAME));
		const extension_t * versions = seek(profile, static_cast <uint16_t> (extension::type_t::VERSIONS));
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
	 * Если памяти не хватило
	 */
	} catch(const bad_alloc &) {
		// Сбрасываем отпечатки
		result = imprint_t();
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
}
/**
 * @brief Метод оценки, похожи ли отпечатки на обозреватель
 *
 * @param imprint отпечатки профиля
 * @return        признак того, что приветствие похоже на приветствие обозревателя
 *
 */
bool nts::fingerprint::browser(const imprint_t & imprint) noexcept {
	// Обозреватель предлагает TLS 1.3, запрашивает узел именем и имеет отпечаток
	return ((imprint.negotiated == EDITION_TLS13) && (imprint.ja4.size() >= 4) && (imprint.ja4[3] == 'd') && !imprint.ja3hash.empty());
}
/**
 * @brief Метод печати профиля текстом для человека
 *
 * @param profile профиль приветствия
 * @param result  строка, в которую помещается печать
 * @return        отказ печати
 *
 */
nts::fingerprint::error_t nts::fingerprint::print(const profile_t & profile, string & result) noexcept {
	/**
	 * Выполняем перехват нехватки памяти
	 */
	try {
		// Сбрасываем строку
		result.clear();
		// Если профиль пуст
		if(profile.suites.empty())
			// Выводим отказ пустого профиля
			return error_t::EMPTY;
		// Дописываем перенос
		result.append(profile.datagram ? "transport: datagrams" : "transport: stream");
		// Дописываем издание записи
		result.append("\nrecord: 0x");
		// Дописываем издание записи
		quartet(profile.record, result);
		// Дописываем издание приветствия
		result.append("\nversion: 0x");
		// Дописываем издание приветствия
		quartet(profile.version, result);
		// Дописываем признак GREASE
		result.append(profile.grease ? "\ngrease: yes" : "\ngrease: no");
		// Дописываем случайное значение
		result.append("\nrandom: ");
		// Дописываем случайное значение
		hexed(profile.random, FINGERPRINT_RANDOM, result);
		// Дописываем опознаватель связи
		result.append("\nsession: ");
		// Дописываем опознаватель связи
		hexed(profile.session.data(), profile.session.size(), result);
		// Если метка возврата есть
		if(!profile.cookie.empty()){
			// Дописываем метку возврата
			result.append("\ncookie: ");
			// Дописываем метку возврата
			hexed(profile.cookie.data(), profile.cookie.size(), result);
		}
		// Дописываем наборы шифрования
		result.append("\nsuites:");
		/**
		 * Выполняем перебор наборов шифрования
		 */
		for(size_t i = 0; i < profile.suites.size(); i++){
			// Дописываем разделитель
			result.append(" 0x");
			// Дописываем набор
			quartet(static_cast <uint16_t> (profile.suites[i]), result);
			// Если набор есть значение GREASE
			if(grease(static_cast <uint16_t> (profile.suites[i])))
				// Дописываем пометку
				result.append("(GREASE)");
		}
		// Дописываем способы сжатия
		result.append("\nmethods:");
		/**
		 * Выполняем перебор способов сжатия
		 */
		for(size_t i = 0; i < profile.methods.size(); i++){
			// Дописываем разделитель
			result.push_back(' ');
			// Дописываем способ сжатия
			decimal(profile.methods[i], result);
		}
		// Дописываем расширения
		result.append("\nextensions:");
		/**
		 * Выполняем перебор расширений
		 */
		for(size_t i = 0; i < profile.extensions.size(); i++){
			// Расширение
			const extension_t & extension = profile.extensions[i];
			// Дописываем вид расширения
			result.append("\n  0x");
			// Дописываем вид расширения
			quartet(extension.type, result);
			// Если расширение есть значение GREASE
			if(extension.grease)
				// Дописываем пометку
				result.append(" GREASE");
			// Дописываем длину тела
			result.append(" length ");
			// Дописываем длину тела
			decimal(extension.data.size(), result);
			/**
			 * Выполняем перебор имён узлов
			 */
			for(size_t j = 0; j < extension.names.size(); j++)
				// Дописываем имя узла
				result.append(" name=").append(extension.names[j]);
			/**
			 * Выполняем перебор прикладных протоколов
			 */
			for(size_t j = 0; j < extension.protocols.size(); j++)
				// Дописываем прикладной протокол
				result.append((j == 0) ? " protocols=" : ",").append(extension.protocols[j]);
			/**
			 * Выполняем перебор групп
			 */
			for(size_t j = 0; j < extension.groups.size(); j++){
				// Дописываем разделитель
				result.append((j == 0) ? " groups=0x" : ",0x");
				// Дописываем группу
				quartet(static_cast <uint16_t> (extension.groups[j]), result);
			}
			/**
			 * Выполняем перебор схем подписи
			 */
			for(size_t j = 0; j < extension.schemes.size(); j++){
				// Дописываем разделитель
				result.append((j == 0) ? " schemes=0x" : ",0x");
				// Дописываем схему
				quartet(static_cast <uint16_t> (extension.schemes[j]), result);
			}
			/**
			 * Выполняем перебор изданий
			 */
			for(size_t j = 0; j < extension.versions.size(); j++){
				// Дописываем разделитель
				result.append((j == 0) ? " versions=0x" : ",0x");
				// Дописываем издание
				quartet(extension.versions[j], result);
			}
			/**
			 * Выполняем перебор долей ключей
			 */
			for(size_t j = 0; j < extension.shares.size(); j++){
				// Дописываем разделитель
				result.append((j == 0) ? " shares=0x" : ",0x");
				// Дописываем группу доли
				quartet(static_cast <uint16_t> (extension.shares[j].group), result);
				// Дописываем длину доли
				result.push_back('/');
				// Дописываем длину доли
				decimal(extension.shares[j].key.size(), result);
			}
			// Если расширение несёт число
			if(extension.value != 0){
				// Дописываем число
				result.append(" value=");
				// Дописываем число
				decimal(extension.value, result);
			}
		}
		// Дописываем перенос строки
		result.push_back('\n');
		// Выводим успешность печати
		return error_t::NONE;
	/**
	 * Если памяти не хватило
	 */
	} catch(const bad_alloc &) {
		// Сбрасываем строку
		result.clear();
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
}
/**
 * @brief Метод разбора начала потока HTTP/2 в его признаки
 *
 * @param data   байты потока от предисловия до первого запроса
 * @param result заполняемые признаки потока
 * @return       отказ разбора
 *
 */
nts::fingerprint::error_t nts::fingerprint::parse(const view_t & data, stream_t & result) noexcept {
	/**
	 * Выполняем перехват нехватки памяти
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
							// Настройка
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
						// Приоритет
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
	 * Если памяти не хватило
	 */
	} catch(const bad_alloc &) {
		// Сбрасываем признаки потока
		result = stream_t();
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
}
/**
 * @brief Метод вычисления отпечатка Akamai по признакам потока HTTP/2
 *
 * @param stream признаки потока
 * @param result строка, в которую помещается отпечаток
 * @return       отказ вычисления
 *
 */
nts::fingerprint::error_t nts::fingerprint::akamai(const stream_t & stream, string & result) noexcept {
	/**
	 * Выполняем перехват нехватки памяти
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
	 * Если памяти не хватило
	 */
	} catch(const bad_alloc &) {
		// Сбрасываем строку
		result.clear();
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
}
/**
 * @brief Метод составления снимка профиля
 *
 * @param profile профиль приветствия
 * @param result  накопитель, в который помещается снимок
 * @return        отказ составления
 *
 */
nts::fingerprint::error_t nts::fingerprint::dump(const profile_t & profile, vector <uint8_t> & result) noexcept {
	/**
	 * Выполняем перехват нехватки памяти
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
		result[place + 1] = static_cast <uint8_t> (length >> 16);
		result[place + 2] = static_cast <uint8_t> (length >> 8);
		result[place + 3] = static_cast <uint8_t> (length);
		// Выводим успешность составления
		return error_t::NONE;
	/**
	 * Если памяти не хватило
	 */
	} catch(const bad_alloc &) {
		// Сбрасываем накопитель
		result.clear();
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
}
/**
 * @brief Метод чтения профиля из снимка
 *
 * @param data   байты снимка
 * @param result заполняемый профиль
 * @return       отказ чтения
 *
 */
nts::fingerprint::error_t nts::fingerprint::load(const view_t & data, profile_t & result) noexcept {
	/**
	 * Выполняем перехват нехватки памяти
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
	 * Если памяти не хватило
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
 * @return        опознаватель профиля либо ноль при отказе
 *
 */
nts::fingerprint::id_t nts::fingerprint::Store::add(const profile_t & profile) noexcept {
	/**
	 * Выполняем перехват нехватки памяти
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
	 * Если памяти не хватило
	 */
	} catch(const bad_alloc &) {
		// Выводим отсутствие опознавателя
		return 0;
	}
}
/**
 * @brief Метод удаления профиля из хранилища
 *
 * @param id опознаватель профиля
 * @return   результат удаления
 *
 */
bool nts::fingerprint::Store::remove(const id_t id) noexcept {
	/**
	 * Выполняем перебор записей хранилища
	 */
	for(size_t i = 0; i < this->_entries.size(); i++){
		// Если опознаватель совпал
		if(this->_entries[i].id == id){
			// Удаляем запись
			this->_entries.erase(this->_entries.begin() + static_cast <ptrdiff_t> (i));
			// Выводим успешность удаления
			return true;
		}
	}
	// Выводим отсутствие профиля
	return false;
}
/**
 * @brief Метод получения профиля из хранилища
 *
 * @param id опознаватель профиля
 * @return   профиль либо nullptr
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
 * @param result перечень опознавателей в порядке добавления
 * @return       отказ получения
 *
 */
nts::fingerprint::error_t nts::fingerprint::Store::list(vector <id_t> & result) const noexcept {
	/**
	 * Выполняем перехват нехватки памяти
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
	 * Если памяти не хватило
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
 * @return признак пустоты
 *
 */
bool nts::fingerprint::Store::empty() const noexcept {
	// Выводим пустоту хранилища
	return this->_entries.empty();
}
/**
 * @brief Метод получения числа профилей хранилища
 *
 * @return число профилей
 *
 */
size_t nts::fingerprint::Store::size() const noexcept {
	// Выводим число записей
	return this->_entries.size();
}
/**
 * @brief Метод составления снимка хранилища
 *
 * @param result накопитель, в который помещается снимок
 * @return       отказ составления
 *
 */
nts::fingerprint::error_t nts::fingerprint::Store::dump(vector <uint8_t> & result) const noexcept {
	/**
	 * Выполняем перехват нехватки памяти
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
	 * Если памяти не хватило
	 */
	} catch(const bad_alloc &) {
		// Сбрасываем накопитель
		result.clear();
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
}
/**
 * @brief Метод чтения хранилища из снимка
 *
 * @param data байты снимка
 * @return     отказ чтения
 *
 */
nts::fingerprint::error_t nts::fingerprint::Store::load(const view_t & data) noexcept {
	/**
	 * Выполняем перехват нехватки памяти
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
			// Добавляем запись
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
	 * Если памяти не хватило
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
}
/**
 * @brief Конструктор хранилища
 *
 */
nts::fingerprint::Store::Store() noexcept {}
