/**
 * @file openssh.cpp
 * @date 2026-10-04
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
 * @brief Модуль формата ключей openssh-key-v1
 *
 * @details Разбор и запись ключей OpenSSH: магия «openssh-key-v1\0», SSH-строки
 *          (uint32 длина + байты), незашифрованный формат и зашифрованный
 *          bcrypt_pbkdf + aes256-ctr. Портировано с OpenSSH PROTOCOL.key
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные модули
 */
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <keys/openssh.hpp>
#include <digest/bcrypt.hpp>
#include <digest/hmac.hpp>
#include <digest/sha2.hpp>
#include <cipher/aes.hpp>
#include <cipher/mode.hpp>
#include <entropy/entropy.hpp>
#include <sys/wipe.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * @brief Служебные объекты модуля
 *
 */
namespace {
	/**
	 * Пространство имён проекта
	 */
	using namespace nts;

	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;

	/**
	 * @brief Константы формата
	 *
	 */
	// Магия формата
	constexpr char MAGIC[] = "openssh-key-v1";
	// Размер магии с NUL
	constexpr size_t MAGIC_SIZE = 15;
	// Размер блока AES
	constexpr size_t BLOCK_SIZE = 16;
	// Размер ключа AES-256
	constexpr size_t KEY_SIZE = 32;
	// Размер IV AES-CTR
	constexpr size_t IV_SIZE = 16;
	// Размер соли bcrypt
	constexpr size_t SALT_SIZE = 16;
	// Число кругов bcrypt по умолчанию
	constexpr size_t DEFAULT_ROUNDS = 16;

	/**
	 * @brief Разборщик SSH-строк
	 *
	 */
	struct Reader {
		// Данные
		const uint8_t * data;
		// Размер данных
		size_t size;
		// Текущая позиция
		size_t pos;

		/**
		 * @brief Конструктор
		 *
		 * @param d данные
		 * @param s размер
		 *
		 */
		Reader(const uint8_t * d, const size_t s) noexcept : data(d), size(s), pos(0) {}

		/**
		 * @brief Метод чтения uint32
		 *
		 * @param value прочитанное значение
		 *
		 * @return      признак успешности
		 *
		 */
		bool uint32(uint32_t & value) noexcept {
			if(pos + 4 > size)
				return false;
			value = (static_cast <uint32_t> (data[pos]) << 24) |
			        (static_cast <uint32_t> (data[pos + 1]) << 16) |
			        (static_cast <uint32_t> (data[pos + 2]) << 8) |
			        static_cast <uint32_t> (data[pos + 3]);
			pos += 4;
			return true;
		}

		/**
		 * @brief Метод чтения строки
		 *
		 * @param str прочитанная строка
		 *
		 * @return    признак успешности
		 *
		 */
		bool string(view_t & str) noexcept {
			uint32_t len;
			if(!uint32(len))
				return false;
			if(pos + len > size)
				return false;
			str.data = data + pos;
			str.size = len;
			pos += len;
			return true;
		}

		/**
		 * @brief Метод чтения строки в std::string
		 *
		 * @param str прочитанная строка
		 *
		 * @return    признак успешности
		 *
		 */
		bool string(std::string & str) noexcept {
			view_t v;
			if(!string(v))
				return false;
			str.assign(reinterpret_cast <const char *> (v.data), v.size);
			return true;
		}

		/**
		 * @brief Метод чтения строки в vector
		 *
		 * @param vec прочитанный вектор
		 *
		 * @return     признак успешности
		 *
		 */
		bool string(vector <uint8_t> & vec) noexcept {
			view_t v;
			if(!string(v))
				return false;
			vec.assign(v.data, v.data + v.size);
			return true;
		}

		/**
		 * @brief Метод проверки окончания данных
		 *
		 * @return признак того, что данные закончились
		 *
		 */
		bool empty() const noexcept {
			return pos >= size;
		}

		/**
		 * @brief Метод получения оставшихся данных
		 *
		 * @return оставшиеся данные
		 *
		 */
		view_t rest() const noexcept {
			return view_t(data + pos, size - pos);
		}
	};

	/**
	 * @brief Записыватель SSH-строк
	 *
	 */
	struct Writer {
		// Буфер
		vector <uint8_t> & buffer;

		/**
		 * @brief Конструктор
		 *
		 * @param buf буфер
		 *
		 */
		Writer(vector <uint8_t> & buf) noexcept : buffer(buf) {}

		/**
		 * @brief Метод записи uint32
		 *
		 * @param value записываемое значение
		 *
		 */
		void uint32(const uint32_t value) noexcept {
			buffer.push_back((value >> 24) & 0xff);
			buffer.push_back((value >> 16) & 0xff);
			buffer.push_back((value >> 8) & 0xff);
			buffer.push_back(value & 0xff);
		}

		/**
		 * @brief Метод записи строки
		 *
		 * @param data данные
		 * @param size размер
		 *
		 */
		void string(const uint8_t * data, const size_t size) noexcept {
			uint32(static_cast <uint32_t> (size));
			buffer.insert(buffer.end(), data, data + size);
		}

		/**
		 * @brief Метод записи строки
		 *
		 * @param str строка
		 *
		 */
		void string(const view_t & str) noexcept {
			string(str.data, str.size);
		}

		/**
		 * @brief Метод записи строки
		 *
		 * @param str строка
		 *
		 */
		void string(const std::string & str) noexcept {
			string(reinterpret_cast <const uint8_t *> (str.data()), str.size());
		}

		/**
		 * @brief Метод записи строки
		 *
		 * @param vec вектор
		 *
		 */
		void string(const vector <uint8_t> & vec) noexcept {
			string(vec.data(), vec.size());
		}

		/**
		 * @brief Метод записи байтов без длины
		 *
		 * @param data данные
		 * @param size размер
		 *
		 */
		void bytes(const uint8_t * data, const size_t size) noexcept {
			buffer.insert(buffer.end(), data, data + size);
		}
	};

	/**
	 * @brief Метод кодирования base64
	 *
	 * @param data данные
	 * @param size размер
	 *
	 * @return     строка base64
	 *
	 */
	string base64_encode(const uint8_t * data, const size_t size) noexcept {
		static const char ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		string result;
		result.reserve((size + 2) / 3 * 4);
		for(size_t i = 0; i < size; i += 3){
			uint32_t v = static_cast <uint32_t> (data[i]) << 16;
			if(i + 1 < size)
				v |= static_cast <uint32_t> (data[i + 1]) << 8;
			if(i + 2 < size)
				v |= static_cast <uint32_t> (data[i + 2]);
			result.push_back(ALPHABET[(v >> 18) & 63]);
			result.push_back(ALPHABET[(v >> 12) & 63]);
			result.push_back((i + 1 < size) ? ALPHABET[(v >> 6) & 63] : '=');
			result.push_back((i + 2 < size) ? ALPHABET[v & 63] : '=');
		}
		return result;
	}

	/**
	 * @brief Метод декодирования base64
	 *
	 * @param text строка base64
	 * @param data место для байтов
	 *
	 * @return     признак успешности
	 *
	 */
	bool base64_decode(const string & text, vector <uint8_t> & data) noexcept {
		static const int8_t TABLE[256] = {
			-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
			-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
			-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
			52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
			-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
			15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
			-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
			41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
			-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
			-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
			-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
			-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
			-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
			-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
			-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
			-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
		};
		data.clear();
		data.reserve(text.size() * 3 / 4);
		uint32_t v = 0;
		int bits = 0;
		for(const char c : text){
			const int8_t d = TABLE[static_cast <uint8_t> (c)];
			if(d == -2) // '='
				break;
			if(d < 0)
				return false;
			v = (v << 6) | static_cast <uint32_t> (d);
			bits += 6;
			if(bits >= 8){
				bits -= 8;
				data.push_back(static_cast <uint8_t> (v >> bits));
			}
		}
		return true;
	}

	/**
	 * @brief Метод разбора секретного блока ed25519
	 *
	 * @param reader  разборщик
	 * @param key     разобранный ключ
	 * @param comment комментарий
	 *
	 * @return        признак успешности
	 *
	 */
	bool parse_private(Reader & reader, keys::key_t & key, string & comment) noexcept {
		// Проверочные числа
		uint32_t check1, check2;
		if(!reader.uint32(check1) || !reader.uint32(check2))
			return false;
		if(check1 != check2)
			return false;
		// Тип ключа
		string type;
		if(!reader.string(type))
			return false;
		if(type != "ssh-ed25519")
			return false;
		// Открытый ключ
		vector <uint8_t> pubkey;
		if(!reader.string(pubkey))
			return false;
		if(pubkey.size() != 32)
			return false;
		// Секретный ключ (64 байта: seed || pubkey)
		vector <uint8_t> privkey;
		if(!reader.string(privkey))
			return false;
		if(privkey.size() != 64)
			return false;
		// Проверяем совпадение открытой части
		if(::memcmp(privkey.data() + 32, pubkey.data(), 32) != 0)
			return false;
		// Комментарий
		if(!reader.string(comment))
			return false;
		// Заполняем ключ
		key.kind = keys::kind_t::ED25519;
		key.d.assign(privkey.data(), privkey.data() + 32);
		key.key = pubkey;
		// Затираем секрет
		wipe(privkey.data(), privkey.size());
		return true;
	}

	/**
	 * @brief Метод записи секретного блока ed25519
	 *
	 * @param writer  записыватель
	 * @param key     ключ
	 * @param comment комментарий
	 *
	 */
	void write_private(Writer & writer, const keys::key_t & key, const string & comment) noexcept {
		// Проверочное число
		uint32_t check;
		entropy::bytes(reinterpret_cast <uint8_t *> (&check), sizeof(check));
		writer.uint32(check);
		writer.uint32(check);
		// Тип ключа
		writer.string("ssh-ed25519");
		// Открытый ключ
		writer.string(key.key);
		// Секретный ключ (64 байта: seed || pubkey)
		vector <uint8_t> privkey;
		privkey.reserve(64);
		privkey.insert(privkey.end(), key.d.begin(), key.d.end());
		privkey.insert(privkey.end(), key.key.begin(), key.key.end());
		writer.string(privkey);
		wipe(privkey.data(), privkey.size());
		// Комментарий
		writer.string(comment);
		// Дополнение до кратности блоку
		const size_t padlen = BLOCK_SIZE - (writer.buffer.size() % BLOCK_SIZE);
		for(size_t i = 1; i <= padlen; ++i)
			writer.buffer.push_back(static_cast <uint8_t> (i));
	}
};

/**
 * \~russian
 * @brief Метод разбора ключа openssh-key-v1
 *
 * \~english
 * @brief Method of the parsing of an openssh-key-v1 key
 *
 * \~
 */
bool nts::keys::openssh::decode(const view_t & data, const view_t & password, key_t & key, string & comment) noexcept {
	// Проверяем параметры
	if(data.data == nullptr || data.size < MAGIC_SIZE)
		return false;
	// Проверяем магию
	if(::memcmp(data.data, MAGIC, MAGIC_SIZE) != 0)
		return false;
	// Заводим разборщик
	Reader reader(data.data + MAGIC_SIZE, data.size - MAGIC_SIZE);
	// Читаем ciphername
	string ciphername;
	if(!reader.string(ciphername))
		return false;
	// Читаем kdfname
	string kdfname;
	if(!reader.string(kdfname))
		return false;
	// Читаем kdfoptions
	vector <uint8_t> kdfoptions;
	if(!reader.string(kdfoptions))
		return false;
	// Читаем число ключей
	uint32_t nkeys;
	if(!reader.uint32(nkeys))
		return false;
	if(nkeys != 1)
		return false;
	// Читаем открытый ключ
	vector <uint8_t> pubkey;
	if(!reader.string(pubkey))
		return false;
	// Читаем секретный блок
	vector <uint8_t> privblock;
	if(!reader.string(privblock))
		return false;
	// Если шифрование есть
	if(ciphername == "aes256-ctr"){
		// Проверяем kdfname
		if(kdfname != "bcrypt")
			return false;
		// Проверяем пароль
		if(password.data == nullptr || password.size == 0)
			return false;
		// Разбираем kdfoptions: salt + rounds
		Reader kdfreader(kdfoptions.data(), kdfoptions.size());
		vector <uint8_t> salt;
		if(!kdfreader.string(salt))
			return false;
		uint32_t rounds;
		if(!kdfreader.uint32(rounds))
			return false;
		// Вырабатываем ключ
		uint8_t enckey[KEY_SIZE + IV_SIZE];
		if(!digest::bcrypt(password, view_t(salt.data(), salt.size()), enckey, sizeof(enckey), rounds))
			return false;
		// Расшифровываем AES-256-CTR вручную
		cipher::aes_t aes;
		if(!aes.key(view_t(enckey, KEY_SIZE))){
			wipe(enckey, sizeof(enckey));
			return false;
		}
		uint8_t counter[IV_SIZE];
		::memcpy(counter, enckey + KEY_SIZE, IV_SIZE);
		uint8_t gamma[IV_SIZE];
		for(size_t off = 0; off < privblock.size(); off += IV_SIZE){
			if(!aes.encrypt(counter, gamma)){
				wipe(enckey, sizeof(enckey));
				return false;
			}
			const size_t chunk = (privblock.size() - off < IV_SIZE) ? privblock.size() - off : IV_SIZE;
			for(size_t i = 0; i < chunk; ++i)
				privblock[off + i] ^= gamma[i];
			// Инкрементируем счётчик как big-endian
			for(size_t i = IV_SIZE; i > 0; --i){
				if(++counter[i - 1] != 0)
					break;
			}
		}
		wipe(enckey, sizeof(enckey));
		wipe(counter, sizeof(counter));
		wipe(gamma, sizeof(gamma));
	} else if(ciphername != "none"){
		return false;
	}
	// Разбираем секретный блок
	Reader privreader(privblock.data(), privblock.size());
	const bool result = parse_private(privreader, key, comment);
	wipe(privblock.data(), privblock.size());
	return result;
}

/**
 * \~russian
 * @brief Метод записи ключа openssh-key-v1
 *
 * \~english
 * @brief Method of the writing of an openssh-key-v1 key
 *
 * \~
 */
bool nts::keys::openssh::encode(const key_t & key, const string & comment, const view_t & password, vector <uint8_t> & result) noexcept {
	// Проверяем ключ
	if(key.kind != kind_t::ED25519 || key.d.size() != 32 || key.key.size() != 32)
		return false;
	// Очищаем результат
	result.clear();
	// Записываем магию
	result.insert(result.end(), MAGIC, MAGIC + MAGIC_SIZE);
	// Заводим записыватель
	Writer writer(result);
	// Определяем шифрование
	const bool encrypted = (password.data != nullptr && password.size > 0);
	// Соль для шифрования
	uint8_t salt[SALT_SIZE];
	// Записываем ciphername, kdfname, kdfoptions
	if(encrypted){
		writer.string("aes256-ctr");
		writer.string("bcrypt");
		// Вырабатываем соль
		if(!entropy::bytes(salt, sizeof(salt)))
			return false;
		// Формируем kdfoptions
		vector <uint8_t> kdfoptions;
		Writer kdfwriter(kdfoptions);
		kdfwriter.string(salt, sizeof(salt));
		kdfwriter.uint32(DEFAULT_ROUNDS);
		writer.string(kdfoptions);
	} else {
		writer.string("none");
		writer.string("none");
		writer.string(view_t());
	}
	// Записываем число ключей
	writer.uint32(1);
	// Записываем открытый ключ
	{
		vector <uint8_t> pubblock;
		Writer pubwriter(pubblock);
		pubwriter.string("ssh-ed25519");
		pubwriter.string(key.key);
		writer.string(pubblock);
	}
	// Записываем секретный блок
	vector <uint8_t> privblock;
	{
		Writer privwriter(privblock);
		write_private(privwriter, key, comment);
	}
	// Если шифрование есть
	if(encrypted){
		// Вырабатываем ключ
		uint8_t enckey[KEY_SIZE + IV_SIZE];
		if(!digest::bcrypt(password, view_t(salt, sizeof(salt)), enckey, sizeof(enckey), DEFAULT_ROUNDS)){
			wipe(privblock.data(), privblock.size());
			return false;
		}
		// Шифруем AES-256-CTR вручную
		cipher::aes_t aes;
		if(!aes.key(view_t(enckey, KEY_SIZE))){
			wipe(enckey, sizeof(enckey));
			wipe(privblock.data(), privblock.size());
			return false;
		}
		uint8_t counter[IV_SIZE];
		::memcpy(counter, enckey + KEY_SIZE, IV_SIZE);
		uint8_t gamma[IV_SIZE];
		for(size_t off = 0; off < privblock.size(); off += IV_SIZE){
			if(!aes.encrypt(counter, gamma)){
				wipe(enckey, sizeof(enckey));
				wipe(privblock.data(), privblock.size());
				return false;
			}
			const size_t chunk = (privblock.size() - off < IV_SIZE) ? privblock.size() - off : IV_SIZE;
			for(size_t i = 0; i < chunk; ++i)
				privblock[off + i] ^= gamma[i];
			// Инкрементируем счётчик как big-endian
			for(size_t i = IV_SIZE; i > 0; --i){
				if(++counter[i - 1] != 0)
					break;
			}
		}
		wipe(enckey, sizeof(enckey));
		wipe(counter, sizeof(counter));
		wipe(gamma, sizeof(gamma));
	}
	// Записываем секретный блок
	writer.string(privblock);
	wipe(privblock.data(), privblock.size());
	return true;
}

/**
 * \~russian
 * @brief Метод записи открытого ключа в строку authorized_keys
 *
 * \~english
 * @brief Method of the writing of a public key into an authorized_keys line
 *
 * \~
 */
string nts::keys::openssh::publish(const key_t & key, const string & comment) noexcept {
	// Проверяем ключ
	if(key.kind != kind_t::ED25519 || key.key.size() != 32)
		return string();
	// Формируем блок открытого ключа
	vector <uint8_t> pubblock;
	Writer pubwriter(pubblock);
	pubwriter.string("ssh-ed25519");
	pubwriter.string(key.key);
	// Формируем строку
	string result = "ssh-ed25519 ";
	result += base64_encode(pubblock.data(), pubblock.size());
	if(!comment.empty()){
		result += ' ';
		result += comment;
	}
	return result;
}

/**
 * \~russian
 * @brief Метод вычисления отпечатка ключа SHA256
 *
 * \~english
 * @brief Method of the computation of the SHA256 fingerprint of a key
 *
 * \~
 */
string nts::keys::openssh::fingerprint(const key_t & key) noexcept {
	// Проверяем ключ
	if(key.kind != kind_t::ED25519 || key.key.size() != 32)
		return string();
	// Формируем блок открытого ключа
	vector <uint8_t> pubblock;
	Writer pubwriter(pubblock);
	pubwriter.string("ssh-ed25519");
	pubwriter.string(key.key);
	// Вычисляем хеш
	uint8_t hash[32];
	digest::Sha2 sha(digest::sha_t::SHA256);
	sha.update(view_t(pubblock.data(), pubblock.size()));
	sha.finish(hash, sizeof(hash));
	// Формируем отпечаток без padding
	string b64 = base64_encode(hash, sizeof(hash));
	while(!b64.empty() && b64.back() == '=')
		b64.pop_back();
	return "SHA256:" + b64;
}

/**
 * \~russian
 * @brief Метод разбора строки known_hosts
 *
 * \~english
 * @brief Method of the parsing of a known_hosts line
 *
 * \~
 */
bool nts::keys::openssh::knownHosts(const string & line, known_host_t & result) noexcept {
	// Сбрасываем сведения о записи
	result = known_host_t();
	// Если строка пуста
	if(line.empty())
		// Выводим отказ разбора
		return false;
	// Место чтения строки
	size_t offset = 0;
	/**
	 * Метод чтения очередного поля строки до пробела
	 */
	auto field = [&line](size_t & at, string & value) noexcept -> bool {
		// Если строка кончилась
		if(at >= line.size())
			// Выводим отказ
			return false;
		// Место конца поля
		const size_t end = line.find(' ', at);
		// Запоминаем поле
		value = line.substr(at, (end == string::npos) ? string::npos : (end - at));
		// Сдвигаем место за поле и пробел
		at = ((end == string::npos) ? line.size() : (end + 1));
		// Выводим признак наличия поля
		return !value.empty();
	};
	// Первое поле строки: хозяин либо маркер хеширования
	string marker;
	// Если первое поле прочитать не удалось
	if(!field(offset, marker))
		// Выводим отказ разбора
		return false;
	// Если запись хешированная: маркер |1|base64(соль)|base64(хеш)
	if(marker.compare(0, 3, "|1|") == 0){
		// Место второго разделителя маркера
		const size_t separator = marker.find('|', 3);
		// Если разделителя нет
		if(separator == string::npos)
			// Выводим отказ разбора
			return false;
		// Записываем соль и хеш из base64
		if(!base64_decode(marker.substr(3, separator - 3), result.salt) || !base64_decode(marker.substr(separator + 1), result.hash))
			// Выводим отказ разбора
			return false;
		// Если соль либо хеш пусты
		if(result.salt.empty() || result.hash.empty())
			// Выводим отказ разбора
			return false;
		// Отмечаем хешированную запись
		result.hashed = true;
	// Иначе хозяин открытым текстом
	} else {
		// Запоминаем хозяина
		result.host = marker;
		// Если хозяин пуст либо несёт запрещённые знаки
		if(result.host.empty() || (result.host.find('*') != string::npos) || (result.host.find('?') != string::npos))
			// Выводим отказ разбора
			return false;
	}
	// Тип ключа
	if(!field(offset, result.type))
		// Выводим отказ разбора
		return false;
	// Открытый ключ из base64
	string encoded;
	// Если поле ключа прочитать либо декодировать не удалось
	if(!field(offset, encoded) || !base64_decode(encoded, result.key))
		// Выводим отказ разбора
		return false;
	// Если ключ пуст
	if(result.key.empty())
		// Выводим отказ разбора
		return false;
	// Комментарий: остаток строки за ключом
	if(offset < line.size())
		// Запоминаем комментарий
		result.comment = line.substr(offset);
	// Выводим признак успешности разбора
	return true;
}

/**
 * \~russian
 * @brief Метод сборки строки known_hosts
 *
 * \~english
 * @brief Method of the building of a known_hosts line
 *
 * \~
 */
bool nts::keys::openssh::knownHosts(const string & host, const key_t & key, const string & comment, const bool hashed, string & result) noexcept {
	// Если хозяин пуст либо ключ негоден
	if(host.empty() || (key.kind != kind_t::ED25519) || (key.key.size() != 32))
		// Выводим отказ сборки
		return false;
	// Формируем блок открытого ключа
	vector <uint8_t> pubblock;
	Writer pubwriter(pubblock);
	pubwriter.string("ssh-ed25519");
	pubwriter.string(key.key);
	// Начало строки: хозяин открытым текстом либо хешем
	string beginning;
	// Если хозяин идёт хешем
	if(hashed){
		// Соль хеша: двадцать случайных байтов
		uint8_t salt[20];
		// Если случайные байты выработать не удалось
		if(!entropy::bytes(salt, sizeof(salt)))
			// Выводим отказ сборки
			return false;
		// Хеш хозяина HMAC-SHA1
		uint8_t hash[20];
		// Если хеш вычислить не удалось
		if(!digest::hmac(digest::hash_t::SHA1, view_t(salt, sizeof(salt)), view_t(reinterpret_cast <const uint8_t *> (host.data()), host.size()), hash, sizeof(hash))){
			// Выполняем затирание соли
			wipe(salt, sizeof(salt));
			// Выводим отказ сборки
			return false;
		}
		// Собираем маркер хеширования
		beginning = "|1|" + base64_encode(salt, sizeof(salt)) + "|" + base64_encode(hash, sizeof(hash));
		// Выполняем затирание рабочих областей
		wipe(salt, sizeof(salt));
		wipe(hash, sizeof(hash));
	// Иначе хозяин открытым текстом
	} else
		// Запоминаем хозяина
		beginning = host;
	// Собираем строку
	result = beginning + " ssh-ed25519 " + base64_encode(pubblock.data(), pubblock.size());
	// Если комментарий задан
	if(!comment.empty())
		// Дописываем комментарий
		result += " " + comment;
	// Выводим признак успешности сборки
	return true;
}

/**
 * \~russian
 * @brief Метод сверки хозяина с записью known_hosts
 *
 * \~english
 * @brief Method of the matching of a host against a known_hosts record
 *
 * \~
 */
bool nts::keys::openssh::knownHostsMatch(const known_host_t & record, const string & host) noexcept {
	// Если запись открытая
	if(!record.hashed)
		// Хозяин сличается строкой
		return (record.host == host);
	// Если соли либо хеша нет
	if(record.salt.empty() || record.hash.empty())
		// Выводим несовпадение
		return false;
	// Хеш сверяемого хозяина HMAC-SHA1
	uint8_t computed[64];
	// Длина хеша записи
	const size_t width = record.hash.size();
	// Если длина хеша непомерна либо хеш вычислить не удалось
	if((width > sizeof(computed)) || !digest::hmac(digest::hash_t::SHA1, view_t(record.salt.data(), record.salt.size()), view_t(reinterpret_cast <const uint8_t *> (host.data()), host.size()), computed, width))
		// Выводим несовпадение
		return false;
	// Накопитель расхождения
	uint8_t diff = 0;
	// Проходим по байтам хеша без раннего выхода
	for(size_t i = 0; i < width; i++)
		// Накапливаем расхождение
		diff |= static_cast <uint8_t> (computed[i] ^ record.hash[i]);
	// Выполняем затирание вычисленного хеша
	wipe(computed, sizeof(computed));
	// Хозяин совпадает при нулевом расхождении
	return (diff == 0);
}
