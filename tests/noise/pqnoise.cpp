/**
 * @file pqnoise.cpp
 * @date 2026-09-08
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
 * @brief Проверки PQNoise: отвлечение KEM, тринадцать узоров в обе роли, предельные длины, свой замороженный корпус, отказы
 *
 * @details Чужого корпуса у PQNoise нет. Корпус tests/corpus/noise/pqnoise.txt порождён нашим же
 *          кодом на закреплённых зёрнах и заморожен: он доказывает неизменность поведения с
 *          дня заморозки, не правильность и не совместимость. Пересоздание - только вслух:
 *          ANTS_NOISE_FREEZE=путь пишет новый файл и проваливает проверку, чтобы заморозка не
 *          прошла молча
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <cstdint>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <starve.hpp>
#include <noise/noise.hpp>
#include <noise/cipher.hpp>
#include <noise/handshake.hpp>
#include <agreement/mlkem.hpp>
#include <agreement/x25519.hpp>

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * Путь к набору корпусов
 */
static const char * CORPUS = ANTS_CORPUS;

/**
 * @brief Служебные объекты набора
 *
 */
namespace {
	/**
	 * Узоры PQNoise
	 */
	static const noise::pattern_t PATTERNS[] = {
		// Перечисляем образцы Noise
		noise::pattern_t::PQN, noise::pattern_t::PQNN, noise::pattern_t::PQNK, noise::pattern_t::PQNX, noise::pattern_t::PQKN,
		noise::pattern_t::PQKK, noise::pattern_t::PQKX, noise::pattern_t::PQXN, noise::pattern_t::PQXK, noise::pattern_t::PQXX,
		noise::pattern_t::PQIN, noise::pattern_t::PQIK, noise::pattern_t::PQIX
	};
	/**
	 * Механизмы и наборы
	 */
	static const noise::kem_t KEMS[] = {noise::kem_t::X25519MLKEM768, noise::kem_t::MLKEM768};
	// Задаём таблицу шифрований
	static const noise::aead_t AEADS[] = {noise::aead_t::CHACHAPOLY, noise::aead_t::AESGCM};
	// Задаём таблицу хешей
	static const digest::hash_t HASHES[] = {digest::hash_t::SHA256, digest::hash_t::SHA512, digest::hash_t::BLAKE2S256, digest::hash_t::BLAKE2B512};
	/**
	 * @brief Область байтов вектора
	 *
	 */
	static view_t span(const std::vector <uint8_t> & data) {
		// Пустой вектор даёт пустую область
		return view_t(data.empty() ? nullptr : data.data(), data.size());
	}
	/**
	 * @brief Область байтов строки
	 *
	 */
	static view_t span(const std::string & text) {
		// Область байтов строки без копирования
		return view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size());
	}
	/**
	 * @brief Разбор шестнадцатеричной строки
	 *
	 */
	static std::vector <uint8_t> unhex(const std::string & text) {
		// Объявляем буфер байтов
		std::vector <uint8_t> result;
		/**
		 * Перебираем: пары символов текста при условии, что они не кончились
		 */
		for(size_t i = 0; (i + 1) < text.size(); i += 2) result.push_back(static_cast <uint8_t> (::strtoul(text.substr(i, 2).c_str(), nullptr, 16)));
		// Выводим буфер разобранных байтов
		return result;
	}
	/**
	 * @brief Запись байтов шестнадцатеричной строкой
	 *
	 */
	static std::string hex(const uint8_t * data, const size_t size) {
		// Объявляем строку
		std::string result;
		// Задаём цифры шестнадцатеричной записи
		static const char * DIGITS = "0123456789abcdef";
		/**
		 * Перебираем: байты области при условии, что они не кончились
		 */
		for(size_t i = 0; i < size; i++){ result.push_back(DIGITS[data[i] >> 4]); result.push_back(DIGITS[data[i] & 0x0F]); }
		// Выводим строку записанных байтов
		return result;
	}
	/**
	 * @brief Детерминированное заполнение: байт i = (seed + i * step) mod 256
	 *
	 */
	static std::vector <uint8_t> bytes(const size_t size, const uint8_t seed, const uint8_t step) {
		// Объявляем буфер байтов заданного размера
		std::vector <uint8_t> result(size);
		/**
		 * Перебираем: байты результата при условии, что они не кончились
		 */
		for(size_t i = 0; i < size; i++) result[i] = static_cast <uint8_t> (seed + (i * step));
		// Выводим заполненный буфер байтов
		return result;
	}
	/**
	 * @brief Имя протокола по узору и набору
	 *
	 */
	static std::string title(const noise::pattern_t pattern, const noise::suite_t & suite) {
		// Объявляем буфер имени рукопожатия
		char text[noise::NAME_LIMIT];
		// Задаём ёмкость буфера имени
		size_t size = sizeof(text);
		// Если имя узора не разобралось, выводим пустую запись
		if(!noise::name(pattern, 0, suite, text, size)) return std::string();
		// Выводим имя протокола собранным буфером
		return std::string(text, size);
	}
	/**
	 * @brief Признак того, что предсообщение стороны несёт постоянный ключ
	 *
	 */
	static bool preknown(const noise::pattern_t pattern, const bool initiator) {
		// Заводим указатель на лексемы сообщения
		const noise::token_t * list = nullptr;
		// Заводим счётчик лексем
		size_t count = 0;
		// Возвращаем признак успешности проверки
		return (noise::premessage(pattern, initiator, list, count) && (count > 0));
	}
	/**
	 * @brief Число своих знаков KEM у стороны - столько случайностей нужно корпусу
	 *
	 */
	static size_t kemtokens(const noise::pattern_t pattern, const bool initiator) {
		// Заводим счётчик знаков KEM
		size_t result = 0;
		/**
		 * Перебираем: сообщения образца при условии, что они не кончились
		 */
		for(size_t i = 0; i < noise::messages(pattern); i++){
			// Если сторона сообщения не совпала с ходом, пропускаем
			if(((i % 2) == 0) != initiator) continue;
			// Заводим указатель на лексемы сообщения
			const noise::token_t * list = nullptr;
			// Заводим счётчик лексем
			size_t count = 0;
			// Получаем лексемы сообщения
			noise::tokens(pattern, i, list, count);
			/**
			 * Перебираем: лексемы сообщения при условии, что они не кончились
			 */
			for(size_t j = 0; j < count; j++) if((list[j] == noise::token_t::EKEM) || (list[j] == noise::token_t::SKEM)) result++;
		}
		// Выводим число своих знаков KEM
		return result;
	}
	/**
	 * @brief Запись корпуса
	 *
	 */
	typedef struct Record {
		// Объявляем строку
		std::string name;
		// Объявляем поля записи корпуса
		std::vector <uint8_t> prologue, initStatic, respStatic, initEphemeral, respEphemeral, hash;
		// Объявляем список дейтаграмм
		std::vector <std::vector <uint8_t>> initCoins, respCoins;
		// Объявляем список сообщений
		std::vector <std::pair <std::vector <uint8_t>, std::vector <uint8_t>>> messages;
	} record_t;
	/**
	 * @brief Прогон одной записи: обе стороны на зёрнах записи; при freeze шифртексты и хеш заполняются, иначе сличаются
	 *
	 * @return пустая строка либо описание расхождения
	 *
	 */
	static std::string run(record_t & record, const bool freeze) {
		// Объявляем объект Noise
		noise::pattern_t pattern;
		// Объявляем объект Noise
		noise::psk_t psks;
		// Объявляем объект Noise
		noise::suite_t suite;
		// Если узор не разобрался, выводим отказ имени
		if(!noise::parse(span(record.name), pattern, psks, suite)) return "имя не разобрано";
		// Объявляем объект Noise
		noise::handshake_t a, b;
		// Если инициатор не завёлся, выводим отказ заведения
		if(!a.start(span(record.name), noise::role_t::INITIATOR, span(record.prologue)) || !b.start(span(record.name), noise::role_t::RESPONDER, span(record.prologue))) return "не заведено";
		if(!record.initStatic.empty() && !a.statics(span(record.initStatic))) return "статика инициатора";
		if(!record.respStatic.empty() && !b.statics(span(record.respStatic))) return "статика отвечающего";
		if(!record.initEphemeral.empty() && !a.ephemeral(span(record.initEphemeral))) return "эфемерида инициатора";
		if(!record.respEphemeral.empty() && !b.ephemeral(span(record.respEphemeral))) return "эфемерида отвечающего";
		// Чужие постоянные ключи по предсообщениям - из открытой части пары собеседника
		uint8_t key[noise::KEM_PUBLIC_MAX];
		// Если узор с предзнанием, ключи сторон установлены
		if(preknown(pattern, false)){ if(!b.self(key) || !a.remote(view_t(key, b.keylength()))) return "ключ отвечающего"; }
		if(preknown(pattern, true)){ if(!a.self(key) || !b.remote(view_t(key, a.keylength()))) return "ключ инициатора"; }
		// Объявляем списки областей байтов
		std::vector <view_t> ic, rc;
		/**
		 * Перебираем: случайности инициатора из записи
		 */
		for(auto & item : record.initCoins) ic.push_back(span(item));
		/**
		 * Перебираем: случайности отвечающего из записи
		 */
		for(auto & item : record.respCoins) rc.push_back(span(item));
		// Проверяем, что данные не пусты
		if(!ic.empty() && !a.coinsDeterministic(ic.data(), ic.size())) return "случайности инициатора";
		if(!rc.empty() && !b.coinsDeterministic(rc.data(), rc.size())) return "случайности отвечающего";
		// Задаём проверочную константу
		const size_t count = noise::messages(pattern);
		// Если сообщений меньше ожидаемого, выводим отказ числа
		if(record.messages.size() < count) return "мало сообщений";
		// Объявляем буферы сообщений
		std::vector <uint8_t> out(noise::MESSAGE), back(noise::MESSAGE);
		/**
		 * Перебираем: сообщения рукопожатия при условии, что они не кончились
		 */
		for(size_t i = 0; i < count; i++){
			// Объявляем объект Noise
			noise::handshake_t & writer = ((i % 2) == 0) ? a : b;
			// Объявляем объект Noise
			noise::handshake_t & reader = ((i % 2) == 0) ? b : a;
			// Задаём ёмкости буферов записи и чтения
			size_t size = out.size(), got = back.size();
			// Если запись сообщения не удалась, выводим отказ записи
			if(!writer.write(span(record.messages[i].first), out.data(), size)) return "запись " + std::to_string(i);
			if(freeze) record.messages[i].second.assign(out.data(), out.data() + size);
			else if((size != record.messages[i].second.size()) || (::memcmp(out.data(), record.messages[i].second.data(), size) != 0)) return "шифртекст " + std::to_string(i);
			// Если чтение сообщения не удалось, выводим отказ чтения
			if(!reader.read(view_t(out.data(), size), back.data(), got)) return "чтение " + std::to_string(i);
			if((got != record.messages[i].first.size()) || ((got > 0) && (::memcmp(back.data(), record.messages[i].first.data(), got) != 0))) return "полезная часть " + std::to_string(i);
		}
		// Если стороны не дошли до конца узора, выводим отказ хода
		if((a.step() != noise::step_t::DONE) || (b.step() != noise::step_t::DONE)) return "не завершено";
		// Объявляем буфер байтов
		uint8_t ha[64], hb[64];
		// Если итоги рукопожатия сторон разошлись, выводим отказ итога
		if(!a.digest(ha) || !b.digest(hb) || (::memcmp(ha, hb, a.length()) != 0)) return "хеши сторон разошлись";
		if(freeze) record.hash.assign(ha, ha + a.length());
		else if((record.hash.size() != a.length()) || (::memcmp(ha, record.hash.data(), a.length()) != 0)) return "хеш рукопожатия";
		// Объявляем объект Noise
		noise::cipher_t a1, a2, b1, b2;
		// Если раскол ключей не удался, выводим отказ раскола
		if(!a.split(a1, a2) || !b.split(b1, b2)) return "раскол";
		/**
		 * Перебираем: прикладные сообщения записи при условии, что они не кончились
		 */
		for(size_t m = count; m < record.messages.size(); m++){
			// Определяем сторону, от которой сообщение
			const bool fromInitiator = ((count == 1) || (((m - count) % 2) == 0));
			// Объявляем объект Noise
			noise::cipher_t & sender = (fromInitiator ? a1 : b2);
			// Объявляем объект Noise
			noise::cipher_t & receiver = (fromInitiator ? b1 : a2);
			// Получаем прикладные данные сообщения
			const std::vector <uint8_t> & payload = record.messages[m].first;
			// Объявляем буфер байтов
			uint8_t tag[noise::TAG];
			// Если зашифрование не удалось, выводим отказ зашифрования
			if(!sender.encrypt(view_t(), span(payload), out.data(), tag)) return "перенос запись " + std::to_string(m);
			// Составляем шифрованное сообщение
			std::vector <uint8_t> cipher(out.data(), out.data() + payload.size());
			// Вставляем байты в список
			cipher.insert(cipher.end(), tag, tag + noise::TAG);
			// Проверяем результат поиска
			if(freeze) record.messages[m].second = cipher;
			else if(cipher != record.messages[m].second) return "перенос шифртекст " + std::to_string(m);
			// Если расшифрование не удалось, выводим отказ расшифрования
			if(!receiver.decrypt(view_t(), view_t(cipher.data(), payload.size()), view_t(cipher.data() + payload.size(), noise::TAG), back.data())) return "перенос чтение " + std::to_string(m);
			if((payload.size() > 0) && (::memcmp(back.data(), payload.data(), payload.size()) != 0)) return "перенос полезная часть " + std::to_string(m);
		}
		// Пустая строка - прогон записи сошёлся
		return std::string();
	}
	/**
	 * @brief Построение записей корпуса на закреплённых зёрнах: 13 узоров × 2 KEM × 2 набора шифра и хеша
	 *
	 */
	static std::vector <record_t> build() {
		// Объявляем список записей
		std::vector <record_t> result;
		// Задаём таблицу шифрований
		const noise::aead_t aeads[] = {noise::aead_t::CHACHAPOLY, noise::aead_t::AESGCM};
		// Задаём таблицу хешей
		const digest::hash_t hashes[] = {digest::hash_t::SHA256, digest::hash_t::BLAKE2B512};
		// Заводим номер проверки
		uint8_t number = 0;
		/**
		 * Перебираем: образцы Noise при условии, что они не кончились
		 */
		for(auto pattern : PATTERNS){
			/**
			 * Перебираем: гибридные KEM при условии, что они не кончились
			 */
			for(auto kem : KEMS){
				/**
				 * Перебираем: варианты наборов шифрования при условии, что их меньше двух
				 */
				for(size_t v = 0; v < 2; v++){
					// Заводим запись корпуса
					record_t record;
					// Объявляем объект Noise
					noise::suite_t suite(kem, aeads[v], hashes[v]);
					// Задаём имя по образцу и набору
					record.name = title(pattern, suite);
					// Задаём байтовое содержимое
					record.prologue = bytes(11, 0x50, 1);
					// Задаём проверочную константу
					const size_t seed = noise::kemlength(kem, noise::part_t::SEED), coins = noise::kemlength(kem, noise::part_t::COINS);
					// Изменяем счётчик
					number++;
					// Задаём байтовое содержимое
					record.initStatic = bytes(seed, static_cast <uint8_t> (0x10 + number), 3);
					// Задаём байтовое содержимое
					record.respStatic = bytes(seed, static_cast <uint8_t> (0x20 + number), 5);
					// Задаём байтовое содержимое
					record.initEphemeral = bytes(seed, static_cast <uint8_t> (0x30 + number), 7);
					// Задаём байтовое содержимое
					record.respEphemeral = bytes(seed, static_cast <uint8_t> (0x40 + number), 11);
					/**
					 * Перебираем: лексемы KEM инициатора при условии, что они не кончились
					 */
					for(size_t i = 0; i < kemtokens(pattern, true); i++) record.initCoins.push_back(bytes(coins, static_cast <uint8_t> (0x60 + number + i), 13));
					/**
					 * Перебираем: лексемы KEM отвечающего при условии, что они не кончились
					 */
					for(size_t i = 0; i < kemtokens(pattern, false); i++) record.respCoins.push_back(bytes(coins, static_cast <uint8_t> (0x80 + number + i), 17));
					// Задаём проверочную константу
					const size_t count = noise::messages(pattern);
					/**
					 * Перебираем: сообщения образца при условии, что они не кончились
					 */
					for(size_t i = 0; i < count; i++) record.messages.push_back(std::make_pair(bytes(i * 5, 0x41, 1), std::vector <uint8_t> ()));
					// Добавляем элемент в список
					record.messages.push_back(std::make_pair(bytes(16, 0x61, 1), std::vector <uint8_t> ()));
					record.messages.push_back(std::make_pair(bytes(9, 0x71, 1), std::vector <uint8_t> ()));
					// Добавляем элемент в список
					result.push_back(record);
				}
			}
		}
		// Выводим построенные записи корпуса
		return result;
	}
	/**
	 * @brief Запись корпуса файлом
	 *
	 */
	static bool save(const std::string & path, const std::vector <record_t> & records) {
		// Открываем файл для записи
		std::ofstream file(path);
		// Проверяем, что файл открыт
		if(!file.is_open()) return false;
		// Записываем заголовок корпуса
		file << "# Корпус PQNoise, порождён кодом A-NTS на закреплённых зёрнах. Доказывает неизменность поведения с дня заморозки,\n# не правильность и не совместимость: чужой реализации PQNoise, с которой его можно сличить, не существует.\n";
		/**
		 * Перебираем: записи корпуса при условии, что они не кончились
		 */
		for(auto & record : records){
			// Записываем имя рукопожатия
			file << "\nhandshake=" << record.name << "\n";
			// Записываем пролог
			file << "prologue=" << hex(record.prologue.data(), record.prologue.size()) << "\n";
			// Записываем зерно статического ключа инициатора
			file << "init_static_seed=" << hex(record.initStatic.data(), record.initStatic.size()) << "\n";
			// Записываем зерно статического ключа отвечающего
			file << "resp_static_seed=" << hex(record.respStatic.data(), record.respStatic.size()) << "\n";
			// Записываем зерно эфемерного ключа инициатора
			file << "init_ephemeral_seed=" << hex(record.initEphemeral.data(), record.initEphemeral.size()) << "\n";
			// Записываем зерно эфемерного ключа отвечающего
			file << "resp_ephemeral_seed=" << hex(record.respEphemeral.data(), record.respEphemeral.size()) << "\n";
			/**
			 * Перебираем: случайности инициатора записи при условии, что они не кончились
			 */
			for(size_t i = 0; i < record.initCoins.size(); i++) file << "init_coins_" << i << "=" << hex(record.initCoins[i].data(), record.initCoins[i].size()) << "\n";
			/**
			 * Перебираем: случайности отвечающего записи при условии, что они не кончились
			 */
			for(size_t i = 0; i < record.respCoins.size(); i++) file << "resp_coins_" << i << "=" << hex(record.respCoins[i].data(), record.respCoins[i].size()) << "\n";
			// Записываем имя рукопожатия
			file << "handshake_hash=" << hex(record.hash.data(), record.hash.size()) << "\n";
			/**
			 * Перебираем: сообщения записи при условии, что они не кончились
			 */
			for(size_t i = 0; i < record.messages.size(); i++){
				// Записываем строку корпуса
				file << "msg_" << i << "_payload=" << hex(record.messages[i].first.data(), record.messages[i].first.size()) << "\n";
				// Записываем строку корпуса
				file << "msg_" << i << "_ciphertext=" << hex(record.messages[i].second.data(), record.messages[i].second.size()) << "\n";
			}
		}
		// Возвращаем признак успеха
		return true;
	}
	/**
	 * @brief Чтение корпуса файлом
	 *
	 */
	static std::vector <record_t> load(const std::string & path) {
		// Объявляем список записей
		std::vector <record_t> result;
		// Открываем файл набора
		std::ifstream file(path);
		// Проверяем, что файл открыт
		if(!file.is_open()) return result;
		// Заводим запись корпуса
		record_t record;
		// Заводим признак открытой записи
		bool open = false;
		// Объявляем строку
		std::string line;
		// Объявляем лямбда-функцию
		auto flush = [&]() { if(open) result.push_back(record); record = record_t(); open = false; };
		/**
		 * Перебираем: строки файла корпуса при условии, что они читаются
		 */
		while(std::getline(file, line)){
			// Проверяем, что данные не пусты
			if(line.empty() || (line[0] == '#')){ if(line.empty()) flush(); continue; }
			// Задаём проверочную константу
			const size_t eq = line.find('=');
			// Проверяем результат поиска
			if(eq == std::string::npos) continue;
			// Задаём строковую константу
			const std::string key = line.substr(0, eq), value = line.substr(eq + 1);
			// Отмечаем открытие записи
			open = true;
			// Если ключ handshake, запоминаем имя записи
			if(key == "handshake") record.name = value;
			else if(key == "prologue") record.prologue = unhex(value);
			else if(key == "init_static_seed") record.initStatic = unhex(value);
			else if(key == "resp_static_seed") record.respStatic = unhex(value);
			else if(key == "init_ephemeral_seed") record.initEphemeral = unhex(value);
			else if(key == "resp_ephemeral_seed") record.respEphemeral = unhex(value);
			else if(key == "handshake_hash") record.hash = unhex(value);
			else if(key.compare(0, 11, "init_coins_") == 0) record.initCoins.push_back(unhex(value));
			else if(key.compare(0, 11, "resp_coins_") == 0) record.respCoins.push_back(unhex(value));
			else if(key.compare(0, 4, "msg_") == 0){
				// Задаём проверочную константу
				const size_t second = key.find('_', 4);
				// Задаём проверочную константу
				const size_t number = ::strtoul(key.substr(4, second - 4).c_str(), nullptr, 10);
				// Если места под сообщение нет, расширяем перечень
				if(record.messages.size() <= number) record.messages.resize(number + 1);
				if(key.substr(second + 1) == "payload") record.messages[number].first = unhex(value);
				else record.messages[number].second = unhex(value);
			}
		}
		// Сохраняем накопленную запись
		flush();
		// Выводим прочитанные записи корпуса
		return result;
	}
};

/**
 * @brief Отвлечение KEM: длины, составной KEM против раздельного счёта ML-KEM и X25519 на зерне, отказы
 *
 */
TEST(PqnoiseTest, Kem){
	// Проверяем длину части ключа гибридной группы
	EXPECT_EQ(noise::kemlength(noise::kem_t::X25519MLKEM768, noise::part_t::PUBLIC), 1216u);
	EXPECT_EQ(noise::kemlength(noise::kem_t::X25519MLKEM768, noise::part_t::SECRET), 2432u);
	EXPECT_EQ(noise::kemlength(noise::kem_t::X25519MLKEM768, noise::part_t::CIPHERTEXT), 1120u);
	EXPECT_EQ(noise::kemlength(noise::kem_t::X25519MLKEM768, noise::part_t::SHARED), 64u);
	EXPECT_EQ(noise::kemlength(noise::kem_t::X25519MLKEM768, noise::part_t::SEED), 96u);
	EXPECT_EQ(noise::kemlength(noise::kem_t::X25519MLKEM768, noise::part_t::COINS), 64u);
	EXPECT_EQ(noise::kemlength(noise::kem_t::MLKEM768, noise::part_t::PUBLIC), 1184u);
	EXPECT_EQ(noise::kemlength(noise::kem_t::MLKEM768, noise::part_t::SECRET), 2400u);
	EXPECT_EQ(noise::kemlength(noise::kem_t::MLKEM768, noise::part_t::CIPHERTEXT), 1088u);
	EXPECT_EQ(noise::kemlength(noise::kem_t::MLKEM768, noise::part_t::SHARED), 32u);
	EXPECT_EQ(noise::kemlength(noise::kem_t::NONE, noise::part_t::PUBLIC), 0u);
	// Составной: зерно 64 ‖ 32, пара = ML-KEM из 64 и X25519 из 32
	const std::vector <uint8_t> seed = bytes(96, 0x01, 1), coins = bytes(64, 0x90, 1);
	// Объявляем буфер байтов
	uint8_t pk[1216], sk[2432], ek[1184], dk[2400], xpub[32];
	// Проверяем генерацию пары ключей гибридной группы
	ASSERT_TRUE(noise::kemgenerateDeterministic(noise::kem_t::X25519MLKEM768, span(seed), pk, sk));
	ASSERT_TRUE(agreement::generate(agreement::kem_t::MLKEM768, view_t(seed.data(), 64), ek, dk));
	ASSERT_TRUE(agreement::x25519(view_t(seed.data() + 64, 32), xpub));
	// Сравниваем байтовые последовательности
	EXPECT_EQ(::memcmp(pk, ek, 1184), 0);
	EXPECT_EQ(::memcmp(pk + 1184, xpub, 32), 0);
	EXPECT_EQ(::memcmp(sk, dk, 2400), 0);
	EXPECT_EQ(::memcmp(sk + 2400, seed.data() + 64, 32), 0);
	// Объявляем буфер байтов
	uint8_t ct[1120], ss[64], ct2[1088], ss2[32], epub[32], xss[32], back[64];
	// Проверяем инкапсуляцию общего секрета
	ASSERT_TRUE(noise::encapsulateDeterministic(noise::kem_t::X25519MLKEM768, view_t(pk, 1216), span(coins), ct, ss));
	ASSERT_TRUE(agreement::encapsulate(agreement::kem_t::MLKEM768, view_t(ek, 1184), view_t(coins.data(), 32), ct2, ss2));
	ASSERT_TRUE(agreement::x25519(view_t(coins.data() + 32, 32), epub));
	ASSERT_TRUE(agreement::x25519(view_t(coins.data() + 32, 32), view_t(xpub, 32), xss));
	// Сравниваем байтовые последовательности
	EXPECT_EQ(::memcmp(ct, ct2, 1088), 0);
	EXPECT_EQ(::memcmp(ct + 1088, epub, 32), 0);
	EXPECT_EQ(::memcmp(ss, ss2, 32), 0);
	EXPECT_EQ(::memcmp(ss + 32, xss, 32), 0);
	// Проверяем декапсуляцию общего секрета
	ASSERT_TRUE(noise::decapsulate(noise::kem_t::X25519MLKEM768, view_t(sk, 2432), view_t(ct, 1120), back));
	// Сравниваем байтовые последовательности
	EXPECT_EQ(::memcmp(back, ss, 64), 0);
	// Повтор случайности даёт тот же шифртекст - потому вызов зовётся Deterministic
	uint8_t again[1120], ssagain[64];
	// Проверяем инкапсуляцию общего секрета
	ASSERT_TRUE(noise::encapsulateDeterministic(noise::kem_t::X25519MLKEM768, view_t(pk, 1216), span(coins), again, ssagain));
	// Сравниваем байтовые последовательности
	EXPECT_EQ(::memcmp(ct, again, 1120), 0);
	// Из энтропии - иной
	ASSERT_TRUE(noise::encapsulate(noise::kem_t::X25519MLKEM768, view_t(pk, 1216), again, ssagain));
	// Проверяем различие байтовых последовательностей
	EXPECT_NE(::memcmp(ct, again, 1120), 0);
	// Проверяем декапсуляцию общего секрета
	ASSERT_TRUE(noise::decapsulate(noise::kem_t::X25519MLKEM768, view_t(sk, 2432), view_t(again, 1120), back));
	// Сравниваем байтовые последовательности
	EXPECT_EQ(::memcmp(back, ssagain, 64), 0);
	// Точка малого порядка в составном - отказ; у чистого ML-KEM подделка - неявное отклонение, не отказ
	::memset(again + 1088, 0, 32);
	// Проверяем декапсуляцию общего секрета
	EXPECT_FALSE(noise::decapsulate(noise::kem_t::X25519MLKEM768, view_t(sk, 2432), view_t(again, 1120), back));
	// Объявляем буфер байтов
	uint8_t forged[1088];
	// Копируем байтовый буфер
	::memcpy(forged, ct2, 1088);
	// Искажаем первый байт
	forged[0] ^= 1;
	// Объявляем буфер байтов
	uint8_t rejected[32];
	// Проверяем декапсуляцию общего секрета
	ASSERT_TRUE(noise::decapsulate(noise::kem_t::MLKEM768, view_t(dk, 2400), view_t(forged, 1088), rejected));
	// Проверяем различие байтовых последовательностей
	EXPECT_NE(::memcmp(rejected, ss2, 32), 0);
	// Отказы длин
	EXPECT_FALSE(noise::kemgenerateDeterministic(noise::kem_t::X25519MLKEM768, view_t(seed.data(), 64), pk, sk));
	EXPECT_FALSE(noise::kemgenerateDeterministic(noise::kem_t::MLKEM768, view_t(seed.data(), 96), pk, sk));
	EXPECT_FALSE(noise::encapsulateDeterministic(noise::kem_t::X25519MLKEM768, view_t(pk, 1184), span(coins), ct, ss));
	EXPECT_FALSE(noise::encapsulateDeterministic(noise::kem_t::X25519MLKEM768, view_t(pk, 1216), view_t(coins.data(), 32), ct, ss));
	EXPECT_FALSE(noise::decapsulate(noise::kem_t::X25519MLKEM768, view_t(sk, 2400), view_t(ct, 1120), back));
	EXPECT_FALSE(noise::decapsulate(noise::kem_t::X25519MLKEM768, view_t(sk, 2432), view_t(ct, 1088), back));
	EXPECT_FALSE(noise::kemgenerate(noise::kem_t::NONE, pk, sk));
}
/**
 * @brief Имена PQNoise: составление и разбор, отказ на psk и на смешении семейств
 *
 */
TEST(PqnoiseTest, Names){
	// Объявляем объект Noise
	noise::pattern_t pattern;
	// Объявляем объект Noise
	noise::psk_t psks;
	// Объявляем объект Noise
	noise::suite_t suite;
	/**
	 * Перебираем: образцы Noise при условии, что они не кончились
	 */
	for(auto p : PATTERNS){
		/**
		 * Перебираем: гибридные KEM при условии, что они не кончились
		 */
		for(auto kem : KEMS){
			// Задаём строковую константу
			const std::string name = title(p, noise::suite_t(kem, noise::aead_t::AESGCM, digest::hash_t::BLAKE2S256));
			// Проверяем пустоту
			ASSERT_FALSE(name.empty());
			// Проверяем составление имени
			EXPECT_EQ(name.compare(0, 8, "PQNoise_"), 0) << name;
			// Проверяем разбор
			ASSERT_TRUE(noise::parse(span(name), pattern, psks, suite)) << name;
			// Узор по имени тот, что задан
			EXPECT_EQ(pattern, p);
			EXPECT_EQ(suite.kem, kem);
			EXPECT_EQ(suite.dh, noise::dh_t::NONE);
			// Проверяем признак постквантового образца
			EXPECT_TRUE(noise::postquantum(pattern));
		}
	}
	// Проверяем разбор
	EXPECT_TRUE(noise::parse(span(std::string("PQNoise_pqXX_X25519MLKEM768_ChaChaPoly_SHA256")), pattern, psks, suite));
	// Узор pqXX узнаётся по имени
	EXPECT_EQ(pattern, noise::pattern_t::PQXX);
	// Проверяем разбор
	EXPECT_FALSE(noise::parse(span(std::string("PQNoise_pqXXpsk0_X25519MLKEM768_ChaChaPoly_SHA256")), pattern, psks, suite));
	EXPECT_FALSE(noise::parse(span(std::string("Noise_pqXX_X25519MLKEM768_ChaChaPoly_SHA256")), pattern, psks, suite));
	EXPECT_FALSE(noise::parse(span(std::string("PQNoise_XX_25519_ChaChaPoly_SHA256")), pattern, psks, suite));
	EXPECT_FALSE(noise::parse(span(std::string("PQNoise_pqXX_25519_ChaChaPoly_SHA256")), pattern, psks, suite));
	EXPECT_FALSE(noise::parse(span(std::string("Noise_XX_X25519MLKEM768_ChaChaPoly_SHA256")), pattern, psks, suite));
	EXPECT_FALSE(noise::postquantum(noise::pattern_t::XX));
	// Узор и набор разных семейств - отказ составления и заведения
	char text[noise::NAME_LIMIT];
	// Задаём ёмкость буфера имени
	size_t size = sizeof(text);
	// Проверяем составление имени
	EXPECT_FALSE(noise::name(noise::pattern_t::PQXX, 0, noise::suite_t(noise::dh_t::X25519, noise::aead_t::AESGCM, digest::hash_t::SHA256), text, size));
	// Длина текста сообщения
	size = sizeof(text);
	// Проверяем составление имени
	EXPECT_FALSE(noise::name(noise::pattern_t::XX, 0, noise::suite_t(noise::kem_t::MLKEM768, noise::aead_t::AESGCM, digest::hash_t::SHA256), text, size));
	// Длина текста сообщения
	size = sizeof(text);
	// Проверяем составление имени
	EXPECT_FALSE(noise::name(noise::pattern_t::PQXX, 0x01, noise::suite_t(noise::kem_t::MLKEM768, noise::aead_t::AESGCM, digest::hash_t::SHA256), text, size));
	// Объявляем объект Noise
	noise::handshake_t h;
	// Проверяем набор шифрования
	EXPECT_FALSE(h.start(noise::pattern_t::PQXX, 0, noise::suite_t(noise::dh_t::X25519, noise::aead_t::AESGCM, digest::hash_t::SHA256), noise::role_t::INITIATOR, view_t()));
	EXPECT_FALSE(h.start(noise::pattern_t::XX, 0, noise::suite_t(noise::kem_t::MLKEM768, noise::aead_t::AESGCM, digest::hash_t::SHA256), noise::role_t::INITIATOR, view_t()));
	/**
	 * Классические знаки не встречаются в pq-узорах и наоборот
	 */
	for(uint8_t i = 1; i <= static_cast <uint8_t> (noise::pattern_t::PQIX); i++){
		// Берём очередной узор
		const noise::pattern_t p = static_cast <noise::pattern_t> (i);
		// Если узор без сообщений, пропускаем
		if(noise::messages(p) == 0) continue;
		/**
		 * Перебираем: сообщения образца при условии, что они не кончились
		 */
		for(size_t m = 0; m < noise::messages(p); m++){
			// Заводим указатель на лексемы сообщения
			const noise::token_t * list = nullptr;
			// Заводим счётчик лексем
			size_t count = 0;
			// Проверяем истинность условия
			ASSERT_TRUE(noise::tokens(p, m, list, count));
			/**
			 * Перебираем: лексемы сообщения при условии, что они не кончились
			 */
			for(size_t j = 0; j < count; j++){
				// Отмечаем кем-лексему
				const bool kemtoken = ((list[j] == noise::token_t::EKEM) || (list[j] == noise::token_t::SKEM));
				// Отмечаем лексему общего значения
				const bool dhtoken = ((list[j] == noise::token_t::EE) || (list[j] == noise::token_t::ES) || (list[j] == noise::token_t::SE) || (list[j] == noise::token_t::SS));
				// Проверяем признак постквантового образца
				EXPECT_EQ(kemtoken, noise::postquantum(p) && kemtoken) << noise::title(p);
				// Проверяем признак постквантового образца
				EXPECT_FALSE(noise::postquantum(p) && dhtoken) << noise::title(p);
				EXPECT_FALSE(!noise::postquantum(p) && kemtoken) << noise::title(p);
			}
		}
	}
}
/**
 * @brief Обе роли своим кодом: тринадцать узоров × два KEM × восемь наборов, полезная часть, хеш, ключ собеседника, перенос
 *
 */
TEST(PqnoiseTest, Roundtrip){
	// Заводим счётчик рукопожатий
	size_t handshakes = 0;
	/**
	 * Перебираем: образцы Noise при условии, что они не кончились
	 */
	for(auto pattern : PATTERNS){
		/**
		 * Перебираем: гибридные KEM при условии, что они не кончились
		 */
		for(auto kem : KEMS){
			/**
			 * Перебираем: шифрования при условии, что они не кончились
			 */
			for(auto aead : AEADS){
				/**
				 * Перебираем: хеши при условии, что они не кончились
				 */
				for(auto hash : HASHES){
					// Заводим запись корпуса
					record_t record;
					// Задаём имя по образцу и набору
					record.name = title(pattern, noise::suite_t(kem, aead, hash));
					// Проверяем пустоту
					ASSERT_FALSE(record.name.empty());
					// Задаём проверочную константу
					const size_t seed = noise::kemlength(kem, noise::part_t::SEED);
					// Задаём байтовое содержимое
					record.initStatic = bytes(seed, 0x11, 1);
					// Задаём байтовое содержимое
					record.respStatic = bytes(seed, 0x22, 1);
					/**
					 * Перебираем: сообщения образца при условии, что они не кончились
					 */
					for(size_t i = 0; i < noise::messages(pattern); i++) record.messages.push_back(std::make_pair(bytes(7, 0x30, 1), std::vector <uint8_t> ()));
					// Добавляем элемент в список
					record.messages.push_back(std::make_pair(bytes(5, 0x40, 1), std::vector <uint8_t> ()));
					record.messages.push_back(std::make_pair(bytes(3, 0x50, 1), std::vector <uint8_t> ()));
					// Эфемериды и случайности из энтропии: заморозка не задана, значит шифртексты не сличаются, а проверяется круг
					const std::string failure = run(record, true);
					// Проверяем пустоту
					EXPECT_TRUE(failure.empty()) << record.name << ": " << failure;
					// Изменяем счётчик
					handshakes++;
				}
			}
		}
	}
	// Число рукопожатий сходится: тринадцать узоров на два KEM на восемь наборов
	EXPECT_EQ(handshakes, 208u);
	// Ключ собеседника узнаётся верно и оба состояния переноса живы; у pqN второе без ключа
	noise::handshake_t a, b;
	// Задаём строковую константу
	const std::string name = "PQNoise_pqXX_X25519MLKEM768_ChaChaPoly_SHA256";
	// Объявляем буфер байтов
	uint8_t sa[2432], pa[1216], sb[2432], pb[1216], out[4096], back[64];
	// Проверяем генерацию пары ключей гибридной группы
	ASSERT_TRUE(noise::kemgenerate(noise::kem_t::X25519MLKEM768, pa, sa));
	ASSERT_TRUE(noise::kemgenerate(noise::kem_t::X25519MLKEM768, pb, sb));
	// Задаём зёрна сторон
	const std::vector <uint8_t> seedA = bytes(96, 0x33, 1), seedB = bytes(96, 0x44, 1);
	// Проверяем составление имени
	ASSERT_TRUE(a.start(span(name), noise::role_t::INITIATOR, view_t()));
	ASSERT_TRUE(b.start(span(name), noise::role_t::RESPONDER, view_t()));
	ASSERT_TRUE(a.statics(span(seedA)));
	ASSERT_TRUE(b.statics(span(seedB)));
	// Длина ключа собеседника сходится: доля кривой плюс ключ постквантового KEM
	EXPECT_EQ(a.keylength(), 1216u);
	/**
	 * Перебираем: шаги рукопожатия при условии, что стороны его не завершили
	 */
	while((a.step() != noise::step_t::DONE) || (b.step() != noise::step_t::DONE)){
		// Объявляем объект Noise
		noise::handshake_t & writer = (a.step() == noise::step_t::WRITE) ? a : b;
		// Объявляем объект Noise
		noise::handshake_t & reader = (a.step() == noise::step_t::WRITE) ? b : a;
		// Задаём ёмкости буферов записи и чтения
		size_t size = sizeof(out), got = sizeof(back);
		// Проверяем истинность условия
		ASSERT_TRUE(writer.write(view_t(), out, size));
		ASSERT_TRUE(reader.read(view_t(out, size), back, got));
	}
	// Объявляем буфер байтов
	uint8_t learned[1216], own[1216];
	// Проверяем получение ключа собеседника
	ASSERT_TRUE(a.peer(learned));
	ASSERT_TRUE(b.self(own));
	// Сравниваем байтовые последовательности
	EXPECT_EQ(::memcmp(learned, own, 1216), 0);
	// Проверяем получение ключа собеседника
	ASSERT_TRUE(b.peer(learned));
	ASSERT_TRUE(a.self(own));
	// Сравниваем байтовые последовательности
	EXPECT_EQ(::memcmp(learned, own, 1216), 0);
	// Объявляем объект Noise
	noise::cipher_t n1, n2;
	// Объявляем объект Noise
	noise::handshake_t c, d;
	// Проверяем истинность условия
	ASSERT_TRUE(c.start(span(std::string("PQNoise_pqN_MLKEM768_AESGCM_SHA512")), noise::role_t::INITIATOR, view_t()));
	ASSERT_TRUE(d.start(span(std::string("PQNoise_pqN_MLKEM768_AESGCM_SHA512")), noise::role_t::RESPONDER, view_t()));
	ASSERT_TRUE(d.statics(view_t(seedB.data(), 64)));
	ASSERT_TRUE(d.self(own));
	ASSERT_TRUE(c.remote(view_t(own, 1184)));
	// Задаём ёмкости буферов записи и чтения
	size_t size = sizeof(out), got = sizeof(back);
	// Проверяем истинность условия
	ASSERT_TRUE(c.write(span(std::string("sealed")), out, size));
	// Запись растёт на ключ KEM, нагрузку и метку
	EXPECT_EQ(size, 1088u + 6u + noise::TAG);
	// Проверяем истинность условия
	ASSERT_TRUE(d.read(view_t(out, size), back, got));
	// Нагрузка вскрыта без остатка
	EXPECT_EQ(got, 6u);
	// Проверяем раскол шифрованной связи
	ASSERT_TRUE(c.split(n1, n2));
	// Проверяем истинность условия
	EXPECT_TRUE(n1.has());
	// Проверяем ложность условия
	EXPECT_FALSE(n2.has());
}
/**
 * @brief Предельные длины сообщений, посчитанные заранее: pqXX и pqIK на обоих KEM; полезная часть до предела проходит, сверх - отказ
 *
 */
TEST(PqnoiseTest, Limits){
	// Накладные расходы сообщений pqXX и pqIK при составном (ct 1120, pk 1216) и чистом (1088, 1184) KEM
	const size_t composite[4] = {1216, 1120 + 1216 + 16 + 16, 1120 + 16 + 1216 + 16 + 16, 1120 + 16 + 16};
	// Задаём проверочную константу
	const size_t pure[4] = {1184, 1088 + 1184 + 16 + 16, 1088 + 16 + 1184 + 16 + 16, 1088 + 16 + 16};
	// Задаём проверочную константу
	const size_t ikComposite[2] = {1120 + 1216 + 1216 + 16 + 16, 1120 + 1120 + 16 + 16};
	// Задаём проверочную константу
	const size_t ikPure[2] = {1088 + 1184 + 1184 + 16 + 16, 1088 + 1088 + 16 + 16};
	/**
	 * Перебираем: гибридные KEM при условии, что они не кончились
	 */
	for(auto kem : KEMS){
		// Отмечаем гибридный KEM
		const bool comp = (kem == noise::kem_t::X25519MLKEM768);
		// Задаём проверочную константу
		const size_t seed = noise::kemlength(kem, noise::part_t::SEED);
		// Задаём зёрна сторон
		const std::vector <uint8_t> seedA = bytes(seed, 0x01, 1), seedB = bytes(seed, 0x02, 1);
		// Объявляем буферы сообщений
		std::vector <uint8_t> out(noise::MESSAGE + 64), back(noise::MESSAGE);
		// pqXX: пустая полезная часть даёт ровно накладные расходы
		{
			// Объявляем объект Noise
			noise::handshake_t a, b;
			// Задаём строковую константу
			const std::string name = title(noise::pattern_t::PQXX, noise::suite_t(kem, noise::aead_t::CHACHAPOLY, digest::hash_t::SHA256));
			// Проверяем составление имени
			ASSERT_TRUE(a.start(span(name), noise::role_t::INITIATOR, view_t()));
			ASSERT_TRUE(b.start(span(name), noise::role_t::RESPONDER, view_t()));
			ASSERT_TRUE(a.statics(span(seedA)));
			ASSERT_TRUE(b.statics(span(seedB)));
			/**
			 * Перебираем: сообщения рукопожатия при условии, что их меньше четырёх
			 */
			for(size_t i = 0; i < 4; i++){
				// Объявляем объект Noise
				noise::handshake_t & writer = ((i % 2) == 0) ? a : b;
				// Объявляем объект Noise
				noise::handshake_t & reader = ((i % 2) == 0) ? b : a;
				// Задаём ёмкости буферов записи и чтения
				size_t size = out.size(), got = back.size();
				// Проверяем истинность условия
				ASSERT_TRUE(writer.write(view_t(), out.data(), size));
				// Проверяем составление имени
				EXPECT_EQ(size, comp ? composite[i] : pure[i]) << name << " сообщение " << i;
				// Проверяем истинность условия
				ASSERT_TRUE(reader.read(view_t(out.data(), size), back.data(), got));
				// У отвечающего без ключа собеседника чтение пусто
				EXPECT_EQ(got, 0u);
			}
		}
		// pqIK
		{
			// Объявляем объект Noise
			noise::handshake_t a, b;
			// Задаём строковую константу
			const std::string name = title(noise::pattern_t::PQIK, noise::suite_t(kem, noise::aead_t::AESGCM, digest::hash_t::BLAKE2S256));
			// Проверяем составление имени
			ASSERT_TRUE(a.start(span(name), noise::role_t::INITIATOR, view_t()));
			ASSERT_TRUE(b.start(span(name), noise::role_t::RESPONDER, view_t()));
			ASSERT_TRUE(a.statics(span(seedA)));
			ASSERT_TRUE(b.statics(span(seedB)));
			// Объявляем буфер байтов
			uint8_t key[noise::KEM_PUBLIC_MAX];
			// Проверяем установку собственного ключа
			ASSERT_TRUE(b.self(key));
			ASSERT_TRUE(a.remote(view_t(key, b.keylength())));
			/**
			 * Перебираем: сообщения рукопожатия при условии, что их меньше двух
			 */
			for(size_t i = 0; i < 2; i++){
				// Объявляем объект Noise
				noise::handshake_t & writer = ((i % 2) == 0) ? a : b;
				// Объявляем объект Noise
				noise::handshake_t & reader = ((i % 2) == 0) ? b : a;
				// Задаём ёмкости буферов записи и чтения
				size_t size = out.size(), got = back.size();
				// Проверяем истинность условия
				ASSERT_TRUE(writer.write(view_t(), out.data(), size));
				// Проверяем составление имени
				EXPECT_EQ(size, comp ? ikComposite[i] : ikPure[i]) << name << " сообщение " << i;
				// Проверяем истинность условия
				ASSERT_TRUE(reader.read(view_t(out.data(), size), back.data(), got));
			}
		}
		/**
		 * Второе сообщение pqXX: полезная часть до 65535 - накладные проходит, +1 - отказ
		 */
		for(size_t extra = 0; extra < 2; extra++){
			// Объявляем объект Noise
			noise::handshake_t a, b;
			// Задаём строковую константу
			const std::string name = title(noise::pattern_t::PQXX, noise::suite_t(kem, noise::aead_t::CHACHAPOLY, digest::hash_t::SHA256));
			// Проверяем составление имени
			ASSERT_TRUE(a.start(span(name), noise::role_t::INITIATOR, view_t()));
			ASSERT_TRUE(b.start(span(name), noise::role_t::RESPONDER, view_t()));
			ASSERT_TRUE(a.statics(span(seedA)));
			ASSERT_TRUE(b.statics(span(seedB)));
			// Задаём ёмкости буферов записи и чтения
			size_t size = out.size(), got = back.size();
			// Проверяем истинность условия
			ASSERT_TRUE(a.write(view_t(), out.data(), size));
			ASSERT_TRUE(b.read(view_t(out.data(), size), back.data(), got));
			// Задаём проверочную константу
			const size_t limit = (noise::MESSAGE - (comp ? composite[1] : pure[1]));
			// Задаём прикладные данные
			std::vector <uint8_t> payload(limit + extra, 0x7A);
			// Длина исходящего буфера
			size = out.size();
			// Проверяем признак превышения размера сообщения
			if(extra == 0){
				// Проверяем составление имени
				ASSERT_TRUE(b.write(span(payload), out.data(), size)) << name;
				// Размер сообщения не превышен
				EXPECT_EQ(size, noise::MESSAGE);
				// Длина входящего буфера
				got = back.size();
				// Проверяем истинность условия
				ASSERT_TRUE(a.read(view_t(out.data(), size), back.data(), got));
				// Принято ровно столько, сколько вмещается
				EXPECT_EQ(got, limit);
			} else {
				// Проверяем составление имени
				EXPECT_FALSE(b.write(span(payload), out.data(), size)) << name;
			}
		}
	}
}
/**
 * @brief Свой замороженный корпус: 52 записи, сличение байт в байт; ANTS_NOISE_FREEZE пересоздаёт его вслух и проваливает проверку
 *
 */
TEST(PqnoiseTest, Corpus){
	// Задаём пути файлов набора
	const std::string path = (std::string(CORPUS) + "/noise/pqnoise.txt");
	// Ищем переменную заморозки корпуса
	const char * freeze = ::getenv("ANTS_NOISE_FREEZE");
	// Проверяем, что задана заморозка корпуса
	if(freeze != nullptr){
		// Составляем записи корпуса
		std::vector <record_t> records = build();
		/**
		 * Перебираем: записи корпуса при условии, что они не кончились
		 */
		for(auto & record : records){
			// Задаём строковую константу
			const std::string failure = run(record, true);
			// Проверяем пустоту
			ASSERT_TRUE(failure.empty()) << record.name << ": " << failure;
		}
		// Проверяем истинность условия
		ASSERT_TRUE(save(freeze, records));
		// Проваливаем проверку вслух
		FAIL() << "корпус пересоздан в " << freeze << " (" << records.size() << " записей): заморозка вслух, проверка нарочно провалена";
	}
	// Загружаем записи корпуса
	std::vector <record_t> records = load(path);
	// Проверяем размер
	ASSERT_EQ(records.size(), 52u);
	// Заводим счётчик взятых записей
	size_t taken = 0;
	/**
	 * Перебираем: записи корпуса при условии, что они не кончились
	 */
	for(auto & record : records){
		// Задаём строковую константу
		const std::string failure = run(record, false);
		// Проверяем пустоту
		EXPECT_TRUE(failure.empty()) << record.name << ": " << failure;
		// Проверяем, что данные не пусты
		if(failure.empty()) taken++;
	}
	// Печатаем итог взятия корпуса
	std::printf("pqnoise: взято %zu из %zu (корпус наш: доказывает неизменность с дня заморозки, не правильность)\n", taken, records.size());
	// Корпус взят целиком
	EXPECT_EQ(taken, 52u);
	// Корпус обязан совпадать с построенным по тем же зёрнам - иначе заморозка устарела
	std::vector <record_t> fresh = build();
	// Проверяем размер
	ASSERT_EQ(fresh.size(), records.size());
	/**
	 * Перебираем: свежие записи при условии, что они не кончились
	 */
	for(size_t i = 0; i < fresh.size(); i++){
		// Проверяем составление имени
		EXPECT_EQ(fresh[i].name, records[i].name);
		EXPECT_EQ(fresh[i].initStatic, records[i].initStatic) << records[i].name;
		EXPECT_EQ(fresh[i].initCoins, records[i].initCoins) << records[i].name;
		EXPECT_EQ(fresh[i].respCoins, records[i].respCoins) << records[i].name;
	}
}
/**
 * @brief Отказы PQNoise: зерно чужой длины, ключ собеседника чужой длины, случайности не по числу, порча шифртекста, чужая статика, паёк выделений
 *
 */
TEST(PqnoiseTest, Refusals){
	// Задаём строковую константу
	const std::string name = "PQNoise_pqXX_X25519MLKEM768_AESGCM_SHA512";
	// Задаём зёрна сторон и случайности
	const std::vector <uint8_t> seedA = bytes(96, 0x05, 1), seedB = bytes(96, 0x06, 1), coins = bytes(64, 0x07, 1);
	// Объявляем буфер байтов
	uint8_t out[4096], back[64];
	{
		// Объявляем объект Noise
		noise::handshake_t a;
		// Проверяем составление имени
		ASSERT_TRUE(a.start(span(name), noise::role_t::INITIATOR, view_t()));
		// Проверяем установку статических ключей
		EXPECT_FALSE(a.statics(view_t(seedA.data(), 64)));
		EXPECT_FALSE(a.statics(view_t(seedA.data(), 32)));
		EXPECT_FALSE(a.ephemeral(view_t(seedA.data(), 95)));
		EXPECT_FALSE(a.remote(view_t(out, 32)));
		EXPECT_FALSE(a.remote(view_t(out, 1184)));
		// Задаём область случайностей
		view_t coin(coins.data(), 32);
		// Проверяем установку случайностей
		EXPECT_FALSE(a.coinsDeterministic(&coin, 1));
		// Задаём область корректных случайностей
		view_t good(coins.data(), 64);
		// Проверяем установку случайностей
		EXPECT_TRUE(a.coinsDeterministic(&good, 1));
		// Задаём область общего секрета
		view_t psk(seedA.data(), 32);
		// Проверяем установку общих секретов
		EXPECT_FALSE(a.psks(&psk, 1));
		// Случайности заданы и исчерпаны - отказ, не энтропия: у pqXX инициатору нужна одна (skem), задана одна, второй круг с одной у отвечающего (ekem, skem - нужны две)
		noise::handshake_t x, y;
		// Проверяем составление имени
		ASSERT_TRUE(x.start(span(name), noise::role_t::INITIATOR, view_t()));
		ASSERT_TRUE(y.start(span(name), noise::role_t::RESPONDER, view_t()));
		ASSERT_TRUE(x.statics(span(seedA)));
		ASSERT_TRUE(y.statics(span(seedB)));
		ASSERT_TRUE(y.coinsDeterministic(&good, 1));
		// Задаём ёмкости буферов записи и чтения
		size_t size = sizeof(out), got = sizeof(back);
		// Проверяем истинность условия
		ASSERT_TRUE(x.write(view_t(), out, size));
		ASSERT_TRUE(y.read(view_t(out, size), back, got));
		// Длина исходящего буфера
		size = sizeof(out);
		// Проверяем истинность условия
		ASSERT_TRUE(y.write(view_t(), out, size));
		// Длина входящего буфера
		got = sizeof(back);
		// Проверяем истинность условия
		ASSERT_TRUE(x.read(view_t(out, size), back, got));
		// Длина исходящего буфера
		size = sizeof(out);
		// Проверяем истинность условия
		ASSERT_TRUE(x.write(view_t(), out, size));
		// Длина входящего буфера
		got = sizeof(back);
		// Проверяем истинность условия
		ASSERT_TRUE(y.read(view_t(out, size), back, got));
		// Длина исходящего буфера
		size = sizeof(out);
		// Проверяем ложность условия
		EXPECT_FALSE(y.write(view_t(), out, size));
		// Проверяем шаг рукопожатия
		EXPECT_EQ(y.step(), noise::step_t::NONE);
		// Классика случайностей KEM не принимает
		noise::handshake_t c;
		// Проверяем истинность условия
		ASSERT_TRUE(c.start(span(std::string("Noise_XX_25519_ChaChaPoly_SHA256")), noise::role_t::INITIATOR, view_t()));
		// Проверяем установку случайностей
		EXPECT_FALSE(c.coinsDeterministic(&good, 1));
	}
	// Порча шифртекста skem: расшифровка не сходится, состояние неисправно
	{
		// Объявляем объект Noise
		noise::handshake_t a, b;
		// Проверяем составление имени
		ASSERT_TRUE(a.start(span(name), noise::role_t::INITIATOR, view_t()));
		ASSERT_TRUE(b.start(span(name), noise::role_t::RESPONDER, view_t()));
		ASSERT_TRUE(a.statics(span(seedA)));
		ASSERT_TRUE(b.statics(span(seedB)));
		// Задаём ёмкости буферов записи и чтения
		size_t size = sizeof(out), got = sizeof(back);
		// Проверяем истинность условия
		ASSERT_TRUE(a.write(view_t(), out, size));
		ASSERT_TRUE(b.read(view_t(out, size), back, got));
		// Длины буферов обеих сторон
		size = sizeof(out); got = sizeof(back);
		// Проверяем истинность условия
		ASSERT_TRUE(b.write(view_t(), out, size));
		// Порча шифртекста ekem (в открытом виде): секрет расходится, метка полезной части не сходится
		out[10] ^= 1;
		// Проверяем ложность условия
		EXPECT_FALSE(a.read(view_t(out, size), back, got));
		// Проверяем шаг рукопожатия
		EXPECT_EQ(a.step(), noise::step_t::NONE);
	}
	// Чужая статика отвечающего у pqIK: skem инициатора распаковывается не тем ключом, метка не сходится
	{
		// Объявляем объект Noise
		noise::handshake_t a, b;
		// Задаём строковую константу
		const std::string ik = "PQNoise_pqIK_MLKEM768_ChaChaPoly_BLAKE2s";
		// Проверяем истинность условия
		ASSERT_TRUE(a.start(span(ik), noise::role_t::INITIATOR, view_t()));
		ASSERT_TRUE(b.start(span(ik), noise::role_t::RESPONDER, view_t()));
		ASSERT_TRUE(a.statics(view_t(seedA.data(), 64)));
		ASSERT_TRUE(b.statics(view_t(seedB.data(), 64)));
		// Объявляем буфер байтов
		uint8_t other[1184], sk[2400];
		// Проверяем генерацию пары ключей гибридной группы
		ASSERT_TRUE(noise::kemgenerate(noise::kem_t::MLKEM768, other, sk));
		ASSERT_TRUE(a.remote(view_t(other, 1184)));
		// Задаём ёмкости буферов записи и чтения
		size_t size = sizeof(out), got = sizeof(back);
		// Проверяем истинность условия
		ASSERT_TRUE(a.write(view_t(), out, size));
		// Проверяем ложность условия
		EXPECT_FALSE(b.read(view_t(out, size), back, got));
		// Проверяем шаг рукопожатия
		EXPECT_EQ(b.step(), noise::step_t::NONE);
		// Без своего постоянного ключа отвечающий pqIK не заведётся: чужой skem нечем распаковать
		noise::handshake_t d;
		// Проверяем истинность условия
		ASSERT_TRUE(d.start(span(ik), noise::role_t::RESPONDER, view_t()));
		// Длина входящего буфера
		got = sizeof(back);
		// Проверяем ложность условия
		EXPECT_FALSE(d.read(view_t(out, size), back, got));
	}
	// Паёк выделений: полный круг pqXX без единого выделения
	{
		// Объявляем объект Noise
		noise::handshake_t a, b;
		// Объявляем объект Noise
		noise::cipher_t a1, a2, b1, b2;
		// Задаём таблицу проверочных констант
		static const uint8_t NAME[] = "PQNoise_pqXX_X25519MLKEM768_ChaChaPoly_BLAKE2s";
		// Заводим признак общего успеха
		bool status = true;
		// Объявляем буфер байтов
		uint8_t tag[16];
		{
			// Ограничиваем доступную память
			starve::ration_t ration(0);
			// Заводим инициатора по имени узора
			status = (a.start(view_t(NAME, sizeof(NAME) - 1), noise::role_t::INITIATOR, view_t()) && b.start(view_t(NAME, sizeof(NAME) - 1), noise::role_t::RESPONDER, view_t()));
			// Устанавливаем статические ключи сторон из зёрен
			status = (status && a.statics(view_t(seedA.data(), 96)) && b.statics(view_t(seedB.data(), 96)));
			/**
			 * Перебираем: сообщения рукопожатия при условии, что шаги идут без отказа
			 */
			for(size_t i = 0; status && (i < 4); i++){
				// Объявляем объект Noise
				noise::handshake_t & writer = ((i % 2) == 0) ? a : b;
				// Объявляем объект Noise
				noise::handshake_t & reader = ((i % 2) == 0) ? b : a;
				// Задаём ёмкости буферов записи и чтения
				size_t size = sizeof(out), got = sizeof(back);
				// Прогоняем сообщение узора между сторонами
				status = (writer.write(view_t(), out, size) && reader.read(view_t(out, size), back, got));
			}
			// Раскалываем ключи связи сторон
			status = (status && a.split(a1, a2) && b.split(b1, b2));
			// Зашифровываем пробный текст первым ключом
			status = (status && a1.encrypt(view_t(), view_t(seedA.data(), 8), out, tag) && b1.decrypt(view_t(), view_t(out, 8), view_t(tag, 16), back));
			// Останавливаем замер расхода выделений
			ration.stop();
		}
		// Проверяем истинность условия
		EXPECT_TRUE(status);
		// Сравниваем байтовые последовательности
		EXPECT_EQ(::memcmp(back, seedA.data(), 8), 0);
	}
}
