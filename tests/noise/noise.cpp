/**
 * @file noise.cpp
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
 * @brief Проверки каркаса Noise: векторы flynn/noise и Cacophony, ядро, отказы, паёк выделений
 *
 * @details Корпуса лежат в дереве как есть. Два корпуса по-разному ведут направление
 *          транспорта после раскола (установлено опытом): flynn чередует заново с
 *          инициатора и чередует даже у односторонних узоров; Cacophony продолжает чередование
 *          по номеру сообщения, а у односторонних шлёт всё от инициатора. Это наблюдение о чужих
 *          наборах, а не о нашем коде: третий корпус начинать с него. Сообщения flynn обратного
 *          хода у односторонних узоров шифрованы вторым состоянием раскола; описание не запрещает
 *          его породить, оно говорит, что у односторонних оно не применяется, - flynn здесь не
 *          ошибается, это расхождение договора. У нас второе состояние без ключа, потому такие
 *          сообщения пропускаются вслух со счётом, а прямой ход сличается как у всех
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <map>
#include <string>
#include <vector>
#include <fstream>
#include <cstring>
#include <cstdint>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <starve.hpp>
#include <noise/noise.hpp>
#include <noise/cipher.hpp>
#include <noise/symmetric.hpp>
#include <noise/handshake.hpp>
#include <digest/hash.hpp>
#include <digest/hmac.hpp>
#include <cipher/chachapoly.hpp>

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
	 * @brief Запись вектора
	 *
	 */
	typedef struct Record {
		// Номер в корпусе от единицы
		size_t index;
		// Имя протокола
		std::string name;
		// Прологи сторон
		std::vector <uint8_t> initPrologue, respPrologue;
		// Временные ключи сторон
		std::vector <uint8_t> initEphemeral, respEphemeral;
		// Постоянные ключи сторон
		std::vector <uint8_t> initStatic, respStatic;
		// Заранее известные чужие постоянные ключи
		std::vector <uint8_t> initRemote, respRemote;
		// Заранее разделённые ключи
		std::vector <std::vector <uint8_t>> psks;
		// Хеш рукопожатия
		std::vector <uint8_t> hash;
		// Сообщения: полезная часть и шифротекст
		std::vector <std::pair <std::vector <uint8_t>, std::vector <uint8_t>>> messages;
	} record_t;
	/**
	 * @brief Счёт прогона корпуса
	 *
	 */
	typedef struct Tally {
		// Взято, пропущено по 448, пропущено сообщений обратного хода у односторонних, сличено прямого хода у односторонних
		size_t taken, skipped448, skippedOneWay, forwardOneWay;
		// Сверено хешей
		size_t hashes;
		// Имена расхождений
		std::vector <std::string> failures;
		Tally() : taken(0), skipped448(0), skippedOneWay(0), forwardOneWay(0), hashes(0) {}
	} tally_t;
	/**
	 * @brief Метод разбора шестнадцатеричной строки
	 *
	 * @param text строка
	 *
	 * @return     байты
	 *
	 */
	static std::vector <uint8_t> unhex(const std::string & text) {
		std::vector <uint8_t> result;
		for(size_t i = 0; (i + 1) < text.size(); i += 2){
			const std::string pair = text.substr(i, 2);
			result.push_back(static_cast <uint8_t> (::strtoul(pair.c_str(), nullptr, 16)));
		}
		return result;
	}
	/**
	 * @brief Метод получения области байтов вектора
	 *
	 * @param data вектор
	 *
	 * @return     область
	 *
	 */
	static view_t span(const std::vector <uint8_t> & data) {
		return view_t(data.empty() ? nullptr : data.data(), data.size());
	}
	/**
	 * @brief Метод получения области байтов строки
	 *
	 * @param text строка
	 *
	 * @return     область
	 *
	 */
	static view_t span(const std::string & text) {
		return view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size());
	}
	/**
	 * @brief Метод чтения корпуса flynn/noise: построчно ключ=значение, записи через пустую строку
	 *
	 * @param path путь к файлу
	 *
	 * @return     записи
	 *
	 */
	static std::vector <record_t> flynn(const std::string & path) {
		std::vector <record_t> result;
		std::ifstream file(path);
		if(!file.is_open()) return result;
		record_t record;
		std::string line;
		bool open = false;
		auto flush = [&]() {
			if(open){
				record.index = (result.size() + 1);
				result.push_back(record);
			}
			record = record_t();
			open = false;
		};
		while(std::getline(file, line)){
			if(!line.empty() && (line.back() == '\r')) line.pop_back();
			if(line.empty()){ flush(); continue; }
			const size_t eq = line.find('=');
			if(eq == std::string::npos) continue;
			const std::string key = line.substr(0, eq), value = line.substr(eq + 1);
			open = true;
			if(key == "handshake") record.name = value;
			else if(key == "gen_init_ephemeral") record.initEphemeral = unhex(value);
			else if(key == "gen_resp_ephemeral") record.respEphemeral = unhex(value);
			else if(key == "init_static") record.initStatic = unhex(value);
			else if(key == "resp_static") record.respStatic = unhex(value);
			else if(key == "preshared_key") record.psks.push_back(unhex(value));
			else if(key == "prologue"){ record.initPrologue = unhex(value); record.respPrologue = record.initPrologue; }
			else if((key.compare(0, 4, "msg_") == 0)){
				const size_t second = key.find('_', 4);
				const size_t number = ::strtoul(key.substr(4, second - 4).c_str(), nullptr, 10);
				const std::string kind = key.substr(second + 1);
				if(record.messages.size() <= number) record.messages.resize(number + 1);
				if(kind == "payload") record.messages[number].first = unhex(value);
				else if(kind == "ciphertext") record.messages[number].second = unhex(value);
			}
		}
		flush();
		return result;
	}
	/**
	 * @brief Метод чтения порождённых хешей рукопожатия для корпуса flynn: «номер имя хеш»
	 *
	 * @param path путь к файлу
	 *
	 * @return     хеши по номеру
	 *
	 */
	static std::map <size_t, std::pair <std::string, std::vector <uint8_t>>> hashes(const std::string & path) {
		std::map <size_t, std::pair <std::string, std::vector <uint8_t>>> result;
		std::ifstream file(path);
		std::string line;
		while(std::getline(file, line)){
			const size_t one = line.find(' ');
			if(one == std::string::npos) continue;
			const size_t two = line.find(' ', one + 1);
			if(two == std::string::npos) continue;
			const size_t index = ::strtoul(line.substr(0, one).c_str(), nullptr, 10);
			result[index] = std::make_pair(line.substr(one + 1, two - one - 1), unhex(line.substr(two + 1)));
		}
		return result;
	}
	/**
	 * @brief Свой читатель JSON под корпус Cacophony: строки, массивы, объекты; чисел и экранов нет
	 *
	 */
	typedef class Reader {
		private:
			// Текст и положение
			const std::string & _text;
			size_t _pos;
		private:
			/**
			 * @brief Метод пропуска пробелов
			 */
			void blank() {
				while((this->_pos < this->_text.size()) && ((this->_text[this->_pos] == ' ') || (this->_text[this->_pos] == '\n') || (this->_text[this->_pos] == '\r') || (this->_text[this->_pos] == '\t'))) this->_pos++;
			}
			/**
			 * @brief Метод чтения строки в кавычках
			 *
			 * @param result строка
			 *
			 * @return       признак успешности
			 */
			bool quoted(std::string & result) {
				this->blank();
				if((this->_pos >= this->_text.size()) || (this->_text[this->_pos] != '"')) return false;
				this->_pos++;
				const size_t end = this->_text.find('"', this->_pos);
				if(end == std::string::npos) return false;
				result = this->_text.substr(this->_pos, end - this->_pos);
				if(result.find('\\') != std::string::npos) return false;
				this->_pos = (end + 1);
				return true;
			}
			/**
			 * @brief Метод чтения одного знака
			 *
			 * @param symbol знак
			 *
			 * @return       признак того, что знак прочитан
			 */
			bool expect(const char symbol) {
				this->blank();
				if((this->_pos < this->_text.size()) && (this->_text[this->_pos] == symbol)){ this->_pos++; return true; }
				return false;
			}
			/**
			 * @brief Метод чтения массива строк
			 *
			 * @param result строки
			 *
			 * @return       признак успешности
			 */
			bool strings(std::vector <std::string> & result) {
				if(!this->expect('[')) return false;
				if(this->expect(']')) return true;
				do {
					std::string item;
					if(!this->quoted(item)) return false;
					result.push_back(item);
				} while(this->expect(','));
				return this->expect(']');
			}
			/**
			 * @brief Метод чтения массива объектов из строковых полей
			 *
			 * @param result объекты
			 *
			 * @return       признак успешности
			 */
			bool objects(std::vector <std::map <std::string, std::string>> & result) {
				if(!this->expect('[')) return false;
				if(this->expect(']')) return true;
				do {
					std::map <std::string, std::string> item;
					if(!this->expect('{')) return false;
					if(!this->expect('}')){
						do {
							std::string key, value;
							if(!this->quoted(key) || !this->expect(':') || !this->quoted(value)) return false;
							item[key] = value;
						} while(this->expect(','));
						if(!this->expect('}')) return false;
					}
					result.push_back(item);
				} while(this->expect(','));
				return this->expect(']');
			}
		public:
			/**
			 * @brief Метод чтения корпуса целиком
			 *
			 * @param result записи
			 *
			 * @return       признак успешности
			 */
			bool corpus(std::vector <record_t> & result) {
				std::string key;
				if(!this->expect('{') || !this->quoted(key) || (key != "vectors") || !this->expect(':') || !this->expect('[')) return false;
				do {
					record_t record;
					if(!this->expect('{')) return false;
					do {
						if(!this->quoted(key) || !this->expect(':')) return false;
						if(key == "messages"){
							std::vector <std::map <std::string, std::string>> items;
							if(!this->objects(items)) return false;
							for(auto & item : items) record.messages.push_back(std::make_pair(unhex(item["payload"]), unhex(item["ciphertext"])));
						} else if((key == "init_psks") || (key == "resp_psks")){
							std::vector <std::string> items;
							if(!this->strings(items)) return false;
							if(key == "init_psks"){ record.psks.clear(); for(auto & item : items) record.psks.push_back(unhex(item)); }
						} else {
							std::string value;
							if(!this->quoted(value)) return false;
							if(key == "protocol_name") record.name = value;
							else if(key == "init_prologue") record.initPrologue = unhex(value);
							else if(key == "resp_prologue") record.respPrologue = unhex(value);
							else if(key == "init_ephemeral") record.initEphemeral = unhex(value);
							else if(key == "resp_ephemeral") record.respEphemeral = unhex(value);
							else if(key == "init_static") record.initStatic = unhex(value);
							else if(key == "resp_static") record.respStatic = unhex(value);
							else if(key == "init_remote_static") record.initRemote = unhex(value);
							else if(key == "resp_remote_static") record.respRemote = unhex(value);
							else if(key == "handshake_hash") record.hash = unhex(value);
							else return false;
						}
					} while(this->expect(','));
					if(!this->expect('}')) return false;
					record.index = (result.size() + 1);
					result.push_back(record);
				} while(this->expect(','));
				return (this->expect(']') && this->expect('}'));
			}
			/**
			 * @brief Конструктор
			 *
			 * @param text текст
			 */
			Reader(const std::string & text) : _text(text), _pos(0) {}
	} reader_t;
	/**
	 * @brief Метод чтения корпуса Cacophony
	 *
	 * @param path путь к файлу
	 *
	 * @return     записи
	 *
	 */
	static std::vector <record_t> cacophony(const std::string & path) {
		std::vector <record_t> result;
		std::ifstream file(path);
		if(!file.is_open()) return result;
		std::string text((std::istreambuf_iterator <char> (file)), std::istreambuf_iterator <char> ());
		reader_t reader(text);
		if(!reader.corpus(result)) result.clear();
		return result;
	}
	/**
	 * @brief Метод заведения стороны по записи
	 *
	 * @param record    запись
	 * @param initiator признак инициатора
	 * @param side      состояние
	 * @param derived   признак вывода чужого ключа из чужого постоянного (flynn)
	 *
	 * @return          признак успешности
	 *
	 */
	static bool arm(const record_t & record, const bool initiator, noise::handshake_t & side, const bool derived) {
		if(!side.start(span(record.name), initiator ? noise::role_t::INITIATOR : noise::role_t::RESPONDER, span(initiator ? record.initPrologue : record.respPrologue))) return false;
		const std::vector <uint8_t> & s = (initiator ? record.initStatic : record.respStatic);
		const std::vector <uint8_t> & e = (initiator ? record.initEphemeral : record.respEphemeral);
		if(!s.empty() && !side.statics(span(s))) return false;
		if(!e.empty() && !side.ephemeral(span(e))) return false;
		const std::vector <uint8_t> & given = (initiator ? record.initRemote : record.respRemote);
		if(!given.empty()){
			if(!side.remote(span(given))) return false;
		} else if(derived){
			// Чужой ключ выводится из чужого постоянного, если предсообщение собеседника его несёт
			noise::pattern_t pattern = noise::pattern_t::NONE;
			noise::psk_t psks = 0;
			noise::suite_t suite;
			noise::parse(span(record.name), pattern, psks, suite);
			const noise::token_t * list = nullptr;
			size_t count = 0;
			if(noise::premessage(pattern, !initiator, list, count) && (count > 0)){
				const std::vector <uint8_t> & other = (initiator ? record.respStatic : record.initStatic);
				uint8_t key[noise::KEY];
				if(other.empty() || !noise::derive(noise::dh_t::X25519, span(other), key)) return false;
				if(!side.remote(view_t(key, noise::KEY))) return false;
			}
		}
		if(!record.psks.empty()){
			std::vector <view_t> list;
			for(auto & item : record.psks) list.push_back(span(item));
			if(!side.psks(list.data(), list.size())) return false;
		}
		return true;
	}
	/**
	 * @brief Метод прогона одной записи
	 *
	 * @param record  запись
	 * @param flynn   признак корпуса flynn (иначе Cacophony)
	 * @param tally   счёт
	 * @param given   хеш рукопожатия, порождённый отдельно (flynn), либо пусто
	 *
	 */
	static void run(const record_t & record, const bool flynn, tally_t & tally, const std::vector <uint8_t> & given) {
		noise::pattern_t pattern = noise::pattern_t::NONE;
		noise::psk_t psks = 0;
		noise::suite_t suite;
		if(!noise::parse(span(record.name), pattern, psks, suite)){
			if((pattern != noise::pattern_t::NONE) && (suite.dh == noise::dh_t::NONE)){ tally.skipped448++; return; }
			tally.failures.push_back(record.name + ": имя не разобрано");
			return;
		}
		tally.taken++;
		noise::handshake_t a, b;
		if(!arm(record, true, a, flynn) || !arm(record, false, b, flynn)){ tally.failures.push_back(record.name + ": стороны не заведены"); return; }
		const size_t count = noise::messages(pattern);
		std::vector <uint8_t> out(noise::MESSAGE), back(noise::MESSAGE);
		for(size_t i = 0; i < count; i++){
			if(i >= record.messages.size()){ tally.failures.push_back(record.name + ": мало сообщений"); return; }
			noise::handshake_t & writer = ((i % 2) == 0) ? a : b;
			noise::handshake_t & reader = ((i % 2) == 0) ? b : a;
			size_t size = out.size();
			if(!writer.write(span(record.messages[i].first), out.data(), size)){ tally.failures.push_back(record.name + ": запись " + std::to_string(i)); return; }
			if((size != record.messages[i].second.size()) || (::memcmp(out.data(), record.messages[i].second.data(), size) != 0)){ tally.failures.push_back(record.name + ": шифротекст " + std::to_string(i)); return; }
			size_t got = back.size();
			if(!reader.read(view_t(out.data(), size), back.data(), got)){ tally.failures.push_back(record.name + ": чтение " + std::to_string(i)); return; }
			if((got != record.messages[i].first.size()) || ((got > 0) && (::memcmp(back.data(), record.messages[i].first.data(), got) != 0))){ tally.failures.push_back(record.name + ": полезная часть " + std::to_string(i)); return; }
		}
		if((a.step() != noise::step_t::DONE) || (b.step() != noise::step_t::DONE)){ tally.failures.push_back(record.name + ": не завершено"); return; }
		noise::cipher_t a1, a2, b1, b2;
		if(!a.split(a1, a2) || !b.split(b1, b2)){ tally.failures.push_back(record.name + ": раскол"); return; }
		const std::vector <uint8_t> & expected = (given.empty() ? record.hash : given);
		if(!expected.empty()){
			uint8_t ha[noise::HASH_MAX], hb[noise::HASH_MAX];
			if(!a.digest(ha) || !b.digest(hb) || (a.length() != expected.size()) || (::memcmp(ha, expected.data(), expected.size()) != 0) || (::memcmp(hb, expected.data(), expected.size()) != 0)){ tally.failures.push_back(record.name + ": хеш рукопожатия"); return; }
			tally.hashes++;
		}
		const bool oneWay = (count == 1);
		for(size_t m = count; m < record.messages.size(); m++){
			const size_t k = (m - count);
			bool fromInitiator;
			if(flynn) fromInitiator = ((k % 2) == 0);
			else fromInitiator = (oneWay ? true : ((m % 2) == 0));
			if(oneWay && !fromInitiator){ tally.skippedOneWay++; continue; }
			if(oneWay) tally.forwardOneWay++;
			noise::cipher_t & sender = (fromInitiator ? a1 : b2);
			noise::cipher_t & receiver = (fromInitiator ? b1 : a2);
			const std::vector <uint8_t> & payload = record.messages[m].first;
			const std::vector <uint8_t> & cipher = record.messages[m].second;
			uint8_t tag[noise::TAG];
			if(!sender.encrypt(view_t(), span(payload), out.data(), tag)){ tally.failures.push_back(record.name + ": транспорт запись " + std::to_string(m)); return; }
			if((cipher.size() != (payload.size() + noise::TAG)) || (::memcmp(out.data(), cipher.data(), payload.size()) != 0) || (::memcmp(tag, cipher.data() + payload.size(), noise::TAG) != 0)){ tally.failures.push_back(record.name + ": транспорт шифротекст " + std::to_string(m)); return; }
			if(!receiver.decrypt(view_t(), view_t(cipher.data(), payload.size()), view_t(cipher.data() + payload.size(), noise::TAG), back.data())){ tally.failures.push_back(record.name + ": транспорт чтение " + std::to_string(m)); return; }
			if((payload.size() > 0) && (::memcmp(back.data(), payload.data(), payload.size()) != 0)){ tally.failures.push_back(record.name + ": транспорт полезная часть " + std::to_string(m)); return; }
		}
	}
	/**
	 * @brief Метод полного рукопожатия XX между двумя сторонами со случайными ключами
	 *
	 * @param name имя протокола
	 * @param a    инициатор
	 * @param b    отвечающий
	 *
	 * @return     признак успешности
	 *
	 */
	static bool converse(const char * name, noise::handshake_t & a, noise::handshake_t & b) {
		uint8_t sa[32], pa[32], sb[32], pb[32];
		if(!noise::generate(noise::dh_t::X25519, sa, pa) || !noise::generate(noise::dh_t::X25519, sb, pb)) return false;
		if(!a.start(span(std::string(name)), noise::role_t::INITIATOR, view_t()) || !b.start(span(std::string(name)), noise::role_t::RESPONDER, view_t())) return false;
		if(!a.statics(view_t(sa, 32)) || !b.statics(view_t(sb, 32))) return false;
		uint8_t out[256], back[256];
		while((a.step() != noise::step_t::DONE) || (b.step() != noise::step_t::DONE)){
			noise::handshake_t & writer = (a.step() == noise::step_t::WRITE) ? a : b;
			noise::handshake_t & reader = (a.step() == noise::step_t::WRITE) ? b : a;
			if(writer.step() != noise::step_t::WRITE) return false;
			size_t size = sizeof(out), got = sizeof(back);
			if(!writer.write(view_t(), out, size) || !reader.read(view_t(out, size), back, got) || (got != 0)) return false;
		}
		return true;
	}
	/**
	 * @brief Метод счёта HKDF Noise вручную по §4.3
	 *
	 * @param hash  функция хеширования
	 * @param chain цепной ключ
	 * @param ikm   материал
	 * @param count число выходов
	 * @param out   выходы по длине хеша
	 *
	 */
	static void manual(const digest::hash_t hash, const std::vector <uint8_t> & chain, const std::vector <uint8_t> & ikm, const size_t count, std::vector <std::vector <uint8_t>> & out) {
		const size_t length = digest::length(hash);
		std::vector <uint8_t> temp(length);
		digest::hmac(hash, span(chain), span(ikm), temp.data(), length);
		std::vector <uint8_t> previous;
		for(size_t i = 1; i <= count; i++){
			std::vector <uint8_t> input(previous);
			input.push_back(static_cast <uint8_t> (i));
			std::vector <uint8_t> item(length);
			digest::hmac(hash, span(temp), span(input), item.data(), length);
			out.push_back(item);
			previous = item;
		}
	}
};

/**
 * @brief Векторы flynn/noise v1.1.0: 1920 записей, восемь наборов, узоры с psk во всех положениях
 *
 */
TEST(NoiseTest, Flynn){
	const std::vector <record_t> records = flynn(std::string(CORPUS) + "/noise/flynn.txt");
	ASSERT_EQ(records.size(), 1920u);
	const auto given = hashes(std::string(CORPUS) + "/noise/flynn-hashes.txt");
	ASSERT_EQ(given.size(), 1920u);
	tally_t tally;
	for(auto & record : records){
		auto it = given.find(record.index);
		ASSERT_NE(it, given.end());
		ASSERT_EQ(it->second.first, record.name) << record.index;
		run(record, true, tally, it->second.second);
	}
	for(auto & failure : tally.failures) ADD_FAILURE() << failure;
	std::printf("flynn: взято %zu из %zu, хешей сверено %zu, пропущено по 448: %zu, у односторонних сличено прямого хода: %zu, пропущено обратного: %zu (9 узоров x 8 наборов x 4 блока x 1 сообщение)\n", tally.taken, records.size(), tally.hashes, tally.skipped448, tally.forwardOneWay, tally.skippedOneWay);
	EXPECT_EQ(tally.taken, 1920u);
	EXPECT_EQ(tally.hashes, 1920u);
	EXPECT_EQ(tally.skipped448, 0u);
	EXPECT_EQ(tally.forwardOneWay, 288u);
	EXPECT_EQ(tally.skippedOneWay, 288u);
}
/**
 * @brief Векторы Cacophony: 944 записи, отложенные узоры, половина на 448 пропускается вслух
 *
 */
TEST(NoiseTest, Cacophony){
	const std::vector <record_t> records = cacophony(std::string(CORPUS) + "/noise/cacophony.txt");
	ASSERT_EQ(records.size(), 944u);
	tally_t tally;
	for(auto & record : records) run(record, false, tally, std::vector <uint8_t> ());
	for(auto & failure : tally.failures) ADD_FAILURE() << failure;
	std::printf("cacophony: взято %zu из %zu, хешей сверено %zu, пропущено по 448: %zu, у односторонних сличено прямого хода: %zu, пропущено обратного: %zu\n", tally.taken, records.size(), tally.hashes, tally.skipped448, tally.forwardOneWay, tally.skippedOneWay);
	EXPECT_EQ(tally.taken, 472u);
	EXPECT_EQ(tally.hashes, 472u);
	EXPECT_EQ(tally.skipped448, 472u);
	EXPECT_EQ(tally.skippedOneWay, 0u);
}
/**
 * @brief Имена протоколов: составление и разбор по всем узорам, видоизменения, отказы
 *
 */
TEST(NoiseTest, Names){
	for(uint8_t i = 1; i <= static_cast <uint8_t> (noise::pattern_t::I1X1); i++){
		const noise::pattern_t pattern = static_cast <noise::pattern_t> (i);
		ASSERT_NE(noise::messages(pattern), 0u) << int(i);
		const size_t bits = ((noise::messages(pattern) + 1) < noise::PSKS_MAX) ? (noise::messages(pattern) + 1) : noise::PSKS_MAX;
		const noise::psk_t psks = static_cast <noise::psk_t> ((1u << bits) - 1);
		char text[noise::NAME_LIMIT];
		size_t size = sizeof(text);
		noise::suite_t suite(noise::dh_t::X25519, noise::aead_t::AESGCM, digest::hash_t::BLAKE2B512);
		ASSERT_TRUE(noise::name(pattern, psks, suite, text, size));
		noise::pattern_t back = noise::pattern_t::NONE;
		noise::psk_t backPsks = 0;
		noise::suite_t backSuite;
		ASSERT_TRUE(noise::parse(view_t(reinterpret_cast <const uint8_t *> (text), size), back, backPsks, backSuite)) << text;
		EXPECT_EQ(back, pattern) << text;
		EXPECT_EQ(backPsks, psks) << text;
		EXPECT_EQ(backSuite.aead, noise::aead_t::AESGCM);
		EXPECT_EQ(backSuite.hash, digest::hash_t::BLAKE2B512);
	}
	noise::pattern_t pattern;
	noise::psk_t psks;
	noise::suite_t suite;
	EXPECT_TRUE(noise::parse(span(std::string("Noise_XXpsk0+psk3_25519_ChaChaPoly_SHA512")), pattern, psks, suite));
	EXPECT_EQ(pattern, noise::pattern_t::XX);
	EXPECT_EQ(psks, 0x09);
	EXPECT_EQ(suite.hash, digest::hash_t::SHA512);
	EXPECT_TRUE(noise::parse(span(std::string("Noise_XX1_25519_AESGCM_BLAKE2s")), pattern, psks, suite));
	EXPECT_EQ(pattern, noise::pattern_t::XX1);
	// 448: узор и хеш разобраны, dh пуст, итог отказ
	EXPECT_FALSE(noise::parse(span(std::string("Noise_IK_448_ChaChaPoly_BLAKE2b")), pattern, psks, suite));
	EXPECT_EQ(pattern, noise::pattern_t::IK);
	EXPECT_EQ(suite.dh, noise::dh_t::NONE);
	EXPECT_EQ(suite.hash, digest::hash_t::BLAKE2B512);
	EXPECT_FALSE(noise::parse(span(std::string("Noise_XXpsk3+psk0_25519_ChaChaPoly_SHA256")), pattern, psks, suite));
	EXPECT_FALSE(noise::parse(span(std::string("Noise_XXpsk4_25519_ChaChaPoly_SHA256")), pattern, psks, suite));
	EXPECT_FALSE(noise::parse(span(std::string("Noise_XY_25519_ChaChaPoly_SHA256")), pattern, psks, suite));
	EXPECT_FALSE(noise::parse(span(std::string("Noise_XX_25519_ChaChaPoly_SHA256_")), pattern, psks, suite));
	EXPECT_FALSE(noise::parse(span(std::string("Nois_XX_25519_ChaChaPoly_SHA256")), pattern, psks, suite));
	EXPECT_FALSE(noise::parse(span(std::string("Noise_XX_25519_ChaChaPoly_MD5")), pattern, psks, suite));
	EXPECT_FALSE(noise::parse(view_t(), pattern, psks, suite));
}
/**
 * @brief HKDF Noise на два и три выхода против ручного счёта по §4.3, усечение при длине 64
 *
 */
TEST(NoiseTest, Hkdf){
	const digest::hash_t hashes[] = {digest::hash_t::SHA256, digest::hash_t::SHA512, digest::hash_t::BLAKE2S256, digest::hash_t::BLAKE2B512};
	for(auto hash : hashes){
		const size_t length = digest::length(hash);
		noise::suite_t suite(noise::dh_t::X25519, noise::aead_t::CHACHAPOLY, hash);
		const std::string name = "Noise_NN_25519_ChaChaPoly_X";
		noise::symmetric_t state;
		ASSERT_TRUE(state.start(span(name), suite));
		// Начальные h и ck: имя с нулями (короче хеша)
		std::vector <uint8_t> chain(length, 0);
		::memcpy(chain.data(), name.data(), name.size());
		uint8_t h[noise::HASH_MAX];
		ASSERT_TRUE(state.digest(h));
		EXPECT_EQ(::memcmp(h, chain.data(), length), 0);
		// MixKey
		std::vector <uint8_t> ikm(32, 0x5A);
		std::vector <std::vector <uint8_t>> out;
		manual(hash, chain, ikm, 2, out);
		ASSERT_TRUE(state.key(span(ikm)));
		chain = out[0];
		// Шифрование пустой полезной части сличается с состоянием шифра на усечённом ключе
		noise::cipher_t direct;
		ASSERT_TRUE(direct.start(noise::aead_t::CHACHAPOLY));
		ASSERT_TRUE(direct.key(view_t(out[1].data(), noise::KEY)));
		uint8_t tag[noise::TAG];
		ASSERT_TRUE(direct.encrypt(view_t(h, length), view_t(), nullptr, tag));
		uint8_t sealed[noise::TAG];
		size_t size = sizeof(sealed);
		ASSERT_TRUE(state.seal(view_t(), sealed, size));
		ASSERT_EQ(size, noise::TAG);
		EXPECT_EQ(::memcmp(sealed, tag, noise::TAG), 0) << "hash " << int(hash);
		// MixKeyAndHash: три выхода
		ASSERT_TRUE(state.digest(h));
		std::vector <uint8_t> psk(32, 0xA5);
		out.clear();
		manual(hash, chain, psk, 3, out);
		ASSERT_TRUE(state.blend(span(psk)));
		std::vector <uint8_t> input(h, h + length);
		input.insert(input.end(), out[1].begin(), out[1].end());
		std::vector <uint8_t> expected(length);
		ASSERT_TRUE(digest::hash(hash, span(input), expected.data(), length));
		ASSERT_TRUE(state.digest(h));
		EXPECT_EQ(::memcmp(h, expected.data(), length), 0);
		noise::cipher_t third;
		ASSERT_TRUE(third.start(noise::aead_t::CHACHAPOLY));
		ASSERT_TRUE(third.key(view_t(out[2].data(), noise::KEY)));
		ASSERT_TRUE(third.encrypt(view_t(h, length), view_t(), nullptr, tag));
		size = sizeof(sealed);
		ASSERT_TRUE(state.seal(view_t(), sealed, size));
		EXPECT_EQ(::memcmp(sealed, tag, noise::TAG), 0);
	}
}
/**
 * @brief Счётчик вложений: 2^64-1 запретно на шифровании, расшифровании и установке; при отказе не растёт
 *
 */
TEST(NoiseTest, Nonce){
	const noise::aead_t aeads[] = {noise::aead_t::CHACHAPOLY, noise::aead_t::AESGCM};
	for(auto aead : aeads){
		noise::cipher_t state;
		uint8_t key[32], out[8], back[8], tag[16];
		::memset(key, 7, sizeof(key));
		ASSERT_TRUE(state.start(aead));
		ASSERT_TRUE(state.key(view_t(key, 32)));
		EXPECT_FALSE(state.nonce(UINT64_MAX));
		ASSERT_TRUE(state.nonce(UINT64_MAX - 1));
		ASSERT_TRUE(state.encrypt(view_t(), view_t(key, 8), out, tag));
		EXPECT_EQ(state.nonce(), UINT64_MAX);
		EXPECT_FALSE(state.encrypt(view_t(), view_t(key, 8), out, tag));
		EXPECT_FALSE(state.decrypt(view_t(), view_t(out, 8), view_t(tag, 16), back));
		EXPECT_EQ(state.nonce(), UINT64_MAX);
		EXPECT_FALSE(state.encrypt(UINT64_MAX, view_t(), view_t(key, 8), out, tag));
		EXPECT_FALSE(state.decrypt(UINT64_MAX, view_t(), view_t(out, 8), view_t(tag, 16), back));
		// Явный счётчик равен потоковому и внутренний не трогает
		noise::cipher_t other;
		ASSERT_TRUE(other.start(aead));
		ASSERT_TRUE(other.key(view_t(key, 32)));
		uint8_t out2[8], tag2[16];
		ASSERT_TRUE(other.encrypt(UINT64_MAX - 1, view_t(), view_t(key, 8), out2, tag2));
		EXPECT_EQ(other.nonce(), 0u);
		EXPECT_EQ(::memcmp(out, out2, 8), 0);
		EXPECT_EQ(::memcmp(tag, tag2, 16), 0);
		ASSERT_TRUE(other.decrypt(UINT64_MAX - 1, view_t(), view_t(out2, 8), view_t(tag2, 16), back));
		EXPECT_EQ(::memcmp(back, key, 8), 0);
		// Порча метки: счётчик не растёт, выход обнулён
		tag2[0] ^= 1;
		::memset(back, 0xEE, 8);
		EXPECT_FALSE(other.decrypt(view_t(), view_t(out2, 8), view_t(tag2, 16), back));
		EXPECT_EQ(other.nonce(), 0u);
		uint8_t zeros[8] = {0, 0, 0, 0, 0, 0, 0, 0};
		EXPECT_EQ(::memcmp(back, zeros, 8), 0);
	}
}
/**
 * @brief Перевыработка ключа по определению; счётчик не сбрасывается
 *
 */
TEST(NoiseTest, Rekey){
	noise::cipher_t state;
	uint8_t key[32];
	for(size_t i = 0; i < 32; i++) key[i] = static_cast <uint8_t> (i * 3);
	ASSERT_TRUE(state.start(noise::aead_t::CHACHAPOLY));
	ASSERT_TRUE(state.key(view_t(key, 32)));
	ASSERT_TRUE(state.nonce(5));
	ASSERT_TRUE(state.rekey());
	EXPECT_EQ(state.nonce(), 5u);
	uint8_t fresh[32];
	ASSERT_TRUE(state.key(fresh));
	// Вручную: ENCRYPT(k, 2^64-1, пусто, нули[32]) без метки
	uint8_t nonce[12] = {0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	uint8_t zeros[32], expected[32], tag[16];
	::memset(zeros, 0, 32);
	cipher::chachapoly_t aead;
	ASSERT_TRUE(aead.start(view_t(key, 32), view_t(nonce, 12)));
	ASSERT_TRUE(aead.encrypt(view_t(), view_t(zeros, 32), expected, tag));
	EXPECT_EQ(::memcmp(fresh, expected, 32), 0);
	EXPECT_NE(::memcmp(fresh, key, 32), 0);
}
/**
 * @brief Односторонний узор: второе состояние после раскола без ключа
 *
 */
TEST(NoiseTest, OneWay){
	uint8_t sb[32], pb[32], out[128], back[128];
	ASSERT_TRUE(noise::generate(noise::dh_t::X25519, sb, pb));
	noise::handshake_t a, b;
	ASSERT_TRUE(a.start(noise::pattern_t::N, 0, noise::suite_t(noise::dh_t::X25519, noise::aead_t::AESGCM, digest::hash_t::SHA256), noise::role_t::INITIATOR, view_t()));
	ASSERT_TRUE(b.start(noise::pattern_t::N, 0, noise::suite_t(noise::dh_t::X25519, noise::aead_t::AESGCM, digest::hash_t::SHA256), noise::role_t::RESPONDER, view_t()));
	ASSERT_TRUE(a.remote(view_t(pb, 32)));
	ASSERT_TRUE(b.statics(view_t(sb, 32)));
	size_t size = sizeof(out), got = sizeof(back);
	ASSERT_TRUE(a.write(span(std::string("hello")), out, size));
	ASSERT_TRUE(b.read(view_t(out, size), back, got));
	ASSERT_EQ(got, 5u);
	EXPECT_EQ(::memcmp(back, "hello", 5), 0);
	noise::cipher_t a1, a2, b1, b2;
	ASSERT_TRUE(a.split(a1, a2));
	ASSERT_TRUE(b.split(b1, b2));
	EXPECT_TRUE(a1.has());
	EXPECT_TRUE(b1.has());
	EXPECT_FALSE(a2.has());
	EXPECT_FALSE(b2.has());
	uint8_t tag[16];
	EXPECT_FALSE(a2.encrypt(view_t(), view_t(out, 5), out, tag));
	uint8_t peer[32];
	ASSERT_TRUE(a.peer(peer));
	EXPECT_EQ(::memcmp(peer, pb, 32), 0);
	EXPECT_FALSE(b.peer(peer));
}
/**
 * @brief Предел сообщения 65535 целиком: полезная часть 65519 с ключом проходит, 65520 - отказ
 *
 */
TEST(NoiseTest, Message){
	noise::handshake_t a, b;
	ASSERT_TRUE(converse("Noise_XX_25519_ChaChaPoly_SHA256", a, b));
	noise::cipher_t a1, a2, b1, b2;
	ASSERT_TRUE(a.split(a1, a2));
	ASSERT_TRUE(b.split(b1, b2));
	std::vector <uint8_t> payload(noise::MESSAGE - noise::TAG, 0x42), out(noise::MESSAGE), back(noise::MESSAGE);
	uint8_t tag[16];
	ASSERT_TRUE(a1.encrypt(view_t(), span(payload), out.data(), tag));
	ASSERT_TRUE(b1.decrypt(view_t(), view_t(out.data(), payload.size()), view_t(tag, 16), back.data()));
	payload.push_back(0x42);
	EXPECT_FALSE(a1.encrypt(view_t(), span(payload), out.data(), tag));
	EXPECT_EQ(a1.nonce(), 1u);
	// Первое сообщение NN без ключа: 32 + полезная часть, предел 65503
	noise::handshake_t c;
	ASSERT_TRUE(c.start(span(std::string("Noise_NN_25519_ChaChaPoly_SHA256")), noise::role_t::INITIATOR, view_t()));
	std::vector <uint8_t> plain(noise::MESSAGE - noise::KEY, 1), place(noise::MESSAGE + 64);
	size_t size = place.size();
	ASSERT_TRUE(c.write(span(plain), place.data(), size));
	EXPECT_EQ(size, noise::MESSAGE);
	noise::handshake_t d;
	ASSERT_TRUE(d.start(span(std::string("Noise_NN_25519_ChaChaPoly_SHA256")), noise::role_t::INITIATOR, view_t()));
	plain.push_back(1);
	size = place.size();
	EXPECT_FALSE(d.write(span(plain), place.data(), size));
	// Малая вместимость - отказ
	noise::handshake_t e;
	ASSERT_TRUE(e.start(span(std::string("Noise_NN_25519_ChaChaPoly_SHA256")), noise::role_t::INITIATOR, view_t()));
	size = 31;
	EXPECT_FALSE(e.write(view_t(), place.data(), size));
}
/**
 * @brief Расхождение пролога, ход не в очередь, чужой ключ не сошёлся, порча метки, состояние после отказа
 *
 */
TEST(NoiseTest, Refusals){
	const std::string name = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
	uint8_t sa[32], pa[32], sb[32], pb[32], out[256], back[256];
	ASSERT_TRUE(noise::generate(noise::dh_t::X25519, sa, pa));
	ASSERT_TRUE(noise::generate(noise::dh_t::X25519, sb, pb));
	// Пролог: у сторон разный - первое сообщение открыто и проходит, второе не сходится
	{
		noise::handshake_t a, b;
		ASSERT_TRUE(a.start(span(name), noise::role_t::INITIATOR, span(std::string("one"))));
		ASSERT_TRUE(b.start(span(name), noise::role_t::RESPONDER, span(std::string("two"))));
		ASSERT_TRUE(a.statics(view_t(sa, 32)));
		ASSERT_TRUE(b.statics(view_t(sb, 32)));
		size_t size = sizeof(out), got = sizeof(back);
		ASSERT_TRUE(a.write(view_t(), out, size));
		ASSERT_TRUE(b.read(view_t(out, size), back, got));
		size = sizeof(out); got = sizeof(back);
		ASSERT_TRUE(b.write(view_t(), out, size));
		EXPECT_FALSE(a.read(view_t(out, size), back, got));
		EXPECT_EQ(a.step(), noise::step_t::NONE);
		EXPECT_FALSE(a.read(view_t(out, size), back, got));
		noise::cipher_t one, two;
		EXPECT_FALSE(a.split(one, two));
	}
	// Ход не в очередь
	{
		noise::handshake_t a;
		ASSERT_TRUE(a.start(span(name), noise::role_t::INITIATOR, view_t()));
		ASSERT_TRUE(a.statics(view_t(sa, 32)));
		EXPECT_EQ(a.step(), noise::step_t::WRITE);
		size_t size = sizeof(out), got = sizeof(back);
		EXPECT_FALSE(a.read(view_t(out, 32), back, got));
		EXPECT_EQ(a.step(), noise::step_t::WRITE);
		ASSERT_TRUE(a.write(view_t(), out, size));
		EXPECT_EQ(a.step(), noise::step_t::READ);
		size = sizeof(out);
		EXPECT_FALSE(a.write(view_t(), out, size));
		// Ключи после первого сообщения не принимаются
		EXPECT_FALSE(a.statics(view_t(sa, 32)));
		EXPECT_FALSE(a.remote(view_t(pb, 32)));
		EXPECT_FALSE(a.ephemeral(view_t(sa, 32)));
		view_t psk(sa, 32);
		EXPECT_FALSE(a.psks(&psk, 1));
	}
	// Чужой постоянный ключ задан заранее и не совпал с принятым
	{
		noise::handshake_t a, b;
		ASSERT_TRUE(a.start(span(name), noise::role_t::INITIATOR, view_t()));
		ASSERT_TRUE(b.start(span(name), noise::role_t::RESPONDER, view_t()));
		ASSERT_TRUE(a.statics(view_t(sa, 32)));
		ASSERT_TRUE(b.statics(view_t(sb, 32)));
		ASSERT_TRUE(a.remote(view_t(pa, 32)));
		size_t size = sizeof(out), got = sizeof(back);
		ASSERT_TRUE(a.write(view_t(), out, size));
		ASSERT_TRUE(b.read(view_t(out, size), back, got));
		size = sizeof(out); got = sizeof(back);
		ASSERT_TRUE(b.write(view_t(), out, size));
		EXPECT_FALSE(a.read(view_t(out, size), back, got));
		EXPECT_EQ(a.step(), noise::step_t::NONE);
	}
	// Порча метки
	{
		noise::handshake_t a, b;
		ASSERT_TRUE(a.start(span(name), noise::role_t::INITIATOR, view_t()));
		ASSERT_TRUE(b.start(span(name), noise::role_t::RESPONDER, view_t()));
		ASSERT_TRUE(a.statics(view_t(sa, 32)));
		ASSERT_TRUE(b.statics(view_t(sb, 32)));
		size_t size = sizeof(out), got = sizeof(back);
		ASSERT_TRUE(a.write(view_t(), out, size));
		ASSERT_TRUE(b.read(view_t(out, size), back, got));
		size = sizeof(out); got = sizeof(back);
		ASSERT_TRUE(b.write(span(std::string("payload")), out, size));
		out[size - 1] ^= 0x80;
		EXPECT_FALSE(a.read(view_t(out, size), back, got));
		EXPECT_EQ(got, 0u);
		EXPECT_EQ(a.step(), noise::step_t::NONE);
		// Короткое сообщение
		noise::handshake_t c;
		ASSERT_TRUE(c.start(span(name), noise::role_t::RESPONDER, view_t()));
		ASSERT_TRUE(c.statics(view_t(sb, 32)));
		got = sizeof(back);
		EXPECT_FALSE(c.read(view_t(out, 31), back, got));
		EXPECT_EQ(c.step(), noise::step_t::NONE);
	}
	// Ключи: чужие длины, лишние psk, недостающие ключи, 448, до заведения
	{
		noise::handshake_t a;
		EXPECT_EQ(a.step(), noise::step_t::NONE);
		EXPECT_FALSE(a.statics(view_t(sa, 32)));
		EXPECT_FALSE(a.start(span(std::string("Noise_XX_448_ChaChaPoly_SHA256")), noise::role_t::INITIATOR, view_t()));
		EXPECT_FALSE(a.start(span(name), noise::role_t::NONE, view_t()));
		EXPECT_FALSE(a.start(noise::pattern_t::NN, 0x08, noise::suite_t(noise::dh_t::X25519, noise::aead_t::CHACHAPOLY, digest::hash_t::SHA256), noise::role_t::INITIATOR, view_t()));
		ASSERT_TRUE(a.start(span(name), noise::role_t::INITIATOR, view_t()));
		EXPECT_FALSE(a.statics(view_t(sa, 31)));
		EXPECT_FALSE(a.remote(view_t(pb, 33)));
		view_t list[5] = {view_t(sa, 32), view_t(sa, 32), view_t(sa, 32), view_t(sa, 32), view_t(sa, 32)};
		EXPECT_FALSE(a.psks(list, 5));
		view_t shorter(sa, 31);
		EXPECT_FALSE(a.psks(&shorter, 1));
		EXPECT_FALSE(a.psks(nullptr, 1));
		// XX без своего постоянного ключа: отказ первого сообщения
		size_t size = sizeof(out);
		EXPECT_FALSE(a.write(view_t(), out, size));
		// psk задан без видоизменения - отказ по числу положений
		noise::handshake_t c;
		ASSERT_TRUE(c.start(span(name), noise::role_t::INITIATOR, view_t()));
		ASSERT_TRUE(c.statics(view_t(sa, 32)));
		view_t psk(sa, 32);
		ASSERT_TRUE(c.psks(&psk, 1));
		size = sizeof(out);
		EXPECT_FALSE(c.write(view_t(), out, size));
		// Видоизменение без ключа
		noise::handshake_t d;
		ASSERT_TRUE(d.start(span(std::string("Noise_XXpsk3_25519_ChaChaPoly_SHA256")), noise::role_t::INITIATOR, view_t()));
		ASSERT_TRUE(d.statics(view_t(sa, 32)));
		size = sizeof(out);
		EXPECT_FALSE(d.write(view_t(), out, size));
	}
	// Состояния шифра: без функции, без ключа, чужая длина ключа
	{
		noise::cipher_t state;
		uint8_t tag[16];
		EXPECT_FALSE(state.start(noise::aead_t::NONE));
		EXPECT_FALSE(state.key(view_t(sa, 32)));
		ASSERT_TRUE(state.start(noise::aead_t::CHACHAPOLY));
		EXPECT_FALSE(state.key(view_t(sa, 31)));
		EXPECT_FALSE(state.has());
		EXPECT_FALSE(state.encrypt(view_t(), view_t(sa, 8), out, tag));
		EXPECT_FALSE(state.rekey());
		EXPECT_FALSE(state.key(out));
		noise::symmetric_t sym;
		EXPECT_FALSE(sym.start(view_t(), noise::suite_t(noise::dh_t::X25519, noise::aead_t::CHACHAPOLY, digest::hash_t::SHA256)));
		EXPECT_FALSE(sym.start(span(name), noise::suite_t(noise::dh_t::NONE, noise::aead_t::CHACHAPOLY, digest::hash_t::SHA256)));
		EXPECT_FALSE(sym.key(view_t(sa, 32)));
		// Хеш рукопожатия не тронут при несошедшейся метке
		noise::symmetric_t keyed;
		ASSERT_TRUE(keyed.start(span(name), noise::suite_t(noise::dh_t::X25519, noise::aead_t::CHACHAPOLY, digest::hash_t::SHA256)));
		ASSERT_TRUE(keyed.key(view_t(sa, 32)));
		uint8_t before[32], after[32], sealed[64];
		size_t size = sizeof(sealed);
		ASSERT_TRUE(keyed.seal(span(std::string("abc")), sealed, size));
		ASSERT_EQ(size, 3u + noise::TAG);
		ASSERT_TRUE(keyed.digest(before));
		sealed[size - 1] ^= 1;
		size_t got = sizeof(out);
		EXPECT_FALSE(keyed.open(view_t(sealed, size), out, got));
		ASSERT_TRUE(keyed.digest(after));
		EXPECT_EQ(::memcmp(before, after, 32), 0);
		// Точка малого порядка: DH отказывает
		uint8_t zeros[32], shared[32];
		::memset(zeros, 0, 32);
		EXPECT_FALSE(noise::agree(noise::dh_t::X25519, view_t(sa, 32), view_t(zeros, 32), shared));
		EXPECT_TRUE(noise::agree(noise::dh_t::X25519, view_t(sa, 32), view_t(pb, 32), shared));
	}
}
/**
 * @brief Обе роли по всем восьми наборам со случайными ключами и полезной частью, включая хеш и ключ собеседника
 *
 */
TEST(NoiseTest, Suites){
	const char * names[] = {
		"Noise_XX_25519_ChaChaPoly_SHA256", "Noise_XX_25519_ChaChaPoly_SHA512", "Noise_XX_25519_ChaChaPoly_BLAKE2s", "Noise_XX_25519_ChaChaPoly_BLAKE2b",
		"Noise_XX_25519_AESGCM_SHA256", "Noise_XX_25519_AESGCM_SHA512", "Noise_XX_25519_AESGCM_BLAKE2s", "Noise_XX_25519_AESGCM_BLAKE2b"
	};
	for(auto name : names){
		noise::handshake_t a, b;
		ASSERT_TRUE(converse(name, a, b)) << name;
		uint8_t ha[64], hb[64], pa[32], pb[32], sa[32], sb[32];
		ASSERT_TRUE(a.digest(ha));
		ASSERT_TRUE(b.digest(hb));
		EXPECT_EQ(::memcmp(ha, hb, a.length()), 0) << name;
		ASSERT_TRUE(a.peer(pb));
		ASSERT_TRUE(b.self(sb));
		ASSERT_TRUE(b.peer(pa));
		ASSERT_TRUE(a.self(sa));
		EXPECT_EQ(::memcmp(pb, sb, 32), 0) << name;
		EXPECT_EQ(::memcmp(pa, sa, 32), 0) << name;
		noise::cipher_t a1, a2, b1, b2;
		ASSERT_TRUE(a.split(a1, a2));
		ASSERT_TRUE(b.split(b1, b2));
		uint8_t out[64], tag[16], back[64];
		ASSERT_TRUE(b2.encrypt(view_t(), span(std::string("from responder")), out, tag));
		ASSERT_TRUE(a2.decrypt(view_t(), view_t(out, 14), view_t(tag, 16), back));
		EXPECT_EQ(::memcmp(back, "from responder", 14), 0) << name;
		ASSERT_TRUE(a1.encrypt(view_t(), span(std::string("from initiator")), out, tag));
		ASSERT_TRUE(b1.decrypt(view_t(), view_t(out, 14), view_t(tag, 16), back));
		EXPECT_EQ(::memcmp(back, "from initiator", 14), 0) << name;
		// Перекрёстные состояния не сходятся
		ASSERT_TRUE(a1.encrypt(view_t(), span(std::string("x")), out, tag));
		EXPECT_FALSE(a2.decrypt(view_t(), view_t(out, 1), view_t(tag, 16), back));
	}
}
/**
 * @brief Паёк выделений: рукопожатие и транспорт без единого выделения памяти
 *
 */
TEST(NoiseTest, Starved){
	// Под пайком ни одной строки std: на прежнем строковом ABI libstdc++ (OpenWRT) даже короткая строка выделяет память
	static const uint8_t NAME[] = "Noise_IK_25519_AESGCM_BLAKE2s";
	const view_t name(NAME, sizeof(NAME) - 1);
	static const uint8_t ONE[] = "one", TWO[] = "two", THREE[] = "three";
	uint8_t sa[32], pa[32], sb[32], pb[32], out[256], back[256], tag[16];
	ASSERT_TRUE(noise::generate(noise::dh_t::X25519, sa, pa));
	ASSERT_TRUE(noise::generate(noise::dh_t::X25519, sb, pb));
	noise::handshake_t a, b;
	noise::cipher_t a1, a2, b1, b2;
	bool status = true;
	{
		starve::ration_t ration(0);
		status = (a.start(name, noise::role_t::INITIATOR, view_t()) && b.start(name, noise::role_t::RESPONDER, view_t()));
		status = (status && a.statics(view_t(sa, 32)) && b.statics(view_t(sb, 32)) && a.remote(view_t(pb, 32)));
		size_t size = sizeof(out), got = sizeof(back);
		status = (status && a.write(view_t(ONE, 3), out, size) && b.read(view_t(out, size), back, got) && (got == 3));
		size = sizeof(out); got = sizeof(back);
		status = (status && b.write(view_t(TWO, 3), out, size) && a.read(view_t(out, size), back, got) && (got == 3));
		status = (status && a.split(a1, a2) && b.split(b1, b2));
		status = (status && a1.encrypt(view_t(), view_t(THREE, 5), out, tag) && b1.decrypt(view_t(), view_t(out, 5), view_t(tag, 16), back));
		ration.stop();
	}
	EXPECT_TRUE(status);
	EXPECT_EQ(::memcmp(back, "three", 5), 0);
}
