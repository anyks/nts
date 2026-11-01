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
		// Обнуляем счётчики прогона
		Tally() : taken(0), skipped448(0), skippedOneWay(0), forwardOneWay(0), hashes(0) {}
	} tally_t;
	/**
	 * @brief Функция разбора шестнадцатеричной строки
	 *
	 * @param text строка
	 * @return     байты
	 *
	 */
	static std::vector <uint8_t> unhex(const std::string & text) {
		// Буфер байтов результата разбора
		std::vector <uint8_t> result;
		/**
		 * Выполняем итерацию цикла
		 */
		for(size_t i = 0; (i + 1) < text.size(); i += 2){
			// Пара шестнадцатеричных знаков очередного байта
			const std::string pair = text.substr(i, 2);
			// Переводим пару шестнадцатеричных знаков в байт
			result.push_back(static_cast <uint8_t> (::strtoul(pair.c_str(), nullptr, 16)));
		}
		// Возвращаем разобранные байты
		return result;
	}
	/**
	 * @brief Функция получения области байтов вектора
	 *
	 * @param data вектор
	 * @return     область
	 *
	 */
	static view_t span(const std::vector <uint8_t> & data) {
		// Возвращаем область байтов вектора
		return view_t(data.empty() ? nullptr : data.data(), data.size());
	}
	/**
	 * @brief Функция получения области байтов строки
	 *
	 * @param text строка
	 * @return     область
	 *
	 */
	static view_t span(const std::string & text) {
		// Возвращаем область байтов строки
		return view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size());
	}
	/**
	 * @brief Функция чтения корпуса flynn/noise: построчно ключ=значение, записи через пустую строку
	 *
	 * @param path путь к файлу
	 * @return     записи
	 *
	 */
	static std::vector <record_t> flynn(const std::string & path) {
		// Записи корпуса по мере чтения
		std::vector <record_t> result;
		// Открываем файл корпуса
		std::ifstream file(path);
		// Файл не открылся - возвращаем пустой набор
		if(!file.is_open()) return result;
		// Накапливаемая запись корпуса
		record_t record;
		// Очередная строка файла
		std::string line;
		// Признак начатой записи
		bool open = false;
		// Завершатель накопленной записи
		auto flush = [&]() {
			// Запись начата - фиксируем её в наборе
			if(open){
				// Номер записи — порядковый в наборе
				record.index = (result.size() + 1);
				// Добавляем накопленную запись в набор
				result.push_back(record);
			}
			// Сбрасываем накопленную запись
			record = record_t();
			// Снимаем признак начатой записи
			open = false;
		};
		/**
		 * Выполняем итерацию цикла
		 */
		while(std::getline(file, line)){
			// Снимаем возврат каретки с конца строки
			if(!line.empty() && (line.back() == '\r')) line.pop_back();
			if(line.empty()){ flush(); continue; }
			// Позиция знака равенства в строке
			const size_t eq = line.find('=');
			// Строка без знака равенства - пропуск
			if(eq == std::string::npos) continue;
			// Ключ и значение поля записи
			const std::string key = line.substr(0, eq), value = line.substr(eq + 1);
			// Отмечаем запись начатой
			open = true;
			// Раскладываем поле записи по его ключу
			if(key == "handshake") record.name = value;
			else if(key == "gen_init_ephemeral") record.initEphemeral = unhex(value);
			else if(key == "gen_resp_ephemeral") record.respEphemeral = unhex(value);
			else if(key == "init_static") record.initStatic = unhex(value);
			else if(key == "resp_static") record.respStatic = unhex(value);
			else if(key == "preshared_key") record.psks.push_back(unhex(value));
			else if(key == "prologue"){ record.initPrologue = unhex(value); record.respPrologue = record.initPrologue; }
			else if((key.compare(0, 4, "msg_") == 0)){
				// Позиция второго подчёркивания ключа
				const size_t second = key.find('_', 4);
				// Номер сообщения из ключа
				const size_t number = ::strtoul(key.substr(4, second - 4).c_str(), nullptr, 10);
				// Вид поля сообщения
				const std::string kind = key.substr(second + 1);
				// Расширяем список сообщений до номера поля
				if(record.messages.size() <= number) record.messages.resize(number + 1);
				if(kind == "payload") record.messages[number].first = unhex(value);
				else if(kind == "ciphertext") record.messages[number].second = unhex(value);
			}
		}
		// Фиксируем последнюю запись файла
		flush();
		// Возвращаем записи корпуса
		return result;
	}
	/**
	 * @brief Функция чтения порождённых хешей рукопожатия для корпуса flynn: «номер имя хеш»
	 *
	 * @param path путь к файлу
	 * @return     хеши по номеру
	 *
	 */
	static std::map <size_t, std::pair <std::string, std::vector <uint8_t>>> hashes(const std::string & path) {
		// Хеши рукопожатия по номерам записей
		std::map <size_t, std::pair <std::string, std::vector <uint8_t>>> result;
		// Открываем файл порождённых хешей
		std::ifstream file(path);
		// Очередная строка файла
		std::string line;
		/**
		 * Выполняем итерацию цикла
		 */
		while(std::getline(file, line)){
			// Позиция первого пробела строки
			const size_t one = line.find(' ');
			// Нет первого пробела - пропуск строки
			if(one == std::string::npos) continue;
			// Позиция второго пробела строки
			const size_t two = line.find(' ', one + 1);
			// Нет второго пробела - пропуск строки
			if(two == std::string::npos) continue;
			// Номер записи из строки
			const size_t index = ::strtoul(line.substr(0, one).c_str(), nullptr, 10);
			// Запоминаем имя и хеш под номером записи
			result[index] = std::make_pair(line.substr(one + 1, two - one - 1), unhex(line.substr(two + 1)));
		}
		// Возвращаем хеши по номерам записей
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
			// Положение в разбираемом тексте
			size_t _pos;
		private:
			/**
			 * @brief Метод пропуска пробелов
			 *
			 */
			void blank() {
				/**
				 * Выполняем итерацию цикла
				 */
				while((this->_pos < this->_text.size()) && ((this->_text[this->_pos] == ' ') || (this->_text[this->_pos] == '\n') || (this->_text[this->_pos] == '\r') || (this->_text[this->_pos] == '\t'))) this->_pos++;
			}
			/**
			 * @brief Метод чтения строки в кавычках
			 *
			 * @param result строка
			 * @return       признак успешности
			 *
			 */
			bool quoted(std::string & result) {
				// Пропускаем пробелы перед строкой
				this->blank();
				// Первый знак должен быть открывающей кавычкой
				if((this->_pos >= this->_text.size()) || (this->_text[this->_pos] != '"')) return false;
				// Пропускаем открывающую кавычку
				this->_pos++;
				// Позиция закрывающей кавычки
				const size_t end = this->_text.find('"', this->_pos);
				// Закрывающей кавычки нет - отказ
				if(end == std::string::npos) return false;
				// Вырезаем строку между кавычками
				result = this->_text.substr(this->_pos, end - this->_pos);
				// Экраны не поддерживаются - отказ
				if(result.find('\\') != std::string::npos) return false;
				// Пропускаем закрывающую кавычку
				this->_pos = (end + 1);
				// Сообщаем об успешном чтении строки
				return true;
			}
			/**
			 * @brief Метод чтения одного знака
			 *
			 * @param symbol знак
			 * @return       признак того, что знак прочитан
			 *
			 */
			bool expect(const char symbol) {
				// Пропускаем пробелы перед знаком
				this->blank();
				// Знак совпал - продвигаем позицию
				if((this->_pos < this->_text.size()) && (this->_text[this->_pos] == symbol)){ this->_pos++; return true; }
				// Знак не совпал
				return false;
			}
			/**
			 * @brief Метод чтения массива строк
			 *
			 * @param result строки
			 * @return       признак успешности
			 *
			 */
			bool strings(std::vector <std::string> & result) {
				// Массив должен начинаться с квадратной скобки
				if(!this->expect('[')) return false;
				if(this->expect(']')) return true;
				// Читаем строки через запятую
				do {
					// Очередная строка массива
					std::string item;
					// Читаем очередную строку массива
					if(!this->quoted(item)) return false;
					// Добавляем строку в массив
					result.push_back(item);
				} while(this->expect(','));
				// Массив должен заканчиваться квадратной скобкой
				return this->expect(']');
			}
			/**
			 * @brief Метод чтения массива объектов из строковых полей
			 *
			 * @param result объекты
			 * @return       признак успешности
			 *
			 */
			bool objects(std::vector <std::map <std::string, std::string>> & result) {
				// Список объектов открывается квадратной скобкой
				if(!this->expect('[')) return false;
				if(this->expect(']')) return true;
				// Читаем объекты через запятую
				do {
					// Поля очередного объекта
					std::map <std::string, std::string> item;
					// Объект открывается фигурной скобкой
					if(!this->expect('{')) return false;
					if(!this->expect('}')){
						// Читаем поля объекта через запятую
						do {
							// Имя и значение поля
							std::string key, value;
							// Поле: имя, двоеточие, значение
							if(!this->quoted(key) || !this->expect(':') || !this->quoted(value)) return false;
							// Запоминаем поле объекта
							item[key] = value;
						} while(this->expect(','));
						// Объект должен заканчиваться фигурной скобкой
						if(!this->expect('}')) return false;
					}
					// Добавляем объект в список
					result.push_back(item);
				} while(this->expect(','));
				// Список объектов закрывается квадратной скобкой
				return this->expect(']');
			}
		public:
			/**
			 * @brief Метод чтения корпуса целиком
			 *
			 * @param result записи
			 * @return       признак успешности
			 *
			 */
			bool corpus(std::vector <record_t> & result) {
				// Имя поля записи
				std::string key;
				// Корпус должен начинаться с поля векторов
				if(!this->expect('{') || !this->quoted(key) || (key != "vectors") || !this->expect(':') || !this->expect('[')) return false;
				// Читаем записи векторов через запятую
				do {
					// Накапливаемая запись вектора
					record_t record;
					// Запись открывается фигурной скобкой
					if(!this->expect('{')) return false;
					// Читаем поля записи через запятую
					do {
						// Читаем имя поля и двоеточие
						if(!this->quoted(key) || !this->expect(':')) return false;
						if(key == "messages"){
							// Сообщения записи - список объектов
							std::vector <std::map <std::string, std::string>> items;
							// Читаем список сообщений
							if(!this->objects(items)) return false;
							/**
							 * Выполняем итерацию цикла
							 */
							for(auto & item : items) record.messages.push_back(std::make_pair(unhex(item["payload"]), unhex(item["ciphertext"])));
						} else if((key == "init_psks") || (key == "resp_psks")){
							// Предразделённые ключи - список строк
							std::vector <std::string> items;
							// Читаем список ключей
							if(!this->strings(items)) return false;
							if(key == "init_psks"){ record.psks.clear(); for(auto & item : items) record.psks.push_back(unhex(item)); }
						} else {
							// Значение прочего поля
							std::string value;
							// Значение прочего поля
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
					// Запись закрывается фигурной скобкой
					if(!this->expect('}')) return false;
					// Номер записи — порядковый в наборе
					record.index = (result.size() + 1);
					// Добавляем запись в набор
					result.push_back(record);
				} while(this->expect(','));
				// Корпус закрывается списком векторов и объектом
				return (this->expect(']') && this->expect('}'));
			}
			/**
			 * @brief Конструктор
			 *
			 * @param text текст
			 *
			 */
			Reader(const std::string & text) : _text(text), _pos(0) {}
	} reader_t;
	/**
	 * @brief Функция чтения корпуса Cacophony
	 *
	 * @param path путь к файлу
	 * @return     записи
	 *
	 */
	static std::vector <record_t> cacophony(const std::string & path) {
		// Записи корпуса по мере чтения
		std::vector <record_t> result;
		// Открываем файл корпуса
		std::ifstream file(path);
		// Файл не открылся - возвращаем пустой набор
		if(!file.is_open()) return result;
		// Читаем файл корпуса целиком
		std::string text((std::istreambuf_iterator <char> (file)), std::istreambuf_iterator <char> ());
		// Заводим читатель на тексте корпуса
		reader_t reader(text);
		// Разбираем корпус читателем, при отказе сбрасываем набор
		if(!reader.corpus(result)) result.clear();
		// Возвращаем записи корпуса
		return result;
	}
	/**
	 * @brief Функция заведения стороны по записи
	 *
	 * @param record    запись
	 * @param initiator признак инициатора
	 * @param side      состояние
	 * @param derived   признак вывода чужого ключа из чужого постоянного (flynn)
	 * @return          признак успешности
	 *
	 */
	static bool arm(const record_t & record, const bool initiator, noise::handshake_t & side, const bool derived) {
		// Заводим сторону: имя протокола, роль, пролог
		if(!side.start(span(record.name), initiator ? noise::role_t::INITIATOR : noise::role_t::RESPONDER, span(initiator ? record.initPrologue : record.respPrologue))) return false;
		// Свой постоянный ключ стороны
		const std::vector <uint8_t> & s = (initiator ? record.initStatic : record.respStatic);
		// Свой временный ключ стороны
		const std::vector <uint8_t> & e = (initiator ? record.initEphemeral : record.respEphemeral);
		// Передаём стороне свой постоянный ключ
		if(!s.empty() && !side.statics(span(s))) return false;
		if(!e.empty() && !side.ephemeral(span(e))) return false;
		// Заданный заранее чужой постоянный ключ
		const std::vector <uint8_t> & given = (initiator ? record.initRemote : record.respRemote);
		// Чужой ключ задан явно - передаём его
		if(!given.empty()){
			if(!side.remote(span(given))) return false;
		} else if(derived){
			// Чужой ключ выводится из чужого постоянного, если предсообщение собеседника его несёт
			noise::pattern_t pattern = noise::pattern_t::NONE;
			// Видоизменения протокола из имени
			noise::psk_t psks = 0;
			// Набор примитивов из имени
			noise::suite_t suite;
			// Разбираем имя протокола на узор и набор
			noise::parse(span(record.name), pattern, psks, suite);
			// Жетоны предсообщения собеседника
			const noise::token_t * list = nullptr;
			// Число жетонов предсообщения
			size_t count = 0;
			// Предсообщение собеседника несёт его постоянный ключ
			if(noise::premessage(pattern, !initiator, list, count) && (count > 0)){
				// Чужой постоянный ключ из записи
				const std::vector <uint8_t> & other = (initiator ? record.respStatic : record.initStatic);
				// Буфер выведенного ключа
				uint8_t key[noise::KEY];
				// Выводим чужой ключ из его постоянного
				if(other.empty() || !noise::derive(noise::dh_t::X25519, span(other), key)) return false;
				if(!side.remote(view_t(key, noise::KEY))) return false;
			}
		}
		// В записи есть предразделённые ключи
		if(!record.psks.empty()){
			// Области предразделённых ключей
			std::vector <view_t> list;
			/**
			 * Выполняем итерацию цикла
			 */
			for(auto & item : record.psks) list.push_back(span(item));
			// Передаём предразделённые ключи стороне
			if(!side.psks(list.data(), list.size())) return false;
		}
		// Сторона заведена полностью
		return true;
	}
	/**
	 * @brief Функция прогона одной записи
	 *
	 * @param record  запись
	 * @param flynn   признак корпуса flynn (иначе Cacophony)
	 * @param tally   счёт
	 * @param given   хеш рукопожатия, порождённый отдельно (flynn), либо пусто
	 *
	 */
	static void run(const record_t & record, const bool flynn, tally_t & tally, const std::vector <uint8_t> & given) {
		// Узор протокола из имени записи
		noise::pattern_t pattern = noise::pattern_t::NONE;
		// Видоизменения протокола из имени
		noise::psk_t psks = 0;
		// Набор примитивов из имени
		noise::suite_t suite;
		// Разбираем имя протокола на узор и набор
		if(!noise::parse(span(record.name), pattern, psks, suite)){
			if((pattern != noise::pattern_t::NONE) && (suite.dh == noise::dh_t::NONE)){ tally.skipped448++; return; }
			// Имя не разобрано - фиксируем расхождение
			tally.failures.push_back(record.name + ": имя не разобрано");
			// Запись без разобранного имени не прогоняется
			return;
		}
		// Запись взята в работу
		tally.taken++;
		// Стороны рукопожатия
		noise::handshake_t a, b;
		// Заводим обе стороны по записи
		if(!arm(record, true, a, flynn) || !arm(record, false, b, flynn)){ tally.failures.push_back(record.name + ": стороны не заведены"); return; }
		// Число сообщений узора
		const size_t count = noise::messages(pattern);
		// Буферы шифротекста и расшифровки
		std::vector <uint8_t> out(noise::MESSAGE), back(noise::MESSAGE);
		/**
		 * Выполняем итерацию цикла
		 */
		for(size_t i = 0; i < count; i++){
			// Сообщений в записи меньше, чем требует узор
			if(i >= record.messages.size()){ tally.failures.push_back(record.name + ": мало сообщений"); return; }
			// Пишущая сторона очередного сообщения
			noise::handshake_t & writer = ((i % 2) == 0) ? a : b;
			// Читающая сторона очередного сообщения
			noise::handshake_t & reader = ((i % 2) == 0) ? b : a;
			// Вместимость буфера шифротекста
			size_t size = out.size();
			// Шифруем полезную часть очередного сообщения
			if(!writer.write(span(record.messages[i].first), out.data(), size)){ tally.failures.push_back(record.name + ": запись " + std::to_string(i)); return; }
			if((size != record.messages[i].second.size()) || (::memcmp(out.data(), record.messages[i].second.data(), size) != 0)){ tally.failures.push_back(record.name + ": шифротекст " + std::to_string(i)); return; }
			// Вместимость буфера расшифровки
			size_t got = back.size();
			// Расшифровываем сообщение второй стороной
			if(!reader.read(view_t(out.data(), size), back.data(), got)){ tally.failures.push_back(record.name + ": чтение " + std::to_string(i)); return; }
			if((got != record.messages[i].first.size()) || ((got > 0) && (::memcmp(back.data(), record.messages[i].first.data(), got) != 0))){ tally.failures.push_back(record.name + ": полезная часть " + std::to_string(i)); return; }
		}
		// Обе стороны должны завершить рукопожатие
		if((a.step() != noise::step_t::DONE) || (b.step() != noise::step_t::DONE)){ tally.failures.push_back(record.name + ": не завершено"); return; }
		// Пары транспортных состояний после раскола
		noise::cipher_t a1, a2, b1, b2;
		// Раскалываем обе стороны на пары состояний
		if(!a.split(a1, a2) || !b.split(b1, b2)){ tally.failures.push_back(record.name + ": раскол"); return; }
		// Ожидаемый хеш: порождённый или из записи
		const std::vector <uint8_t> & expected = (given.empty() ? record.hash : given);
		// Хеш задан - сверяем его
		if(!expected.empty()){
			// Буферы хешей обеих сторон
			uint8_t ha[noise::HASH_MAX], hb[noise::HASH_MAX];
			// Сверяем хеши обеих сторон с ожидаемым
			if(!a.digest(ha) || !b.digest(hb) || (a.length() != expected.size()) || (::memcmp(ha, expected.data(), expected.size()) != 0) || (::memcmp(hb, expected.data(), expected.size()) != 0)){ tally.failures.push_back(record.name + ": хеш рукопожатия"); return; }
			// Хеши сошлись - увеличиваем счёт
			tally.hashes++;
		}
		// Признак одностороннего узора
		const bool oneWay = (count == 1);
		/**
		 * Выполняем итерацию цикла
		 */
		for(size_t m = count; m < record.messages.size(); m++){
			// Номер транспортного сообщения
			const size_t k = (m - count);
			// Признак отправки от инициатора
			bool fromInitiator;
			// Первый корпус чередует заново с инициатора
			if(flynn) fromInitiator = ((k % 2) == 0);
			else fromInitiator = (oneWay ? true : ((m % 2) == 0));
			// Обратный ход одностороннего узора не проверяем
			if(oneWay && !fromInitiator){ tally.skippedOneWay++; continue; }
			if(oneWay) tally.forwardOneWay++;
			// Состояние отправителя транспортного сообщения
			noise::cipher_t & sender = (fromInitiator ? a1 : b2);
			// Состояние получателя транспортного сообщения
			noise::cipher_t & receiver = (fromInitiator ? b1 : a2);
			// Полезная часть транспортного сообщения
			const std::vector <uint8_t> & payload = record.messages[m].first;
			// Шифротекст транспортного сообщения
			const std::vector <uint8_t> & cipher = record.messages[m].second;
			// Буфер метки подлинности
			uint8_t tag[noise::TAG];
			// Шифруем сообщение состоянием отправителя
			if(!sender.encrypt(view_t(), span(payload), out.data(), tag)){ tally.failures.push_back(record.name + ": транспорт запись " + std::to_string(m)); return; }
			if((cipher.size() != (payload.size() + noise::TAG)) || (::memcmp(out.data(), cipher.data(), payload.size()) != 0) || (::memcmp(tag, cipher.data() + payload.size(), noise::TAG) != 0)){ tally.failures.push_back(record.name + ": транспорт шифротекст " + std::to_string(m)); return; }
			if(!receiver.decrypt(view_t(), view_t(cipher.data(), payload.size()), view_t(cipher.data() + payload.size(), noise::TAG), back.data())){ tally.failures.push_back(record.name + ": транспорт чтение " + std::to_string(m)); return; }
			if((payload.size() > 0) && (::memcmp(back.data(), payload.data(), payload.size()) != 0)){ tally.failures.push_back(record.name + ": транспорт полезная часть " + std::to_string(m)); return; }
		}
	}
	/**
	 * @brief Функция полного рукопожатия XX между двумя сторонами со случайными ключами
	 *
	 * @param name имя протокола
	 * @param a    инициатор
	 * @param b    отвечающий
	 * @return     признак успешности
	 *
	 */
	static bool converse(const char * name, noise::handshake_t & a, noise::handshake_t & b) {
		// Свои и открытые ключи обеих сторон
		uint8_t sa[32], pa[32], sb[32], pb[32];
		// Порождаем пары ключей обмена
		if(!noise::generate(noise::dh_t::X25519, sa, pa) || !noise::generate(noise::dh_t::X25519, sb, pb)) return false;
		if(!a.start(span(std::string(name)), noise::role_t::INITIATOR, view_t()) || !b.start(span(std::string(name)), noise::role_t::RESPONDER, view_t())) return false;
		if(!a.statics(view_t(sa, 32)) || !b.statics(view_t(sb, 32))) return false;
		// Буферы сообщения и расшифровки
		uint8_t out[256], back[256];
		/**
		 * Выполняем итерацию цикла
		 */
		while((a.step() != noise::step_t::DONE) || (b.step() != noise::step_t::DONE)){
			// Пишущая сторона по шагу рукопожатия
			noise::handshake_t & writer = (a.step() == noise::step_t::WRITE) ? a : b;
			// Читающая сторона по шагу рукопожатия
			noise::handshake_t & reader = (a.step() == noise::step_t::WRITE) ? b : a;
			// Пишущая сторона должна ждать записи
			if(writer.step() != noise::step_t::WRITE) return false;
			// Вместимости буферов сообщения и расшифровки
			size_t size = sizeof(out), got = sizeof(back);
			// Гоняем сообщения до завершения обеих сторон
			if(!writer.write(view_t(), out, size) || !reader.read(view_t(out, size), back, got) || (got != 0)) return false;
		}
		// Рукопожатие завершилось у обеих сторон
		return true;
	}
	/**
	 * @brief Функция счёта HKDF Noise вручную по §4.3
	 *
	 * @param hash  функция хеширования
	 * @param chain цепной ключ
	 * @param ikm   материал
	 * @param count число выходов
	 * @param out   выходы по длине хеша
	 *
	 */
	static void manual(const digest::hash_t hash, const std::vector <uint8_t> & chain, const std::vector <uint8_t> & ikm, const size_t count, std::vector <std::vector <uint8_t>> & out) {
		// Длина выхода проверяемого хеша
		const size_t length = digest::length(hash);
		// Временный ключ цепи
		std::vector <uint8_t> temp(length);
		// Заводим ключ цепи из входного материала
		digest::hmac(hash, span(chain), span(ikm), temp.data(), length);
		// Предыдущий выход для цепочки
		std::vector <uint8_t> previous;
		/**
		 * Выполняем итерацию цикла
		 */
		for(size_t i = 1; i <= count; i++){
			// Предыдущий выход с номером
			std::vector <uint8_t> input(previous);
			// Добавляем номер выхода
			input.push_back(static_cast <uint8_t> (i));
			// Буфер очередного выхода
			std::vector <uint8_t> item(length);
			// Выводим очередной блок из ключа цепи
			digest::hmac(hash, span(temp), span(input), item.data(), length);
			// Кладём выход в список
			out.push_back(item);
			// Запоминаем выход для цепочки следующего блока
			previous = item;
		}
	}
};

/**
 * @brief Векторы flynn/noise v1.1.0: 1920 записей, восемь наборов, узоры с psk во всех положениях
 *
 */
TEST(NoiseTest, Flynn){
	// Читаем записи корпуса в формате ключ-значение
	const std::vector <record_t> records = flynn(std::string(CORPUS) + "/noise/flynn.txt");
	// Корпус читается полностью: 1920 записей
	ASSERT_EQ(records.size(), 1920u);
	// Порождённые хеши рукопожатий
	const auto given = hashes(std::string(CORPUS) + "/noise/flynn-hashes.txt");
	// Хеш порождён для каждой записи
	ASSERT_EQ(given.size(), 1920u);
	// Счёт прогона корпуса
	tally_t tally;
	/**
	 * Выполняем итерацию цикла
	 */
	for(auto & record : records){
		// Порождённый хеш записи по её номеру
		auto it = given.find(record.index);
		// Порождённый хеш записи найден
		ASSERT_NE(it, given.end());
		// Имя порождённого хеша совпадает с именем записи
		ASSERT_EQ(it->second.first, record.name) << record.index;
		// Прогоняем запись с порождённым хешом
		run(record, true, tally, it->second.second);
	}
	/**
	 * Выполняем итерацию цикла
	 */
	for(auto & failure : tally.failures) ADD_FAILURE() << failure;
	// Докладываем счёт прогона корпуса
	std::printf("flynn: взято %zu из %zu, хешей сверено %zu, пропущено по 448: %zu, у односторонних сличено прямого хода: %zu, пропущено обратного: %zu (9 узоров x 8 наборов x 4 блока x 1 сообщение)\n", tally.taken, records.size(), tally.hashes, tally.skipped448, tally.forwardOneWay, tally.skippedOneWay);
	// Все записи корпуса взяты в работу
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
	// Читаем записи корпуса в виде списка векторов
	const std::vector <record_t> records = cacophony(std::string(CORPUS) + "/noise/cacophony.txt");
	// Корпус разобран: 944 записи
	ASSERT_EQ(records.size(), 944u);
	// Счёт прогона корпуса
	tally_t tally;
	/**
	 * Выполняем итерацию цикла
	 */
	for(auto & record : records) run(record, false, tally, std::vector <uint8_t> ());
	/**
	 * Выполняем итерацию цикла
	 */
	for(auto & failure : tally.failures) ADD_FAILURE() << failure;
	// Докладываем счёт прогона корпуса
	std::printf("cacophony: взято %zu из %zu, хешей сверено %zu, пропущено по 448: %zu, у односторонних сличено прямого хода: %zu, пропущено обратного: %zu\n", tally.taken, records.size(), tally.hashes, tally.skipped448, tally.forwardOneWay, tally.skippedOneWay);
	// Принято ровно половина записей: 448-й не поддержан
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
	/**
	 * Выполняем итерацию цикла
	 */
	for(uint8_t i = 1; i <= static_cast <uint8_t> (noise::pattern_t::I1X1); i++){
		// Узор перебираемого значения
		const noise::pattern_t pattern = static_cast <noise::pattern_t> (i);
		// Каждый узор несёт сообщения
		ASSERT_NE(noise::messages(pattern), 0u) << int(i);
		// Число видоизменённых положений предразделённых ключей
		const size_t bits = ((noise::messages(pattern) + 1) < noise::PSKS_MAX) ? (noise::messages(pattern) + 1) : noise::PSKS_MAX;
		// Маска всех видоизменённых положений
		const noise::psk_t psks = static_cast <noise::psk_t> ((1u << bits) - 1);
		// Буфер составленного имени протокола
		char text[noise::NAME_LIMIT];
		// Вместимость буфера имени
		size_t size = sizeof(text);
		// Набор известных примитивов для составления имени
		noise::suite_t suite(noise::dh_t::X25519, noise::aead_t::AESGCM, digest::hash_t::BLAKE2B512);
		// Имя протокола составлено
		ASSERT_TRUE(noise::name(pattern, psks, suite, text, size));
		// Разобранный узор
		noise::pattern_t back = noise::pattern_t::NONE;
		// Разобранные видоизменения
		noise::psk_t backPsks = 0;
		// Разобранный набор примитивов
		noise::suite_t backSuite;
		// Составленное имя разбирается обратно
		ASSERT_TRUE(noise::parse(view_t(reinterpret_cast <const uint8_t *> (text), size), back, backPsks, backSuite)) << text;
		// Разбор возвращает исходный узор
		EXPECT_EQ(back, pattern) << text;
		EXPECT_EQ(backPsks, psks) << text;
		EXPECT_EQ(backSuite.aead, noise::aead_t::AESGCM);
		EXPECT_EQ(backSuite.hash, digest::hash_t::BLAKE2B512);
	}
	// Узор разбираемого имени
	noise::pattern_t pattern;
	// Видоизменения разбираемого имени
	noise::psk_t psks;
	// Набор разбираемого имени
	noise::suite_t suite;
	// Видоизменения psk0+psk3 разбираются
	EXPECT_TRUE(noise::parse(span(std::string("Noise_XXpsk0+psk3_25519_ChaChaPoly_SHA512")), pattern, psks, suite));
	// Имя несёт узор XX
	EXPECT_EQ(pattern, noise::pattern_t::XX);
	EXPECT_EQ(psks, 0x09);
	EXPECT_EQ(suite.hash, digest::hash_t::SHA512);
	// Отложенный узор XX1 разбирается
	EXPECT_TRUE(noise::parse(span(std::string("Noise_XX1_25519_AESGCM_BLAKE2s")), pattern, psks, suite));
	// Имя несёт узор XX1
	EXPECT_EQ(pattern, noise::pattern_t::XX1);
	// 448: узор и хеш разобраны, dh пуст, итог отказ
	EXPECT_FALSE(noise::parse(span(std::string("Noise_IK_448_ChaChaPoly_BLAKE2b")), pattern, psks, suite));
	// Узор разобран до отказа по DH
	EXPECT_EQ(pattern, noise::pattern_t::IK);
	EXPECT_EQ(suite.dh, noise::dh_t::NONE);
	EXPECT_EQ(suite.hash, digest::hash_t::BLAKE2B512);
	// Видоизменения вне очереди отклоняются
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
	// Четыре хеша каркаса для проверки HKDF
	const digest::hash_t hashes[] = {digest::hash_t::SHA256, digest::hash_t::SHA512, digest::hash_t::BLAKE2S256, digest::hash_t::BLAKE2B512};
	/**
	 * Выполняем итерацию цикла
	 */
	for(auto hash : hashes){
		// Длина выхода проверяемого хеша
		const size_t length = digest::length(hash);
		// Набор с проверяемым хешом
		noise::suite_t suite(noise::dh_t::X25519, noise::aead_t::CHACHAPOLY, hash);
		// Имя протокола с хешом-заглушкой
		const std::string name = "Noise_NN_25519_ChaChaPoly_X";
		// Проверяемое симметричное состояние
		noise::symmetric_t state;
		// Состояние заводится по имени протокола
		ASSERT_TRUE(state.start(span(name), suite));
		// Начальные h и ck: имя с нулями (короче хеша)
		std::vector <uint8_t> chain(length, 0);
		::memcpy(chain.data(), name.data(), name.size());
		// Буфер свёртки состояния
		uint8_t h[noise::HASH_MAX];
		// Свёртка состояния получена
		ASSERT_TRUE(state.digest(h));
		// Свёртка совпадает с именем, дополненным нулями
		EXPECT_EQ(::memcmp(h, chain.data(), length), 0);
		// MixKey
		std::vector <uint8_t> ikm(32, 0x5A);
		// Выходы ручного счёта
		std::vector <std::vector <uint8_t>> out;
		// Ручной счёт HKDF на два выхода
		manual(hash, chain, ikm, 2, out);
		// Смешивание ключа по MixKey
		ASSERT_TRUE(state.key(span(ikm)));
		// Первый выход ручного счёта — новый ключ цепи
		chain = out[0];
		// Шифрование пустой полезной части сличается с состоянием шифра на усечённом ключе
		noise::cipher_t direct;
		// Прямой шифр на усечённом ключе
		ASSERT_TRUE(direct.start(noise::aead_t::CHACHAPOLY));
		ASSERT_TRUE(direct.key(view_t(out[1].data(), noise::KEY)));
		// Буфер метки прямого шифра
		uint8_t tag[noise::TAG];
		// Метка прямого шифра на свёртке состояния
		ASSERT_TRUE(direct.encrypt(view_t(h, length), view_t(), nullptr, tag));
		// Буфер метки симметричного состояния
		uint8_t sealed[noise::TAG];
		// Вместимость буфера метки
		size_t size = sizeof(sealed);
		// Метка симметричного состояния
		ASSERT_TRUE(state.seal(view_t(), sealed, size));
		// Печать состоит из одной метки
		ASSERT_EQ(size, noise::TAG);
		// Метки прямого шифра и состояния совпадают
		EXPECT_EQ(::memcmp(sealed, tag, noise::TAG), 0) << "hash " << int(hash);
		// MixKeyAndHash: три выхода
		ASSERT_TRUE(state.digest(h));
		// Фиктивный предразделённый ключ
		std::vector <uint8_t> psk(32, 0xA5);
		// Очищаем выходы ручного счёта
		out.clear();
		// Ручной счёт HKDF на три выхода
		manual(hash, chain, psk, 3, out);
		// Смешивание ключа и свёртки по MixKeyAndHash
		ASSERT_TRUE(state.blend(span(psk)));
		// Свёртка состояния как основа
		std::vector <uint8_t> input(h, h + length);
		// Добавляем второй выход к свёртке
		input.insert(input.end(), out[1].begin(), out[1].end());
		// Ожидаемая свёртка после смешивания
		std::vector <uint8_t> expected(length);
		// Ожидаемая свёртка после смешивания
		ASSERT_TRUE(digest::hash(hash, span(input), expected.data(), length));
		ASSERT_TRUE(state.digest(h));
		// Свёртка состояния сошлась с ручным счётом
		EXPECT_EQ(::memcmp(h, expected.data(), length), 0);
		// Шифр на третьем выходе
		noise::cipher_t third;
		// Третий выход заводит шифр
		ASSERT_TRUE(third.start(noise::aead_t::CHACHAPOLY));
		ASSERT_TRUE(third.key(view_t(out[2].data(), noise::KEY)));
		ASSERT_TRUE(third.encrypt(view_t(h, length), view_t(), nullptr, tag));
		// Сбрасываем вместимость буфера метки
		size = sizeof(sealed);
		// Метка симметричного состояния после смешивания
		ASSERT_TRUE(state.seal(view_t(), sealed, size));
		// Метка третьего выхода совпадает с меткой состояния
		EXPECT_EQ(::memcmp(sealed, tag, noise::TAG), 0);
	}
}
/**
 * @brief Счётчик вложений: 2^64-1 запретно на шифровании, расшифровании и установке; при отказе не растёт
 *
 */
TEST(NoiseTest, Nonce){
	// Оба шифра каркаса для проверки счётчика
	const noise::aead_t aeads[] = {noise::aead_t::CHACHAPOLY, noise::aead_t::AESGCM};
	/**
	 * Выполняем итерацию цикла
	 */
	for(auto aead : aeads){
		// Проверяемое состояние шифра
		noise::cipher_t state;
		// Ключ и буферы сообщения
		uint8_t key[32], out[8], back[8], tag[16];
		::memset(key, 7, sizeof(key));
		// Шифр заведён на ключе
		ASSERT_TRUE(state.start(aead));
		ASSERT_TRUE(state.key(view_t(key, 32)));
		// Установка счётчика в 2^64-1 запрещена
		EXPECT_FALSE(state.nonce(UINT64_MAX));
		// Шифрование на последнем разрешённом счётчике
		ASSERT_TRUE(state.nonce(UINT64_MAX - 1));
		ASSERT_TRUE(state.encrypt(view_t(), view_t(key, 8), out, tag));
		// Счётчик дошёл до предела
		EXPECT_EQ(state.nonce(), UINT64_MAX);
		// За пределом счётчика шифрование и расшифрование отказывают
		EXPECT_FALSE(state.encrypt(view_t(), view_t(key, 8), out, tag));
		EXPECT_FALSE(state.decrypt(view_t(), view_t(out, 8), view_t(tag, 16), back));
		// Отказ не трогает счётчик
		EXPECT_EQ(state.nonce(), UINT64_MAX);
		// Явный счётчик 2^64-1 также отклоняется
		EXPECT_FALSE(state.encrypt(UINT64_MAX, view_t(), view_t(key, 8), out, tag));
		EXPECT_FALSE(state.decrypt(UINT64_MAX, view_t(), view_t(out, 8), view_t(tag, 16), back));
		// Явный счётчик равен потоковому и внутренний не трогает
		noise::cipher_t other;
		// Второе состояние шифра заведено
		ASSERT_TRUE(other.start(aead));
		ASSERT_TRUE(other.key(view_t(key, 32)));
		// Буферы второго состояния шифра
		uint8_t out2[8], tag2[16];
		// Шифрование с явным счётчиком
		ASSERT_TRUE(other.encrypt(UINT64_MAX - 1, view_t(), view_t(key, 8), out2, tag2));
		// Внутренний счётчик не тронут явным
		EXPECT_EQ(other.nonce(), 0u);
		EXPECT_EQ(::memcmp(out, out2, 8), 0);
		EXPECT_EQ(::memcmp(tag, tag2, 16), 0);
		// Расшифрование с явным счётчиком
		ASSERT_TRUE(other.decrypt(UINT64_MAX - 1, view_t(), view_t(out2, 8), view_t(tag2, 16), back));
		// Расшифрованный текст совпадает с исходным
		EXPECT_EQ(::memcmp(back, key, 8), 0);
		// Порча метки: счётчик не растёт, выход обнулён
		tag2[0] ^= 1;
		::memset(back, 0xEE, 8);
		// Порченая метка отклоняется
		EXPECT_FALSE(other.decrypt(view_t(), view_t(out2, 8), view_t(tag2, 16), back));
		// Отказ не трогает внутренний счётчик
		EXPECT_EQ(other.nonce(), 0u);
		// Образец нулей для сверки обнуления
		uint8_t zeros[8] = {0, 0, 0, 0, 0, 0, 0, 0};
		// Выход обнулён после отказа
		EXPECT_EQ(::memcmp(back, zeros, 8), 0);
	}
}
/**
 * @brief Перевыработка ключа по определению; счётчик не сбрасывается
 *
 */
TEST(NoiseTest, Rekey){
	// Проверяемое состояние шифра
	noise::cipher_t state;
	// Исходный ключ шифра
	uint8_t key[32];
	/**
	 * Выполняем итерацию цикла
	 */
	for(size_t i = 0; i < 32; i++) key[i] = static_cast <uint8_t> (i * 3);
	// Ключ заведён, счётчик поставлен в 5, перевыработка выполнена
	ASSERT_TRUE(state.start(noise::aead_t::CHACHAPOLY));
	ASSERT_TRUE(state.key(view_t(key, 32)));
	ASSERT_TRUE(state.nonce(5));
	ASSERT_TRUE(state.rekey());
	// Перевыработка не сбрасывает счётчик
	EXPECT_EQ(state.nonce(), 5u);
	// Буфер перевыработанного ключа
	uint8_t fresh[32];
	// Перевыработанный ключ извлечён
	ASSERT_TRUE(state.key(fresh));
	// Вручную: ENCRYPT(k, 2^64-1, пусто, нули[32]) без метки
	uint8_t nonce[12] = {0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	// Буферы эталона перевыработки
	uint8_t zeros[32], expected[32], tag[16];
	::memset(zeros, 0, 32);
	// Эталон ChaCha20-Poly1305
	cipher::chachapoly_t aead;
	// Эталон перевыработки по определению
	ASSERT_TRUE(aead.start(view_t(key, 32), view_t(nonce, 12)));
	ASSERT_TRUE(aead.encrypt(view_t(), view_t(zeros, 32), expected, tag));
	// Перевыработанный ключ совпадает с определением
	EXPECT_EQ(::memcmp(fresh, expected, 32), 0);
	// Перевыработанный ключ отличается от исходного
	EXPECT_NE(::memcmp(fresh, key, 32), 0);
}
/**
 * @brief Односторонний узор: второе состояние после раскола без ключа
 *
 */
TEST(NoiseTest, OneWay){
	// Ключ отвечающего и буферы сообщения
	uint8_t sb[32], pb[32], out[128], back[128];
	// Пара ключей отвечающего
	ASSERT_TRUE(noise::generate(noise::dh_t::X25519, sb, pb));
	// Стороны одностороннего узора
	noise::handshake_t a, b;
	// Стороны одностороннего узора заведены
	ASSERT_TRUE(a.start(noise::pattern_t::N, 0, noise::suite_t(noise::dh_t::X25519, noise::aead_t::AESGCM, digest::hash_t::SHA256), noise::role_t::INITIATOR, view_t()));
	ASSERT_TRUE(b.start(noise::pattern_t::N, 0, noise::suite_t(noise::dh_t::X25519, noise::aead_t::AESGCM, digest::hash_t::SHA256), noise::role_t::RESPONDER, view_t()));
	ASSERT_TRUE(a.remote(view_t(pb, 32)));
	ASSERT_TRUE(b.statics(view_t(sb, 32)));
	// Вместимости буферов сообщения и расшифровки
	size_t size = sizeof(out), got = sizeof(back);
	// Единственное сообщение узора проходит
	ASSERT_TRUE(a.write(span(std::string("hello")), out, size));
	ASSERT_TRUE(b.read(view_t(out, size), back, got));
	// Полезная часть принята целиком
	ASSERT_EQ(got, 5u);
	// Расшифрованное сообщение — «hello»
	EXPECT_EQ(::memcmp(back, "hello", 5), 0);
	// Пары состояний после раскола
	noise::cipher_t a1, a2, b1, b2;
	// Раскол на пары транспортных состояний
	ASSERT_TRUE(a.split(a1, a2));
	ASSERT_TRUE(b.split(b1, b2));
	// Прямые состояния несут ключи
	EXPECT_TRUE(a1.has());
	EXPECT_TRUE(b1.has());
	// Встречные состояния без ключей
	EXPECT_FALSE(a2.has());
	EXPECT_FALSE(b2.has());
	// Буфер метки подлинности
	uint8_t tag[16];
	// Шифрование встречным состоянием отказывает
	EXPECT_FALSE(a2.encrypt(view_t(), view_t(out, 5), out, tag));
	// Буфер ключа собеседника
	uint8_t peer[32];
	// Ключ собеседника у инициатора
	ASSERT_TRUE(a.peer(peer));
	// Ключ собеседника совпадает с открытым ключом
	EXPECT_EQ(::memcmp(peer, pb, 32), 0);
	// Отвечающий ключа собеседника не хранит
	EXPECT_FALSE(b.peer(peer));
}
/**
 * @brief Предел сообщения 65535 целиком: полезная часть 65519 с ключом проходит, 65520 - отказ
 *
 */
TEST(NoiseTest, Message){
	// Стороны рукопожатия предела
	noise::handshake_t a, b;
	// Рукопожатие XX заведено
	ASSERT_TRUE(converse("Noise_XX_25519_ChaChaPoly_SHA256", a, b));
	// Транспортные состояния после раскола
	noise::cipher_t a1, a2, b1, b2;
	// Раскол на пары транспортных состояний
	ASSERT_TRUE(a.split(a1, a2));
	ASSERT_TRUE(b.split(b1, b2));
	// Полезная часть у предела и буферы
	std::vector <uint8_t> payload(noise::MESSAGE - noise::TAG, 0x42), out(noise::MESSAGE), back(noise::MESSAGE);
	// Буфер метки подлинности
	uint8_t tag[16];
	// Полезная часть у предела проходит в обе стороны
	ASSERT_TRUE(a1.encrypt(view_t(), span(payload), out.data(), tag));
	ASSERT_TRUE(b1.decrypt(view_t(), view_t(out.data(), payload.size()), view_t(tag, 16), back.data()));
	// Добавляем байт за предел
	payload.push_back(0x42);
	// Байт за пределом отклоняется
	EXPECT_FALSE(a1.encrypt(view_t(), span(payload), out.data(), tag));
	// Отказ не расходует счётчик
	EXPECT_EQ(a1.nonce(), 1u);
	// Первое сообщение NN без ключа: 32 + полезная часть, предел 65503
	noise::handshake_t c;
	// Сторона узора NN без ключа заведена
	ASSERT_TRUE(c.start(span(std::string("Noise_NN_25519_ChaChaPoly_SHA256")), noise::role_t::INITIATOR, view_t()));
	// Полезная часть и буфер сообщения без ключа
	std::vector <uint8_t> plain(noise::MESSAGE - noise::KEY, 1), place(noise::MESSAGE + 64);
	// Вместимость буфера сообщения
	size_t size = place.size();
	// Первое сообщение без ключа записано
	ASSERT_TRUE(c.write(span(plain), place.data(), size));
	// Сообщение занимает ровно предел
	EXPECT_EQ(size, noise::MESSAGE);
	// Вторая сторона узора NN
	noise::handshake_t d;
	// Вторая сторона заведена
	ASSERT_TRUE(d.start(span(std::string("Noise_NN_25519_ChaChaPoly_SHA256")), noise::role_t::INITIATOR, view_t()));
	// Добавляем байт за предел
	plain.push_back(1);
	// Сбрасываем вместимость буфера
	size = place.size();
	// Полезная часть за пределом отклоняется
	EXPECT_FALSE(d.write(span(plain), place.data(), size));
	// Малая вместимость - отказ
	noise::handshake_t e;
	// Третья сторона узора NN
	ASSERT_TRUE(e.start(span(std::string("Noise_NN_25519_ChaChaPoly_SHA256")), noise::role_t::INITIATOR, view_t()));
	// Вместимость меньше временного ключа
	size = 31;
	// Малая вместимость отклоняется
	EXPECT_FALSE(e.write(view_t(), place.data(), size));
}
/**
 * @brief Расхождение пролога, ход не в очередь, чужой ключ не сошёлся, порча метки, состояние после отказа
 *
 */
TEST(NoiseTest, Refusals){
	// Имя проверяемого протокола
	const std::string name = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
	// Ключи сторон и буферы сообщений
	uint8_t sa[32], pa[32], sb[32], pb[32], out[256], back[256];
	// Пары ключей обеих сторон
	ASSERT_TRUE(noise::generate(noise::dh_t::X25519, sa, pa));
	ASSERT_TRUE(noise::generate(noise::dh_t::X25519, sb, pb));
	// Пролог: у сторон разный - первое сообщение открыто и проходит, второе не сходится
	{
		// Стороны с разными прологами
		noise::handshake_t a, b;
		// Стороны заведены на разных прологах
		ASSERT_TRUE(a.start(span(name), noise::role_t::INITIATOR, span(std::string("one"))));
		ASSERT_TRUE(b.start(span(name), noise::role_t::RESPONDER, span(std::string("two"))));
		ASSERT_TRUE(a.statics(view_t(sa, 32)));
		ASSERT_TRUE(b.statics(view_t(sb, 32)));
		// Вместимости буферов сообщения и расшифровки
		size_t size = sizeof(out), got = sizeof(back);
		// Первое сообщение с разными прологами проходит
		ASSERT_TRUE(a.write(view_t(), out, size));
		ASSERT_TRUE(b.read(view_t(out, size), back, got));
		// Сбрасываем вместимости буферов
		size = sizeof(out); got = sizeof(back);
		// Второе сообщение записано
		ASSERT_TRUE(b.write(view_t(), out, size));
		// Второе сообщение с разными прологами отклоняется
		EXPECT_FALSE(a.read(view_t(out, size), back, got));
		// Сторона-инициатор после отказа не ждёт хода
		EXPECT_EQ(a.step(), noise::step_t::NONE);
		// Повторное чтение после отказа отклоняется
		EXPECT_FALSE(a.read(view_t(out, size), back, got));
		// Пара состояний для раскола после отказа
		noise::cipher_t one, two;
		// Раскол после отказа отклоняется
		EXPECT_FALSE(a.split(one, two));
	}
	// Ход не в очередь
	{
		// Сторона для проверки очерёдности
		noise::handshake_t a;
		// Сторона заведена
		ASSERT_TRUE(a.start(span(name), noise::role_t::INITIATOR, view_t()));
		ASSERT_TRUE(a.statics(view_t(sa, 32)));
		// Сторона ждёт записи
		EXPECT_EQ(a.step(), noise::step_t::WRITE);
		// Вместимости буферов сообщения и расшифровки
		size_t size = sizeof(out), got = sizeof(back);
		// Чтение вместо записи отклоняется
		EXPECT_FALSE(a.read(view_t(out, 32), back, got));
		// Очерёдность после отказа не тронута
		EXPECT_EQ(a.step(), noise::step_t::WRITE);
		// Первое сообщение записано
		ASSERT_TRUE(a.write(view_t(), out, size));
		// Сторона ждёт чтения
		EXPECT_EQ(a.step(), noise::step_t::READ);
		// Сбрасываем вместимость буфера сообщения
		size = sizeof(out);
		// Запись вместо чтения отклоняется
		EXPECT_FALSE(a.write(view_t(), out, size));
		// Ключи после первого сообщения не принимаются
		EXPECT_FALSE(a.statics(view_t(sa, 32)));
		EXPECT_FALSE(a.remote(view_t(pb, 32)));
		EXPECT_FALSE(a.ephemeral(view_t(sa, 32)));
		// Область предразделённого ключа
		view_t psk(sa, 32);
		// Предразделённый ключ после первого сообщения отклоняется
		EXPECT_FALSE(a.psks(&psk, 1));
	}
	// Чужой постоянный ключ задан заранее и не совпал с принятым
	{
		// Стороны с заданным заранее чужим ключом
		noise::handshake_t a, b;
		// Сторона заведена заново
		ASSERT_TRUE(a.start(span(name), noise::role_t::INITIATOR, view_t()));
		ASSERT_TRUE(b.start(span(name), noise::role_t::RESPONDER, view_t()));
		ASSERT_TRUE(a.statics(view_t(sa, 32)));
		ASSERT_TRUE(b.statics(view_t(sb, 32)));
		ASSERT_TRUE(a.remote(view_t(pa, 32)));
		// Вместимости буферов сообщения и расшифровки
		size_t size = sizeof(out), got = sizeof(back);
		// Первое сообщение с заданным чужим ключом проходит
		ASSERT_TRUE(a.write(view_t(), out, size));
		ASSERT_TRUE(b.read(view_t(out, size), back, got));
		// Сбрасываем вместимости буферов
		size = sizeof(out); got = sizeof(back);
		// Второе сообщение записано
		ASSERT_TRUE(b.write(view_t(), out, size));
		// Второе сообщение с несошедшимся чужим ключом отклоняется
		EXPECT_FALSE(a.read(view_t(out, size), back, got));
		// Сторона-инициатор после отказа не ждёт хода
		EXPECT_EQ(a.step(), noise::step_t::NONE);
	}
	// Порча метки
	{
		// Стороны для порчи метки
		noise::handshake_t a, b;
		// Сторона заведена заново
		ASSERT_TRUE(a.start(span(name), noise::role_t::INITIATOR, view_t()));
		ASSERT_TRUE(b.start(span(name), noise::role_t::RESPONDER, view_t()));
		ASSERT_TRUE(a.statics(view_t(sa, 32)));
		ASSERT_TRUE(b.statics(view_t(sb, 32)));
		// Вместимости буферов сообщения и расшифровки
		size_t size = sizeof(out), got = sizeof(back);
		// Первое сообщение проходит
		ASSERT_TRUE(a.write(view_t(), out, size));
		ASSERT_TRUE(b.read(view_t(out, size), back, got));
		// Сбрасываем вместимости буферов
		size = sizeof(out); got = sizeof(back);
		// Второе сообщение с полезной частью записано
		ASSERT_TRUE(b.write(span(std::string("payload")), out, size));
		// Портим последний байт метки
		out[size - 1] ^= 0x80;
		// Порченая метка отклоняется
		EXPECT_FALSE(a.read(view_t(out, size), back, got));
		// Полезная часть не выдана
		EXPECT_EQ(got, 0u);
		EXPECT_EQ(a.step(), noise::step_t::NONE);
		// Короткое сообщение
		noise::handshake_t c;
		// Отвечающий короткого сообщения заведён
		ASSERT_TRUE(c.start(span(name), noise::role_t::RESPONDER, view_t()));
		ASSERT_TRUE(c.statics(view_t(sb, 32)));
		// Сбрасываем вместимость буфера расшифровки
		got = sizeof(back);
		// Короткое сообщение отклоняется
		EXPECT_FALSE(c.read(view_t(out, 31), back, got));
		// Отвечающий после отказа не ждёт хода
		EXPECT_EQ(c.step(), noise::step_t::NONE);
	}
	// Ключи: чужие длины, лишние psk, недостающие ключи, 448, до заведения
	{
		// Незаведённая сторона
		noise::handshake_t a;
		// Незаведённая сторона не ждёт хода
		EXPECT_EQ(a.step(), noise::step_t::NONE);
		// Ключи незаведённой стороны отклоняются
		EXPECT_FALSE(a.statics(view_t(sa, 32)));
		EXPECT_FALSE(a.start(span(std::string("Noise_XX_448_ChaChaPoly_SHA256")), noise::role_t::INITIATOR, view_t()));
		EXPECT_FALSE(a.start(span(name), noise::role_t::NONE, view_t()));
		EXPECT_FALSE(a.start(noise::pattern_t::NN, 0x08, noise::suite_t(noise::dh_t::X25519, noise::aead_t::CHACHAPOLY, digest::hash_t::SHA256), noise::role_t::INITIATOR, view_t()));
		// Сторона заведена
		ASSERT_TRUE(a.start(span(name), noise::role_t::INITIATOR, view_t()));
		// Постоянный ключ чужой длины отклоняется
		EXPECT_FALSE(a.statics(view_t(sa, 31)));
		EXPECT_FALSE(a.remote(view_t(pb, 33)));
		// Ключей больше положенных положений узора
		view_t list[5] = {view_t(sa, 32), view_t(sa, 32), view_t(sa, 32), view_t(sa, 32), view_t(sa, 32)};
		// Лишние предразделённые ключи отклоняются
		EXPECT_FALSE(a.psks(list, 5));
		// Предразделённый ключ не той длины
		view_t shorter(sa, 31);
		// Предразделённый ключ чужой длины отклоняется
		EXPECT_FALSE(a.psks(&shorter, 1));
		EXPECT_FALSE(a.psks(nullptr, 1));
		// XX без своего постоянного ключа: отказ первого сообщения
		size_t size = sizeof(out);
		// Запись без своего постоянного ключа отклоняется
		EXPECT_FALSE(a.write(view_t(), out, size));
		// psk задан без видоизменения - отказ по числу положений
		noise::handshake_t c;
		// Сторона с предразделённым ключом заведена
		ASSERT_TRUE(c.start(span(name), noise::role_t::INITIATOR, view_t()));
		ASSERT_TRUE(c.statics(view_t(sa, 32)));
		// Область предразделённого ключа
		view_t psk(sa, 32);
		// Предразделённый ключ принят
		ASSERT_TRUE(c.psks(&psk, 1));
		// Сбрасываем вместимость буфера сообщения
		size = sizeof(out);
		// Запись с ключом без видоизменения отклоняется
		EXPECT_FALSE(c.write(view_t(), out, size));
		// Видоизменение без ключа
		noise::handshake_t d;
		// Сторона с видоизменением psk3 заведена
		ASSERT_TRUE(d.start(span(std::string("Noise_XXpsk3_25519_ChaChaPoly_SHA256")), noise::role_t::INITIATOR, view_t()));
		ASSERT_TRUE(d.statics(view_t(sa, 32)));
		// Сбрасываем вместимость буфера сообщения
		size = sizeof(out);
		// Запись с видоизменением без своего ключа отклоняется
		EXPECT_FALSE(d.write(view_t(), out, size));
	}
	// Состояния шифра: без функции, без ключа, чужая длина ключа
	{
		// Незаведённое состояние шифра
		noise::cipher_t state;
		// Буфер метки подлинности
		uint8_t tag[16];
		// Шифр без функции и ключ без шифра отклоняются
		EXPECT_FALSE(state.start(noise::aead_t::NONE));
		EXPECT_FALSE(state.key(view_t(sa, 32)));
		// Шифр ChaCha20-Poly1305 заведён
		ASSERT_TRUE(state.start(noise::aead_t::CHACHAPOLY));
		// Ключ чужой длины отклоняется
		EXPECT_FALSE(state.key(view_t(sa, 31)));
		EXPECT_FALSE(state.has());
		EXPECT_FALSE(state.encrypt(view_t(), view_t(sa, 8), out, tag));
		EXPECT_FALSE(state.rekey());
		EXPECT_FALSE(state.key(out));
		// Незаведённое симметричное состояние
		noise::symmetric_t sym;
		// Заведение с пустым именем и без DH отклоняется
		EXPECT_FALSE(sym.start(view_t(), noise::suite_t(noise::dh_t::X25519, noise::aead_t::CHACHAPOLY, digest::hash_t::SHA256)));
		EXPECT_FALSE(sym.start(span(name), noise::suite_t(noise::dh_t::NONE, noise::aead_t::CHACHAPOLY, digest::hash_t::SHA256)));
		EXPECT_FALSE(sym.key(view_t(sa, 32)));
		// Хеш рукопожатия не тронут при несошедшейся метке
		noise::symmetric_t keyed;
		// Симметричное состояние с ключом заведено
		ASSERT_TRUE(keyed.start(span(name), noise::suite_t(noise::dh_t::X25519, noise::aead_t::CHACHAPOLY, digest::hash_t::SHA256)));
		ASSERT_TRUE(keyed.key(view_t(sa, 32)));
		// Буферы хешей до и после и метки
		uint8_t before[32], after[32], sealed[64];
		// Вместимость буфера печати
		size_t size = sizeof(sealed);
		// Полезная часть запечатана с меткой
		ASSERT_TRUE(keyed.seal(span(std::string("abc")), sealed, size));
		// Печать — полезная часть плюс метка
		ASSERT_EQ(size, 3u + noise::TAG);
		// Хеш рукопожатия до порчи
		ASSERT_TRUE(keyed.digest(before));
		// Портим последний байт метки
		sealed[size - 1] ^= 1;
		// Вместимость буфера расшифровки
		size_t got = sizeof(out);
		// Порченая метка отклоняется
		EXPECT_FALSE(keyed.open(view_t(sealed, size), out, got));
		// Хеш рукопожатия после отказа
		ASSERT_TRUE(keyed.digest(after));
		// Хеш рукопожатия не тронут отказом
		EXPECT_EQ(::memcmp(before, after, 32), 0);
		// Точка малого порядка: DH отказывает
		uint8_t zeros[32], shared[32];
		::memset(zeros, 0, 32);
		// Согласование с точкой малого порядка отклоняется
		EXPECT_FALSE(noise::agree(noise::dh_t::X25519, view_t(sa, 32), view_t(zeros, 32), shared));
		// Согласование с полноценным ключом проходит
		EXPECT_TRUE(noise::agree(noise::dh_t::X25519, view_t(sa, 32), view_t(pb, 32), shared));
	}
}
/**
 * @brief Обе роли по всем восьми наборам со случайными ключами и полезной частью, включая хеш и ключ собеседника
 *
 */
TEST(NoiseTest, Suites){
	// Имена протоколов по восьми наборам
	const char * names[] = {
		"Noise_XX_25519_ChaChaPoly_SHA256", "Noise_XX_25519_ChaChaPoly_SHA512", "Noise_XX_25519_ChaChaPoly_BLAKE2s", "Noise_XX_25519_ChaChaPoly_BLAKE2b",
		"Noise_XX_25519_AESGCM_SHA256", "Noise_XX_25519_AESGCM_SHA512", "Noise_XX_25519_AESGCM_BLAKE2s", "Noise_XX_25519_AESGCM_BLAKE2b"
	};
	/**
	 * Выполняем итерацию цикла
	 */
	for(auto name : names){
		// Стороны очередного набора
		noise::handshake_t a, b;
		// Рукопожатие очередного набора завершается
		ASSERT_TRUE(converse(name, a, b)) << name;
		// Буферы хешей и ключей сторон
		uint8_t ha[64], hb[64], pa[32], pb[32], sa[32], sb[32];
		// Хеши рукопожатия обеих сторон
		ASSERT_TRUE(a.digest(ha));
		ASSERT_TRUE(b.digest(hb));
		// Хеши рукопожатия обеих сторон совпадают
		EXPECT_EQ(::memcmp(ha, hb, a.length()), 0) << name;
		// Ключи собеседника и свои у обеих сторон
		ASSERT_TRUE(a.peer(pb));
		ASSERT_TRUE(b.self(sb));
		ASSERT_TRUE(b.peer(pa));
		ASSERT_TRUE(a.self(sa));
		// Ключи собеседника сходятся со своими у обеих сторон
		EXPECT_EQ(::memcmp(pb, sb, 32), 0) << name;
		EXPECT_EQ(::memcmp(pa, sa, 32), 0) << name;
		// Транспортные состояния после раскола
		noise::cipher_t a1, a2, b1, b2;
		// Раскол на пары транспортных состояний
		ASSERT_TRUE(a.split(a1, a2));
		ASSERT_TRUE(b.split(b1, b2));
		// Буферы транспортного сообщения
		uint8_t out[64], tag[16], back[64];
		// Сообщение от отвечающего проходит встречным состоянием
		ASSERT_TRUE(b2.encrypt(view_t(), span(std::string("from responder")), out, tag));
		ASSERT_TRUE(a2.decrypt(view_t(), view_t(out, 14), view_t(tag, 16), back));
		// Расшифрованный текст совпадает с сообщением от отвечающего
		EXPECT_EQ(::memcmp(back, "from responder", 14), 0) << name;
		// Сообщение от инициатора проходит прямым состоянием
		ASSERT_TRUE(a1.encrypt(view_t(), span(std::string("from initiator")), out, tag));
		ASSERT_TRUE(b1.decrypt(view_t(), view_t(out, 14), view_t(tag, 16), back));
		// Расшифрованный текст совпадает с сообщением от инициатора
		EXPECT_EQ(::memcmp(back, "from initiator", 14), 0) << name;
		// Перекрёстные состояния не сходятся
		ASSERT_TRUE(a1.encrypt(view_t(), span(std::string("x")), out, tag));
		// Перекрёстные состояния не сходятся
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
	// Область имени протокола
	const view_t name(NAME, sizeof(NAME) - 1);
	// Полезные части трёх сообщений
	static const uint8_t ONE[] = "one", TWO[] = "two", THREE[] = "three";
	// Ключи сторон и буферы сообщений
	uint8_t sa[32], pa[32], sb[32], pb[32], out[256], back[256], tag[16];
	// Пары ключей обеих сторон
	ASSERT_TRUE(noise::generate(noise::dh_t::X25519, sa, pa));
	ASSERT_TRUE(noise::generate(noise::dh_t::X25519, sb, pb));
	// Стороны рукопожатия под паёком
	noise::handshake_t a, b;
	// Транспортные состояния после раскола
	noise::cipher_t a1, a2, b1, b2;
	// Нарастающий признак успеха прогона
	bool status = true;
	{
		// Паёк на ноль выделений
		starve::ration_t ration(0);
		// Заведение обеих сторон под паёком
		status = (a.start(name, noise::role_t::INITIATOR, view_t()) && b.start(name, noise::role_t::RESPONDER, view_t()));
		// Передача ключей обеих сторон
		status = (status && a.statics(view_t(sa, 32)) && b.statics(view_t(sb, 32)) && a.remote(view_t(pb, 32)));
		// Вместимости буферов сообщения и расшифровки
		size_t size = sizeof(out), got = sizeof(back);
		// Первое сообщение проходит без выделений
		status = (status && a.write(view_t(ONE, 3), out, size) && b.read(view_t(out, size), back, got) && (got == 3));
		// Сбрасываем вместимости буферов
		size = sizeof(out); got = sizeof(back);
		// Второе сообщение проходит без выделений
		status = (status && b.write(view_t(TWO, 3), out, size) && a.read(view_t(out, size), back, got) && (got == 3));
		// Раскол проходит без выделений
		status = (status && a.split(a1, a2) && b.split(b1, b2));
		// Транспортное сообщение проходит без выделений
		status = (status && a1.encrypt(view_t(), view_t(THREE, 5), out, tag) && b1.decrypt(view_t(), view_t(out, 5), view_t(tag, 16), back));
		// Останавливаем учёт выделений
		ration.stop();
	}
	// Весь прогон прошёл без единого выделения
	EXPECT_TRUE(status);
	// Расшифрованное сообщение — «three»
	EXPECT_EQ(::memcmp(back, "three", 5), 0);
}
/**
 * @brief Годность набора примитивов: ровно одно из DH и KEM, имя шифра и имя хеша
 *
 */
TEST(NoiseTest, Valid){
	// Классический набор с X25519 годен при любом известном шифре и хеше
	EXPECT_TRUE(noise::valid(noise::suite_t(noise::dh_t::X25519, noise::aead_t::CHACHAPOLY, digest::hash_t::SHA256)));
	EXPECT_TRUE(noise::valid(noise::suite_t(noise::dh_t::X25519, noise::aead_t::AESGCM, digest::hash_t::SHA512)));
	EXPECT_TRUE(noise::valid(noise::suite_t(noise::dh_t::X25519, noise::aead_t::CHACHAPOLY, digest::hash_t::BLAKE2S256)));
	EXPECT_TRUE(noise::valid(noise::suite_t(noise::dh_t::X25519, noise::aead_t::AESGCM, digest::hash_t::BLAKE2B512)));
	// Набор PQNoise с KEM годен
	EXPECT_TRUE(noise::valid(noise::suite_t(noise::kem_t::X25519MLKEM768, noise::aead_t::CHACHAPOLY, digest::hash_t::SHA256)));
	EXPECT_TRUE(noise::valid(noise::suite_t(noise::kem_t::MLKEM768, noise::aead_t::AESGCM, digest::hash_t::SHA512)));
	// Пустой набор не годен
	EXPECT_FALSE(noise::valid(noise::suite_t()));
	// Набор без функции обмена и без KEM не годен
	EXPECT_FALSE(noise::valid(noise::suite_t(noise::dh_t::NONE, noise::aead_t::CHACHAPOLY, digest::hash_t::SHA256)));
	// Набор с чужим шифром не годен
	EXPECT_FALSE(noise::valid(noise::suite_t(noise::dh_t::X25519, noise::aead_t::NONE, digest::hash_t::SHA256)));
	// Набор с чужим хешем не годен
	EXPECT_FALSE(noise::valid(noise::suite_t(noise::dh_t::X25519, noise::aead_t::CHACHAPOLY, digest::hash_t::NONE)));
	// Набор с хешем вне перечня каркаса не годен
	EXPECT_FALSE(noise::valid(noise::suite_t(noise::dh_t::X25519, noise::aead_t::CHACHAPOLY, digest::hash_t::MD5)));
}
