/**
 * @file acme.cpp
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
 * @brief Модуль протокола ACME — сообщения управления сертификатами по RFC 8555
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочный файл модуля
 */
#include <acme/acme.hpp>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <digest/hash.hpp>

/**
 * Стандартные заголовочные файлы
 */
#include <cstring>

/**
 * @brief Основное пространство имён
 *
 */
namespace nts {
	/**
	 * Подписываемся на стандартное пространство имён
	 */
	using namespace std;

	/**
	 * @brief Внутренние сущности модуля протокола ACME
	 *
	 */
	namespace {
		/**
		 * @brief Разборщик записей JSON ответов службы ACME
		 *
		 * @details Разбирается подмножество JSON ответов ACME: объекты, массивы,
		 *          строки с экранировками, числа, булевы значения и null. Просмотры
		 *          строк указывают внутрь разбираемого текста, экранированные строки
		 *          материализуются
		 *
		 */
		typedef class Json {
			public:
				/**
				 * @brief Виды значений JSON
				 *
				 */
				enum class kind_t : uint8_t {
					// Значение не установлено
					NONE = 0x00,
					// Объект
					OBJECT = 0x01,
					// Массив
					ARRAY = 0x02,
					// Строка
					STRING = 0x03,
					// Число
					NUMBER = 0x04,
					// Булево значение либо null
					VALUE = 0x05
				};
				/**
				 * @brief Значение JSON
				 *
				 */
				typedef struct Value {
					// Вид значения
					kind_t kind;
					// Просмотр строки либо числа внутри текста
					view_t view;
					// Материализованная строка с экранировками
					string text;
					// Набор членов объекта
					vector <pair <string, Value>> members;
					// Набор значений массива
					vector <Value> items;
					/**
					 * @brief Конструктор
					 *
					 */
					Value() noexcept : kind(kind_t::NONE) {}
				} value_t;
			private:
				// Просмотр разбираемого текста
				view_t _text;
				// Позиция разбора
				size_t _position;
			private:
				/**
				 * @brief Метод пропуска промежутка
				 *
				 */
				void gap() noexcept {
					/**
					 * Пропускаем символы промежутка
					 */
					while((this->_position < this->_text.size) && ((this->_text.data[this->_position] == ' ') || (this->_text.data[this->_position] == '\t') || (this->_text.data[this->_position] == '\r') || (this->_text.data[this->_position] == '\n')))
						// Переносим позицию
						this->_position++;
				}
				/**
				 * @brief Метод разбора строки
				 *
				 * @param result значение, в которое помещается строка
				 * @return       признак успешности разбора
				 *
				 */
				bool string(value_t & result) {
					// Если строки нет
					if((this->_position >= this->_text.size) || (this->_text.data[this->_position] != '"'))
						// Выводим отказ разбора
						return false;
					// Переносим позицию за кавычку
					this->_position++;
					// Начало строки
					const size_t start = this->_position;
					// Признак экранировок в строке
					bool escaped = false;
					/**
					 * Выполняем поиск закрывающей кавычки
					 */
					while(this->_position < this->_text.size){
						// Символ строки
						const uint8_t symbol = this->_text.data[this->_position];
						// Если встретилась экранировка
						if(symbol == '\\'){
							// Запоминаем наличие экранировок
							escaped = true;
							// Переносим позицию за экранированный символ
							this->_position += 2;
							// Переходим к следующему символу
							continue;
						}
						// Если встретилась закрывающая кавычка
						if(symbol == '"')
							// Выходим из обхода
							break;
						// Переносим позицию
						this->_position++;
					}
					// Если закрывающей кавычки нет
					if(this->_position >= this->_text.size)
						// Выводим отказ разбора
						return false;
					// Запоминаем вид значения
					result.kind = kind_t::STRING;
					// Если экранировок нет: запоминаем просмотр строки
					if(!escaped)
						// Запоминаем просмотр строки
						result.view = view_t(this->_text.data + start, this->_position - start);
					// Иначе строка материализуется
					else {
						// Очищаем накопитель строки перед материализацией экранировок
						result.text.clear();
						// Занимаем место под итог
						result.text.reserve(this->_position - start);
						/**
						 * Выполняем разбор строки с экранировками
						 */
						for(size_t position = start; position < this->_position; position++){
							// Символ строки
							const uint8_t symbol = this->_text.data[position];
							// Если символ не экранировка
							if(symbol != '\\'){
								// Переносим символ
								result.text += static_cast <char> (symbol);
								// Переходим к следующему символу
								continue;
							}
							// Если экранированного символа нет
							if(position + 1 >= this->_position)
								// Выводим отказ разбора
								return false;
							/**
							 * Экранированный символ
							 */
							switch(this->_text.data[++position]){
								// Кавычка
								case '"': result.text += '"'; break;
								// Обратная черта
								case '\\': result.text += '\\'; break;
								// Черта
								case '/': result.text += '/'; break;
								// Возврат на символ
								case 'b': result.text += '\b'; break;
								// Перевод страницы
								case 'f': result.text += '\f'; break;
								// Перевод строки
								case 'n': result.text += '\n'; break;
								// Возврат каретки
								case 'r': result.text += '\r'; break;
								// Табуляция
								case 't': result.text += '\t'; break;
								// Код Unicode: ответы ACME их не несут в именах и адресах
								case 'u': {
									// Если записи кода нет
									if(position + 4 >= this->_position)
										// Выводим отказ разбора
										return false;
									// Значение кода
									uint32_t code = 0;
									/**
									 * Выполняем разбор четырёх разрядов кода
									 */
									for(size_t digit = 0; digit < 4; digit++){
										// Символ разряда
										const uint8_t item = this->_text.data[position + 1 + digit];
										// Переносим разряд
										code <<= 4;
										// Символ цифры
										if((item >= '0') && (item <= '9'))
											// Накапливаем разряд
											code |= (item - '0');
										// Символ строчной буквы
										else if((item >= 'a') && (item <= 'f'))
											// Накапливаем разряд
											code |= (item - 'a' + 10);
										// Символ заглавной буквы
										else if((item >= 'A') && (item <= 'F'))
											// Накапливаем разряд
											code |= (item - 'A' + 10);
										// Символ чужой
										else
											// Выводим отказ разбора
											return false;
									}
									// Переносим позицию за запись кода
									position += 4;
									// Кодируем значение в UTF-8
									if(code < 0x80)
										// Переносим однобайтовый символ
										result.text += static_cast <char> (code);
									// Двухбайтовый символ
									else if(code < 0x800){
										// Переносим символ
										result.text += static_cast <char> (0xC0 | (code >> 6));
										// Дописываем продолжение символа
										result.text += static_cast <char> (0x80 | (code & 0x3F));
									// Трёхбайтовый символ
									} else {
										// Переносим символ
										result.text += static_cast <char> (0xE0 | (code >> 12));
										// Дописываем продолжение символа
										result.text += static_cast <char> (0x80 | ((code >> 6) & 0x3F));
										// Дописываем завершение символа
										result.text += static_cast <char> (0x80 | (code & 0x3F));
									}
								} break;
								// Экранировка чужая
								default:
									// Выводим отказ разбора
									return false;
							}
						}
					}
					// Переносим позицию за кавычку
					this->_position++;
					// Выводим успешность разбора
					return true;
				}
				/**
				 * @brief Метод разбора значения
				 *
				 * @param result значение, в которое помещается итог
				 * @param depth  глубина вложенности записи
				 * @return       признак успешности разбора
				 *
				 */
				bool parse(value_t & result, const uint8_t depth) {
					// Если вложенность чрезмерна
					if(depth > 32)
						// Выводим отказ разбора
						return false;
					// Пропускаем промежуток
					this->gap();
					// Если текст кончился
					if(this->_position >= this->_text.size)
						// Выводим отказ разбора
						return false;
					/**
					 * Символ начала значения
					 */
					switch(this->_text.data[this->_position]){
						// Объект
						case '{': {
							// Запоминаем вид значения
							result.kind = kind_t::OBJECT;
							// Переносим позицию
							this->_position++;
							// Пропускаем промежуток
							this->gap();
							// Если объект пуст
							if((this->_position < this->_text.size) && (this->_text.data[this->_position] == '}')){
								// Переносим позицию
								this->_position++;
								// Выводим успешность разбора
								return true;
							}
							/**
							 * Выполняем разбор членов объекта
							 */
							while(true){
								// Имя члена
								value_t name;
								// Пропускаем промежуток
								this->gap();
								// Если имени нет
								if(!this->string(name))
									// Выводим отказ разбора
									return false;
								// Пропускаем промежуток
								this->gap();
								// Если двоеточия нет
								if((this->_position >= this->_text.size) || (this->_text.data[this->_position] != ':'))
									// Выводим отказ разбора
									return false;
								// Переносим позицию
								this->_position++;
								// Значение члена
								value_t value;
								// Если значение разобрать не удалось
								if(!this->parse(value, depth + 1))
									// Выводим отказ разбора
									return false;
								// Запоминаем член объекта
								result.members.emplace_back(((name.view.size != 0) ? std::string(reinterpret_cast <const char *> (name.view.data), name.view.size) : name.text), std::move(value));
								// Пропускаем промежуток
								this->gap();
								// Если объект кончился
								if((this->_position < this->_text.size) && (this->_text.data[this->_position] == '}')){
									// Переносим позицию
									this->_position++;
									// Выводим успешность разбора
									return true;
								}
								// Если разделителя нет
								if((this->_position >= this->_text.size) || (this->_text.data[this->_position] != ','))
									// Выводим отказ разбора
									return false;
								// Переносим позицию
								this->_position++;
							}
						}
						// Массив
						case '[': {
							// Запоминаем вид значения
							result.kind = kind_t::ARRAY;
							// Переносим позицию
							this->_position++;
							// Пропускаем промежуток
							this->gap();
							// Если массив пуст
							if((this->_position < this->_text.size) && (this->_text.data[this->_position] == ']')){
								// Переносим позицию
								this->_position++;
								// Выводим успешность разбора
								return true;
							}
							/**
							 * Выполняем разбор значений массива
							 */
							while(true){
								// Значение массива
								value_t value;
								// Если значение разобрать не удалось
								if(!this->parse(value, depth + 1))
									// Выводим отказ разбора
									return false;
								// Запоминаем значение массива
								result.items.emplace_back(std::move(value));
								// Пропускаем промежуток
								this->gap();
								// Если массив кончился
								if((this->_position < this->_text.size) && (this->_text.data[this->_position] == ']')){
									// Переносим позицию
									this->_position++;
									// Выводим успешность разбора
									return true;
								}
								// Если разделителя нет
								if((this->_position >= this->_text.size) || (this->_text.data[this->_position] != ','))
									// Выводим отказ разбора
									return false;
								// Переносим позицию
								this->_position++;
							}
						}
						// Строка
						case '"':
							// Выводим итог разбора строки
							return this->string(result);
						// Булево значение true
						case 't': {
							// Если записи значения нет
							if((this->_position + 4 > this->_text.size) || (::memcmp(this->_text.data + this->_position, "true", 4) != 0))
								// Выводим отказ разбора
								return false;
							// Запоминаем вид значения
							result.kind = kind_t::VALUE;
							// Запоминаем просмотр значения
							result.view = view_t(this->_text.data + this->_position, 4);
							// Переносим позицию
							this->_position += 4;
							// Выводим успешность разбора
							return true;
						}
						// Булево значение false
						case 'f': {
							// Если записи значения нет
							if((this->_position + 5 > this->_text.size) || (::memcmp(this->_text.data + this->_position, "false", 5) != 0))
								// Выводим отказ разбора
								return false;
							// Запоминаем вид значения
							result.kind = kind_t::VALUE;
							// Запоминаем просмотр значения
							result.view = view_t(this->_text.data + this->_position, 5);
							// Переносим позицию
							this->_position += 5;
							// Выводим успешность разбора
							return true;
						}
						// Значение null
						case 'n': {
							// Если записи значения нет
							if((this->_position + 4 > this->_text.size) || (::memcmp(this->_text.data + this->_position, "null", 4) != 0))
								// Выводим отказ разбора
								return false;
							// Запоминаем вид значения
							result.kind = kind_t::VALUE;
							// Запоминаем просмотр значения
							result.view = view_t(this->_text.data + this->_position, 4);
							// Переносим позицию
							this->_position += 4;
							// Выводим успешность разбора
							return true;
						}
						// Число
						default: {
							// Символ начала числа
							const uint8_t symbol = this->_text.data[this->_position];
							// Если числа нет
							if((symbol != '-') && ((symbol < '0') || (symbol > '9')))
								// Выводим отказ разбора
								return false;
							// Начало числа
							const size_t start = this->_position;
							/**
							 * Выполняем поиск конца числа
							 */
							while(this->_position < this->_text.size){
								// Символ числа
								const uint8_t item = this->_text.data[this->_position];
								// Если символ числовой
								if(((item >= '0') && (item <= '9')) || (item == '-') || (item == '+') || (item == '.') || (item == 'e') || (item == 'E'))
									// Переносим позицию
									this->_position++;
								// Иначе число кончилось
								else
									// Выходим из обхода
									break;
							}
							// Запоминаем вид значения
							result.kind = kind_t::NUMBER;
							// Запоминаем просмотр числа
							result.view = view_t(this->_text.data + start, this->_position - start);
							// Выводим успешность разбора
							return true;
						}
					}
				}
			public:
				/**
				 * @brief Метод разбора записи целиком
				 *
				 * @param text   просмотр разбираемого текста
				 * @param result значение, в которое помещается итог
				 * @return       признак успешности разбора
				 *
				 */
				bool parse(const view_t & text, value_t & result) {
					// Запоминаем просмотр текста
					this->_text = text;
					// Сбрасываем позицию разбора
					this->_position = 0;
					// Если запись пуста
					if(text.size == 0)
						// Выводим отказ разбора
						return false;
					// Если значение разобрать не удалось
					if(!this->parse(result, 0))
						// Выводим отказ разбора
						return false;
					// Пропускаем промежуток
					this->gap();
					// Выводим отсутствие хвоста за записью
					return (this->_position == this->_text.size);
				}
			public:
				/**
				 * @brief Конструктор
				 *
				 */
				Json() noexcept : _position(0) {}
		} json_t;

		/**
		 * @brief Функция извлечения члена объекта по имени
		 *
		 * @param object разобранный объект
		 * @param name   имя искомого члена
		 * @return       указатель на значение члена либо пустой указатель
		 *
		 */
		static const json_t::value_t * member(const json_t::value_t & object, const char * name) noexcept {
			// Если значение не объект
			if(object.kind != json_t::kind_t::OBJECT)
				// Выводим отсутствие члена
				return nullptr;
			/**
			 * Выполняем обход членов объекта
			 */
			for(size_t position = 0; position < object.members.size(); position++){
				// Если имя члена совпало
				if(object.members[position].first.compare(name) == 0)
					// Выводим значение члена
					return &object.members[position].second;
			}
			// Член не найден
			return nullptr;
		}
		/**
		 * @brief Функция извлечения строки значения
		 *
		 * @param value разобранное значение
		 * @return      строка значения, пустая у значения иного вида
		 *
		 */
		static string text(const json_t::value_t & value) {
			// Если значение не строка
			if(value.kind != json_t::kind_t::STRING)
				// Выводим пустую строку
				return string();
			// Если строка материализована
			if(value.view.size == 0)
				// Выводим материализованную строку
				return value.text;
			// Выводим строку просмотра
			return string(reinterpret_cast <const char *> (value.view.data), value.view.size);
		}
		/**
		 * @brief Функция извлечения строкового члена объекта
		 *
		 * @param object разобранный объект
		 * @param name   имя искомого члена
		 * @param result строка, в которую помещается значение члена
		 * @return       признак того, что член найден и строков
		 *
		 */
		static bool member(const json_t::value_t & object, const char * name, string & result) {
			// Значение члена
			const json_t::value_t * value = member(object, name);
			// Если член не найден либо не строков
			if((value == nullptr) || (value->kind != json_t::kind_t::STRING))
				// Выводим отсутствие члена
				return false;
			// Запоминаем строку значения
			result = text(*value);
			// Выводим найденность члена
			return true;
		}
		/**
		 * @brief Функция извлечения числа значения
		 *
		 * @param value  разобранное значение
		 * @param result место, в которое помещается число
		 * @return       признак того, что значение числово
		 *
		 */
		static bool number(const json_t::value_t & value, uint32_t & result) noexcept {
			// Если значение не число
			if(value.kind != json_t::kind_t::NUMBER)
				// Выводим отсутствие числа
				return false;
			// Число
			uint32_t outcome = 0;
			/**
			 * Выполняем разбор записи числа
			 */
			for(size_t position = 0; position < value.view.size; position++){
				// Символ числа
				const uint8_t symbol = value.view.data[position];
				// Если символ не цифра
				if((symbol < '0') || (symbol > '9'))
					// Выводим отсутствие числа
					return false;
				// Накапливаем число
				outcome = outcome * 10 + (symbol - '0');
			}
			// Запоминаем число
			result = outcome;
			// Выводим найденность числа
			return true;
		}
		/**
		 * @brief Функция извлечения признака булева значения
		 *
		 * @param value  разобранное значение
		 * @param result место, в которое помещается признак
		 * @return       признак того, что значение булево
		 *
		 */
		static bool boolean(const json_t::value_t & value, bool & result) noexcept {
			// Если значение не булево
			if(value.kind != json_t::kind_t::VALUE)
				// Выводим отсутствие значения
				return false;
			// Значение true
			if((value.view.size == 4) && (::memcmp(value.view.data, "true", 4) == 0)){
				// Запоминаем признак
				result = true;
				// Выводим найденность значения
				return true;
			}
			// Значение false
			if((value.view.size == 5) && (::memcmp(value.view.data, "false", 5) == 0)){
				// Запоминаем признак
				result = false;
				// Выводим найденность значения
				return true;
			}
			// Значение не булево
			return false;
		}
		/**
		 * @brief Функция извлечения набора строк массива
		 *
		 * @param value  разобранное значение массива
		 * @param result место, в которое помещается набор строк
		 * @return       признак того, что значение массив строк
		 *
		 */
		static bool strings(const json_t::value_t & value, vector <string> & result) {
			// Если значение не массив
			if(value.kind != json_t::kind_t::ARRAY)
				// Выводим отсутствие массива
				return false;
			// Очищаем набор извлекаемых строк
			result.clear();
			/**
			 * Выполняем обход значений массива
			 */
			for(size_t position = 0; position < value.items.size(); position++){
				// Если значение не строка
				if(value.items[position].kind != json_t::kind_t::STRING)
					// Выводим отказ массива
					return false;
				// Запоминаем строку значения
				result.emplace_back(text(value.items[position]));
			}
			// Выводим успешность извлечения
			return true;
		}
		/**
		 * @brief Функция определения вида идентификатора по его имени
		 *
		 * @param type имя вида идентификатора
		 * @return     вид идентификатора, identifier_t::NONE у неизвестного имени
		 *
		 */
		static acme::identifier_t identifierKind(const string & type) noexcept {
			// Идентификатор доменного имени
			if(type.compare("dns") == 0)
				// Выводим вид идентификатора
				return acme::identifier_t::DNS;
			// Идентификатор адреса IP
			if(type.compare("ip") == 0)
				// Выводим вид идентификатора
				return acme::identifier_t::IP;
			// Имя неизвестно
			return acme::identifier_t::NONE;
		}
		/**
		 * @brief Функция получения имени вида идентификатора
		 *
		 * @param identifier вид идентификатора
		 * @return           имя вида идентификатора, пустое у неустановленного
		 *
		 */
		static const char * identifierName(const acme::identifier_t identifier) noexcept {
			/**
			 * Выполняем определение вида идентификатора
			 */
			switch(identifier){
				// Идентификатор доменного имени
				case acme::identifier_t::DNS: return "dns";
				// Идентификатор адреса IP
				case acme::identifier_t::IP: return "ip";
				// Идентификатор не установлен
				default: return "";
			}
		}
		/**
		 * @brief Функция записи строки JSON с экранировками
		 *
		 * @param text   записываемая строка
		 * @param result строка, к которой дописывается запись
		 *
		 */
		static void write(const string & text, string & result) {
			// Дописываем открывающую кавычку
			result += '"';
			/**
			 * Выполняем обход символов строки
			 */
			for(size_t position = 0; position < text.size(); position++){
				// Символ строки
				const char symbol = text[position];
				/**
				 * Выполняем определение символа
				 */
				switch(symbol){
					// Кавычка
					case '"': result += "\\\""; break;
					// Обратная черта
					case '\\': result += "\\\\"; break;
					// Перевод строки
					case '\n': result += "\\n"; break;
					// Возврат каретки
					case '\r': result += "\\r"; break;
					// Табуляция
					case '\t': result += "\\t"; break;
					// Прочие символы переносятся как есть
					default: result += symbol;
				}
			}
			// Дописываем закрывающую кавычку
			result += '"';
		}
	}

	/**
	 * @brief Функция сборки запроса ACME
	 *
	 * @param url     адрес ресурса запроса
	 * @param nonce   метка новизны из ответа службы
	 * @param kid     адрес учётной записи, пустой при записи ключа JWK
	 * @param key     сведения об открытом ключе учётной записи для записи JWK
	 * @param payload полезная нагрузка запроса, пустая у запроса POST-as-GET
	 * @param signer  подготовленный секретный ключ учётной записи
	 * @param result  строка, в которую помещается тело запроса application/jose+json
	 * @return        причина отказа либо error_t::NONE
	 *
	 */
	acme::error_t acme::request(const string & url, const string & nonce, const string & kid, const keys::key_t & key, const view_t & payload, const keys::signer_t & signer, string & result) noexcept {
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Очищаем строку тела запроса перед сборкой
			result.clear();
			// Если адрес либо метка пусты
			if(url.empty() || nonce.empty())
				// Выводим отказ записи
				return error_t::EMPTY;
			// Если ключ не подготовлен
			if(!signer.ready())
				// Выводим отказ ключа
				return error_t::EMPTY;
			// Алгоритм подписи по ключу
			const jws::algorithm_t algorithm = jws::algorithm(signer);
			// Если алгоритм не определён
			if(algorithm == jws::algorithm_t::NONE)
				// Выводим отказ алгоритма
				return error_t::ALGORITHM;
			// Собираем заголовок запроса
			string header;
			// Дописываем открывающую скобку
			header += '{';
			// Если задан адрес учётной записи: заголовок несёт kid
			if(!kid.empty()){
				// Дописываем член kid
				header += "\"kid\":";
				// Выводим адрес учётной записи
				write(kid, header);
			// Иначе заголовок несёт jwk
			} else {
				// Собираем запись ключа JWK
				string jwk;
				// Вывод записи ключа JWK
				const jws::error_t encoded = jws::jwk(key, jwk);
				// Если запись собрать не удалось
				if(encoded != jws::error_t::NONE){
					// Если не удалось выделить память
					if(encoded == jws::error_t::MEMORY)
						// Выводим отказ нехватки памяти
						return error_t::MEMORY;
					// Выводим отказ ключа
					return error_t::ALGORITHM;
				}
				// Дописываем член jwk
				header += "\"jwk\":";
				// Дописываем запись ключа
				header += jwk;
			}
			// Дописываем член nonce
			header += ",\"nonce\":";
			// Выводим метку новизны
			write(nonce, header);
			// Дописываем член url
			header += ",\"url\":";
			// Выводим адрес ресурса
			write(url, header);
			// Дописываем закрывающую скобку
			header += '}';
			// Собираем запись JWS
			string jws;
			// Вывод записи JWS
			const jws::error_t signedResult = jws::encode(algorithm, header, payload, signer, jws);
			// Если запись собрать не удалось
			if(signedResult != jws::error_t::NONE){
				// Если не удалось выделить память
				if(signedResult == jws::error_t::MEMORY)
					// Выводим отказ нехватки памяти
					return error_t::MEMORY;
				// Выводим отказ подписи
				return error_t::SIGNATURE;
			}
			// Разбираем запись JWS на части
			jws::signature_t signature;
			// Вывод разбора записи JWS
			const jws::error_t parsed = signature.parse(view_t(reinterpret_cast <const uint8_t *> (jws.data()), jws.size()));
			// Если запись разобрать не удалось
			if(parsed != jws::error_t::NONE){
				// Если не удалось выделить память
				if(parsed == jws::error_t::MEMORY)
					// Выводим отказ нехватки памяти
					return error_t::MEMORY;
				// Выводим отказ подписи
				return error_t::SIGNATURE;
			}
			// Кодируем подпись в base64url
			string tail;
			// Кодируем подпись в base64url
			jws::base64url(view_t(signature.sign().data(), signature.sign().size()), tail);
			// Собираем тело запроса: записи заголовка и полезной нагрузки указывают внутрь записи JWS
			result.assign("{\"protected\":");
			// Выводим запись заголовка
			write(string(reinterpret_cast <const char *> (jws.data()), jws.find('.')), result);
			// Дописываем полезную нагрузку
			result += ",\"payload\":";
			// Выводим запись полезной нагрузки
			write(string(reinterpret_cast <const char *> (jws.data()) + jws.find('.') + 1, jws.rfind('.') - jws.find('.') - 1), result);
			// Дописываем подпись
			result += ",\"signature\":";
			// Выводим запись подписи
			write(tail, result);
			// Дописываем закрывающую скобку
			result += '}';
			// Выводим успешность сборки
			return error_t::NONE;
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		}
	}

	/**
	 * @brief Функция сборки полезной нагрузки заведения учётной записи
	 *
	 * @param contacts             набор адресов связи («mailto:…»), вправе быть пустым
	 * @param termsOfServiceAgreed признак согласия с условиями службы
	 * @param onlyReturnExisting   признак запроса лишь существующей записи
	 * @param result               строка, в которую помещается полезная нагрузка
	 *
	 */
	void acme::newAccount(const vector <string> & contacts, const bool termsOfServiceAgreed, const bool onlyReturnExisting, string & result) noexcept {
		// Очищаем строку полезной нагрузки записи
		result.clear();
		// Если задан запрос лишь существующей записи
		if(onlyReturnExisting){
			// Собираем полезную нагрузку
			result.assign("{\"onlyReturnExisting\":true}");
			// Выходим
			return;
		}
		// Дописываем открывающую скобку
		result += '{';
		// Дописываем член contact
		result += "\"contact\":[";
		/**
		 * Выполняем обход адресов связи
		 */
		for(size_t position = 0; position < contacts.size(); position++){
			// Если адрес не первый
			if(position > 0)
				// Дописываем разделитель
				result += ',';
			// Дописываем адрес
			write(contacts[position], result);
		}
		// Дописываем закрывающую скобку массива
		result += ']';
		// Если задано согласие с условиями службы
		if(termsOfServiceAgreed)
			// Дописываем член termsOfServiceAgreed
			result += ",\"termsOfServiceAgreed\":true";
		// Дописываем закрывающую скобку
		result += '}';
	}
	/**
	 * @brief Функция сборки полезной нагрузки заведения заказа
	 *
	 * @param identifiers набор идентификаторов заказа: вид и значение
	 * @param result      строка, в которую помещается полезная нагрузка
	 * @return            причина отказа либо error_t::NONE
	 *
	 */
	acme::error_t acme::newOrder(const vector <pair <identifier_t, string>> & identifiers, string & result) noexcept {
		// Очищаем строку полезной нагрузки заказа
		result.clear();
		// Если набор идентификаторов пуст
		if(identifiers.empty())
			// Выводим отказ записи
			return error_t::EMPTY;
		// Дописываем открывающую скобку
		result += '{';
		// Дописываем член identifiers
		result += "\"identifiers\":[";
		/**
		 * Выполняем обход идентификаторов заказа
		 */
		for(size_t position = 0; position < identifiers.size(); position++){
			// Имя вида идентификатора
			const char * type = identifierName(identifiers[position].first);
			// Если вид идентификатора не установлен
			if(type[0] == '\0')
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Если идентификатор не первый
			if(position > 0)
				// Дописываем разделитель
				result += ',';
			// Дописываем запись идентификатора
			result += "{\"type\":\"";
			// Выводим вид идентификатора
			result += type;
			// Дописываем разделитель значения
			result += "\",\"value\":";
			// Выводим значение идентификатора
			write(identifiers[position].second, result);
			// Закрываем запись идентификатора
			result += '}';
		}
		// Дописываем закрывающие скобки
		result += "]}";
		// Выводим успешность сборки
		return error_t::NONE;
	}
	/**
	 * @brief Функция сборки полезной нагрузки завершения заказа
	 *
	 * @param csr    запись запроса на сертификат в кодировке DER
	 * @param result строка, в которую помещается полезная нагрузка
	 *
	 */
	void acme::finalize(const view_t & csr, string & result) noexcept {
		// Кодируем запись запроса в base64url
		string encoded;
		// Кодируем запрос
		jws::base64url(csr, encoded);
		// Собираем полезную нагрузку
		result.assign("{\"csr\":\"");
		// Дописываем запись запроса
		result += encoded;
		// Закрываем запись полезной нагрузки
		result += "\"}";
	}
	/**
	 * @brief Функция сборки полезной нагрузки отзыва сертификата
	 *
	 * @param certificate запись сертификата в кодировке DER
	 * @param reason      причина отзыва по разделу 5.3.1 RFC 5280
	 * @param result      строка, в которую помещается полезная нагрузка
	 *
	 */
	void acme::revokeCert(const view_t & certificate, const uint8_t reason, string & result) noexcept {
		// Кодируем запись сертификата в base64url
		string encoded;
		// Кодируем сертификат
		jws::base64url(certificate, encoded);
		// Собираем полезную нагрузку
		result.assign("{\"certificate\":\"");
		// Дописываем запись сертификата
		result += encoded;
		// Дописываем разделитель причины
		result += "\",\"reason\":";
		// Дописываем запись причины отзыва
		if(reason > 9)
			// Дописываем старший разряд причины
			result += static_cast <char> ('0' + (reason / 10));
		// Дописываем младший разряд причины
		result += static_cast <char> ('0' + (reason % 10));
		// Закрываем запись полезной нагрузки
		result += '}';
	}
	/**
	 * @brief Функция сборки полезной нагрузки ответа на испытание
	 *
	 * @param result строка, в которую помещается полезная нагрузка
	 *
	 */
	void acme::answer(string & result) noexcept {
		// Ответ на испытание - пустой объект
		result.assign("{}");
	}

	/**
	 * @brief Функция выработки полномочного ключа испытания
	 *
	 * @param token  метка испытания
	 * @param key    сведения об открытом ключе учётной записи
	 * @param result строка, в которую помещается ключ в base64url
	 * @return       причина отказа либо error_t::NONE
	 *
	 */
	acme::error_t acme::keyAuthorization(const string & token, const keys::key_t & key, string & result) noexcept {
		// Очищаем строку ключа полномочия
		result.clear();
		// Вырабатываем владение ключом
		string possession;
		// Если владение выработать не удалось
		const error_t outcome = keyPossession(token, key, possession);
		// Если выработка отказала
		if(outcome != error_t::NONE)
			// Выводим причину отказа
			return outcome;
		// Место, в которое помещается хеш владения
		uint8_t digest[32];
		// Если хеш владения выработать не удалось
		if(!digest::hash(digest::hash_t::SHA256, view_t(reinterpret_cast <const uint8_t *> (possession.data()), possession.size()), digest, sizeof(digest)))
			// Выводим отказ памяти
			return error_t::MEMORY;
		// Кодируем ключ в base64url
		jws::base64url(view_t(digest, sizeof(digest)), result);
		// Выводим успешность выработки
		return error_t::NONE;
	}
	/**
	 * @brief Функция выработки владения ключом испытания
	 *
	 * @param token  метка испытания
	 * @param key    сведения об открытом ключе учётной записи
	 * @param result строка, в которую помещается владение
	 * @return       причина отказа либо error_t::NONE
	 *
	 */
	acme::error_t acme::keyPossession(const string & token, const keys::key_t & key, string & result) noexcept {
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Очищаем строку владения ключом
			result.clear();
			// Если метка пуста
			if(token.empty())
				// Выводим отказ записи
				return error_t::EMPTY;
			// Вырабатываем отпечаток ключа учётной записи
			string thumbprint;
			// Вывод отпечатка ключа учётной записи
			const jws::error_t printed = jws::thumbprint(key, thumbprint);
			// Если отпечаток выработать не удалось
			if(printed != jws::error_t::NONE){
				// Если не удалось выделить память
				if(printed == jws::error_t::MEMORY)
					// Выводим отказ нехватки памяти
					return error_t::MEMORY;
				// Выводим отказ ключа
				return error_t::ALGORITHM;
			}
			// Собираем владение: метка ‖ '.' ‖ отпечаток
			result.assign(token);
			// Дописываем разделитель
			result += '.';
			// Дописываем отпечаток ключа
			result += thumbprint;
			// Выводим успешность выработки
			return error_t::NONE;
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		}
	}

	/**
	 * @brief Метод разбора ответа ресурса directory
	 *
	 * @param data просмотр разбираемого ответа
	 * @return     причина отказа либо error_t::NONE
	 *
	 */
	acme::error_t acme::Directory::parse(const view_t & data) noexcept {
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Сбрасываем разобранные сведения
			this->clear();
			// Если ответ пуст
			if(data.size == 0)
				// Выводим отказ записи
				return error_t::EMPTY;
			// Разборщик записи ответа
			json_t json;
			// Разобранный ответ
			json_t::value_t answer;
			// Если ответ разобрать не удалось
			if(!json.parse(data, answer) || (answer.kind != json_t::kind_t::OBJECT))
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Извлекаем адрес ресурса выдачи метки новизны
			if(!member(answer, "newNonce", this->newNonce))
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Извлекаем адрес ресурса заведения учётной записи
			if(!member(answer, "newAccount", this->newAccount))
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Извлекаем адрес ресурса заведения заказа
			if(!member(answer, "newOrder", this->newOrder))
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Извлекаем адрес ресурса отзыва сертификата
			if(!member(answer, "revokeCert", this->revokeCert))
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Извлекаем необязательные адреса ресурсов
			member(answer, "newAuthz", this->newAuthz);
			member(answer, "keyChange", this->keyChange);
			member(answer, "renewalInfo", this->renewalInfo);
			// Выводим успешность разбора
			return error_t::NONE;
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		}
	}
	/**
	 * @brief Метод очистки разобранных сведений
	 *
	 */
	void acme::Directory::clear() noexcept {
		// Сбрасываем адреса ресурсов
		this->newNonce.clear();
		// Сбрасываем адрес заведения учётной записи
		this->newAccount.clear();
		// Сбрасываем адрес заведения заказа
		this->newOrder.clear();
		// Сбрасываем адрес заведения полномочия
		this->newAuthz.clear();
		// Сбрасываем адрес отзыва сертификата
		this->revokeCert.clear();
		// Сбрасываем адрес смены ключа
		this->keyChange.clear();
		// Сбрасываем адрес сведений о продлении
		this->renewalInfo.clear();
	}

	/**
	 * @brief Метод разбора ответа ресурса учётной записи
	 *
	 * @param data просмотр разбираемого ответа
	 * @return     причина отказа либо error_t::NONE
	 *
	 */
	acme::error_t acme::Account::parse(const view_t & data) noexcept {
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Сбрасываем разобранные сведения
			this->clear();
			// Если ответ пуст
			if(data.size == 0)
				// Выводим отказ записи
				return error_t::EMPTY;
			// Разборщик записи ответа
			json_t json;
			// Разобранный ответ
			json_t::value_t answer;
			// Если ответ разобрать не удалось
			if(!json.parse(data, answer) || (answer.kind != json_t::kind_t::OBJECT))
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Извлекаем состояние записи
			if(!member(answer, "status", this->status))
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Извлекаем набор адресов заказов записи
			const json_t::value_t * orders = member(answer, "orders");
			// Если набор задан
			if(orders != nullptr){
				// Если набор массив строк: запись по разделу 7.1.2 RFC 8555
				if(orders->kind == json_t::kind_t::ARRAY){
					// Если набор не массив строк
					if(!strings(*orders, this->orders))
						// Выводим отказ записи
						return error_t::STRUCTURE;
				// Иначе набор строкой: службы пишут и единственный адрес строкой
				} else if(orders->kind == json_t::kind_t::STRING)
					// Запоминаем единственный адрес
					this->orders.emplace_back(text(*orders));
				// Набор чужого вида
				else
					// Выводим отказ записи
					return error_t::STRUCTURE;
			}
			// Выводим успешность разбора
			return error_t::NONE;
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		}
	}
	/**
	 * @brief Метод очистки разобранных сведений
	 *
	 */
	void acme::Account::clear() noexcept {
		// Сбрасываем состояние записи
		this->status.clear();
		// Сбрасываем набор адресов заказов
		this->orders.clear();
	}

	/**
	 * @brief Метод разбора ответа ресурса заказа
	 *
	 * @param data просмотр разбираемого ответа
	 * @return     причина отказа либо error_t::NONE
	 *
	 */
	acme::error_t acme::Order::parse(const view_t & data) noexcept {
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Сбрасываем разобранные сведения
			this->clear();
			// Если ответ пуст
			if(data.size == 0)
				// Выводим отказ записи
				return error_t::EMPTY;
			// Разборщик записи ответа
			json_t json;
			// Разобранный ответ
			json_t::value_t answer;
			// Если ответ разобрать не удалось
			if(!json.parse(data, answer) || (answer.kind != json_t::kind_t::OBJECT))
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Извлекаем состояние заказа
			if(!member(answer, "status", this->status))
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Извлекаем срок действия заказа
			member(answer, "expires", this->expires);
			// Извлекаем набор идентификаторов заказа
			const json_t::value_t * identifiers = member(answer, "identifiers");
			// Если набор не задан либо не массив
			if((identifiers == nullptr) || (identifiers->kind != json_t::kind_t::ARRAY) || identifiers->items.empty())
				// Выводим отказ записи
				return error_t::STRUCTURE;
			/**
			 * Выполняем обход идентификаторов заказа
			 */
			for(size_t position = 0; position < identifiers->items.size(); position++){
				// Запись идентификатора
				const json_t::value_t & entry = identifiers->items[position];
				// Вид и значение идентификатора
				string type, value;
				// Если члены записи не найдены
				if(!member(entry, "type", type) || !member(entry, "value", value))
					// Выводим отказ записи
					return error_t::STRUCTURE;
				// Вид идентификатора
				const identifier_t kind = identifierKind(type);
				// Если вид неизвестен
				if(kind == identifier_t::NONE)
					// Выводим отказ записи
					return error_t::STRUCTURE;
				// Запоминаем идентификатор
				this->identifiers.emplace_back(kind, value);
			}
			// Извлекаем набор адресов записей полномочий
			const json_t::value_t * authorizations = member(answer, "authorizations");
			// Если набор не задан либо не массив строк
			if((authorizations == nullptr) || !strings(*authorizations, this->authorizations))
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Извлекаем адрес ресурса завершения заказа
			if(!member(answer, "finalize", this->finalize))
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Извлекаем адрес ресурса выданного сертификата
			member(answer, "certificate", this->certificate);
			// Выводим успешность разбора
			return error_t::NONE;
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		}
	}
	/**
	 * @brief Метод очистки разобранных сведений
	 *
	 */
	void acme::Order::clear() noexcept {
		// Сбрасываем состояние заказа
		this->status.clear();
		// Сбрасываем срок действия заказа
		this->expires.clear();
		// Сбрасываем набор идентификаторов
		this->identifiers.clear();
		// Сбрасываем набор адресов записей полномочий
		this->authorizations.clear();
		// Сбрасываем адрес ресурса завершения заказа
		this->finalize.clear();
		// Сбрасываем адрес ресурса выданного сертификата
		this->certificate.clear();
	}

	/**
	 * @brief Метод очистки разобранных сведений
	 *
	 */
	void acme::Challenge::clear() noexcept {
		// Сбрасываем вид испытания
		this->type.clear();
		// Сбрасываем адрес ресурса испытания
		this->url.clear();
		// Сбрасываем состояние испытания
		this->status.clear();
		// Сбрасываем метку испытания
		this->token.clear();
		// Сбрасываем дату проверки испытания
		this->validated.clear();
	}

	/**
	 * @brief Метод разбора ответа ресурса записи полномочий
	 *
	 * @param data просмотр разбираемого ответа
	 * @return     причина отказа либо error_t::NONE
	 *
	 */
	acme::error_t acme::Authorization::parse(const view_t & data) noexcept {
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Сбрасываем разобранные сведения
			this->clear();
			// Если ответ пуст
			if(data.size == 0)
				// Выводим отказ записи
				return error_t::EMPTY;
			// Разборщик записи ответа
			json_t json;
			// Разобранный ответ
			json_t::value_t answer;
			// Если ответ разобрать не удалось
			if(!json.parse(data, answer) || (answer.kind != json_t::kind_t::OBJECT))
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Извлекаем состояние записи
			if(!member(answer, "status", this->status))
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Извлекаем срок действия записи
			member(answer, "expires", this->expires);
			// Извлекаем идентификатор записи
			const json_t::value_t * identity = member(answer, "identifier");
			// Если идентификатор не задан
			if(identity == nullptr)
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Вид и значение идентификатора
			string type, value;
			// Если члены записи не найдены
			if(!member(*identity, "type", type) || !member(*identity, "value", value))
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Вид идентификатора
			const identifier_t kind = identifierKind(type);
			// Если вид неизвестен
			if(kind == identifier_t::NONE)
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Запоминаем идентификатор
			this->identifier = std::make_pair(kind, value);
			// Извлекаем признак записи с маской
			const json_t::value_t * wildcard = member(answer, "wildcard");
			// Если признак задан
			if(wildcard != nullptr){
				// Если признак не булев
				if(!boolean(*wildcard, this->wildcard))
					// Выводим отказ записи
					return error_t::STRUCTURE;
			}
			// Извлекаем набор испытаний записи
			const json_t::value_t * challenges = member(answer, "challenges");
			// Если набор не задан либо не массив
			if((challenges == nullptr) || (challenges->kind != json_t::kind_t::ARRAY))
				// Выводим отказ записи
				return error_t::STRUCTURE;
			/**
			 * Выполняем обход испытаний записи
			 */
			for(size_t position = 0; position < challenges->items.size(); position++){
				// Запись испытания
				const json_t::value_t & entry = challenges->items[position];
				// Разобранное испытание
				challenge_t challenge;
				// Если обязательные члены записи не найдены
				if(!member(entry, "type", challenge.type) || !member(entry, "url", challenge.url) || !member(entry, "status", challenge.status))
					// Выводим отказ записи
					return error_t::STRUCTURE;
				// Извлекаем метку испытания: новые виды испытаний её не несут
				member(entry, "token", challenge.token);
				// Извлекаем дату проверки испытания
				member(entry, "validated", challenge.validated);
				// Запоминаем испытание
				this->challenges.emplace_back(std::move(challenge));
			}
			// Выводим успешность разбора
			return error_t::NONE;
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		}
	}
	/**
	 * @brief Метод очистки разобранных сведений
	 *
	 */
	void acme::Authorization::clear() noexcept {
		// Сбрасываем состояние записи
		this->status.clear();
		// Сбрасываем срок действия записи
		this->expires.clear();
		// Сбрасываем идентификатор записи
		this->identifier = std::make_pair(identifier_t::NONE, string());
		// Сбрасываем признак записи с маской
		this->wildcard = false;
		// Сбрасываем набор испытаний записи
		this->challenges.clear();
	}
	/**
	 * @brief Конструктор
	 *
	 */
	acme::Authorization::Authorization() noexcept : wildcard(false) {}

	/**
	 * @brief Метод разбора ответа об отказе
	 *
	 * @param data просмотр разбираемого ответа
	 * @return     причина отказа либо error_t::NONE
	 *
	 */
	acme::error_t acme::Problem::parse(const view_t & data) noexcept {
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Сбрасываем разобранные сведения
			this->clear();
			// Если ответ пуст
			if(data.size == 0)
				// Выводим отказ записи
				return error_t::EMPTY;
			// Разборщик записи ответа
			json_t json;
			// Разобранный ответ
			json_t::value_t answer;
			// Если ответ разобрать не удалось
			if(!json.parse(data, answer) || (answer.kind != json_t::kind_t::OBJECT))
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Извлекаем опознаватель вида отказа
			if(!member(answer, "type", this->type))
				// Выводим отказ записи
				return error_t::STRUCTURE;
			// Извлекаем краткое описание отказа
			member(answer, "detail", this->detail);
			// Извлекаем состояние ответа
			const json_t::value_t * status = member(answer, "status");
			// Если состояние задано
			if(status != nullptr){
				// Если состояние не числово
				if(!number(*status, this->status))
					// Выводим отказ записи
					return error_t::STRUCTURE;
			}
			// Выводим успешность разбора
			return error_t::NONE;
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return error_t::MEMORY;
		}
	}
	/**
	 * @brief Метод очистки разобранных сведений
	 *
	 */
	void acme::Problem::clear() noexcept {
		// Сбрасываем опознаватель вида отказа
		this->type.clear();
		// Сбрасываем краткое описание отказа
		this->detail.clear();
		// Сбрасываем состояние ответа
		this->status = 0;
	}
	/**
	 * @brief Конструктор
	 *
	 */
	acme::Problem::Problem() noexcept : status(0) {}
}
