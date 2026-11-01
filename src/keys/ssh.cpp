/**
 * @file ssh.cpp
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
 * @brief Модуль формата ключей SSH (openssh-key-v1)
 *
 * @details Разбор и запись ключей формата openssh-key-v1: магия «openssh-key-v1\0»,
 *          SSH-строки (uint32 длина + байты), незашифрованный формат и зашифрованный
 *          bcrypt_pbkdf + aes256-ctr
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
#include <keys/ssh.hpp>
#include <sys/wipe.hpp>
#include <digest/bcrypt.hpp>
#include <digest/hmac.hpp>
#include <digest/sha2.hpp>
#include <cipher/aes.hpp>
#include <cipher/mode.hpp>
#include <entropy/entropy.hpp>

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
	/**
	 * Затирание областей памяти берётся из открытого API библиотеки
	 */
	using nts::sys::wipe;

	/**
	 * Размер IV AES-CTR
	 */
	constexpr size_t IV_SIZE = 16;
	/**
	 * Размер ключа AES-256
	 */
	constexpr size_t KEY_SIZE = 32;
	/**
	 * Размер соли bcrypt
	 */
	constexpr size_t SALT_SIZE = 16;
	/**
	 * Размер магии с NUL
	 */
	constexpr size_t MAGIC_SIZE = 15;
	/**
	 * Размер блока AES
	 */
	constexpr size_t BLOCK_SIZE = 16;
	/**
	 * Число кругов bcrypt по умолчанию
	 */
	constexpr size_t DEFAULT_ROUNDS = 16;
	/**
	 * Магия формата
	 */
	constexpr char MAGIC[] = "openssh-key-v1";

	/**
	 * @brief Класс чтеца SSH-строк
	 *
	 */
	typedef class Reader {
		private:
			// Текущая позиция
			size_t _pos;
			// Размер данных
			size_t _size;
			// Данные для обработки
			const uint8_t * _data;
		public:
			/**
			 * @brief Метод проверки окончания данных
			 *
			 * @return признак того, что данные закончились
			 *
			 */
			bool empty() const noexcept {
				// Выводим признак того, что место чтения дошло до конца
				return (this->_pos >= this->_size);
			}
			/**
			 * @brief Метод получения оставшихся данных
			 *
			 * @return оставшиеся данные
			 *
			 */
			view_t rest() const noexcept {
				// Выводим просмотр остатка данных
				return view_t(this->_data + this->_pos, this->_size - this->_pos);
			}
		public:
			/**
			 * @brief Метод извлечения записи как числа
			 *
			 * @param value прочитанное значение
			 * @return      признак успешности
			 *
			 */
			bool get(uint32_t & value) noexcept {
				// Если четырёх байтов не осталось
				if((this->_pos + 4) > this->_size)
					// Выводим отказ чтения
					return false;
				// Собираем значение из четырёх байтов как big-endian
				value = (
					(static_cast <uint32_t> (this->_data[this->_pos]) << 24) |
					(static_cast <uint32_t> (this->_data[this->_pos + 1]) << 16) |
					(static_cast <uint32_t> (this->_data[this->_pos + 2]) << 8) |
					static_cast <uint32_t> (this->_data[this->_pos + 3])
				);
				// Сдвигаем место чтения за значение
				this->_pos += 4;
				// Выводим признак успешности чтения
				return true;
			}
			/**
			 * @brief Метод извлечения записи как строки
			 *
			 * @param str прочитанная строка
			 * @return    признак успешности
			 *
			 */
			bool get(view_t & str) noexcept {
				// Длина строки
				uint32_t length = 0;
				// Если длину прочитать не удалось
				if(!this->get(length))
					// Выводим отказ чтения
					return false;
				// Если строка не помещается в остаток данных
				if((this->_pos + length) > this->_size)
					// Выводим отказ чтения
					return false;
				// Запоминаем длину строки
				str.size = length;
				// Запоминаем просмотр строки
				str.data = (this->_data + this->_pos);
				// Сдвигаем место чтения за строку
				this->_pos += length;
				// Выводим признак успешности чтения
				return true;
			}
			/**
			 * @brief Метод извлечения записи как строки
			 *
			 * @param str прочитанная строка
			 * @return    признак успешности
			 *
			 */
			bool get(string & str) noexcept {
				/**
				 * Выполняем перехват ошибок
				 */
				try {
					// Просмотр прочитанной строки
					view_t view;
					// Если строку прочитать не удалось
					if(!this->get(view))
						// Выводим отказ чтения
						return false;
					// Запоминаем строку
					str.assign(reinterpret_cast <const char *> (view.data), view.size);
					// Выводим признак успешности чтения
					return true;
				/**
				 * Выполняем перехват ошибок
				 */
				} catch(const bad_alloc &) {
					// Выводим отказ нехватки памяти
					return false;
				}
			}
			/**
			 * @brief Метод извлечения записи как строки
			 *
			 * @param vec прочитанный вектор
			 * @return     признак успешности
			 *
			 */
			bool get(vector <uint8_t> & vec) noexcept {
				/**
				 * Выполняем перехват ошибок
				 */
				try {
					// Просмотр прочитанной строки
					view_t view;
					// Если строку прочитать не удалось
					if(!this->get(view))
						// Выводим отказ чтения
						return false;
					// Запоминаем байты строки
					vec.assign(view.data, view.data + view.size);
					// Выводим признак успешности чтения
					return true;
				/**
				 * Выполняем перехват ошибок
				 */
				} catch(const bad_alloc &) {
					// Выводим отказ нехватки памяти
					return false;
				}
			}
		public:
			/**
			 * @brief Конструктор
			 *
			 * @param data данные для обработки
			 * @param size размер данных для обработки
			 *
			 */
			explicit Reader(const uint8_t * data, const size_t size) noexcept :
			 _pos(0), _size(size), _data(data) {}
	} reader_t;
	/**
	 * @brief Класс писателя SSH-строк
	 *
	 */
	typedef class Writer {
		private:
			// Буфер для хранения данных
			vector <uint8_t> & _buffer;
		public:
			/**
			 * @brief Метод добавления записи как число
			 *
			 * @param value записываемое значение
			 *
			 */
			void add(const uint32_t value) noexcept {
				/**
				 * Выполняем перехват ошибок
				 */
				try {
					// Записываем значение по байтам как big-endian
					this->_buffer.push_back((value >> 24) & 0xff);
					this->_buffer.push_back((value >> 16) & 0xff);
					this->_buffer.push_back((value >> 8) & 0xff);
					this->_buffer.push_back(value & 0xff);
				/**
				 * Выполняем перехват ошибок
				 */
				} catch(const bad_alloc &) {
					// Выводим отказ нехватки памяти
					return;
				}
			}
			/**
			 * @brief Метод добавления записи как строки
			 *
			 * @param str строка для добавления в буфер
			 *
			 */
			void add(const view_t & str) noexcept {
				// Записываем строку из просмотра
				this->add(str.data, str.size);
			}
			/**
			 * @brief Метод добавления записи как строки
			 *
			 * @param str строка для добавления в буфер
			 *
			 */
			void add(const string & str) noexcept {
				// Записываем строку из std::string
				this->add(reinterpret_cast <const uint8_t *> (str.data()), str.size());
			}
			/**
			 * @brief Метод добавления записи как строки
			 *
			 * @param vec вектор для добавления в буфер
			 *
			 */
			void add(const vector <uint8_t> & vec) noexcept {
				// Записываем строку из вектора
				this->add(vec.data(), vec.size());
			}
			/**
			 * @brief Метод добавления записи как строки
			 *
			 * @param data строковые данные для добавления в буфер
			 * @param size размер строковых данных для добавления в буфер
			 *
			 */
			void add(const uint8_t * data, const size_t size) noexcept {
				/**
				 * Выполняем перехват ошибок
				 */
				try {
					// Записываем длину строки
					this->add(static_cast <uint32_t> (size));
					// Записываем байты строки
					this->_buffer.insert(this->_buffer.end(), data, data + size);
				/**
				 * Выполняем перехват ошибок
				 */
				} catch(const bad_alloc &) {
					// Выводим отказ нехватки памяти
					return;
				}
			}
		public:
			/**
			 * @brief Метод дополнения буфера до кратности блоку
			 *
			 * @details Дописывает в буфер N байтов со значениями 1..N, где N выбрано
			 *          так, чтобы длина буфера стала кратной размеру блока.
			 *
			 */
			void pad() noexcept {
				/**
				 * Выполняем перехват ошибок
				 */
				try {
					// Число байтов дополнения
					const size_t length = BLOCK_SIZE - (this->_buffer.size() % BLOCK_SIZE);
					/**
					 * Проходим по байтам дополнения
					 */
					for(size_t i = 1; i <= length; ++i)
						// Записываем байт дополнения
						this->_buffer.push_back(static_cast <uint8_t> (i));
				/**
				 * Выполняем перехват ошибок
				 */
				} catch(const bad_alloc &) {
					// Выводим отказ нехватки памяти
					return;
				}
			}
		public:
			/**
			 * @brief Конструктор
			 *
			 * @param buffer буфер для хранения данных
			 *
			 */
			explicit Writer(vector <uint8_t> & buffer) noexcept : _buffer(buffer) {}
	} writer_t;

	/**
	 * @brief Функция кодирования base64
	 *
	 * @param data данные
	 * @param size размер
	 * @return     строка base64
	 *
	 */
	string base64Encode(const uint8_t * data, const size_t size) noexcept {
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Накопитель строки base64
			string result = "";
			// Если данные переданы верно
			if((data != nullptr) && (size > 0)){
				// Алфавит base64
				static const char ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
				// Занимаем место под строку по её пределу
				result.reserve((size + 2) / 3 * 4);
				/**
				 * Проходим по данным тройками байтов
				 */
				for(size_t i = 0; i < size; i += 3){
					// Собираем тройку байтов в число
					uint32_t digits = (static_cast <uint32_t> (data[i]) << 16);
					// Если второй байт есть
					if((i + 1) < size)
						// Добавляем второй байт
						digits |= static_cast <uint32_t> (data[i + 1]) << 8;
					// Если третий байт есть
					if((i + 2) < size)
						// Добавляем третий байт
						digits |= static_cast <uint32_t> (data[i + 2]);
					// Записываем четыре знака base64
					result.push_back(ALPHABET[(digits >> 18) & 63]);
					result.push_back(ALPHABET[(digits >> 12) & 63]);
					result.push_back(((i + 1) < size) ? ALPHABET[(digits >> 6) & 63] : '=');
					result.push_back(((i + 2) < size) ? ALPHABET[digits & 63] : '=');
				}
			}
			// Выводим строку base64
			return result;
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return "";
		}
	}
	/**
	 * @brief Функция декодирования base64
	 *
	 * @param text строка base64
	 * @param data место для байтов
	 * @return     признак успешности
	 *
	 */
	bool base64Decode(const string & text, vector <uint8_t> & data) noexcept {
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Таблица разбора знаков base64
			static const int8_t TABLE[256] = {
				// Знаки вне алфавита разбора дают отказ
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
			// Сбрасываем накопитель байтов
			data.clear();
			// Занимаем место под байты по их пределу
			data.reserve(text.size() * 3 / 4);
			// Число накопленных битов
			int32_t bits = 0;
			// Накопитель разбираемого числа
			uint32_t digits = 0;
			/**
			 * Проходим по знакам строки
			 */
			for(const char letter : text){
				// Разбираем знак по таблице
				const int8_t symbol = TABLE[static_cast <uint8_t> (letter)];
				// Если знак - дополнение '='
				if(symbol == -2)
					// Дополнение завершает строку
					break;
				// Если знак чужой
				if(symbol < 0)
					// Выводим отказ разбора
					return false;
				// Добавляем шесть битов знака
				digits = ((digits << 6) | static_cast <uint32_t> (symbol));
				// Считаем накопленные биты
				bits += 6;
				// Если байт набран
				if(bits >= 8){
					// Считаем остаток битов
					bits -= 8;
					// Записываем набранный байт
					data.push_back(static_cast <uint8_t> (digits >> bits));
				}
			}
			// Выводим признак успешности разбора
			return true;
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return false;
		}
	}
	/**
	 * @brief Функция разбора секретного блока ed25519
	 *
	 * @param reader  разборщик
	 * @param key     разобранный ключ
	 * @param comment комментарий
	 * @return        признак успешности
	 *
	 */
	bool parsePrivate(reader_t & reader, keys::key_t & key, string & comment) noexcept {
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Проверочные числа
			uint32_t check1 = 0, check2 = 0;
			// Если проверочные числа прочитать не удалось
			if(!reader.get(check1) || !reader.get(check2))
				// Выводим отказ разбора
				return false;
			// Если проверочные числа не совпали
			if(check1 != check2)
				// Выводим отказ разбора
				return false;
			// Тип ключа
			string type;
			// Если тип ключа прочитать не удалось
			if(!reader.get(type))
				// Выводим отказ разбора
				return false;
			// Если тип ключа не ed25519
			if(type != "ssh-ed25519")
				// Выводим отказ разбора
				return false;
			// Открытый ключ
			vector <uint8_t> pubkey;
			// Если открытый ключ прочитать не удалось
			if(!reader.get(pubkey))
				// Выводим отказ разбора
				return false;
			// Если открытый ключ не той длины
			if(pubkey.size() != 32)
				// Выводим отказ разбора
				return false;
			// Секретный ключ (64 байта: seed || pubkey)
			vector <uint8_t> privkey;
			// Если секретный ключ прочитать не удалось
			if(!reader.get(privkey))
				// Выводим отказ разбора
				return false;
			// Если секретный ключ не той длины
			if(privkey.size() != 64)
				// Выводим отказ разбора
				return false;
			// Если открытая часть секретного ключа не совпала с открытым ключом
			if(::memcmp(privkey.data() + 32, pubkey.data(), 32) != 0)
				// Выводим отказ разбора
				return false;
			// Если комментарий прочитать не удалось
			if(!reader.get(comment))
				// Выводим отказ разбора
				return false;
			// Запоминаем вид ключа
			key.kind = keys::kind_t::ED25519;
			// Запоминаем секретную часть ключа
			key.d.assign(privkey.data(), privkey.data() + 32);
			// Запоминаем открытую часть ключа
			key.key = pubkey;
			// Выполняем затирание секрета
			wipe(privkey.data(), privkey.size());
			// Выводим признак успешности разбора
			return true;
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return false;
		}
	}
	/**
	 * @brief Функция записи секретного блока ed25519
	 *
	 * @param writer  записыватель
	 * @param key     ключ
	 * @param comment комментарий
	 *
	 */
	void writePrivate(writer_t & writer, const keys::key_t & key, const string & comment) noexcept {
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Проверочное число
			uint32_t check = 0;
			// Вырабатываем проверочное число
			entropy::bytes(reinterpret_cast <uint8_t *> (&check), sizeof(check));
			// Записываем проверочное число дважды
			writer.add(check);
			writer.add(check);
			// Записываем тип ключа
			writer.add("ssh-ed25519");
			// Записываем открытый ключ
			writer.add(key.key);
			// Секретный ключ (64 байта: seed || pubkey)
			vector <uint8_t> privkey;
			// Занимаем место под секретный ключ
			privkey.reserve(64);
			// Записываем секретную часть
			privkey.insert(privkey.end(), key.d.begin(), key.d.end());
			// Записываем открытую часть
			privkey.insert(privkey.end(), key.key.begin(), key.key.end());
			// Записываем секретный ключ
			writer.add(privkey);
			// Выполняем затирание секрета
			wipe(privkey.data(), privkey.size());
			// Записываем комментарий
			writer.add(comment);
			// Дополняем буфер до кратности блоку
			writer.pad();
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return;
		}
	}
};

/**
 * @brief Конструктор
 *
 */
nts::keys::ssh::KnownHost::KnownHost() noexcept :
 hashed(false), host{""}, type{""}, comment{""} {}

/**
 * @brief Функция вычисления отпечатка ключа SHA256
 *
 * @param key открытый ключ
 * @return    отпечаток
 *
 */
string nts::keys::ssh::fingerprint(const key_t & key) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Если ключ негоден
		if(key.kind != kind_t::ED25519 || key.key.size() != 32)
			// Выводим пустую строку
			return "";
		// Блок открытого ключа
		vector <uint8_t> pubblock;
		// Заводим записыватель блока
		writer_t pubwriter(pubblock);
		// Записываем тип ключа
		pubwriter.add("ssh-ed25519");
		// Записываем открытый ключ
		pubwriter.add(key.key);
		// Хеш блока открытого ключа
		uint8_t hash[32];
		// Модуль хеша SHA256
		digest::Sha2 sha(digest::sha_t::SHA256);
		// Добавляем блок в хеш
		sha.update(view_t(pubblock.data(), pubblock.size()));
		// Завершаем хеш
		sha.finish(hash, sizeof(hash));
		// Отпечаток в base64 без дополнения
		string b64 = ::base64Encode(hash, sizeof(hash));
		/**
		 * Пока в конце знаки дополнения
		 */
		while(!b64.empty() && b64.back() == '=')
			// Убираем знак дополнения
			b64.pop_back();
		// Выводим отпечаток с меткой алгоритма
		return ("SHA256:" + b64);
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return "";
	}
}
/**
 * @brief Функция записи открытого ключа в строку authorized_keys
 *
 * @param key     открытый ключ
 * @param comment комментарий
 * @return        строка authorized_keys
 *
 */
string nts::keys::ssh::publish(const key_t & key, const string & comment) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Если ключ негоден
		if((key.kind != kind_t::ED25519) || (key.key.size() != 32))
			// Выводим пустую строку
			return "";
		// Блок открытого ключа
		vector <uint8_t> pubblock;
		// Заводим записыватель блока
		writer_t pubwriter(pubblock);
		// Записываем тип ключа
		pubwriter.add("ssh-ed25519");
		// Записываем открытый ключ
		pubwriter.add(key.key);
		// Начало строки: тип ключа
		string result = "ssh-ed25519 ";
		// Дописываем ключ в base64
		result += ::base64Encode(pubblock.data(), pubblock.size());
		// Если комментарий задан
		if(!comment.empty()){
			// Дописываем разделитель
			result.append(1, ' ');
			// Дописываем комментарий
			result.append(comment);
		}
		// Выводим строку
		return result;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return "";
	}
}
/**
 * @brief Функция сверки хозяина с записью known_hosts
 *
 * @param record запись known_hosts
 * @param host   сверяемый хозяин
 * @return       признак совпадения
 *
 */
bool nts::keys::ssh::knownHostsMatch(const known_host_t & record, const string & host) noexcept {
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
	/**
	 * Проходим по байтам хеша без раннего выхода
	 */
	for(size_t i = 0; i < width; i++)
		// Накапливаем расхождение
		diff |= static_cast <uint8_t> (computed[i] ^ record.hash[i]);
	// Выполняем затирание вычисленного хеша
	::wipe(computed, sizeof(computed));
	// Хозяин совпадает при нулевом расхождении
	return (diff == 0);
}
/**
 * @brief Функция разбора строки known_hosts
 *
 * @param line   строка known_hosts
 * @param result разобранная запись
 * @return       признак успешности разбора
 *
 */
bool nts::keys::ssh::knownHosts(const string & line, known_host_t & result) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
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
			/**
			 * Выполняем перехват ошибок
			 */
			try {
				// Если строка кончилась
				if(at >= line.size())
					// Выводим отрицательный результат - строка кончилась
					return false;
				// Место конца поля
				const size_t end = line.find(' ', at);
				// Запоминаем поле
				value = line.substr(at, (end == string::npos) ? string::npos : (end - at));
				// Сдвигаем место за поле и пробел
				at = ((end == string::npos) ? line.size() : (end + 1));
				// Выводим признак наличия поля
				return !value.empty();
			/**
			 * Выполняем перехват ошибок
			 */
			} catch(const bad_alloc &) {
				// Выводим отказ нехватки памяти
				return false;
			}
		};
		// Первое поле строки: хозяин либо маркер хеширования
		string marker = "";
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
			// Если соль либо хеш из base64 записать не удалось
			if(!::base64Decode(marker.substr(3, separator - 3), result.salt) || !::base64Decode(marker.substr(separator + 1), result.hash))
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
		// Если тип ключа прочитать не удалось
		if(!field(offset, result.type))
			// Выводим отказ разбора
			return false;
		// Открытый ключ из base64
		string encoded = "";
		// Если поле ключа прочитать либо декодировать не удалось
		if(!field(offset, encoded) || !::base64Decode(encoded, result.key))
			// Выводим отказ разбора
			return false;
		// Если ключ пуст
		if(result.key.empty())
			// Выводим отказ разбора
			return false;
		// Если за ключом остался комментарий
		if(offset < line.size())
			// Запоминаем комментарий
			result.comment = line.substr(offset);
		// Выводим признак успешности разбора
		return true;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return false;
	}
}
/**
 * @brief Функция сборки строки known_hosts
 *
 * @param host    хозяин
 * @param key     открытый ключ
 * @param comment комментарий
 * @param hashed  признак хеширования хозяина
 * @param result  собранная строка
 * @return        признак успешности сборки
 *
 */
bool nts::keys::ssh::knownHosts(const string & host, const key_t & key, const string & comment, const bool hashed, string & result) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Если хозяин пуст либо ключ негоден
		if(host.empty() || (key.kind != kind_t::ED25519) || (key.key.size() != 32))
			// Выводим отказ сборки
			return false;
		// Блок открытого ключа
		vector <uint8_t> pubblock;
		// Заводим записыватель блока
		writer_t pubwriter(pubblock);
		// Записываем тип ключа
		pubwriter.add("ssh-ed25519");
		// Записываем открытый ключ
		pubwriter.add(key.key);
		// Начало строки: хозяин открытым текстом либо хешем
		string beginning = "";
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
				::wipe(salt, sizeof(salt));
				// Выводим отказ сборки
				return false;
			}
			// Собираем маркер хеширования
			beginning = ("|1|" + ::base64Encode(salt, sizeof(salt)) + "|" + ::base64Encode(hash, sizeof(hash)));
			// Выполняем затирание рабочих областей
			::wipe(salt, sizeof(salt));
			::wipe(hash, sizeof(hash));
		// Иначе хозяин открытым текстом, запоминаем хозяина
		} else beginning = host;
		// Собираем строку
		result = (beginning + " ssh-ed25519 " + ::base64Encode(pubblock.data(), pubblock.size()));
		// Если комментарий задан
		if(!comment.empty())
			// Дописываем комментарий
			result += (" " + comment);
		// Выводим признак успешности сборки
		return true;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return false;
	}
}
/**
 * @brief Функция разбора ключа openssh-key-v1
 *
 * @param data     запись ключа (DER либо PEM)
 * @param password пароль для зашифрованного ключа, пустой для незашифрованного
 * @param key      разобранный ключ
 * @param comment  комментарий ключа
 * @return         признак успешности разбора
 *
 */
bool nts::keys::ssh::decode(const view_t & data, const view_t & password, key_t & key, string & comment) noexcept {
	// Если данные пусты либо короче магии
	if((data.data == nullptr) || (data.size < MAGIC_SIZE))
		// Выводим отказ разбора
		return false;
	// Если магия не совпала
	if(::memcmp(data.data, MAGIC, MAGIC_SIZE) != 0)
		// Выводим отказ разбора
		return false;
	// Заводим разборщик остатка данных за магией
	reader_t reader(data.data + MAGIC_SIZE, data.size - MAGIC_SIZE);
	// Имя шифра
	string ciphername = "";
	// Если имя шифра прочитать не удалось
	if(!reader.get(ciphername))
		// Выводим отказ разбора
		return false;
	// Имя функции выработки ключа
	string kdfname = "";
	// Если имя функции прочитать не удалось
	if(!reader.get(kdfname))
		// Выводим отказ разбора
		return false;
	// Параметры функции выработки ключа
	vector <uint8_t> kdfoptions;
	// Если параметры прочитать не удалось
	if(!reader.get(kdfoptions))
		// Выводим отказ разбора
		return false;
	// Число ключей
	uint32_t nkeys = 0;
	// Если число ключей прочитать не удалось
	if(!reader.get(nkeys))
		// Выводим отказ разбора
		return false;
	// Если ключей не один
	if(nkeys != 1)
		// Выводим отказ разбора
		return false;
	// Открытый ключ
	vector <uint8_t> pubkey;
	// Если открытый ключ прочитать не удалось
	if(!reader.get(pubkey))
		// Выводим отказ разбора
		return false;
	// Секретный блок
	vector <uint8_t> privblock;
	// Если секретный блок прочитать не удалось
	if(!reader.get(privblock))
		// Выводим отказ разбора
		return false;
	// Если шифрование есть
	if(ciphername == "aes256-ctr"){
		// Если функция выработки ключа не bcrypt
		if(kdfname != "bcrypt")
			// Выводим отказ разбора
			return false;
		// Если пароль пуст
		if((password.data == nullptr) || (password.size == 0))
			// Выводим отказ разбора
			return false;
		// Заводим разборщик параметров: соль + число кругов
		reader_t kdfreader(kdfoptions.data(), kdfoptions.size());
		// Соль выработки ключа
		vector <uint8_t> salt;
		// Если соль прочитать не удалось
		if(!kdfreader.get(salt))
			// Выводим отказ разбора
			return false;
		// Число кругов выработки ключа
		uint32_t rounds = 0;
		// Если число кругов прочитать не удалось
		if(!kdfreader.get(rounds))
			// Выводим отказ разбора
			return false;
		// Ключ шифрования с IV
		uint8_t enckey[KEY_SIZE + IV_SIZE];
		// Если ключ выработать не удалось
		if(!digest::bcrypt(password, view_t(salt.data(), salt.size()), enckey, sizeof(enckey), rounds))
			// Выводим отказ разбора
			return false;
		// Модуль шифра AES
		cipher::aes_t aes;
		// Если ключ шифру установить не удалось
		if(!aes.key(view_t(enckey, KEY_SIZE))){
			// Выполняем затирание ключа
			::wipe(enckey, sizeof(enckey));
			// Выводим отказ разбора
			return false;
		}
		// Счётчик гаммы
		uint8_t counter[IV_SIZE];
		// Запоминаем начальный счётчик из IV
		::memcpy(counter, enckey + KEY_SIZE, IV_SIZE);
		// Гамма шифра
		uint8_t gamma[IV_SIZE];
		/**
		 * Проходим по секретному блоку кусками по размеру блока
		 */
		for(size_t off = 0; off < privblock.size(); off += IV_SIZE){
			// Если гамму выработать не удалось
			if(!aes.encrypt(counter, gamma)){
				// Выполняем затирание ключа
				::wipe(enckey, sizeof(enckey));
				// Выводим отказ разбора
				return false;
			}
			// Длина куска: последний может быть короче блока
			const size_t chunk = (((privblock.size() - off) < IV_SIZE) ? (privblock.size() - off) : IV_SIZE);
			/**
			 * Проходим по байтам куска
			 */
			for(size_t i = 0; i < chunk; ++i)
				// Накладываем гамму на байт
				privblock[off + i] ^= gamma[i];
			/**
			 * Инкрементируем счётчик как big-endian
			 */
			for(size_t i = IV_SIZE; i > 0; --i){
				// Если переноса нет
				if(++counter[i - 1] != 0)
					// Инкремент завершён
					break;
			}
		}
		// Выполняем затирание рабочих областей
		::wipe(enckey, sizeof(enckey));
		::wipe(counter, sizeof(counter));
		::wipe(gamma, sizeof(gamma));
	// Иначе если шифр чужой
	} else if(ciphername != "none")
		// Выводим отказ разбора
		return false;
	// Заводим разборщик секретного блока
	reader_t privreader(privblock.data(), privblock.size());
	// Разбираем секретный блок
	const bool result = ::parsePrivate(privreader, key, comment);
	// Выполняем затирание секретного блока
	::wipe(privblock.data(), privblock.size());
	// Выводим признак успешности разбора
	return result;
}
/**
 * @brief Функция записи ключа openssh-key-v1
 *
 * @param key      ключ для записи
 * @param comment  комментарий ключа
 * @param password пароль для шифрования, пустой для незашифрованной записи
 * @param result   место, в которое помещается запись DER
 * @return         признак успешности записи
 *
 */
bool nts::keys::ssh::encode(const key_t & key, const string & comment, const view_t & password, vector <uint8_t> & result) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Если ключ негоден
		if((key.kind != kind_t::ED25519) || (key.d.size() != 32) || (key.key.size() != 32))
			// Выводим отказ записи
			return false;
		// Сбрасываем набор байтов записи ключа перед сборкой
		result.clear();
		// Записываем магию
		result.insert(result.end(), MAGIC, MAGIC + MAGIC_SIZE);
		// Заводим записыватель результата
		writer_t writer(result);
		// Признак шифрования: пароль задан
		const bool encrypted = (password.data != nullptr && password.size > 0);
		// Соль для шифрования
		uint8_t salt[SALT_SIZE];
		// Если шифрование есть
		if(encrypted){
			// Записываем имя шифра
			writer.add("aes256-ctr");
			// Записываем имя функции выработки ключа
			writer.add("bcrypt");
			// Если соль выработать не удалось
			if(!entropy::bytes(salt, sizeof(salt)))
				// Выводим отказ записи
				return false;
			// Параметры функции выработки ключа
			vector <uint8_t> kdfoptions;
			// Заводим записыватель параметров
			writer_t kdfwriter(kdfoptions);
			// Записываем соль
			kdfwriter.add(salt, sizeof(salt));
			// Записываем число кругов
			kdfwriter.add(DEFAULT_ROUNDS);
			// Записываем параметры
			writer.add(kdfoptions);
		// Иначе шифрования нет
		} else {
			// Записываем отсутствие шифра
			writer.add("none");
			// Записываем отсутствие функции выработки ключа
			writer.add("none");
			// Записываем пустые параметры
			writer.add(view_t());
		}
		// Записываем число ключей
		writer.add(1);
		// Блок открытого ключа
		vector <uint8_t> pubblock;
		{
			// Заводим записыватель блока
			writer_t pubwriter(pubblock);
			// Записываем тип ключа
			pubwriter.add("ssh-ed25519");
			// Записываем открытый ключ
			pubwriter.add(key.key);
		}
		// Записываем блок открытого ключа
		writer.add(pubblock);
		// Секретный блок
		vector <uint8_t> privblock;
		{
			// Заводим записыватель секретного блока
			writer_t privwriter(privblock);
			// Записываем секретный блок
			writePrivate(privwriter, key, comment);
		}
		// Если шифрование есть
		if(encrypted){
			// Ключ шифрования с IV
			uint8_t enckey[KEY_SIZE + IV_SIZE];
			// Если ключ выработать не удалось
			if(!digest::bcrypt(password, view_t(salt, sizeof(salt)), enckey, sizeof(enckey), DEFAULT_ROUNDS)){
				// Выполняем затирание секретного блока
				::wipe(privblock.data(), privblock.size());
				// Выводим отказ записи
				return false;
			}
			// Модуль шифра AES
			cipher::aes_t aes;
			// Если ключ шифру установить не удалось
			if(!aes.key(view_t(enckey, KEY_SIZE))){
				// Выполняем затирание ключа
				::wipe(enckey, sizeof(enckey));
				// Выполняем затирание секретного блока
				::wipe(privblock.data(), privblock.size());
				// Выводим отказ записи
				return false;
			}
			// Счётчик гаммы
			uint8_t counter[IV_SIZE];
			// Запоминаем начальный счётчик из IV
			::memcpy(counter, enckey + KEY_SIZE, IV_SIZE);
			// Гамма шифра
			uint8_t gamma[IV_SIZE];
			/**
			 * Проходим по секретному блоку кусками по размеру блока
			 */
			for(size_t off = 0; off < privblock.size(); off += IV_SIZE){
				// Если гамму выработать не удалось
				if(!aes.encrypt(counter, gamma)){
					// Выполняем затирание ключа
					::wipe(enckey, sizeof(enckey));
					// Выполняем затирание секретного блока
					::wipe(privblock.data(), privblock.size());
					// Выводим отказ записи
					return false;
				}
				// Длина куска: последний может быть короче блока
				const size_t chunk = (privblock.size() - off < IV_SIZE) ? privblock.size() - off : IV_SIZE;
				/**
				 * Проходим по байтам куска
				 */
				for(size_t i = 0; i < chunk; ++i)
					// Накладываем гамму на байт
					privblock[off + i] ^= gamma[i];
				/**
				 * Инкрементируем счётчик как big-endian
				 */
				for(size_t i = IV_SIZE; i > 0; --i){
					// Если переноса нет
					if(++counter[i - 1] != 0)
						// Инкремент завершён
						break;
				}
			}
			// Выполняем затирание рабочих областей
			::wipe(enckey, sizeof(enckey));
			::wipe(counter, sizeof(counter));
			::wipe(gamma, sizeof(gamma));
		}
		// Записываем секретный блок
		writer.add(privblock);
		// Выполняем затирание секретного блока
		::wipe(privblock.data(), privblock.size());
		// Выводим признак успешности записи
		return true;
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим отказ нехватки памяти
		return false;
	}
}
