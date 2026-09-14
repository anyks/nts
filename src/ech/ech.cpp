/**
 * @file ech.cpp
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
 * @brief Реализация модуля зашифрованного приветствия клиента ECH по RFC 9849
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
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <ech/ech.hpp>
#include <sys/wipe.hpp>
#include <agreement/x25519.hpp>
#include <digest/hkdf.hpp>

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
	 * @brief Метод проверки публичного имени конфигурации на вид имени DNS
	 *
	 * @param name публичное имя
	 *
	 * @return     признак годного имени: метки LDH через точку, без дефиса на краях метки, не литерал IPv4 (раздел 4 RFC 9849)
	 *
	 */
	static bool named(const string & name) noexcept {
		// Пустое либо чрезмерное имя негодно
		if(name.empty() || (name.size() > 253))
			return false;
		// Начало текущей метки и признак того, что все знаки - цифры и точки (литерал IPv4)
		size_t start = 0;
		bool digits = true;
		/**
		 * Выполняем перебор знаков имени метка за меткой
		 */
		for(size_t i = 0; i <= name.size(); i++){
			// Если метка кончилась
			if((i == name.size()) || (name[i] == '.')){
				// Длина метки
				const size_t length = (i - start);
				// Пустая либо длинная метка, дефис на краю метки - негодно
				if((length == 0) || (length > 63) || (name[start] == '-') || (name[i - 1] == '-'))
					return false;
				// Начало следующей метки
				start = (i + 1);
				continue;
			}
			// Знак метки
			const char sign = name[i];
			// Если знак не буква, не цифра и не дефис
			if(!(((sign >= 'a') && (sign <= 'z')) || ((sign >= 'A') && (sign <= 'Z')) || ((sign >= '0') && (sign <= '9')) || (sign == '-')))
				return false;
			// Не цифра - не литерал IPv4
			if(!((sign >= '0') && (sign <= '9')))
				digits = false;
		}
		// Литерал IPv4 негоден (SHOULD раздела 4 RFC 9849)
		return !digits;
	}
	/**
	 * Пространство имён библиотеки
	 */
	using namespace nts;

	/**
	 * Намеренные решения модуля
	 *
	 * 1. Признаётся одно издание конфигурации - 0xFE0D (RFC 9849); конфигурации иных
	 *    изданий в перечне пропускаются по длине, как велит раздел 4.
	 * 2. Конфигурация хранит себя как записана (`raw`): привязка HPKE обязана совпадать
	 *    байт в байт у сторон, и складывать её заново из полей было бы вторым источником
	 *    истины.
	 * 3. Восстановление внутреннего приветствия строго по разделу 7.1: всякая негодная
	 *    ссылка ech_outer_extensions - отказ OUTER, а хвост заполнения обязан быть нулевым.
	 */

	/**
	 * Привязка HPKE конфигурации: «tls ech» и нулевой байт
	 */
	static const uint8_t BINDING[] = {'t', 'l', 's', ' ', 'e', 'c', 'h', 0x00};

	/**
	 * Метки подтверждения принятия
	 */
	static const char ACCEPT[] = "ech accept confirmation";
	static const char RETRY[] = "hrr ech accept confirmation";

	/**
	 * Виды расширения encrypted_client_hello
	 */
	static constexpr uint8_t OUTER = 0x00;
	static constexpr uint8_t INNER = 0x01;

	/**
	 * Наибольшая длина перечня вынесенных расширений
	 */
	static constexpr size_t OUTSOURCED = 127;

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
	 * @brief Метод дописывания числа старшим байтом вперёд
	 *
	 * @param value  дописываемое число
	 * @param width  ширина числа в байтах
	 * @param result накопитель
	 *
	 */
	static void inscribe(const size_t value, const size_t width, vector <uint8_t> & result) {
		/**
		 * Выполняем перебор байтов числа от старшего к младшему
		 */
		for(size_t i = width; i > 0; i--)
			// Дописываем очередной байт числа
			result.push_back(static_cast <uint8_t> (value >> ((i - 1) * 8)));
	}
	/**
	 * @brief Метод записи двухбайтовой длины в заранее занятое место
	 *
	 * @param result накопитель
	 * @param place  место длины
	 * @param length записываемая длина
	 *
	 */
	static void backfill(vector <uint8_t> & result, const size_t place, const size_t length) noexcept {
		// Записываем старший байт длины
		result[place] = static_cast <uint8_t> (length >> 8);
		// Записываем младший байт длины
		result[place + 1] = static_cast <uint8_t> (length);
	}
	/**
	 * @brief Метод разбора содержимого конфигурации ECHConfigContents
	 *
	 * @param data   содержимое конфигурации
	 * @param result конфигурация
	 * @return       отказ разбора
	 *
	 */
	static ech::error_t contents(const view_t & data, ech::config_t & result) {
		// Смещение внутри содержимого
		size_t offset = 0;
		// Если заголовок ключа не помещается: опознаватель, способ, длина ключа
		if(data.size < 5)
			// Выводим отказ обрыва
			return ech::error_t::HUNGRY;
		// Читаем опознаватель конфигурации
		result.id = data.data[offset++];
		// Читаем способ инкапсуляции ключа
		result.kem = static_cast <hpke::kem_t> (twain(data.data + offset));
		// Переходим за способ
		offset += 2;
		// Длина открытой части ключа
		size_t length = twain(data.data + offset);
		// Переходим за длину
		offset += 2;
		// Если ключ пуст
		if(length == 0)
			// Выводим отказ пустого поля
			return ech::error_t::EMPTY;
		// Если ключ в содержимое не входит
		if((offset + length + 2) > data.size)
			// Выводим отказ обрыва
			return ech::error_t::HUNGRY;
		// Читаем открытую часть ключа
		result.key.assign(data.data + offset, data.data + offset + length);
		// Переходим за ключ
		offset += length;
		// Длина перечня наборов
		length = twain(data.data + offset);
		// Переходим за длину
		offset += 2;
		// Если перечень наборов пуст, нечётной ширины либо в содержимое не входит
		if((length < 4) || ((length % 4) != 0) || ((offset + length + 2) > data.size))
			// Выводим отказ записи
			return ech::error_t::FORMAT;
		/**
		 * Выполняем перебор наборов
		 */
		for(size_t i = 0; i < length; i += 4)
			// Добавляем набор в перечень
			result.suites.push_back(ech::suite_t(static_cast <hpke::kdf_t> (twain(data.data + offset + i)), static_cast <hpke::aead_t> (twain(data.data + offset + i + 2))));
		// Переходим за перечень наборов
		offset += length;
		// Читаем наибольшую длину имени
		result.length = data.data[offset++];
		// Длина публичного имени
		length = data.data[offset++];
		// Если имя пусто
		if(length == 0)
			// Выводим отказ пустого поля
			return ech::error_t::EMPTY;
		// Если имя в содержимое не входит
		if((offset + length + 2) > data.size)
			// Выводим отказ обрыва
			return ech::error_t::HUNGRY;
		// Читаем публичное имя
		result.name.assign(reinterpret_cast <const char *> (data.data + offset), length);
		// Переходим за имя
		offset += length;
		// Длина расширений конфигурации
		length = twain(data.data + offset);
		// Переходим за длину
		offset += 2;
		// Если расширения в содержимое не входят
		if((offset + length) != data.size)
			// Выводим отказ записи
			return ech::error_t::FORMAT;
		// Читаем расширения конфигурации как записаны
		/**
		 * Раздел 4 RFC 9849: перечень расширений есть Extension<0..2^16-1> из вида (2 байта)
		 * и тела с длиной (2 байта) - обрыв внутри перечня делает конфигурацию негодной
		 */
		for(size_t at = 0; at < length;){
			// Если заголовка расширения не осталось
			if((at + 4) > length)
				return ech::error_t::FORMAT;
			// Длина тела расширения
			const size_t body = twain(data.data + offset + at + 2);
			// Если тело выходит за перечень
			if((at + 4 + body) > length)
				return ech::error_t::FORMAT;
			// Переходим за расширение
			at += (4 + body);
		}
		result.extensions.assign(data.data + offset, data.data + offset + length);
		// Выводим успешность разбора
		return ech::error_t::NONE;
	}
	/**
	 * @brief Метод разбора одной конфигурации из перечня
	 *
	 * @param data    разбираемые байты от начала конфигурации
	 * @param result  конфигурация
	 * @param consumed число прочитанных байтов
	 * @return        отказ разбора: VERSION у чужого издания (конфигурация пропущена по длине)
	 *
	 */
	static ech::error_t solitary(const view_t & data, ech::config_t & result, size_t & consumed) {
		// Сбрасываем конфигурацию
		result = ech::config_t();
		// Если заголовок конфигурации не помещается
		if(data.size < 4)
			// Выводим отказ обрыва
			return ech::error_t::HUNGRY;
		// Издание конфигурации
		const uint16_t version = twain(data.data);
		// Длина содержимого
		const size_t length = twain(data.data + 2);
		// Если содержимое не помещается
		if((4 + length) > data.size)
			// Выводим отказ обрыва
			return ech::error_t::HUNGRY;
		// Запоминаем число прочитанных байтов
		consumed = (4 + length);
		// Если издание чужое
		if(version != ech::ECH_VERSION)
			// Выводим отказ издания
			return ech::error_t::VERSION;
		// Отказ разбора содержимого
		const ech::error_t failure = contents(view_t(data.data + 4, length), result);
		// Если содержимое разобрать не удалось
		if(failure != ech::error_t::NONE)
			// Выводим отказ разбора
			return failure;
		// Запоминаем конфигурацию как записана
		result.raw.assign(data.data, data.data + consumed);
		// Выводим успешность разбора
		return ech::error_t::NONE;
	}
	/**
	 * @brief Метод измерения длины тела приветствия клиента без хвоста
	 *
	 * @param data   байты приветствия с возможным хвостом заполнения
	 * @param length место, в которое помещается длина тела
	 * @return       отказ измерения
	 *
	 */
	static ech::error_t measure(const view_t & data, const bool datagram, size_t & length) noexcept {
		// Смещение внутри байтов: издание и случайное значение
		size_t offset = (2 + hello::HELLO_RANDOM);
		// Если заголовок приветствия не помещается
		if(data.size < (offset + 1))
			// Выводим отказ обрыва
			return ech::error_t::HUNGRY;
		// Переходим за опознаватель связи
		offset += (1 + data.data[offset]);
		// Поверх дейтаграмм за опознавателем связи идёт поле метки возврата состояния (RFC 9147)
		if(datagram){
			// Если байта длины метки нет
			if((offset + 1) > data.size)
				// Выводим отказ нехватки байтов
				return ech::error_t::HUNGRY;
			// Пропускаем метку
			offset += (1 + data.data[offset]);
		}
		// Если перечень наборов не помещается
		if((offset + 2) > data.size)
			// Выводим отказ обрыва
			return ech::error_t::HUNGRY;
		// Переходим за перечень наборов
		offset += (2 + twain(data.data + offset));
		// Если перечень способов сжатия не помещается
		if((offset + 1) > data.size)
			// Выводим отказ обрыва
			return ech::error_t::HUNGRY;
		// Переходим за перечень способов сжатия
		offset += (1 + data.data[offset]);
		// Если перечень расширений не помещается
		if((offset + 2) > data.size)
			// Выводим отказ обрыва
			return ech::error_t::HUNGRY;
		// Переходим за перечень расширений
		offset += (2 + twain(data.data + offset));
		// Если тело в байты не входит
		if(offset > data.size)
			// Выводим отказ обрыва
			return ech::error_t::HUNGRY;
		// Запоминаем длину тела
		length = offset;
		// Выводим успешность измерения
		return ech::error_t::NONE;
	}
};

/**
 * @brief Метод разбора перечня конфигураций ECHConfigList
 *
 * @param data   разбираемый перечень
 * @param result перечень конфигураций признаваемого издания
 *
 * @return       отказ разбора
 *
 */
nts::ech::error_t nts::ech::parse(const view_t & data, vector <config_t> & result) noexcept {
	/**
	 * Выполняем перехват нехватки памяти
	 */
	try {
		// Сбрасываем перечень
		result.clear();
		// Если длина перечня не помещается
		if((data.data == nullptr) || (data.size < 2))
			// Выводим отказ обрыва
			return error_t::HUNGRY;
		// Длина перечня
		const size_t length = twain(data.data);
		// Если перечень пуст либо в байты не входит
		if((length < 4) || ((2 + length) != data.size))
			// Выводим отказ записи
			return error_t::FORMAT;
		// Смещение внутри перечня
		size_t offset = 2;
		/**
		 * Выполняем перебор конфигураций перечня
		 */
		while(offset < data.size){
			// Конфигурация
			config_t config;
			// Число прочитанных байтов
			size_t consumed = 0;
			// Отказ разбора конфигурации
			const error_t failure = solitary(view_t(data.data + offset, data.size - offset), config, consumed);
			// Если конфигурация оборвана либо сложена не по правилам
			if((failure != error_t::NONE) && (failure != error_t::VERSION)){
				// Сбрасываем перечень
				result.clear();
				// Выводим отказ разбора
				return failure;
			}
			// Переходим за конфигурацию
			offset += consumed;
			// Если издание чужое
			if(failure == error_t::VERSION)
				// Переходим к следующей конфигурации
				continue;
			// Признак наличия признаваемого набора
			bool usable = false;
			/**
			 * Выполняем перебор наборов конфигурации
			 */
			for(size_t i = 0; (i < config.suites.size()) && !usable; i++)
				// Запоминаем признаваемость набора
				usable = supported(config.kem, config.suites[i]);
			/**
			 * Раздел 4.2 RFC 9849: конфигурация с обязательным (старший разряд вида)
			 * расширением, клиенту неведомым, пропускается; здесь неведомы все. Открытый
			 * ключ обязан быть длиной ключа KEM, иначе отправителя HPKE не завести и
			 * следующая годная конфигурация перечня осталась бы непопробованной
			 */
			for(size_t at = 0; usable && ((at + 4) <= config.extensions.size()); at += (4 + twain(config.extensions.data() + at + 2)))
				// Обязательное расширение делает конфигурацию негодной
				usable = ((config.extensions[at] & 0x80) == 0);
			// Если ключ не длиной ключа KEM: у X25519 тридцать два байта
			if(usable && (config.key.size() != agreement::X25519_SIZE))
				// Конфигурация негодна
				usable = false;
			// Раздел 4 RFC 9849: конфигурация с публичным именем не вида DNS пропускается
			if(usable && !named(config.name))
				// Конфигурация негодна
				usable = false;
			// Если конфигурация исполнима
			if(usable)
				// Добавляем конфигурацию в перечень
				result.push_back(config);
		}
		// Выводим итог: без единой признаваемой конфигурации - отказ издания
		return (result.empty() ? error_t::VERSION : error_t::NONE);
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
 * @brief Метод разбора одной конфигурации ECHConfig
 *
 * @param data   разбираемая конфигурация
 * @param result конфигурация
 *
 * @return       отказ разбора
 *
 */
nts::ech::error_t nts::ech::parse(const view_t & data, config_t & result) noexcept {
	/**
	 * Выполняем перехват нехватки памяти
	 */
	try {
		// Число прочитанных байтов
		size_t consumed = 0;
		// Если байтов нет
		if(data.data == nullptr)
			// Выводим отказ обрыва
			return error_t::HUNGRY;
		// Отказ разбора конфигурации
		const error_t failure = solitary(data, result, consumed);
		// Если конфигурация не разобрана
		if(failure != error_t::NONE){
			// Сбрасываем конфигурацию
			result = config_t();
			// Выводим отказ разбора
			return failure;
		}
		// Если за конфигурацией идут лишние байты
		if(consumed != data.size){
			// Сбрасываем конфигурацию
			result = config_t();
			// Выводим отказ записи
			return error_t::FORMAT;
		}
		// Выводим успешность разбора
		return error_t::NONE;
	/**
	 * Если памяти не хватило
	 */
	} catch(const bad_alloc &) {
		// Сбрасываем конфигурацию
		result = config_t();
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
}
/**
 * @brief Метод составления одной конфигурации ECHConfig
 *
 * @param config составляемая конфигурация
 * @param result накопитель, в конец которого дописывается конфигурация
 *
 * @return       отказ составления
 *
 */
nts::ech::error_t nts::ech::build(const config_t & config, vector <uint8_t> & result) noexcept {
	/**
	 * Выполняем перехват нехватки памяти
	 */
	try {
		// Если ключ, наборы либо имя пусты
		if(config.key.empty() || config.suites.empty() || config.name.empty())
			// Выводим отказ пустого поля
			return error_t::EMPTY;
		// Если поля в свои ширины не входят
		if((config.key.size() > 0xFFFF) || (config.suites.size() > 0x3FFF) || (config.name.size() > ECH_NAME) || (config.extensions.size() > 0xFFFF))
			// Выводим отказ длины
			return error_t::LENGTH;
		// Начало конфигурации в накопителе
		const size_t start = result.size();
		// Дописываем издание
		inscribe(ECH_VERSION, 2, result);
		// Место длины содержимого
		const size_t place = result.size();
		// Занимаем место под длину содержимого
		inscribe(0, 2, result);
		// Дописываем опознаватель
		result.push_back(config.id);
		// Дописываем способ инкапсуляции
		inscribe(static_cast <uint16_t> (config.kem), 2, result);
		// Дописываем длину ключа
		inscribe(config.key.size(), 2, result);
		// Дописываем ключ
		result.insert(result.end(), config.key.begin(), config.key.end());
		// Дописываем длину перечня наборов
		inscribe(config.suites.size() * 4, 2, result);
		/**
		 * Выполняем перебор наборов
		 */
		for(size_t i = 0; i < config.suites.size(); i++){
			// Дописываем функцию вывода
			inscribe(static_cast <uint16_t> (config.suites[i].kdf), 2, result);
			// Дописываем шифр
			inscribe(static_cast <uint16_t> (config.suites[i].aead), 2, result);
		}
		// Дописываем наибольшую длину имени
		result.push_back(config.length);
		// Дописываем длину имени
		result.push_back(static_cast <uint8_t> (config.name.size()));
		// Дописываем имя
		result.insert(result.end(), config.name.begin(), config.name.end());
		// Дописываем длину расширений
		inscribe(config.extensions.size(), 2, result);
		// Дописываем расширения
		result.insert(result.end(), config.extensions.begin(), config.extensions.end());
		// Длина содержимого
		const size_t length = (result.size() - place - 2);
		// Если содержимое в свою длину не входит
		if(length > 0xFFFF){
			// Снимаем дописанное
			result.resize(start);
			// Выводим отказ длины
			return error_t::LENGTH;
		}
		// Записываем длину содержимого
		backfill(result, place, length);
		// Выводим успешность составления
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
 * @brief Метод составления перечня конфигураций ECHConfigList
 *
 * @param configs составляемые конфигурации
 * @param result  накопитель, в конец которого дописывается перечень
 *
 * @return        отказ составления
 *
 */
nts::ech::error_t nts::ech::build(const vector <config_t> & configs, vector <uint8_t> & result) noexcept {
	/**
	 * Выполняем перехват нехватки памяти
	 */
	try {
		// Если конфигураций нет
		if(configs.empty())
			// Выводим отказ пустого поля
			return error_t::EMPTY;
		// Начало перечня в накопителе
		const size_t start = result.size();
		// Место длины перечня
		const size_t place = result.size();
		// Занимаем место под длину перечня
		inscribe(0, 2, result);
		/**
		 * Выполняем перебор конфигураций
		 */
		for(size_t i = 0; i < configs.size(); i++){
			// Отказ составления конфигурации
			const error_t failure = build(configs[i], result);
			// Если конфигурацию составить не удалось
			if(failure != error_t::NONE){
				// Снимаем дописанное
				result.resize(start);
				// Выводим отказ составления
				return failure;
			}
		}
		// Длина перечня
		const size_t length = (result.size() - place - 2);
		// Если перечень в свою длину не входит
		if(length > 0xFFFF){
			// Снимаем дописанное
			result.resize(start);
			// Выводим отказ длины
			return error_t::LENGTH;
		}
		// Записываем длину перечня
		backfill(result, place, length);
		// Выводим успешность составления
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
 * @brief Метод разбора тела расширения encrypted_client_hello
 *
 * @param data   тело расширения
 * @param result расширение
 *
 * @return       отказ разбора
 *
 */
nts::ech::error_t nts::ech::parse(const view_t & data, hello_t & result) noexcept {
	/**
	 * Выполняем перехват нехватки памяти
	 */
	try {
		// Сбрасываем расширение
		result = hello_t();
		// Если вид не помещается
		if((data.data == nullptr) || (data.size < 1))
			// Выводим отказ обрыва
			return error_t::HUNGRY;
		// Если расширение внутреннего вида
		if(data.data[0] == INNER){
			// Если за видом идут лишние байты
			if(data.size != 1)
				// Выводим отказ записи
				return error_t::FORMAT;
			// Отмечаем внутренний вид
			result.inner = true;
			// Выводим успешность разбора
			return error_t::NONE;
		}
		// Если вид неведом
		if(data.data[0] != OUTER)
			// Выводим отказ записи
			return error_t::FORMAT;
		// Смещение внутри тела: вид, набор, опознаватель, длина enc
		size_t offset = 1;
		// Если заголовок не помещается
		if(data.size < (offset + 4 + 1 + 2))
			// Выводим отказ обрыва
			return error_t::HUNGRY;
		// Читаем функцию вывода
		result.suite.kdf = static_cast <hpke::kdf_t> (twain(data.data + offset));
		// Читаем шифр
		result.suite.aead = static_cast <hpke::aead_t> (twain(data.data + offset + 2));
		// Переходим за набор
		offset += 4;
		// Читаем опознаватель конфигурации
		result.id = data.data[offset++];
		// Длина инкапсулированного ключа
		size_t length = twain(data.data + offset);
		// Переходим за длину
		offset += 2;
		// Если ключ в тело не входит
		if((offset + length + 2) > data.size)
			// Выводим отказ обрыва
			return error_t::HUNGRY;
		// Читаем инкапсулированный ключ
		result.enc.assign(data.data + offset, data.data + offset + length);
		// Переходим за ключ
		offset += length;
		// Длина шифротекста
		length = twain(data.data + offset);
		// Переходим за длину
		offset += 2;
		// Если шифротекст пуст
		if(length == 0)
			// Выводим отказ пустого поля
			return error_t::EMPTY;
		// Если шифротекст в тело не входит либо за ним идут лишние байты
		if((offset + length) != data.size)
			// Выводим отказ записи
			return error_t::FORMAT;
		// Читаем шифротекст
		result.payload.assign(data.data + offset, data.data + offset + length);
		// Выводим успешность разбора
		return error_t::NONE;
	/**
	 * Если памяти не хватило
	 */
	} catch(const bad_alloc &) {
		// Сбрасываем расширение
		result = hello_t();
		// Выводим отказ памяти
		return error_t::MEMORY;
	}
}
/**
 * @brief Метод составления тела расширения encrypted_client_hello
 *
 * @param hello  составляемое расширение
 * @param result накопитель, в конец которого дописывается тело
 *
 * @return       отказ составления
 *
 */
nts::ech::error_t nts::ech::build(const hello_t & hello, vector <uint8_t> & result) noexcept {
	/**
	 * Выполняем перехват нехватки памяти
	 */
	try {
		// Если расширение внутреннего вида
		if(hello.inner){
			// Дописываем вид
			result.push_back(INNER);
			// Выводим успешность составления
			return error_t::NONE;
		}
		// Если шифротекст пуст
		if(hello.payload.empty())
			// Выводим отказ пустого поля
			return error_t::EMPTY;
		// Если поля в свои ширины не входят
		if((hello.enc.size() > 0xFFFF) || (hello.payload.size() > 0xFFFF))
			// Выводим отказ длины
			return error_t::LENGTH;
		// Дописываем вид
		result.push_back(OUTER);
		// Дописываем функцию вывода
		inscribe(static_cast <uint16_t> (hello.suite.kdf), 2, result);
		// Дописываем шифр
		inscribe(static_cast <uint16_t> (hello.suite.aead), 2, result);
		// Дописываем опознаватель
		result.push_back(hello.id);
		// Дописываем длину инкапсулированного ключа
		inscribe(hello.enc.size(), 2, result);
		// Дописываем инкапсулированный ключ
		result.insert(result.end(), hello.enc.begin(), hello.enc.end());
		// Дописываем длину шифротекста
		inscribe(hello.payload.size(), 2, result);
		// Дописываем шифротекст
		result.insert(result.end(), hello.payload.begin(), hello.payload.end());
		// Выводим успешность составления
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
 * @brief Метод составления привязки HPKE конфигурации
 *
 * @param config конфигурация как записана на проводе
 * @param result накопитель, в который помещается привязка
 *
 * @return       отказ составления
 *
 */
nts::ech::error_t nts::ech::binding(const view_t & config, vector <uint8_t> & result) noexcept {
	/**
	 * Выполняем перехват нехватки памяти
	 */
	try {
		// Если конфигурации нет
		if((config.data == nullptr) || (config.size == 0))
			// Выводим отказ пустого поля
			return error_t::EMPTY;
		// Сбрасываем накопитель
		result.clear();
		// Дописываем метку привязки
		result.insert(result.end(), BINDING, BINDING + sizeof(BINDING));
		// Дописываем конфигурацию
		result.insert(result.end(), config.data, config.data + config.size);
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
 * @brief Метод подсчёта заполнения закодированного внутреннего приветствия
 *
 * @param named   длина имени узла внутреннего приветствия, ноль без имени
 * @param maximum наибольшая длина имени по конфигурации
 * @param encoded длина закодированного приветствия без заполнения
 *
 * @return        число нулевых байтов заполнения
 *
 */
size_t nts::ech::padding(const size_t named, const size_t maximum, const size_t encoded) noexcept {
	// Заполнение по имени: с именем длины D - max(0, M - D), без имени - M + 9
	const size_t byname = ((named > 0) ? ((maximum > named) ? (maximum - named) : 0) : (maximum + 9));
	// Длина с заполнением по имени
	const size_t length = (encoded + byname);
	// Раздел 6.1.3 RFC 9849: длина доводится до кратной 32
	return (byname + (31 - ((length - 1) % 32)));
}
/**
 * @brief Метод кодирования внутреннего приветствия EncodedClientHelloInner
 *
 * @param inner      внутреннее приветствие
 * @param outsourced виды расширений, вынесенных во внешнее приветствие подряд
 * @param padding    число нулевых байтов заполнения
 * @param result     накопитель, в который помещается закодированное приветствие
 *
 * @return           отказ кодирования
 *
 */
nts::ech::error_t nts::ech::encode(const hello::client_t & inner, const vector <uint16_t> & outsourced, const size_t padding, vector <uint8_t> & result) noexcept {
	// Выводим итог кодирования записью поверх записей
	return encode(inner, outsourced, padding, false, result);
}
/**
 * \~russian
 * @brief Метод кодирования внутреннего приветствия с выбором записи
 *
 * @param inner      внутреннее приветствие
 * @param outsourced виды расширений, выносимых во внешнее приветствие ссылкой
 * @param padding    число нулевых байтов заполнения
 * @param datagram   признак записи поверх дейтаграмм
 * @param result     накопитель закодированного приветствия
 *
 * @return           отказ кодирования
 *
 * \~english
 * @brief Method of the encoding of the inner greeting with the choice of the record
 *
 * @param inner      inner greeting
 * @param outsourced kinds of the extensions carried to the outer greeting by a reference
 * @param padding    number of the zero bytes of the padding
 * @param datagram   sign of the record over datagrams
 * @param result     accumulator of the encoded greeting
 *
 * @return           failure of the encoding
 *
 * \~
 */
nts::ech::error_t nts::ech::encode(const hello::client_t & inner, const vector <uint16_t> & outsourced, const size_t padding, const bool datagram, vector <uint8_t> & result) noexcept {
	/**
	 * Выполняем перехват нехватки памяти
	 */
	try {
		// Сбрасываем накопитель
		result.clear();
		// Если вынесенных расширений слишком много
		if(outsourced.size() > OUTSOURCED)
			// Выводим отказ длины
			return error_t::LENGTH;
		// Кодируемое приветствие: копия внутреннего без опознавателя связи
		hello::client_t encoded;
		// Переносим издание
		encoded.version = inner.version;
		// Переносим случайное значение
		::memcpy(encoded.random, inner.random, hello::HELLO_RANDOM);
		// Переносим метку возврата
		encoded.cookie = inner.cookie;
		// Переносим наборы
		encoded.suites = inner.suites;
		// Переносим способы сжатия
		encoded.methods = inner.methods;
		// Тело расширения ech_outer_extensions
		vector <uint8_t> references;
		// Если расширения выносятся
		if(!outsourced.empty()){
			// Дописываем длину перечня
			references.push_back(static_cast <uint8_t> (outsourced.size() * 2));
			/**
			 * Выполняем перебор вынесенных расширений
			 */
			for(size_t i = 0; i < outsourced.size(); i++){
				// Раздел 5.1 RFC 9849: само encrypted_client_hello и ech_outer_extensions выносить нельзя
				if((outsourced[i] == ECH_EXTENSION) || (outsourced[i] == ECH_OUTER))
					// Выводим отказ ссылок
					return error_t::OUTER;
				// Дописываем вид расширения
				inscribe(outsourced[i], 2, references);
			}
		}
		// Место вынесенных расширений во внутреннем приветствии
		size_t place = inner.extensions.size();
		// Число вынесенных расширений, встреченных подряд
		size_t carried = 0;
		/**
		 * Выполняем перебор расширений внутреннего приветствия
		 */
		for(size_t i = 0; i < inner.extensions.size(); i++){
			// Признак того, что расширение выносится
			bool outsource = false;
			/**
			 * Выполняем перебор вынесенных видов
			 */
			for(size_t j = 0; (j < outsourced.size()) && !outsource; j++)
				// Запоминаем совпадение вида
				outsource = (inner.extensions[i].type == outsourced[j]);
			// Если расширение выносится
			if(outsource){
				// Раздел 5.1 RFC 9849: вынесенные расширения идут подряд и в порядке перечня
				if((carried > 0) && (place + carried != i))
					// Выводим отказ ссылок
					return error_t::OUTER;
				// Если вынесенных больше перечня (повтор вида во внутреннем приветствии) либо расширение не по порядку перечня
				if((carried >= outsourced.size()) || (inner.extensions[i].type != outsourced[carried]))
					// Выводим отказ ссылок
					return error_t::OUTER;
				// Если расширение первое из вынесенных
				if(carried == 0){
					// Запоминаем место
					place = i;
					// Ставим на место ech_outer_extensions
					encoded.extensions.push_back(hello::extension_t(ECH_OUTER, view_t(references.data(), references.size())));
				}
				// Считаем вынесенное расширение
				carried++;
				// Переходим к следующему расширению
				continue;
			}
			// Переносим расширение как есть
			encoded.extensions.push_back(inner.extensions[i]);
		}
		// Если вынесено не всё, что заказано
		if(carried != outsourced.size())
			// Выводим отказ ссылок
			return error_t::OUTER;
		// Отказ составления приветствия
		const hello::error_t failure = hello::build(encoded, result, datagram);
		// Если приветствие составить не удалось
		if(failure != hello::error_t::NONE){
			// Сбрасываем накопитель
			result.clear();
			// Выводим отказ: нехватка памяти своим кодом, прочее - записью
			return ((failure == hello::error_t::MEMORY) ? error_t::MEMORY : error_t::FORMAT);
		}
		// Дописываем заполнение
		result.insert(result.end(), padding, 0x00);
		// Выводим успешность кодирования
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
 * @brief Метод восстановления внутреннего приветствия из закодированного
 *
 * @param encoded закодированное внутреннее приветствие
 * @param outer   внешнее приветствие
 * @param result  накопитель, в который помещается тело внутреннего приветствия
 *
 * @return        отказ восстановления
 *
 */
nts::ech::error_t nts::ech::decode(const view_t & encoded, const hello::client_t & outer, vector <uint8_t> & result) noexcept {
	// Выводим итог восстановления записью поверх записей
	return decode(encoded, outer, false, result);
}
/**
 * \~russian
 * @brief Метод восстановления внутреннего приветствия с выбором записи
 *
 * @param encoded  закодированное внутреннее приветствие
 * @param outer    внешнее приветствие
 * @param datagram признак записи поверх дейтаграмм
 * @param result   накопитель восстановленного приветствия
 *
 * @return         отказ восстановления
 *
 * \~english
 * @brief Method of the restoring of the inner greeting with the choice of the record
 *
 * @param encoded  encoded inner greeting
 * @param outer    outer greeting
 * @param datagram sign of the record over datagrams
 * @param result   accumulator of the restored greeting
 *
 * @return         failure of the restoring
 *
 * \~
 */
nts::ech::error_t nts::ech::decode(const view_t & encoded, const hello::client_t & outer, const bool datagram, vector <uint8_t> & result) noexcept {
	/**
	 * Выполняем перехват нехватки памяти
	 */
	try {
		// Сбрасываем накопитель
		result.clear();
		// Длина тела без заполнения
		size_t length = 0;
		// Отказ измерения тела
		const error_t measured = measure(encoded, datagram, length);
		// Если тело измерить не удалось
		if(measured != error_t::NONE)
			// Выводим отказ измерения
			return measured;
		/**
		 * Выполняем перебор байтов заполнения
		 */
		for(size_t i = length; i < encoded.size; i++){
			// Раздел 5.1 RFC 9849: заполнение обязано быть нулевым
			if(encoded.data[i] != 0x00)
				// Выводим отказ записи
				return error_t::FORMAT;
		}
		// Закодированное приветствие
		hello::client_t inner;
		// Отказ разбора закодированного приветствия
		const hello::error_t parsed = hello::parse(view_t(encoded.data, length), inner, datagram);
		// Если закодированное приветствие разобрать не удалось
		if(parsed != hello::error_t::NONE)
			// Выводим отказ: нехватка памяти своим кодом, прочее - записью
			return ((parsed == hello::error_t::MEMORY) ? error_t::MEMORY : error_t::FORMAT);
		// Раздел 5.1 RFC 9849: опознаватель связи закодированного приветствия пуст
		if(!inner.session.empty())
			// Выводим отказ записи
			return error_t::FORMAT;
		// Восстанавливаемое приветствие
		hello::client_t restored;
		// Переносим издание
		restored.version = inner.version;
		// Переносим случайное значение
		::memcpy(restored.random, inner.random, hello::HELLO_RANDOM);
		// Раздел 7.1 RFC 9849: опознаватель связи копируется из внешнего приветствия
		restored.session = outer.session;
		// Переносим метку возврата
		restored.cookie = inner.cookie;
		// Переносим наборы
		restored.suites = inner.suites;
		// Переносим способы сжатия
		restored.methods = inner.methods;
		// Признак встречи ech_outer_extensions
		bool referenced = false;
		/**
		 * Выполняем перебор расширений закодированного приветствия
		 */
		for(size_t i = 0; i < inner.extensions.size(); i++){
			// Если расширение не есть ech_outer_extensions
			if(inner.extensions[i].type != ECH_OUTER){
				// Переносим расширение как есть
				restored.extensions.push_back(inner.extensions[i]);
				// Переходим к следующему расширению
				continue;
			}
			// Если ech_outer_extensions повторено
			if(referenced)
				// Выводим отказ ссылок
				return error_t::OUTER;
			// Отмечаем встречу
			referenced = true;
			// Тело ссылок
			const view_t & data = inner.extensions[i].data;
			// Если перечень ссылок сложен не по правилам
			if((data.size < 3) || ((data.size - 1) != data.data[0]) || ((data.data[0] % 2) != 0))
				// Выводим отказ ссылок
				return error_t::OUTER;
			// Место последнего взятого расширения внешнего приветствия
			size_t position = 0;
			/**
			 * Выполняем перебор ссылок
			 */
			for(size_t j = 1; j < data.size; j += 2){
				// Вид расширения по ссылке
				const uint16_t type = twain(data.data + j);
				// Разделы 5.1 и 7.1 RFC 9849: ссылка на само encrypted_client_hello либо на ech_outer_extensions негодна - во внутреннем приветствии их быть не вправе
				if((type == ECH_EXTENSION) || (type == ECH_OUTER))
					// Выводим отказ ссылок
					return error_t::OUTER;
				/**
				 * Выполняем перебор ссылок, идущих раньше
				 */
				for(size_t k = 1; k < j; k += 2){
					// Раздел 7.1 RFC 9849: повторная ссылка негодна
					if(twain(data.data + k) == type)
						// Выводим отказ ссылок
						return error_t::OUTER;
				}
				// Признак того, что расширение найдено во внешнем приветствии
				bool found = false;
				/**
				 * Выполняем перебор расширений внешнего приветствия от последнего взятого
				 */
				for(size_t k = position; (k < outer.extensions.size()) && !found; k++){
					// Если расширение найдено
					if(outer.extensions[k].type == type){
						// Переносим расширение внешнего приветствия
						restored.extensions.push_back(outer.extensions[k]);
						// Запоминаем место следующего поиска: порядок обязан совпадать
						position = (k + 1);
						// Отмечаем находку
						found = true;
					}
				}
				// Раздел 7.1 RFC 9849: расширение отсутствует либо идёт не в том порядке
				if(!found)
					// Выводим отказ ссылок
					return error_t::OUTER;
			}
		}
		// Отказ составления приветствия
		const hello::error_t failure = hello::build(restored, result, datagram);
		// Если приветствие составить не удалось
		if(failure != hello::error_t::NONE){
			// Сбрасываем накопитель
			result.clear();
			// Выводим отказ: нехватка памяти своим кодом, прочее - записью
			return ((failure == hello::error_t::MEMORY) ? error_t::MEMORY : error_t::FORMAT);
		}
		// Выводим успешность восстановления
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
 * @brief Метод составления добавочных данных внешнего приветствия ClientHelloOuterAAD
 *
 * @param body   тело внешнего приветствия
 * @param result накопитель, в который помещается тело с обнулённым шифротекстом
 *
 * @return       отказ составления
 *
 */
nts::ech::error_t nts::ech::redact(const view_t & body, vector <uint8_t> & result) noexcept {
	// Выводим итог составления записью поверх записей
	return redact(body, false, result);
}
/**
 * \~russian
 * @brief Метод составления связанных данных из внешнего приветствия с выбором записи
 *
 * @param body     тело внешнего приветствия
 * @param datagram признак записи поверх дейтаграмм
 * @param result   накопитель связанных данных
 *
 * @return         отказ составления
 *
 * \~english
 * @brief Method of the composition of the associated data from the outer greeting with the choice of the record
 *
 * @param body     body of the outer greeting
 * @param datagram sign of the record over datagrams
 * @param result   accumulator of the associated data
 *
 * @return         failure of the composition
 *
 * \~
 */
nts::ech::error_t nts::ech::redact(const view_t & body, const bool datagram, vector <uint8_t> & result) noexcept {
	/**
	 * Выполняем перехват нехватки памяти
	 */
	try {
		// Сбрасываем накопитель
		result.clear();
		// Внешнее приветствие
		hello::client_t outer;
		// Отказ разбора внешнего приветствия
		const hello::error_t parsed = hello::parse(body, outer, datagram);
		// Если внешнее приветствие разобрать не удалось
		if(parsed != hello::error_t::NONE)
			// Выводим отказ: нехватка памяти своим кодом, прочее - записью
			return ((parsed == hello::error_t::MEMORY) ? error_t::MEMORY : error_t::FORMAT);
		// Расширение encrypted_client_hello
		const hello::extension_t * extension = hello::extension(outer.extensions, ECH_EXTENSION);
		// Если расширения нет
		if(extension == nullptr)
			// Выводим отказ пустого поля
			return error_t::EMPTY;
		// Разобранное расширение
		hello_t hello;
		// Отказ разбора расширения
		const error_t failure = parse(extension->data, hello);
		// Если расширение разобрать не удалось
		if(failure != error_t::NONE)
			// Выводим отказ разбора
			return failure;
		// Если расширение внутреннего вида
		if(hello.inner)
			// Выводим отказ записи
			return error_t::FORMAT;
		// Переносим тело
		result.assign(body.data, body.data + body.size);
		// Смещение шифротекста внутри тела: тело расширения указывает в тело приветствия
		const size_t offset = (static_cast <size_t> (extension->data.data - body.data) + extension->data.size - hello.payload.size());
		// Обнуляем шифротекст
		::memset(result.data() + offset, 0x00, hello.payload.size());
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
 * @brief Метод вычисления подтверждения принятия ECH
 *
 * @param algorithm  хеш набора шифрования связи
 * @param random     случайное значение внутреннего приветствия
 * @param transcript хеш переписки с обнулённым подтверждением
 * @param retry      признак просьбы о повторе
 * @param result     место, в которое помещаются восемь байтов подтверждения
 *
 * @return           результат вычисления
 *
 */
bool nts::ech::confirmation(const digest::hash_t algorithm, const view_t & random, const view_t & transcript, const bool retry, uint8_t * result) noexcept {
	// Место, в которое помещается извлечённый секрет
	uint8_t secret[64];
	// Длина хеша
	const size_t size = digest::length(algorithm);
	// Если хеш неведом либо доводы пусты
	if((size == 0) || (size > sizeof(secret)) || (random.data == nullptr) || (random.size != hello::HELLO_RANDOM) || (transcript.size != size) || (result == nullptr))
		// Выводим отказ вычисления
		return false;
	// Раздел 7.2 RFC 9849: HKDF-Extract(0, ClientHelloInner.random)
	if(!digest::extract(algorithm, view_t(nullptr, 0), random, secret, size))
		// Выводим отказ вычисления
		return false;
	// Метка подтверждения
	const char * label = (retry ? RETRY : ACCEPT);
	// Итог развёртывания: HKDF-Expand-Label(secret, метка, transcript, 8)
	const bool derived = digest::label(algorithm, view_t(secret, size), view_t(reinterpret_cast <const uint8_t *> (label), ::strlen(label)), transcript, result, ECH_CONFIRMATION);
	// Выполняем затирание извлечённого секрета
	sys::wipe(secret, sizeof(secret));
	// Выводим итог развёртывания
	return derived;
}
/**
 * @brief Метод проверки, признаётся ли набор HPKE конфигурации
 *
 * @param kem   способ инкапсуляции ключа
 * @param suite набор симметричных алгоритмов
 *
 * @return      признак того, что набор исполним
 *
 */
bool nts::ech::supported(const hpke::kem_t kem, const suite_t & suite) noexcept {
	// Набор HPKE
	hpke::suite_t item;
	// Переносим способ инкапсуляции
	item.kem = kem;
	// Переносим функцию вывода
	item.kdf = suite.kdf;
	// Переносим шифр: только экспорт ECH не годен
	item.aead = suite.aead;
	// Выводим признак поддержки модулем hpke, кроме набора только экспорта
	return ((suite.aead != hpke::aead_t::EXPORT_ONLY) && hpke::supported(item));
}
