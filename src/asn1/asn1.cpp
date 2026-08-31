/**
 * @file asn1.cpp
 * @date 2026-08-26
 *
 * @license{LicenseRef-ANTS-1.0}
 *
 * @author Yuriy Lobarev
 *
 * @telegram{forman}
 * @phone{+7 (910) 983-95-90}
 *
 * @email forman@anyks.com
 * @site https://anyks.com
 *
 * @brief Исходный файл модуля ASN.1 — реализация разбора данных в кодировке DER (X.690)
 *
 * @note Извлечение значения не проверяет номер метки, а проверяет только вид метки
 *       и правила записи содержимого. Основание: в X.509 неявная разметка меток
 *       заменяет универсальный номер номером места употребления, и целое число там
 *       сплошь и рядом приходит с меткой вида [0]. Проверка номера метки возложена
 *       на разбор — на метод Reader::next с ожидаемой меткой, — потому что там
 *       известно, что именно ожидается в этом месте записи.
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
#include <climits>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <asn1/asn1.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * @brief Основное пространство имён
 *
 */
/**
 * @brief Внутренние служебные объекты
 *
 */
namespace {
	/**
	 * Пространство имён библиотеки
	 */
	using namespace anyks;

	/**
	 * Пространство имён модуля
	 */
	using namespace anyks::asn1;

	/**
	 * @brief Метод перевода даты в число суток от начала эпохи
	 *
	 * @param year  год
	 * @param month месяц
	 * @param day   день
	 * @return      число суток от 1 января 1970 года
	 *
	 * @note Перевод выполняется вычислением, а не средствами системы: timegm есть не
	 *       у всякой системы, mktime работает в местном часовом поясе, а оба они
	 *       зависят от настроек окружения. Время сертификата от окружения зависеть
	 *       не может: срок действия обязан читаться одинаково везде
	 *
	 */
	static int64_t civil(const int64_t year, const uint32_t month, const uint32_t day) noexcept {
		// Сдвигаем начало года на март, чем избавляемся от особого положения високосного дня
		const int64_t shifted = (year - static_cast <int64_t> (month <= 2));
		// Определяем номер четырёхсотлетия
		const int64_t era = ((shifted >= 0 ? shifted : (shifted - 399)) / 400);
		// Определяем номер года внутри четырёхсотлетия
		const uint64_t yoe = static_cast <uint64_t> (shifted - (era * 400));
		// Определяем номер дня внутри года, начинающегося с марта
		const uint64_t doy = ((((153 * (month + (month > 2 ? -3 : 9))) + 2) / 5) + day - 1);
		// Определяем номер дня внутри четырёхсотлетия
		const uint64_t doe = ((yoe * 365) + (yoe / 4) - (yoe / 100) + doy);
		// Выводим число суток от начала эпохи
		return ((era * 146097) + static_cast <int64_t> (doe) - 719468);
	}

	/**
	 * @brief Метод перевода числа суток от начала эпохи в дату
	 *
	 * @param days  число суток от 1 января 1970 года
	 * @param year  год
	 * @param month месяц
	 * @param day   день
	 *
	 */
	static void civil(const int64_t days, int64_t & year, uint32_t & month, uint32_t & day) noexcept {
		// Сдвигаем начало отсчёта к началу четырёхсотлетия
		const int64_t shifted = (days + 719468);
		// Определяем номер четырёхсотлетия
		const int64_t era = ((shifted >= 0 ? shifted : (shifted - 146096)) / 146097);
		// Определяем номер дня внутри четырёхсотлетия
		const uint64_t doe = static_cast <uint64_t> (shifted - (era * 146097));
		// Определяем номер года внутри четырёхсотлетия
		const uint64_t yoe = ((doe - (doe / 1460) + (doe / 36524) - (doe / 146096)) / 365);
		// Определяем номер дня внутри года, начинающегося с марта
		const uint64_t doy = (doe - ((365 * yoe) + (yoe / 4) - (yoe / 100)));
		// Определяем номер месяца внутри года, начинающегося с марта
		const uint64_t mp = (((5 * doy) + 2) / 153);
		// Запоминаем день месяца
		day = static_cast <uint32_t> (doy - (((153 * mp) + 2) / 5) + 1);
		// Запоминаем месяц
		month = static_cast <uint32_t> (mp + (mp < 10 ? 3 : -9));
		// Запоминаем год
		year = (static_cast <int64_t> (yoe) + (era * 400) + static_cast <int64_t> (month <= 2));
	}

	/**
	 * @brief Метод извлечения числа из записи десятичными знаками
	 *
	 * @param data   указатель на начало записи числа
	 * @param count  число знаков записи
	 * @param result переменная, в которую помещается результат
	 * @return       признак успешности извлечения
	 *
	 */
	static bool digits(const uint8_t * data, const size_t count, uint32_t & result) noexcept {
		// Обнуляем результат
		result = 0;
		/**
		 * Выполняем обход знаков записи числа
		 */
		for(size_t i = 0; i < count; i++){
			// Если знак записи не является десятичным
			if((data[i] < 0x30) || (data[i] > 0x39))
				// Выводим отказ извлечения
				return false;
			// Дополняем число очередным знаком записи
			result = ((result * 10) + static_cast <uint32_t> (data[i] - 0x30));
		}
		// Выводим успешность извлечения
		return true;
	}

	/**
	 * @brief Метод проверки записи в кодировке UTF-8 с извлечением знаков
	 *
	 * @param view   просмотр проверяемой записи
	 * @param result набор знаков, в который помещается результат, либо nullptr
	 * @return       причина отказа либо error_t::NONE
	 *
	 * @note Проверка строгая: длинная запись знака, знак из области суррогатов и
	 *       знак за пределом области Юникода отвергаются. Послабления здесь дают
	 *       две разные записи одного знака, а на сличении имён держится проверка
	 *       принадлежности сертификата
	 *
	 */
	static error_t utf8(const view_t & view, vector <uint32_t> * result) {
		/**
		 * Выполняем обход записи
		 */
		for(size_t i = 0; i < view.size;){
			// Извлекаем первый байт записи знака
			const uint8_t byte = view.data[i];
			// Число байтов записи знака
			size_t count = 0;
			// Значение знака
			uint32_t code = 0;
			// Если знак записан одним байтом
			if(byte < 0x80){
				// Запоминаем число байтов записи знака
				count = 1;
				// Запоминаем значение знака
				code = static_cast <uint32_t> (byte);
			// Если знак записан двумя байтами
			} else if((byte & 0xE0) == 0xC0) {
				// Если запись знака длиннее необходимой
				if(byte < 0xC2)
					// Выводим причину отказа
					return error_t::VALUE;
				// Запоминаем число байтов записи знака
				count = 2;
				// Запоминаем значащие разряды первого байта
				code = static_cast <uint32_t> (byte & 0x1F);
			// Если знак записан тремя байтами
			} else if((byte & 0xF0) == 0xE0) {
				// Запоминаем число байтов записи знака
				count = 3;
				// Запоминаем значащие разряды первого байта
				code = static_cast <uint32_t> (byte & 0x0F);
			// Если знак записан четырьмя байтами
			} else if((byte & 0xF8) == 0xF0) {
				// Если запись знака выходит за пределы области Юникода
				if(byte > 0xF4)
					// Выводим причину отказа
					return error_t::VALUE;
				// Запоминаем число байтов записи знака
				count = 4;
				// Запоминаем значащие разряды первого байта
				code = static_cast <uint32_t> (byte & 0x07);
			// Если первый байт записи знака недопустим
			} else return error_t::VALUE;
			// Если запись знака оборвана
			if((view.size - i) < count)
				// Выводим причину отказа
				return error_t::VALUE;
			/**
			 * Выполняем обход продолжающих байтов записи знака
			 */
			for(size_t j = 1; j < count; j++){
				// Извлекаем очередной байт записи знака
				const uint8_t next = view.data[i + j];
				// Если байт не является продолжающим
				if((next & 0xC0) != 0x80)
					// Выводим причину отказа
					return error_t::VALUE;
				// Дополняем значение знака очередными шестью разрядами
				code = ((code << 6) | static_cast <uint32_t> (next & 0x3F));
			}
			// Если запись знака длиннее необходимой
			if(((count == 3) && (code < 0x800)) || ((count == 4) && (code < 0x10000)))
				// Выводим причину отказа
				return error_t::VALUE;
			// Если знак принадлежит области суррогатов либо выходит за пределы области Юникода
			if(((code >= 0xD800) && (code <= 0xDFFF)) || (code > 0x10FFFF))
				// Выводим причину отказа
				return error_t::VALUE;
			// Если набор знаков собирается
			if(result != nullptr)
				// Добавляем знак в набор знаков
				result->push_back(code);
			// Переходим к следующему знаку записи
			i += count;
		}
		// Выводим успешность проверки
		return error_t::NONE;
	}

	/**
	 * @brief Метод записи знака в кодировке UTF-8
	 *
	 * @param code   значение записываемого знака
	 * @param result строка, в которую производится запись
	 *
	 */
	static void utf8(const uint32_t code, string & result) {
		// Если знак записывается одним байтом
		if(code < 0x80)
			// Записываем единственный байт знака
			result.append(1, static_cast <char> (code));
		// Если знак записывается двумя байтами
		else if(code < 0x800) {
			// Записываем первый байт знака
			result.append(1, static_cast <char> (0xC0 | (code >> 6)));
			// Записываем второй байт знака
			result.append(1, static_cast <char> (0x80 | (code & 0x3F)));
		// Если знак записывается тремя байтами
		} else if(code < 0x10000) {
			// Записываем первый байт знака
			result.append(1, static_cast <char> (0xE0 | (code >> 12)));
			// Записываем второй байт знака
			result.append(1, static_cast <char> (0x80 | ((code >> 6) & 0x3F)));
			// Записываем третий байт знака
			result.append(1, static_cast <char> (0x80 | (code & 0x3F)));
		// Если знак записывается четырьмя байтами
		} else {
			// Записываем первый байт знака
			result.append(1, static_cast <char> (0xF0 | (code >> 18)));
			// Записываем второй байт знака
			result.append(1, static_cast <char> (0x80 | ((code >> 12) & 0x3F)));
			// Записываем третий байт знака
			result.append(1, static_cast <char> (0x80 | ((code >> 6) & 0x3F)));
			// Записываем четвёртый байт знака
			result.append(1, static_cast <char> (0x80 | (code & 0x3F)));
		}
	}

	/**
	 * @brief Метод проверки принадлежности знака набору знаков печатной строки
	 *
	 * @param byte проверяемый знак
	 * @return     признак принадлежности знака набору
	 *
	 */
	static bool printable(const uint8_t byte) noexcept {
		// Если знак является буквой либо десятичным знаком
		if(((byte >= 0x41) && (byte <= 0x5A)) || ((byte >= 0x61) && (byte <= 0x7A)) || ((byte >= 0x30) && (byte <= 0x39)))
			// Выводим принадлежность знака набору
			return true;
		/**
		 * Определяем принадлежность знака набору по остальным знакам набора
		 */
		switch(byte){
			// Если знаком является пробел, скобка, знак действия либо разделитель
			case 0x20: case 0x27: case 0x28: case 0x29: case 0x2B: case 0x2C:
			case 0x2D: case 0x2E: case 0x2F: case 0x3A: case 0x3D: case 0x3F:
				// Выводим принадлежность знака набору
				return true;
		}
		// Выводим отсутствие принадлежности знака набору
		return false;
	}
};

/**
 * @brief Метод разбора очередного элемента
 *
 * @param element объект элемента, в который производится разбор
 * @return        признак успешности разбора
 *
 */
bool anyks::asn1::Reader::next(element_t & element) noexcept {
	// Сбрасываем причину прошлого отказа
	this->_error = error_t::NONE;
	// Если разбирать больше нечего
	if((this->_view.data == nullptr) || (this->_offset >= this->_view.size)){
		// Запоминаем причину отказа
		this->_error = error_t::TRUNCATED;
		// Выводим отказ разбора
		return false;
	}
	// Запоминаем место, с которого начинается элемент
	const size_t begin = this->_offset;
	// Извлекаем первый байт метки
	const uint8_t first = this->_view.data[this->_offset++];
	// Определяем класс метки
	element.cls = static_cast <cls_t> (first >> 6);
	// Определяем вид метки
	element.constructed = ((first & 0x20) != 0);
	// Извлекаем номер метки короткой записи
	element.tag = static_cast <uint32_t> (first & 0x1F);
	// Если номер метки записан длинной записью
	if(element.tag == 0x1F){
		// Обнуляем номер метки
		element.tag = 0;
		// Признак наличия продолжения записи номера метки
		bool next = true;
		// Число разобранных байтов номера метки
		size_t count = 0;
		/**
		 * Выполняем разбор номера метки
		 */
		while(next){
			// Если данные оборваны
			if(this->_offset >= this->_view.size){
				// Запоминаем причину отказа
				this->_error = error_t::TRUNCATED;
				// Выводим отказ разбора
				return false;
			}
			// Извлекаем очередной байт номера метки
			const uint8_t byte = this->_view.data[this->_offset++];
			// Если первый байт записи не несёт значащих разрядов
			if((count == 0) && (byte == 0x80)){
				// Запоминаем причину отказа
				this->_error = error_t::EXCESSIVE;
				// Выводим отказ разбора
				return false;
			}
			// Если номер метки не умещается в разрядную сетку
			if(element.tag > (UINT32_MAX >> 7)){
				// Запоминаем причину отказа
				this->_error = error_t::HUGE_SIZE;
				// Выводим отказ разбора
				return false;
			}
			// Дополняем номер метки очередными семью разрядами
			element.tag = ((element.tag << 7) | static_cast <uint32_t> (byte & 0x7F));
			// Определяем наличие продолжения записи
			next = ((byte & 0x80) != 0);
			// Увеличиваем число разобранных байтов
			count++;
		}
		// Если номер метки следовало записать короткой записью
		if(element.tag < 0x1F){
			// Запоминаем причину отказа
			this->_error = error_t::EXCESSIVE;
			// Выводим отказ разбора
			return false;
		}
	}
	/**
	 * Метка окончания содержимого относится к длине неопределённого вида,
	 * которой в кодировке DER нет, поэтому встретиться она здесь не может
	 */
	if((element.cls == cls_t::UNIVERSAL) && (element.tag == 0)){
		// Запоминаем причину отказа
		this->_error = error_t::TAG;
		// Выводим отказ разбора
		return false;
	}
	// Если данные оборваны
	if(this->_offset >= this->_view.size){
		// Запоминаем причину отказа
		this->_error = error_t::TRUNCATED;
		// Выводим отказ разбора
		return false;
	}
	// Длина содержимого элемента
	uint64_t length = 0;
	// Извлекаем первый байт длины
	const uint8_t marker = this->_view.data[this->_offset++];
	// Если длина записана короткой записью
	if(marker < 0x80)
		// Запоминаем длину содержимого
		length = static_cast <uint64_t> (marker);
	// Если длина записана неопределённым видом
	else if(marker == 0x80) {
		// Запоминаем причину отказа
		this->_error = error_t::INDEFINITE;
		// Выводим отказ разбора
		return false;
	// Если длина записана длинной записью
	} else {
		// Определяем число байтов записи длины
		const size_t count = static_cast <size_t> (marker & 0x7F);
		/**
		 * Значение 0xFF стандартом оставлено про запас, а восемь байтов —
		 * предел разрядной сетки, дальше длина всё равно не представима
		 */
		if((marker == 0xFF) || (count > 8)){
			// Запоминаем причину отказа
			this->_error = error_t::HUGE_SIZE;
			// Выводим отказ разбора
			return false;
		}
		// Если данные оборваны
		if((this->_view.size - this->_offset) < count){
			// Запоминаем причину отказа
			this->_error = error_t::TRUNCATED;
			// Выводим отказ разбора
			return false;
		}
		// Если запись длины начинается с незначащего байта
		if(this->_view.data[this->_offset] == 0x00){
			// Запоминаем причину отказа
			this->_error = error_t::EXCESSIVE;
			// Выводим отказ разбора
			return false;
		}
		/**
		 * Выполняем сборку длины содержимого
		 */
		for(size_t i = 0; i < count; i++)
			// Дополняем длину очередным байтом записи
			length = ((length << 8) | static_cast <uint64_t> (this->_view.data[this->_offset++]));
		// Если длину следовало записать короткой записью
		if(length < 0x80){
			// Запоминаем причину отказа
			this->_error = error_t::EXCESSIVE;
			// Выводим отказ разбора
			return false;
		}
	}
	// Если длина содержимого не умещается в разрядную сетку машины
	if(length > static_cast <uint64_t> (SIZE_MAX)){
		// Запоминаем причину отказа
		this->_error = error_t::HUGE_SIZE;
		// Выводим отказ разбора
		return false;
	}
	/**
	 * Проверка ведётся вычитанием, а не сложением: сложение смещения с длиной
	 * переполняется молча и превращает проверку границы в её отсутствие
	 */
	if((this->_view.size - this->_offset) < static_cast <size_t> (length)){
		// Запоминаем причину отказа
		this->_error = error_t::TRUNCATED;
		// Выводим отказ разбора
		return false;
	}
	// Запоминаем просмотр содержимого элемента
	element.content = view_t(this->_view.data + this->_offset, static_cast <size_t> (length));
	// Сдвигаем место разбора за содержимое элемента
	this->_offset += static_cast <size_t> (length);
	// Запоминаем просмотр элемента целиком
	element.element = view_t(this->_view.data + begin, this->_offset - begin);
	// Выводим успешность разбора
	return true;
}

/**
 * @brief Метод разбора очередного элемента с проверкой ожидаемой метки
 *
 * @param tag     ожидаемая метка универсального класса
 * @param element объект элемента, в который производится разбор
 * @return        признак успешности разбора
 *
 */
bool anyks::asn1::Reader::next(const tag_t tag, element_t & element) noexcept {
	// Выполняем разбор очередного элемента
	if(!this->next(element))
		// Выводим отказ разбора
		return false;
	// Если метка элемента не та, которая ожидалась
	if((element.cls != cls_t::UNIVERSAL) || (element.tag != static_cast <uint32_t> (tag))){
		// Запоминаем причину отказа
		this->_error = error_t::TAG;
		// Выводим отказ разбора
		return false;
	}
	// Выводим успешность разбора
	return true;
}

/**
 * @brief Метод получения разборщика содержимого составного элемента
 *
 * @param element составной элемент, содержимое которого разбирается
 * @return        разборщик содержимого составного элемента
 *
 */
anyks::asn1::Reader anyks::asn1::Reader::enter(const element_t & element) const noexcept {
	// Создаём разборщик содержимого составного элемента
	Reader result(element.content);
	// Если элемент имеет простой вид метки
	if(!element.constructed)
		// Запоминаем причину отказа
		result._error = error_t::FORM;
	// Выводим разборщик содержимого составного элемента
	return result;
}

/**
 * @brief Метод извлечения причины последнего отказа
 *
 * @return причина последнего отказа
 *
 */
anyks::asn1::error_t anyks::asn1::Reader::err() const noexcept {
	// Выводим причину последнего отказа
	return this->_error;
}

/**
 * @brief Метод проверки наличия неразобранных данных
 *
 * @return признак наличия неразобранных данных
 *
 */
bool anyks::asn1::Reader::empty() const noexcept {
	// Выводим признак наличия неразобранных данных
	return (this->_offset >= this->_view.size);
}

/**
 * @brief Метод извлечения размера ещё не разобранных данных
 *
 * @return размер ещё не разобранных данных в байтах
 *
 */
size_t anyks::asn1::Reader::size() const noexcept {
	// Выводим размер ещё не разобранных данных
	return (this->_offset < this->_view.size ? (this->_view.size - this->_offset) : 0);
}

/**
 * @brief Конструктор пустого разборщика
 *
 */
anyks::asn1::Reader::Reader() noexcept : _offset(0), _error(error_t::NONE) {}

/**
 * @brief Конструктор разборщика области данных
 *
 * @param view просмотр разбираемой области данных
 *
 */
anyks::asn1::Reader::Reader(const view_t & view) noexcept : _view(view), _offset(0), _error(error_t::NONE) {}

/**
 * @brief Конструктор разборщика области данных
 *
 * @param data указатель на начало разбираемой области данных
 * @param size размер разбираемой области данных
 *
 */
anyks::asn1::Reader::Reader(const uint8_t * data, const size_t size) noexcept : _view(data, size), _offset(0), _error(error_t::NONE) {}

/**
 * @brief Метод извлечения логического значения
 *
 * @param element элемент, из которого извлекается значение
 * @param result  переменная, в которую помещается результат
 * @return        причина отказа либо error_t::NONE
 *
 */
anyks::asn1::error_t anyks::asn1::boolean(const element_t & element, bool & result) noexcept {
	// Если элемент имеет составной вид метки
	if(element.constructed)
		// Выводим причину отказа
		return error_t::FORM;
	// Если содержимое элемента записано не одним байтом
	if(element.content.size != 1)
		// Выводим причину отказа
		return error_t::VALUE;
	/**
	 * Определяем значение по единственному байту содержимого
	 */
	switch(element.content.data[0]){
		// Если записано значение лжи
		case 0x00: {
			// Запоминаем результат
			result = false;
			// Выводим успешность извлечения
			return error_t::NONE;
		}
		// Если записано значение истины
		case 0xFF: {
			// Запоминаем результат
			result = true;
			// Выводим успешность извлечения
			return error_t::NONE;
		}
	}
	// Выводим причину отказа
	return error_t::VALUE;
}

/**
 * @brief Метод извлечения целого числа произвольной разрядности
 *
 * @param element элемент, из которого извлекается значение
 * @param result  просмотр, в который помещается содержимое числа
 * @return        причина отказа либо error_t::NONE
 *
 */
anyks::asn1::error_t anyks::asn1::integer(const element_t & element, view_t & result) noexcept {
	// Если элемент имеет составной вид метки
	if(element.constructed)
		// Выводим причину отказа
		return error_t::FORM;
	// Если содержимое элемента пустое
	if(element.content.size < 1)
		// Выводим причину отказа
		return error_t::VALUE;
	// Если число записано более чем одним байтом
	if(element.content.size > 1){
		// Извлекаем два старших байта записи числа
		const uint8_t first = element.content.data[0];
		const uint8_t second = element.content.data[1];
		/**
		 * Кратчайшая запись требует, чтобы девять старших разрядов числа не были
		 * все нулями и не были все единицами: иначе старший байт лишний, и одно
		 * и то же число получает две разные записи
		 */
		if(((first == 0x00) && ((second & 0x80) == 0)) || ((first == 0xFF) && ((second & 0x80) != 0)))
			// Выводим причину отказа
			return error_t::EXCESSIVE;
	}
	// Запоминаем результат
	result = element.content;
	// Выводим успешность извлечения
	return error_t::NONE;
}

/**
 * @brief Метод извлечения целого числа
 *
 * @param element элемент, из которого извлекается значение
 * @param result  переменная, в которую помещается результат
 * @return        причина отказа либо error_t::NONE
 *
 */
anyks::asn1::error_t anyks::asn1::integer(const element_t & element, int64_t & result) noexcept {
	// Просмотр содержимого числа
	view_t view;
	// Выполняем извлечение содержимого числа
	const error_t error = integer(element, view);
	// Если извлечение содержимого числа не удалось
	if(error != error_t::NONE)
		// Выводим причину отказа
		return error;
	// Если число не умещается в разрядную сетку
	if(view.size > sizeof(int64_t))
		// Выводим причину отказа
		return error_t::HUGE_SIZE;
	// Определяем знак числа по старшему разряду старшего байта
	uint64_t value = (((view.data[0] & 0x80) != 0) ? UINT64_MAX : 0);
	/**
	 * Выполняем сборку числа
	 */
	for(size_t i = 0; i < view.size; i++)
		// Дополняем число очередным байтом записи
		value = ((value << 8) | static_cast <uint64_t> (view.data[i]));
	// Запоминаем результат
	result = static_cast <int64_t> (value);
	// Выводим успешность извлечения
	return error_t::NONE;
}

/**
 * @brief Метод извлечения строки битов
 *
 * @param element элемент, из которого извлекается значение
 * @param result  просмотр, в который помещается содержимое строки битов
 * @param unused  число неиспользуемых битов в последнем байте
 * @return        причина отказа либо error_t::NONE
 *
 */
anyks::asn1::error_t anyks::asn1::bits(const element_t & element, view_t & result, uint8_t & unused) noexcept {
	// Если элемент имеет составной вид метки
	if(element.constructed)
		// Выводим причину отказа
		return error_t::FORM;
	// Если содержимое элемента пустое
	if(element.content.size < 1)
		// Выводим причину отказа
		return error_t::VALUE;
	// Извлекаем число неиспользуемых битов в последнем байте
	const uint8_t count = element.content.data[0];
	// Если число неиспользуемых битов выходит за пределы байта
	if(count > 7)
		// Выводим причину отказа
		return error_t::VALUE;
	// Если строка битов пустая, а неиспользуемые биты объявлены
	if((element.content.size == 1) && (count != 0))
		// Выводим причину отказа
		return error_t::VALUE;
	// Если строка битов не пустая
	if(element.content.size > 1){
		/**
		 * Кодировка DER требует, чтобы неиспользуемые разряды последнего байта
		 * были нулевыми: иначе одна и та же строка битов получает разные записи
		 */
		if((element.content.data[element.content.size - 1] & ((1 << count) - 1)) != 0)
			// Выводим причину отказа
			return error_t::VALUE;
	}
	// Запоминаем число неиспользуемых битов
	unused = count;
	// Запоминаем результат
	result = view_t(element.content.data + 1, element.content.size - 1);
	// Выводим успешность извлечения
	return error_t::NONE;
}

/**
 * @brief Метод извлечения опознавателя объекта
 *
 * @param element элемент, из которого извлекается значение
 * @param result  строка, в которую помещается запись опознавателя через точку
 * @return        причина отказа либо error_t::NONE
 *
 */
anyks::asn1::error_t anyks::asn1::oid(const element_t & element, string & result) noexcept {
	// Если элемент имеет составной вид метки
	if(element.constructed)
		// Выводим причину отказа
		return error_t::FORM;
	// Если содержимое элемента пустое
	if(element.content.size < 1)
		// Выводим причину отказа
		return error_t::VALUE;
	// Если запись последней составляющей оборвана
	if((element.content.data[element.content.size - 1] & 0x80) != 0)
		// Выводим причину отказа
		return error_t::VALUE;
	// Признак разбора первой составляющей опознавателя
	bool first = true;
	// Значение очередной составляющей опознавателя
	uint64_t value = 0;
	// Число разобранных байтов очередной составляющей
	size_t count = 0;
	// Очищаем строку результата
	result.clear();
	/**
	 * Строка собирается сразу текстом, а не через промежуточный набор чисел:
	 * опознаватель нужен потребителю именно записью, и промежуточный набор
	 * означал бы выделение памяти на каждом разборе имени
	 */
	for(size_t i = 0; i < element.content.size; i++){
		// Извлекаем очередной байт записи
		const uint8_t byte = element.content.data[i];
		// Если первый байт составляющей не несёт значащих разрядов
		if((count == 0) && (byte == 0x80))
			// Выводим причину отказа
			return error_t::EXCESSIVE;
		// Если составляющая не умещается в разрядную сетку
		if(value > (UINT64_MAX >> 7))
			// Выводим причину отказа
			return error_t::HUGE_SIZE;
		// Дополняем составляющую очередными семью разрядами
		value = ((value << 7) | static_cast <uint64_t> (byte & 0x7F));
		// Увеличиваем число разобранных байтов
		count++;
		// Если запись составляющей продолжается
		if((byte & 0x80) != 0)
			// Переходим к следующему байту записи
			continue;
		// Если разобрана первая составляющая опознавателя
		if(first){
			/**
			 * Первые две составляющие записаны одним числом: первая может принимать
			 * значения от нуля до двух, и вторая при первых двух значениях не
			 * превышает тридцати девяти
			 */
			if(value < 40){
				// Записываем первую составляющую опознавателя
				result.append(1, '0');
				// Записываем разделитель составляющих
				result.append(1, '.');
				// Записываем вторую составляющую опознавателя
				result.append(to_string(value));
			// Если первая составляющая опознавателя равна единице
			} else if(value < 80) {
				// Записываем первую составляющую опознавателя
				result.append(1, '1');
				// Записываем разделитель составляющих
				result.append(1, '.');
				// Записываем вторую составляющую опознавателя
				result.append(to_string(value - 40));
			// Если первая составляющая опознавателя равна двум
			} else {
				// Записываем первую составляющую опознавателя
				result.append(1, '2');
				// Записываем разделитель составляющих
				result.append(1, '.');
				// Записываем вторую составляющую опознавателя
				result.append(to_string(value - 80));
			}
			// Снимаем признак разбора первой составляющей
			first = false;
		// Если разобрана очередная составляющая опознавателя
		} else {
			// Записываем разделитель составляющих
			result.append(1, '.');
			// Записываем очередную составляющую опознавателя
			result.append(to_string(value));
		}
		// Обнуляем значение составляющей
		value = 0;
		// Обнуляем число разобранных байтов
		count = 0;
	}
	// Выводим успешность извлечения
	return error_t::NONE;
}

/**
 * @brief Метод извлечения времени
 *
 * @param element элемент, из которого извлекается значение
 * @param type    вид записи времени
 * @param result  переменная, в которую помещается число секунд от начала эпохи
 * @return        причина отказа либо error_t::NONE
 *
 */
anyks::asn1::error_t anyks::asn1::time(const element_t & element, const tag_t type, int64_t & result) noexcept {
	// Если элемент имеет составной вид метки
	if(element.constructed)
		// Выводим причину отказа
		return error_t::FORM;
	// Признак записи времени с двузначным годом
	const bool shortly = (type == tag_t::UTC_TIME);
	// Если вид записи времени не поддерживается
	if(!shortly && (type != tag_t::GENERALIZED_TIME))
		// Выводим причину отказа
		return error_t::TAG;
	// Определяем требуемую длину записи времени
	const size_t length = (shortly ? 13 : 15);
	/**
	 * Кодировка DER оставляет от записи времени единственный вид: часовой пояс
	 * только Z, доли секунды запрещены, секунды обязательны. Всякое послабление
	 * даёт два разных написания одного мгновения
	 */
	if((element.content.size != length) || (element.content.data[length - 1] != 0x5A))
		// Выводим причину отказа
		return error_t::VALUE;
	// Значение года
	uint32_t year = 0;
	// Определяем место начала записи месяца
	const size_t offset = (shortly ? 2 : 4);
	// Выполняем извлечение года
	if(!digits(element.content.data, offset, year))
		// Выводим причину отказа
		return error_t::VALUE;
	/**
	 * Двузначный год толкуется по правилу RFC 5280: значение от пятидесяти и
	 * выше относится к двадцатому веку, меньшее - к двадцать первому
	 */
	if(shortly)
		// Дополняем год веком
		year += (year >= 50 ? 1900 : 2000);
	// Значения месяца, дня, часа, минуты и секунды
	uint32_t month = 0, day = 0, hour = 0, minute = 0, second = 0;
	// Выполняем извлечение остальных составляющих записи времени
	if(!digits(element.content.data + offset, 2, month) ||
	   !digits(element.content.data + offset + 2, 2, day) ||
	   !digits(element.content.data + offset + 4, 2, hour) ||
	   !digits(element.content.data + offset + 6, 2, minute) ||
	   !digits(element.content.data + offset + 8, 2, second))
		// Выводим причину отказа
		return error_t::VALUE;
	// Число суток в каждом месяце года
	static const uint32_t days[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
	// Если месяц записан значением за пределами года
	if((month < 1) || (month > 12))
		// Выводим причину отказа
		return error_t::VALUE;
	// Определяем число суток в записанном месяце
	uint32_t count = days[month - 1];
	// Если месяцем является февраль високосного года
	if((month == 2) && (((year % 4) == 0) && (((year % 100) != 0) || ((year % 400) == 0))))
		// Увеличиваем число суток февраля
		count++;
	// Если день, час, минута либо секунда записаны недопустимым значением
	if((day < 1) || (day > count) || (hour > 23) || (minute > 59) || (second > 59))
		// Выводим причину отказа
		return error_t::VALUE;
	// Собираем число секунд от начала эпохи
	result = ((civil(static_cast <int64_t> (year), month, day) * 86400) +
	          (static_cast <int64_t> (hour) * 3600) +
	          (static_cast <int64_t> (minute) * 60) + static_cast <int64_t> (second));
	// Выводим успешность извлечения
	return error_t::NONE;
}

/**
 * @brief Метод извлечения строки
 *
 * @param element элемент, из которого извлекается значение
 * @param type    вид строки, определяющий правила записи содержимого
 * @param result  строка, в которую помещается результат в кодировке UTF-8
 * @return        причина отказа либо error_t::NONE
 *
 */
anyks::asn1::error_t anyks::asn1::text(const element_t & element, const tag_t type, string & result) noexcept {
	// Если элемент имеет составной вид метки
	if(element.constructed)
		// Выводим причину отказа
		return error_t::FORM;
	/**
	 * Работа со строкой выделяет память, и нехватка её обязана дойти до
	 * вызывающего причиной отказа, а не завершить процесс
	 */
	try {
		// Очищаем строку результата
		result.clear();
		/**
		 * Определяем правила записи содержимого по виду строки
		 */
		switch(static_cast <uint32_t> (type)){
			// Если строка записана знаками кодировки UTF-8
			case static_cast <uint32_t> (tag_t::UTF8_STRING): {
				// Выполняем проверку записи строки
				const error_t error = utf8(element.content, nullptr);
				// Если запись строки не отвечает правилам кодировки
				if(error != error_t::NONE)
					// Выводим причину отказа
					return error;
				// Запоминаем результат
				result.assign(reinterpret_cast <const char *> (element.content.data), element.content.size);
			} break;
			// Если строка записана знаками печатного набора
			case static_cast <uint32_t> (tag_t::PRINTABLE_STRING): {
				/**
				 * Выполняем обход знаков строки
				 */
				for(size_t i = 0; i < element.content.size; i++){
					// Если знак не принадлежит печатному набору
					if(!printable(element.content.data[i]))
						// Выводим причину отказа
						return error_t::VALUE;
				}
				// Запоминаем результат
				result.assign(reinterpret_cast <const char *> (element.content.data), element.content.size);
			} break;
			// Если строка записана знаками набора IA5
			case static_cast <uint32_t> (tag_t::IA5_STRING): {
				/**
				 * Выполняем обход знаков строки
				 */
				for(size_t i = 0; i < element.content.size; i++){
					// Если знак не принадлежит набору IA5
					if(element.content.data[i] > 0x7F)
						// Выводим причину отказа
						return error_t::VALUE;
				}
				// Запоминаем результат
				result.assign(reinterpret_cast <const char *> (element.content.data), element.content.size);
			} break;
			// Если строка записана видимыми знаками
			case static_cast <uint32_t> (tag_t::VISIBLE_STRING): {
				/**
				 * Выполняем обход знаков строки
				 */
				for(size_t i = 0; i < element.content.size; i++){
					// Если знак не является видимым
					if((element.content.data[i] < 0x20) || (element.content.data[i] > 0x7E))
						// Выводим причину отказа
						return error_t::VALUE;
				}
				// Запоминаем результат
				result.assign(reinterpret_cast <const char *> (element.content.data), element.content.size);
			} break;
			// Если строка записана знаками кодировки UCS-2
			case static_cast <uint32_t> (tag_t::BMP_STRING): {
				// Если запись строки оборвана посреди знака
				if((element.content.size % 2) != 0)
					// Выводим причину отказа
					return error_t::VALUE;
				/**
				 * Выполняем обход знаков строки
				 */
				for(size_t i = 0; i < element.content.size; i += 2){
					// Собираем значение знака из пары байтов
					const uint32_t code = ((static_cast <uint32_t> (element.content.data[i]) << 8) |
					                       static_cast <uint32_t> (element.content.data[i + 1]));
					/**
					 * Кодировка UCS-2 области суррогатов не имеет: пара суррогатов
					 * это средство кодировки UTF-16, которой здесь нет
					 */
					if((code >= 0xD800) && (code <= 0xDFFF))
						// Выводим причину отказа
						return error_t::VALUE;
					// Записываем знак в кодировке UTF-8
					utf8(code, result);
				}
			} break;
			// Если строка записана знаками кодировки UCS-4
			case static_cast <uint32_t> (tag_t::UNIVERSAL_STRING): {
				// Если запись строки оборвана посреди знака
				if((element.content.size % 4) != 0)
					// Выводим причину отказа
					return error_t::VALUE;
				/**
				 * Выполняем обход знаков строки
				 */
				for(size_t i = 0; i < element.content.size; i += 4){
					// Собираем значение знака из четвёрки байтов
					const uint32_t code = ((static_cast <uint32_t> (element.content.data[i]) << 24) |
					                       (static_cast <uint32_t> (element.content.data[i + 1]) << 16) |
					                       (static_cast <uint32_t> (element.content.data[i + 2]) << 8) |
					                       static_cast <uint32_t> (element.content.data[i + 3]));
					// Если знак принадлежит области суррогатов либо выходит за пределы области Юникода
					if(((code >= 0xD800) && (code <= 0xDFFF)) || (code > 0x10FFFF))
						// Выводим причину отказа
						return error_t::VALUE;
					// Записываем знак в кодировке UTF-8
					utf8(code, result);
				}
			} break;
			/**
			 * Строка кодировки T.61 отдаётся как есть
			 *
			 * Набор знаков её задан переключаемыми таблицами, единого толкования у
			 * него нет, и на деле в сертификатах ей записывают то Latin-1, то UTF-8.
			 * Всякое приведение здесь было бы догадкой, а догадка в имени - это
			 * расхождение при сличении имён
			 */
			case static_cast <uint32_t> (tag_t::T61_STRING):
				// Запоминаем результат
				result.assign(reinterpret_cast <const char *> (element.content.data), element.content.size);
			break;
			// Если вид строки не поддерживается
			default: return error_t::TAG;
		}
	/**
	 * Если память выделить не удалось
	 */
	} catch(const bad_alloc &) {
		// Выводим причину отказа
		return error_t::MEMORY;
	}
	// Выводим успешность извлечения
	return error_t::NONE;
}

/**
 * @brief Метод записи метки элемента
 *
 * @param cls         класс метки
 * @param constructed признак составного вида метки
 * @param tag         номер метки внутри своего класса
 *
 */
void anyks::asn1::Writer::identifier(const cls_t cls, const bool constructed, const uint32_t tag) noexcept {
	// Собираем первый байт метки из класса и вида метки
	uint8_t first = static_cast <uint8_t> ((static_cast <uint8_t> (cls) << 6) | (constructed ? 0x20 : 0x00));
	// Если номер метки умещается в короткую запись
	if(tag < 0x1F){
		// Дополняем первый байт метки номером метки
		this->_buffer.push_back(static_cast <uint8_t> (first | static_cast <uint8_t> (tag)));
		// Выходим из метода
		return;
	}
	// Записываем первый байт метки с признаком длинной записи номера
	this->_buffer.push_back(static_cast <uint8_t> (first | 0x1F));
	// Число значащих семёрок разрядов номера метки
	size_t count = 1;
	/**
	 * Определяем число значащих семёрок разрядов номера метки
	 */
	while((tag >> (7 * count)) != 0)
		// Увеличиваем число значащих семёрок разрядов
		count++;
	/**
	 * Выполняем запись номера метки от старших разрядов к младшим
	 */
	for(size_t i = count; i > 0; i--)
		// Записываем очередные семь разрядов номера метки
		this->_buffer.push_back(static_cast <uint8_t> (((tag >> (7 * (i - 1))) & 0x7F) | (i > 1 ? 0x80 : 0x00)));
}

/**
 * @brief Метод записи длины содержимого
 *
 * @param offset место, в которое вставляется запись длины
 * @param length длина содержимого
 *
 */
void anyks::asn1::Writer::length(const size_t offset, const size_t length) noexcept {
	// Если длина умещается в короткую запись
	if(length < 0x80){
		// Вставляем единственный байт записи длины
		this->_buffer.insert(this->_buffer.begin() + static_cast <ptrdiff_t> (offset), static_cast <uint8_t> (length));
		// Выходим из метода
		return;
	}
	// Число значащих байтов записи длины
	size_t count = 1;
	/**
	 * Определяем число значащих байтов записи длины
	 */
	while((length >> (8 * count)) != 0)
		// Увеличиваем число значащих байтов записи
		count++;
	// Собираемая запись длины
	vector <uint8_t> result;
	// Резервируем место под запись длины
	result.reserve(count + 1);
	// Записываем первый байт с числом байтов записи длины
	result.push_back(static_cast <uint8_t> (0x80 | static_cast <uint8_t> (count)));
	/**
	 * Выполняем запись длины от старших байтов к младшим
	 */
	for(size_t i = count; i > 0; i--)
		// Записываем очередной байт записи длины
		result.push_back(static_cast <uint8_t> ((length >> (8 * (i - 1))) & 0xFF));
	// Вставляем собранную запись длины
	this->_buffer.insert(this->_buffer.begin() + static_cast <ptrdiff_t> (offset), result.begin(), result.end());
}

/**
 * @brief Метод извлечения причины последнего отказа
 *
 * @return причина последнего отказа
 *
 */
anyks::asn1::error_t anyks::asn1::Writer::err() const noexcept {
	// Выводим причину последнего отказа
	return this->_error;
}

/**
 * @brief Метод извлечения собранной записи
 *
 * @return просмотр собранной записи
 *
 */
anyks::view_t anyks::asn1::Writer::data() const noexcept {
	/**
	 * Незакрытый составной элемент означает, что записи ещё нет: длина его не
	 * проставлена, и отдавать такую запись наружу нельзя
	 */
	if(!this->_opened.empty() || (this->_error != error_t::NONE))
		// Выводим пустой просмотр
		return view_t();
	// Выводим просмотр собранной записи
	return view_t(this->_buffer.data(), this->_buffer.size());
}

/**
 * @brief Метод очистки собранной записи
 *
 */
void anyks::asn1::Writer::clear() noexcept {
	// Очищаем буфер собираемой записи
	this->_buffer.clear();
	// Очищаем места начала содержимого открытых элементов
	this->_opened.clear();
	// Сбрасываем причину последнего отказа
	this->_error = error_t::NONE;
}

/**
 * @brief Метод открытия составного элемента
 *
 * @param cls класс метки
 * @param tag номер метки внутри своего класса
 * @return    признак успешности записи
 *
 */
bool anyks::asn1::Writer::open(const cls_t cls, const uint32_t tag) noexcept {
	// Если запись уже завершилась отказом
	if(this->_error != error_t::NONE)
		// Выводим отказ записи
		return false;
	/**
	 * Запись выделяет память, и нехватка её обязана дойти до вызывающего
	 * причиной отказа, а не завершить процесс
	 */
	try {
		// Выполняем запись метки составного элемента
		this->identifier(cls, true, tag);
		// Запоминаем место начала содержимого составного элемента
		this->_opened.push_back(this->_buffer.size());
	/**
	 * Если память выделить не удалось
	 */
	} catch(const bad_alloc &) {
		// Запоминаем причину отказа
		this->_error = error_t::MEMORY;
		// Выводим отказ записи
		return false;
	}
	// Выводим успешность записи
	return true;
}

/**
 * @brief Метод открытия составного элемента
 *
 * @param tag метка универсального класса
 * @return    признак успешности записи
 *
 */
bool anyks::asn1::Writer::open(const tag_t tag) noexcept {
	// Выполняем открытие составного элемента универсального класса
	return this->open(cls_t::UNIVERSAL, static_cast <uint32_t> (tag));
}

/**
 * @brief Метод закрытия последнего открытого составного элемента
 *
 * @return признак успешности записи
 *
 */
bool anyks::asn1::Writer::close() noexcept {
	// Если запись уже завершилась отказом
	if(this->_error != error_t::NONE)
		// Выводим отказ записи
		return false;
	// Если закрывать нечего
	if(this->_opened.empty()){
		// Запоминаем причину отказа
		this->_error = error_t::BALANCE;
		// Выводим отказ записи
		return false;
	}
	// Извлекаем место начала содержимого закрываемого элемента
	const size_t offset = this->_opened.back();
	/**
	 * Запись выделяет память, и нехватка её обязана дойти до вызывающего
	 * причиной отказа, а не завершить процесс
	 */
	try {
		// Выполняем запись длины содержимого закрываемого элемента
		this->length(offset, this->_buffer.size() - offset);
	/**
	 * Если память выделить не удалось
	 */
	} catch(const bad_alloc &) {
		// Запоминаем причину отказа
		this->_error = error_t::MEMORY;
		// Выводим отказ записи
		return false;
	}
	// Снимаем закрытый элемент с набора открытых
	this->_opened.pop_back();
	// Выводим успешность записи
	return true;
}

/**
 * @brief Метод записи произвольного элемента
 *
 * @param cls         класс метки
 * @param constructed признак составного вида метки
 * @param tag         номер метки внутри своего класса
 * @param content     содержимое элемента
 * @return            признак успешности записи
 *
 */
bool anyks::asn1::Writer::element(const cls_t cls, const bool constructed, const uint32_t tag, const view_t & content) noexcept {
	// Если запись уже завершилась отказом
	if(this->_error != error_t::NONE)
		// Выводим отказ записи
		return false;
	/**
	 * Запись выделяет память, и нехватка её обязана дойти до вызывающего
	 * причиной отказа, а не завершить процесс
	 */
	try {
		// Выполняем запись метки элемента
		this->identifier(cls, constructed, tag);
		// Выполняем запись длины содержимого элемента
		this->length(this->_buffer.size(), content.size);
		// Если содержимое элемента не пустое
		if((content.data != nullptr) && (content.size > 0))
			// Выполняем запись содержимого элемента
			this->_buffer.insert(this->_buffer.end(), content.data, content.data + content.size);
	/**
	 * Если память выделить не удалось
	 */
	} catch(const bad_alloc &) {
		// Запоминаем причину отказа
		this->_error = error_t::MEMORY;
		// Выводим отказ записи
		return false;
	}
	// Выводим успешность записи
	return true;
}

/**
 * @brief Метод записи логического значения
 *
 * @param value записываемое значение
 * @return      признак успешности записи
 *
 */
bool anyks::asn1::Writer::boolean(const bool value) noexcept {
	// Собираем содержимое логического значения
	const uint8_t content = (value ? 0xFF : 0x00);
	// Выполняем запись логического значения
	return this->element(cls_t::UNIVERSAL, false, static_cast <uint32_t> (tag_t::BOOLEAN), view_t(&content, 1));
}

/**
 * @brief Метод записи отсутствия значения
 *
 * @return признак успешности записи
 *
 */
bool anyks::asn1::Writer::nothing() noexcept {
	// Выполняем запись отсутствия значения
	return this->element(cls_t::UNIVERSAL, false, static_cast <uint32_t> (tag_t::NOTHING), view_t());
}

/**
 * @brief Метод записи целого числа
 *
 * @param value записываемое значение
 * @return      признак успешности записи
 *
 */
bool anyks::asn1::Writer::integer(const int64_t value) noexcept {
	// Собираемое содержимое целого числа
	uint8_t content[sizeof(int64_t)];
	// Получаем двоичное представление числа в дополнительном коде
	const uint64_t binary = static_cast <uint64_t> (value);
	/**
	 * Выполняем разбор числа на байты от старшего к младшему
	 */
	for(size_t i = 0; i < sizeof(int64_t); i++)
		// Записываем очередной байт числа
		content[i] = static_cast <uint8_t> ((binary >> (8 * (sizeof(int64_t) - 1 - i))) & 0xFF);
	// Место начала кратчайшей записи числа
	size_t offset = 0;
	/**
	 * Кратчайшая запись требует, чтобы девять старших разрядов числа не были все
	 * нулями и не были все единицами: иначе старший байт лишний
	 */
	while(((offset + 1) < sizeof(int64_t)) &&
	      (((content[offset] == 0x00) && ((content[offset + 1] & 0x80) == 0)) ||
	       ((content[offset] == 0xFF) && ((content[offset + 1] & 0x80) != 0))))
		// Отбрасываем лишний старший байт записи
		offset++;
	// Выполняем запись целого числа
	return this->element(cls_t::UNIVERSAL, false, static_cast <uint32_t> (tag_t::INTEGER), view_t(content + offset, sizeof(int64_t) - offset));
}

/**
 * @brief Метод записи строки байтов
 *
 * @param value записываемое содержимое
 * @return      признак успешности записи
 *
 */
bool anyks::asn1::Writer::octets(const view_t & value) noexcept {
	// Выполняем запись строки байтов
	return this->element(cls_t::UNIVERSAL, false, static_cast <uint32_t> (tag_t::OCTET_STRING), value);
}

/**
 * @brief Метод записи строки битов
 *
 * @param value  записываемое содержимое
 * @param unused число неиспользуемых разрядов последнего байта
 * @return       признак успешности записи
 *
 */
bool anyks::asn1::Writer::bits(const view_t & value, const uint8_t unused) noexcept {
	// Если запись уже завершилась отказом
	if(this->_error != error_t::NONE)
		// Выводим отказ записи
		return false;
	// Если число неиспользуемых разрядов выходит за пределы байта
	if((unused > 7) || ((value.size == 0) && (unused != 0))){
		// Запоминаем причину отказа
		this->_error = error_t::VALUE;
		// Выводим отказ записи
		return false;
	}
	// Если неиспользуемые разряды последнего байта заполнены
	if((value.size > 0) && ((value.data[value.size - 1] & ((1 << unused) - 1)) != 0)){
		// Запоминаем причину отказа
		this->_error = error_t::VALUE;
		// Выводим отказ записи
		return false;
	}
	/**
	 * Запись выделяет память, и нехватка её обязана дойти до вызывающего
	 * причиной отказа, а не завершить процесс
	 */
	try {
		// Собираемое содержимое строки битов
		vector <uint8_t> content;
		// Резервируем место под содержимое строки битов
		content.reserve(value.size + 1);
		// Записываем число неиспользуемых разрядов последнего байта
		content.push_back(unused);
		// Если строка битов не пустая
		if((value.data != nullptr) && (value.size > 0))
			// Записываем содержимое строки битов
			content.insert(content.end(), value.data, value.data + value.size);
		// Выполняем запись строки битов
		return this->element(cls_t::UNIVERSAL, false, static_cast <uint32_t> (tag_t::BIT_STRING), view_t(content.data(), content.size()));
	/**
	 * Если память выделить не удалось
	 */
	} catch(const bad_alloc &) {
		// Запоминаем причину отказа
		this->_error = error_t::MEMORY;
		// Выводим отказ записи
		return false;
	}
}

/**
 * @brief Метод записи опознавателя объекта
 *
 * @param value запись опознавателя через точку
 * @return      признак успешности записи
 *
 */
bool anyks::asn1::Writer::oid(const string & value) noexcept {
	// Если запись уже завершилась отказом
	if(this->_error != error_t::NONE)
		// Выводим отказ записи
		return false;
	/**
	 * Запись выделяет память, и нехватка её обязана дойти до вызывающего
	 * причиной отказа, а не завершить процесс
	 */
	try {
		// Набор составляющих опознавателя объекта
		vector <uint64_t> parts;
		// Значение очередной составляющей опознавателя
		uint64_t part = 0;
		// Признак наличия знаков у очередной составляющей
		bool filled = false;
		/**
		 * Выполняем обход записи опознавателя объекта
		 */
		for(size_t i = 0; i <= value.size(); i++){
			// Если разбор дошёл до разделителя составляющих либо до конца записи
			if((i == value.size()) || (value[i] == '.')){
				// Если составляющая записана без единого знака
				if(!filled){
					// Запоминаем причину отказа
					this->_error = error_t::VALUE;
					// Выводим отказ записи
					return false;
				}
				// Добавляем составляющую в набор составляющих
				parts.push_back(part);
				// Обнуляем значение составляющей
				part = 0;
				// Снимаем признак наличия знаков
				filled = false;
				// Переходим к следующей составляющей
				continue;
			}
			// Если знак записи не является десятичным
			if((value[i] < '0') || (value[i] > '9')){
				// Запоминаем причину отказа
				this->_error = error_t::VALUE;
				// Выводим отказ записи
				return false;
			}
			// Если составляющая не умещается в разрядную сетку
			if(part > ((UINT64_MAX - 9) / 10)){
				// Запоминаем причину отказа
				this->_error = error_t::HUGE_SIZE;
				// Выводим отказ записи
				return false;
			}
			// Дополняем составляющую очередным знаком записи
			part = ((part * 10) + static_cast <uint64_t> (value[i] - '0'));
			// Устанавливаем признак наличия знаков
			filled = true;
		}
		/**
		 * Первые две составляющие записываются одним числом, поэтому меньше двух
		 * составляющих опознаватель иметь не может. Первая составляющая принимает
		 * значения от нуля до двух, и при первых двух её значениях вторая не
		 * превышает тридцати девяти
		 */
		if((parts.size() < 2) || (parts[0] > 2) || ((parts[0] < 2) && (parts[1] > 39))){
			// Запоминаем причину отказа
			this->_error = error_t::VALUE;
			// Выводим отказ записи
			return false;
		}
		// Собираемое содержимое опознавателя объекта
		vector <uint8_t> content;
		// Сводим первые две составляющие в одно число
		parts[1] += (parts[0] * 40);
		/**
		 * Выполняем обход составляющих опознавателя объекта
		 */
		for(size_t i = 1; i < parts.size(); i++){
			// Извлекаем значение очередной составляющей
			const uint64_t item = parts[i];
			// Число значащих семёрок разрядов составляющей
			size_t count = 1;
			/**
			 * Определяем число значащих семёрок разрядов составляющей
			 */
			while((count < 10) && ((item >> (7 * count)) != 0))
				// Увеличиваем число значащих семёрок разрядов
				count++;
			/**
			 * Выполняем запись составляющей от старших разрядов к младшим
			 */
			for(size_t j = count; j > 0; j--)
				// Записываем очередные семь разрядов составляющей
				content.push_back(static_cast <uint8_t> (((item >> (7 * (j - 1))) & 0x7F) | (j > 1 ? 0x80 : 0x00)));
		}
		// Выполняем запись опознавателя объекта
		return this->element(cls_t::UNIVERSAL, false, static_cast <uint32_t> (tag_t::OBJECT), view_t(content.data(), content.size()));
	/**
	 * Если память выделить не удалось
	 */
	} catch(const bad_alloc &) {
		// Запоминаем причину отказа
		this->_error = error_t::MEMORY;
		// Выводим отказ записи
		return false;
	}
}

/**
 * @brief Метод записи времени
 *
 * @param type  вид записи времени
 * @param value число секунд от начала эпохи
 * @return      признак успешности записи
 *
 */
bool anyks::asn1::Writer::time(const tag_t type, const int64_t value) noexcept {
	// Если запись уже завершилась отказом
	if(this->_error != error_t::NONE)
		// Выводим отказ записи
		return false;
	// Признак записи времени с двузначным годом
	const bool shortly = (type == tag_t::UTC_TIME);
	// Если вид записи времени не поддерживается
	if(!shortly && (type != tag_t::GENERALIZED_TIME)){
		// Запоминаем причину отказа
		this->_error = error_t::TAG;
		// Выводим отказ записи
		return false;
	}
	// Определяем число суток от начала эпохи с округлением вниз
	const int64_t days = ((value >= 0) ? (value / 86400) : (((value + 1) / 86400) - 1));
	// Определяем число секунд внутри суток
	const int64_t rest = (value - (days * 86400));
	// Значение года
	int64_t year = 0;
	// Значения месяца и дня
	uint32_t month = 0, day = 0;
	// Выполняем перевод числа суток в дату
	civil(days, year, month, day);
	/**
	 * Запись с двузначным годом различает лишь сто лет: правилом RFC 5280 это
	 * промежуток с 1950 по 2049 год, за его пределами двузначный год толкуется
	 * не тем веком
	 */
	if(shortly && ((year < 1950) || (year > 2049))){
		// Запоминаем причину отказа
		this->_error = error_t::VALUE;
		// Выводим отказ записи
		return false;
	}
	// Если год не умещается в четырёхзначную запись
	if(!shortly && ((year < 0) || (year > 9999))){
		// Запоминаем причину отказа
		this->_error = error_t::VALUE;
		// Выводим отказ записи
		return false;
	}
	// Собираемое содержимое записи времени
	uint8_t content[15];
	// Определяем место начала записи месяца
	const size_t offset = (shortly ? 2 : 4);
	// Определяем записываемое значение года
	const uint32_t written = static_cast <uint32_t> (shortly ? (year % 100) : year);
	/**
	 * Выполняем запись года
	 */
	for(size_t i = 0; i < offset; i++)
		// Записываем очередной знак года
		content[offset - 1 - i] = static_cast <uint8_t> (0x30 + ((written / static_cast <uint32_t> (i == 0 ? 1 : (i == 1 ? 10 : (i == 2 ? 100 : 1000)))) % 10));
	// Набор оставшихся составляющих записи времени
	const uint32_t parts[5] = {
		month, day,
		static_cast <uint32_t> (rest / 3600),
		static_cast <uint32_t> ((rest / 60) % 60),
		static_cast <uint32_t> (rest % 60)
	};
	/**
	 * Выполняем запись оставшихся составляющих
	 */
	for(size_t i = 0; i < 5; i++){
		// Записываем старший знак составляющей
		content[offset + (i * 2)] = static_cast <uint8_t> (0x30 + ((parts[i] / 10) % 10));
		// Записываем младший знак составляющей
		content[offset + (i * 2) + 1] = static_cast <uint8_t> (0x30 + (parts[i] % 10));
	}
	// Записываем обозначение всемирного времени
	content[offset + 10] = 0x5A;
	// Выполняем запись времени
	return this->element(cls_t::UNIVERSAL, false, static_cast <uint32_t> (type), view_t(content, offset + 11));
}

/**
 * @brief Метод записи строки
 *
 * @param type  вид строки, определяющий правила записи содержимого
 * @param value записываемая строка в кодировке UTF-8
 * @return      признак успешности записи
 *
 */
bool anyks::asn1::Writer::text(const tag_t type, const string & value) noexcept {
	// Если запись уже завершилась отказом
	if(this->_error != error_t::NONE)
		// Выводим отказ записи
		return false;
	// Получаем просмотр записываемой строки
	const view_t view(reinterpret_cast <const uint8_t *> (value.data()), value.size());
	/**
	 * Запись выделяет память, и нехватка её обязана дойти до вызывающего
	 * причиной отказа, а не завершить процесс
	 */
	try {
		/**
		 * Определяем правила записи содержимого по виду строки
		 */
		switch(static_cast <uint32_t> (type)){
			// Если строка записывается знаками кодировки UTF-8
			case static_cast <uint32_t> (tag_t::UTF8_STRING): {
				// Выполняем проверку записи строки
				const error_t error = utf8(view, nullptr);
				// Если запись строки не отвечает правилам кодировки
				if(error != error_t::NONE){
					// Запоминаем причину отказа
					this->_error = error;
					// Выводим отказ записи
					return false;
				}
				// Выполняем запись строки
				return this->element(cls_t::UNIVERSAL, false, static_cast <uint32_t> (type), view);
			}
			// Если строка записывается знаками печатного набора, набора IA5 либо видимыми знаками
			case static_cast <uint32_t> (tag_t::PRINTABLE_STRING):
			case static_cast <uint32_t> (tag_t::IA5_STRING):
			case static_cast <uint32_t> (tag_t::VISIBLE_STRING): {
				/**
				 * Выполняем обход знаков строки
				 */
				for(size_t i = 0; i < view.size; i++){
					// Признак принадлежности знака набору знаков строки
					bool allowed = false;
					/**
					 * Определяем принадлежность знака набору знаков строки
					 */
					switch(static_cast <uint32_t> (type)){
						// Если строка записывается знаками печатного набора
						case static_cast <uint32_t> (tag_t::PRINTABLE_STRING): allowed = printable(view.data[i]); break;
						// Если строка записывается знаками набора IA5
						case static_cast <uint32_t> (tag_t::IA5_STRING): allowed = (view.data[i] <= 0x7F); break;
						// Если строка записывается видимыми знаками
						default: allowed = ((view.data[i] >= 0x20) && (view.data[i] <= 0x7E));
					}
					// Если знак не принадлежит набору знаков строки
					if(!allowed){
						// Запоминаем причину отказа
						this->_error = error_t::VALUE;
						// Выводим отказ записи
						return false;
					}
				}
				// Выполняем запись строки
				return this->element(cls_t::UNIVERSAL, false, static_cast <uint32_t> (type), view);
			}
			// Если строка записывается знаками кодировки UCS-2 либо UCS-4
			case static_cast <uint32_t> (tag_t::BMP_STRING):
			case static_cast <uint32_t> (tag_t::UNIVERSAL_STRING): {
				// Набор знаков записываемой строки
				vector <uint32_t> codes;
				// Выполняем проверку записи строки с извлечением знаков
				const error_t error = utf8(view, &codes);
				// Если запись строки не отвечает правилам кодировки
				if(error != error_t::NONE){
					// Запоминаем причину отказа
					this->_error = error;
					// Выводим отказ записи
					return false;
				}
				// Определяем число байтов на знак строки
				const size_t width = ((type == tag_t::BMP_STRING) ? 2 : 4);
				// Собираемое содержимое строки
				vector <uint8_t> content;
				// Резервируем место под содержимое строки
				content.reserve(codes.size() * width);
				/**
				 * Выполняем обход знаков строки
				 */
				for(size_t i = 0; i < codes.size(); i++){
					/**
					 * Кодировка UCS-2 знаки за пределами основной многоязычной области
					 * не представляет, а подменять их парой суррогатов нельзя: пара
					 * суррогатов это средство кодировки UTF-16, которой здесь нет
					 */
					if((width == 2) && (codes[i] > 0xFFFF)){
						// Запоминаем причину отказа
						this->_error = error_t::VALUE;
						// Выводим отказ записи
						return false;
					}
					/**
					 * Выполняем запись знака от старших байтов к младшим
					 */
					for(size_t j = width; j > 0; j--)
						// Записываем очередной байт знака
						content.push_back(static_cast <uint8_t> ((codes[i] >> (8 * (j - 1))) & 0xFF));
				}
				// Выполняем запись строки
				return this->element(cls_t::UNIVERSAL, false, static_cast <uint32_t> (type), view_t(content.data(), content.size()));
			}
			// Если строка записывается кодировкой T.61
			case static_cast <uint32_t> (tag_t::T61_STRING):
				// Выполняем запись строки как есть
				return this->element(cls_t::UNIVERSAL, false, static_cast <uint32_t> (type), view);
			// Если вид строки не поддерживается
			default: {
				// Запоминаем причину отказа
				this->_error = error_t::TAG;
				// Выводим отказ записи
				return false;
			}
		}
	/**
	 * Если память выделить не удалось
	 */
	} catch(const bad_alloc &) {
		// Запоминаем причину отказа
		this->_error = error_t::MEMORY;
		// Выводим отказ записи
		return false;
	}
}

/**
 * @brief Конструктор записчика
 *
 */
anyks::asn1::Writer::Writer() noexcept : _error(error_t::NONE) {}
