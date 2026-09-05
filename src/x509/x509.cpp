/**
 * @file x509.cpp
 * @date 2026-08-27
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
 * @brief Исходный файл модуля сертификатов X.509 — реализация разбора записи
 *        сертификата по RFC 5280
 *
 * @note Разбор нигде не пользуется методом asn1::Reader::enter: составной вид метки
 *       здесь проверяется тут же, у места разбора, потому что его нарушение означает
 *       не просто «не тот вид», а иное устройство записи, и причину отказа надлежит
 *       назвать устройством, а не кодировкой.
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

/**
 * Подключаем заголовочные файлы проекта
 */
#include <x509/x509.hpp>

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
	using namespace nts;

	/**
	 * Пространство имён модуля
	 */
	using namespace nts::x509;

	/**
	 * @brief Метод получения короткого обозначения признака имени
	 *
	 * @details Набор коротких обозначений взят ровно тем, каким его задаёт раздел 3
	 *          RFC 4514, и расширять его не следует. У OpenSSL таблица обозначений
	 *          своя и более обширная - оттого записи имён расходятся на признаках
	 *          serialNumber, organizationIdentifier и emailAddress, - но короткое
	 *          обозначение вне стандарта разбирается лишь тем, кто знает ту же
	 *          таблицу, тогда как запись опознавателем разбирается всяким.
	 *          Расхождение это намеренное и проверено сличением: из 128 корневых
	 *          сертификатов доверенного набора оно затрагивает четыре записи
	 *
	 * @param oid опознаватель признака имени
	 * @return    короткое обозначение признака либо сам опознаватель
	 *
	 */
	static const string & shorten(const string & oid) noexcept {
		/**
		 * @brief Соответствие опознавателя признака его короткому обозначению
		 *
		 */
		static const struct {
			// Короткое обозначение признака имени
			string name = "";
			// Опознаватель признака имени
			const char * oid = nullptr;
		} names[] = {
			{"CN", "2.5.4.3"},
			{"C", "2.5.4.6"},
			{"L", "2.5.4.7"},
			{"ST", "2.5.4.8"},
			{"O", "2.5.4.10"},
			{"OU", "2.5.4.11"},
			{"STREET", "2.5.4.9"},
			{"DC", "0.9.2342.19200300.100.1.25"},
			{"UID", "0.9.2342.19200300.100.1.1"}
		};
		/**
		 * Выполняем перебор набора коротких обозначений признаков
		 */
		for(size_t i = 0; i < (sizeof(names) / sizeof(names[0])); i++){
			// Если опознаватель признака найден в наборе
			if(oid.compare(names[i].oid) == 0)
				// Выводим короткое обозначение признака
				return names[i].name;
		}
		// Выводим сам опознаватель признака
		return oid;
	}
};

/**
 * @brief Метод разбора опознавателя алгоритма
 *
 * @param element элемент записи опознавателя алгоритма
 * @param oid     строка, в которую помещается опознаватель алгоритма
 * @param params  просмотр, в который помещается запись настроек алгоритма
 * @return        причина отказа либо error_t::NONE
 *
 */
nts::x509::error_t nts::x509::Certificate::identifier(const asn1::element_t & element, string & oid, view_t & params) noexcept {
	// Если запись опознавателя алгоритма имеет простой вид метки
	if(!element.constructed)
		// Выводим причину отказа
		return error_t::STRUCTURE;
	// Создаём разборщик содержимого записи опознавателя алгоритма
	asn1::reader_t reader(element.content);
	// Объект разобранного элемента
	asn1::element_t item;
	// Выполняем разбор опознавателя алгоритма
	if(!reader.next(asn1::tag_t::OBJECT, item))
		// Выводим причину отказа
		return error_t::ENCODING;
	// Итог извлечения опознавателя алгоритма
	const asn1::error_t status = asn1::oid(item, oid);
	// Если память под опознаватель алгоритма выделить не удалось
	if(status == asn1::error_t::MEMORY)
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	// Если извлечение опознавателя алгоритма не удалось
	if(status != asn1::error_t::NONE)
		// Выводим причину отказа
		return error_t::ENCODING;
	/**
	 * Настройки алгоритма отдаются записью как есть: устройство их задаётся самим
	 * алгоритмом, и разбирать их разборщику сертификата нечем
	 */
	if(!reader.empty()){
		// Выполняем разбор настроек алгоритма
		if(!reader.next(item))
			// Выводим причину отказа
			return error_t::ENCODING;
		// Запоминаем запись настроек алгоритма
		params = item.element;
		// Если после настроек алгоритма остались лишние поля
		if(!reader.empty())
			// Выводим причину отказа
			return error_t::STRUCTURE;
	}
	// Выводим успешность разбора
	return error_t::NONE;
}

/**
 * @brief Метод разбора отличительного имени
 *
 * @param element элемент записи имени
 * @param result  объект имени, в который производится разбор
 * @return        причина отказа либо error_t::NONE
 *
 */
nts::x509::error_t nts::x509::Certificate::name(const asn1::element_t & element, name_t & result) noexcept {
	// Если запись имени имеет простой вид метки
	if(!element.constructed)
		// Выводим причину отказа
		return error_t::STRUCTURE;
	// Запоминаем запись имени целиком
	result.element = element.element;
	/**
	 * Разбор имени собирает признаки и составляющие, а значит выделяет память:
	 * нехватка её обязана дойти до вызывающего причиной отказа, а не завершить
	 * процесс. Метод объявлен noexcept, и перехват в разборе сертификата сюда не
	 * дотягивается - бросок обязан быть пойман здесь же
	 */
	try {
		// Создаём разборщик содержимого записи имени
		asn1::reader_t reader(element.content);
		/**
		 * Выполняем обход составляющих имени
		 */
		while(!reader.empty()){
			// Объект разобранной составляющей имени
			asn1::element_t item;
			// Выполняем разбор составляющей имени
			if(!reader.next(asn1::tag_t::SET, item))
				// Выводим причину отказа
				return error_t::ENCODING;
			// Если составляющая имени имеет простой вид метки
			if(!item.constructed)
				// Выводим причину отказа
				return error_t::STRUCTURE;
			// Создаём разборщик содержимого составляющей имени
			asn1::reader_t items(item.content);
			/**
			 * Составляющая имени без единого признака устройством имени запрещена:
			 * пустая составляющая ничего не обозначает, но участвует в сличении имён
			 */
			if(items.empty())
				// Выводим причину отказа
				return error_t::NAME;
			// Набор признаков составляющей имени
			vector <attribute_t> part;
			/**
			 * Выполняем обход признаков составляющей имени
			 */
			while(!items.empty()){
				// Объект разобранного признака
				asn1::element_t pair;
				// Выполняем разбор признака
				if(!items.next(asn1::tag_t::SEQUENCE, pair))
					// Выводим причину отказа
					return error_t::ENCODING;
				// Если признак имеет простой вид метки
				if(!pair.constructed)
					// Выводим причину отказа
					return error_t::STRUCTURE;
				// Создаём разборщик содержимого признака
				asn1::reader_t fields(pair.content);
				// Объект разобранного поля признака
				asn1::element_t field;
				// Разбираемый признак имени
				attribute_t attribute;
				// Выполняем разбор опознавателя признака
				if(!fields.next(asn1::tag_t::OBJECT, field))
					// Выводим причину отказа
					return error_t::ENCODING;
				// Итог извлечения опознавателя признака
				const asn1::error_t named = asn1::oid(field, attribute.oid);
				// Если память под опознаватель признака выделить не удалось
				if(named == asn1::error_t::MEMORY)
					// Выводим отказ нехватки памяти
					return error_t::MEMORY;
				// Если извлечение опознавателя признака не удалось
				if(named != asn1::error_t::NONE)
					// Выводим причину отказа
					return error_t::NAME;
				// Выполняем разбор значения признака
				if(!fields.next(field))
					// Выводим причину отказа
					return error_t::ENCODING;
				// Если значение признака записано меткой не универсального класса
				if(field.cls != asn1::cls_t::UNIVERSAL)
					// Выводим причину отказа
					return error_t::NAME;
				// Запоминаем вид записи значения признака
				attribute.type = static_cast <asn1::tag_t> (field.tag);
				// Итог извлечения значения признака
				const asn1::error_t valued = asn1::text(field, attribute.type, attribute.value);
				// Если память под значение признака выделить не удалось
				if(valued == asn1::error_t::MEMORY)
					// Выводим отказ нехватки памяти
					return error_t::MEMORY;
				// Если извлечение значения признака не удалось
				if(valued != asn1::error_t::NONE)
					// Выводим причину отказа
					return error_t::NAME;
				// Если после значения признака остались лишние поля
				if(!fields.empty())
					// Выводим причину отказа
					return error_t::STRUCTURE;
				// Добавляем признак в набор признаков составляющей
				/**
				 * Раздел 4.1.2.4 RFC 5280 и X.501: признаки одной составляющей имени
				 * различны по виду, повтор вида - оплошность записи
				 */
				for(size_t i = 0; i < part.size(); i++){
					// Если признак такого вида в составляющей уже есть
					if(part[i].oid.compare(attribute.oid) == 0)
						// Выводим отказ повторного признака
						return error_t::DUPLICATE;
				}
				part.push_back(attribute);
			}
			// Добавляем составляющую в набор составляющих имени
			result.parts.push_back(part);
		}
	/**
	 * Если память выделить не удалось
	 */
	} catch(const bad_alloc &) {
		// Выводим причину отказа
		return error_t::MEMORY;
	}
	// Выводим успешность разбора
	return error_t::NONE;
}

/**
 * @brief Метод разбора записи сертификата
 *
 * @param data просмотр разбираемой записи сертификата
 * @return     причина отказа либо error_t::NONE
 *
 */
nts::x509::error_t nts::x509::Certificate::parse(const view_t & data) noexcept {
	// Выполняем очистку разобранных сведений
	this->clear();
	/**
	 * Разбор собирает имена и расширения, а значит выделяет память: нехватка её
	 * обязана дойти до вызывающего причиной отказа, а не завершить процесс
	 */
	try {
		// Создаём разборщик записи сертификата
		asn1::reader_t reader(data);
		// Объект разобранной записи сертификата
		asn1::element_t certificate;
		// Выполняем разбор записи сертификата
		if(!reader.next(asn1::tag_t::SEQUENCE, certificate))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		/**
		 * Лишние байты после записи сертификата отвергаются: подпись поставлена под
		 * одной записью, и всякое продолжение за её пределами подписью не покрыто
		 */
		if(!reader.empty() || !certificate.constructed)
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Запоминаем запись сертификата целиком
		this->_element = certificate.element;
		// Создаём разборщик содержимого записи сертификата
		asn1::reader_t top(certificate.content);
		// Объект разобранной подписываемой части сертификата
		asn1::element_t body;
		// Выполняем разбор подписываемой части сертификата
		if(!top.next(asn1::tag_t::SEQUENCE, body))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		/**
		 * Правила DER кладут последовательности составной вид метки: простой её вид
		 * означает запись, правилам не отвечающую. Сверка эта стоит у всякой прочей
		 * последовательности разбора, а у подписываемой части её недоставало
		 */
		if(!body.constructed)
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Запоминаем подписываемую часть сертификата
		this->_body = body.element;
		// Объект разобранного элемента
		asn1::element_t item;
		// Выполняем разбор опознавателя алгоритма подписи
		if(!top.next(asn1::tag_t::SEQUENCE, item))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Просмотр записи настроек алгоритма подписи снаружи
		view_t params;
		// Выполняем извлечение опознавателя алгоритма подписи
		this->_error = this->identifier(item, this->_outer, params);
		// Если извлечение опознавателя алгоритма подписи не удалось
		if(this->_error != error_t::NONE)
			// Выводим причину отказа
			return this->_error;
		// Выполняем разбор подписи сертификата
		if(!top.next(asn1::tag_t::BIT_STRING, item))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Выполняем извлечение подписи сертификата
		if(asn1::bits(item, this->_signature, this->_unused) != asn1::error_t::NONE)
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Если после подписи остались лишние поля
		if(!top.empty())
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Создаём разборщик содержимого подписываемой части сертификата
		asn1::reader_t inner(body.content);
		// Выполняем разбор первого поля подписываемой части
		if(!inner.next(item))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Если издание сертификата записано явно
		if((item.cls == asn1::cls_t::CONTEXT) && (item.tag == 0)){
			// Если запись издания сертификата имеет простой вид метки
			if(!item.constructed)
				// Запоминаем причину отказа
				return (this->_error = error_t::VERSION);
			// Создаём разборщик содержимого записи издания сертификата
			asn1::reader_t release(item.content);
			// Объект разобранного издания сертификата
			asn1::element_t number;
			// Выполняем разбор издания сертификата
			if(!release.next(asn1::tag_t::INTEGER, number))
				// Запоминаем причину отказа
				return (this->_error = error_t::ENCODING);
			// Значение издания сертификата
			int64_t value = 0;
			// Выполняем извлечение издания сертификата
			if((asn1::integer(number, value) != asn1::error_t::NONE) || !release.empty())
				// Запоминаем причину отказа
				return (this->_error = error_t::VERSION);
			/**
			 * Первое издание записывается отсутствием поля, а не значением нуля:
			 * кодировка DER значение по умолчанию не записывает вовсе
			 */
			if((value < 1) || (value > 2))
				// Запоминаем причину отказа
				return (this->_error = error_t::VERSION);
			// Запоминаем издание сертификата
			this->_version = static_cast <version_t> (value);
			// Выполняем разбор следующего поля подписываемой части
			if(!inner.next(item))
				// Запоминаем причину отказа
				return (this->_error = error_t::ENCODING);
		}
		// Если порядковый номер сертификата записан не целым числом
		if((item.cls != asn1::cls_t::UNIVERSAL) || (item.tag != static_cast <uint32_t> (asn1::tag_t::INTEGER)))
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Выполняем извлечение порядкового номера сертификата
		if(asn1::integer(item, this->_serial) != asn1::error_t::NONE)
			// Запоминаем причину отказа
			return (this->_error = error_t::SERIAL);
		// Выполняем разбор опознавателя алгоритма подписи внутри подписываемой части
		if(!inner.next(asn1::tag_t::SEQUENCE, item))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Выполняем извлечение опознавателя алгоритма подписи
		this->_error = this->identifier(item, this->_algorithm, this->_parameters);
		// Если извлечение опознавателя алгоритма подписи не удалось
		if(this->_error != error_t::NONE)
			// Выводим причину отказа
			return this->_error;
		/**
		 * Разделы 4.1.1.2 и 4.1.2.3 RFC 5280: опознаватель алгоритма подписи снаружи
		 * подписываемой части обязан совпадать с опознавателем внутри неё
		 */
		if(this->_outer.compare(this->_algorithm) != 0)
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Выполняем разбор имени издателя сертификата
		if(!inner.next(asn1::tag_t::SEQUENCE, item))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Выполняем извлечение имени издателя сертификата
		this->_error = this->name(item, this->_issuer);
		// Если извлечение имени издателя сертификата не удалось
		if(this->_error != error_t::NONE)
			// Выводим причину отказа
			return this->_error;
		// Выполняем разбор срока действия сертификата
		if(!inner.next(asn1::tag_t::SEQUENCE, item))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Если запись срока действия имеет простой вид метки
		if(!item.constructed)
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Создаём разборщик содержимого записи срока действия
		asn1::reader_t validity(item.content);
		// Набор границ срока действия сертификата
		int64_t * bounds[2] = {&this->_before, &this->_after};
		/**
		 * Выполняем обход границ срока действия сертификата
		 */
		for(size_t i = 0; i < 2; i++){
			// Объект разобранной границы срока действия
			asn1::element_t moment;
			// Выполняем разбор границы срока действия
			if(!validity.next(moment))
				// Запоминаем причину отказа
				return (this->_error = error_t::ENCODING);
			// Если граница срока действия записана меткой не универсального класса
			if(moment.cls != asn1::cls_t::UNIVERSAL)
				// Запоминаем причину отказа
				return (this->_error = error_t::VALIDITY);
			// Определяем вид записи времени
			const asn1::tag_t type = static_cast <asn1::tag_t> (moment.tag);
			// Если вид записи времени не отвечает устройству срока действия
			if((type != asn1::tag_t::UTC_TIME) && (type != asn1::tag_t::GENERALIZED_TIME))
				// Запоминаем причину отказа
				return (this->_error = error_t::VALIDITY);
			// Выполняем извлечение границы срока действия
			if(asn1::time(moment, type, *bounds[i]) != asn1::error_t::NONE)
				// Запоминаем причину отказа
				return (this->_error = error_t::VALIDITY);
			/**
			 * Правило RFC 5280 разделяет два вида записи времени по 2049 году: до него
			 * время записывается двузначным годом, начиная с 2050 - четырёхзначным.
			 * Правило это снимает у записи двоякость, и нарушение его означает запись,
			 * которую разные разборщики прочтут по-разному
			 */
			if((*bounds[i] <= 2524607999) != (type == asn1::tag_t::UTC_TIME))
				// Запоминаем причину отказа
				return (this->_error = error_t::VALIDITY);
		}
		// Если после границ срока действия остались лишние поля
		if(!validity.empty())
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Выполняем разбор имени владельца сертификата
		if(!inner.next(asn1::tag_t::SEQUENCE, item))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Выполняем извлечение имени владельца сертификата
		this->_error = this->name(item, this->_subject);
		// Если извлечение имени владельца сертификата не удалось
		if(this->_error != error_t::NONE)
			// Выводим причину отказа
			return this->_error;
		// Выполняем разбор сведений об открытом ключе
		if(!inner.next(asn1::tag_t::SEQUENCE, item))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Если запись сведений об открытом ключе имеет простой вид метки
		if(!item.constructed)
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Запоминаем запись сведений об открытом ключе целиком
		this->_key.element = item.element;
		{
			// Создаём разборщик содержимого записи сведений об открытом ключе
			asn1::reader_t info(item.content);
			// Объект разобранного поля сведений об открытом ключе
			asn1::element_t field;
			// Выполняем разбор опознавателя алгоритма ключа
			if(!info.next(asn1::tag_t::SEQUENCE, field))
				// Запоминаем причину отказа
				return (this->_error = error_t::ENCODING);
			// Выполняем извлечение опознавателя алгоритма ключа
			this->_error = this->identifier(field, this->_key.algorithm, this->_key.parameters);
			// Если извлечение опознавателя алгоритма ключа не удалось
			if(this->_error != error_t::NONE)
				// Выводим причину отказа
				return this->_error;
			// Выполняем разбор открытого ключа
			if(!info.next(asn1::tag_t::BIT_STRING, field))
				// Запоминаем причину отказа
				return (this->_error = error_t::ENCODING);
			// Выполняем извлечение открытого ключа
			if(asn1::bits(field, this->_key.key, this->_key.unused) != asn1::error_t::NONE)
				// Запоминаем причину отказа
				return (this->_error = error_t::KEY);
			// Если после открытого ключа остались лишние поля
			if(!info.empty())
				// Запоминаем причину отказа
				return (this->_error = error_t::STRUCTURE);
		}
		// Номер метки последнего разобранного необязательного поля
		uint32_t last = 0;
		/**
		 * Выполняем обход необязательных полей подписываемой части
		 */
		while(!inner.empty()){
			// Выполняем разбор необязательного поля
			if(!inner.next(item))
				// Запоминаем причину отказа
				return (this->_error = error_t::ENCODING);
			/**
			 * Необязательные поля различаются меткой места употребления и обязаны идти
			 * по возрастанию номера: устройство записи задаёт их порядок, и запись с
			 * иным порядком - это иная запись, а не та же самая
			 */
			if((item.cls != asn1::cls_t::CONTEXT) || (item.tag <= last) || (item.tag > 3))
				// Запоминаем причину отказа
				return (this->_error = error_t::STRUCTURE);
			// Запоминаем номер метки разобранного необязательного поля
			last = item.tag;
			/**
			 * Определяем разбираемое необязательное поле по номеру метки
			 */
			switch(item.tag){
				// Если разбирается опознаватель издателя либо владельца
				case 1:
				case 2: {
					/**
					 * Опознаватели издателя и владельца появились во втором издании:
					 * в первом издании поля этого нет, и его наличие означает запись,
					 * не отвечающую объявленному изданию
					 */
					if(this->_version == version_t::V1)
						// Запоминаем причину отказа
						return (this->_error = error_t::VERSION);
					// Если опознаватель имеет составной вид метки
					if(item.constructed)
						// Запоминаем причину отказа
						return (this->_error = error_t::STRUCTURE);
					// Число неиспользуемых разрядов опознавателя
					uint8_t bits = 0;
					// Просмотр записи опознавателя
					view_t value;
					// Выполняем извлечение опознавателя
					if(asn1::bits(item, value, bits) != asn1::error_t::NONE)
						// Запоминаем причину отказа
						return (this->_error = error_t::STRUCTURE);
					// Запоминаем опознаватель издателя либо владельца
					((item.tag == 1) ? this->_issuerUID : this->_subjectUID) = value;
				} break;
				// Если разбирается набор расширений сертификата
				case 3: {
					/**
					 * Расширения появились в третьем издании: их наличие у сертификата
					 * иного издания означает запись, не отвечающую объявленному изданию
					 */
					if(this->_version != version_t::V3)
						// Запоминаем причину отказа
						return (this->_error = error_t::VERSION);
					// Если запись набора расширений имеет простой вид метки
					if(!item.constructed)
						// Запоминаем причину отказа
						return (this->_error = error_t::STRUCTURE);
					// Создаём разборщик содержимого записи набора расширений
					asn1::reader_t outside(item.content);
					// Объект разобранного набора расширений
					asn1::element_t list;
					// Выполняем разбор набора расширений
					if(!outside.next(asn1::tag_t::SEQUENCE, list))
						// Запоминаем причину отказа
						return (this->_error = error_t::ENCODING);
					// Если после набора расширений остались лишние поля
					if(!outside.empty() || !list.constructed)
						// Запоминаем причину отказа
						return (this->_error = error_t::STRUCTURE);
					// Создаём разборщик содержимого набора расширений
					asn1::reader_t items(list.content);
					/**
					 * Пустой набор расширений устройством записи запрещён: поле это
					 * необязательное, и отсутствие расширений записывается его отсутствием
					 */
					if(items.empty())
						// Запоминаем причину отказа
						return (this->_error = error_t::EXTENSION);
					/**
					 * Выполняем обход расширений сертификата
					 */
					while(!items.empty()){
						// Объект разобранного расширения
						asn1::element_t entry;
						// Выполняем разбор расширения
						if(!items.next(asn1::tag_t::SEQUENCE, entry))
							// Запоминаем причину отказа
							return (this->_error = error_t::ENCODING);
						// Если запись расширения имеет простой вид метки
						if(!entry.constructed)
							// Запоминаем причину отказа
							return (this->_error = error_t::STRUCTURE);
						// Создаём разборщик содержимого записи расширения
						asn1::reader_t fields(entry.content);
						// Объект разобранного поля расширения
						asn1::element_t field;
						// Разбираемое расширение сертификата
						extension_t extension;
						// Выполняем разбор опознавателя расширения
						if(!fields.next(asn1::tag_t::OBJECT, field))
							// Запоминаем причину отказа
							return (this->_error = error_t::ENCODING);
						// Итог извлечения опознавателя расширения
						const asn1::error_t status = asn1::oid(field, extension.oid);
						// Если память под опознаватель расширения выделить не удалось
						if(status == asn1::error_t::MEMORY)
							// Запоминаем отказ нехватки памяти
							return (this->_error = error_t::MEMORY);
						// Если извлечение опознавателя расширения не удалось
						if(status != asn1::error_t::NONE)
							// Запоминаем причину отказа
							return (this->_error = error_t::EXTENSION);
						// Выполняем разбор следующего поля расширения
						if(!fields.next(field))
							// Запоминаем причину отказа
							return (this->_error = error_t::ENCODING);
						// Если признак обязательности расширения записан явно
						if((field.cls == asn1::cls_t::UNIVERSAL) && (field.tag == static_cast <uint32_t> (asn1::tag_t::BOOLEAN))){
							// Выполняем извлечение признака обязательности расширения
							if(asn1::boolean(field, extension.critical) != asn1::error_t::NONE)
								// Запоминаем причину отказа
								return (this->_error = error_t::EXTENSION);
							/**
							 * Необязательность расширения записывается отсутствием поля:
							 * кодировка DER значение по умолчанию не записывает вовсе
							 */
							if(!extension.critical)
								// Запоминаем причину отказа
								return (this->_error = error_t::EXTENSION);
							// Выполняем разбор следующего поля расширения
							if(!fields.next(field))
								// Запоминаем причину отказа
								return (this->_error = error_t::ENCODING);
						}
						// Если содержимое расширения записано не строкой байтов
						if((field.cls != asn1::cls_t::UNIVERSAL) || field.constructed ||
						   (field.tag != static_cast <uint32_t> (asn1::tag_t::OCTET_STRING)))
							// Запоминаем причину отказа
							return (this->_error = error_t::STRUCTURE);
						// Запоминаем содержимое расширения
						extension.value = field.content;
						// Если после содержимого расширения остались лишние поля
						if(!fields.empty())
							// Запоминаем причину отказа
							return (this->_error = error_t::STRUCTURE);
						/**
						 * Выполняем обход разобранных расширений
						 */
						for(size_t i = 0; i < this->_extensions.size(); i++){
							/**
							 * Повторное расширение запрещено RFC 5280: два расширения одного
							 * опознавателя дают два разных ответа на один вопрос, и выбор
							 * между ними у разных разборщиков расходится
							 */
							if(this->_extensions[i].oid.compare(extension.oid) == 0)
								// Запоминаем причину отказа
								return (this->_error = error_t::DUPLICATE);
						}
						// Добавляем расширение в набор расширений сертификата
						this->_extensions.push_back(extension);
					}
				} break;
			}
		}
	/**
	 * Если память выделить не удалось
	 */
	} catch(const bad_alloc &) {
		// Запоминаем причину отказа
		return (this->_error = error_t::MEMORY);
	}
	// Выводим успешность разбора
	return error_t::NONE;
}

/**
 * @brief Метод очистки разобранных сведений
 *
 */
void nts::x509::Certificate::clear() noexcept {
	// Сбрасываем издание сертификата
	this->_version = version_t::V1;
	// Сбрасываем причину последнего отказа
	this->_error = error_t::NONE;
	// Сбрасываем просмотры записи сертификата
	this->_element = view_t();
	this->_body = view_t();
	this->_serial = view_t();
	this->_signature = view_t();
	this->_issuerUID = view_t();
	this->_subjectUID = view_t();
	this->_parameters = view_t();
	// Сбрасываем число неиспользуемых разрядов подписи
	this->_unused = 0;
	// Сбрасываем опознаватели алгоритма подписи
	this->_algorithm.clear();
	this->_outer.clear();
	// Сбрасываем имена издателя и владельца сертификата
	this->_issuer = name_t();
	this->_subject = name_t();
	// Сбрасываем срок действия сертификата
	this->_before = 0;
	this->_after = 0;
	// Сбрасываем сведения об открытом ключе
	this->_key = key_t();
	// Сбрасываем набор расширений сертификата
	this->_extensions.clear();
}

/**
 * @brief Метод извлечения причины последнего отказа
 *
 * @return причина последнего отказа
 *
 */
nts::x509::error_t nts::x509::Certificate::err() const noexcept {
	// Выводим причину последнего отказа
	return this->_error;
}

/**
 * @brief Метод извлечения издания сертификата
 *
 * @return издание сертификата
 *
 */
nts::x509::version_t nts::x509::Certificate::release() const noexcept {
	// Выводим издание сертификата
	return this->_version;
}

/**
 * @brief Метод извлечения подписываемой части сертификата
 *
 * @return просмотр подписываемой части сертификата
 *
 */
const nts::view_t & nts::x509::Certificate::body() const noexcept {
	// Выводим подписываемую часть сертификата
	return this->_body;
}

/**
 * @brief Метод извлечения порядкового номера сертификата
 *
 * @return просмотр порядкового номера сертификата
 *
 */
const nts::view_t & nts::x509::Certificate::number() const noexcept {
	// Выводим порядковый номер сертификата
	return this->_serial;
}

/**
 * @brief Метод извлечения подписи сертификата
 *
 * @param unused число неиспользуемых разрядов последнего байта подписи
 * @return       просмотр записи подписи
 *
 */
const nts::view_t & nts::x509::Certificate::sign(uint8_t & unused) const noexcept {
	// Запоминаем число неиспользуемых разрядов последнего байта подписи
	unused = this->_unused;
	// Выводим подпись сертификата
	return this->_signature;
}

/**
 * @brief Метод извлечения опознавателя алгоритма подписи
 *
 * @return опознаватель алгоритма подписи
 *
 */
const string & nts::x509::Certificate::algorithms() const noexcept {
	// Выводим опознаватель алгоритма подписи
	return this->_algorithm;
}

/**
 * @brief Метод извлечения имени издателя сертификата
 *
 * @return имя издателя сертификата
 *
 */
const nts::x509::name_t & nts::x509::Certificate::issuers() const noexcept {
	// Выводим имя издателя сертификата
	return this->_issuer;
}

/**
 * @brief Метод извлечения имени владельца сертификата
 *
 * @return имя владельца сертификата
 *
 */
const nts::x509::name_t & nts::x509::Certificate::subjects() const noexcept {
	// Выводим имя владельца сертификата
	return this->_subject;
}

/**
 * @brief Метод извлечения срока действия сертификата
 *
 * @param before начало срока действия в секундах от начала эпохи
 * @param after  окончание срока действия в секундах от начала эпохи
 *
 */
void nts::x509::Certificate::validity(int64_t & before, int64_t & after) const noexcept {
	// Запоминаем начало срока действия сертификата
	before = this->_before;
	// Запоминаем окончание срока действия сертификата
	after = this->_after;
}

/**
 * @brief Метод извлечения сведений об открытом ключе
 *
 * @return сведения об открытом ключе
 *
 */
const nts::x509::key_t & nts::x509::Certificate::key() const noexcept {
	// Выводим сведения об открытом ключе
	return this->_key;
}

/**
 * @brief Метод извлечения набора расширений сертификата
 *
 * @return набор расширений сертификата
 *
 */
const vector <nts::x509::extension_t> & nts::x509::Certificate::extension() const noexcept {
	// Выводим набор расширений сертификата
	return this->_extensions;
}

/**
 * @brief Метод поиска расширения сертификата по опознавателю
 *
 * @param oid опознаватель разыскиваемого расширения
 * @return    расширение сертификата либо nullptr
 *
 */
const nts::x509::extension_t * nts::x509::Certificate::extension(const string & oid) const noexcept {
	/**
	 * Выполняем обход набора расширений сертификата
	 */
	for(size_t i = 0; i < this->_extensions.size(); i++){
		// Если опознаватель расширения совпал с разыскиваемым
		if(this->_extensions[i].oid.compare(oid) == 0)
			// Выводим найденное расширение
			return &this->_extensions[i];
	}
	// Выводим отсутствие расширения
	return nullptr;
}

/**
 * @brief Метод поиска расширения сертификата по опознавателю-литералу
 *
 * @param oid опознаватель разыскиваемого расширения
 * @return    расширение сертификата либо nullptr
 *
 */
const nts::x509::extension_t * nts::x509::Certificate::extension(const char * oid) const noexcept {
	// Если опознаватель не задан
	if(oid == nullptr)
		// Выводим отсутствие расширения
		return nullptr;
	/**
	 * Выполняем обход набора расширений сертификата
	 */
	for(size_t i = 0; i < this->_extensions.size(); i++){
		// Если опознаватель расширения совпал с разыскиваемым (сличение без построения строки)
		if(this->_extensions[i].oid.compare(oid) == 0)
			// Выводим найденное расширение
			return &this->_extensions[i];
	}
	// Выводим отсутствие расширения
	return nullptr;
}

/**
 * @brief Конструктор сертификата
 *
 */
nts::x509::Certificate::Certificate() noexcept :
	_version(version_t::V1), _error(error_t::NONE), _unused(0), _before(0), _after(0) {}

/**
 * @brief Метод поиска признака имени по опознавателю
 *
 * @param name имя, в котором ведётся поиск
 * @param oid  опознаватель разыскиваемого признака
 * @return     признак имени либо nullptr
 *
 */
const nts::x509::attribute_t * nts::x509::attribute(const name_t & name, const string & oid) noexcept {
	/**
	 * Выполняем обход составляющих имени
	 */
	for(size_t i = 0; i < name.parts.size(); i++){
		/**
		 * Выполняем обход признаков составляющей имени
		 */
		for(size_t j = 0; j < name.parts[i].size(); j++){
			// Если опознаватель признака совпал с разыскиваемым
			if(name.parts[i][j].oid.compare(oid) == 0)
				// Выводим найденный признак имени
				return &name.parts[i][j];
		}
	}
	// Выводим отсутствие признака имени
	return nullptr;
}

/**
 * @brief Метод сборки записи имени в виде строки
 *
 * @param name   имя, запись которого собирается
 * @param result строка, в которую помещается результат
 * @return       причина отказа либо error_t::NONE
 *
 */
nts::x509::error_t nts::x509::text(const name_t & name, string & result) noexcept {
	/**
	 * Сборка записи выделяет память, и нехватка её обязана дойти до вызывающего
	 * причиной отказа, а не завершить процесс
	 */
	try {
		// Очищаем строку результата
		result.clear();
		/**
		 * Выполняем обход составляющих имени от последней к первой
		 */
		for(size_t i = name.parts.size(); i > 0; i--){
			// Если собираемая запись не пустая
			if(!result.empty())
				// Записываем разделитель составляющих имени
				result.append(1, ',');
			/**
			 * Выполняем обход признаков составляющей имени
			 */
			for(size_t j = 0; j < name.parts[i - 1].size(); j++){
				// Получаем разбираемый признак имени
				const attribute_t & item = name.parts[i - 1][j];
				// Если признак не первый в составляющей имени
				if(j > 0)
					// Записываем разделитель признаков внутри составляющей
					result.append(1, '+');
				/**
				 * Короткие обозначения признаков заданы RFC 4514, для остальных
				 * признаков записывается сам опознаватель
				 *
				 * Набор коротких обозначений взят ровно тем, каким его задаёт раздел 3
				 * RFC 4514, и расширять его не следует. У OpenSSL таблица обозначений
				 * своя и более обширная - оттого записи имён расходятся на признаках
				 * serialNumber, organizationIdentifier и emailAddress, - но короткое
				 * обозначение вне стандарта разбирается лишь тем, кто знает ту же
				 * таблицу, тогда как запись опознавателем разбирается всяким.
				 * Расхождение это намеренное и проверено сличением: из 128 корневых
				 * сертификатов доверенного набора оно затрагивает четыре записи
				 */
				result.append(shorten(item.oid));
				// Записываем разделитель обозначения и значения признака
				result.append(1, '=');
				/**
				 * Выполняем обход знаков значения признака
				 */
				for(size_t k = 0; k < item.value.size(); k++){
					// Извлекаем очередной знак значения признака
					const char letter = item.value[k];
					/**
					 * Знаки, несущие в записи имени своё значение, экранируются: без
					 * экранирования запись имени со скобкой или запятой читается как
					 * запись двух разных имён
					 */
					switch(letter){
						// Если знак несёт в записи имени своё значение
						case ',': case '+': case '"': case '\\':
						case '<': case '>': case ';': case '=':
							// Записываем знак экранирования
							result.append(1, '\\');
						break;
						// Если знаком является пробел либо решётка
						case ' ': case '#': {
							// Пробел и решётка экранируются лишь в начале записи значения
							if(k == 0)
								// Записываем знак экранирования
								result.append(1, '\\');
						} break;
					}
					// Если пробел завершает запись значения признака
					if((letter == ' ') && ((k + 1) == item.value.size()) && (k > 0))
						// Записываем знак экранирования
						result.append(1, '\\');
					// Записываем очередной знак значения признака
					result.append(1, letter);
				}
			}
		}
	/**
	 * Если память выделить не удалось
	 */
	} catch(const bad_alloc &) {
		// Выводим причину отказа
		return error_t::MEMORY;
	}
	// Выводим успешность сборки
	return error_t::NONE;
}

/**
 * @brief Метод извлечения основных ограничений сертификата
 *
 * @param extension расширение основных ограничений
 * @param authority признак принадлежности сертификата удостоверяющему центру
 * @param depth     предельная глубина цепочки либо минус единица
 * @return          причина отказа либо error_t::NONE
 *
 */
nts::x509::error_t nts::x509::constraints(const extension_t & extension, bool & authority, int64_t & depth) noexcept {
	// Сбрасываем признак принадлежности сертификата удостоверяющему центру
	authority = false;
	// Сбрасываем предельную глубину цепочки
	depth = -1;
	// Создаём разборщик содержимого расширения
	asn1::reader_t reader(extension.value);
	// Объект разобранной записи основных ограничений
	asn1::element_t item;
	// Выполняем разбор записи основных ограничений
	if(!reader.next(asn1::tag_t::SEQUENCE, item))
		// Выводим причину отказа
		return error_t::ENCODING;
	// Если после записи основных ограничений остались лишние поля
	if(!reader.empty() || !item.constructed)
		// Выводим причину отказа
		return error_t::STRUCTURE;
	// Создаём разборщик содержимого записи основных ограничений
	asn1::reader_t fields(item.content);
	// Если запись основных ограничений пустая
	if(fields.empty())
		// Выводим успешность извлечения
		return error_t::NONE;
	// Объект разобранного поля основных ограничений
	asn1::element_t field;
	// Выполняем разбор первого поля основных ограничений
	if(!fields.next(field))
		// Выводим причину отказа
		return error_t::ENCODING;
	// Если признак принадлежности удостоверяющему центру записан явно
	if((field.cls == asn1::cls_t::UNIVERSAL) && (field.tag == static_cast <uint32_t> (asn1::tag_t::BOOLEAN))){
		// Выполняем извлечение признака принадлежности удостоверяющему центру
		if(asn1::boolean(field, authority) != asn1::error_t::NONE)
			// Выводим причину отказа
			return error_t::EXTENSION;
		/**
		 * Отсутствие принадлежности удостоверяющему центру записывается отсутствием
		 * поля: кодировка DER значение по умолчанию не записывает вовсе
		 */
		if(!authority)
			// Выводим причину отказа
			return error_t::EXTENSION;
		// Если запись основных ограничений на этом закончилась
		if(fields.empty())
			// Выводим успешность извлечения
			return error_t::NONE;
		// Выполняем разбор следующего поля основных ограничений
		if(!fields.next(field))
			// Выводим причину отказа
			return error_t::ENCODING;
	}
	// Если предельная глубина цепочки записана не целым числом
	if((field.cls != asn1::cls_t::UNIVERSAL) || (field.tag != static_cast <uint32_t> (asn1::tag_t::INTEGER)))
		// Выводим причину отказа
		return error_t::STRUCTURE;
	// Выполняем извлечение предельной глубины цепочки
	if(asn1::integer(field, depth) != asn1::error_t::NONE)
		// Выводим причину отказа
		return error_t::EXTENSION;
	/**
	 * Предельная глубина цепочки не может быть отрицательной, и без принадлежности
	 * удостоверяющему центру смысла не имеет вовсе
	 */
	if((depth < 0) || !authority)
		// Выводим причину отказа
		return error_t::EXTENSION;
	// Если после предельной глубины цепочки остались лишние поля
	if(!fields.empty())
		// Выводим причину отказа
		return error_t::STRUCTURE;
	// Выводим успешность извлечения
	return error_t::NONE;
}

/**
 * @brief Метод извлечения назначения открытого ключа
 *
 * @param extension расширение назначения ключа
 * @param result    набор разрядов назначения ключа
 * @return          причина отказа либо error_t::NONE
 *
 */
nts::x509::error_t nts::x509::usage(const extension_t & extension, uint16_t & result) noexcept {
	// Сбрасываем набор разрядов назначения ключа
	result = 0;
	// Создаём разборщик содержимого расширения
	asn1::reader_t reader(extension.value);
	// Объект разобранной записи назначения ключа
	asn1::element_t item;
	// Выполняем разбор записи назначения ключа
	if(!reader.next(asn1::tag_t::BIT_STRING, item))
		// Выводим причину отказа
		return error_t::ENCODING;
	// Если после записи назначения ключа остались лишние поля
	if(!reader.empty())
		// Выводим причину отказа
		return error_t::STRUCTURE;
	// Просмотр записи разрядов назначения ключа
	view_t view;
	// Число неиспользуемых разрядов последнего байта
	uint8_t unused = 0;
	// Выполняем извлечение разрядов назначения ключа
	if(asn1::bits(item, view, unused) != asn1::error_t::NONE)
		// Выводим причину отказа
		return error_t::EXTENSION;
	/**
	 * Назначение ключа умещается в девять разрядов, и пустая запись назначения
	 * означает ключ, не пригодный ни для чего
	 */
	if((view.size < 1) || (view.size > 2))
		// Выводим причину отказа
		return error_t::EXTENSION;
	// Запоминаем первые восемь разрядов назначения ключа
	result = static_cast <uint16_t> (view.data[0]);
	// Если записан девятый разряд назначения ключа
	if((view.size > 1) && ((view.data[1] & 0x80) != 0))
		// Запоминаем девятый разряд назначения ключа
		result |= static_cast <uint16_t> (usage_t::DECIPHER_ONLY);
	// Выводим успешность извлечения
	return error_t::NONE;
}

/**
 * @brief Метод извлечения расширенного назначения открытого ключа
 *
 * @param extension расширение расширенного назначения ключа
 * @param result    набор опознавателей назначения ключа
 * @return          причина отказа либо error_t::NONE
 *
 */
nts::x509::error_t nts::x509::purpose(const extension_t & extension, vector <string> & result) noexcept {
	/**
	 * Сборка набора опознавателей выделяет память, и нехватка её обязана дойти до
	 * вызывающего причиной отказа, а не завершить процесс
	 */
	try {
		// Очищаем набор опознавателей назначения ключа
		result.clear();
		// Создаём разборщик содержимого расширения
		asn1::reader_t reader(extension.value);
		// Объект разобранной записи расширенного назначения ключа
		asn1::element_t item;
		// Выполняем разбор записи расширенного назначения ключа
		if(!reader.next(asn1::tag_t::SEQUENCE, item))
			// Выводим причину отказа
			return error_t::ENCODING;
		// Если после записи расширенного назначения ключа остались лишние поля
		if(!reader.empty() || !item.constructed)
			// Выводим причину отказа
			return error_t::STRUCTURE;
		// Создаём разборщик содержимого записи расширенного назначения ключа
		asn1::reader_t items(item.content);
		// Если запись расширенного назначения ключа пустая
		if(items.empty())
			// Выводим причину отказа
			return error_t::EXTENSION;
		/**
		 * Выполняем обход опознавателей назначения ключа
		 */
		while(!items.empty()){
			// Объект разобранного опознавателя назначения ключа
			asn1::element_t entry;
			// Выполняем разбор опознавателя назначения ключа
			if(!items.next(asn1::tag_t::OBJECT, entry))
				// Выводим причину отказа
				return error_t::ENCODING;
			// Извлекаемый опознаватель назначения ключа
			string oid;
			// Итог извлечения опознавателя назначения ключа
			const asn1::error_t status = asn1::oid(entry, oid);
			// Если память под опознаватель назначения ключа выделить не удалось
			if(status == asn1::error_t::MEMORY)
				// Выводим отказ нехватки памяти
				return error_t::MEMORY;
			// Если извлечение опознавателя назначения ключа не удалось
			if(status != asn1::error_t::NONE)
				// Выводим причину отказа
				return error_t::EXTENSION;
			// Добавляем опознаватель в набор опознавателей назначения ключа
			result.push_back(oid);
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
 * @brief Метод извлечения дополнительных имён владельца
 *
 * @param extension расширение дополнительных имён
 * @param result    набор дополнительных имён
 * @return          причина отказа либо error_t::NONE
 *
 */
nts::x509::error_t nts::x509::alternatives(const extension_t & extension, vector <alternative_t> & result) noexcept {
	/**
	 * Сборка набора имён выделяет память, и нехватка её обязана дойти до
	 * вызывающего причиной отказа, а не завершить процесс
	 */
	try {
		// Очищаем набор дополнительных имён
		result.clear();
		// Создаём разборщик содержимого расширения
		asn1::reader_t reader(extension.value);
		// Объект разобранной записи дополнительных имён
		asn1::element_t item;
		// Выполняем разбор записи дополнительных имён
		if(!reader.next(asn1::tag_t::SEQUENCE, item))
			// Выводим причину отказа
			return error_t::ENCODING;
		// Если после записи дополнительных имён остались лишние поля
		if(!reader.empty() || !item.constructed)
			// Выводим причину отказа
			return error_t::STRUCTURE;
		// Создаём разборщик содержимого записи дополнительных имён
		asn1::reader_t items(item.content);
		/**
		 * Пустой набор дополнительных имён устройством записи запрещён: расширение
		 * это необязательное, и отсутствие имён записывается его отсутствием
		 */
		if(items.empty())
			// Выводим причину отказа
			return error_t::EXTENSION;
		/**
		 * Выполняем обход дополнительных имён
		 */
		while(!items.empty()){
			// Объект разобранного дополнительного имени
			asn1::element_t entry;
			// Выполняем разбор дополнительного имени
			if(!items.next(entry))
				// Выводим причину отказа
				return error_t::ENCODING;
			// Если дополнительное имя записано меткой не места употребления
			if(entry.cls != asn1::cls_t::CONTEXT)
				// Выводим причину отказа
				return error_t::STRUCTURE;
			// Разбираемое дополнительное имя
			alternative_t alternative;
			// Запоминаем запись дополнительного имени целиком
			alternative.element = entry.element;
			/**
			 * Определяем вид дополнительного имени по номеру метки
			 */
			switch(entry.tag){
				// Если записан адрес электронной почты, доменное имя либо указатель ресурса
				case 1: case 2: case 6: {
					// Определяем вид дополнительного имени
					alternative.kind = ((entry.tag == 1) ? kind_t::EMAIL : ((entry.tag == 2) ? kind_t::DNS : kind_t::URI));
					/**
					 * Имена эти записаны строкой набора IA5, и метка их разметкой места
					 * употребления подменена: проверять набор знаков надлежит здесь
					 */
					const asn1::error_t status = asn1::text(entry, asn1::tag_t::IA5_STRING, alternative.value);
					// Если память под дополнительное имя выделить не удалось
					if(status == asn1::error_t::MEMORY)
						// Выводим отказ нехватки памяти
						return error_t::MEMORY;
					// Если извлечение дополнительного имени не удалось
					if(status != asn1::error_t::NONE)
						// Выводим причину отказа
						return error_t::EXTENSION;
				} break;
				// Если записан адрес сети
				case 7: {
					// Определяем вид дополнительного имени
					alternative.kind = kind_t::ADDRESS;
					// Если запись адреса сети имеет составной вид метки
					if(entry.constructed)
						// Выводим причину отказа
						return error_t::STRUCTURE;
					/**
					 * Раздел 4.2.1.6 RFC 5280: адрес сети в дополнительных именах записан
					 * ровно четырьмя байтами для IPv4 и ровно шестнадцатью для IPv6
					 */
					if((entry.content.size != 4) && (entry.content.size != 16))
						// Выводим причину отказа
						return error_t::EXTENSION;
					// Запоминаем байты адреса сети как есть
					alternative.value.assign(reinterpret_cast <const char *> (entry.content.data), entry.content.size);
				} break;
				// Если записано отличительное имя
				case 4: {
					// Определяем вид дополнительного имени
					alternative.kind = kind_t::DIRECTORY;
					// Если запись отличительного имени имеет простой вид метки
					if(!entry.constructed)
						// Выводим причину отказа
						return error_t::STRUCTURE;
				} break;
				// Если записано имя иного вида
				default: alternative.kind = kind_t::OTHER;
			}
			// Добавляем дополнительное имя в набор дополнительных имён
			result.push_back(alternative);
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
 * @brief Метод извлечения опознавателя ключа владельца
 *
 * @param extension расширение опознавателя ключа владельца
 * @param result    просмотр, в который помещается опознаватель ключа
 * @return          причина отказа либо error_t::NONE
 *
 */
nts::x509::error_t nts::x509::subjectKey(const extension_t & extension, view_t & result) noexcept {
	// Сбрасываем просмотр опознавателя ключа
	result = view_t();
	// Создаём разборщик содержимого расширения
	asn1::reader_t reader(extension.value);
	// Объект разобранной записи опознавателя ключа
	asn1::element_t item;
	// Выполняем разбор записи опознавателя ключа
	if(!reader.next(asn1::tag_t::OCTET_STRING, item))
		// Выводим причину отказа
		return error_t::ENCODING;
	// Если после записи опознавателя ключа остались лишние поля
	if(!reader.empty() || item.constructed)
		// Выводим причину отказа
		return error_t::STRUCTURE;
	// Запоминаем опознаватель ключа
	result = item.content;
	// Выводим успешность извлечения
	return error_t::NONE;
}

/**
 * @brief Метод извлечения опознавателя ключа издателя
 *
 * @param extension расширение опознавателя ключа издателя
 * @param result    просмотр, в который помещается опознаватель ключа
 * @return          причина отказа либо error_t::NONE
 *
 */
nts::x509::error_t nts::x509::authorityKey(const extension_t & extension, view_t & result) noexcept {
	// Сбрасываем просмотр опознавателя ключа
	result = view_t();
	// Создаём разборщик содержимого расширения
	asn1::reader_t reader(extension.value);
	// Объект разобранной записи опознавателя ключа издателя
	asn1::element_t item;
	// Выполняем разбор записи опознавателя ключа издателя
	if(!reader.next(asn1::tag_t::SEQUENCE, item))
		// Выводим причину отказа
		return error_t::ENCODING;
	// Если после записи опознавателя ключа издателя остались лишние поля
	if(!reader.empty() || !item.constructed)
		// Выводим причину отказа
		return error_t::STRUCTURE;
	// Создаём разборщик содержимого записи опознавателя ключа издателя
	asn1::reader_t fields(item.content);
	// Номер метки последнего разобранного поля
	uint32_t last = 0;
	/**
	 * Выполняем обход полей записи опознавателя ключа издателя
	 */
	while(!fields.empty()){
		// Объект разобранного поля
		asn1::element_t field;
		// Выполняем разбор поля
		if(!fields.next(field))
			// Выводим причину отказа
			return error_t::ENCODING;
		/**
		 * Поля различаются меткой места употребления и обязаны идти по возрастанию
		 * номера: устройство записи задаёт их порядок
		 */
		if((field.cls != asn1::cls_t::CONTEXT) || (field.tag < last) || (field.tag > 2))
			// Выводим причину отказа
			return error_t::STRUCTURE;
		// Если разбирается опознаватель ключа
		if(field.tag == 0){
			// Если запись опознавателя ключа имеет составной вид метки
			if(field.constructed)
				// Выводим причину отказа
				return error_t::STRUCTURE;
			// Запоминаем опознаватель ключа
			result = field.content;
		}
		// Запоминаем номер метки разобранного поля
		last = (field.tag + 1);
	}
	// Выводим успешность извлечения
	return error_t::NONE;
}
