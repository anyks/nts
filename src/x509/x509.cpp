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
#include <sign/rsa.hpp>

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
	 * @brief Функция получения короткого обозначения признака имени
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
	static const char * shorten(const string & oid) noexcept {
		/**
		 * @brief Соответствие опознавателя признака его короткому обозначению
		 *
		 */
		static const struct {
			// Короткое обозначение признака имени (указатель на литерал: таблица не выделяет памяти даже при прежнем устройстве строк)
			const char * name = nullptr;
			// Опознаватель признака имени
			const char * oid = nullptr;
		} names[] = {
			// Заполняем таблицу соответствий
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
		return oid.c_str();
	}
	/**
	 * @brief Функция проверки слабости хеша в настройках подписи RSASSA-PSS
	 *
	 * @param parameters запись настроек подписи RSASSA-PSS-params либо пустой просмотр
	 * @return           признак хеша SHA-1: явно записанного либо подразумеваемого умолчанием
	 *
	 */
	static bool pssweak(const view_t & parameters) noexcept {
		// Без настроек умолчание по разделу 3.1 RFC 4055 - SHA-1
		if((parameters.data == nullptr) || (parameters.size == 0))
			// Выводим признак слабого хеша
			return true;
		// Разборщик записи настроек
		asn1::reader_t reader(parameters);
		// Последовательность настроек
		asn1::element_t sequence;
		// Если последовательность не прочиталась - судить нечем, подпись отвергнет сама проверка
		if(!reader.next(sequence))
			// Выводим признак стойкого хеша
			return false;
		// Разборщик содержимого последовательности
		asn1::reader_t inner(sequence.content);
		// Первое поле
		asn1::element_t field;
		// Если полей нет либо первое не [0] hashAlgorithm - хеш по умолчанию SHA-1
		if(!inner.next(field) || (field.cls != asn1::cls_t::CONTEXT) || (field.tag != 0))
			// Выводим признак слабого хеша
			return true;
		// Разборщик содержимого [0]
		asn1::reader_t tagged(field.content);
		// Последовательность AlgorithmIdentifier и её опознаватель
		asn1::element_t identifier, object;
		// Если алгоритм хеша не прочитался
		if(!tagged.next(identifier))
			// Выводим признак слабого хеша
			return true;
		// Разборщик содержимого AlgorithmIdentifier
		asn1::reader_t named(identifier.content);
		// Если опознаватель не прочитался
		if(!named.next(object))
			// Выводим признак слабого хеша
			return true;
		// Опознаватель хеша
		string oid;
		// Если опознаватель не разобрался
		if(asn1::oid(object, oid) != asn1::error_t::NONE)
			// Выводим признак слабого хеша
			return true;
		// SHA-1 (1.3.14.3.2.26) слаб
		return (oid.compare("1.3.14.3.2.26") == 0);
	}
	/**
	 * @brief Функция разбора отличительного имени
	 *
	 * @param element элемент записи имени
	 * @param result  объект имени, в который производится разбор
	 * @return        причина отказа либо nts::x509::error_t::NONE
	 *
	 * @note Разборщик вынесен из сертификата: им же разбираются имена вида directoryName
	 *       в subjectAltName и в nameConstraints, и негодная запись там отвергается так
	 *       же строго, как и в поле subject
	 *
	 */
	static nts::x509::error_t distinguished(const asn1::element_t & element, name_t & result) noexcept {
		// Если запись имени имеет простой вид метки
		if(!element.constructed)
			// Выводим причину отказа
			return nts::x509::error_t::STRUCTURE;
		// Запоминаем запись имени целиком
		result.element = element.element;
		/**
		 * Выполняем перехват ошибок
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
					return nts::x509::error_t::ENCODING;
				// Если составляющая имени имеет простой вид метки
				if(!item.constructed)
					// Выводим причину отказа
					return nts::x509::error_t::STRUCTURE;
				// Создаём разборщик содержимого составляющей имени
				asn1::reader_t items(item.content);
				/**
				 * Составляющая имени без единого признака устройством имени запрещена:
				 * пустая составляющая ничего не обозначает, но участвует в сличении имён
				 */
				if(items.empty())
					// Выводим причину отказа
					return nts::x509::error_t::NAME;
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
						return nts::x509::error_t::ENCODING;
					// Если признак имеет простой вид метки
					if(!pair.constructed)
						// Выводим причину отказа
						return nts::x509::error_t::STRUCTURE;
					// Создаём разборщик содержимого признака
					asn1::reader_t fields(pair.content);
					// Объект разобранного поля признака
					asn1::element_t field;
					// Разбираемый признак имени
					attribute_t attribute;
					// Выполняем разбор опознавателя признака
					if(!fields.next(asn1::tag_t::OBJECT, field))
						// Выводим причину отказа
						return nts::x509::error_t::ENCODING;
					// Итог извлечения опознавателя признака
					const asn1::error_t named = asn1::oid(field, attribute.oid);
					// Если память под опознаватель признака выделить не удалось
					if(named == asn1::error_t::MEMORY)
						// Выводим отказ нехватки памяти
						return nts::x509::error_t::MEMORY;
					// Если извлечение опознавателя признака не удалось
					if(named != asn1::error_t::NONE)
						// Выводим причину отказа
						return nts::x509::error_t::NAME;
					// Выполняем разбор значения признака
					if(!fields.next(field))
						// Выводим причину отказа
						return nts::x509::error_t::ENCODING;
					// Если значение признака записано меткой не универсального класса
					if(field.cls != asn1::cls_t::UNIVERSAL)
						// Выводим причину отказа
						return nts::x509::error_t::NAME;
					// Запоминаем вид записи значения признака
					attribute.type = static_cast <asn1::tag_t> (field.tag);
					// Итог извлечения значения признака
					const asn1::error_t valued = asn1::text(field, attribute.type, attribute.value);
					// Если память под значение признака выделить не удалось
					if(valued == asn1::error_t::MEMORY)
						// Выводим отказ нехватки памяти
						return nts::x509::error_t::MEMORY;
					// Если извлечение значения признака не удалось
					if(valued != asn1::error_t::NONE)
						// Выводим причину отказа
						return nts::x509::error_t::NAME;
					// Если после значения признака остались лишние поля
					if(!fields.empty())
						// Выводим причину отказа
						return nts::x509::error_t::STRUCTURE;
					// Добавляем признак в набор признаков составляющей
					/**
					 * Раздел 4.1.2.4 RFC 5280 и X.501: признаки одной составляющей имени
					 * различны по виду, повтор вида - оплошность записи
					 */
					for(size_t i = 0; i < part.size(); i++){
						// Если признак такого вида в составляющей уже есть
						if(part[i].oid.compare(attribute.oid) == 0)
							// Выводим отказ повторного признака
							return nts::x509::error_t::DUPLICATE;
					}
					// Запоминаем признак в составляющей
					part.push_back(attribute);
				}
				// Добавляем составляющую в набор составляющих имени
				result.parts.push_back(part);
			}
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим причину отказа
			return nts::x509::error_t::MEMORY;
		}
		// Выводим успешность разбора
		return nts::x509::error_t::NONE;
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
		return nts::x509::error_t::STRUCTURE;
	// Создаём разборщик содержимого записи опознавателя алгоритма
	asn1::reader_t reader(element.content);
	// Объект разобранного элемента
	asn1::element_t item;
	// Выполняем разбор опознавателя алгоритма
	if(!reader.next(asn1::tag_t::OBJECT, item))
		// Выводим причину отказа
		return nts::x509::error_t::ENCODING;
	// Итог извлечения опознавателя алгоритма
	const asn1::error_t status = asn1::oid(item, oid);
	// Если память под опознаватель алгоритма выделить не удалось
	if(status == asn1::error_t::MEMORY)
		// Выводим отказ нехватки памяти
		return nts::x509::error_t::MEMORY;
	// Если извлечение опознавателя алгоритма не удалось
	if(status != asn1::error_t::NONE)
		// Выводим причину отказа
		return nts::x509::error_t::ENCODING;
	/**
	 * Настройки алгоритма отдаются записью как есть: устройство их задаётся самим
	 * алгоритмом, и разбирать их разборщику сертификата нечем
	 */
	if(!reader.empty()){
		// Выполняем разбор настроек алгоритма
		if(!reader.next(item))
			// Выводим причину отказа
			return nts::x509::error_t::ENCODING;
		// Запоминаем запись настроек алгоритма
		params = item.element;
		// Если после настроек алгоритма остались лишние поля
		if(!reader.empty())
			// Выводим причину отказа
			return nts::x509::error_t::STRUCTURE;
	}
	// Выводим успешность разбора
	return nts::x509::error_t::NONE;
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
	// Выводим итог разбора отличительного имени вынесенным разборщиком
	return distinguished(element, result);
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
	 * Выполняем перехват ошибок
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
			if(((*bounds[i] >= -631152000) && (*bounds[i] <= 2524607999)) != (type == asn1::tag_t::UTC_TIME))
				// Запоминаем причину отказа: раздел 4.1.2.5 RFC 5280 отводит UTCTime лишь годам 1950…2049, а время вне них - GeneralizedTime
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
	 * Выполняем перехват ошибок
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
	// Сбрасываем просмотр тела сертификата
	this->_body = view_t();
	// Сбрасываем просмотр серийного номера
	this->_serial = view_t();
	// Сбрасываем просмотр подписи
	this->_signature = view_t();
	// Сбрасываем просмотр опознавателя издателя
	this->_issuerUID = view_t();
	// Сбрасываем просмотр опознавателя владельца
	this->_subjectUID = view_t();
	// Сбрасываем просмотр параметров ключа
	this->_parameters = view_t();
	// Сбрасываем число неиспользуемых разрядов подписи
	this->_unused = 0;
	// Сбрасываем опознаватели алгоритма подписи
	this->_algorithm.clear();
	// Сбрасываем опознаватель подписи снаружи тела
	this->_outer.clear();
	// Сбрасываем имена издателя и владельца сертификата
	this->_issuer = name_t();
	// Сбрасываем имя владельца сертификата
	this->_subject = name_t();
	// Сбрасываем срок действия сертификата
	this->_before = 0;
	// Сбрасываем конец срока действия
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
 * @brief Метод получения записи настроек алгоритма подписи
 *
 * @return просмотр записи настроек (RSASSA-PSS-params у id-RSASSA-PSS) либо пустой просмотр
 *
 */
const view_t & nts::x509::Certificate::settings() const noexcept {
	// Выводим просмотр записи настроек алгоритма подписи
	return this->_parameters;
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
 * @param oid опознаватель разыскиваемого расширения
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
 * @brief Функция поиска признака имени по опознавателю
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
 * @brief Функция сборки записи имени в виде строки
 *
 * @param name   имя, запись которого собирается
 * @param result строка, в которую помещается результат
 * @return       причина отказа либо error_t::NONE
 *
 */
nts::x509::error_t nts::x509::text(const name_t & name, string & result) noexcept {
	/**
	 * Выполняем перехват ошибок
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
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим причину отказа
		return error_t::MEMORY;
	}
	// Выводим успешность сборки
	return error_t::NONE;
}

/**
 * @brief Функция извлечения основных ограничений сертификата
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
 * @brief Функция извлечения назначения открытого ключа
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
 * @brief Функция извлечения расширенного назначения открытого ключа
 *
 * @param extension расширение расширенного назначения ключа
 * @param result    набор опознавателей назначения ключа
 * @return          причина отказа либо error_t::NONE
 *
 */
nts::x509::error_t nts::x509::purpose(const extension_t & extension, vector <string> & result) noexcept {
	/**
	 * Выполняем перехват ошибок
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
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим причину отказа
		return error_t::MEMORY;
	}
	// Выводим успешность извлечения
	return error_t::NONE;
}

/**
 * @brief Функция извлечения дополнительных имён владельца
 *
 * @param extension расширение дополнительных имён
 * @param result    набор дополнительных имён
 * @return          причина отказа либо error_t::NONE
 *
 */
nts::x509::error_t nts::x509::alternatives(const extension_t & extension, vector <alternative_t> & result) noexcept {
	/**
	 * Выполняем перехват ошибок
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
					// Создаём разборщик содержимого явной обёртки [4]
					asn1::reader_t wrapped(entry.content);
					// Объект записи самого имени
					asn1::element_t inner;
					// Если запись имени внутри обёртки не прочиталась
					if(!wrapped.next(asn1::tag_t::SEQUENCE, inner))
						// Выводим причину отказа
						return error_t::ENCODING;
					// Если внутри обёртки лежит не одна запись либо имя не составное
					if(!wrapped.empty() || !inner.constructed)
						// Выводим причину отказа
						return error_t::STRUCTURE;
					// Разобранное имя: набор признаков наружу не выдаётся, важна лишь годность записи
					name_t parsed;
					// Итог разбора имени тем же разборщиком, что и у поля subject
					const error_t named = distinguished(inner, parsed);
					// Если имя не разобралось
					if(named != error_t::NONE)
						// Выводим причину отказа
						return named;
				} break;
				// Если записано имя иного вида
				default: alternative.kind = kind_t::OTHER;
			}
			// Добавляем дополнительное имя в набор дополнительных имён
			result.push_back(alternative);
		}
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим причину отказа
		return error_t::MEMORY;
	}
	// Выводим успешность извлечения
	return error_t::NONE;
}

/**
 * @brief Функция извлечения опознавателя ключа владельца
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
 * @brief Функция извлечения опознавателя ключа издателя
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
/**
 * @brief Функция проверки критичных расширений сертификата на известность
 *
 * @param certificate проверяемый сертификат
 * @return            признак того, что все критичные расширения известны библиотеке
 *
 */
bool nts::x509::recognized(const certificate_t & certificate) noexcept {
	// Известные расширения: subjectKeyIdentifier, keyUsage, subjectAltName, basicConstraints, authorityKeyIdentifier, extendedKeyUsage
	static const char * RECOGNIZED[] = {"2.5.29.14", "2.5.29.15", "2.5.29.17", "2.5.29.19", "2.5.29.30", "2.5.29.35", "2.5.29.37"};
	// Расширения сертификата
	const vector <extension_t> & extensions = certificate.extension();
	/**
	 * Выполняем перебор расширений сертификата
	 */
	for(size_t i = 0; i < extensions.size(); i++){
		// Если расширение не критично
		if(!extensions[i].critical)
			// Переходим к следующему
			continue;
		// Признак известности
		bool known = false;
		/**
		 * Выполняем перебор известных расширений
		 */
		for(size_t j = 0; !known && (j < (sizeof(RECOGNIZED) / sizeof(RECOGNIZED[0]))); j++)
			// Сличаем опознаватель
			known = (extensions[i].oid.compare(RECOGNIZED[j]) == 0);
		// Если расширение неизвестно
		if(!known)
			// Выводим отрицательный результат - расширение неизвестно
			return false;
	}
	// Сообщаем, что расширения знакомы
	return true;
}

/**
 * @brief Функция проверки стойкости алгоритма подписи
 *
 * @param algorithm  опознаватель алгоритма подписи
 * @param parameters запись настроек алгоритма подписи либо пустой просмотр
 * @return           признак слабой подписи: хеш MD2/MD4/MD5/SHA-1, у RSASSA-PSS - по настройкам (без них SHA-1)
 *
 */
bool nts::x509::weak(const string & algorithm, const view_t & parameters) noexcept {
	// Подписи с хешами MD2/MD4/MD5/SHA-1: RSA (RFC 3279, RFC 8017), ECDSA (RFC 3279), DSA
	static const char * const HASHES[] = {"1.2.840.113549.1.1.2", "1.2.840.113549.1.1.3", "1.2.840.113549.1.1.4", "1.2.840.113549.1.1.5", "1.3.14.3.2.29", "1.2.840.10045.4.1", "1.2.840.10040.4.3"};
	/**
	 * Выполняем перебор слабых алгоритмов
	 */
	for(size_t i = 0; i < (sizeof(HASHES) / sizeof(HASHES[0])); i++){
		// Если алгоритм подписи слаб
		if(algorithm.compare(HASHES[i]) == 0)
			// Выводим признак слабой подписи
			return true;
	}
	// Подпись RSASSA-PSS: хеш из настроек, без настроек - SHA-1 (раздел 3.1 RFC 4055)
	return ((algorithm.compare("1.2.840.113549.1.1.10") == 0) && pssweak(parameters));
}

/**
 * @brief Функция проверки стойкости открытого ключа
 *
 * @param key сведения об открытом ключе
 * @return    признак слабого ключа: RSA короче 2048 разрядов (SP 800-131A) либо не разбираемый
 *
 */
bool nts::x509::weak(const key_t & key) noexcept {
	// Если ключ RSA (rsaEncryption либо id-RSASSA-PSS)
	if((key.algorithm.compare("1.2.840.113549.1.1.1") == 0) || (key.algorithm.compare("1.2.840.113549.1.1.10") == 0)){
		// Объект RSA для разбора ключа
		sign::rsa_t rsa;
		// Слабость: ключ не разобрать либо короче 2048 разрядов
		return (!rsa.decode(key.key) || (rsa.bits() < 2048));
	}
	// Ключ стоек
	return false;
}

/**
 * @brief Функция проверки стойкости сертификата как звена доверия
 *
 * @param certificate проверяемый сертификат
 * @param anchor      признак якоря: самоподпись якоря не судится, ключ судится всегда
 * @return            признак слабого звена: подпись хешем MD5/SHA-1 либо ключ RSA короче 2048 разрядов
 *
 */
bool nts::x509::weak(const certificate_t & certificate, const bool anchor) noexcept {
	/**
	 * У якоря самоподпись не судится - она ни на что не влияет, а корни с самоподписью
	 * SHA-1 (DigiCert Global Root CA, GlobalSign R1) живы
	 */
	if(!anchor && weak(certificate.algorithms(), certificate.settings()))
		// Выводим признак слабого звена
		return true;
	// Выводим итог проверки стойкости ключа звена
	return weak(certificate.key());
}
/**
 * @brief Функция извлечения ограничений имён издателя
 *
 * @param extension расширение nameConstraints (2.5.29.30)
 * @param permitted дозволенные поддеревья имён
 * @param excluded  запрещённые поддеревья имён
 * @return          причина отказа либо error_t::NONE
 *
 */
nts::x509::error_t nts::x509::constraints(const extension_t & extension, vector <alternative_t> & permitted, vector <alternative_t> & excluded) noexcept {
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Сбрасываем перечни
		permitted.clear();
		// Сбрасываем перечень запрещённых поддеревьев
		excluded.clear();
		// Разборщик расширения
		asn1::reader_t reader(extension.value);
		// Элемент NameConstraints
		asn1::element_t item;
		// Если внешняя последовательность не прочиталась
		if(!reader.next(asn1::tag_t::SEQUENCE, item))
			// Выводим причину отказа
			return error_t::ENCODING;
		// Если за ней идут лишние байты либо она не составная
		if(!reader.empty() || !item.constructed)
			// Выводим причину отказа
			return error_t::STRUCTURE;
		// Разборщик поддеревьев
		asn1::reader_t parts(item.content);
		/**
		 * Выполняем перебор частей: [0] permittedSubtrees, [1] excludedSubtrees
		 */
		while(!parts.empty()){
			// Часть
			asn1::element_t part;
			// Если часть не прочиталась
			if(!parts.next(part))
				// Выводим причину отказа
				return error_t::ENCODING;
			// Если часть не помечена контекстом [0] либо [1] либо не составная
			if((part.cls != asn1::cls_t::CONTEXT) || ((part.tag != 0) && (part.tag != 1)) || !part.constructed)
				// Выводим причину отказа
				return error_t::STRUCTURE;
			// Перечень, в который ложатся поддеревья
			vector <alternative_t> & result = ((part.tag == 0) ? permitted : excluded);
			// Разборщик поддеревьев части
			asn1::reader_t trees(part.content);
			// Раздел 4.2.1.10 RFC 5280: перечень поддеревьев непуст
			if(trees.empty())
				// Выводим причину отказа
				return error_t::EXTENSION;
			/**
			 * Выполняем перебор поддеревьев GeneralSubtree
			 */
			while(!trees.empty()){
				// Поддерево
				asn1::element_t tree;
				// Если поддерево не прочиталось
				if(!trees.next(asn1::tag_t::SEQUENCE, tree))
					// Выводим причину отказа
					return error_t::ENCODING;
				// Если поддерево не составное
				if(!tree.constructed)
					// Выводим причину отказа
					return error_t::STRUCTURE;
				// Разборщик поддерева
				asn1::reader_t fields(tree.content);
				// Основание поддерева
				asn1::element_t base;
				// Если основание не прочиталось
				if(!fields.next(base))
					// Выводим причину отказа
					return error_t::ENCODING;
				// Если основание не помечено контекстом
				if(base.cls != asn1::cls_t::CONTEXT)
					// Выводим причину отказа
					return error_t::STRUCTURE;
				// Раздел 4.2.1.10 RFC 5280: minimum и maximum не выпускаются - поддерево с ними не разбирается
				if(!fields.empty())
					// Выводим причину отказа
					return error_t::EXTENSION;
				// Имя поддерева
				alternative_t alternative;
				// Запись имени целиком
				alternative.element = base.element;
				/**
				 * Выполняем определение вида имени
				 */
				switch(base.tag){
					// Адрес почты, доменное имя, указатель ресурса
					case 1: case 2: case 6: {
						// Вид имени
						alternative.kind = ((base.tag == 1) ? kind_t::EMAIL : ((base.tag == 2) ? kind_t::DNS : kind_t::URI));
						// Отказ разбора текста
						const asn1::error_t status = asn1::text(base, asn1::tag_t::IA5_STRING, alternative.value);
						// Если памяти не хватило
						if(status == asn1::error_t::MEMORY)
							// Выводим причину отказа
							return error_t::MEMORY;
						// Если текст не разобрался
						if(status != asn1::error_t::NONE)
							// Выводим причину отказа
							return error_t::EXTENSION;
					} break;
					// Адрес сети с маской: 8 либо 32 байта
					case 7: {
						// Вид имени
						alternative.kind = kind_t::ADDRESS;
						// Если запись составная либо длина не адрес с маской
						if(base.constructed || ((base.content.size != 8) && (base.content.size != 32)))
							// Выводим причину отказа
							return error_t::EXTENSION;
						// Переносим адрес с маской
						alternative.value.assign(reinterpret_cast <const char *> (base.content.data), base.content.size);
					} break;
					// Отличительное имя
					case 4: {
						// Вид имени
						alternative.kind = kind_t::DIRECTORY;
						// Если запись не составная
						if(!base.constructed)
							// Выводим причину отказа
							return error_t::STRUCTURE;
						// Разборщик содержимого явной обёртки [4]
						asn1::reader_t wrapped(base.content);
						// Запись самого имени
						asn1::element_t inner;
						// Если запись имени внутри обёртки не прочиталась
						if(!wrapped.next(asn1::tag_t::SEQUENCE, inner))
							// Выводим причину отказа
							return error_t::ENCODING;
						// Если внутри обёртки не одна запись либо имя не составное
						if(!wrapped.empty() || !inner.constructed)
							// Выводим причину отказа
							return error_t::STRUCTURE;
						// Разобранное имя: важна лишь годность записи
						name_t parsed;
						// Итог разбора имени тем же разборщиком, что и у поля subject
						const error_t named = distinguished(inner, parsed);
						// Если имя не разобралось
						if(named != error_t::NONE)
							// Выводим причину отказа
							return named;
					} break;
					// Иное имя
					default: alternative.kind = kind_t::OTHER;
				}
				// Добавляем поддерево
				result.push_back(alternative);
			}
		}
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Выводим причину отказа
		return error_t::MEMORY;
	}
	// Сообщаем об успешной проверке
	return error_t::NONE;
}

/**
 * @brief Конструктор
 *
 */
nts::x509::Attribute::Attribute() noexcept : type(asn1::tag_t::UTF8_STRING) {}

/**
 * @brief Конструктор
 *
 */
nts::x509::Alternative::Alternative() noexcept : kind(kind_t::OTHER) {}

/**
 * @brief Конструктор
 *
 */
nts::x509::Extension::Extension() noexcept : critical(false) {}

/**
 * @brief Конструктор
 *
 */
nts::x509::Key::Key() noexcept : unused(0) {}

/**
 * @brief Деструктор
 *
 */
nts::x509::Certificate::~Certificate() noexcept {}
