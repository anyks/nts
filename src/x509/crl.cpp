/**
 * @file crl.cpp
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
 * @brief Исходный файл модуля списков отзыва сертификатов —
 *        разбор CertificateList по разделу 5 RFC 5280
 *
 * @note Запись подписи у списка та же, что и у сертификата: подписываемая
 *       часть, опознаватель алгоритма и строка битов подписи. Проверка
 *       подписи переупотребляет модуль проверки подписи сертификата.
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <new>
#include <string>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <x509/crl.hpp>
#include <x509/signature.hpp>
#include <asn1/asn1.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * Служебные объекты модуля списков отзыва сертификатов
 */
namespace {
	/**
	 * Подписываемся на пространство имён проекта
	 */
	using namespace nts;
	/**
	 * Подписываемся на пространство имён модуля сертификатов
	 */
	using namespace nts::x509;

	/**
	 * @brief Функция перевода отказа разборщика ASN.1 в отказ модуля
	 *
	 * @param error отказ разборщика ASN.1
	 * @return      отказ модуля
	 *
	 */
	static nts::x509::error_t translate(const asn1::error_t error) noexcept {
		// Выводим отказ модуля: нехватка памяти отдаётся своим отказом, всё прочее - отказом устройства
		return ((error == asn1::error_t::MEMORY) ? nts::x509::error_t::MEMORY : nts::x509::error_t::STRUCTURE);
	}
	/**
	 * @brief Функция разбора опознавателя объекта
	 *
	 * @param element разбираемый элемент
	 * @param result  место, в которое помещается опознаватель
	 * @return        отказ разбора опознавателя
	 *
	 */
	static nts::x509::error_t oidOf(const asn1::element_t & element, string & result) noexcept {
		// Итог разбора опознавателя
		const asn1::error_t outcome = asn1::oid(element, result);
		// Выводим переведённый отказ разбора, если он есть
		return ((outcome == asn1::error_t::NONE) ? nts::x509::error_t::NONE : translate(outcome));
	}
	/**
	 * @brief Функция разбора малого целого числа
	 *
	 * @param element разбираемый элемент
	 * @param result  место, в которое помещается число
	 * @return        отказ разбора числа
	 *
	 */
	static nts::x509::error_t smallInteger(const asn1::element_t & element, int64_t & result) noexcept {
		// Итог разбора целого числа
		const asn1::error_t outcome = asn1::integer(element, result);
		// Выводим переведённый отказ разбора, если он есть
		return ((outcome == asn1::error_t::NONE) ? nts::x509::error_t::NONE : translate(outcome));
	}
	/**
	 * @brief Функция разбора записи опознавателя алгоритма
	 *
	 * @param reader  разборщик, из которого читается запись
	 * @param oid     место, в которое помещается опознаватель алгоритма
	 * @param params  место, в которое помещается запись настроек алгоритма
	 * @param present место, в которое помещается признак наличия настроек
	 * @return        отказ разбора записи
	 *
	 */
	static nts::x509::error_t algorithmIdentifier(asn1::reader_t & reader, string & oid, asn1::element_t & params, bool & present) noexcept {
		// Сбрасываем признак наличия настроек
		present = false;
		// Набор алгоритма
		asn1::element_t element;
		// Если набор алгоритма разобрать не удалось
		if(!reader.next(asn1::tag_t::SEQUENCE, element) || !element.constructed)
			// Выводим переведённый отказ разбора
			return translate(reader.err());
		// Разборщик содержимого набора алгоритма
		asn1::reader_t items = reader.enter(element);
		// Если опознаватель алгоритма разобрать не удалось
		if(!items.next(asn1::tag_t::OBJECT, element))
			// Выводим переведённый отказ разбора
			return translate(items.err());
		// Итог разбора опознавателя алгоритма
		const nts::x509::error_t outcome = oidOf(element, oid);
		// Если опознаватель алгоритма разобрать не удалось
		if(outcome != nts::x509::error_t::NONE)
			// Выводим отказ разбора
			return outcome;
		// Если настройки алгоритма записаны
		if(!items.empty()){
			// Если настройки алгоритма разобрать не удалось
			if(!items.next(params))
				// Выводим переведённый отказ разбора
				return translate(items.err());
			// Устанавливаем признак наличия настроек
			present = true;
			// Если после настроек остался хвост
			if(!items.empty())
				// Выводим отказ устройства записи
				return nts::x509::error_t::STRUCTURE;
		}
		// Выводим успешность разбора опознавателя алгоритма
		return nts::x509::error_t::NONE;
	}
	/**
	 * @brief Функция разбора отличительного имени
	 *
	 * @param element разбираемый элемент записи имени
	 * @param result  объект имени, в который производится разбор
	 * @return        причина отказа либо nts::x509::error_t::NONE
	 *
	 * @note Разборщик повторяет разборщик имени сертификата: список несёт имя
	 *       издателя по тем же правилам X.501, и негодная запись отвергается так же строго
	 *
	 */
	static nts::x509::error_t distinguished(const asn1::element_t & element, nts::x509::name_t & result) noexcept {
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
				// Разбор составляющей имени
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
				vector <nts::x509::attribute_t> part;
				/**
				 * Выполняем обход признаков составляющей имени
				 */
				while(!items.empty()){
					// Объект разобранного признака
					asn1::element_t pair;
					// Разбор признака
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
					nts::x509::attribute_t attribute;
					// Разбор опознавателя признака
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
					// Разбор значения признака
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
					// Добавляем признак в набор признаков составляющей
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
	/**
	 * @brief Функция разбора записи времени
	 *
	 * @param element разбираемый элемент записи времени
	 * @param result  место, в которое помещается время в секундах от начала эпохи
	 * @return        причина отказа либо nts::x509::error_t::NONE
	 *
	 * @note Правило записи времени то же, что у срока действия сертификата:
	 *       раздел 4.1.2.5 RFC 5280 отводит UTCTime лишь годам 1950…2049
	 *
	 */
	static nts::x509::error_t moment(const asn1::element_t & element, int64_t & result) noexcept {
		// Если время записано меткой не универсального класса
		if(element.cls != asn1::cls_t::UNIVERSAL)
			// Выводим причину отказа
			return nts::x509::error_t::VALIDITY;
		// Определяем вид записи времени
		const asn1::tag_t type = static_cast <asn1::tag_t> (element.tag);
		// Если вид записи времени не отвечает устройству записи
		if((type != asn1::tag_t::UTC_TIME) && (type != asn1::tag_t::GENERALIZED_TIME))
			// Выводим причину отказа
			return nts::x509::error_t::VALIDITY;
		// Извлечение времени
		if(asn1::time(element, type, result) != asn1::error_t::NONE)
			// Выводим причину отказа
			return nts::x509::error_t::VALIDITY;
		/**
		 * Правило RFC 5280 разделяет два вида записи времени по 2049 году: до него
		 * время записывается двузначным годом, начиная с 2050 - четырёхзначным.
		 * Правило это снимает у записи двоякость, и нарушение его означает запись,
		 * которую разные разборщики прочтут по-разному
		 */
		if(((result >= -631152000) && (result <= 2524607999)) != (type == asn1::tag_t::UTC_TIME))
			// Выводим причину отказа
			return nts::x509::error_t::VALIDITY;
		// Выводим успешность разбора
		return nts::x509::error_t::NONE;
	}
	/**
	 * @brief Функция разбора набора расширений
	 *
	 * @param element разбираемый элемент набора расширений (SEQUENCE OF Extension)
	 * @param result  место, в которое помещается набор расширений
	 * @return        причина отказа либо nts::x509::error_t::NONE
	 *
	 */
	static nts::x509::error_t extensions(const asn1::element_t & element, vector <nts::x509::extension_t> & result) noexcept {
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Если запись набора расширений имеет простой вид метки
			if(!element.constructed)
				// Выводим причину отказа
				return nts::x509::error_t::STRUCTURE;
			// Создаём разборщик содержимого набора расширений
			asn1::reader_t items(element.content);
			/**
			 * Пустой набор расширений устройством записи запрещён: поле это
			 * необязательное, и отсутствие расширений записывается его отсутствием
			 */
			if(items.empty())
				// Выводим причину отказа
				return nts::x509::error_t::EXTENSION;
			/**
			 * Выполняем обход расширений набора
			 */
			while(!items.empty()){
				// Объект разобранного расширения
				asn1::element_t entry;
				// Разбор расширения
				if(!items.next(asn1::tag_t::SEQUENCE, entry))
					// Выводим причину отказа
					return nts::x509::error_t::ENCODING;
				// Если запись расширения имеет простой вид метки
				if(!entry.constructed)
					// Выводим причину отказа
					return nts::x509::error_t::STRUCTURE;
				// Создаём разборщик содержимого записи расширения
				asn1::reader_t fields(entry.content);
				// Объект разобранного поля расширения
				asn1::element_t field;
				// Разбираемое расширение
				nts::x509::extension_t extension;
				// Разбор опознавателя расширения
				if(!fields.next(asn1::tag_t::OBJECT, field))
					// Выводим причину отказа
					return nts::x509::error_t::ENCODING;
				// Итог извлечения опознавателя расширения
				const nts::x509::error_t status = oidOf(field, extension.oid);
				// Если извлечение опознавателя расширения не удалось
				if(status != nts::x509::error_t::NONE)
					// Выводим причину отказа
					return status;
				// Разбор следующего поля расширения
				if(!fields.next(field))
					// Выводим причину отказа
					return nts::x509::error_t::ENCODING;
				// Если признак обязательности расширения записан явно
				if((field.cls == asn1::cls_t::UNIVERSAL) && (field.tag == static_cast <uint32_t> (asn1::tag_t::BOOLEAN))){
					// Извлечение признака обязательности расширения
					if(asn1::boolean(field, extension.critical) != asn1::error_t::NONE)
						// Выводим причину отказа
						return nts::x509::error_t::EXTENSION;
					/**
					 * Необязательность расширения записывается отсутствием поля:
					 * кодировка DER значение по умолчанию не записывает вовсе
					 */
					if(!extension.critical)
						// Выводим причину отказа
						return nts::x509::error_t::EXTENSION;
					// Разбор следующего поля расширения
					if(!fields.next(field))
						// Выводим причину отказа
						return nts::x509::error_t::ENCODING;
				}
				// Если содержимое расширения записано не строкой байтов
				if((field.cls != asn1::cls_t::UNIVERSAL) || field.constructed || (field.tag != static_cast <uint32_t> (asn1::tag_t::OCTET_STRING)))
					// Выводим причину отказа
					return nts::x509::error_t::STRUCTURE;
				// Запоминаем содержимое расширения
				extension.value = field.content;
				// Если после содержимого расширения остались лишние поля
				if(!fields.empty())
					// Выводим причину отказа
					return nts::x509::error_t::STRUCTURE;
				/**
				 * Выполняем обход разобранных расширений
				 */
				for(size_t i = 0; i < result.size(); i++){
					/**
					 * Повторное расширение запрещено RFC 5280: два расширения одного
					 * опознавателя дают два разных ответа на один вопрос, и выбор
					 * между ними у разных разборщиков расходится
					 */
					if(result[i].oid.compare(extension.oid) == 0)
						// Выводим причину отказа
						return nts::x509::error_t::DUPLICATE;
				}
				// Добавляем расширение в набор расширений
				result.push_back(extension);
			}
			// Выводим успешность разбора
			return nts::x509::error_t::NONE;
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Выводим отказ нехватки памяти
			return nts::x509::error_t::MEMORY;
		}
	}
};

/**
 * @brief Метод разбора записи списка отзыва
 *
 * @param data просмотр разбираемой записи списка
 * @return     причина отказа либо error_t::NONE
 *
 */
nts::x509::error_t nts::x509::Revocations::parse(const view_t & data) noexcept {
	// Очистка разобранных сведений
	this->clear();
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Создаём разборщик записи списка
		asn1::reader_t reader(data);
		// Объект разобранной записи списка
		asn1::element_t list;
		// Разбор записи списка
		if(!reader.next(asn1::tag_t::SEQUENCE, list))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Если после записи остались лишние байты либо запись не составная
		if(!reader.empty() || !list.constructed)
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Запоминаем запись списка целиком
		this->_element = list.element;
		// Создаём разборщик содержимого записи списка
		asn1::reader_t top(list.content);
		// Объект разобранной подписываемой части списка
		asn1::element_t body;
		// Разбор подписываемой части списка
		if(!top.next(asn1::tag_t::SEQUENCE, body))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Если подписываемая часть не составная
		if(!body.constructed)
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Запоминаем подписываемую часть списка
		this->_body = body.element;
		// Объект разобранного элемента
		asn1::element_t item;
		// Просмотр записи настроек алгоритма подписи
		asn1::element_t params;
		// Признак наличия настроек алгоритма подписи
		bool present = false;
		// Извлечение опознавателя алгоритма подписи
		this->_error = algorithmIdentifier(top, this->_algorithm, params, present);
		// Если извлечение опознавателя алгоритма подписи не удалось
		if(this->_error != error_t::NONE)
			// Выводим причину отказа
			return this->_error;
		// Запоминаем запись настроек алгоритма подписи
		if(present)
			// Запоминаем элемент настроек
			this->_parameters = params.element;
		// Разбор подписи списка
		if(!top.next(asn1::tag_t::BIT_STRING, item))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Извлечение подписи списка
		if(asn1::bits(item, this->_signature, this->_unused) != asn1::error_t::NONE)
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Если после подписи остались лишние поля
		if(!top.empty())
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		// Создаём разборщик содержимого подписываемой части списка
		asn1::reader_t inner(body.content);
		// Объект разобранного поля подписываемой части
		asn1::element_t field;
		// Разбор первого поля подписываемой части
		if(!inner.next(field))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		/**
		 * Издание списка записано целым числом и идёт первым полем: второе издание
		 * (значение 1) обязано быть записано у списка с расширениями, первое издание
		 * записывается отсутствием поля - тогда первым полем идёт набор алгоритма
		 */
		if((field.cls == asn1::cls_t::UNIVERSAL) && (field.tag == static_cast <uint32_t> (asn1::tag_t::INTEGER))){
			// Издание списка
			int64_t version = -1;
			// Извлечение издания списка
			if(smallInteger(field, version) != error_t::NONE)
				// Запоминаем причину отказа
				return (this->_error = error_t::STRUCTURE);
			// Если издание списка не второе: раздел 5.1.2.1 RFC 5280
			if(version != 1)
				// Запоминаем причину отказа
				return (this->_error = error_t::VERSION);
			// Разбор набора алгоритма подписи подписываемой части
			if(!inner.next(asn1::tag_t::SEQUENCE, field))
				// Запоминаем причину отказа
				return (this->_error = error_t::ENCODING);
		}
		// Если набор алгоритма подписи подписываемой части не составной
		if(!field.constructed || (field.cls != asn1::cls_t::UNIVERSAL) || (field.tag != static_cast <uint32_t> (asn1::tag_t::SEQUENCE)))
			// Запоминаем причину отказа
			return (this->_error = error_t::STRUCTURE);
		{
			// Создаём разборщик содержимого набора алгоритма подписи
			asn1::reader_t items(field.content);
			// Объект разобранного опознавателя алгоритма
			asn1::element_t oidField;
			// Разбор опознавателя алгоритма подписи подписываемой части
			if(!items.next(asn1::tag_t::OBJECT, oidField))
				// Запоминаем причину отказа
				return (this->_error = error_t::ENCODING);
			// Опознаватель алгоритма подписи подписываемой части
			string innerAlgorithm;
			// Извлечение опознавателя алгоритма подписи подписываемой части
			if(oidOf(oidField, innerAlgorithm) != error_t::NONE)
				// Запоминаем причину отказа
				return (this->_error = error_t::STRUCTURE);
			/**
			 * Раздел 5.1.1.2 RFC 5280: опознаватель алгоритма подписи внутри
			 * подписываемой части обязан совпадать с наружным
			 */
			if(innerAlgorithm.compare(this->_algorithm) != 0)
				// Запоминаем причину отказа
				return (this->_error = error_t::STRUCTURE);
		}
		// Разбор имени издателя списка
		if(!inner.next(asn1::tag_t::SEQUENCE, field))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Извлечение имени издателя списка
		this->_error = distinguished(field, this->_issuer);
		// Если извлечение имени издателя не удалось
		if(this->_error != error_t::NONE)
			// Выводим причину отказа
			return this->_error;
		// Разбор даты выдачи списка
		if(!inner.next(field))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		// Извлечение даты выдачи списка
		if(moment(field, this->_thisUpdate) != error_t::NONE)
			// Запоминаем причину отказа
			return (this->_error = error_t::VALIDITY);
		// Если подписываемая часть исчерпана
		if(inner.empty())
			// Выводим успешность разбора: дата следующего списка и всё за ней необязательны
			return error_t::NONE;
		// Разбор следующего поля подписываемой части
		if(!inner.next(field))
			// Запоминаем причину отказа
			return (this->_error = error_t::ENCODING);
		/**
		 * Дата следующего списка необязательна и записывается меткой времени:
		 * за датой выдачи может идти дата следующего списка, набор отозванных
		 * сертификатов либо расширения списка
		 */
		if((field.cls == asn1::cls_t::UNIVERSAL) && ((field.tag == static_cast <uint32_t> (asn1::tag_t::UTC_TIME)) || (field.tag == static_cast <uint32_t> (asn1::tag_t::GENERALIZED_TIME)))){
			// Извлечение даты следующего списка
			if(moment(field, this->_nextUpdate) != error_t::NONE)
				// Запоминаем причину отказа
				return (this->_error = error_t::VALIDITY);
			// Если подписываемая часть исчерпана
			if(inner.empty())
				// Выводим успешность разбора
				return error_t::NONE;
			// Разбор следующего поля подписываемой части
			if(!inner.next(field))
				// Запоминаем причину отказа
				return (this->_error = error_t::ENCODING);
		}
		/**
		 * Набор отозванных сертификатов необязателен и записывается набором:
		 * за датами может идти набор отозванных сертификатов либо расширения списка
		 */
		if((field.cls == asn1::cls_t::UNIVERSAL) && (field.tag == static_cast <uint32_t> (asn1::tag_t::SEQUENCE))){
			// Если набор отозванных сертификатов не составной
			if(!field.constructed)
				// Запоминаем причину отказа
				return (this->_error = error_t::STRUCTURE);
			// Создаём разборщик содержимого набора отозванных сертификатов
			asn1::reader_t entries(field.content);
			/**
			 * Выполняем обход записей отозванных сертификатов
			 */
			while(!entries.empty()){
				// Объект разобранной записи отзыва
				asn1::element_t entry;
				// Разбор записи отзыва
				if(!entries.next(asn1::tag_t::SEQUENCE, entry))
					// Запоминаем причину отказа
					return (this->_error = error_t::ENCODING);
				// Если запись отзыва не составная
				if(!entry.constructed)
					// Запоминаем причину отказа
					return (this->_error = error_t::STRUCTURE);
				// Создаём разборщик содержимого записи отзыва
				asn1::reader_t fields(entry.content);
				// Объект разобранного поля записи отзыва
				asn1::element_t entryField;
				// Разбираемая запись отозванного сертификата
				revoked_t revoked;
				// Разбор порядкового номера отозванного сертификата
				if(!fields.next(asn1::tag_t::INTEGER, entryField))
					// Запоминаем причину отказа
					return (this->_error = error_t::ENCODING);
				/**
				 * Порядковый номер сертификата - целое число до двадцати байтов:
				 * раздел 4.1.2.2 RFC 5280
				 */
				if((entryField.content.size == 0) || (entryField.content.size > 20))
					// Запоминаем причину отказа
					return (this->_error = error_t::SERIAL);
				// Запоминаем порядковый номер отозванного сертификата
				revoked.serial = entryField.content;
				// Разбор даты отзыва
				if(!fields.next(entryField))
					// Запоминаем причину отказа
					return (this->_error = error_t::ENCODING);
				// Извлечение даты отзыва
				if(moment(entryField, revoked.date) != error_t::NONE)
					// Запоминаем причину отказа
					return (this->_error = error_t::VALIDITY);
				// Если запись отзыва не исчерпана
				if(!fields.empty()){
					// Разбор набора расширений записи отзыва
					if(!fields.next(asn1::tag_t::SEQUENCE, entryField))
						// Запоминаем причину отказа
						return (this->_error = error_t::ENCODING);
					// Извлечение набора расширений записи отзыва
					this->_error = extensions(entryField, revoked.extensions);
					// Если извлечение расширений записи отзыва не удалось
					if(this->_error != error_t::NONE)
						// Выводим причину отказа
						return this->_error;
					// Если после расширений записи отзыва остались лишние поля
					if(!fields.empty())
						// Запоминаем причину отказа
						return (this->_error = error_t::STRUCTURE);
				}
				// Добавляем запись в набор записей отозванных сертификатов
				this->_revoked.push_back(revoked);
			}
			// Если подписываемая часть исчерпана
			if(inner.empty())
				// Выводим успешность разбора
				return error_t::NONE;
			// Разбор следующего поля подписываемой части
			if(!inner.next(field))
				// Запоминаем причину отказа
				return (this->_error = error_t::ENCODING);
		}
		/**
		 * Расширения списка необязательны и записываются явным [0]: раздел 5.1.2.7
		 * RFC 5280. Поле это последнее в подписываемой части
		 */
		if((field.cls == asn1::cls_t::CONTEXT) && (field.tag == 0)){
			// Если запись расширений списка не составная
			if(!field.constructed)
				// Запоминаем причину отказа
				return (this->_error = error_t::STRUCTURE);
			// Создаём разборщик содержимого записи расширений списка
			asn1::reader_t outside(field.content);
			// Объект разобранного набора расширений
			asn1::element_t items;
			// Разбор набора расширений
			if(!outside.next(asn1::tag_t::SEQUENCE, items))
				// Запоминаем причину отказа
				return (this->_error = error_t::ENCODING);
			// Если после набора расширений остались лишние поля
			if(!outside.empty())
				// Запоминаем причину отказа
				return (this->_error = error_t::STRUCTURE);
			// Извлечение набора расширений списка
			this->_error = extensions(items, this->_extensions);
			// Если извлечение расширений списка не удалось
			if(this->_error != error_t::NONE)
				// Выводим причину отказа
				return this->_error;
			// Если после расширений списка остались лишние поля
			if(!inner.empty())
				// Запоминаем причину отказа
				return (this->_error = error_t::STRUCTURE);
			// Выводим успешность разбора
			return error_t::NONE;
		}
		// Запоминаем причину отказа: поле не отвечает устройству подписываемой части
		return (this->_error = error_t::STRUCTURE);
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &) {
		// Запоминаем причину отказа
		return (this->_error = error_t::MEMORY);
	}
}

/**
 * @brief Метод очистки разобранных сведений
 *
 */
void nts::x509::Revocations::clear() noexcept {
	// Сбрасываем причину последнего отказа
	this->_error = error_t::NONE;
	// Сбрасываем просмотры записи списка
	this->_element = view_t();
	// Сбрасываем просмотр подписываемой части списка
	this->_body = view_t();
	// Сбрасываем запись подписи
	this->_signature = view_t();
	// Сбрасываем число неиспользованных разрядов подписи
	this->_unused = 0;
	// Сбрасываем алгоритм подписи
	this->_algorithm.clear();
	// Сбрасываем просмотр настроек алгоритма подписи
	this->_parameters = view_t();
	// Сбрасываем имя издателя
	this->_issuer.element = view_t();
	// Сбрасываем разобранные части имени издателя
	this->_issuer.parts.clear();
	// Сбрасываем даты списка
	this->_thisUpdate = 0;
	// Сбрасываем дату следующего обновления списка
	this->_nextUpdate = 0;
	// Сбрасываем наборы записей отзывов и расширений
	this->_revoked.clear();
	// Сбрасываем набор записей расширений
	this->_extensions.clear();
}

/**
 * @brief Метод извлечения причины последнего отказа
 *
 * @return причина последнего отказа
 *
 */
nts::x509::error_t nts::x509::Revocations::err() const noexcept {
	// Выводим причину последнего отказа
	return this->_error;
}

/**
 * @brief Метод извлечения подписываемой части списка
 *
 * @return просмотр подписываемой части списка
 *
 */
const nts::view_t & nts::x509::Revocations::body() const noexcept {
	// Выводим просмотр подписываемой части списка
	return this->_body;
}

/**
 * @brief Метод извлечения подписи списка
 *
 * @param unused число неиспользуемых разрядов последнего байта подписи
 * @return       просмотр записи подписи
 *
 */
const nts::view_t & nts::x509::Revocations::sign(uint8_t & unused) const noexcept {
	// Выводим число неиспользуемых разрядов последнего байта подписи
	unused = this->_unused;
	// Выводим просмотр записи подписи
	return this->_signature;
}

/**
 * @brief Метод извлечения опознавателя алгоритма подписи
 *
 * @return опознаватель алгоритма подписи
 *
 */
const std::string & nts::x509::Revocations::algorithms() const noexcept {
	// Выводим опознаватель алгоритма подписи
	return this->_algorithm;
}

/**
 * @brief Метод получения записи настроек алгоритма подписи
 *
 * @return просмотр записи настроек либо пустой просмотр
 *
 */
const nts::view_t & nts::x509::Revocations::settings() const noexcept {
	// Выводим просмотр записи настроек алгоритма подписи
	return this->_parameters;
}

/**
 * @brief Метод извлечения имени издателя списка
 *
 * @return имя издателя списка
 *
 */
const nts::x509::name_t & nts::x509::Revocations::issuers() const noexcept {
	// Выводим имя издателя списка
	return this->_issuer;
}

/**
 * @brief Метод извлечения дат списка
 *
 * @param thisUpdate дата выдачи списка в секундах от начала эпохи
 * @param nextUpdate дата следующего списка в секундах от начала эпохи, ноль при её отсутствии
 *
 */
void nts::x509::Revocations::updates(int64_t & thisUpdate, int64_t & nextUpdate) const noexcept {
	// Выводим дату выдачи списка
	thisUpdate = this->_thisUpdate;
	// Выводим дату следующего списка
	nextUpdate = this->_nextUpdate;
}

/**
 * @brief Метод извлечения набора записей отозванных сертификатов
 *
 * @return набор записей отозванных сертификатов
 *
 */
const std::vector <nts::x509::revoked_t> & nts::x509::Revocations::revoked() const noexcept {
	// Выводим набор записей отозванных сертификатов
	return this->_revoked;
}

/**
 * @brief Метод извлечения набора расширений списка
 *
 * @return набор расширений списка
 * @param oid опознаватель разыскиваемого расширения
 *
 */
const std::vector <nts::x509::extension_t> & nts::x509::Revocations::extension() const noexcept {
	// Выводим набор расширений списка
	return this->_extensions;
}

/**
 * @brief Метод розыска расширения списка по опознавателю
 *
 * @param oid опознаватель разыскиваемого расширения
 * @return    расширение списка либо nullptr
 *
 */
const nts::x509::extension_t * nts::x509::Revocations::extension(const string & oid) const noexcept {
	/**
	 * Выполняем обход расширений списка
	 */
	for(size_t i = 0; i < this->_extensions.size(); i++){
		// Если расширение найдено
		if(this->_extensions[i].oid.compare(oid) == 0)
			// Выводим найденное расширение
			return &this->_extensions[i];
	}
	// Расширение не найдено
	return nullptr;
}

/**
 * @brief Конструктор списка отзыва
 *
 */
nts::x509::Revocations::Revocations() noexcept : _error(error_t::NONE), _unused(0), _thisUpdate(0), _nextUpdate(0) {}

/**
 * @brief Функция проверки подписи списка отзыва
 *
 * @param crl список, подпись которого проверяется
 * @param key сведения об открытом ключе издателя списка
 * @return    отказ проверки: NONE - подпись сошлась, SIGNATURE - не сошлась либо
 *            непригодна, KEY - ключ чужого алгоритма, MEMORY - памяти не хватило
 *
 *            непригодна, KEY - ключ чужого алгоритма, MEMORY - памяти не хватило
 *
 */
nts::x509::error_t nts::x509::verify(const crl_t & crl, const nts::x509::key_t & key) noexcept {
	// Число неиспользуемых разрядов последнего байта подписи
	uint8_t unused = 0;
	// Получаем подпись проверяемого списка
	const view_t & signature = crl.sign(unused);
	/**
	 * Подпись строкой битов обязана нести целое число байтов: неиспользуемые
	 * разряды последнего байта - украшение записи, у подписи их нет
	 */
	if(unused != 0)
		// Выводим отказ подписи
		return error_t::SIGNATURE;
	// Выводим итог проверки подписи списка вынесенной проверкой
	return nts::x509::verify(crl.body(), signature, crl.algorithms(), crl.settings(), key);
}

/**
 * @brief Конструктор
 *
 */
nts::x509::Revoked::Revoked() noexcept : date(0) {}

/**
 * @brief Деструктор
 *
 */
nts::x509::Revocations::~Revocations() noexcept {}
