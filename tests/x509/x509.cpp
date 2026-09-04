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
 * @brief Исходный файл проверок модуля сертификатов X.509
 *
 * @note Записи сертификатов собираются здесь же записчиком модуля ASN.1, а не берутся
 *       готовыми: проверка неверной записи требует записи, которую ни один выдающий
 *       сертификаты не выдаст, и собрать её можно только самому
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <starve.hpp>
#include <vector>
#include <x509/x509.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * @brief Набор изъянов, вносимых в собираемую запись сертификата
 *
 */
typedef struct Defect {
	// Издание сертификата записано значением по умолчанию
	bool version;
	// Издание сертификата не записано вовсе, а расширения записаны
	bool release;
	// Необязательность расширения записана значением по умолчанию
	bool critical;
	// Расширение записано дважды
	bool duplicate;
	// Срок действия записан четырёхзначным годом до 2050 года
	bool generalized;
	// После записи сертификата записаны лишние байты
	bool trailing;
	// Необязательные поля записаны с нарушением порядка
	bool order;
	// Запись издания сертификата несёт лишнее поле сверх самого издания
	bool crowded;
	// Содержимое расширения записано составной строкой байтов
	bool enclosed;
	// Граница срока действия записана не меткой времени
	bool untimed;
	// Содержимое расширения записано не строкой байтов
	bool numeric;
	// Основные ограничения открываются полем не универсального класса
	bool foreign;
	// Признак пустого набора расширений: поле необязательное, и пустым ему быть нельзя
	bool vacant;
	// Признак записи опознавателя издателя: поле это дозволено лишь изданиям выше первого
	bool identified;
	// Признак записи опознавателя издателя составной формой
	bool wrapped;
	// Признак записи опознавателя издателя с негодным числом неиспользуемых разрядов
	bool tainted;
	// Признак третьего поля в записи срока действия: их ровно два
	bool prolonged;
	// Признак признака имени с опознавателем вне таблицы RFC 4514
	bool serial;
	// Опознаватель алгоритма подписи снаружи расходится с внутренним
	bool mismatched;
	// Составляющая имени владельца несёт два признака одного вида
	bool doubled;
	/**
	 * @brief Конструктор
	 *
	 */
	Defect() noexcept :
		version(false), release(false), critical(false),
		duplicate(false), generalized(false), trailing(false),
		order(false), crowded(false), enclosed(false),
		untimed(false), numeric(false), foreign(false),
		vacant(false), identified(false), wrapped(false), tainted(false), prolonged(false), serial(false),
		mismatched(false), doubled(false) {}
} defect_t;

/**
 * @brief Метод записи отличительного имени
 *
 * @param writer записчик записи
 * @param value  значение общего имени
 *
 */
static void name(asn1::writer_t & writer, const char * oid, const char * value) {
	// Открываем запись имени
	writer.open(asn1::tag_t::SEQUENCE);
	// Открываем составляющую имени
	writer.open(asn1::tag_t::SET);
	// Открываем признак имени
	writer.open(asn1::tag_t::SEQUENCE);
	// Записываем опознаватель признака имени
	writer.oid(oid);
	// Записываем значение признака имени
	writer.text(asn1::tag_t::UTF8_STRING, value);
	// Закрываем признак имени
	writer.close();
	// Закрываем составляющую имени
	writer.close();
	// Закрываем запись имени
	writer.close();
}
/**
 * @brief Метод записи имени стороны общим именем
 *
 * @param writer записчик, в который записывается имя
 * @param value  значение общего имени
 *
 */
static void name(asn1::writer_t & writer, const char * value) {
	// Открываем запись имени
	writer.open(asn1::tag_t::SEQUENCE);
	// Открываем составляющую имени
	writer.open(asn1::tag_t::SET);
	// Открываем признак имени
	writer.open(asn1::tag_t::SEQUENCE);
	// Записываем опознаватель общего имени
	writer.oid("2.5.4.3");
	// Записываем значение общего имени
	writer.text(asn1::tag_t::UTF8_STRING, value);
	// Закрываем признак имени
	writer.close();
	// Закрываем составляющую имени
	writer.close();
	// Закрываем запись имени
	writer.close();
}
/**
 * @brief Метод записи опознавателя алгоритма
 *
 * @param writer записчик записи
 * @param value  опознаватель алгоритма
 *
 */
static void algorithm(asn1::writer_t & writer, const char * value) {
	// Открываем запись опознавателя алгоритма
	writer.open(asn1::tag_t::SEQUENCE);
	// Записываем опознаватель алгоритма
	writer.oid(value);
	// Записываем отсутствие настроек алгоритма
	writer.nothing();
	// Закрываем запись опознавателя алгоритма
	writer.close();
}
/**
 * @brief Метод сборки записи сертификата
 *
 * @param writer записчик записи
 * @param defect набор вносимых изъянов
 *
 */
static void build(asn1::writer_t & writer, const defect_t & defect) {
	// Содержимое открытого ключа и подписи
	const uint8_t key[] = {0x30, 0x03, 0x02, 0x01, 0x01};
	// Открываем запись сертификата
	writer.open(asn1::tag_t::SEQUENCE);
	// Открываем подписываемую часть сертификата
	writer.open(asn1::tag_t::SEQUENCE);
	// Если издание сертификата записывается
	if(!defect.release){
		// Открываем запись издания сертификата
		writer.open(asn1::cls_t::CONTEXT, 0);
		// Записываем издание сертификата
		writer.integer(defect.version ? 0 : 2);
		// Если запись издания сертификата несёт лишнее поле
		if(defect.crowded)
			// Записываем лишнее поле записи издания сертификата
			writer.integer(2);
		// Закрываем запись издания сертификата
		writer.close();
	}
	// Записываем порядковый номер сертификата
	writer.integer(305419896);
	// Записываем опознаватель алгоритма подписи
	algorithm(writer, "1.2.840.113549.1.1.11");
	// Записываем имя издателя сертификата
	name(writer, "anyks.com");
	// Открываем запись срока действия сертификата
	writer.open(asn1::tag_t::SEQUENCE);
	// Если граница срока действия записывается не меткой времени
	if(defect.untimed)
		// Записываем начало срока действия строкой знаков
		writer.text(asn1::tag_t::UTF8_STRING, "260101000000Z");
	// Записываем начало срока действия сертификата
	else writer.time((defect.generalized ? asn1::tag_t::GENERALIZED_TIME : asn1::tag_t::UTC_TIME), 1787747696);
	// Записываем окончание срока действия сертификата
	writer.time(asn1::tag_t::UTC_TIME, 1819283696);
	// Если срок действия записывается третьим полем
	if(defect.prolonged)
		// Записываем лишнюю границу срока действия
		writer.time(asn1::tag_t::UTC_TIME, 1819283696);
	// Закрываем запись срока действия сертификата
	writer.close();
	// Если имя владельца записывается признаком с опознавателем вне таблицы
	if(defect.serial)
		// Записываем имя владельца порядковым номером: RFC 4514 обозначения ему не даёт
		name(writer, "2.5.4.5", "0001");
	// Записываем имя владельца сертификата
	else if(defect.doubled){
		writer.open(asn1::tag_t::SEQUENCE);
		writer.open(asn1::tag_t::SET);
		writer.open(asn1::tag_t::SEQUENCE);
		writer.oid("2.5.4.3");
		writer.text(asn1::tag_t::UTF8_STRING, "a");
		writer.close();
		writer.open(asn1::tag_t::SEQUENCE);
		writer.oid("2.5.4.3");
		writer.text(asn1::tag_t::UTF8_STRING, "b");
		writer.close();
		writer.close();
		writer.close();
	} else name(writer, "anyks.com");
	// Открываем запись сведений об открытом ключе
	writer.open(asn1::tag_t::SEQUENCE);
	// Записываем опознаватель алгоритма ключа
	algorithm(writer, "1.2.840.113549.1.1.1");
	// Записываем открытый ключ
	writer.bits(view_t(key, sizeof(key)));
	// Закрываем запись сведений об открытом ключе
	writer.close();
	/**
	 * Опознаватель издателя записывается меткой места употребления [1] неявно, как
	 * строка разрядов: первый байт содержимого несёт число неиспользуемых разрядов.
	 * Раздел 4.1.2.8 RFC 5280 дозволяет поле лишь изданиям выше первого
	 */
	if(defect.identified || defect.wrapped || defect.tainted){
		// Содержимое опознавателя издателя: число неиспользуемых разрядов и сами разряды
		const uint8_t uid[3] = {static_cast <uint8_t> (defect.tainted ? 0x08 : 0x00), 0xA5, 0x5A};
		// Если опознаватель издателя записывается составной формой
		if(defect.wrapped){
			// Открываем составную запись опознавателя издателя
			writer.open(asn1::cls_t::CONTEXT, 1);
			// Закрываем составную запись опознавателя издателя
			writer.close();
		// Записываем опознаватель издателя простой формой
		} else writer.element(asn1::cls_t::CONTEXT, false, 1, view_t(uid, sizeof(uid)));
	}
	// Если необязательные поля записываются с нарушением порядка
	if(defect.order){
		// Открываем запись набора расширений
		writer.open(asn1::cls_t::CONTEXT, 3);
		// Открываем набор расширений
		writer.open(asn1::tag_t::SEQUENCE);
		// Открываем расширение основных ограничений
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель расширения основных ограничений
		writer.oid("2.5.29.19");
		// Записываем содержимое расширения основных ограничений
		writer.octets(view_t());
		// Закрываем расширение основных ограничений
		writer.close();
		// Закрываем набор расширений
		writer.close();
		// Закрываем запись набора расширений
		writer.close();
		// Записываем опознаватель владельца сертификата
		writer.element(asn1::cls_t::CONTEXT, false, 2, view_t(key, 2));
		// Закрываем подписываемую часть сертификата
		writer.close();
		// Записываем опознаватель алгоритма подписи
		algorithm(writer, "1.2.840.113549.1.1.11");
		// Записываем подпись сертификата
		writer.bits(view_t(key, sizeof(key)));
		// Закрываем запись сертификата
		writer.close();
		// Выходим из метода
		return;
	}
	// Открываем запись набора расширений
	writer.open(asn1::cls_t::CONTEXT, 3);
	// Открываем набор расширений
	writer.open(asn1::tag_t::SEQUENCE);
	// Определяем число записываемых расширений основных ограничений
	const size_t count = (defect.vacant ? 0 : (defect.duplicate ? 2 : 1));
	/**
	 * Выполняем запись расширений основных ограничений
	 */
	for(size_t i = 0; i < count; i++){
		// Содержимое расширения основных ограничений
		asn1::writer_t inner;
		// Открываем запись основных ограничений
		inner.open(asn1::tag_t::SEQUENCE);
		// Если основные ограничения открываются полем не универсального класса
		if(defect.foreign)
			// Записываем признак принадлежности меткой места употребления
			inner.element(asn1::cls_t::CONTEXT, false, 0, view_t());
		// Записываем признак принадлежности удостоверяющему центру
		else inner.boolean(true);
		// Закрываем запись основных ограничений
		inner.close();
		// Открываем расширение основных ограничений
		writer.open(asn1::tag_t::SEQUENCE);
		// Записываем опознаватель расширения основных ограничений
		writer.oid("2.5.29.19");
		// Если признак обязательности расширения записывается
		if(defect.critical)
			// Записываем необязательность расширения значением по умолчанию
			writer.boolean(false);
		else writer.boolean(true);
		// Если содержимое расширения записывается не строкой байтов
		if(defect.numeric)
			// Записываем содержимое расширения целым числом
			writer.integer(2);
		// Если содержимое расширения записывается составной строкой байтов
		else if(defect.enclosed){
			// Открываем составную строку байтов содержимого расширения
			writer.open(asn1::cls_t::UNIVERSAL, static_cast <uint32_t> (asn1::tag_t::OCTET_STRING));
			// Закрываем составную строку байтов содержимого расширения
			writer.close();
		// Если содержимое расширения записывается простой строкой байтов
		} else
			// Записываем содержимое расширения основных ограничений
			writer.octets(inner.data());
		// Закрываем расширение основных ограничений
		writer.close();
	}
	// Закрываем набор расширений
	writer.close();
	// Закрываем запись набора расширений
	writer.close();
	// Закрываем подписываемую часть сертификата
	writer.close();
	// Записываем опознаватель алгоритма подписи
	algorithm(writer, (defect.mismatched ? "1.2.840.113549.1.1.5" : "1.2.840.113549.1.1.11"));
	// Записываем подпись сертификата
	writer.bits(view_t(key, sizeof(key)));
	// Закрываем запись сертификата
	writer.close();
}
/**
 * @brief Проверка разбора усечённых и порченых записей сертификата
 *
 * @note Проверка эта итога разбора не судит: усечённая запись вправе и не
 *       разобраться, и разобраться в иное. Судит она лишь того, что разбор не
 *       валится и за поданную область байтов не выходит, - недоверенная запись
 *       не смеет уводить разбор ни в отказ работы, ни в чужую память
 *
 */
TEST(X509Test, Ragged) {
	// Создаём записчик записи сертификата
	asn1::writer_t writer;
	// Собираем запись сертификата
	build(writer, defect_t());
	// Проверяем успешность сборки записи сертификата
	ASSERT_EQ(writer.err(), asn1::error_t::NONE);
	// Получаем собранную запись сертификата
	const view_t whole = writer.data();
	// Выполняем перенос собранной записи сертификата
	const vector <uint8_t> origin(whole.data, whole.data + whole.size);
	// Проверяем, что собранная запись сертификата не пуста
	ASSERT_GT(origin.size(), size_t(16));
	/**
	 * Выполняем перебор длин усечения записи сертификата
	 */
	for(size_t size = 0; size < origin.size(); size++){
		// Создаём объект разбираемого сертификата
		x509::certificate_t certificate;
		/**
		 * Всякий неполный обрубок записи обязан быть отвергнут: длина всякой записи
		 * DER объявляется впереди её содержимого, и обрубок объявленной длины не
		 * наберёт. Заслон этот стережёт весь разбор сертификата разом
		 */
		ASSERT_NE(certificate.parse(view_t(origin.data(), size)), x509::error_t::NONE) << "длина " << size;
	}
	/**
	 * Выполняем перебор мест порчи записи сертификата
	 */
	for(size_t place = 0; place < origin.size(); place++){
		/**
		 * Выполняем перебор порчи очередного байта записи
		 */
		for(size_t item = 0; item < 3; item++){
			// Выполняем перенос собранной записи сертификата
			vector <uint8_t> spoiled = origin;
			/**
			 * Порча берётся тремя видами: обращением всех разрядов, обнулением и
			 * набивкой единицами - так задеваются и метки, и длины, и содержимое
			 */
			switch(item){
				// Выполняем обращение всех разрядов порченого байта
				case 0: spoiled[place] = static_cast <uint8_t> (spoiled[place] ^ 0xFF); break;
				// Выполняем обнуление порченого байта
				case 1: spoiled[place] = 0x00; break;
				// Выполняем набивку порченого байта единицами
				case 2: spoiled[place] = 0xFF; break;
			}
			// Создаём объект разбираемого сертификата
			x509::certificate_t certificate;
			// Разбор порченой записи обязан обойтись без отказа работы
			(void) certificate.parse(view_t(spoiled.data(), spoiled.size()));
		}
	}
}

/**
 * @brief Проверка извлекателей расширений сертификата
 *
 * @note Извлекатели эти в самой библиотеке пока не зовутся: они заведены для
 *       потребителей фреймворка. Оттого проверяются они прямо, минуя разбор целого
 *       сертификата, - иначе успешные их пути не задеваются ничем
 *
 */
TEST(X509Test, Extractors) {
	// Создаём записчик записи расширенного назначения ключа
	asn1::writer_t purposed;
	// Открываем последовательность назначений ключа
	purposed.open(asn1::tag_t::SEQUENCE);
	// Записываем назначение подлинности стороны сервера
	purposed.oid("1.3.6.1.5.5.7.3.1");
	// Записываем назначение подлинности стороны клиента
	purposed.oid("1.3.6.1.5.5.7.3.2");
	// Закрываем последовательность назначений ключа
	purposed.close();
	// Проверяем успешность сборки записи назначений ключа
	ASSERT_EQ(purposed.err(), asn1::error_t::NONE);
	// Составляемое расширение расширенного назначения ключа
	x509::extension_t extension;
	// Устанавливаем опознаватель расширения назначения ключа
	extension.oid = "2.5.29.37";
	// Устанавливаем тело расширения назначения ключа
	extension.value = purposed.data();
	// Набор извлечённых назначений ключа
	vector <string> purposes;
	// Выполняем извлечение расширенного назначения ключа
	ASSERT_EQ(x509::purpose(extension, purposes), x509::error_t::NONE);
	// Проверяем число извлечённых назначений ключа
	ASSERT_EQ(purposes.size(), size_t(2));
	// Проверяем первое извлечённое назначение ключа
	ASSERT_STREQ(purposes[0].c_str(), "1.3.6.1.5.5.7.3.1");
	// Проверяем второе извлечённое назначение ключа
	ASSERT_STREQ(purposes[1].c_str(), "1.3.6.1.5.5.7.3.2");
	// Опознаватель ключа, записываемый расширением
	const uint8_t named[8] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7};
	// Создаём записчик записи опознавателя ключа стороны
	asn1::writer_t subjected;
	// Записываем опознаватель ключа стороны
	subjected.octets(view_t(named, sizeof(named)));
	// Проверяем успешность сборки записи опознавателя ключа стороны
	ASSERT_EQ(subjected.err(), asn1::error_t::NONE);
	// Устанавливаем опознаватель расширения опознавателя ключа стороны
	extension.oid = "2.5.29.14";
	// Устанавливаем тело расширения опознавателя ключа стороны
	extension.value = subjected.data();
	// Место, в которое помещается извлечённый опознаватель ключа стороны
	view_t subject;
	// Выполняем извлечение опознавателя ключа стороны
	ASSERT_EQ(x509::subjectKey(extension, subject), x509::error_t::NONE);
	// Проверяем длину извлечённого опознавателя ключа стороны
	ASSERT_EQ(subject.size, sizeof(named));
	// Проверяем схождение извлечённого опознавателя с записанным
	ASSERT_EQ(::memcmp(subject.data, named, sizeof(named)), 0);
	// Создаём записчик записи опознавателя ключа издателя
	asn1::writer_t authorized;
	// Открываем последовательность опознавателя ключа издателя
	authorized.open(asn1::tag_t::SEQUENCE);
	/**
	 * Опознаватель ключа издателя лежит полем нулевого места, помеченным неявно:
	 * раздел 4.2.1.1 RFC 5280 кладёт ему именно такую разметку
	 */
	authorized.element(asn1::cls_t::CONTEXT, false, 0, view_t(named, sizeof(named)));
	// Закрываем последовательность опознавателя ключа издателя
	authorized.close();
	// Проверяем успешность сборки записи опознавателя ключа издателя
	ASSERT_EQ(authorized.err(), asn1::error_t::NONE);
	// Устанавливаем опознаватель расширения опознавателя ключа издателя
	extension.oid = "2.5.29.35";
	// Устанавливаем тело расширения опознавателя ключа издателя
	extension.value = authorized.data();
	// Место, в которое помещается извлечённый опознаватель ключа издателя
	view_t authority;
	// Выполняем извлечение опознавателя ключа издателя
	ASSERT_EQ(x509::authorityKey(extension, authority), x509::error_t::NONE);
	// Проверяем длину извлечённого опознавателя ключа издателя
	ASSERT_EQ(authority.size, sizeof(named));
	// Проверяем схождение извлечённого опознавателя с записанным
	ASSERT_EQ(::memcmp(authority.data, named, sizeof(named)), 0);
	// Создаём записчик записи основных ограничений с предельной глубиной
	asn1::writer_t limited;
	// Открываем последовательность основных ограничений
	limited.open(asn1::tag_t::SEQUENCE);
	// Записываем принадлежность удостоверяющему центру
	limited.boolean(true);
	// Записываем предельную глубину цепочки сертификатов
	limited.integer(static_cast <int64_t> (3));
	// Закрываем последовательность основных ограничений
	limited.close();
	// Проверяем успешность сборки записи основных ограничений
	ASSERT_EQ(limited.err(), asn1::error_t::NONE);
	// Устанавливаем опознаватель расширения основных ограничений
	extension.oid = "2.5.29.19";
	// Устанавливаем тело расширения основных ограничений
	extension.value = limited.data();
	// Признак принадлежности удостоверяющему центру
	bool centre = false;
	// Предельная глубина цепочки сертификатов
	int64_t depth = -1;
	// Выполняем извлечение основных ограничений
	ASSERT_EQ(x509::constraints(extension, centre, depth), x509::error_t::NONE);
	// Проверяем принадлежность удостоверяющему центру
	ASSERT_TRUE(centre);
	// Проверяем извлечённую предельную глубину цепочки
	ASSERT_EQ(depth, static_cast <int64_t> (3));
}

/**
 * @brief Проверка разбора верной записи сертификата
 *
 */
TEST(X509Test, Certificate) {
	// Создаём записчик записи сертификата
	asn1::writer_t writer;
	// Собираем запись сертификата
	build(writer, defect_t());
	// Проверяем успешность сборки записи сертификата
	ASSERT_EQ(writer.err(), asn1::error_t::NONE);
	// Создаём объект сертификата
	x509::certificate_t certificate;
	// Выполняем разбор записи сертификата
	ASSERT_EQ(certificate.parse(writer.data()), x509::error_t::NONE);
	// Проверяем издание сертификата
	ASSERT_EQ(certificate.release(), x509::version_t::V3);
	// Проверяем опознаватель алгоритма подписи
	ASSERT_STREQ(certificate.algorithms().c_str(), "1.2.840.113549.1.1.11");
	// Проверяем опознаватель алгоритма открытого ключа
	ASSERT_STREQ(certificate.key().algorithm.c_str(), "1.2.840.113549.1.1.1");
	// Проверяем порядковый номер сертификата
	ASSERT_EQ(certificate.number().size, size_t(4));
	// Срок действия сертификата
	int64_t before = 0, after = 0;
	// Извлекаем срок действия сертификата
	certificate.validity(before, after);
	// Проверяем начало срока действия сертификата
	ASSERT_EQ(before, int64_t(1787747696));
	// Проверяем окончание срока действия сертификата
	ASSERT_EQ(after, int64_t(1819283696));
	// Проверяем число расширений сертификата
	ASSERT_EQ(certificate.extension().size(), size_t(1));
	// Проверяем обязательность расширения
	ASSERT_TRUE(certificate.extension()[0].critical);
	// Разыскиваем расширение основных ограничений
	const x509::extension_t * item = certificate.extension("2.5.29.19");
	// Проверяем наличие расширения основных ограничений
	ASSERT_TRUE(item != nullptr);
	// Признак принадлежности сертификата удостоверяющему центру
	bool authority = false;
	// Предельная глубина цепочки
	int64_t depth = 0;
	// Выполняем извлечение основных ограничений
	ASSERT_EQ(x509::constraints(*item, authority, depth), x509::error_t::NONE);
	// Проверяем признак принадлежности сертификата удостоверяющему центру
	ASSERT_TRUE(authority);
	// Проверяем предельную глубину цепочки
	ASSERT_EQ(depth, int64_t(-1));
	// Проверяем отсутствие незаписанного расширения
	ASSERT_TRUE(certificate.extension("2.5.29.15") == nullptr);
	// Разыскиваем общее имя владельца сертификата
	const x509::attribute_t * attribute = x509::attribute(certificate.subjects(), "2.5.4.3");
	// Проверяем наличие общего имени владельца сертификата
	ASSERT_TRUE(attribute != nullptr);
	// Проверяем значение общего имени владельца сертификата
	ASSERT_STREQ(attribute->value.c_str(), "anyks.com");
	// Собранная запись имени владельца сертификата
	std::string text;
	// Выполняем сборку записи имени владельца сертификата
	ASSERT_EQ(x509::text(certificate.subjects(), text), x509::error_t::NONE);
	// Проверяем собранную запись имени владельца сертификата
	ASSERT_STREQ(text.c_str(), "CN=anyks.com");
	// Проверяем, что подписываемая часть меньше записи сертификата
	ASSERT_TRUE(certificate.body().size < writer.data().size);
	// Проверяем, что подписываемая часть указывает внутрь записи сертификата
	ASSERT_TRUE(certificate.body().data > writer.data().data);
}
/**
 * @brief Проверка отказа от записей сертификата, запрещённых стандартом
 *
 */
TEST(X509Test, Strict) {
	// Изъян записи издания сертификата значением по умолчанию
	defect_t version;
	// Вносим изъян записи издания сертификата
	version.version = true;
	// Изъян записи расширений у сертификата первого издания
	defect_t release;
	// Вносим изъян записи расширений у сертификата первого издания
	release.release = true;
	// Изъян записи необязательности расширения значением по умолчанию
	defect_t critical;
	// Вносим изъян записи необязательности расширения
	critical.critical = true;
	// Изъян повторного расширения
	defect_t duplicate;
	// Вносим изъян повторного расширения
	duplicate.duplicate = true;
	// Изъян записи срока действия четырёхзначным годом
	defect_t generalized;
	// Вносим изъян записи срока действия четырёхзначным годом
	generalized.generalized = true;
	// Изъян порядка необязательных полей
	defect_t order;
	// Вносим изъян порядка необязательных полей
	order.order = true;
	// Набор вносимых изъянов
	const defect_t defects[] = {version, release, critical, duplicate, generalized, order};
	// Набор ожидаемых причин отказа
	const x509::error_t errors[] = {
		x509::error_t::VERSION, x509::error_t::VERSION, x509::error_t::EXTENSION,
		x509::error_t::DUPLICATE, x509::error_t::VALIDITY, x509::error_t::STRUCTURE
	};
	/**
	 * Выполняем обход набора вносимых изъянов
	 */
	for(size_t i = 0; i < (sizeof(defects) / sizeof(defects[0])); i++){
		// Создаём записчик записи сертификата
		asn1::writer_t writer;
		// Собираем запись сертификата
		build(writer, defects[i]);
		// Проверяем успешность сборки записи сертификата
		ASSERT_EQ(writer.err(), asn1::error_t::NONE) << "изъян " << i;
		// Создаём объект сертификата
		x509::certificate_t certificate;
		// Проверяем отказ разбора записи сертификата
		ASSERT_EQ(certificate.parse(writer.data()), errors[i]) << "изъян " << i;
	}
}
/**
 * @brief Проверка отказа от лишних байтов после записи сертификата
 *
 */
TEST(X509Test, Trailing) {
	// Создаём записчик записи сертификата
	asn1::writer_t writer;
	// Собираем запись сертификата
	build(writer, defect_t());
	// Собираемая запись с лишними байтами
	std::vector <uint8_t> buffer(writer.data().data, writer.data().data + writer.data().size);
	// Дополняем запись лишним байтом
	buffer.push_back(0x00);
	// Создаём объект сертификата
	x509::certificate_t certificate;
	// Проверяем отказ разбора записи сертификата
	ASSERT_EQ(certificate.parse(view_t(buffer.data(), buffer.size())), x509::error_t::STRUCTURE);
}
/**
 * @brief Проверка сборки записи имени с экранированием знаков
 *
 */
TEST(X509Test, Escaping) {
	// Создаём записчик записи сертификата
	asn1::writer_t writer;
	// Открываем запись имени
	writer.open(asn1::tag_t::SEQUENCE);
	// Открываем составляющую имени
	writer.open(asn1::tag_t::SET);
	// Открываем признак имени
	writer.open(asn1::tag_t::SEQUENCE);
	// Записываем опознаватель общего имени
	writer.oid("2.5.4.3");
	// Записываем значение общего имени со знаками, требующими экранирования
	writer.text(asn1::tag_t::UTF8_STRING, " имя, с запятой ");
	// Закрываем признак имени
	writer.close();
	// Закрываем составляющую имени
	writer.close();
	// Закрываем запись имени
	writer.close();
	// Создаём разборщик собранной записи
	asn1::reader_t reader(writer.data());
	// Объект разобранного элемента
	asn1::element_t element;
	// Выполняем разбор записи имени
	ASSERT_TRUE(reader.next(asn1::tag_t::SEQUENCE, element));
	// Разбираемое имя
	x509::name_t value;
	// Собираем имя из разобранной записи вручную
	value.parts.resize(1);
	// Добавляем признак имени
	value.parts[0].resize(1);
	// Записываем опознаватель признака имени
	value.parts[0][0].oid = "2.5.4.3";
	// Записываем значение признака имени
	value.parts[0][0].value = " имя, с запятой ";
	// Собранная запись имени
	std::string text;
	// Выполняем сборку записи имени
	ASSERT_EQ(x509::text(value, text), x509::error_t::NONE);
	// Проверяем экранирование пробелов по краям и запятой внутри записи
	ASSERT_STREQ(text.c_str(), "CN=\\ имя\\, с запятой\\ ");
	// Разбираемое имя из одного лишь пробела
	x509::name_t single;
	// Собираем имя из одного признака
	single.parts.resize(1);
	// Добавляем признак имени
	single.parts[0].resize(1);
	// Записываем опознаватель признака имени
	single.parts[0][0].oid = "2.5.4.3";
	// Записываем значение признака имени из одного пробела
	single.parts[0][0].value = " ";
	// Собранная запись имени из одного пробела
	std::string sole;
	// Выполняем сборку записи имени из одного пробела
	ASSERT_EQ(x509::text(single, sole), x509::error_t::NONE);
	/**
	 * Пробел, стоящий разом первым и последним знаком, экранируется ОДИН раз: правило
	 * начала записи и правило её конца отвечают за разные места, и место начала
	 * сверяется отдельной половиной условия конца
	 */
	ASSERT_STREQ(sole.c_str(), "CN=\\ ");
}

/**
 * Проверка отказов разбора расширений сертификата с негодной записью
 */
TEST(X509Test, Malformed) {
	// Составляемое расширение сертификата
	x509::extension_t extension;
	// Признак принадлежности сертификата удостоверяющему центру
	bool authority = false;
	// Предельная глубина цепочки сертификатов
	int64_t depth = -1;
	/**
	 * Основные ограничения записываются последовательностью, и последовательность эта
	 * обязана быть составной. Метка последовательности с простым видом записи
	 * встречается только у подделки: сам записчик такой записи не составит
	 */
	const uint8_t simple[] = {0x30, 0x00};
	// Устанавливаем опознаватель расширения основных ограничений
	extension.oid = "2.5.29.19";
	// Устанавливаем тело расширения записью с простой меткой последовательности
	extension.value = view_t(simple, sizeof(simple));
	// Проверяем успешность разбора пустой записи основных ограничений
	ASSERT_EQ(x509::constraints(extension, authority, depth), x509::error_t::NONE);
	// Запись основных ограничений, за которой идут лишние поля
	const uint8_t trailed[] = {0x30, 0x00, 0x30, 0x00};
	// Устанавливаем тело расширения записью с лишними полями
	extension.value = view_t(trailed, sizeof(trailed));
	// Проверяем отказ разбора записи основных ограничений с лишними полями
	ASSERT_EQ(x509::constraints(extension, authority, depth), x509::error_t::STRUCTURE);
	// Запись основных ограничений с предельной глубиной цепочки не целым числом
	const uint8_t bogus[] = {0x30, 0x05, 0x01, 0x01, 0xFF, 0x05, 0x00};
	// Устанавливаем тело расширения записью с негодной предельной глубиной
	extension.value = view_t(bogus, sizeof(bogus));
	// Проверяем отказ разбора записи основных ограничений с негодной глубиной
	ASSERT_EQ(x509::constraints(extension, authority, depth), x509::error_t::STRUCTURE);
	/**
	 * Раздел 4.2.1.9 RFC 5280: предельная глубина цепочки имеет смысл лишь у
	 * сертификата удостоверяющего центра, и без признака принадлежности ему запись
	 * такая противоречива
	 */
	const uint8_t depthless[] = {0x30, 0x03, 0x02, 0x01, 0x00};
	// Устанавливаем тело расширения записью с глубиной без признака центра
	extension.value = view_t(depthless, sizeof(depthless));
	// Проверяем отказ разбора глубины цепочки без признака удостоверяющего центра
	ASSERT_EQ(x509::constraints(extension, authority, depth), x509::error_t::EXTENSION);
	// Запись основных ограничений с отрицательной предельной глубиной цепочки
	const uint8_t negative[] = {0x30, 0x06, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x81};
	// Устанавливаем тело расширения записью с отрицательной глубиной
	extension.value = view_t(negative, sizeof(negative));
	// Проверяем отказ разбора отрицательной предельной глубины цепочки
	ASSERT_EQ(x509::constraints(extension, authority, depth), x509::error_t::EXTENSION);
	// Разряды назначения ключа, извлечённые из расширения
	uint16_t usage = 0;
	// Устанавливаем опознаватель расширения назначения ключа
	extension.oid = "2.5.29.15";
	// Запись назначения ключа, не содержащая ни одного разряда
	const uint8_t bitless[] = {0x03, 0x01, 0x00};
	// Устанавливаем тело расширения записью без разрядов назначения
	extension.value = view_t(bitless, sizeof(bitless));
	// Проверяем отказ разбора назначения ключа без единого разряда
	ASSERT_EQ(x509::usage(extension, usage), x509::error_t::EXTENSION);
	// Запись назначения ключа, занявшая больше двух байтов разрядов
	const uint8_t lengthy[] = {0x03, 0x04, 0x00, 0xFF, 0xFF, 0xFF};
	// Устанавливаем тело расширения записью с непомерным числом разрядов
	extension.value = view_t(lengthy, sizeof(lengthy));
	// Проверяем отказ разбора назначения ключа с непомерным числом разрядов
	ASSERT_EQ(x509::usage(extension, usage), x509::error_t::EXTENSION);
	/**
	 * Девятый разряд назначения ключа живёт во ВТОРОМ байте записи, и на однобайтовой
	 * записи заслон его не трогает вовсе. Раздел 4.2.1.3 RFC 5280 отводит этому
	 * разряду назначение расшифрования
	 */
	const uint8_t deciphering[] = {0x03, 0x03, 0x07, 0x00, 0x80};
	// Устанавливаем тело расширения записью с девятым разрядом назначения
	extension.value = view_t(deciphering, sizeof(deciphering));
	// Проверяем успешность разбора назначения ключа с девятым разрядом
	ASSERT_EQ(x509::usage(extension, usage), x509::error_t::NONE);
	// Проверяем извлечение девятого разряда назначения ключа
	ASSERT_EQ((usage & static_cast <uint16_t> (x509::usage_t::DECIPHER_ONLY)), static_cast <uint16_t> (x509::usage_t::DECIPHER_ONLY));
	// Запись назначения ключа с двумя байтами, у которых девятый разряд снят
	const uint8_t undeciphering[] = {0x03, 0x03, 0x07, 0xFF, 0x00};
	// Устанавливаем тело расширения записью со снятым девятым разрядом
	extension.value = view_t(undeciphering, sizeof(undeciphering));
	// Проверяем успешность разбора назначения ключа со снятым девятым разрядом
	ASSERT_EQ(x509::usage(extension, usage), x509::error_t::NONE);
	// Проверяем отсутствие девятого разряда назначения ключа
	ASSERT_EQ((usage & static_cast <uint16_t> (x509::usage_t::DECIPHER_ONLY)), static_cast <uint16_t> (0));
}

/**
 * Проверка отказов разбора расширений с записью не той формы
 */
TEST(X509Test, Illformed) {
	/**
	 * Метка записи несёт признак формы отдельным разрядом, и разборщик разбирает
	 * запись по НОМЕРУ метки, формы не спрашивая: последовательность с простой формой
	 * записи разбирается, а вот годной не является. Составить такую запись сам
	 * записчик не может - встречается она только у подделки
	 */
	const uint8_t primitive[] = {0x10, 0x00};
	// Запись последовательности с лишними полями следом
	const uint8_t trailed[] = {0x30, 0x00, 0x30, 0x00};
	// Составляемое расширение сертификата
	x509::extension_t extension;
	// Устанавливаем тело расширения записью с простой формой последовательности
	extension.value = view_t(primitive, sizeof(primitive));
	// Признак принадлежности сертификата удостоверяющему центру
	bool authority = false;
	// Предельная глубина цепочки сертификатов
	int64_t depth = -1;
	// Устанавливаем опознаватель расширения основных ограничений
	extension.oid = "2.5.29.19";
	// Проверяем отказ разбора основных ограничений записью простой формы
	ASSERT_EQ(x509::constraints(extension, authority, depth), x509::error_t::STRUCTURE);
	// Набор извлечённых назначений ключа
	vector <string> purposes;
	// Устанавливаем опознаватель расширения расширенного назначения ключа
	extension.oid = "2.5.29.37";
	// Проверяем отказ разбора назначения ключа записью простой формы
	ASSERT_EQ(x509::purpose(extension, purposes), x509::error_t::STRUCTURE);
	// Устанавливаем тело расширения записью с лишними полями
	extension.value = view_t(trailed, sizeof(trailed));
	// Проверяем отказ разбора назначения ключа записью с лишними полями
	ASSERT_EQ(x509::purpose(extension, purposes), x509::error_t::STRUCTURE);
	// Набор извлечённых дополнительных имён владельца
	vector <x509::alternative_t> alternatives;
	// Устанавливаем опознаватель расширения дополнительных имён владельца
	extension.oid = "2.5.29.17";
	// Проверяем отказ разбора дополнительных имён записью с лишними полями
	ASSERT_EQ(x509::alternatives(extension, alternatives), x509::error_t::STRUCTURE);
	// Устанавливаем тело расширения записью с простой формой последовательности
	extension.value = view_t(primitive, sizeof(primitive));
	// Проверяем отказ разбора дополнительных имён записью простой формы
	ASSERT_EQ(x509::alternatives(extension, alternatives), x509::error_t::STRUCTURE);
	// Просмотр извлечённого опознавателя ключа
	view_t identifier;
	// Устанавливаем опознаватель расширения опознавателя ключа издателя
	extension.oid = "2.5.29.35";
	// Проверяем отказ разбора опознавателя ключа издателя записью простой формы
	ASSERT_EQ(x509::authorityKey(extension, identifier), x509::error_t::STRUCTURE);
	/**
	 * Лишние поля за записью опознавателя и простая форма самой записи сверяются
	 * РАЗНЫМИ половинами одного заслона, и всякая отвергает запись в одиночку
	 */
	const uint8_t appended[] = {0x30, 0x02, 0x80, 0x00, 0x05, 0x00};
	// Устанавливаем тело расширения записью с лишним полем на конце
	extension.value = view_t(appended, sizeof(appended));
	// Проверяем отказ разбора опознавателя ключа издателя записью с лишним полем
	ASSERT_EQ(x509::authorityKey(extension, identifier), x509::error_t::STRUCTURE);
	/**
	 * Поля записи опознавателя ключа издателя различаются меткой МЕСТА УПОТРЕБЛЕНИЯ:
	 * метка универсального класса того же номера отвергается половиной, отвечающей за
	 * класс
	 */
	const uint8_t universal[] = {0x30, 0x02, 0x04, 0x00};
	// Устанавливаем тело расширения записью с полем универсального класса
	extension.value = view_t(universal, sizeof(universal));
	// Проверяем отказ разбора опознавателя ключа издателя полем универсального класса
	ASSERT_EQ(x509::authorityKey(extension, identifier), x509::error_t::STRUCTURE);
	/**
	 * Раздел 4.2.1.1 RFC 5280 задаёт полям записи порядок по возрастанию номера метки:
	 * возврат к меньшему номеру трогает половину, отвечающую за порядок
	 */
	const uint8_t reverted[] = {0x30, 0x06, 0x82, 0x01, 0x01, 0x80, 0x01, 0x02};
	// Устанавливаем тело расширения записью с нарушенным порядком полей
	extension.value = view_t(reverted, sizeof(reverted));
	// Проверяем отказ разбора опознавателя ключа издателя с нарушенным порядком полей
	ASSERT_EQ(x509::authorityKey(extension, identifier), x509::error_t::STRUCTURE);
	/**
	 * Номер метки поля ограничен сверху той же половиной заслона: полей у записи
	 * опознавателя ключа издателя ровно три
	 */
	const uint8_t excessive[] = {0x30, 0x02, 0x83, 0x00};
	// Устанавливаем тело расширения записью с полем непомерного номера метки
	extension.value = view_t(excessive, sizeof(excessive));
	// Проверяем отказ разбора опознавателя ключа издателя полем непомерного номера
	ASSERT_EQ(x509::authorityKey(extension, identifier), x509::error_t::STRUCTURE);
	/**
	 * Строка октетов наоборот обязана быть ПРОСТОЙ: составная её форма это средство
	 * кодировки BER, которой кодировка DER не знает
	 */
	const uint8_t compound[] = {0x24, 0x00};
	// Устанавливаем опознаватель расширения опознавателя ключа стороны
	extension.oid = "2.5.29.14";
	// Устанавливаем тело расширения составной строкой октетов
	extension.value = view_t(compound, sizeof(compound));
	// Проверяем отказ разбора опознавателя ключа составной строкой октетов
	ASSERT_EQ(x509::subjectKey(extension, identifier), x509::error_t::STRUCTURE);
	// Запись опознавателя ключа стороны с лишними полями следом
	const uint8_t doubled[] = {0x04, 0x01, 0xA0, 0x04, 0x01, 0xA1};
	// Устанавливаем тело расширения записью с лишними полями
	extension.value = view_t(doubled, sizeof(doubled));
	// Проверяем отказ разбора опознавателя ключа записью с лишними полями
	ASSERT_EQ(x509::subjectKey(extension, identifier), x509::error_t::STRUCTURE);
	// Годная запись опознавателя ключа стороны
	const uint8_t sound[] = {0x04, 0x01, 0xA0};
	// Устанавливаем тело расширения годной записью опознавателя ключа
	extension.value = view_t(sound, sizeof(sound));
	// Проверяем успешность разбора годной записи опознавателя ключа
	ASSERT_EQ(x509::subjectKey(extension, identifier), x509::error_t::NONE);
	// Проверяем длину извлечённого опознавателя ключа стороны
	ASSERT_EQ(identifier.size, static_cast <size_t> (1));
}

/**
 * Проверка отказов разбора сертификата с последовательностью не той формы
 */
TEST(X509Test, Unstructured) {
	// Создаём записчик записи сертификата
	asn1::writer_t writer;
	// Собираем запись сертификата
	build(writer, defect_t());
	// Проверяем успешность сборки записи сертификата
	ASSERT_EQ(writer.err(), asn1::error_t::NONE);
	// Извлекаем собранную запись сертификата
	const view_t sound = writer.data();
	// Копия записи сертификата, в которой портится форма последовательности
	vector <uint8_t> spoiled(sound.data, sound.data + sound.size);
	// Создаём объект сертификата
	x509::certificate_t certificate;
	// Проверяем успешность разбора неиспорченной записи сертификата
	ASSERT_EQ(certificate.parse(view_t(spoiled.data(), spoiled.size())), x509::error_t::NONE);
	/**
	 * Внешняя последовательность сертификата обязана быть составной. Разборщик
	 * разбирает запись по номеру метки, формы не спрашивая, и простая её форма
	 * проходит разбор, а заслон отвергает уже разобранное
	 */
	spoiled[0] = 0x10;
	// Проверяем отказ разбора сертификата с простой формой внешней последовательности
	ASSERT_EQ(certificate.parse(view_t(spoiled.data(), spoiled.size())), x509::error_t::STRUCTURE);
	// Возвращаем составную форму внешней последовательности на место
	spoiled[0] = 0x30;
	// Место, на котором стоит набор расширений сертификата
	size_t place = 0;
	/**
	 * Набор расширений идёт полем с меткой третьего места, и внутри него лежит
	 * последовательность самих расширений. Разыскиваем её, чтобы испортить форму
	 */
	for(size_t i = 0; (i + 2) < spoiled.size(); i++){
		// Если найдено поле с меткой третьего места и последовательностью внутри
		if((spoiled[i] == 0xA3) && (spoiled[i + 2] == 0x30)){
			// Запоминаем место последовательности набора расширений
			place = (i + 2);
			// Выходим из розыска набора расширений
			break;
		}
	}
	// Проверяем, что набор расширений в записи сертификата разыскан
	ASSERT_NE(place, static_cast <size_t> (0));
	// Портим форму записи последовательности набора расширений
	spoiled[place] = 0x10;
	// Проверяем отказ разбора сертификата с простой формой набора расширений
	ASSERT_EQ(certificate.parse(view_t(spoiled.data(), spoiled.size())), x509::error_t::STRUCTURE);
	// Возвращаем составную форму набора расширений на место
	spoiled[place] = 0x30;
	/**
	 * Необязательные поля подписываемой части идут метками мест с первого по третье, и
	 * метка сверх третьей ни одному полю не отвечает
	 */
	spoiled[place - 2] = 0xA4;
	// Проверяем отказ разбора сертификата с меткой места сверх дозволенных
	ASSERT_EQ(certificate.parse(view_t(spoiled.data(), spoiled.size())), x509::error_t::STRUCTURE);
	// Возвращаем метку места набора расширений на место
	spoiled[place - 2] = 0xA3;
	// Место, на котором стоит запись издания сертификата
	size_t release = 0;
	/**
	 * Издание сертификата идёт первым полем подписываемой части, полем с меткой
	 * НУЛЕВОГО места. Разыскиваем его, чтобы подменить метку места
	 */
	for(size_t i = 0; (i + 4) < spoiled.size(); i++){
		// Если найдено поле с меткой нулевого места и целым числом внутри
		if((spoiled[i] == 0xA0) && (spoiled[i + 1] == 0x03) && (spoiled[i + 2] == 0x02)){
			// Запоминаем место записи издания сертификата
			release = i;
			// Выходим из розыска записи издания сертификата
			break;
		}
	}
	// Проверяем, что запись издания в записи сертификата разыскана
	ASSERT_NE(release, static_cast <size_t> (0));
	/**
	 * Метка места у первого поля подписываемой части сверяется с нулём: поле с иной
	 * меткой изданием не является, и разбор идёт дальше, к порядковому номеру, где
	 * поле это уже негодно
	 */
	spoiled[release] = 0xA1;
	// Проверяем отказ разбора сертификата с изданием не своей метки места
	ASSERT_EQ(certificate.parse(view_t(spoiled.data(), spoiled.size())), x509::error_t::STRUCTURE);
	// Возвращаем метку места записи издания на место
	spoiled[release] = 0xA0;
	/**
	 * Порядковый номер сертификата идёт целым числом сразу за записью издания, и
	 * запись его строкой байтов отвергается второй половиной заслона
	 */
	spoiled[release + 5] = 0x04;
	// Проверяем отказ разбора сертификата с порядковым номером не целым числом
	ASSERT_EQ(certificate.parse(view_t(spoiled.data(), spoiled.size())), x509::error_t::STRUCTURE);
}

/**
 * Проверка отказов разбора сертификата с лишним полем и составной строкой байтов
 */
TEST(X509Test, Overfilled) {
	// Порок записи сертификата, дописывающий лишнее поле к изданию
	defect_t crowded;
	// Объявляем запись издания сертификата несущей лишнее поле
	crowded.crowded = true;
	// Создаём записчик записи сертификата с лишним полем издания
	asn1::writer_t first;
	// Собираем запись сертификата с лишним полем издания
	build(first, crowded);
	// Проверяем успешность сборки записи сертификата
	ASSERT_EQ(first.err(), asn1::error_t::NONE);
	// Создаём объект сертификата
	x509::certificate_t certificate;
	/**
	 * Запись издания сертификата вмещает одно лишь издание: раздел 4.1 RFC 5280 иных
	 * полей ей не отводит, и лишнее поле означает подделку
	 */
	ASSERT_EQ(certificate.parse(first.data()), x509::error_t::VERSION);
	// Порок записи сертификата, записывающий содержимое расширения составным
	defect_t enclosed;
	// Объявляем содержимое расширения записанным составной строкой байтов
	enclosed.enclosed = true;
	// Создаём записчик записи сертификата с составным содержимым расширения
	asn1::writer_t second;
	// Собираем запись сертификата с составным содержимым расширения
	build(second, enclosed);
	// Проверяем успешность сборки записи сертификата
	ASSERT_EQ(second.err(), asn1::error_t::NONE);
	/**
	 * Содержимое расширения записывается ПРОСТОЙ строкой байтов: составная её форма
	 * это средство кодировки BER, которой кодировка DER не знает
	 */
	ASSERT_EQ(certificate.parse(second.data()), x509::error_t::STRUCTURE);
	// Порок записи сертификата, записывающий границу срока действия не меткой времени
	defect_t untimed;
	// Объявляем границу срока действия записанной строкой знаков
	untimed.untimed = true;
	// Создаём записчик записи сертификата с границей срока не меткой времени
	asn1::writer_t third;
	// Собираем запись сертификата с границей срока не меткой времени
	build(third, untimed);
	// Проверяем успешность сборки записи сертификата
	ASSERT_EQ(third.err(), asn1::error_t::NONE);
	/**
	 * Раздел 4.1.2.5 RFC 5280 отводит границам срока действия ДВЕ метки времени, и
	 * всякая иная метка универсального класса отвергается ими обеими сразу
	 */
	ASSERT_EQ(certificate.parse(third.data()), x509::error_t::VALIDITY);
	// Порок записи сертификата, записывающий содержимое расширения целым числом
	defect_t numeric;
	// Объявляем содержимое расширения записанным целым числом
	numeric.numeric = true;
	// Создаём записчик записи сертификата с содержимым расширения целым числом
	asn1::writer_t fourth;
	// Собираем запись сертификата с содержимым расширения целым числом
	build(fourth, numeric);
	// Проверяем успешность сборки записи сертификата
	ASSERT_EQ(fourth.err(), asn1::error_t::NONE);
	/**
	 * Содержимое расширения записывается СТРОКОЙ БАЙТОВ: класс, вид метки и её номер
	 * сверяются РАЗНЫМИ половинами заслона, и метка целого числа трогает ту из них,
	 * что отвечает за номер
	 */
	ASSERT_EQ(certificate.parse(fourth.data()), x509::error_t::STRUCTURE);
	// Порок записи, открывающий основные ограничения полем не универсального класса
	defect_t foreign;
	// Объявляем основные ограничения открытыми меткой места употребления
	foreign.foreign = true;
	// Создаём записчик записи сертификата с чужеродным полем основных ограничений
	asn1::writer_t fifth;
	// Собираем запись сертификата с чужеродным полем основных ограничений
	build(fifth, foreign);
	// Проверяем успешность сборки записи сертификата
	ASSERT_EQ(fifth.err(), asn1::error_t::NONE);
	// Выполняем разбор сертификата с чужеродным полем основных ограничений
	ASSERT_EQ(certificate.parse(fifth.data()), x509::error_t::NONE);
	// Разыскиваем расширение основных ограничений сертификата
	const x509::extension_t * extension = certificate.extension("2.5.29.19");
	// Проверяем, что расширение основных ограничений найдено
	ASSERT_NE(extension, nullptr);
	// Признак принадлежности удостоверяющему центру
	bool authority = false;
	// Предельная глубина цепочки сертификатов
	int64_t depth = 0;
	/**
	 * Раздел 4.2.1.9 RFC 5280 отводит основным ограничениям признак и целое число:
	 * поле не универсального класса не годится ни тем, ни другим, и класс сверяется
	 * ОТДЕЛЬНОЙ половиной всякого из двух заслонов
	 */
	ASSERT_EQ(x509::constraints(*extension, authority, depth), x509::error_t::STRUCTURE);
}

/**
 * @brief Метод сбора смещений меток всех элементов записи
 *
 * @details Обход идёт вглубь: у составного элемента разбирается и его содержимое. Смещение
 *          берётся у просмотра элемента целиком - первым его байтом и лежит метка
 *
 * @param data    разбираемая запись
 * @param origin  начало записи, от которого считаются смещения
 * @param result  набор, в который складываются смещения меток
 *
 */
static void offsets(const view_t & data, const uint8_t * origin, vector <size_t> & result) {
	// Создаём разборщик записи
	asn1::reader_t reader(data);
	// Признак того, что первым элементом записи шёл опознаватель
	bool identifier = false;
	/**
	 * Выполняем обход элементов записи
	 */
	while(!reader.empty()){
		// Объект разобранного элемента
		asn1::element_t element;
		// Если очередной элемент разобрать не удалось
		if(!reader.next(element))
			// Прекращаем обход записи
			break;
		/**
		 * Настройки алгоритма обходу не подлежат: разборщик сертификата отдаёт их
		 * записью как есть, устройство их задаётся самим алгоритмом, и судить их вид
		 * ему нечем. Опознать их можно по соседству - в записи опознавателя алгоритма
		 * настройки идут вслед за самим опознавателем
		 */
		if(identifier)
			// Прекращаем обход записи опознавателя алгоритма
			break;
		// Запоминаем, что первым элементом записи шёл опознаватель алгоритма
		identifier = ((element.cls == asn1::cls_t::UNIVERSAL) && (element.tag == static_cast <uint32_t> (asn1::tag_t::OBJECT)));
		// Запоминаем смещение метки очередного элемента
		result.push_back(static_cast <size_t> (element.element.data - origin));
		// Если элемент составной, обходим и его содержимое
		if(element.constructed && (element.content.size > 0))
			// Выполняем обход содержимого составного элемента
			offsets(element.content, origin, result);
	}
}

/**
 * @brief Проверка отказа разбора при подмене вида метки
 *
 */
TEST(X509Test, Recast) {
	// Создаём записчик записи сертификата
	asn1::writer_t writer;
	// Собираем запись сертификата
	build(writer, defect_t());
	// Проверяем успешность сборки записи сертификата
	ASSERT_EQ(writer.err(), asn1::error_t::NONE);
	// Получаем собранную запись сертификата
	const view_t whole = writer.data();
	// Выполняем перенос собранной записи сертификата
	const vector <uint8_t> origin(whole.data, whole.data + whole.size);
	// Набор смещений меток всех элементов записи
	vector <size_t> places;
	// Выполняем сбор смещений меток всех элементов записи
	offsets(view_t(origin.data(), origin.size()), origin.data(), places);
	// Проверяем, что элементы записи собраны
	ASSERT_GT(places.size(), size_t(16));
	// Проверяем, что годная запись сертификата разбирается
	x509::certificate_t sample;
	// Выполняем разбор годной записи сертификата
	ASSERT_EQ(sample.parse(view_t(origin.data(), origin.size())), x509::error_t::NONE);
	/**
	 * Выполняем обход меток элементов записи
	 */
	for(size_t i = 0; i < places.size(); i++){
		// Выполняем перенос годной записи сертификата
		vector <uint8_t> item(origin);
		/**
		 * Обращаем разряд составного вида метки: правила DER кладут составной вид
		 * последовательностям и наборам, а простой - всем прочим видам записи, и
		 * подмена эта делает запись негодной, какой бы элемент ни задела
		 */
		item[places[i]] = static_cast <uint8_t> (item[places[i]] ^ 0x20);
		// Запоминаем подменённый вид метки для сообщения об отказе
		const unsigned changed = static_cast <unsigned> (item[places[i]]);
		// Создаём объект разбираемого сертификата
		x509::certificate_t certificate;
		// Проверяем отказ разбора записи с подменённым видом метки
		ASSERT_NE(certificate.parse(view_t(item.data(), item.size())), x509::error_t::NONE) << "метка " << i << " по смещению " << places[i] << ", вид 0x" << std::hex << static_cast <unsigned> (origin[places[i]]) << " -> 0x" << changed;
	}
}

/**
 * @brief Проверка необязательных полей подписываемой части сертификата
 *
 * @note Раздел 4.1.2.8 RFC 5280: опознаватели издателя и владельца дозволены лишь
 *       изданиям выше первого; раздел 4.1.2.9: набор расширений - поле
 *       необязательное, и пустым ему быть нельзя
 *
 */
TEST(X509Test, Peripheral) {
	// Изъян: опознаватель издателя у сертификата первого издания
	defect_t ancient;
	// Ставим первое издание сертификата
	ancient.version = true;
	// Записываем опознаватель издателя
	ancient.identified = true;
	// Изъян: опознаватель издателя составной формы
	defect_t wrapped;
	// Записываем опознаватель издателя составной формой
	wrapped.wrapped = true;
	// Изъян: опознаватель издателя с негодным числом неиспользуемых разрядов
	defect_t tainted;
	// Записываем опознаватель издателя с восемью неиспользуемыми разрядами
	tainted.tainted = true;
	// Изъян: пустой набор расширений
	defect_t vacant;
	// Оставляем набор расширений пустым
	vacant.vacant = true;
	// Изъян: опознаватель издателя у сертификата третьего издания - изъяном не является
	defect_t sound;
	// Записываем опознаватель издателя
	sound.identified = true;
	/**
	 * Изъян: опознаватель издателя у настоящего первого издания - без поля издания
	 * вовсе. Явно записанное первое издание отвергается ещё разбором издания: DER
	 * значение по умолчанию не пишет, - и до опознавателя разбор там не доходит
	 */
	defect_t primeval;
	// Оставляем поле издания незаписанным
	primeval.release = true;
	// Записываем опознаватель издателя
	primeval.identified = true;
	// Изъян: третье поле в записи срока действия
	defect_t prolonged;
	// Записываем лишнюю границу срока действия
	prolonged.prolonged = true;
	// Набор вносимых изъянов
	const defect_t defects[] = {ancient, wrapped, tainted, vacant, sound, primeval, prolonged};
	// Ожидаемые отказы разбора
	const x509::error_t errors[] = {
		x509::error_t::VERSION, x509::error_t::STRUCTURE, x509::error_t::STRUCTURE,
		x509::error_t::EXTENSION, x509::error_t::NONE, x509::error_t::VERSION,
		x509::error_t::STRUCTURE
	};
	/**
	 * Выполняем обход набора вносимых изъянов
	 */
	for(size_t i = 0; i < (sizeof(defects) / sizeof(defects[0])); i++){
		// Создаём записчик записи сертификата
		asn1::writer_t writer;
		// Собираем запись сертификата с очередным изъяном
		build(writer, defects[i]);
		// Проверяем успешность сборки записи сертификата
		ASSERT_EQ(writer.err(), asn1::error_t::NONE) << "изъян " << i;
		// Объект разбираемого сертификата
		x509::certificate_t certificate;
		// Проверяем итог разбора записи с очередным изъяном
		ASSERT_EQ(certificate.parse(writer.data()), errors[i]) << "изъян " << i;
		// Проверяем, что причина отказа хранится сертификатом
		ASSERT_EQ(certificate.err(), errors[i]) << "изъян " << i;
	}
	/**
	 * Байты за концом внешней последовательности сертификата - отказ устройства
	 * записи: длина сертификата объявлена его меткой, и хвост означает подделку
	 */
	asn1::writer_t writer;
	// Собираем годную запись сертификата
	build(writer, defect_t());
	// Получаем собранную запись сертификата
	const view_t whole = writer.data();
	// Переносим собранную запись сертификата
	vector <uint8_t> trailed(whole.data, whole.data + whole.size);
	// Дописываем лишний байт за концом записи сертификата
	trailed.push_back(0x00);
	// Объект разбираемого сертификата
	x509::certificate_t certificate;
	// Проверяем отказ разбора записи с лишним байтом за её концом
	ASSERT_EQ(certificate.parse(view_t(trailed.data(), trailed.size())), x509::error_t::STRUCTURE);
	/**
	 * Хвост ВНУТРИ внешней последовательности - за подписью - ловится своим заслоном:
	 * внешняя длина объявлена с запасом, и байт за подписью в неё входит. Длина
	 * внешней последовательности увеличивается на единицу прямо в записи
	 */
	vector <uint8_t> padded(whole.data, whole.data + whole.size);
	// Дописываем байт внутрь внешней последовательности
	padded.push_back(0x00);
	// Число байтов долгой формы длины внешней последовательности
	const size_t count = ((padded[1] & 0x80) != 0) ? (padded[1] & 0x7F) : 0;
	// Проверяем, что длина записана долгой формой: запись сертификата длиннее 127 байтов
	ASSERT_GT(count, static_cast <size_t> (0));
	/**
	 * Увеличиваем объявленную длину на единицу: младший байт стоит последним
	 */
	for(size_t i = (1 + count); i > 1; i--){
		// Увеличиваем очередной байт длины
		padded[i] = static_cast <uint8_t> (padded[i] + 1);
		// Если переноса в старший байт не случилось
		if(padded[i] != 0)
			// Выходим из увеличения длины
			break;
	}
	// Объект разбираемого сертификата с хвостом внутри
	x509::certificate_t inner;
	// Проверяем отказ разбора записи с хвостом внутри внешней последовательности
	ASSERT_EQ(inner.parse(view_t(padded.data(), padded.size())), x509::error_t::STRUCTURE);
	/**
	 * Признак имени с опознавателем вне таблицы RFC 4514 записывается самим
	 * опознавателем: запись такая разбирается всяким, а короткое обозначение вне
	 * стандарта - лишь тем, кто знает ту же таблицу
	 */
	defect_t serial;
	// Записываем имя владельца порядковым номером
	serial.serial = true;
	// Создаём записчик записи сертификата с порядковым номером в имени
	asn1::writer_t numbered;
	// Собираем запись сертификата с порядковым номером в имени
	build(numbered, serial);
	// Объект разбираемого сертификата с порядковым номером в имени
	x509::certificate_t named;
	// Проверяем успешность разбора сертификата с порядковым номером в имени
	ASSERT_EQ(named.parse(numbered.data()), x509::error_t::NONE);
	// Запись имени владельца сертификата
	string subject;
	// Проверяем успешность записи имени владельца
	ASSERT_EQ(x509::text(named.subjects(), subject), x509::error_t::NONE);
	// Проверяем, что признак записан самим опознавателем
	ASSERT_EQ(subject, string("2.5.4.5=0001"));
}

/**
 * @brief Проверка отказов разборщиков расширений на негодном теле
 *
 * @note Тела эти собираются байтами: записчик таких не составит, а встречаются они
 *       лишь у подделки. Всякий разборщик расширения читает содержимое, пришедшее
 *       извне, и обязан отвергнуть всё, что правилам записи не отвечает
 *
 */
TEST(X509Test, Misextended) {
	// Составляемое расширение сертификата
	x509::extension_t extension;
	// Признак принадлежности удостоверяющему центру
	bool authority = false;
	// Предельная глубина цепочки
	int64_t depth = -1;
	// Устанавливаем опознаватель расширения основных ограничений
	extension.oid = "2.5.29.19";
	// Первое поле ограничений объявлено длиною, которой не набирается
	const uint8_t unfilled[] = {0x30, 0x02, 0x02, 0x05};
	// Устанавливаем тело расширения обрубленным первым полем
	extension.value = view_t(unfilled, sizeof(unfilled));
	// Проверяем отказ разбора ограничений с обрубленным первым полем
	ASSERT_EQ(x509::constraints(extension, authority, depth), x509::error_t::ENCODING);
	// Признак принадлежности записан двумя байтами: истинностное значение занимает один
	const uint8_t doubled[] = {0x30, 0x04, 0x01, 0x02, 0xFF, 0xFF};
	// Устанавливаем тело расширения двухбайтовым признаком принадлежности
	extension.value = view_t(doubled, sizeof(doubled));
	// Проверяем отказ разбора ограничений с двухбайтовым признаком
	ASSERT_EQ(x509::constraints(extension, authority, depth), x509::error_t::EXTENSION);
	/**
	 * Раздел 11.5 X.690: значение по умолчанию кодировка DER не записывает вовсе -
	 * явная ложь признака принадлежности означает запись не по правилам
	 */
	const uint8_t explicitly[] = {0x30, 0x03, 0x01, 0x01, 0x00};
	// Устанавливаем тело расширения явно записанной ложью признака
	extension.value = view_t(explicitly, sizeof(explicitly));
	// Проверяем отказ разбора ограничений с явно записанной ложью
	ASSERT_EQ(x509::constraints(extension, authority, depth), x509::error_t::EXTENSION);
	// Поле глубины вслед за признаком объявлено длиною, которой не набирается
	const uint8_t stunted[] = {0x30, 0x05, 0x01, 0x01, 0xFF, 0x02, 0x05};
	// Устанавливаем тело расширения обрубленным полем глубины
	extension.value = view_t(stunted, sizeof(stunted));
	// Проверяем отказ разбора ограничений с обрубленным полем глубины
	ASSERT_EQ(x509::constraints(extension, authority, depth), x509::error_t::ENCODING);
	// Глубина записана с незначащим старшим байтом: раздел 8.3.2 X.690 велит кратчайшую запись
	const uint8_t padded[] = {0x30, 0x07, 0x01, 0x01, 0xFF, 0x02, 0x02, 0x00, 0x01};
	// Устанавливаем тело расширения глубиной с незначащим байтом
	extension.value = view_t(padded, sizeof(padded));
	// Проверяем отказ разбора ограничений с некратчайшей записью глубины
	ASSERT_EQ(x509::constraints(extension, authority, depth), x509::error_t::EXTENSION);
	// За глубиной цепочки идёт лишнее поле
	const uint8_t overfilled[] = {0x30, 0x08, 0x01, 0x01, 0xFF, 0x02, 0x01, 0x00, 0x05, 0x00};
	// Устанавливаем тело расширения лишним полем за глубиной
	extension.value = view_t(overfilled, sizeof(overfilled));
	// Проверяем отказ разбора ограничений с лишним полем за глубиной
	ASSERT_EQ(x509::constraints(extension, authority, depth), x509::error_t::STRUCTURE);
	// Разряды назначения ключа
	uint16_t usage = 0;
	// Устанавливаем опознаватель расширения назначения ключа
	extension.oid = "2.5.29.15";
	// За строкой разрядов назначения идёт лишнее поле
	const uint8_t trailed[] = {0x03, 0x02, 0x05, 0x80, 0x05, 0x00};
	// Устанавливаем тело расширения лишним полем за разрядами
	extension.value = view_t(trailed, sizeof(trailed));
	// Проверяем отказ разбора назначения с лишним полем
	ASSERT_EQ(x509::usage(extension, usage), x509::error_t::STRUCTURE);
	// Неиспользуемых разрядов объявлено восемь: в байте их не больше семи
	const uint8_t unused[] = {0x03, 0x02, 0x08, 0x80};
	// Устанавливаем тело расширения негодным числом неиспользуемых разрядов
	extension.value = view_t(unused, sizeof(unused));
	// Проверяем отказ разбора назначения с негодным числом неиспользуемых разрядов
	ASSERT_EQ(x509::usage(extension, usage), x509::error_t::EXTENSION);
	// Набор опознавателей расширенного назначения
	vector <string> purposes;
	// Устанавливаем опознаватель расширения расширенного назначения
	extension.oid = "2.5.29.37";
	// Расширенное назначение записано строкой байтов вместо последовательности
	const uint8_t octets[] = {0x04, 0x00};
	// Устанавливаем тело расширения строкой байтов
	extension.value = view_t(octets, sizeof(octets));
	// Проверяем отказ разбора назначения записью не той метки
	ASSERT_EQ(x509::purpose(extension, purposes), x509::error_t::ENCODING);
	// Пустая последовательность назначений
	const uint8_t empty[] = {0x30, 0x00};
	// Устанавливаем тело расширения пустой последовательностью
	extension.value = view_t(empty, sizeof(empty));
	// Проверяем отказ разбора пустого набора назначений
	ASSERT_EQ(x509::purpose(extension, purposes), x509::error_t::EXTENSION);
	// Внутри набора назначений стоит целое число вместо опознавателя
	const uint8_t numeric[] = {0x30, 0x02, 0x02, 0x00};
	// Устанавливаем тело расширения числом на месте опознавателя
	extension.value = view_t(numeric, sizeof(numeric));
	// Проверяем отказ разбора назначения с числом на месте опознавателя
	ASSERT_EQ(x509::purpose(extension, purposes), x509::error_t::ENCODING);
	// Опознаватель оборван на байте с признаком продолжения
	const uint8_t unfinished[] = {0x30, 0x03, 0x06, 0x01, 0x80};
	// Устанавливаем тело расширения оборванным опознавателем
	extension.value = view_t(unfinished, sizeof(unfinished));
	// Проверяем отказ разбора назначения с оборванным опознавателем
	ASSERT_EQ(x509::purpose(extension, purposes), x509::error_t::EXTENSION);
	// Набор дополнительных имён владельца
	vector <x509::alternative_t> names;
	// Устанавливаем опознаватель расширения дополнительных имён
	extension.oid = "2.5.29.17";
	// Устанавливаем тело расширения пустой последовательностью
	extension.value = view_t(empty, sizeof(empty));
	// Проверяем отказ разбора пустого набора имён
	ASSERT_EQ(x509::alternatives(extension, names), x509::error_t::EXTENSION);
	// Имя объявлено длиною, которой не набирается
	const uint8_t cut[] = {0x30, 0x02, 0x82, 0x05};
	// Устанавливаем тело расширения обрубленным именем
	extension.value = view_t(cut, sizeof(cut));
	// Проверяем отказ разбора набора с обрубленным именем
	ASSERT_EQ(x509::alternatives(extension, names), x509::error_t::ENCODING);
	// Имя записано меткой универсального класса: имена размечаются местом употребления
	const uint8_t universal[] = {0x30, 0x02, 0x04, 0x00};
	// Устанавливаем тело расширения именем универсального класса
	extension.value = view_t(universal, sizeof(universal));
	// Проверяем отказ разбора имени универсального класса
	ASSERT_EQ(x509::alternatives(extension, names), x509::error_t::STRUCTURE);
	// Доменное имя несёт знак вне набора IA5
	const uint8_t alien[] = {0x30, 0x04, 0x82, 0x02, 0x41, 0x80};
	// Устанавливаем тело расширения доменным именем со знаком вне набора
	extension.value = view_t(alien, sizeof(alien));
	// Проверяем отказ разбора доменного имени со знаком вне набора IA5
	ASSERT_EQ(x509::alternatives(extension, names), x509::error_t::EXTENSION);
	// Адрес сети записан составной формой
	const uint8_t nested[] = {0x30, 0x02, 0xA7, 0x00};
	// Устанавливаем тело расширения адресом составной формы
	extension.value = view_t(nested, sizeof(nested));
	// Проверяем отказ разбора адреса составной формы
	ASSERT_EQ(x509::alternatives(extension, names), x509::error_t::STRUCTURE);
	// Адрес сети длиною в один байт: IPv4 занимает четыре, IPv6 - шестнадцать
	const uint8_t odd[] = {0x30, 0x03, 0x87, 0x01, 0x00};
	// Устанавливаем тело расширения адресом негодной длины
	extension.value = view_t(odd, sizeof(odd));
	// Проверяем отказ разбора адреса негодной длины
	ASSERT_EQ(x509::alternatives(extension, names), x509::error_t::EXTENSION);
	// Имя каталога записано простой формой: оно обязано быть последовательностью
	const uint8_t flat[] = {0x30, 0x02, 0x84, 0x00};
	// Устанавливаем тело расширения именем каталога простой формы
	extension.value = view_t(flat, sizeof(flat));
	// Проверяем отказ разбора имени каталога простой формы
	ASSERT_EQ(x509::alternatives(extension, names), x509::error_t::STRUCTURE);
	// Опознаватель ключа
	view_t identifier;
	// Устанавливаем опознаватель расширения опознавателя ключа владельца
	extension.oid = "2.5.29.14";
	// Устанавливаем тело расширения последовательностью вместо строки байтов
	extension.value = view_t(empty, sizeof(empty));
	// Проверяем отказ разбора опознавателя владельца записью не той метки
	ASSERT_EQ(x509::subjectKey(extension, identifier), x509::error_t::ENCODING);
	// Устанавливаем опознаватель расширения опознавателя ключа издателя
	extension.oid = "2.5.29.35";
	// Устанавливаем тело расширения строкой байтов вместо последовательности
	extension.value = view_t(octets, sizeof(octets));
	// Проверяем отказ разбора опознавателя издателя записью не той метки
	ASSERT_EQ(x509::authorityKey(extension, identifier), x509::error_t::ENCODING);
	// Поле опознавателя издателя объявлено длиною, которой не набирается
	const uint8_t broken[] = {0x30, 0x02, 0x80, 0x05};
	// Устанавливаем тело расширения обрубленным полем
	extension.value = view_t(broken, sizeof(broken));
	// Проверяем отказ разбора опознавателя издателя с обрубленным полем
	ASSERT_EQ(x509::authorityKey(extension, identifier), x509::error_t::ENCODING);
	// Поле с номером метки выше дозволенных: устройство записи знает лишь [0], [1] и [2]
	const uint8_t beyond[] = {0x30, 0x02, 0x83, 0x00};
	// Устанавливаем тело расширения полем с чужим номером метки
	extension.value = view_t(beyond, sizeof(beyond));
	// Проверяем отказ разбора опознавателя издателя с чужим номером метки
	ASSERT_EQ(x509::authorityKey(extension, identifier), x509::error_t::STRUCTURE);
	// Опознаватель ключа [0] записан составной формой: он строка байтов, а не набор
	const uint8_t composite[] = {0x30, 0x02, 0xA0, 0x00};
	// Устанавливаем тело расширения опознавателем составной формы
	extension.value = view_t(composite, sizeof(composite));
	// Проверяем отказ разбора опознавателя ключа составной формы
	ASSERT_EQ(x509::authorityKey(extension, identifier), x509::error_t::STRUCTURE);
}

/**
 * @brief Проверка согласованности опознавателей и повтора признака имени
 *
 */
TEST(X509Test, Consistent){
	defect_t defect;
	defect.mismatched = true;
	asn1::writer_t writer;
	build(writer, defect);
	x509::certificate_t certificate;
	/**
	 * Разделы 4.1.1.2 и 4.1.2.3 RFC 5280: опознаватель алгоритма подписи снаружи
	 * обязан совпадать с опознавателем внутри подписываемой части
	 */
	ASSERT_EQ(certificate.parse(writer.data()), x509::error_t::STRUCTURE);
	defect_t twice;
	twice.doubled = true;
	asn1::writer_t again;
	build(again, twice);
	// X.501: два признака одного вида в одной составляющей имени - повтор
	ASSERT_EQ(certificate.parse(again.data()), x509::error_t::DUPLICATE);
}
/**
 * @brief Проверка разбора при нехватке памяти
 *
 * @note Разбор сертификата, сборка записи имени и извлечение дополнительных имён
 *       выделяют память, и на всяком запасе выделений они обязаны ответить либо
 *       успехом, либо отказом памяти, но не прерыванием исполнения
 *
 */
TEST(X509Test, Starved) {
	// Создаём записчик записи сертификата
	asn1::writer_t writer;
	// Собираем запись сертификата
	build(writer, defect_t());
	// Проверяем успешность сборки записи сертификата
	ASSERT_EQ(writer.err(), asn1::error_t::NONE);
	// Признак того, что нехватка памяти при разборе хоть раз объявлена отказом
	bool starved = false;
	/**
	 * Выполняем перебор запасов выделений при разборе записи сертификата
	 */
	for(size_t budget = 0; budget < 512; budget++){
		// Создаём объект сертификата
		x509::certificate_t certificate;
		// Итог разбора при отмеренном запасе
		x509::error_t outcome = x509::error_t::NONE;
		{
			// Отмеряем запас выделений на время разбора
			starve::ration_t ration(budget);
			// Выполняем разбор записи сертификата при отмеренном запасе
			outcome = certificate.parse(writer.data());
		}
		// Проверяем, что разбор ответил успехом либо отказом памяти
		ASSERT_TRUE((outcome == x509::error_t::NONE) || (outcome == x509::error_t::MEMORY)) << "запас " << budget;
		// Проверяем, что запомненная причина отказа совпадает с отвеченной
		ASSERT_EQ(certificate.err(), outcome) << "запас " << budget;
		// Запоминаем объявленный отказ памяти
		starved = (starved || (outcome == x509::error_t::MEMORY));
	}
	// Проверяем, что нехватка памяти при разборе объявлена отказом хоть раз
	ASSERT_TRUE(starved);
	// Имя с длинным значением признака: короткое значение памяти не выделяет
	x509::name_t name;
	// Признак имени с длинным значением
	x509::attribute_t attribute;
	// Устанавливаем опознаватель общего имени
	attribute.oid = "2.5.4.3";
	// Устанавливаем длинное значение общего имени
	attribute.value = "a-rather-long-common-name-for-the-starvation-check.anyks.com";
	// Добавляем составляющую имени с единственным признаком
	name.parts.push_back(vector <x509::attribute_t> (1, attribute));
	// Сбрасываем признак объявленного отказа памяти
	starved = false;
	/**
	 * Выполняем перебор запасов выделений при сборке записи имени
	 */
	for(size_t budget = 0; budget < 512; budget++){
		// Собранная запись имени
		std::string text;
		// Итог сборки при отмеренном запасе
		x509::error_t outcome = x509::error_t::NONE;
		{
			// Отмеряем запас выделений на время сборки
			starve::ration_t ration(budget);
			// Выполняем сборку записи имени при отмеренном запасе
			outcome = x509::text(name, text);
		}
		// Проверяем, что сборка ответила успехом либо отказом памяти
		ASSERT_TRUE((outcome == x509::error_t::NONE) || (outcome == x509::error_t::MEMORY)) << "запас " << budget;
		// Если сборка удалась
		if(outcome == x509::error_t::NONE){
			// Проверяем собранную запись имени
			ASSERT_STREQ(text.c_str(), "CN=a-rather-long-common-name-for-the-starvation-check.anyks.com") << "запас " << budget;
		}
		// Запоминаем объявленный отказ памяти
		starved = (starved || (outcome == x509::error_t::MEMORY));
	}
	// Проверяем, что нехватка памяти при сборке объявлена отказом хоть раз
	ASSERT_TRUE(starved);
	// Создаём записчик записи дополнительных имён
	asn1::writer_t named;
	// Открываем последовательность дополнительных имён
	named.open(asn1::tag_t::SEQUENCE);
	// Записываем доменное имя с длинным значением меткой второго места употребления
	named.element(asn1::cls_t::CONTEXT, false, 2, view_t(reinterpret_cast <const uint8_t *> ("a-rather-long-alternative-name.anyks.com"), 40));
	// Записываем второе доменное имя с длинным значением
	named.element(asn1::cls_t::CONTEXT, false, 2, view_t(reinterpret_cast <const uint8_t *> ("another-long-alternative-name.anyks.com"), 39));
	// Закрываем последовательность дополнительных имён
	named.close();
	// Проверяем успешность сборки записи дополнительных имён
	ASSERT_EQ(named.err(), asn1::error_t::NONE);
	// Составляемое расширение дополнительных имён
	x509::extension_t extension;
	// Устанавливаем опознаватель расширения дополнительных имён
	extension.oid = "2.5.29.17";
	// Устанавливаем тело расширения дополнительных имён
	extension.value = named.data();
	// Сбрасываем признак объявленного отказа памяти
	starved = false;
	/**
	 * Выполняем перебор запасов выделений при извлечении дополнительных имён
	 */
	for(size_t budget = 0; budget < 512; budget++){
		// Набор извлечённых дополнительных имён
		vector <x509::alternative_t> alternatives;
		// Итог извлечения при отмеренном запасе
		x509::error_t outcome = x509::error_t::NONE;
		{
			// Отмеряем запас выделений на время извлечения
			starve::ration_t ration(budget);
			// Выполняем извлечение дополнительных имён при отмеренном запасе
			outcome = x509::alternatives(extension, alternatives);
		}
		// Проверяем, что извлечение ответило успехом либо отказом памяти
		ASSERT_TRUE((outcome == x509::error_t::NONE) || (outcome == x509::error_t::MEMORY)) << "запас " << budget;
		// Если извлечение удалось
		if(outcome == x509::error_t::NONE){
			// Проверяем число извлечённых дополнительных имён
			ASSERT_EQ(alternatives.size(), size_t(2)) << "запас " << budget;
		}
		// Запоминаем объявленный отказ памяти
		starved = (starved || (outcome == x509::error_t::MEMORY));
	}
	// Проверяем, что нехватка памяти при извлечении объявлена отказом хоть раз
	ASSERT_TRUE(starved);
}
