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
	/**
	 * @brief Конструктор
	 *
	 */
	Defect() noexcept :
		version(false), release(false), critical(false),
		duplicate(false), generalized(false), trailing(false), order(false) {}
} defect_t;

/**
 * @brief Метод записи отличительного имени
 *
 * @param writer записчик записи
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
	// Записываем начало срока действия сертификата
	writer.time((defect.generalized ? asn1::tag_t::GENERALIZED_TIME : asn1::tag_t::UTC_TIME), 1787747696);
	// Записываем окончание срока действия сертификата
	writer.time(asn1::tag_t::UTC_TIME, 1819283696);
	// Закрываем запись срока действия сертификата
	writer.close();
	// Записываем имя владельца сертификата
	name(writer, "anyks.com");
	// Открываем запись сведений об открытом ключе
	writer.open(asn1::tag_t::SEQUENCE);
	// Записываем опознаватель алгоритма ключа
	algorithm(writer, "1.2.840.113549.1.1.1");
	// Записываем открытый ключ
	writer.bits(view_t(key, sizeof(key)));
	// Закрываем запись сведений об открытом ключе
	writer.close();
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
	const size_t count = (defect.duplicate ? 2 : 1);
	/**
	 * Выполняем запись расширений основных ограничений
	 */
	for(size_t i = 0; i < count; i++){
		// Содержимое расширения основных ограничений
		asn1::writer_t inner;
		// Открываем запись основных ограничений
		inner.open(asn1::tag_t::SEQUENCE);
		// Записываем признак принадлежности удостоверяющему центру
		inner.boolean(true);
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
	algorithm(writer, "1.2.840.113549.1.1.11");
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
		 * Разбор усечённой записи обязан обойтись без отказа работы: итог его здесь
		 * не судится, ибо усечение вправе оставить запись и разбираемой
		 */
		(void) certificate.parse(view_t(origin.data(), size));
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
}
