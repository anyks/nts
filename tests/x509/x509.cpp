/**
 * @file x509.cpp
 * @date 2026-08-27
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
using namespace anyks;

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
