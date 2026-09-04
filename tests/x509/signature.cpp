/**
 * @file signature.cpp
 * @date 2026-08-29
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
 * @brief Исходный файл проверок модуля проверки подписи сертификата X.509
 *
 * @note Сертификаты взяты из приложения D RFC 9215 все три: два с ключом длиной 256
 *       разрядов на разных кривых и один с ключом длиной 512 разрядов. Всякий из них
 *       подписан своим же ключом, оттого проверка не требует ни цепочки, ни хранилища
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Подключаем заголовочные файлы проекта
 */
#include <vector>
#include <string>
#include <cstring>
#include <main.hpp>
#include <starve.hpp>
#include <asn1/asn1.hpp>
#include <x509/signature.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Сертификат раздела D.1.2 RFC 9215: ключ 256 разрядов на испытательной кривой RFC 7091
 */
static const char * CERTIFICATE_FIRST =
	"3082012d3081dba00302010202010a300a06082a850307010103023012311030"
	"0e060355040313074578616d706c653020170d3031303130313030303030305a"
	"180f32303530313233313030303030305a30123110300e060355040313074578"
	"616d706c653066301f06082a85030701010101301306072a8503020223000608"
	"2a8503070101020203430004400bd86fe5d8db89668f789b4e1dba8585c5508b"
	"45ec5b59d8906ddb70e2492b7fda77ff871a10fbdf2766d293c5d164afbb3c7b"
	"973a41c885d11d70d689b4f126a3133011300f0603551d130101ff0405300301"
	"01ff300a06082a850307010103020341004d53f012fe081776507d4d9bb81f00"
	"efdb4eefd4ab83bac4bacf735173cfa81c41aa28d2f1ab148280cd9ed56feda4"
	"1974053554a42767b83ad043fd39dc0493";

/**
 * Сертификат раздела D.2.2 RFC 9215: ключ 256 разрядов на кривой id-tc26-gost-3410-2012-256-paramSetA
 */
static const char * CERTIFICATE_SECOND =
	"308201253081d3a00302010202010a300a06082a850307010103023012311030"
	"0e060355040313074578616d706c653020170d3031303130313030303030305a"
	"180f32303530313233313030303030305a30123110300e060355040313074578"
	"616d706c65305e301706082a85030701010101300b06092a8503070102010101"
	"0343000440742795d4bee884ddf2850fec03ea3faf1844e01d9da60b645093a5"
	"5e26dfc39978f596cf4d4d0c6cf1d18943d94493d16b9ec0a16d512d2e127cc4"
	"691a6318e2a3133011300f0603551d130101ff040530030101ff300a06082a85"
	"030701010302034100140b4da9124b09cb0d5ce928ee874273a310129492ec0e"
	"29369e3b791248578c1d0e1da5be347c6f1b5256c7aeac200ad64ac77a6f5b3a"
	"0e097318e7ae6ee769";

/**
 * Сертификат раздела D.3.2 RFC 9215: ключ 512 разрядов на испытательной кривой приложения E
 */
static const char * CERTIFICATE_THIRD =
	"308201aa30820116a00302010202010b300a06082a8503070101030330123110"
	"300e060355040313074578616d706c653020170d303130313031303030303030"
	"5a180f32303530313233313030303030305a30123110300e0603550403130745"
	"78616d706c653081a0301706082a85030701010102300b06092a850307010201"
	"020003818400048180e1ef30d52c6133ddd99d1d5c41455cf7df4d8b4c925bbc"
	"69af1433d15658515add2146850c325c5b81c133be655aa8c4d440e7b98a8d59"
	"487b0c7696bcc55d11ecbe7736a9ec357ff2fd39931f4e114cb8cda359270ac7"
	"f0e7ff43d9419419ea61fd2ab77f5d9f63523d3b50a04f63e2a0cf51b7c13adc"
	"21560f0bd40cc9c737a3133011300f0603551d130101ff040530030101ff300a"
	"06082a8503070101030303818100415703d892f1a5f3f68c4353189a7ee207b8"
	"0b5631ef9d49529a4d6b542c2cfa15aa2eacf11f470fde7d954856903c35fd8f"
	"955ef300d95c77534a724a0eee702f86fa60a081091a23dd795e1e3c689ee512"
	"a3c82ee0dcc2643c78eea8fcacd35492558486b20f1c9ec197c90699850260c9"
	"3bcbcd9c5c3317e19344e173ae36";
/**
 * @brief Метод разбора записи сертификата шестнадцатеричными знаками
 *
 * @param text разбираемая запись сертификата
 *
 * @return     разобранная запись сертификата
 *
 */
static std::vector <uint8_t> bytes(const char * text) {
	// Разобранная запись сертификата
	std::vector <uint8_t> result;
	/**
	 * Выполняем перебор пар знаков разбираемой записи
	 */
	for(size_t i = 0; text[i * 2] != '\0'; i++){
		// Собираемое значение байта
		uint8_t value = 0;
		/**
		 * Выполняем перебор знаков очередной пары
		 */
		for(size_t j = 0; j < 2; j++){
			// Извлекаем очередной знак записи
			const char letter = text[(i * 2) + j];
			// Дополняем значение байта очередным знаком записи
			value = static_cast <uint8_t> ((value << 4) | ((letter <= '9') ? (letter - '0') : ((letter - 'a') + 10)));
		}
		// Записываем разобранный байт
		result.push_back(value);
	}
	// Выводим разобранную запись сертификата
	return result;
}

/**
 * Набор проверяемых сертификатов
 */
static const char * CERTIFICATES[3] = {
	CERTIFICATE_FIRST,
	CERTIFICATE_SECOND,
	CERTIFICATE_THIRD
};

/**
 * @brief Проверка подписи сертификатов контрольного приложения
 *
 */
TEST(SignatureTest, Certificates) {
	/**
	 * Выполняем перебор проверяемых сертификатов
	 */
	for(size_t i = 0; i < (sizeof(CERTIFICATES) / sizeof(const char *)); i++){
		// Выполняем разбор записи очередного сертификата
		const std::vector <uint8_t> data = bytes(CERTIFICATES[i]);
		// Объект разбираемого сертификата
		x509::certificate_t certificate;
		// Выполняем разбор сертификата
		ASSERT_EQ(certificate.parse(view_t(data.data(), data.size())), x509::error_t::NONE) << "Сертификат: " << i;
		/**
		 * Сертификаты подписаны своими же ключами, оттого подпись проверяется
		 * сведениями об открытом ключе самого сертификата
		 */
		ASSERT_EQ(x509::verify(certificate, certificate.key()), x509::error_t::NONE) << "Сертификат: " << i;
	}
}
/**
 * @brief Проверка отказа при порче подписанного сертификата
 *
 */
TEST(SignatureTest, Forgery) {
	/**
	 * Выполняем перебор проверяемых сертификатов
	 */
	for(size_t i = 0; i < (sizeof(CERTIFICATES) / sizeof(const char *)); i++){
		// Выполняем разбор записи очередного сертификата
		std::vector <uint8_t> data = bytes(CERTIFICATES[i]);
		// Объект разбираемого сертификата
		x509::certificate_t certificate;
		// Выполняем разбор сертификата
		ASSERT_EQ(certificate.parse(view_t(data.data(), data.size())), x509::error_t::NONE) << "Сертификат: " << i;
		// Получаем подписанное тело сертификата
		const view_t & body = certificate.body();
		// Определяем место тела сертификата внутри его записи
		const size_t offset = static_cast <size_t> (body.data - data.data());
		/**
		 * Выполняем перебор байтов подписанного тела сертификата с шагом, дающим
		 * порчу и внутри имён, и внутри сроков, и внутри самого открытого ключа
		 */
		for(size_t j = 0; j < body.size; j += 7){
			// Выполняем порчу очередного байта тела сертификата
			data[offset + j] = static_cast <uint8_t> (data[offset + j] ^ 0x01);
			// Объект разбираемого испорченного сертификата
			x509::certificate_t item;
			/**
			 * Если испорченный сертификат всё же разобрался
			 *
			 * @note Тело проверки взято в скобки намеренно: макрос проверки сам
			 *       разворачивается в условие, и без скобок собиратель не берётся
			 *       судить, к какому из двух условий отнести продолжение
			 */
			if(item.parse(view_t(data.data(), data.size())) == x509::error_t::NONE){
				// Проверяем отказ проверки подписи испорченного сертификата
				ASSERT_NE(x509::verify(item, item.key()), x509::error_t::NONE) << "Сертификат: " << i << ", место порчи: " << j;
			}
			// Выполняем восстановление очередного байта тела сертификата
			data[offset + j] = static_cast <uint8_t> (data[offset + j] ^ 0x01);
		}
		// Число неиспользуемых разрядов последнего байта подписи
		uint8_t unused = 0;
		// Получаем подпись сертификата
		const view_t & signature = certificate.sign(unused);
		// Определяем место подписи внутри записи сертификата
		const size_t place = static_cast <size_t> (signature.data - data.data());
		/**
		 * Выполняем перебор байтов подписи сертификата
		 */
		for(size_t j = 0; j < signature.size; j += 5){
			// Выполняем порчу очередного байта подписи
			data[place + j] = static_cast <uint8_t> (data[place + j] ^ 0x01);
			// Объект разбираемого сертификата с испорченной подписью
			x509::certificate_t item;
			// Выполняем разбор сертификата с испорченной подписью
			ASSERT_EQ(item.parse(view_t(data.data(), data.size())), x509::error_t::NONE) << "Сертификат: " << i;
			// Проверяем отказ проверки испорченной подписи
			ASSERT_NE(x509::verify(item, item.key()), x509::error_t::NONE) << "Сертификат: " << i << ", место порчи: " << j;
			// Выполняем восстановление очередного байта подписи
			data[place + j] = static_cast <uint8_t> (data[place + j] ^ 0x01);
		}
	}
}
/**
 * @brief Проверка отказа при чужом открытом ключе
 *
 */
TEST(SignatureTest, Foreign) {
	// Выполняем разбор записей первого и второго сертификатов
	const std::vector <uint8_t> first = bytes(CERTIFICATE_FIRST);
	// Выполняем разбор записи второго сертификата
	const std::vector <uint8_t> second = bytes(CERTIFICATE_SECOND);
	// Выполняем разбор записи третьего сертификата
	const std::vector <uint8_t> third = bytes(CERTIFICATE_THIRD);
	// Объекты разбираемых сертификатов
	x509::certificate_t one, two, three;
	// Выполняем разбор первого сертификата
	ASSERT_EQ(one.parse(view_t(first.data(), first.size())), x509::error_t::NONE);
	// Выполняем разбор второго сертификата
	ASSERT_EQ(two.parse(view_t(second.data(), second.size())), x509::error_t::NONE);
	// Выполняем разбор третьего сертификата
	ASSERT_EQ(three.parse(view_t(third.data(), third.size())), x509::error_t::NONE);
	// Проверяем отказ проверки подписи ключом с другой кривой той же разрядности
	ASSERT_NE(x509::verify(one, two.key()), x509::error_t::NONE);
	// Проверяем отказ проверки подписи ключом другой разрядности
	ASSERT_NE(x509::verify(one, three.key()), x509::error_t::NONE);
	// Проверяем отказ проверки подписи длинного сертификата коротким ключом
	ASSERT_NE(x509::verify(three, one.key()), x509::error_t::NONE);
	// Проверяем схождение подписи всякого сертификата своим же ключом
	ASSERT_EQ(x509::verify(one, one.key()), x509::error_t::NONE);
	// Проверяем схождение подписи второго сертификата своим же ключом
	ASSERT_EQ(x509::verify(two, two.key()), x509::error_t::NONE);
	// Проверяем схождение подписи третьего сертификата своим же ключом
	ASSERT_EQ(x509::verify(three, three.key()), x509::error_t::NONE);
}
/**
 * @brief Проверка отказов модуля проверки подписи
 *
 */
TEST(SignatureTest, Failures) {
	// Выполняем разбор записи первого сертификата
	const std::vector <uint8_t> data = bytes(CERTIFICATE_FIRST);
	// Объект разбираемого сертификата
	x509::certificate_t certificate;
	// Выполняем разбор сертификата
	ASSERT_EQ(certificate.parse(view_t(data.data(), data.size())), x509::error_t::NONE);
	// Число неиспользуемых разрядов последнего байта подписи
	uint8_t unused = 0;
	// Получаем подпись сертификата
	const view_t & signature = certificate.sign(unused);
	// Получаем сведения об открытом ключе сертификата
	const x509::key_t & key = certificate.key();
	// Проверяем отказ проверки подписи непереданной записи
	ASSERT_NE(x509::verify(view_t(), signature, certificate.algorithms(), key), x509::error_t::NONE);
	// Проверяем отказ проверки непереданной подписи
	ASSERT_NE(x509::verify(certificate.body(), view_t(), certificate.algorithms(), key), x509::error_t::NONE);
	// Проверяем отказ проверки подписи неизвестного алгоритма
	ASSERT_NE(x509::verify(certificate.body(), signature, std::string("1.2.840.113549.1.1.11"), key), x509::error_t::NONE);
	// Проверяем отказ проверки подписи по устаревшему хешу ГОСТ Р 34.11-94
	ASSERT_NE(x509::verify(certificate.body(), signature, std::string("1.2.643.2.2.3"), key), x509::error_t::NONE);
	// Проверяем отказ проверки подписи неполной длины
	ASSERT_NE(x509::verify(certificate.body(), view_t(signature.data, signature.size - 1), certificate.algorithms(), key), x509::error_t::NONE);
	// Сведения об открытом ключе с непригодным алгоритмом
	x509::key_t item = key;
	// Подменяем опознаватель алгоритма открытого ключа
	item.algorithm = std::string("1.2.840.10045.2.1");
	// Проверяем отказ проверки подписи ключом непригодного алгоритма
	ASSERT_NE(x509::verify(certificate.body(), signature, certificate.algorithms(), item), x509::error_t::NONE);
	// Восстанавливаем опознаватель алгоритма открытого ключа
	item.algorithm = key.algorithm;
	// Сбрасываем настройки алгоритма открытого ключа
	item.parameters = view_t();
	// Проверяем отказ проверки подписи ключом без настроек алгоритма
	ASSERT_NE(x509::verify(certificate.body(), signature, certificate.algorithms(), item), x509::error_t::NONE);
	// Восстанавливаем настройки алгоритма открытого ключа
	item.parameters = key.parameters;
	// Сбрасываем запись открытого ключа
	item.key = view_t();
	// Проверяем отказ проверки подписи без записи открытого ключа
	ASSERT_NE(x509::verify(certificate.body(), signature, certificate.algorithms(), item), x509::error_t::NONE);
	// Проверяем схождение подписи после восстановления всех значений
	ASSERT_EQ(x509::verify(certificate.body(), signature, certificate.algorithms(), key), x509::error_t::NONE);
}

/**
 * Проверка отказов проверки подписи на негодные доводы
 */
TEST(SignatureTest, Unsigned) {
	// Подписанная запись, подпись которой проверяется
	const vector <uint8_t> body(64, 0x41);
	// Подпись, сходимость которой проверяется
	const vector <uint8_t> signature(64, 0x3C);
	// Ключ проверки подписи, оставленный незаполненным
	x509::key_t key;
	// Проверяем отказ проверки подписи без подписанной записи
	ASSERT_NE(x509::verify(view_t(nullptr, body.size()), view_t(signature.data(), signature.size()), "1.2.643.7.1.1.3.2", key), x509::error_t::NONE);
	// Проверяем отказ проверки подписи с подписанной записью нулевой длины
	ASSERT_NE(x509::verify(view_t(body.data(), 0), view_t(signature.data(), signature.size()), "1.2.643.7.1.1.3.2", key), x509::error_t::NONE);
	// Проверяем отказ проверки подписи без самой подписи
	ASSERT_NE(x509::verify(view_t(body.data(), body.size()), view_t(nullptr, signature.size()), "1.2.643.7.1.1.3.2", key), x509::error_t::NONE);
	// Проверяем отказ проверки подписи на неизвестном алгоритме
	ASSERT_NE(x509::verify(view_t(body.data(), body.size()), view_t(signature.data(), signature.size()), "1.2.3.4.5", key), x509::error_t::NONE);
	// Проверяем отказ проверки подписи содержимого без содержимого
	ASSERT_NE(x509::check(key, view_t(nullptr, body.size()), view_t(signature.data(), signature.size())), x509::error_t::NONE);
	// Проверяем отказ проверки подписи содержимого с содержимым нулевой длины
	ASSERT_NE(x509::check(key, view_t(body.data(), 0), view_t(signature.data(), signature.size())), x509::error_t::NONE);
	// Проверяем отказ проверки подписи содержимого без самой подписи
	ASSERT_NE(x509::check(key, view_t(body.data(), body.size()), view_t(nullptr, signature.size())), x509::error_t::NONE);
	/**
	 * Ключ, у которого настройки алгоритма не переданы вовсе, отвергается заслоном
	 * извлечения опознавателя кривой: опознаватель тот берётся из настроек, и брать
	 * его не из чего
	 */
	key.algorithm = "1.2.643.7.1.1.1.1";
	// Проверяем отказ проверки подписи с непереданными настройками алгоритма ключа
	ASSERT_NE(x509::check(key, view_t(body.data(), body.size()), view_t(signature.data(), signature.size())), x509::error_t::NONE);
	// Устанавливаем настройки алгоритма ключа нулевой длины
	key.parameters = view_t(body.data(), 0);
	// Проверяем отказ проверки подписи с настройками алгоритма нулевой длины
	ASSERT_NE(x509::check(key, view_t(body.data(), body.size()), view_t(signature.data(), signature.size())), x509::error_t::NONE);
	// Создаём записчик записи настроек алгоритма ключа
	asn1::writer_t parameters;
	// Открываем последовательность настроек алгоритма ключа
	parameters.open(asn1::tag_t::SEQUENCE);
	// Записываем опознаватель набора параметров кривой
	parameters.oid("1.2.643.7.1.2.1.1.1");
	// Закрываем последовательность настроек алгоритма ключа
	parameters.close();
	// Проверяем успешность сборки записи настроек алгоритма ключа
	ASSERT_EQ(parameters.err(), asn1::error_t::NONE);
	// Устанавливаем составленные настройки алгоритма ключа
	key.parameters = parameters.data();
	/**
	 * Настройки теперь годны, а вот запись открытого ключа не передана: отказ обязан
	 * прийти уже от извлечения координат, а не от разбора настроек
	 */
	ASSERT_NE(x509::check(key, view_t(body.data(), body.size()), view_t(signature.data(), signature.size())), x509::error_t::NONE);
	// Устанавливаем запись открытого ключа нулевой длины
	key.key = view_t(body.data(), 0);
	// Проверяем отказ проверки подписи с записью открытого ключа нулевой длины
	ASSERT_NE(x509::check(key, view_t(body.data(), body.size()), view_t(signature.data(), signature.size())), x509::error_t::NONE);
}

/**
 * @brief Проверка отказов на негодную запись ключевого материала
 *
 * @note Заслоны эти стерегут разбор записей, взятых из сертификата, а стало быть
 *       приходящих извне; исправные сертификаты приложения D RFC 9215 ни один из
 *       них не задевают, оттого всякая негодная запись собирается здесь вручную
 *
 */
TEST(SignatureTest, Malformed) {
	// Подписанное содержимое, подпись которого проверяется
	const vector <uint8_t> body(64, 0x41);
	// Подпись длиной в два числа порядка подгруппы кривой длиной 256 разрядов
	const vector <uint8_t> signature(64, 0x3C);
	// Запись координат открытого ключа длиной в две координаты кривой
	const vector <uint8_t> point(64, 0x5A);
	// Создаём записчик исправной записи настроек алгоритма ключа
	asn1::writer_t sound;
	// Открываем последовательность настроек алгоритма ключа
	sound.open(asn1::tag_t::SEQUENCE);
	// Записываем опознаватель набора параметров кривой
	sound.oid("1.2.643.7.1.2.1.1.1");
	// Закрываем последовательность настроек алгоритма ключа
	sound.close();
	// Проверяем успешность сборки записи настроек алгоритма ключа
	ASSERT_EQ(sound.err(), asn1::error_t::NONE);
	// Создаём записчик исправной записи открытого ключа
	asn1::writer_t opened;
	// Записываем строку байтов координат открытого ключа
	opened.octets(view_t(point.data(), point.size()));
	// Проверяем успешность сборки записи открытого ключа
	ASSERT_EQ(opened.err(), asn1::error_t::NONE);
	// Сведения об открытом ключе, собираемые вручную
	x509::key_t key;
	// Устанавливаем опознаватель алгоритма открытого ключа
	key.algorithm = "1.2.643.7.1.1.1.1";
	// Устанавливаем исправную запись настроек алгоритма ключа
	key.parameters = sound.data();
	// Устанавливаем исправную запись открытого ключа
	key.key = opened.data();
	/**
	 * Настройки алгоритма ключа записаны последовательностью: раздел 2.1 RFC 9215.
	 * Запись иного вида отвергается ещё до захода внутрь
	 */
	asn1::writer_t alien;
	// Записываем настройки алгоритма ключа строкой байтов вместо последовательности
	alien.octets(view_t(point.data(), 8));
	// Проверяем успешность сборки чужеродной записи настроек
	ASSERT_EQ(alien.err(), asn1::error_t::NONE);
	// Подменяем настройки алгоритма ключа записью чужеродного вида
	key.parameters = alien.data();
	// Проверяем отказ проверки подписи на настройках чужеродного вида
	ASSERT_NE(x509::check(key, view_t(body.data(), body.size()), view_t(signature.data(), signature.size())), x509::error_t::NONE);
	/**
	 * Первым внутри последовательности настроек стоит опознаватель набора параметров
	 * кривой, и никакой иной элемент его места занять не вправе
	 */
	asn1::writer_t numeric;
	// Открываем последовательность настроек алгоритма ключа
	numeric.open(asn1::tag_t::SEQUENCE);
	// Записываем число вместо опознавателя набора параметров кривой
	numeric.integer(1);
	// Закрываем последовательность настроек алгоритма ключа
	numeric.close();
	// Проверяем успешность сборки записи настроек с числом внутри
	ASSERT_EQ(numeric.err(), asn1::error_t::NONE);
	// Подменяем настройки алгоритма ключа записью с числом вместо опознавателя
	key.parameters = numeric.data();
	// Проверяем отказ проверки подписи на настройках без опознавателя кривой
	ASSERT_NE(x509::check(key, view_t(body.data(), body.size()), view_t(signature.data(), signature.size())), x509::error_t::NONE);
	// Восстанавливаем исправную запись настроек алгоритма ключа
	key.parameters = sound.data();
	/**
	 * Раздел 4 RFC 9215 велит нести координаты открытого ключа строкой байтов.
	 * Запись иного вида отвергается извлечением координат
	 */
	asn1::writer_t wrapped;
	// Открываем последовательность вместо строки байтов открытого ключа
	wrapped.open(asn1::tag_t::SEQUENCE);
	// Записываем координаты открытого ключа внутрь последовательности
	wrapped.octets(view_t(point.data(), point.size()));
	// Закрываем последовательность открытого ключа
	wrapped.close();
	// Проверяем успешность сборки записи открытого ключа чужеродного вида
	ASSERT_EQ(wrapped.err(), asn1::error_t::NONE);
	// Подменяем запись открытого ключа записью чужеродного вида
	key.key = wrapped.data();
	// Проверяем отказ проверки подписи на записи ключа чужеродного вида
	ASSERT_NE(x509::check(key, view_t(body.data(), body.size()), view_t(signature.data(), signature.size())), x509::error_t::NONE);
	/**
	 * Строка байтов открытого ключа занимает ровно две координаты точки кривой:
	 * строка иной длины на кривую не ложится
	 */
	asn1::writer_t stunted;
	// Записываем строку байтов короче двух координат точки кривой
	stunted.octets(view_t(point.data(), point.size() - 1));
	// Проверяем успешность сборки укороченной записи открытого ключа
	ASSERT_EQ(stunted.err(), asn1::error_t::NONE);
	// Подменяем запись открытого ключа укороченной записью
	key.key = stunted.data();
	// Проверяем отказ проверки подписи на укороченной записи открытого ключа
	ASSERT_NE(x509::check(key, view_t(body.data(), body.size()), view_t(signature.data(), signature.size())), x509::error_t::NONE);
	// Восстанавливаем исправную запись открытого ключа
	key.key = opened.data();
	/**
	 * Подпись занимает два числа длиной в порядок подгруппы точек кривой: длина
	 * иная означает подпись, к этой кривой не относящуюся
	 */
	ASSERT_NE(x509::check(key, view_t(body.data(), body.size()), view_t(signature.data(), signature.size() - 1)), x509::error_t::NONE);
	/**
	 * Координаты исправной длины, но точке кривой не отвечающие, отвергаются
	 * установкой открытого ключа: точка вне кривой ключом быть не может
	 */
	ASSERT_NE(x509::check(key, view_t(body.data(), body.size()), view_t(signature.data(), signature.size())), x509::error_t::NONE);
	/**
	 * Извлечение опознавателя набора параметров и заведение кривой стоят открытыми
	 * приёмами, и всякий из них судит пригодность алгоритма ключа сам за себя
	 */
	string oid;
	// Эллиптическая кривая, заводимая по сведениям об открытом ключе
	curve::curve_t curve;
	// Проверяем схождение извлечения опознавателя на исправных сведениях о ключе
	ASSERT_EQ(x509::identifier(key, oid), x509::error_t::NONE);
	// Проверяем совпадение извлечённого опознавателя набора параметров кривой
	ASSERT_EQ(oid, string("1.2.643.7.1.2.1.1.1"));
	// Проверяем схождение заведения кривой на исправных сведениях о ключе
	ASSERT_EQ(x509::parameters(key, curve), x509::error_t::NONE);
	// Подменяем опознаватель алгоритма ключа опознавателем чужого алгоритма
	key.algorithm = "1.2.840.10045.2.1";
	// Проверяем отказ извлечения опознавателя на чужом алгоритме ключа
	ASSERT_EQ(x509::identifier(key, oid), x509::error_t::KEY);
	// Проверяем отказ заведения кривой на чужом алгоритме ключа
	ASSERT_EQ(x509::parameters(key, curve), x509::error_t::KEY);
	// Восстанавливаем опознаватель алгоритма открытого ключа
	key.algorithm = "1.2.643.7.1.1.1.1";
	// Сбрасываем запись настроек алгоритма ключа
	key.parameters = view_t();
	// Проверяем отказ заведения кривой без записи настроек алгоритма ключа
	ASSERT_EQ(x509::parameters(key, curve), x509::error_t::KEY);
}

/**
 * @brief Проверка отказа на подпись сертификата неполного числа байтов
 *
 */
TEST(SignatureTest, Fractional) {
	// Выполняем разбор записи первого сертификата
	vector <uint8_t> data = bytes(CERTIFICATE_FIRST);
	/**
	 * Подпись сертификата записана разрядной строкой, первый байт содержимого
	 * которой несёт число неиспользуемых разрядов последнего байта. Подпись занимает
	 * целое число байтов, оттого число это обязано быть нулевым: раздел 4.1.1.3
	 * RFC 5280. Ставим его отличным от нуля у самой последней разрядной строки
	 */
	size_t place = 0;
	/**
	 * Разрядная строка подписи стоит последним элементом сертификата, оттого
	 * опознаётся не образцом байтов - тот встречается и внутри самой подписи, - а
	 * тем, что содержимое её кончается ровно на конце записи
	 */
	for(size_t i = 0; (i + 3) < data.size(); i++){
		// Если очередной элемент не разрядная строка краткой длины
		if((data[i] != 0x03) || (data[i + 1] >= 0x80))
			// Переходим к следующему элементу записи
			continue;
		// Если содержимое разрядной строки кончается на конце записи
		if((i + 2 + static_cast <size_t> (data[i + 1])) == data.size()){
			// Запоминаем место числа неиспользуемых разрядов
			place = (i + 2);
			// Выходим из поиска разрядной строки подписи
			break;
		}
	}
	// Проверяем, что место числа неиспользуемых разрядов найдено
	ASSERT_NE(place, static_cast <size_t> (0));
	// Объект разбираемого сертификата
	x509::certificate_t certificate;
	// Выполняем разбор исправного сертификата
	ASSERT_EQ(certificate.parse(view_t(data.data(), data.size())), x509::error_t::NONE);
	// Проверяем схождение подписи исправного сертификата своим же ключом
	ASSERT_EQ(x509::verify(certificate, certificate.key()), x509::error_t::NONE);
	// Ставим число неиспользуемых разрядов последнего байта подписи отличным от нуля
	data[place] = 0x01;
	/**
	 * Правила DER велят держать неиспользуемые разряды нулевыми, иначе одна и та же
	 * строка разрядов получает разные записи, и разбор отвергает запись ещё до
	 * проверки подписи. Обнуляем младший разряд последнего байта, оставляя запись
	 * правилам отвечающей: заслон проверки подписи обязан отвергнуть её сам
	 */
	data[data.size() - 1] = static_cast <uint8_t> (data[data.size() - 1] & 0xFE);
	// Объект сертификата с подписью неполного числа байтов
	x509::certificate_t fractional;
	// Выполняем разбор сертификата с подписью неполного числа байтов
	ASSERT_EQ(fractional.parse(view_t(data.data(), data.size())), x509::error_t::NONE);
	// Проверяем отказ проверки подписи неполного числа байтов
	ASSERT_NE(x509::verify(fractional, fractional.key()), x509::error_t::NONE);
}
/**
 * @brief Проверка подписи при нехватке памяти
 *
 * @note Проверка подписи извлекает опознаватель набора параметров кривой, а
 *       значит выделяет память: на всяком запасе выделений она обязана ответить
 *       либо схождением, либо отказом, но не прерыванием исполнения
 *
 */
TEST(SignatureTest, Starved) {
	// Выполняем разбор записи первого сертификата
	const std::vector <uint8_t> data = bytes(CERTIFICATE_FIRST);
	// Объект разбираемого сертификата
	x509::certificate_t certificate;
	// Выполняем разбор сертификата
	ASSERT_EQ(certificate.parse(view_t(data.data(), data.size())), x509::error_t::NONE);
	// Признак того, что подпись хоть раз сошлась
	bool verified = false;
	/**
	 * Выполняем перебор запасов выделений при проверке подписи
	 */
	for(size_t budget = 0; budget < 512; budget++){
		// Итог проверки подписи при отмеренном запасе
		x509::error_t outcome = x509::error_t::NONE;
		{
			// Отмеряем запас выделений на время проверки подписи
			starve::ration_t ration(budget);
			// Выполняем проверку подписи при отмеренном запасе
			outcome = x509::verify(certificate, certificate.key());
		}
		// Проверяем, что проверка ответила схождением либо отказом памяти
		ASSERT_TRUE((outcome == x509::error_t::NONE) || (outcome == x509::error_t::MEMORY)) << "запас " << budget;
		// Запоминаем схождение подписи
		verified = (verified || (outcome == x509::error_t::NONE));
	}
	// Проверяем, что при достаточном запасе подпись сошлась
	ASSERT_TRUE(verified);
	// Признак того, что нехватка памяти при разборе хоть раз объявлена отказом
	bool starved = false;
	/**
	 * Выполняем перебор запасов выделений при разборе настоящего сертификата
	 */
	for(size_t budget = 0; budget < 512; budget++){
		// Объект сертификата, разбираемого при отмеренном запасе
		x509::certificate_t item;
		// Итог разбора при отмеренном запасе
		x509::error_t outcome = x509::error_t::NONE;
		{
			// Отмеряем запас выделений на время разбора
			starve::ration_t ration(budget);
			// Выполняем разбор сертификата при отмеренном запасе
			outcome = item.parse(view_t(data.data(), data.size()));
		}
		// Проверяем, что разбор ответил успехом либо отказом памяти
		ASSERT_TRUE((outcome == x509::error_t::NONE) || (outcome == x509::error_t::MEMORY)) << "запас " << budget;
		// Запоминаем объявленный отказ памяти
		starved = (starved || (outcome == x509::error_t::MEMORY));
	}
	// Проверяем, что нехватка памяти при разборе объявлена отказом хоть раз
	ASSERT_TRUE(starved);
}
