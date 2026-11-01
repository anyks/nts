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
 * @note Сертификаты ГОСТ взяты из приложения D RFC 9215 все три: два с ключом длиной 256
 *       разрядов на разных кривых и один с ключом длиной 512 разрядов. Всякий из них
 *       подписан своим же ключом, оттого проверка не требует ни цепочки, ни хранилища.
 *       Классические сертификаты и подписи выработаны системным OpenSSL 3: часть лежит
 *       в наборе образцов tests/corpus, а разновидности хешей и схем записаны здесь же
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
#include <fstream>
#include <main.hpp>
#include <starve.hpp>
#include <pem/pem.hpp>
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
 * @brief Функция разбора записи сертификата шестнадцатеричными знаками
 *
 * @param text разбираемая запись сертификата
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
			 *
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

/**
 * Самоподписанный сертификат RSASSA-PSS с хешем SHA-256 и солью в тридцать два байта,
 * выработанный OpenSSL 3 ключом rsa2048.pem набора образцов
 */
static const char * CERTIFICATE_PSS256 =
	"3082037130820225a00302010202146e42f42ea4f1fb86935dd03bc6d56c7ef8"
	"459a1f304106092a864886f70d01010a3034a00f300d06096086480165030402"
	"010500a11c301a06092a864886f70d010108300d060960864801650304020105"
	"00a20302012030143112301006035504030c09616e796b732d707373301e170d"
	"3236303930343030343933315a170d3336303930313030343933315a30143112"
	"301006035504030c09616e796b732d70737330820122300d06092a864886f70d"
	"01010105000382010f003082010a0282010100eac7cd7a7194a80d1dad5bc5c6"
	"61ea115d936e367fdeba834ce710ddf58e5a29b1c8416ccc93af245408fdf3f9"
	"88b8921ea3f5e07706863f6b020b363e63ae8953850a82e2cc2bd271fdf0cbd5"
	"39a7012917bf31aed762dedc3e643783553bb0c46b1b2ec07b81471625cf37e6"
	"b806603baf88852f6d985b3753bf35477a338653c1281cb2496f699f587b63af"
	"b479c430cee8ebe2da093ad8611a770ea7562ff4f55d3368d6b575602904e991"
	"e5e72580ac1d960a55de54641d14875e13fbfce2458d28ed60d33e4bd6fbb0d3"
	"cb303b81a5968f37369a89ace5f2513fe4951d5c8b34030bc6e62321a8b90f42"
	"bb833b7564928bc872ceb55f096c29482bccf50203010001a3533051301d0603"
	"551d0e04160414a55317e80048cfa53161a7b1b03332af0b25da57301f060355"
	"1d23041830168014a55317e80048cfa53161a7b1b03332af0b25da57300f0603"
	"551d130101ff040530030101ff304106092a864886f70d01010a3034a00f300d"
	"06096086480165030402010500a11c301a06092a864886f70d010108300d0609"
	"6086480165030402010500a20302012003820101007e55c255ff8543fda773b7"
	"af47560dfeeeb2e8b596b5e36a1e59eab167cc113243128ece1be1c9a85a2d28"
	"62061dcbf6e358299bb484fbaa65471796c33cd7fa4fb40b91fea4313a23fb8c"
	"29b1b4cb9099633301ce77fc102bd203a86340a4ec465e09c68430790ddde426"
	"9149cdd2171f88bc60d40854c2fe0e89a4f4e1bb0f308d364136428efee60b38"
	"fada8649afdb5173e57df2337e2a8c9218107984864cae31caa123a8cb7ad5c9"
	"f7a285b82bead72ce7eeb4cacaba858a9ba572d892ed2ac8b5fb2519d42a05e5"
	"87ad8d4bc8f1623f9acf63bcba6671a60a606e1760b49cedd736126d004b8557"
	"c804deabf9aef3fe86e995959c160754fd3c29d2ea";

/**
 * Самоподписанный сертификат RSASSA-PSS с хешем SHA-384 и солью в сорок восемь байтов
 */
static const char * CERTIFICATE_PSS384 =
	"308203773082022ba00302010202143f967b8a7bbc59a497e47634fba4746f55"
	"f9e95b304106092a864886f70d01010a3034a00f300d06096086480165030402"
	"020500a11c301a06092a864886f70d010108300d060960864801650304020205"
	"00a20302013030173115301306035504030c0c616e796b732d70737333383430"
	"1e170d3236303930343030343933315a170d3336303930313030343933315a30"
	"173115301306035504030c0c616e796b732d70737333383430820122300d0609"
	"2a864886f70d01010105000382010f003082010a0282010100eac7cd7a7194a8"
	"0d1dad5bc5c661ea115d936e367fdeba834ce710ddf58e5a29b1c8416ccc93af"
	"245408fdf3f988b8921ea3f5e07706863f6b020b363e63ae8953850a82e2cc2b"
	"d271fdf0cbd539a7012917bf31aed762dedc3e643783553bb0c46b1b2ec07b81"
	"471625cf37e6b806603baf88852f6d985b3753bf35477a338653c1281cb2496f"
	"699f587b63afb479c430cee8ebe2da093ad8611a770ea7562ff4f55d3368d6b5"
	"75602904e991e5e72580ac1d960a55de54641d14875e13fbfce2458d28ed60d3"
	"3e4bd6fbb0d3cb303b81a5968f37369a89ace5f2513fe4951d5c8b34030bc6e6"
	"2321a8b90f42bb833b7564928bc872ceb55f096c29482bccf50203010001a353"
	"3051301d0603551d0e04160414a55317e80048cfa53161a7b1b03332af0b25da"
	"57301f0603551d23041830168014a55317e80048cfa53161a7b1b03332af0b25"
	"da57300f0603551d130101ff040530030101ff304106092a864886f70d01010a"
	"3034a00f300d06096086480165030402020500a11c301a06092a864886f70d01"
	"0108300d06096086480165030402020500a2030201300382010100d5920d00fd"
	"493fc81632043b0ee1cac335c748913f682be3aa7091d282878e81beca3258d5"
	"feb46af93f10a4fa773d1a7bfaf03974b1cf7b2a349965e35d25fb75356420a1"
	"fa84be63b38bf019bfd1ecda697dd72e46bca34cafb0bb9e30f482a9c1efe501"
	"e882d6df9c27ab3e14e984f4aa8ab0f1cd4c93c41a2a228c3b9abb795a896824"
	"78c0155ab3aea331e50ef2188be91327641d64e669279008a928329ebb4e4223"
	"678b8336e78cd71a276a1ec14abdcca1f2b5be23086c511bcdd3ceb83c31d645"
	"310dda3cffdb3a2c36085d4990a8fe41229e084c993679f558b90e851543845c"
	"0da217e3042ef155508a516970f60f214ee0933f6787554f5079eb";

/**
 * Самоподписанный сертификат RSASSA-PSS с хешем SHA-512 и солью в шестьдесят четыре байта
 */
static const char * CERTIFICATE_PSS512 =
	"308203773082022ba003020102021416049d7d0a9e2304a2e2ad37822af38dad"
	"f60892304106092a864886f70d01010a3034a00f300d06096086480165030402"
	"030500a11c301a06092a864886f70d010108300d060960864801650304020305"
	"00a20302014030173115301306035504030c0c616e796b732d70737335313230"
	"1e170d3236303930343030343933315a170d3336303930313030343933315a30"
	"173115301306035504030c0c616e796b732d70737335313230820122300d0609"
	"2a864886f70d01010105000382010f003082010a0282010100eac7cd7a7194a8"
	"0d1dad5bc5c661ea115d936e367fdeba834ce710ddf58e5a29b1c8416ccc93af"
	"245408fdf3f988b8921ea3f5e07706863f6b020b363e63ae8953850a82e2cc2b"
	"d271fdf0cbd539a7012917bf31aed762dedc3e643783553bb0c46b1b2ec07b81"
	"471625cf37e6b806603baf88852f6d985b3753bf35477a338653c1281cb2496f"
	"699f587b63afb479c430cee8ebe2da093ad8611a770ea7562ff4f55d3368d6b5"
	"75602904e991e5e72580ac1d960a55de54641d14875e13fbfce2458d28ed60d3"
	"3e4bd6fbb0d3cb303b81a5968f37369a89ace5f2513fe4951d5c8b34030bc6e6"
	"2321a8b90f42bb833b7564928bc872ceb55f096c29482bccf50203010001a353"
	"3051301d0603551d0e04160414a55317e80048cfa53161a7b1b03332af0b25da"
	"57301f0603551d23041830168014a55317e80048cfa53161a7b1b03332af0b25"
	"da57300f0603551d130101ff040530030101ff304106092a864886f70d01010a"
	"3034a00f300d06096086480165030402030500a11c301a06092a864886f70d01"
	"0108300d06096086480165030402030500a203020140038201010087e5a66f17"
	"5e530d3f33d9ebc91fe27ad60d76ad0e807b5f470a1a1f5b0c9401eba0b34d2a"
	"1b1d5713647c5479eb8aaa85e939dd429324d746c06a2d61b22efc064e031921"
	"cdea6bc1baba4962d1168c9c01ed18382f1b4df5e654aaeacc696cb57ab2b613"
	"70a0470f55eb4d5ec086e2bf45ff63a9f8e4ab04f7e099300c89b242d3f56d48"
	"cc0d5989b51f1a0f8d3ce293f362d67b433ce05fa901c6803e9866f9e709b869"
	"f22b316a5ffd79991ebd95378ecad273417f970f1fcfde9aa6034a490bce6206"
	"245b8afec6742e10631db48687416fa5b42a08fef073e3da485b9d072b44c3a4"
	"ff5e806077c4a0faefe28238829a906d11f3b41e6d6666dbaba5e4";

/**
 * Самоподписанный сертификат sha1WithRSAEncryption
 */
static const char * CERTIFICATE_RSA1 =
	"3082030b308201f3a00302010202142f71d10e8c9d54684d2dcb0507ed5bee2d"
	"1e7281300d06092a864886f70d010105050030153113301106035504030c0a61"
	"6e796b732d73686131301e170d3236303930343030343933315a170d33363039"
	"30313030343933315a30153113301106035504030c0a616e796b732d73686131"
	"30820122300d06092a864886f70d01010105000382010f003082010a02820101"
	"00eac7cd7a7194a80d1dad5bc5c661ea115d936e367fdeba834ce710ddf58e5a"
	"29b1c8416ccc93af245408fdf3f988b8921ea3f5e07706863f6b020b363e63ae"
	"8953850a82e2cc2bd271fdf0cbd539a7012917bf31aed762dedc3e643783553b"
	"b0c46b1b2ec07b81471625cf37e6b806603baf88852f6d985b3753bf35477a33"
	"8653c1281cb2496f699f587b63afb479c430cee8ebe2da093ad8611a770ea756"
	"2ff4f55d3368d6b575602904e991e5e72580ac1d960a55de54641d14875e13fb"
	"fce2458d28ed60d33e4bd6fbb0d3cb303b81a5968f37369a89ace5f2513fe495"
	"1d5c8b34030bc6e62321a8b90f42bb833b7564928bc872ceb55f096c29482bcc"
	"f50203010001a3533051301d0603551d0e04160414a55317e80048cfa53161a7"
	"b1b03332af0b25da57301f0603551d23041830168014a55317e80048cfa53161"
	"a7b1b03332af0b25da57300f0603551d130101ff040530030101ff300d06092a"
	"864886f70d010105050003820101009d1a5e5b13f8669ceba311fc14176613b2"
	"65cd7f433a578a31e8e9562b90576607d64e71430223d585a304e16690be5dc4"
	"75e2c1ab9c9088b784e4be7e09797cac20ed57f2a54596025e6c4b4ea37a3b82"
	"674ba8b32769974b3d3d226d0a2b541c945249dc79823ab479108bff7dc8bdd5"
	"6dc66f7452411322ebb2f3666516af9db1824832144691046b7bf098bba96b3d"
	"41e83a56d90ce24031efbed046b5de8cd7b6e1fc38913a761c1f8d99879c92d7"
	"5661db0e74cf4ac9171811bf8068782b65e666811f9e769725350e1d731ef209"
	"fd35b4ae37c93158870be9ba7c7e820b8865dd85570b306f3877018a8f847823"
	"1bc383eda6e204d51137ec0eebdb96";

/**
 * Самоподписанный сертификат sha224WithRSAEncryption
 */
static const char * CERTIFICATE_RSA224 =
	"3082030f308201f7a00302010202145f4cc52d60c9aabcc075abcfebb53c68f3"
	"fc7861300d06092a864886f70d01010e050030173115301306035504030c0c61"
	"6e796b732d736861323234301e170d3236303930343030343933315a170d3336"
	"303930313030343933315a30173115301306035504030c0c616e796b732d7368"
	"6132323430820122300d06092a864886f70d01010105000382010f003082010a"
	"0282010100eac7cd7a7194a80d1dad5bc5c661ea115d936e367fdeba834ce710"
	"ddf58e5a29b1c8416ccc93af245408fdf3f988b8921ea3f5e07706863f6b020b"
	"363e63ae8953850a82e2cc2bd271fdf0cbd539a7012917bf31aed762dedc3e64"
	"3783553bb0c46b1b2ec07b81471625cf37e6b806603baf88852f6d985b3753bf"
	"35477a338653c1281cb2496f699f587b63afb479c430cee8ebe2da093ad8611a"
	"770ea7562ff4f55d3368d6b575602904e991e5e72580ac1d960a55de54641d14"
	"875e13fbfce2458d28ed60d33e4bd6fbb0d3cb303b81a5968f37369a89ace5f2"
	"513fe4951d5c8b34030bc6e62321a8b90f42bb833b7564928bc872ceb55f096c"
	"29482bccf50203010001a3533051301d0603551d0e04160414a55317e80048cf"
	"a53161a7b1b03332af0b25da57301f0603551d23041830168014a55317e80048"
	"cfa53161a7b1b03332af0b25da57300f0603551d130101ff040530030101ff30"
	"0d06092a864886f70d01010e05000382010100e14605238b6c96150c37826f93"
	"2dd6e06bd283397426eca9a59f974ff4ba73187a021da21a01d1380d560937a0"
	"75cabb4f58fcae8798bb494d3f97876a02a5f9d4c20732d532393236d316bf0d"
	"fa7f5d10984c089d7145ac09e8b66d58870a127e79e70577725ff474f6493f5d"
	"7c74a2b4ef09eb8a57b0e39657d32a0c19089e39c6e0b4a167949e7320d42faf"
	"4bd32ee7dcb879c46743a37c2bf432ff13a9efb841dcf63470dedecca002aa41"
	"bd43f1762033350a569e6a31c0b1e83bd2d8afcb113a154fa075e9cc8dcc5795"
	"adcca54123b842dcb55abbc096c8a70a11ec813f760efefa23abbab842e20629"
	"169a585ff84859b75ae54b7dd7996757094f82";

/**
 * Самоподписанный сертификат sha384WithRSAEncryption
 */
static const char * CERTIFICATE_RSA384 =
	"3082030f308201f7a0030201020214271355b67d6b98a7898c51fd0b8d4fea00"
	"073bb3300d06092a864886f70d01010c050030173115301306035504030c0c61"
	"6e796b732d736861333834301e170d3236303930343030343933315a170d3336"
	"303930313030343933315a30173115301306035504030c0c616e796b732d7368"
	"6133383430820122300d06092a864886f70d01010105000382010f003082010a"
	"0282010100eac7cd7a7194a80d1dad5bc5c661ea115d936e367fdeba834ce710"
	"ddf58e5a29b1c8416ccc93af245408fdf3f988b8921ea3f5e07706863f6b020b"
	"363e63ae8953850a82e2cc2bd271fdf0cbd539a7012917bf31aed762dedc3e64"
	"3783553bb0c46b1b2ec07b81471625cf37e6b806603baf88852f6d985b3753bf"
	"35477a338653c1281cb2496f699f587b63afb479c430cee8ebe2da093ad8611a"
	"770ea7562ff4f55d3368d6b575602904e991e5e72580ac1d960a55de54641d14"
	"875e13fbfce2458d28ed60d33e4bd6fbb0d3cb303b81a5968f37369a89ace5f2"
	"513fe4951d5c8b34030bc6e62321a8b90f42bb833b7564928bc872ceb55f096c"
	"29482bccf50203010001a3533051301d0603551d0e04160414a55317e80048cf"
	"a53161a7b1b03332af0b25da57301f0603551d23041830168014a55317e80048"
	"cfa53161a7b1b03332af0b25da57300f0603551d130101ff040530030101ff30"
	"0d06092a864886f70d01010c05000382010100ac47270bf2a01eab56d399a676"
	"5b4851c0fedfe2a3157fe424db23ae7a7d37494841de48054eea013742214063"
	"d789d70a29749bf7d64690a0d6821893cf98d6c7df24ab4f09556fd4c051c87b"
	"0c7ab08c574d41bb7e7e927a461aa96624b51ae8ab6c6aee9aadcd3496daca15"
	"3489f56a27e11b88f9b13c39d3f5af5aacf2a91506e151e703d8c1eadc2abd32"
	"3fb2903db803ac53ff6ae17097e9c7c5aca39203c1b425d1292d3a3335df6211"
	"21836d1ec0e177156c668809f5033916810c6430f5716a5f6330c0543f6d70d3"
	"986e55f2cdb7cb4d7ffebd2d299d8c31c44d5863c3c9695f67ec6337eaf7dda5"
	"e6a7f41f86019c3ed3ae7f603905fed678c16b";

/**
 * Самоподписанный сертификат sha512WithRSAEncryption
 */
static const char * CERTIFICATE_RSA512 =
	"3082030f308201f7a003020102021402eaa4285982cf6086e4d2f01b2c1d9cba"
	"edb9b2300d06092a864886f70d01010d050030173115301306035504030c0c61"
	"6e796b732d736861353132301e170d3236303930343030343933315a170d3336"
	"303930313030343933315a30173115301306035504030c0c616e796b732d7368"
	"6135313230820122300d06092a864886f70d01010105000382010f003082010a"
	"0282010100eac7cd7a7194a80d1dad5bc5c661ea115d936e367fdeba834ce710"
	"ddf58e5a29b1c8416ccc93af245408fdf3f988b8921ea3f5e07706863f6b020b"
	"363e63ae8953850a82e2cc2bd271fdf0cbd539a7012917bf31aed762dedc3e64"
	"3783553bb0c46b1b2ec07b81471625cf37e6b806603baf88852f6d985b3753bf"
	"35477a338653c1281cb2496f699f587b63afb479c430cee8ebe2da093ad8611a"
	"770ea7562ff4f55d3368d6b575602904e991e5e72580ac1d960a55de54641d14"
	"875e13fbfce2458d28ed60d33e4bd6fbb0d3cb303b81a5968f37369a89ace5f2"
	"513fe4951d5c8b34030bc6e62321a8b90f42bb833b7564928bc872ceb55f096c"
	"29482bccf50203010001a3533051301d0603551d0e04160414a55317e80048cf"
	"a53161a7b1b03332af0b25da57301f0603551d23041830168014a55317e80048"
	"cfa53161a7b1b03332af0b25da57300f0603551d130101ff040530030101ff30"
	"0d06092a864886f70d01010d05000382010100863cc1d046390b227e25dc28e4"
	"2df760a1d65988ba9c69e8a2702cc2f4907bbd70983f5c9a556a01bccc28a54d"
	"288743b2ed5241821b1105f6f98aeea195c3d994a6baacf789ccdb1b5d830a4d"
	"e585f96f303473a41dbfc789eb069bdaba83d7165b4b7ce3904672a0021eaf79"
	"b5cd710b7366c6a4e2ef555a1c9bd8aafc8059e9c81dfcf9cf54c0c5b945c8ca"
	"f13c9ba7eda1c6ab9386234b4f5127be524aff967f7e0fb7fde8bf5696634558"
	"d1c0b9911416688d44e0ed6d7ecee783095df65979e6e2a4585d09566ea30d7e"
	"315011279e1c02d61566ef14f5cb095778ebd8625075e5bcec2acfef5045b69e"
	"5d04be3a52122096166aee6f7baa566304b4f0";

/**
 * Самоподписанный сертификат ecdsa-with-SHA224 на кривой P-256
 */
static const char * CERTIFICATE_EC224 =
	"3082018230820127a00302010202146286a09e62b2086d164a1aca42b476399a"
	"4a12df300a06082a8648ce3d04030130163114301206035504030c0b616e796b"
	"732d6563323234301e170d3236303930343030343933315a170d333630393031"
	"3030343933315a30163114301206035504030c0b616e796b732d656332323430"
	"59301306072a8648ce3d020106082a8648ce3d03010703420004c5f904e60471"
	"a9e989b91486bfc7e441fc3c68fe4835dab258b857ec232a7f7d58ac1fd30f18"
	"942a0021d85c790a56b8720781def57176adbb5cd92272a37764a3533051301d"
	"0603551d0e04160414e378ebd1734997cd732aa6fe7ad6bc6d9cf2e9c8301f06"
	"03551d23041830168014e378ebd1734997cd732aa6fe7ad6bc6d9cf2e9c8300f"
	"0603551d130101ff040530030101ff300a06082a8648ce3d0403010349003046"
	"022100a3b1e9b6330113ebc8f29ca9b03066f95d2d9e2c8d9ab30a69ccf0fd75"
	"d35e90022100de2bccc11b602058fc6f9c6e72d9b93d4ba95b87f272f4550328"
	"5255f48e5fe0";

/**
 * Самоподписанный сертификат ecdsa-with-SHA384 на кривой P-384 ключом ec384.pem
 */
static const char * CERTIFICATE_EC384 =
	"308201be30820144a00302010202147aa8f1b522c61d34a5ce959dc3c4ab9a9a"
	"b9edc2300a06082a8648ce3d04030330163114301206035504030c0b616e796b"
	"732d6563333834301e170d3236303930343030343933315a170d333630393031"
	"3030343933315a30163114301206035504030c0b616e796b732d656333383430"
	"76301006072a8648ce3d020106052b8104002203620004dbaf602b7d76094129"
	"19a7b7a5740af603739528d3f2dbab4b7d0395f00e7f1e8a2bec3554f405c257"
	"370551a413a1d3c5615492a0185c4e2e768559293a5be8d2366005803987c4e0"
	"baa407b30cdd7b586fa8d132651081d06abff50c84a7a8a3533051301d060355"
	"1d0e04160414ba8ed075a1394bd83be9ff2b5722d7bded312f26301f0603551d"
	"23041830168014ba8ed075a1394bd83be9ff2b5722d7bded312f26300f060355"
	"1d130101ff040530030101ff300a06082a8648ce3d0403030368003065023100"
	"b00e6c9bd866291be13c154684aeaa68396720fd376d48590bfde0dc99527626"
	"c546ec5a04f85684347c5fbd104e52df02306ca16dca9c073085e4d8cf95774e"
	"44447a0e1a153f4384e100e51ad7d68923f32837a669976e98ab74d82317f844"
	"94ca";

/**
 * Самоподписанный сертификат ecdsa-with-SHA512 на кривой P-256: хеш длиннее порядка
 * подгруппы и усекается
 */
static const char * CERTIFICATE_EC512 =
	"3082018230820127a003020102021433daab3a5e84a4cee9ebdc814d5819cfd6"
	"4bc44a300a06082a8648ce3d04030430163114301206035504030c0b616e796b"
	"732d6563353132301e170d3236303930343030343933315a170d333630393031"
	"3030343933315a30163114301206035504030c0b616e796b732d656335313230"
	"59301306072a8648ce3d020106082a8648ce3d03010703420004c5f904e60471"
	"a9e989b91486bfc7e441fc3c68fe4835dab258b857ec232a7f7d58ac1fd30f18"
	"942a0021d85c790a56b8720781def57176adbb5cd92272a37764a3533051301d"
	"0603551d0e04160414e378ebd1734997cd732aa6fe7ad6bc6d9cf2e9c8301f06"
	"03551d23041830168014e378ebd1734997cd732aa6fe7ad6bc6d9cf2e9c8300f"
	"0603551d130101ff040530030101ff300a06082a8648ce3d0403040349003046"
	"022100e1efbb77f2f2b7d6e8215195ce0c6988a5270535cb3cc0f117ec919bc8"
	"57ac00022100d0cbda8b0d0e35f72258dbd83efe0f726b6a35cec79a0fb9171c"
	"ca3af0d261ca";

/**
 * Содержимое, подписанное ключами набора образцов ради проверки подписи владения
 */
static const char * POSSESSION = "ANTS possession of the key";

/**
 * Подпись содержимого ключом ec256.pem с хешем SHA-256: SEQUENCE {r, s}
 */
static const char * SIGNATURE_EC256 =
	"304402200d9d2f3847ab43b03aa191b8711b7feaf96053e1b45a1e67ef2eb9a2"
	"ff92d0bf02207d905057feda2f90527be112d1fa3bb5420919a0562aaecd78c1"
	"28a085ddf6fe";

/**
 * Подпись содержимого ключом ec384.pem с хешем SHA-384: SEQUENCE {r, s}
 */
static const char * SIGNATURE_EC384 =
	"3066023100d35cdd0d944ffe5043dddc54af2ceccb6d38a65628ed428caab6e1"
	"3eab07652f3c9a9e20cc4ecceed564630a25230cff023100f9d57f35ca57f408"
	"b8f6fc41d5529c51034ab3aefb004752c476aed4993adbdb641696fdf80748a2"
	"30b0e0f2bd1e91c6";

/**
 * Подпись содержимого ключом rsa2048.pem по схеме RSASSA-PSS с хешем SHA-256 и солью в хеш
 */
static const char * SIGNATURE_PSS =
	"cc881738b04739b3c1ff7cc916cd48cfe4957fe4667b614de081a1d8757f3b83"
	"02053143631e2df12ca1159e0f55186a14738978808a73d89d7f543f589f23ab"
	"8ed96fd8c2a448fc0e36e217a011726d31b491d4e4f4fe4342e1a8c50344ce4c"
	"b59b83d1a461aa8e0da7d02b2c52d0a6dd91e468c5f0430fc91dc28ce0f5e6cd"
	"913fc2def2f519538224ae7371957a82709763b8d74869264f771e10428a1445"
	"9e0313fe6d4b4138181bba82ab5ae22e27ae45611cb25af5c1318282056bb0cd"
	"bf82117c359fb563ce0beb8a986c506a279cdfa8e7e300b1e871f4a59e5b3291"
	"719d33d88532c336334c3f3a0fa5c2044ea79ec7c6606001fecefb021af9b827";

/**
 * Подпись содержимого ключом rsa2048.pem по схеме PKCS #1 v1.5 с хешем SHA-256:
 * подписью владения в TLS 1.3 она служить не вправе
 */
static const char * SIGNATURE_PKCS1 =
	"ae7cd4b099ce210d44159c0f0b513189e7f943e55c878fcb65d7fa19dcbaa69b"
	"5cb0af7b5e55736eec93549e9720ceeeaf4e44df7cf511bb890d01a7e6e34a9f"
	"74a55b1a3695aa1cd0144a28e8953c0b3e7f81eb392cddb1361e1406439779fe"
	"21b3dd4d158b26bd4607d132ad059f765f88f3a718fbecd97578f7074b0f2752"
	"2747fd82bd48f5f4b5dfcb099930d29be77b5a357cea524f37c6484bfd30da4d"
	"f9e882a16ad3004be0884232131f165edb7e2d6f381fca69940ad1cfe0169470"
	"c2949b0d98bdfa4504713884b41a4f26754aa957eca8fb50423263b3c6ec90c5"
	"07465a84d037d008af2110f7f85c4d44b6631044858f5851ae2a96e832010cae";

/**
 * Подпись содержимого ключом ed25519.pem: сырые шестьдесят четыре байта
 */
static const char * SIGNATURE_ED25519 =
	"6b7e6e8e4691475c5865a0fd3b59c49ae21a99b1f96971639be38d8a60853f16"
	"a950ef2bc8a2e10572d3414772942d401d6827a75e41845c5a21adcb12998704";

/**
 * @brief Функция чтения сертификатов из файла набора образцов
 *
 * @param name   имя файла набора образцов
 * @param result перечень записей сертификатов файла в порядке следования
 * @return       признак успешности чтения сертификатов
 *
 */
static bool corpus(const char * name, std::vector <std::vector <uint8_t>> & result) {
	// Путь к файлу набора образцов
	const std::string path = std::string(ANTS_CORPUS) + "/" + name;
	// Открываем файл набора образцов
	std::ifstream file(path, std::ios::binary);
	// Если файл открыть не удалось
	if(!file.is_open())
		// Выводим отказ чтения сертификатов
		return false;
	// Считываем содержимое файла целиком
	const std::string text((std::istreambuf_iterator <char> (file)), std::istreambuf_iterator <char> ());
	// Выводим итог извлечения сертификатов из текста
	return (pem::certificates(text, result) == pem::error_t::NONE);
}
/**
 * @brief Функция чтения первого сертификата файла набора образцов
 *
 * @param name   имя файла набора образцов
 * @param result запись первого сертификата файла
 * @return       признак успешности чтения сертификата
 *
 */
static bool solo(const char * name, std::vector <uint8_t> & result) {
	// Перечень записей сертификатов файла
	std::vector <std::vector <uint8_t>> items;
	// Если сертификаты файла прочитать не удалось либо их нет
	if(!corpus(name, items) || items.empty())
		// Выводим отказ чтения сертификата
		return false;
	// Запоминаем запись первого сертификата
	result = items[0];
	// Выводим успешность чтения сертификата
	return true;
}
/**
 * @brief Функция проверки отказа подписи при порче записи и подписи
 *
 * @param data  запись самоподписанного сертификата
 * @param label подпись сертификата в сообщениях об отказе
 *
 */
static void spoil(std::vector <uint8_t> data, const std::string & label) {
	// Объект разбираемого сертификата
	x509::certificate_t certificate;
	// Выполняем разбор сертификата
	ASSERT_EQ(certificate.parse(view_t(data.data(), data.size())), x509::error_t::NONE) << label;
	// Проверяем, что подпись сертификата своим ключом сходится
	ASSERT_EQ(x509::verify(certificate, certificate.key()), x509::error_t::NONE) << label;
	// Получаем подписанное тело сертификата
	const view_t & body = certificate.body();
	// Копия подписанного тела сертификата
	std::vector <uint8_t> copy(body.data, body.data + body.size);
	// Число неиспользуемых разрядов последнего байта подписи
	uint8_t unused = 0;
	// Получаем подпись сертификата
	const view_t & signature = certificate.sign(unused);
	/**
	 * Выполняем перебор байтов подписанного тела сертификата: порча тела проверяется
	 * прямою проверкой записи, ибо разбору испорченное тело поддаётся не всегда
	 */
	for(size_t j = 0; j < copy.size(); j += 11){
		// Портим очередной байт тела
		copy[j] = static_cast <uint8_t> (copy[j] ^ 0x01);
		// Проверяем, что подпись испорченного тела не сходится
		ASSERT_EQ(x509::verify(view_t(copy.data(), copy.size()), signature, certificate.algorithms(), certificate.key()), x509::error_t::SIGNATURE) << label << ", место порчи тела: " << j;
		// Возвращаем байт тела на место
		copy[j] = static_cast <uint8_t> (copy[j] ^ 0x01);
	}
	// Определяем место подписи в записи сертификата
	const size_t place = static_cast <size_t> (signature.data - data.data());
	/**
	 * Выполняем перебор байтов подписи сертификата
	 */
	for(size_t j = 0; j < signature.size; j += 5){
		// Портим очередной байт подписи
		data[place + j] = static_cast <uint8_t> (data[place + j] ^ 0x01);
		// Объект разбираемого испорченного сертификата
		x509::certificate_t item;
		// Выполняем разбор испорченного сертификата
		ASSERT_EQ(item.parse(view_t(data.data(), data.size())), x509::error_t::NONE) << label;
		// Проверяем, что испорченная подпись не сходится
		ASSERT_EQ(x509::verify(item, item.key()), x509::error_t::SIGNATURE) << label << ", место порчи подписи: " << j;
		// Возвращаем байт подписи на место
		data[place + j] = static_cast <uint8_t> (data[place + j] ^ 0x01);
	}
}
/**
 * @brief Проверка подписи самоподписанных классических сертификатов набора образцов
 *
 */
TEST(SignatureTest, Classic) {
	// Имена файлов самоподписанных сертификатов набора образцов
	static const char * NAMES[3] = {"rsa2048.crt", "ec256.crt", "ed25519.crt"};
	// Разобранные сертификаты набора образцов
	x509::certificate_t certificates[3];
	// Записи сертификатов набора образцов
	std::vector <uint8_t> records[3];
	/**
	 * Выполняем перебор сертификатов набора образцов
	 */
	for(size_t i = 0; i < 3; i++){
		// Выполняем чтение сертификата набора образцов
		ASSERT_TRUE(solo(NAMES[i], records[i])) << NAMES[i];
		// Выполняем разбор сертификата
		ASSERT_EQ(certificates[i].parse(view_t(records[i].data(), records[i].size())), x509::error_t::NONE) << NAMES[i];
		// Проверяем, что подпись сертификата своим ключом сходится
		ASSERT_EQ(x509::verify(certificates[i], certificates[i].key()), x509::error_t::NONE) << NAMES[i];
	}
	/**
	 * Выполняем перебор пар сертификатов: ключ чужого алгоритма даёт свой отказ
	 */
	for(size_t i = 0; i < 3; i++){
		/**
		 * Выполняем перебор ключей прочих сертификатов
		 */
		for(size_t j = 0; j < 3; j++){
			// Если ключ принадлежит другому сертификату
			if(i != j){
				// Проверяем отказ ключа чужого алгоритма
				ASSERT_EQ(x509::verify(certificates[i], certificates[j].key()), x509::error_t::KEY) << NAMES[i] << " ключом " << NAMES[j];
			}
		}
	}
	/**
	 * Выполняем перебор сертификатов ради порчи записи и подписи
	 */
	for(size_t i = 0; i < 3; i++)
		// Проверяем отказ при порче тела и подписи сертификата
		spoil(records[i], NAMES[i]);
}
/**
 * @brief Проверка подписи разновидностей хешей и схем классических сертификатов
 *
 */
TEST(SignatureTest, Variants) {
	// Записи сертификатов разновидностей
	static const char * VARIANTS[10] = {
		CERTIFICATE_PSS256, CERTIFICATE_PSS384, CERTIFICATE_PSS512,
		CERTIFICATE_RSA1, CERTIFICATE_RSA224, CERTIFICATE_RSA384, CERTIFICATE_RSA512,
		CERTIFICATE_EC224, CERTIFICATE_EC384, CERTIFICATE_EC512
	};
	// Подписи разновидностей в сообщениях об отказе
	static const char * LABELS[10] = {
		"RSASSA-PSS SHA-256", "RSASSA-PSS SHA-384", "RSASSA-PSS SHA-512",
		"sha1WithRSAEncryption", "sha224WithRSAEncryption", "sha384WithRSAEncryption", "sha512WithRSAEncryption",
		"ecdsa-with-SHA224", "ecdsa-with-SHA384", "ecdsa-with-SHA512"
	};
	/**
	 * Выполняем перебор сертификатов разновидностей
	 */
	for(size_t i = 0; i < 10; i++)
		// Проверяем схождение подписи и отказ при порче тела и подписи
		spoil(bytes(VARIANTS[i]), LABELS[i]);
	// Запись сертификата RSASSA-PSS
	const std::vector <uint8_t> data = bytes(CERTIFICATE_PSS256);
	// Объект разбираемого сертификата
	x509::certificate_t certificate;
	// Выполняем разбор сертификата
	ASSERT_EQ(certificate.parse(view_t(data.data(), data.size())), x509::error_t::NONE);
	// Число неиспользуемых разрядов последнего байта подписи
	uint8_t unused = 0;
	// Получаем подпись сертификата
	const view_t & signature = certificate.sign(unused);
	/**
	 * Без настроек подпись RSASSA-PSS проверяется умолчаниями раздела 3.1 RFC 4055,
	 * а сертификат подписан с хешем SHA-256, оттого подпись без настроек не сходится
	 */
	ASSERT_EQ(x509::verify(certificate.body(), signature, certificate.algorithms(), certificate.key()), x509::error_t::SIGNATURE);
	// Настройки подписи RSASSA-PSS с хешем SHA-256 и солью в тридцать два байта
	const std::vector <uint8_t> settings = bytes("3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120");
	// Проверяем, что с настройками подпись сходится
	ASSERT_EQ(x509::verify(certificate.body(), signature, certificate.algorithms(), view_t(settings.data(), settings.size()), certificate.key()), x509::error_t::NONE);
	// Настройки подписи RSASSA-PSS с иной длиной соли
	const std::vector <uint8_t> salted = bytes("3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020121");
	// Проверяем, что с иной длиной соли подпись не сходится
	ASSERT_EQ(x509::verify(certificate.body(), signature, certificate.algorithms(), view_t(salted.data(), salted.size()), certificate.key()), x509::error_t::SIGNATURE);
	// Настройки подписи RSASSA-PSS с хешем маски, отличным от хеша подписи
	const std::vector <uint8_t> mixed = bytes("3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402020500a203020120");
	// Проверяем отказ настроек с расходящимися хешами
	ASSERT_EQ(x509::verify(certificate.body(), signature, certificate.algorithms(), view_t(mixed.data(), mixed.size()), certificate.key()), x509::error_t::SIGNATURE);
	// Настройки подписи RSASSA-PSS с хвостовым полем, отличным от единицы
	const std::vector <uint8_t> trailed = bytes("3039a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120a303020102");
	// Проверяем отказ настроек с неизвестным хвостовым полем
	ASSERT_EQ(x509::verify(certificate.body(), signature, certificate.algorithms(), view_t(trailed.data(), trailed.size()), certificate.key()), x509::error_t::SIGNATURE);
	// Настройки подписи RSASSA-PSS с полями не по порядку меток
	const std::vector <uint8_t> unordered = bytes("3034a11c301a06092a864886f70d010108300d06096086480165030402010500a00f300d06096086480165030402010500a203020120");
	// Проверяем отказ настроек с полями не по порядку
	ASSERT_EQ(x509::verify(certificate.body(), signature, certificate.algorithms(), view_t(unordered.data(), unordered.size()), certificate.key()), x509::error_t::SIGNATURE);
}
/**
 * @brief Проверка подписи звеньев цепочек классических сертификатов набора образцов
 *
 */
TEST(SignatureTest, Chains) {
	// Имена файлов цепочек набора образцов
	static const char * CHAINS[2] = {"chain-rsa.pem", "chain-ec.pem"};
	// Имена файлов отдельных звеньев набора образцов по цепочкам
	static const char * LINKS[2][3] = {{"leaf-rsa.crt", "mid-rsa.crt", "ca-rsa.crt"}, {"leaf-ec.crt", "mid-ec.crt", "ca-ec.crt"}};
	/**
	 * Выполняем перебор цепочек набора образцов
	 */
	for(size_t i = 0; i < 2; i++){
		// Записи сертификатов цепочки
		std::vector <std::vector <uint8_t>> chain;
		// Выполняем чтение цепочки набора образцов
		ASSERT_TRUE(corpus(CHAINS[i], chain)) << CHAINS[i];
		// Проверяем, что цепочка состоит из листа, промежуточного издателя и корня
		ASSERT_EQ(chain.size(), static_cast <size_t> (3)) << CHAINS[i];
		/**
		 * Выполняем перебор звеньев цепочки: файлы отдельных звеньев обязаны совпадать
		 * с записями цепочки
		 */
		for(size_t j = 0; j < 3; j++){
			// Запись отдельного звена
			std::vector <uint8_t> link;
			// Выполняем чтение отдельного звена
			ASSERT_TRUE(solo(LINKS[i][j], link)) << LINKS[i][j];
			// Проверяем совпадение отдельного звена с записью цепочки
			ASSERT_EQ(link, chain[j]) << LINKS[i][j];
		}
		// Разобранные сертификаты цепочки
		x509::certificate_t items[3];
		/**
		 * Выполняем разбор сертификатов цепочки
		 */
		for(size_t j = 0; j < 3; j++)
			// Выполняем разбор очередного сертификата цепочки
			ASSERT_EQ(items[j].parse(view_t(chain[j].data(), chain[j].size())), x509::error_t::NONE) << LINKS[i][j];
		// Проверяем подпись листа ключом промежуточного издателя
		ASSERT_EQ(x509::verify(items[0], items[1].key()), x509::error_t::NONE) << CHAINS[i];
		// Проверяем подпись промежуточного издателя ключом корня
		ASSERT_EQ(x509::verify(items[1], items[2].key()), x509::error_t::NONE) << CHAINS[i];
		// Проверяем подпись корня своим ключом
		ASSERT_EQ(x509::verify(items[2], items[2].key()), x509::error_t::NONE) << CHAINS[i];
		// Проверяем отказ подписи листа ключом корня: ключ того же алгоритма, но чужой
		ASSERT_EQ(x509::verify(items[0], items[2].key()), x509::error_t::SIGNATURE) << CHAINS[i];
		// Проверяем отказ подписи промежуточного издателя ключом листа
		ASSERT_EQ(x509::verify(items[1], items[0].key()), x509::error_t::SIGNATURE) << CHAINS[i];
		// Проверяем отказ подписи корня ключом промежуточного издателя
		ASSERT_EQ(x509::verify(items[2], items[1].key()), x509::error_t::SIGNATURE) << CHAINS[i];
		// Число неиспользуемых разрядов последнего байта подписи
		uint8_t unused = 0;
		// Получаем подпись листа цепочки
		const view_t & signature = items[0].sign(unused);
		// Копия записи листа цепочки
		std::vector <uint8_t> copy = chain[0];
		// Определяем место подписи в записи листа
		const size_t place = static_cast <size_t> (signature.data - chain[0].data());
		/**
		 * Выполняем перебор байтов подписи листа
		 */
		for(size_t j = 0; j < signature.size; j += 3){
			// Портим очередной байт подписи
			copy[place + j] = static_cast <uint8_t> (copy[place + j] ^ 0x01);
			// Объект разбираемого испорченного листа
			x509::certificate_t item;
			// Выполняем разбор испорченного листа
			ASSERT_EQ(item.parse(view_t(copy.data(), copy.size())), x509::error_t::NONE) << CHAINS[i];
			// Проверяем, что испорченная подпись ключом издателя не сходится
			ASSERT_EQ(x509::verify(item, items[1].key()), x509::error_t::SIGNATURE) << CHAINS[i] << ", место порчи: " << j;
			// Возвращаем байт подписи на место
			copy[place + j] = static_cast <uint8_t> (copy[place + j] ^ 0x01);
		}
	}
	// Записи сертификатов цепочки RSA
	std::vector <std::vector <uint8_t>> rsa;
	// Записи сертификатов цепочки эллиптической кривой
	std::vector <std::vector <uint8_t>> ec;
	// Выполняем чтение обеих цепочек
	ASSERT_TRUE(corpus(CHAINS[0], rsa) && corpus(CHAINS[1], ec));
	// Разобранные листы обеих цепочек
	x509::certificate_t first, second;
	// Выполняем разбор листа цепочки RSA
	ASSERT_EQ(first.parse(view_t(rsa[0].data(), rsa[0].size())), x509::error_t::NONE);
	// Выполняем разбор листа цепочки эллиптической кривой
	ASSERT_EQ(second.parse(view_t(ec[0].data(), ec[0].size())), x509::error_t::NONE);
	// Проверяем отказ ключа чужого алгоритма у листа RSA
	ASSERT_EQ(x509::verify(first, second.key()), x509::error_t::KEY);
	// Проверяем отказ ключа чужого алгоритма у листа эллиптической кривой
	ASSERT_EQ(x509::verify(second, first.key()), x509::error_t::KEY);
	// Запись просроченного листа, изданного корнем цепочки эллиптической кривой
	std::vector <uint8_t> expired;
	// Выполняем чтение просроченного листа
	ASSERT_TRUE(solo("expired.crt", expired));
	// Разобранные просроченный лист и корень
	x509::certificate_t third, root;
	// Выполняем разбор просроченного листа
	ASSERT_EQ(third.parse(view_t(expired.data(), expired.size())), x509::error_t::NONE);
	// Выполняем разбор корня цепочки эллиптической кривой
	ASSERT_EQ(root.parse(view_t(ec[2].data(), ec[2].size())), x509::error_t::NONE);
	// Проверяем, что подпись просроченного листа корнем сходится: срок действия подписи не касается
	ASSERT_EQ(x509::verify(third, root.key()), x509::error_t::NONE);
	// Проверяем отказ подписи просроченного листа ключом промежуточного издателя
	ASSERT_EQ(x509::verify(third, second.key()), x509::error_t::SIGNATURE);
}
/**
 * @brief Проверка подписи владения классическим ключом по правилам TLS 1.3
 *
 */
TEST(SignatureTest, Possession) {
	// Подписанное содержимое
	const view_t content(reinterpret_cast <const uint8_t *> (POSSESSION), ::strlen(POSSESSION));
	// Записи сертификатов ключей набора образцов
	std::vector <uint8_t> rsa, ec256, ed25519;
	// Выполняем чтение сертификата ключа RSA
	ASSERT_TRUE(solo("rsa2048.crt", rsa));
	// Выполняем чтение сертификата ключа эллиптической кривой P-256
	ASSERT_TRUE(solo("ec256.crt", ec256));
	// Выполняем чтение сертификата ключа Ed25519
	ASSERT_TRUE(solo("ed25519.crt", ed25519));
	// Запись сертификата ключа эллиптической кривой P-384
	const std::vector <uint8_t> ec384 = bytes(CERTIFICATE_EC384);
	// Разобранные сертификаты ключей
	x509::certificate_t first, second, third, fourth;
	// Выполняем разбор сертификата ключа RSA
	ASSERT_EQ(first.parse(view_t(rsa.data(), rsa.size())), x509::error_t::NONE);
	// Выполняем разбор сертификата ключа эллиптической кривой P-256
	ASSERT_EQ(second.parse(view_t(ec256.data(), ec256.size())), x509::error_t::NONE);
	// Выполняем разбор сертификата ключа Ed25519
	ASSERT_EQ(third.parse(view_t(ed25519.data(), ed25519.size())), x509::error_t::NONE);
	// Выполняем разбор сертификата ключа эллиптической кривой P-384
	ASSERT_EQ(fourth.parse(view_t(ec384.data(), ec384.size())), x509::error_t::NONE);
	// Подписи содержимого, выработанные OpenSSL 3
	const std::vector <uint8_t> pss = bytes(SIGNATURE_PSS), pkcs1 = bytes(SIGNATURE_PKCS1), sec256 = bytes(SIGNATURE_EC256), sec384 = bytes(SIGNATURE_EC384), sed = bytes(SIGNATURE_ED25519);
	// Проверяем подпись владения ключом RSA по схеме RSASSA-PSS
	ASSERT_EQ(x509::check(first.key(), digest::hash_t::SHA256, content, view_t(pss.data(), pss.size())), x509::error_t::NONE);
	// Проверяем отказ подписи владения ключом RSA по схеме PKCS #1 v1.5
	ASSERT_EQ(x509::check(first.key(), digest::hash_t::SHA256, content, view_t(pkcs1.data(), pkcs1.size())), x509::error_t::SIGNATURE);
	// Проверяем отказ подписи владения ключом RSA с чужим хешем
	ASSERT_EQ(x509::check(first.key(), digest::hash_t::SHA384, content, view_t(pss.data(), pss.size())), x509::error_t::SIGNATURE);
	// Проверяем отказ подписи владения ключом RSA без алгоритма хеша
	ASSERT_EQ(x509::check(first.key(), digest::hash_t::NONE, content, view_t(pss.data(), pss.size())), x509::error_t::SIGNATURE);
	// Проверяем подпись владения ключом эллиптической кривой P-256
	ASSERT_EQ(x509::check(second.key(), digest::hash_t::SHA256, content, view_t(sec256.data(), sec256.size())), x509::error_t::NONE);
	// Проверяем отказ подписи владения ключом P-256 с чужим хешем
	ASSERT_EQ(x509::check(second.key(), digest::hash_t::SHA384, content, view_t(sec256.data(), sec256.size())), x509::error_t::SIGNATURE);
	// Проверяем отказ подписи владения ключом P-256 сырой записью вместо SEQUENCE {r, s}
	ASSERT_EQ(x509::check(second.key(), digest::hash_t::SHA256, content, view_t(sec256.data() + 6, 64)), x509::error_t::SIGNATURE);
	// Проверяем подпись владения ключом эллиптической кривой P-384
	ASSERT_EQ(x509::check(fourth.key(), digest::hash_t::SHA384, content, view_t(sec384.data(), sec384.size())), x509::error_t::NONE);
	// Проверяем отказ подписи владения ключом P-384 подписью ключа P-256
	ASSERT_EQ(x509::check(fourth.key(), digest::hash_t::SHA256, content, view_t(sec256.data(), sec256.size())), x509::error_t::SIGNATURE);
	// Проверяем подпись владения ключом Ed25519: алгоритм хеша не рассматривается
	ASSERT_EQ(x509::check(third.key(), digest::hash_t::NONE, content, view_t(sed.data(), sed.size())), x509::error_t::NONE);
	// Проверяем подпись владения ключом Ed25519 при заданном алгоритме хеша
	ASSERT_EQ(x509::check(third.key(), digest::hash_t::SHA512, content, view_t(sed.data(), sed.size())), x509::error_t::NONE);
	// Проверяем отказ подписи владения ключом Ed25519 неполной длины
	ASSERT_EQ(x509::check(third.key(), digest::hash_t::NONE, content, view_t(sed.data(), sed.size() - 1)), x509::error_t::SIGNATURE);
	// Проверяем отказ подписи чужим ключом того же алгоритма
	ASSERT_EQ(x509::check(second.key(), digest::hash_t::SHA384, content, view_t(sec384.data(), sec384.size())), x509::error_t::SIGNATURE);
	// Проверяем отказ подписи владения ключом Ed25519 подписью RSA
	ASSERT_EQ(x509::check(third.key(), digest::hash_t::SHA256, content, view_t(pss.data(), pss.size())), x509::error_t::SIGNATURE);
	// Проверяем отказ пустого содержимого
	ASSERT_EQ(x509::check(second.key(), digest::hash_t::SHA256, view_t(), view_t(sec256.data(), sec256.size())), x509::error_t::SIGNATURE);
	// Копия подписанного содержимого
	std::string altered(POSSESSION);
	// Портим подписанное содержимое
	altered[0] = 'a';
	// Просмотр испорченного содержимого
	const view_t spoiled(reinterpret_cast <const uint8_t *> (altered.data()), altered.size());
	// Проверяем отказ подписи RSA испорченного содержимого
	ASSERT_EQ(x509::check(first.key(), digest::hash_t::SHA256, spoiled, view_t(pss.data(), pss.size())), x509::error_t::SIGNATURE);
	// Проверяем отказ подписи P-256 испорченного содержимого
	ASSERT_EQ(x509::check(second.key(), digest::hash_t::SHA256, spoiled, view_t(sec256.data(), sec256.size())), x509::error_t::SIGNATURE);
	// Проверяем отказ подписи Ed25519 испорченного содержимого
	ASSERT_EQ(x509::check(third.key(), digest::hash_t::NONE, spoiled, view_t(sed.data(), sed.size())), x509::error_t::SIGNATURE);
	// Копии подписей ради порчи
	std::vector <uint8_t> pssed = pss, seced = sec256, eded = sed;
	/**
	 * Выполняем перебор байтов подписей: всякая порча даёт отказ
	 */
	for(size_t j = 0; j < 64; j += 7){
		// Портим очередной байт подписи RSA
		pssed[j] = static_cast <uint8_t> (pssed[j] ^ 0x01);
		// Портим очередной байт подписи P-256, минуя заголовок записи
		seced[j + 4] = static_cast <uint8_t> (seced[j + 4] ^ 0x01);
		// Портим очередной байт подписи Ed25519
		eded[j] = static_cast <uint8_t> (eded[j] ^ 0x01);
		// Проверяем отказ испорченной подписи RSA
		ASSERT_EQ(x509::check(first.key(), digest::hash_t::SHA256, content, view_t(pssed.data(), pssed.size())), x509::error_t::SIGNATURE) << "место порчи: " << j;
		// Проверяем отказ испорченной подписи P-256
		ASSERT_EQ(x509::check(second.key(), digest::hash_t::SHA256, content, view_t(seced.data(), seced.size())), x509::error_t::SIGNATURE) << "место порчи: " << j;
		// Проверяем отказ испорченной подписи Ed25519
		ASSERT_EQ(x509::check(third.key(), digest::hash_t::NONE, content, view_t(eded.data(), eded.size())), x509::error_t::SIGNATURE) << "место порчи: " << j;
		// Возвращаем байт подписи RSA на место
		pssed[j] = static_cast <uint8_t> (pssed[j] ^ 0x01);
		// Возвращаем байт подписи P-256 на место
		seced[j + 4] = static_cast <uint8_t> (seced[j + 4] ^ 0x01);
		// Возвращаем байт подписи Ed25519 на место
		eded[j] = static_cast <uint8_t> (eded[j] ^ 0x01);
	}
	// Запись сертификата ГОСТ
	const std::vector <uint8_t> gost = bytes(CERTIFICATE_FIRST);
	// Объект разбираемого сертификата ГОСТ
	x509::certificate_t fifth;
	// Выполняем разбор сертификата ГОСТ
	ASSERT_EQ(fifth.parse(view_t(gost.data(), gost.size())), x509::error_t::NONE);
	// Проверяем, что ключ ГОСТ проверяет подпись тем же путём, что и без алгоритма хеша
	ASSERT_EQ(x509::check(fifth.key(), digest::hash_t::SHA256, content, view_t(sed.data(), sed.size())), x509::check(fifth.key(), content, view_t(sed.data(), sed.size())));
	// Проверяем отказ подписи ключом ГОСТ подписью Ed25519
	ASSERT_EQ(x509::check(fifth.key(), digest::hash_t::NONE, content, view_t(sed.data(), sed.size())), x509::error_t::SIGNATURE);
	// Сведения об открытом ключе неизвестного алгоритма
	x509::key_t foreign;
	// Устанавливаем опознаватель алгоритма X25519, подписей не имеющего
	foreign.algorithm = "1.3.101.110";
	// Устанавливаем запись открытого ключа
	foreign.key = view_t(sed.data(), 32);
	// Проверяем отказ ключа чужого алгоритма
	ASSERT_EQ(x509::check(foreign, digest::hash_t::SHA256, content, view_t(sed.data(), sed.size())), x509::error_t::KEY);
}
/**
 * @brief Проверка отказов классических ключей негодного устройства
 *
 */
TEST(SignatureTest, Unsuitable) {
	// Записи сертификатов ключей набора образцов
	std::vector <uint8_t> rsa, ec, ed;
	// Выполняем чтение сертификатов набора образцов
	ASSERT_TRUE(solo("rsa2048.crt", rsa) && solo("ec256.crt", ec) && solo("ed25519.crt", ed));
	// Разобранные сертификаты ключей
	x509::certificate_t first, second, third;
	// Выполняем разбор сертификата ключа RSA
	ASSERT_EQ(first.parse(view_t(rsa.data(), rsa.size())), x509::error_t::NONE);
	// Выполняем разбор сертификата ключа эллиптической кривой
	ASSERT_EQ(second.parse(view_t(ec.data(), ec.size())), x509::error_t::NONE);
	// Выполняем разбор сертификата ключа Ed25519
	ASSERT_EQ(third.parse(view_t(ed.data(), ed.size())), x509::error_t::NONE);
	// Копия сведений об открытом ключе RSA
	x509::key_t key = first.key();
	// Объявляем неполный последний байт ключа
	key.unused = 1;
	// Проверяем отказ ключа с неполным последним байтом
	ASSERT_EQ(x509::verify(first, key), x509::error_t::SIGNATURE);
	// Возвращаем сведения об открытом ключе RSA
	key = first.key();
	// Устанавливаем ключу RSA настройки, которых у него быть не должно
	key.parameters = second.key().parameters;
	// Проверяем отказ ключа RSA с настройками
	ASSERT_EQ(x509::verify(first, key), x509::error_t::SIGNATURE);
	// Возвращаем сведения об открытом ключе RSA
	key = first.key();
	// Обрезаем запись ключа RSA
	key.key.size -= 1;
	// Проверяем отказ ключа RSA с обрезанной записью
	ASSERT_EQ(x509::verify(first, key), x509::error_t::SIGNATURE);
	// Копия сведений об открытом ключе эллиптической кривой
	key = second.key();
	// Убираем настройки ключа: именованной кривой без них нет
	key.parameters = view_t();
	// Проверяем отказ ключа эллиптической кривой без настроек
	ASSERT_EQ(x509::verify(second, key), x509::error_t::SIGNATURE);
	// Возвращаем сведения об открытом ключе эллиптической кривой
	key = second.key();
	// Устанавливаем ключу эллиптической кривой настройки, не несущие опознавателя
	key.parameters = first.key().parameters;
	// Проверяем отказ ключа эллиптической кривой с негодными настройками
	ASSERT_EQ(x509::verify(second, key), x509::error_t::SIGNATURE);
	// Возвращаем сведения об открытом ключе эллиптической кривой
	key = second.key();
	// Копия записи точки ключа
	std::vector <uint8_t> point(key.key.data, key.key.data + key.key.size);
	// Объявляем точку сжатой записью
	point[0] = 0x02;
	// Устанавливаем запись точки ключа
	key.key = view_t(point.data(), point.size());
	// Проверяем отказ ключа эллиптической кривой в сжатой записи
	ASSERT_EQ(x509::verify(second, key), x509::error_t::SIGNATURE);
	// Возвращаем запись точки ключа
	point[0] = 0x04;
	// Портим координату точки: точка сходит с кривой
	point[5] = static_cast <uint8_t> (point[5] ^ 0x01);
	// Проверяем отказ ключа эллиптической кривой с точкой вне кривой
	ASSERT_EQ(x509::verify(second, key), x509::error_t::SIGNATURE);
	// Копия сведений об открытом ключе Ed25519
	key = third.key();
	// Устанавливаем ключу Ed25519 настройки, которых у алгоритма нет
	key.parameters = first.key().parameters;
	// Проверяем отказ ключа Ed25519 с настройками
	ASSERT_EQ(x509::verify(third, key), x509::error_t::SIGNATURE);
	// Возвращаем сведения об открытом ключе Ed25519
	key = third.key();
	// Обрезаем запись ключа Ed25519
	key.key.size -= 1;
	// Проверяем отказ ключа Ed25519 неполной длины
	ASSERT_EQ(x509::verify(third, key), x509::error_t::SIGNATURE);
	// Возвращаем сведения об открытом ключе Ed25519
	key = third.key();
	// Число неиспользуемых разрядов последнего байта подписи
	uint8_t unused = 0;
	// Получаем подпись сертификата Ed25519
	const view_t & signature = third.sign(unused);
	// Проверяем отказ подписи Ed25519 неполной длины
	ASSERT_EQ(x509::verify(third.body(), view_t(signature.data, signature.size - 1), third.algorithms(), key), x509::error_t::SIGNATURE);
	// Проверяем отказ подписи Ed25519 ключом Ed448 по опознавателю подписи
	ASSERT_EQ(x509::verify(third.body(), signature, "1.3.101.113", key), x509::error_t::KEY);
	// Проверяем отказ неизвестного алгоритма подписи
	ASSERT_EQ(x509::verify(third.body(), signature, "1.2.3.4.5.6.7.8.9", key), x509::error_t::SIGNATURE);
	// Проверяем отказ подписи Ed25519 ключом ГОСТ по опознавателю подписи
	ASSERT_EQ(x509::verify(third.body(), signature, "1.2.643.7.1.1.3.2", key), x509::error_t::KEY);
}
/**
 * @brief Проверка ответа классической проверки при нехватке памяти
 *
 */
TEST(SignatureTest, ClassicStarved) {
	// Имена файлов сертификатов набора образцов
	static const char * NAMES[2] = {"ec256.crt", "ed25519.crt"};
	/**
	 * Выполняем перебор сертификатов набора образцов
	 */
	for(size_t i = 0; i < 2; i++){
		// Запись сертификата
		std::vector <uint8_t> data;
		// Выполняем чтение сертификата набора образцов
		ASSERT_TRUE(solo(NAMES[i], data)) << NAMES[i];
		// Объект разбираемого сертификата
		x509::certificate_t certificate;
		// Выполняем разбор сертификата
		ASSERT_EQ(certificate.parse(view_t(data.data(), data.size())), x509::error_t::NONE) << NAMES[i];
		// Признак того, что подпись хоть раз сошлась
		bool verified = false;
		/**
		 * Выполняем перебор запасов выделений при проверке подписи
		 */
		for(size_t budget = 0; budget < 64; budget++){
			// Итог проверки подписи при отмеренном запасе
			x509::error_t outcome = x509::error_t::NONE;
			{
				// Отмеряем запас выделений на время проверки подписи
				starve::ration_t ration(budget);
				// Выполняем проверку подписи при отмеренном запасе
				outcome = x509::verify(certificate, certificate.key());
			}
			// Проверяем, что проверка ответила схождением либо отказом памяти
			ASSERT_TRUE((outcome == x509::error_t::NONE) || (outcome == x509::error_t::MEMORY)) << NAMES[i] << ", запас " << budget;
			// Запоминаем схождение подписи
			verified = (verified || (outcome == x509::error_t::NONE));
		}
		// Проверяем, что при достаточном запасе подпись сошлась
		ASSERT_TRUE(verified) << NAMES[i];
	}
}
