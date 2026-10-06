/**
 * @file cmp.cpp
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
 * @brief Исходный файл проверок модуля протокола управления сертификатами
 *
 * @note Эталоном служат записи OpenSSL (openssl cmp -reqout_only с защитой
 *       подписью и PBM, ответы мок-сервера openssl cmp -use_mock_srv), круговая
 *       сборка ключами набора tests/corpus
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <main.hpp>
#include <posix.hpp>
#include <pem/pem.hpp>
#include <cmp/cmp.hpp>
#include <keys/keys.hpp>
#include <x509/x509.hpp>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Путь к набору образцов проверок
 */
static const char * CORPUS = ANTS_CORPUS;

/**
 * Служебные объекты проверок модуля CMP
 */
namespace {
	/**
	 * @brief Метод чтения файла целиком
	 *
	 * @param path путь к читаемому файлу
	 *
	 * @return     содержимое файла
	 *
	 */
	static std::string slurp(const std::string & path) {
		// Открываем файл на чтение
		std::ifstream file(path, std::ios::binary);
		// Читаем содержимое файла в поток
		std::stringstream stream;
		// Переливаем содержимое файла
		stream << file.rdbuf();
		// Выводим содержимое файла
		return stream.str();
	}
	/**
	 * @brief Метод получения просмотра строки
	 *
	 * @param text строка, на которую заводится просмотр
	 *
	 * @return     просмотр строки
	 *
	 */
	static view_t view(const std::string & text) {
		// Выводим просмотр строки
		return view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size());
	}
	/**
	 * @brief Метод получения просмотра набора байтов
	 *
	 * @param data набор байтов, на который заводится просмотр
	 *
	 * @return     просмотр набора байтов
	 *
	 */
	static view_t view(const std::vector <uint8_t> & data) {
		// Выводим просмотр набора байтов
		return view_t(data.data(), data.size());
	}
	/**
	 * @brief Метод разбора сертификата из записи PEM
	 *
	 * @param path   путь к файлу записи
	 * @param text   место, в которое помещается прочитанная запись
	 * @param blocks место, в которое помещается набор блоков PEM
	 * @param result сертификат, в который помещается итог разбора
	 *
	 */
	static void load(const std::string & path, std::string & text, std::vector <pem::block_t> & blocks, x509::certificate_t & result) {
		// Читаем запись сертификата
		text = slurp(path);
		// Разбираем запись PEM
		ASSERT_EQ(pem::decode(text, blocks), pem::error_t::NONE);
		// Разбираем сертификат
		ASSERT_EQ(result.parse(view(blocks[0].data)), x509::error_t::NONE);
	}
	/**
	 * @brief Метод выполнения команды командной строки
	 *
	 * @param command выполняемая команда
	 *
	 * @return       код завершения команды
	 *
	 */
	static int shell(const std::string & command) noexcept {
		// Выполняем команду без входа
		return std::system((command + " </dev/null").c_str());
	}
	/**
	 * @brief Песочница файлов проверки
	 *
	 */
	typedef struct Sandbox {
		// Путь песочницы
		std::string _path;
		/**
		 * @brief Метод получения пути файла песочницы
		 *
		 * @param name имя файла
		 *
		 * @return     путь файла песочницы
		 *
		 */
		std::string file(const std::string & name) const {
			// Выводим путь файла песочницы
			return this->_path + "/" + name;
		}
		/**
		 * @brief Метод записи содержимого в файл песочницы
		 *
		 * @param name    имя файла
		 * @param content записываемое содержимое
		 *
		 */
		void spill(const std::string & name, const std::string & content) const {
			// Открываем файл на запись
			std::ofstream file(this->file(name), std::ios::binary);
			// Записываем содержимое
			file << content;
		}
		/**
		 * @brief Метод записи набора байтов в файл песочницы
		 *
		 * @param name    имя файла
		 * @param content записываемый набор байтов
		 *
		 */
		void spill(const std::string & name, const std::vector <uint8_t> & content) const {
			// Открываем файл на запись
			std::ofstream file(this->file(name), std::ios::binary);
			// Записываем содержимое
			file.write(reinterpret_cast <const char *> (content.data()), content.size());
		}
		/**
		 * @brief Конструктор песочницы
		 *
		 */
		Sandbox() {
			// Образец пути песочницы
			char pattern[] = "/tmp/ants-cmp-XXXXXX";
			// Заводим каталог песочницы
			const char * made = ::mkdtemp(pattern);
			// Запоминаем путь песочницы
			this->_path = ((made != nullptr) ? made : "/tmp");
		}
		/**
		 * @brief Деструктор песочницы
		 *
		 */
		~Sandbox() {
			// Если песочница заведена
			if(this->_path != "/tmp")
				// Удаляем каталог песочницы
				(void) shell((std::string("rm -rf ") + this->_path).c_str());
		}
	} sandbox_t;
	/**
	 * @brief Метод сборки имени directoryName из общего имени
	 *
	 * @param common общее имя владельца
	 * @param result место, в которое помещается запись GeneralName
	 *
	 */
	static void nameOf(const std::string & common, std::vector <uint8_t> & result) {
		// Записчик записи имени
		asn1::writer_t name;
		// Открываем запись имени
		ASSERT_TRUE(name.open(asn1::tag_t::SEQUENCE));
		// Открываем набор составляющих
		ASSERT_TRUE(name.open(asn1::tag_t::SET));
		// Открываем запись составляющей
		ASSERT_TRUE(name.open(asn1::tag_t::SEQUENCE));
		// Записываем опознаватель общего имени
		ASSERT_TRUE(name.oid("2.5.4.3"));
		// Записываем значение общего имени
		ASSERT_TRUE(name.text(asn1::tag_t::UTF8_STRING, common));
		// Закрываем запись составляющей, набор и запись имени
		ASSERT_TRUE(name.close());
		ASSERT_TRUE(name.close());
		ASSERT_TRUE(name.close());
		// Собираем запись GeneralName
		ASSERT_EQ(cmp::directoryName(name.data(), result), cmp::error_t::NONE);
	}
}

/**
 * @brief Проверка круговой сборки и разбора запроса ir с защитой подписью
 *
 */
TEST(CmpTest, RequestSignRoundtrip) {
	// Песочница файлов проверки
	sandbox_t sandbox;
	// Записи сертификатов и ключи набора образцов
	struct {
		// Файлы сертификата и ключа
		const char * certificate, * key;
		// Алгоритм хеша
		digest::hash_t hash;
	} CASES[] = {
		{"leaf-rsa.crt", "leaf-rsa.key", digest::hash_t::SHA256},
		{"leaf-ec.crt", "leaf-ec.key", digest::hash_t::SHA256},
		{"leaf-rsa.crt", "leaf-rsa.key", digest::hash_t::SHA384}
	};
	// Перебираем записи набора
	for(size_t i = 0; i < (sizeof(CASES) / sizeof(CASES[0])); i++){
		// Запись сертификата и набор блоков PEM
		std::string text;
		// Набор блоков PEM
		std::vector <pem::block_t> blocks;
		// Сертификат владельца
		x509::certificate_t certificate;
		// Разбираем сертификат
		load(std::string(CORPUS) + "/" + CASES[i].certificate, text, blocks, certificate);
		// Секретный ключ подписи
		keys::signer_t signer;
		// Подготавливаем ключ подписи
		ASSERT_EQ(signer.prepare(view(slurp(std::string(CORPUS) + "/" + CASES[i].key))), keys::error_t::NONE);
		// Записи имён отправителя и получателя
		std::vector <uint8_t> sender, recipient;
		// Собираем имена отправителя и получателя
		nameOf("cmp-client", sender);
		nameOf("cmp-ca", recipient);
		// Запись шаблона сертификата
		std::vector <uint8_t> certTemplate;
		// Собираем шаблон сертификата: имя владельца и открытый ключ из сертификата
		ASSERT_EQ(cmp::certTemplate(certificate.subjects().element, certificate.key().element, certTemplate), cmp::error_t::NONE);
		// Запись сообщения
		std::vector <uint8_t> record;
		// Собираем запрос ir с защитой подписью
		ASSERT_EQ(cmp::request(cmp::body_t::IR, view(sender), view(recipient), {view(certTemplate)}, signer, CASES[i].hash, record), cmp::error_t::NONE);
		// Разбираем запись сообщения
		cmp::message_t parsed;
		// Разбор обязан удаться
		ASSERT_EQ(parsed.parse(view(record)), cmp::error_t::NONE);
		// Вид тела обязан быть ir
		ASSERT_EQ(parsed.kind(), cmp::body_t::IR);
		// Издание протокола обязано быть cmp2000
		ASSERT_EQ(parsed.header().pvno, 2);
		// Имена отправителя и получателя обязаны совпасть
		ASSERT_EQ(parsed.header().sender.size, sender.size());
		ASSERT_EQ(::memcmp(parsed.header().sender.data, sender.data(), sender.size()), 0);
		ASSERT_EQ(parsed.header().recipient.size, recipient.size());
		ASSERT_EQ(::memcmp(parsed.header().recipient.data, recipient.data(), recipient.size()), 0);
		// Время создания обязано быть записано
		ASSERT_TRUE(parsed.header().hasTime);
		// Защита обязана быть записана
		ASSERT_TRUE(parsed.protection().size > 0);
		// Разбираем запросы тела
		std::vector <cmp::request_t> requests;
		// Разбор обязан удаться
		ASSERT_EQ(cmp::requests(parsed.body(), requests), cmp::error_t::NONE);
		// Запрос обязан быть один
		ASSERT_EQ(requests.size(), 1);
		// Опознаватель запроса обязан быть нулевым
		ASSERT_EQ(requests[0].id, 0);
		// Шаблон обязан совпасть
		ASSERT_EQ(requests[0].certTemplate.size, certTemplate.size());
		ASSERT_EQ(::memcmp(requests[0].certTemplate.data, certTemplate.data(), certTemplate.size()), 0);
		// Подтверждение владения обязано быть записано
		ASSERT_TRUE(requests[0].popo.size > 0);
		// Проверка защиты ключом владельца обязана удаться
		ASSERT_EQ(cmp::verify(parsed, certificate.key()), cmp::error_t::NONE);
		// Чужой сертификат того же вида ключа
		std::string otherText;
		// Набор блоков PEM чужого сертификата
		std::vector <pem::block_t> otherBlocks;
		// Чужой сертификат
		x509::certificate_t other;
		// Разбираем чужой сертификат
		load(std::string(CORPUS) + ((CASES[i].key[5] == 'r') ? "/mid-rsa.crt" : "/mid-ec.crt"), otherText, otherBlocks, other);
		// Проверка чужим ключом обязана отказать
		ASSERT_EQ(cmp::verify(parsed, other.key()), cmp::error_t::PROTECTION);
	}
}

/**
 * @brief Проверка круговой сборки и разбора запроса cr с защитой PBM
 *
 */
TEST(CmpTest, RequestPbmRoundtrip) {
	// Пароль общего секрета
	static const char * PASSWORD = "cmp-shared-secret";
	// Опознаватель ключа отправителя
	static const char * KID = "client-1";
	// Песочница файлов проверки
	sandbox_t sandbox;
	// Запись сертификата и набор блоков PEM
	std::string text;
	// Набор блоков PEM
	std::vector <pem::block_t> blocks;
	// Сертификат владельца
	x509::certificate_t certificate;
	// Разбираем сертификат
	load(std::string(CORPUS) + "/leaf-rsa.crt", text, blocks, certificate);
	// Записи имён отправителя и получателя
	std::vector <uint8_t> sender, recipient;
	// Собираем имена отправителя и получателя
	nameOf("cmp-client", sender);
	nameOf("cmp-ca", recipient);
	// Запись шаблона сертификата
	std::vector <uint8_t> certTemplate;
	// Собираем шаблон сертификата
	ASSERT_EQ(cmp::certTemplate(certificate.subjects().element, certificate.key().element, certTemplate), cmp::error_t::NONE);
	// Запись сообщения
	std::vector <uint8_t> record;
	// Собираем запрос cr с защитой PBM
	ASSERT_EQ(cmp::request(cmp::body_t::CR, view(sender), view(recipient), {view(certTemplate)}, view(std::string(KID)), view(std::string(PASSWORD)), digest::hash_t::SHA256, record), cmp::error_t::NONE);
	// Разбираем запись сообщения
	cmp::message_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cmp::error_t::NONE);
	// Вид тела обязан быть cr
	ASSERT_EQ(parsed.kind(), cmp::body_t::CR);
	// Алгоритм защиты обязан быть PBM
	ASSERT_EQ(parsed.header().protection, "1.2.840.113533.7.66.13");
	// Опознаватель ключа отправителя обязан совпасть
	ASSERT_EQ(parsed.header().senderKID.size, ::strlen(KID));
	ASSERT_EQ(::memcmp(parsed.header().senderKID.data, KID, ::strlen(KID)), 0);
	// Разбираем запросы тела
	std::vector <cmp::request_t> requests;
	// Разбор обязан удаться
	ASSERT_EQ(cmp::requests(parsed.body(), requests), cmp::error_t::NONE);
	// Запрос обязан быть один
	ASSERT_EQ(requests.size(), 1);
	// Проверка защиты паролем обязана удаться
	ASSERT_EQ(cmp::verify(parsed, view(std::string(PASSWORD))), cmp::error_t::NONE);
	// Проверка чужим паролем обязана отказать
	ASSERT_EQ(cmp::verify(parsed, view(std::string("foreign-secret"))), cmp::error_t::PROTECTION);
}

/**
 * @brief Проверка круговой сборки и разбора ответа ip
 *
 */
TEST(CmpTest, ResponseRoundtrip) {
	// Песочница файлов проверки
	sandbox_t sandbox;
	// Запись сертификата ЦС и набор блоков PEM
	std::string text;
	// Набор блоков PEM
	std::vector <pem::block_t> blocks;
	// Сертификат ЦС
	x509::certificate_t certificate;
	// Разбираем сертификат ЦС
	load(std::string(CORPUS) + "/ca-rsa.crt", text, blocks, certificate);
	// Секретный ключ подписи ЦС
	keys::signer_t signer;
	// Подготавливаем ключ подписи ЦС
	ASSERT_EQ(signer.prepare(view(slurp(std::string(CORPUS) + "/ca-rsa.key"))), keys::error_t::NONE);
	// Записи имён отправителя и получателя
	std::vector <uint8_t> sender, recipient;
	// Собираем имена отправителя и получателя
	nameOf("cmp-ca", sender);
	nameOf("cmp-client", recipient);
	// Ответ о сертификате
	cmp::response_t response;
	// Опознаватель запроса
	response.id = 0;
	// Статус принятия
	response.status.status = cmp::status_t::ACCEPTED;
	// Запись выданного сертификата
	response.certificate = view(blocks[0].data);
	// Запись сообщения
	std::vector <uint8_t> record;
	// Собираем ответ ip с защитой подписью
	ASSERT_EQ(cmp::respond(cmp::body_t::IP, view(sender), view(recipient), {response}, signer, digest::hash_t::SHA256, record), cmp::error_t::NONE);
	// Разбираем запись сообщения
	cmp::message_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cmp::error_t::NONE);
	// Вид тела обязан быть ip
	ASSERT_EQ(parsed.kind(), cmp::body_t::IP);
	// Разбираем ответ тела
	std::vector <view_t> caPubs;
	// Ответы о сертификатах
	std::vector <cmp::response_t> responses;
	// Разбор обязан удаться
	ASSERT_EQ(cmp::response(parsed.body(), caPubs, responses), cmp::error_t::NONE);
	// Сертификатов ЦС быть не должно
	ASSERT_TRUE(caPubs.empty());
	// Ответ обязан быть один
	ASSERT_EQ(responses.size(), 1);
	// Опознаватель запроса обязан быть нулевым
	ASSERT_EQ(responses[0].id, 0);
	// Статус обязан быть принятием
	ASSERT_EQ(responses[0].status.status, cmp::status_t::ACCEPTED);
	// Запись сертификата обязана совпасть
	ASSERT_EQ(responses[0].certificate.size, blocks[0].data.size());
	ASSERT_EQ(::memcmp(responses[0].certificate.data, blocks[0].data.data(), blocks[0].data.size()), 0);
	// Проверка защиты ключом ЦС обязана удаться
	ASSERT_EQ(cmp::verify(parsed, certificate.key()), cmp::error_t::NONE);
}

/**
 * @brief Проверка круговой сборки и разбора подтверждений certConf и pkiConf
 *
 */
TEST(CmpTest, ConfirmRoundtrip) {
	// Песочница файлов проверки
	sandbox_t sandbox;
	// Запись сертификата и набор блоков PEM
	std::string text;
	// Набор блоков PEM
	std::vector <pem::block_t> blocks;
	// Сертификат владельца
	x509::certificate_t certificate;
	// Разбираем сертификат
	load(std::string(CORPUS) + "/leaf-rsa.crt", text, blocks, certificate);
	// Секретный ключ подписи
	keys::signer_t signer;
	// Подготавливаем ключ подписи
	ASSERT_EQ(signer.prepare(view(slurp(std::string(CORPUS) + "/leaf-rsa.key"))), keys::error_t::NONE);
	// Записи имён отправителя и получателя
	std::vector <uint8_t> sender, recipient;
	// Собираем имена отправителя и получателя
	nameOf("cmp-client", sender);
	nameOf("cmp-ca", recipient);
	// Хеш принимаемого сертификата
	uint8_t hash[32];
	// Вырабатываем хеш записи сертификата
	ASSERT_TRUE(digest::hash(digest::hash_t::SHA256, view(blocks[0].data), hash, sizeof(hash)));
	// Запись сообщения certConf
	std::vector <uint8_t> record;
	// Собираем подтверждение сертификата
	ASSERT_EQ(cmp::certConfirm(view(sender), view(recipient), {view_t(hash, sizeof(hash))}, signer, digest::hash_t::SHA256, record), cmp::error_t::NONE);
	// Разбираем запись сообщения
	cmp::message_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cmp::error_t::NONE);
	// Вид тела обязан быть certConf
	ASSERT_EQ(parsed.kind(), cmp::body_t::CERTCONF);
	// Проверка защиты ключом владельца обязана удаться
	ASSERT_EQ(cmp::verify(parsed, certificate.key()), cmp::error_t::NONE);
	// Запись сообщения pkiConf
	std::vector <uint8_t> pkiConf;
	// Собираем подтверждение
	ASSERT_EQ(cmp::confirm(view(sender), view(recipient), signer, digest::hash_t::SHA256, pkiConf), cmp::error_t::NONE);
	// Разбираем запись сообщения
	cmp::message_t parsedConf;
	// Разбор обязан удаться
	ASSERT_EQ(parsedConf.parse(view(pkiConf)), cmp::error_t::NONE);
	// Вид тела обязан быть pkiconf
	ASSERT_EQ(parsedConf.kind(), cmp::body_t::PKICONF);
	// Проверка защиты ключом владельца обязана удаться
	ASSERT_EQ(cmp::verify(parsedConf, certificate.key()), cmp::error_t::NONE);
}

/**
 * @brief Проверка круговой сборки и разбора запроса отзыва rr
 *
 */
TEST(CmpTest, RevokeRoundtrip) {
	// Песочница файлов проверки
	sandbox_t sandbox;
	// Запись сертификата и набор блоков PEM
	std::string text;
	// Набор блоков PEM
	std::vector <pem::block_t> blocks;
	// Сертификат владельца
	x509::certificate_t certificate;
	// Разбираем сертификат
	load(std::string(CORPUS) + "/leaf-rsa.crt", text, blocks, certificate);
	// Секретный ключ подписи
	keys::signer_t signer;
	// Подготавливаем ключ подписи
	ASSERT_EQ(signer.prepare(view(slurp(std::string(CORPUS) + "/leaf-rsa.key"))), keys::error_t::NONE);
	// Записи имён отправителя и получателя
	std::vector <uint8_t> sender, recipient;
	// Собираем имена отправителя и получателя
	nameOf("cmp-client", sender);
	nameOf("cmp-ca", recipient);
	// Запись сообщения
	std::vector <uint8_t> record;
	// Собираем запрос отзыва
	ASSERT_EQ(cmp::revoke(view(sender), view(recipient), certificate.issuers().element, certificate.number(), signer, digest::hash_t::SHA256, record), cmp::error_t::NONE);
	// Разбираем запись сообщения
	cmp::message_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cmp::error_t::NONE);
	// Вид тела обязан быть rr
	ASSERT_EQ(parsed.kind(), cmp::body_t::RR);
	// Проверка защиты ключом владельца обязана удаться
	ASSERT_EQ(cmp::verify(parsed, certificate.key()), cmp::error_t::NONE);
}

/**
 * @brief Проверка круговой сборки и разбора общего сообщения genm
 *
 */
TEST(CmpTest, GeneralRoundtrip) {
	// Песочница файлов проверки
	sandbox_t sandbox;
	// Запись сертификата и набор блоков PEM
	std::string text;
	// Набор блоков PEM
	std::vector <pem::block_t> blocks;
	// Сертификат владельца
	x509::certificate_t certificate;
	// Разбираем сертификат
	load(std::string(CORPUS) + "/leaf-rsa.crt", text, blocks, certificate);
	// Секретный ключ подписи
	keys::signer_t signer;
	// Подготавливаем ключ подписи
	ASSERT_EQ(signer.prepare(view(slurp(std::string(CORPUS) + "/leaf-rsa.key"))), keys::error_t::NONE);
	// Записи имён отправителя и получателя
	std::vector <uint8_t> sender, recipient;
	// Собираем имена отправителя и получателя
	nameOf("cmp-client", sender);
	nameOf("cmp-ca", recipient);
	// Сведения общего сообщения: id-it-caCerts {1.3.6.1.5.5.7.4.17} без значения
	cmp::info_t info;
	// Опознаватель вида сведений
	info.oid = "1.3.6.1.5.5.7.4.17";
	// Запись сообщения
	std::vector <uint8_t> record;
	// Собираем общее сообщение
	ASSERT_EQ(cmp::general(view(sender), view(recipient), {info}, signer, digest::hash_t::SHA256, record), cmp::error_t::NONE);
	// Разбираем запись сообщения
	cmp::message_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cmp::error_t::NONE);
	// Вид тела обязан быть genm
	ASSERT_EQ(parsed.kind(), cmp::body_t::GENM);
	// Разбираем сведения тела
	std::vector <cmp::info_t> infos;
	// Разбор обязан удаться
	ASSERT_EQ(cmp::infos(parsed.body(), infos), cmp::error_t::NONE);
	// Сведения обязаны быть одни
	ASSERT_EQ(infos.size(), 1);
	// Опознаватель обязан совпасть
	ASSERT_EQ(infos[0].oid, info.oid);
	// Значения быть не должно
	ASSERT_TRUE(infos[0].value.size == 0);
	// Проверка защиты ключом владельца обязана удаться
	ASSERT_EQ(cmp::verify(parsed, certificate.key()), cmp::error_t::NONE);
}

/**
 * @brief Проверка круговой сборки и разбора сообщения об отказе error
 *
 */
TEST(CmpTest, FailureRoundtrip) {
	// Песочница файлов проверки
	sandbox_t sandbox;
	// Запись сертификата и набор блоков PEM
	std::string text;
	// Набор блоков PEM
	std::vector <pem::block_t> blocks;
	// Сертификат ЦС
	x509::certificate_t certificate;
	// Разбираем сертификат ЦС
	load(std::string(CORPUS) + "/ca-rsa.crt", text, blocks, certificate);
	// Секретный ключ подписи ЦС
	keys::signer_t signer;
	// Подготавливаем ключ подписи ЦС
	ASSERT_EQ(signer.prepare(view(slurp(std::string(CORPUS) + "/ca-rsa.key"))), keys::error_t::NONE);
	// Записи имён отправителя и получателя
	std::vector <uint8_t> sender, recipient;
	// Собираем имена отправителя и получателя
	nameOf("cmp-ca", sender);
	nameOf("cmp-client", recipient);
	// Сведения о статусе отказа
	cmp::status_info_t status;
	// Статус отклонения
	status.status = cmp::status_t::REJECTION;
	// Строка статуса
	status.strings.push_back("bad request");
	// Сведения об отказе: бит badRequest (2)
	status.failure.assign({0x20, 0x00, 0x00});
	// Запись сообщения
	std::vector <uint8_t> record;
	// Собираем сообщение об отказе
	ASSERT_EQ(cmp::failure(view(sender), view(recipient), status, signer, digest::hash_t::SHA256, record), cmp::error_t::NONE);
	// Разбираем запись сообщения
	cmp::message_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cmp::error_t::NONE);
	// Вид тела обязан быть error
	ASSERT_EQ(parsed.kind(), cmp::body_t::ERROR);
	// Проверка защиты ключом ЦС обязана удаться
	ASSERT_EQ(cmp::verify(parsed, certificate.key()), cmp::error_t::NONE);
}

/**
 * @brief Проверка разбора записи запроса ir от OpenSSL с защитой PBM
 *
 */
TEST(CmpTest, OpensslPbmRequest) {
	// Пароль общего секрета
	static const char * PASSWORD = "12345";
	// Песочница файлов проверки
	sandbox_t sandbox;
	// Вырабатываем запрос ir от OpenSSL с защитой PBM
	if(shell(std::string("openssl cmp -cmd ir -reqout_only ") + sandbox.file("ir.der") +
		" -newkey " + CORPUS + "/leaf-rsa.key -subject \"/CN=cmp-test\"" +
		" -recipient \"/CN=ca-rsa\" -secret pass:" + PASSWORD + " -ref client1 -batch 2>/dev/null") != 0)
		// Пропускаем проверку, если OpenSSL недоступен
		GTEST_SKIP() << "openssl cmp is not available";
	// Читаем запись запроса
	const std::string record = slurp(sandbox.file("ir.der"));
	// Если записи нет
	if(record.empty())
		// Пропускаем проверку
		GTEST_SKIP() << "openssl cmp produced no record";
	// Разбираем запись сообщения
	cmp::message_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cmp::error_t::NONE);
	// Вид тела обязан быть ir
	ASSERT_EQ(parsed.kind(), cmp::body_t::IR);
	// Издание протокола обязано быть cmp2000
	ASSERT_EQ(parsed.header().pvno, 2);
	// Алгоритм защиты обязан быть PBM
	ASSERT_EQ(parsed.header().protection, "1.2.840.113533.7.66.13");
	// Опознаватель ключа отправителя обязан быть client1
	ASSERT_EQ(parsed.header().senderKID.size, 7);
	ASSERT_EQ(::memcmp(parsed.header().senderKID.data, "client1", 7), 0);
	// Метка новизны отправителя обязана быть записана
	ASSERT_TRUE(parsed.header().senderNonce.size > 0);
	// Опознаватель сделки обязан быть записан
	ASSERT_TRUE(parsed.header().transaction.size > 0);
	// Разбираем запросы тела
	std::vector <cmp::request_t> requests;
	// Разбор обязан удаться
	ASSERT_EQ(cmp::requests(parsed.body(), requests), cmp::error_t::NONE);
	// Запрос обязан быть один
	ASSERT_EQ(requests.size(), 1);
	// Проверка защиты паролем обязана удаться
	ASSERT_EQ(cmp::verify(parsed, view(std::string(PASSWORD))), cmp::error_t::NONE);
	// Проверка чужим паролем обязана отказать
	ASSERT_EQ(cmp::verify(parsed, view(std::string("foreign"))), cmp::error_t::PROTECTION);
}

/**
 * @brief Проверка разбора записи запроса ir от OpenSSL с защитой подписью
 *
 */
TEST(CmpTest, OpensslSignRequest) {
	// Песочница файлов проверки
	sandbox_t sandbox;
	// Вырабатываем запрос ir от OpenSSL с защитой подписью
	if(shell(std::string("openssl cmp -cmd ir -reqout_only ") + sandbox.file("ir-sig.der") +
		" -newkey " + CORPUS + "/leaf-rsa.key -subject \"/CN=cmp-test\"" +
		" -cert " + CORPUS + "/leaf-rsa.crt -key " + CORPUS + "/leaf-rsa.key" +
		" -recipient \"/CN=ca-rsa\" -batch 2>/dev/null") != 0)
		// Пропускаем проверку, если OpenSSL недоступен
		GTEST_SKIP() << "openssl cmp is not available";
	// Читаем запись запроса
	const std::string record = slurp(sandbox.file("ir-sig.der"));
	// Если записи нет
	if(record.empty())
		// Пропускаем проверку
		GTEST_SKIP() << "openssl cmp produced no record";
	// Разбираем запись сообщения
	cmp::message_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cmp::error_t::NONE);
	// Вид тела обязан быть ir
	ASSERT_EQ(parsed.kind(), cmp::body_t::IR);
	// Алгоритм защиты обязан быть подписью RSA с SHA-256
	ASSERT_EQ(parsed.header().protection, "1.2.840.113549.1.1.11");
	// Запись сертификата и набор блоков PEM
	std::string text;
	// Набор блоков PEM
	std::vector <pem::block_t> blocks;
	// Сертификат владельца
	x509::certificate_t certificate;
	// Разбираем сертификат
	load(std::string(CORPUS) + "/leaf-rsa.crt", text, blocks, certificate);
	// Проверка защиты ключом владельца обязана удаться
	ASSERT_EQ(cmp::verify(parsed, certificate.key()), cmp::error_t::NONE);
	// Разбираем запросы тела
	std::vector <cmp::request_t> requests;
	// Разбор обязан удаться
	ASSERT_EQ(cmp::requests(parsed.body(), requests), cmp::error_t::NONE);
	// Запрос обязан быть один
	ASSERT_EQ(requests.size(), 1);
	// Дополнительные сертификаты обязаны быть записаны (OpenSSL кладёт цепочку)
	ASSERT_TRUE(parsed.certificates().size() > 0);
}

/**
 * @brief Проверка разбора ответа мок-сервера OpenSSL
 *
 */
TEST(CmpTest, OpensslMockResponse) {
	// Пароль общего секрета
	static const char * PASSWORD = "12345";
	// Песочница файлов проверки
	sandbox_t sandbox;
	// Вырабатываем ответ мок-сервера OpenSSL: ip с выданным сертификатом
	(void) shell(std::string("openssl cmp -use_mock_srv -cmd ir -newkey ") + CORPUS + "/leaf-rsa.key" +
		" -subject \"/CN=cmp-test\" -secret pass:" + PASSWORD + " -ref client1" +
		" -srv_ref MockSrv -srv_secret pass:" + PASSWORD +
		" -rsp_cert " + CORPUS + "/ca-rsa.crt -srvcert " + CORPUS + "/ca-rsa.crt" +
		" -expect_sender \"/CN=ANYKS Root rsa\" -certout " + sandbox.file("cert.pem") +
		" -rspout " + sandbox.file("rsp.der") + " -batch 2>/dev/null");
	// Читаем запись ответа
	const std::string record = slurp(sandbox.file("rsp.der"));
	// Если записи нет
	if(record.empty())
		// Пропускаем проверку
		GTEST_SKIP() << "openssl cmp produced no record";
	// Разбираем запись сообщения
	cmp::message_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cmp::error_t::NONE);
	// Вид тела обязан быть ip
	ASSERT_EQ(parsed.kind(), cmp::body_t::IP);
	// Алгоритм защиты обязан быть PBM
	ASSERT_EQ(parsed.header().protection, "1.2.840.113533.7.66.13");
	// Проверка защиты паролем обязана удаться
	ASSERT_EQ(cmp::verify(parsed, view(std::string(PASSWORD))), cmp::error_t::NONE);
	// Разбираем ответ тела
	std::vector <view_t> caPubs;
	// Ответы о сертификатах
	std::vector <cmp::response_t> responses;
	// Разбор обязан удаться
	ASSERT_EQ(cmp::response(parsed.body(), caPubs, responses), cmp::error_t::NONE);
	// Ответ обязан быть один
	ASSERT_EQ(responses.size(), 1);
	// Статус обязан быть принятием
	ASSERT_EQ(responses[0].status.status, cmp::status_t::ACCEPTED);
	// Запись сертификата обязана быть
	ASSERT_TRUE(responses[0].certificate.size > 0);
	// Разбираем выданный сертификат
	x509::certificate_t issued;
	// Разбор обязан удаться
	ASSERT_EQ(issued.parse(responses[0].certificate), x509::error_t::NONE);
}

/**
 * @brief Проверка приёма нашей записи эталоном OpenSSL
 *
 */
TEST(CmpTest, OpensslAcceptsOurs) {
	// Пароль общего секрета
	static const char * PASSWORD = "12345";
	// Песочница файлов проверки
	sandbox_t sandbox;
	// Запись сертификата и набор блоков PEM
	std::string text;
	// Набор блоков PEM
	std::vector <pem::block_t> blocks;
	// Сертификат владельца
	x509::certificate_t certificate;
	// Разбираем сертификат
	load(std::string(CORPUS) + "/leaf-rsa.crt", text, blocks, certificate);
	// Записи имён отправителя и получателя
	std::vector <uint8_t> sender, recipient;
	// Собираем имена отправителя и получателя
	nameOf("cmp-test", sender);
	nameOf("ca-rsa", recipient);
	// Запись шаблона сертификата
	std::vector <uint8_t> certTemplate;
	// Собираем шаблон сертификата
	ASSERT_EQ(cmp::certTemplate(certificate.subjects().element, certificate.key().element, certTemplate), cmp::error_t::NONE);
	// Запись сообщения
	std::vector <uint8_t> record;
	// Собираем запрос ir с защитой PBM
	ASSERT_EQ(cmp::request(cmp::body_t::IR, view(sender), view(recipient), {view(certTemplate)}, view(std::string("client1")), view(std::string(PASSWORD)), digest::hash_t::SHA256, record), cmp::error_t::NONE);
	// Записываем запрос в файл песочницы
	sandbox.spill("ours.der", record);
	// Отдаём запрос мок-серверу OpenSSL: разбор обязан дойти до проверки полномочий
	const int rc = shell(std::string("openssl cmp -use_mock_srv -reqin ") + sandbox.file("ours.der") +
		" -cmd ir -secret pass:" + PASSWORD + " -ref client1" +
		" -srv_ref MockSrv -srv_secret pass:" + PASSWORD +
		" -srvcert " + CORPUS + "/ca-rsa.crt -batch 2>" + sandbox.file("log.txt"));
	// Читаем журнал
	const std::string log = slurp(sandbox.file("log.txt"));
	// Если OpenSSL недоступен
	if(log.empty() && (rc != 0))
		// Пропускаем проверку
		GTEST_SKIP() << "openssl cmp is not available";
	// В журнале не обязано быть отказа разбора записи (DER parse errors)
	ASSERT_EQ(log.find("error parsing"), std::string::npos);
	ASSERT_EQ(log.find("asn1"), std::string::npos);
	ASSERT_EQ(log.find("bad DER"), std::string::npos);
}

/**
 * @brief Проверка отказов разбора
 *
 */
TEST(CmpTest, Refusals) {
	// Разборщик сообщения
	cmp::message_t parsed;
	// Пустая запись отвергается
	ASSERT_EQ(parsed.parse(view_t()), cmp::error_t::EMPTY);
	// Запись не SEQUENCE отвергается
	static const uint8_t INTEGER_RECORD[] = {0x02, 0x01, 0x00};
	// Разбор отвергается
	ASSERT_EQ(parsed.parse(view_t(INTEGER_RECORD, sizeof(INTEGER_RECORD))), cmp::error_t::STRUCTURE);
	// Обрезанная запись отвергается
	static const uint8_t TRUNCATED[] = {0x30, 0x82, 0x01, 0x00, 0x02};
	// Разбор отвергается
	ASSERT_EQ(parsed.parse(view_t(TRUNCATED, sizeof(TRUNCATED))), cmp::error_t::STRUCTURE);
	// Проверка неразобранного сообщения отвергается
	x509::certificate_t certificate;
	// Проверка отвергается
	ASSERT_EQ(cmp::verify(parsed, certificate.key()), cmp::error_t::EMPTY);
	// Проверка паролем отвергается
	ASSERT_EQ(cmp::verify(parsed, view_t()), cmp::error_t::EMPTY);
}
