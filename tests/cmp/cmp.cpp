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
#include <starve.hpp>
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

/**
 * @brief Проверка круговой сборки и разбора запроса p10cr (PKCS #10)
 *
 */
TEST(CmpTest, Pkcs10Roundtrip) {
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
	// Вырабатываем запрос PKCS #10 эталоном
	if(shell(std::string("openssl req -new -key ") + CORPUS + "/leaf-rsa.key -out " + sandbox.file("csr.der") + " -outform DER -subj \"/CN=cmp-test\" 2>/dev/null") != 0)
		// Пропускаем проверку, если OpenSSL недоступен
		GTEST_SKIP() << "openssl req is not available";
	// Читаем запись запроса
	const std::string csr = slurp(sandbox.file("csr.der"));
	// Если записи нет
	if(csr.empty())
		// Пропускаем проверку
		GTEST_SKIP() << "openssl req produced no record";
	// Записи имён отправителя и получателя
	std::vector <uint8_t> sender, recipient;
	// Собираем имена отправителя и получателя
	nameOf("cmp-client", sender);
	nameOf("cmp-ca", recipient);
	// Запись сообщения
	std::vector <uint8_t> record;
	// Собираем запрос p10cr с защитой подписью
	ASSERT_EQ(cmp::requestPkcs10(view(sender), view(recipient), view(csr), signer, digest::hash_t::SHA256, record), cmp::error_t::NONE);
	// Разбираем запись сообщения
	cmp::message_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cmp::error_t::NONE);
	// Вид тела обязан быть p10cr
	ASSERT_EQ(parsed.kind(), cmp::body_t::P10CR);
	// Запись запроса обязана совпасть
	ASSERT_EQ(parsed.body().size, csr.size());
	ASSERT_EQ(::memcmp(parsed.body().data, csr.data(), csr.size()), 0);
	// Проверка защиты ключом владельца обязана удаться
	ASSERT_EQ(cmp::verify(parsed, certificate.key()), cmp::error_t::NONE);
}

/**
 * @brief Проверка круговой сборки и разбора вызовов popdecc/popdecr
 *
 */
TEST(CmpTest, ChallengeRoundtrip) {
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
	nameOf("cmp-ca", sender);
	nameOf("cmp-client", recipient);
	// Вызов подтверждения владения
	cmp::challenge_t challenge;
	// Свидетель и вызов
	static const uint8_t WITNESS[] = {0x01, 0x02, 0x03, 0x04};
	static const uint8_t CHALLENGE[] = {0x05, 0x06, 0x07, 0x08};
	// Запоминаем свидетеля и вызов
	challenge.witness = view_t(WITNESS, sizeof(WITNESS));
	challenge.challenge = view_t(CHALLENGE, sizeof(CHALLENGE));
	// Запись сообщения
	std::vector <uint8_t> record;
	// Собираем вызовы popdecc
	ASSERT_EQ(cmp::challenge(view(sender), view(recipient), {challenge}, signer, digest::hash_t::SHA256, record), cmp::error_t::NONE);
	// Разбираем запись сообщения
	cmp::message_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cmp::error_t::NONE);
	// Вид тела обязан быть popdecc
	ASSERT_EQ(parsed.kind(), cmp::body_t::POPDECC);
	// Разбираем вызовы тела
	std::vector <cmp::challenge_t> challenges;
	// Разбор обязан удаться
	ASSERT_EQ(cmp::challenges(parsed.body(), challenges), cmp::error_t::NONE);
	// Вызов обязан быть один
	ASSERT_EQ(challenges.size(), 1);
	// Свидетель и вызов обязаны совпасть
	ASSERT_EQ(challenges[0].witness.size, sizeof(WITNESS));
	ASSERT_EQ(::memcmp(challenges[0].witness.data, WITNESS, sizeof(WITNESS)), 0);
	ASSERT_EQ(challenges[0].challenge.size, sizeof(CHALLENGE));
	ASSERT_EQ(::memcmp(challenges[0].challenge.data, CHALLENGE, sizeof(CHALLENGE)), 0);
	// Проверка защиты ключом ЦС обязана удаться
	ASSERT_EQ(cmp::verify(parsed, certificate.key()), cmp::error_t::NONE);
	// Запись ответа popdecr
	std::vector <uint8_t> reply;
	// Собираем ответы popdecr
	ASSERT_EQ(cmp::challengeReply(view(recipient), view(sender), {42, 7}, signer, digest::hash_t::SHA256, reply), cmp::error_t::NONE);
	// Разбираем запись ответа
	cmp::message_t parsedReply;
	// Разбор обязан удаться
	ASSERT_EQ(parsedReply.parse(view(reply)), cmp::error_t::NONE);
	// Вид тела обязан быть popdecr
	ASSERT_EQ(parsedReply.kind(), cmp::body_t::POPDECR);
	// Разбираем ответы тела
	std::vector <int64_t> answers;
	// Разбор обязан удаться
	ASSERT_EQ(cmp::challengeAnswers(parsedReply.body(), answers), cmp::error_t::NONE);
	// Ответов обязано быть два
	ASSERT_EQ(answers.size(), 2);
	// Числа обязаны совпасть
	ASSERT_EQ(answers[0], 42);
	ASSERT_EQ(answers[1], 7);
}

/**
 * @brief Проверка круговой сборки и разбора ответа восстановления ключа krp
 *
 */
TEST(CmpTest, RecoveryRoundtrip) {
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
	// Ответ восстановления ключа
	cmp::recovery_t recovery;
	// Статус принятия
	recovery.status.status = cmp::status_t::ACCEPTED;
	// Запись нового сертификата подписи
	recovery.certificate = view(blocks[0].data);
	// Записи сертификатов ЦС
	recovery.caCertificates.push_back(view(blocks[0].data));
	// Запись сообщения
	std::vector <uint8_t> record;
	// Собираем ответ krp
	ASSERT_EQ(cmp::recovered(view(sender), view(recipient), recovery, signer, digest::hash_t::SHA256, record), cmp::error_t::NONE);
	// Разбираем запись сообщения
	cmp::message_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cmp::error_t::NONE);
	// Вид тела обязан быть krp
	ASSERT_EQ(parsed.kind(), cmp::body_t::KRP);
	// Разбираем ответ тела
	cmp::recovery_t parsedRecovery;
	// Разбор обязан удаться
	ASSERT_EQ(cmp::recovery(parsed.body(), parsedRecovery), cmp::error_t::NONE);
	// Статус обязан быть принятием
	ASSERT_EQ(parsedRecovery.status.status, cmp::status_t::ACCEPTED);
	// Запись сертификата обязана совпасть
	ASSERT_EQ(parsedRecovery.certificate.size, blocks[0].data.size());
	// Сертификат ЦС обязан быть один
	ASSERT_EQ(parsedRecovery.caCertificates.size(), 1);
	// Проверка защиты ключом ЦС обязана удаться
	ASSERT_EQ(cmp::verify(parsed, certificate.key()), cmp::error_t::NONE);
}

/**
 * @brief Проверка круговой сборки и разбора ответа отзыва rp
 *
 */
TEST(CmpTest, RevokedRoundtrip) {
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
	// Сведения о статусе отзыва
	cmp::status_info_t status;
	// Статус принятия
	status.status = cmp::status_t::ACCEPTED;
	// Запись сообщения
	std::vector <uint8_t> record;
	// Собираем ответ rp
	ASSERT_EQ(cmp::revoked(view(sender), view(recipient), {status}, signer, digest::hash_t::SHA256, record), cmp::error_t::NONE);
	// Разбираем запись сообщения
	cmp::message_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cmp::error_t::NONE);
	// Вид тела обязан быть rp
	ASSERT_EQ(parsed.kind(), cmp::body_t::RP);
	// Разбираем ответ тела
	cmp::revoked_t revoked;
	// Разбор обязан удаться
	ASSERT_EQ(cmp::revoked(parsed.body(), revoked), cmp::error_t::NONE);
	// Статус обязан быть один
	ASSERT_EQ(revoked.statuses.size(), 1);
	// Статус обязан быть принятием
	ASSERT_EQ(revoked.statuses[0].status, cmp::status_t::ACCEPTED);
	// Проверка защиты ключом ЦС обязана удаться
	ASSERT_EQ(cmp::verify(parsed, certificate.key()), cmp::error_t::NONE);
}

/**
 * @brief Проверка круговой сборки и разбора объявлений ckuann/cann/crlann
 *
 */
TEST(CmpTest, AnnouncementsRoundtrip) {
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
	// Запись сообщения ckuann
	std::vector <uint8_t> ckuann;
	// Собираем объявление обновления ключа ЦС
	ASSERT_EQ(cmp::caKeyUpdate(view(sender), view(recipient), view(blocks[0].data), view(blocks[0].data), view(blocks[0].data), signer, digest::hash_t::SHA256, ckuann), cmp::error_t::NONE);
	// Разбираем запись сообщения
	cmp::message_t parsedCkuann;
	// Разбор обязан удаться
	ASSERT_EQ(parsedCkuann.parse(view(ckuann)), cmp::error_t::NONE);
	// Вид тела обязан быть ckuann
	ASSERT_EQ(parsedCkuann.kind(), cmp::body_t::CKUANN);
	// Разбираем объявление тела
	view_t oldWithNew, newWithOld, newWithNew;
	// Разбор обязан удаться
	ASSERT_EQ(cmp::caKeyUpdate(parsedCkuann.body(), oldWithNew, newWithOld, newWithNew), cmp::error_t::NONE);
	// Записи сертификатов обязаны совпасть
	ASSERT_EQ(oldWithNew.size, blocks[0].data.size());
	ASSERT_EQ(newWithOld.size, blocks[0].data.size());
	ASSERT_EQ(newWithNew.size, blocks[0].data.size());
	// Проверка защиты ключом ЦС обязана удаться
	ASSERT_EQ(cmp::verify(parsedCkuann, certificate.key()), cmp::error_t::NONE);
	// Запись сообщения cann
	std::vector <uint8_t> cann;
	// Собираем объявление сертификата
	ASSERT_EQ(cmp::announce(view(sender), view(recipient), view(blocks[0].data), signer, digest::hash_t::SHA256, cann), cmp::error_t::NONE);
	// Разбираем запись сообщения
	cmp::message_t parsedCann;
	// Разбор обязан удаться
	ASSERT_EQ(parsedCann.parse(view(cann)), cmp::error_t::NONE);
	// Вид тела обязан быть cann
	ASSERT_EQ(parsedCann.kind(), cmp::body_t::CANN);
	// Запись сертификата обязана совпасть
	ASSERT_EQ(parsedCann.body().size, blocks[0].data.size());
	// Проверка защиты ключом ЦС обязана удаться
	ASSERT_EQ(cmp::verify(parsedCann, certificate.key()), cmp::error_t::NONE);
	// Запись сообщения crlann
	std::vector <uint8_t> crlann;
	// Читаем запись списка отзыва набора
	const std::string crlText = slurp(std::string(CORPUS) + "/ca-rsa.crl");
	// Если записи нет
	ASSERT_FALSE(crlText.empty());
	// Набор блоков PEM списка отзыва
	std::vector <pem::block_t> crlBlocks;
	// Разбираем запись PEM списка отзыва
	ASSERT_EQ(pem::decode(crlText, crlBlocks), pem::error_t::NONE);
	// Собираем объявление списков отзыва
	ASSERT_EQ(cmp::announceCrls(view(sender), view(recipient), {view(crlBlocks[0].data)}, signer, digest::hash_t::SHA256, crlann), cmp::error_t::NONE);
	// Разбираем запись сообщения
	cmp::message_t parsedCrlann;
	// Разбор обязан удаться
	ASSERT_EQ(parsedCrlann.parse(view(crlann)), cmp::error_t::NONE);
	// Вид тела обязан быть crlann
	ASSERT_EQ(parsedCrlann.kind(), cmp::body_t::CRLANN);
	// Разбираем объявление тела
	std::vector <view_t> crls;
	// Разбор обязан удаться
	ASSERT_EQ(cmp::crlAnnouncement(parsedCrlann.body(), crls), cmp::error_t::NONE);
	// Список обязан быть один
	ASSERT_EQ(crls.size(), 1);
	// Запись списка обязана совпасть
	ASSERT_EQ(crls[0].size, crlBlocks[0].data.size());
	// Проверка защиты ключом ЦС обязана удаться
	ASSERT_EQ(cmp::verify(parsedCrlann, certificate.key()), cmp::error_t::NONE);
}

/**
 * @brief Проверка круговой сборки и разбора объявления отзыва rann
 *
 */
TEST(CmpTest, RevAnnouncementRoundtrip) {
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
	// Объявление отзыва
	cmp::announcement_t announcement;
	// Статус извещения об отзыве
	announcement.status = cmp::status_t::REVOCATION_NOTIFICATION;
	// Время занесения и компрометации
	announcement.willBeRevokedAt = 1780000000;
	announcement.badSinceDate = 1770000000;
	// Опознаватель сертификата CertId: собираем записью issuer+serial
	// Запись опознавателя сертификата (хранится вне блока записчика)
	std::vector <uint8_t> certIdRecord;
	{
		// Записчик записи CertId
		asn1::writer_t certId;
		// Открываем запись CertId
		ASSERT_TRUE(certId.open(asn1::tag_t::SEQUENCE));
		// Переносим запись имени издателя под явной меткой [4] (directoryName)
		ASSERT_TRUE(certId.open(asn1::cls_t::CONTEXT, 4));
		// Разборщик записи имени издателя
		asn1::reader_t reader(certificate.issuers().element);
		// Элемент записи имени
		asn1::element_t name;
		// Разбор обязан удаться
		ASSERT_TRUE(reader.next(name));
		// Переносим содержимое имени
		ASSERT_TRUE(certId.element(name.cls, name.constructed, name.tag, name.content));
		// Закрываем явную метку [4]
		ASSERT_TRUE(certId.close());
		// Записываем порядковый номер
		ASSERT_TRUE(certId.element(asn1::cls_t::UNIVERSAL, false, static_cast <uint32_t> (asn1::tag_t::INTEGER), certificate.number()));
		// Закрываем запись CertId
		ASSERT_TRUE(certId.close());
		// Переносим запись опознавателя в набор байтов: просмотр записчика недолговечен
		certIdRecord.assign(certId.data().data, certId.data().data + certId.data().size);
	}
	// Запоминаем запись опознавателя
	announcement.certificate = view(certIdRecord);
	// Запись сообщения
	std::vector <uint8_t> record;
	// Собираем объявление отзыва
	ASSERT_EQ(cmp::announceRevocation(view(sender), view(recipient), announcement, signer, digest::hash_t::SHA256, record), cmp::error_t::NONE);
	// Разбираем запись сообщения
	cmp::message_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cmp::error_t::NONE);
	// Вид тела обязан быть rann
	ASSERT_EQ(parsed.kind(), cmp::body_t::RANN);
	// Разбираем объявление тела
	cmp::announcement_t parsedAnnouncement;
	// Разбор обязан удаться
	ASSERT_EQ(cmp::announcement(parsed.body(), parsedAnnouncement), cmp::error_t::NONE);
	// Статус обязан быть извещением об отзыве
	ASSERT_EQ(parsedAnnouncement.status, cmp::status_t::REVOCATION_NOTIFICATION);
	// Время обязано совпасть
	ASSERT_EQ(parsedAnnouncement.willBeRevokedAt, 1780000000);
	ASSERT_EQ(parsedAnnouncement.badSinceDate, 1770000000);
	// Проверка защиты ключом ЦС обязана удаться
	ASSERT_EQ(cmp::verify(parsed, certificate.key()), cmp::error_t::NONE);
}

/**
 * @brief Проверка круговой сборки и разбора вложенных сообщений nested
 *
 */
TEST(CmpTest, NestedRoundtrip) {
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
	// Запись шаблона сертификата
	std::vector <uint8_t> certTemplate;
	// Собираем шаблон сертификата
	ASSERT_EQ(cmp::certTemplate(certificate.subjects().element, certificate.key().element, certTemplate), cmp::error_t::NONE);
	// Запись вложенного сообщения ir
	std::vector <uint8_t> inner;
	// Собираем запрос ir
	ASSERT_EQ(cmp::request(cmp::body_t::IR, view(sender), view(recipient), {view(certTemplate)}, signer, digest::hash_t::SHA256, inner), cmp::error_t::NONE);
	// Запись сообщения nested
	std::vector <uint8_t> record;
	// Собираем вложенное сообщение
	ASSERT_EQ(cmp::nest(view(sender), view(recipient), {view(inner)}, signer, digest::hash_t::SHA256, record), cmp::error_t::NONE);
	// Разбираем запись сообщения
	cmp::message_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cmp::error_t::NONE);
	// Вид тела обязан быть nested
	ASSERT_EQ(parsed.kind(), cmp::body_t::NESTED);
	// Разбираем вложенные сообщения
	std::vector <view_t> messages;
	// Разбор обязан удаться
	ASSERT_EQ(cmp::nested(parsed.body(), messages), cmp::error_t::NONE);
	// Вложенное сообщение обязано быть одно
	ASSERT_EQ(messages.size(), 1);
	// Разбираем вложенное сообщение
	cmp::message_t parsedInner;
	// Разбор обязан удаться
	ASSERT_EQ(parsedInner.parse(messages[0]), cmp::error_t::NONE);
	// Вид тела вложенного обязан быть ir
	ASSERT_EQ(parsedInner.kind(), cmp::body_t::IR);
	// Проверка защиты вложенного обязана удаться
	ASSERT_EQ(cmp::verify(parsedInner, certificate.key()), cmp::error_t::NONE);
	// Проверка защиты внешнего обязана удаться
	ASSERT_EQ(cmp::verify(parsed, certificate.key()), cmp::error_t::NONE);
}

/**
 * @brief Проверка круговой сборки и разбора опроса pollReq/pollRep
 *
 */
TEST(CmpTest, PollRoundtrip) {
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
	// Запись сообщения pollReq
	std::vector <uint8_t> pollReq;
	// Собираем запрос опроса
	ASSERT_EQ(cmp::pollRequest(view(sender), view(recipient), {0, 1}, signer, digest::hash_t::SHA256, pollReq), cmp::error_t::NONE);
	// Разбираем запись сообщения
	cmp::message_t parsedReq;
	// Разбор обязан удаться
	ASSERT_EQ(parsedReq.parse(view(pollReq)), cmp::error_t::NONE);
	// Вид тела обязан быть pollReq
	ASSERT_EQ(parsedReq.kind(), cmp::body_t::POLLREQ);
	// Разбираем опрос тела
	std::vector <cmp::poll_t> reqs;
	// Разбор обязан удаться
	ASSERT_EQ(cmp::poll(parsedReq.body(), reqs), cmp::error_t::NONE);
	// Записей обязано быть две
	ASSERT_EQ(reqs.size(), 2);
	// Опознаватели обязаны совпасть
	ASSERT_EQ(reqs[0].id, 0);
	ASSERT_EQ(reqs[1].id, 1);
	// Запись сообщения pollRep
	std::vector <uint8_t> pollRep;
	// Запись опроса ответа
	cmp::poll_t poll;
	// Опознаватель и время ожидания
	poll.id = 0;
	poll.checkAfter = 60;
	// Строка причины
	poll.reason.push_back("waiting");
	// Собираем ответ опроса
	ASSERT_EQ(cmp::pollReply(view(recipient), view(sender), {poll}, signer, digest::hash_t::SHA256, pollRep), cmp::error_t::NONE);
	// Разбираем запись сообщения
	cmp::message_t parsedRep;
	// Разбор обязан удаться
	ASSERT_EQ(parsedRep.parse(view(pollRep)), cmp::error_t::NONE);
	// Вид тела обязан быть pollRep
	ASSERT_EQ(parsedRep.kind(), cmp::body_t::POLLREP);
	// Разбираем опрос тела
	std::vector <cmp::poll_t> reps;
	// Разбор обязан удаться
	ASSERT_EQ(cmp::poll(parsedRep.body(), reps), cmp::error_t::NONE);
	// Запись обязана быть одна
	ASSERT_EQ(reps.size(), 1);
	// Поля обязаны совпасть
	ASSERT_EQ(reps[0].id, 0);
	ASSERT_EQ(reps[0].checkAfter, 60);
	ASSERT_EQ(reps[0].reason.size(), 1);
	ASSERT_EQ(reps[0].reason[0], "waiting");
	// Проверка защиты обязана удаться
	ASSERT_EQ(cmp::verify(parsedRep, certificate.key()), cmp::error_t::NONE);
}

/**
 * @brief Проверка разбора сведений о статусе PKIStatusInfo
 *
 */
TEST(CmpTest, StatusInfo) {
	// Записчик записи сведений о статусе
	asn1::writer_t writer;
	// Открываем запись сведений о статусе
	ASSERT_TRUE(writer.open(asn1::tag_t::SEQUENCE));
	// Записываем статус отклонения
	ASSERT_TRUE(writer.integer(static_cast <int64_t> (2)));
	// Открываем запись строк статуса
	ASSERT_TRUE(writer.open(asn1::tag_t::SEQUENCE));
	// Записываем строку статуса
	ASSERT_TRUE(writer.text(asn1::tag_t::UTF8_STRING, "bad request"));
	// Закрываем запись строк статуса
	ASSERT_TRUE(writer.close());
	// Содержимое строки битов сведений об отказе: бит badRequest (2)
	const uint8_t failure[] = {0x20, 0x00, 0x00};
	// Записываем сведения об отказе строкой битов
	ASSERT_TRUE(writer.bits(view_t(failure, sizeof(failure))));
	// Закрываем запись сведений о статусе
	ASSERT_TRUE(writer.close());
	// Сборка обязана удаться
	ASSERT_EQ(writer.err(), asn1::error_t::NONE);
	// Разборщик собранной записи
	asn1::reader_t reader(writer.data());
	// Элемент записи сведений о статусе
	asn1::element_t element;
	// Разбор обязан удаться
	ASSERT_TRUE(reader.next(element));
	// Сведения о статусе
	cmp::status_info_t info;
	// Разбор сведений обязан удаться
	ASSERT_EQ(cmp::statusInfo(element, info), cmp::error_t::NONE);
	// Статус обязан быть отклонением
	ASSERT_EQ(info.status, cmp::status_t::REJECTION);
	// Строка статуса обязана быть одна и совпасть
	ASSERT_EQ(info.strings.size(), 1);
	ASSERT_EQ(info.strings[0], "bad request");
	// Сведения об отказе обязаны совпасть с записанными
	ASSERT_EQ(info.failure.size(), sizeof(failure));
	ASSERT_EQ(::memcmp(info.failure.data(), failure, sizeof(failure)), 0);
	// Запись статуса без строк и сведений об отказе
	asn1::writer_t brief;
	// Открываем запись сведений о статусе
	ASSERT_TRUE(brief.open(asn1::tag_t::SEQUENCE));
	// Записываем статус за пределами перечня: он отдаётся неизвестным
	ASSERT_TRUE(brief.integer(static_cast <int64_t> (42)));
	// Закрываем запись сведений о статусе
	ASSERT_TRUE(brief.close());
	// Разборщик собранной записи
	asn1::reader_t briefReader(brief.data());
	// Элемент записи сведений о статусе
	asn1::element_t briefElement;
	// Разбор обязан удаться
	ASSERT_TRUE(briefReader.next(briefElement));
	// Сведения о статусе
	cmp::status_info_t briefInfo;
	// Разбор сведений обязан удаться
	ASSERT_EQ(cmp::statusInfo(briefElement, briefInfo), cmp::error_t::NONE);
	// Статус за пределами перечня обязан быть неизвестным
	ASSERT_EQ(briefInfo.status, cmp::status_t::UNKNOWN);
	// Строк и сведений об отказе быть не должно
	ASSERT_TRUE(briefInfo.strings.empty());
	ASSERT_TRUE(briefInfo.failure.empty());
	// Элемент простого вида отвергается: запись статуса составная
	asn1::element_t plain;
	// Разбор обязан отказать устройством записи
	ASSERT_EQ(cmp::statusInfo(plain, briefInfo), cmp::error_t::STRUCTURE);
}

/**
 * @brief Проверка круговой сборки запроса ir с хешами SHA-1/SHA-224/SHA-384/SHA-512
 *
 */
TEST(CmpTest, RequestSignHashes) {
	// Песочница файлов проверки
	sandbox_t sandbox;
	// Записи сертификатов и ключи набора образцов
	struct {
		// Файлы сертификата и ключа
		const char * certificate, * key;
		// Алгоритм хеша
		digest::hash_t hash;
	} CASES[] = {
		{"leaf-rsa.crt", "leaf-rsa.key", digest::hash_t::SHA1},
		{"leaf-rsa.crt", "leaf-rsa.key", digest::hash_t::SHA224},
		{"leaf-rsa.crt", "leaf-rsa.key", digest::hash_t::SHA384},
		{"leaf-rsa.crt", "leaf-rsa.key", digest::hash_t::SHA512},
		{"leaf-ec.crt", "leaf-ec.key", digest::hash_t::SHA224},
		{"leaf-ec.crt", "leaf-ec.key", digest::hash_t::SHA384},
		{"leaf-ec.crt", "leaf-ec.key", digest::hash_t::SHA512}
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
		// Собираем шаблон сертификата
		ASSERT_EQ(cmp::certTemplate(certificate.subjects().element, certificate.key().element, certTemplate), cmp::error_t::NONE);
		// Запись сообщения
		std::vector <uint8_t> record;
		// Собираем запрос ir с защитой подписью
		ASSERT_EQ(cmp::request(cmp::body_t::IR, view(sender), view(recipient), {view(certTemplate)}, signer, CASES[i].hash, record), cmp::error_t::NONE);
		// Разбираем запись сообщения
		cmp::message_t parsed;
		// Разбор обязан удаться
		ASSERT_EQ(parsed.parse(view(record)), cmp::error_t::NONE);
		// Проверка защиты ключом владельца обязана удаться
		ASSERT_EQ(cmp::verify(parsed, certificate.key()), cmp::error_t::NONE);
	}
}

/**
 * @brief Проверка круговой сборки запроса cr с защитой PBM по хешам SHA-1/SHA-224/SHA-384/SHA-512
 *
 */
TEST(CmpTest, RequestPbmHashes) {
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
	// Алгоритмы хешей набора
	const digest::hash_t HASHES[] = {
		digest::hash_t::SHA1,
		digest::hash_t::SHA224,
		digest::hash_t::SHA384,
		digest::hash_t::SHA512
	};
	// Перебираем алгоритмы хешей
	for(size_t i = 0; i < (sizeof(HASHES) / sizeof(HASHES[0])); i++){
		// Запись сообщения
		std::vector <uint8_t> record;
		// Собираем запрос cr с защитой PBM
		ASSERT_EQ(cmp::request(cmp::body_t::CR, view(sender), view(recipient), {view(certTemplate)}, view(std::string(KID)), view(std::string(PASSWORD)), HASHES[i], record), cmp::error_t::NONE);
		// Разбираем запись сообщения
		cmp::message_t parsed;
		// Разбор обязан удаться
		ASSERT_EQ(parsed.parse(view(record)), cmp::error_t::NONE);
		// Проверка защиты паролем обязана удаться
		ASSERT_EQ(cmp::verify(parsed, view(std::string(PASSWORD))), cmp::error_t::NONE);
	}
}

/**
 * @brief Проверка отказов разборщика ответов response
 *
 */
TEST(CmpTest, ResponseRefusals) {
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
	// Пустое тело отвергается
	{
		// Ответы о сертификатах
		std::vector <view_t> caPubs;
		// Ответы
		std::vector <cmp::response_t> responses;
		// Разбор обязан отказать пустой записью
		ASSERT_EQ(cmp::response(view_t(), caPubs, responses), cmp::error_t::EMPTY);
	}
	// Обрезанное тело отвергается
	{
		// Ответы о сертификатах
		std::vector <view_t> caPubs;
		// Ответы
		std::vector <cmp::response_t> responses;
		// Обрезанная запись тела
		view_t truncated(parsed.body().data, parsed.body().size / 2);
		// Разбор обязан отказать
		ASSERT_NE(cmp::response(truncated, caPubs, responses), cmp::error_t::NONE);
	}
	// Тело не SEQUENCE отвергается
	{
		// Ответы о сертификатах
		std::vector <view_t> caPubs;
		// Ответы
		std::vector <cmp::response_t> responses;
		// Запись не SEQUENCE
		static const uint8_t INTEGER_BODY[] = {0x02, 0x01, 0x00};
		// Разбор обязан отказать
		ASSERT_NE(cmp::response(view_t(INTEGER_BODY, sizeof(INTEGER_BODY)), caPubs, responses), cmp::error_t::NONE);
	}
}

/**
 * @brief Проверка отказов разборщика запросов requests
 *
 */
TEST(CmpTest, RequestsRefusals) {
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
	// Запись шаблона сертификата
	std::vector <uint8_t> certTemplate;
	// Собираем шаблон сертификата
	ASSERT_EQ(cmp::certTemplate(certificate.subjects().element, certificate.key().element, certTemplate), cmp::error_t::NONE);
	// Запись сообщения
	std::vector <uint8_t> record;
	// Собираем запрос ir с защитой подписью
	ASSERT_EQ(cmp::request(cmp::body_t::IR, view(sender), view(recipient), {view(certTemplate)}, signer, digest::hash_t::SHA256, record), cmp::error_t::NONE);
	// Разбираем запись сообщения
	cmp::message_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cmp::error_t::NONE);
	// Пустое тело отвергается
	{
		// Запросы
		std::vector <cmp::request_t> requests;
		// Разбор обязан отказать пустой записью
		ASSERT_EQ(cmp::requests(view_t(), requests), cmp::error_t::EMPTY);
	}
	// Обрезанное тело отвергается
	{
		// Запросы
		std::vector <cmp::request_t> requests;
		// Обрезанная запись тела
		view_t truncated(parsed.body().data, parsed.body().size / 2);
		// Разбор обязан отказать
		ASSERT_NE(cmp::requests(truncated, requests), cmp::error_t::NONE);
	}
	// Тело не SEQUENCE отвергается
	{
		// Запросы
		std::vector <cmp::request_t> requests;
		// Запись не SEQUENCE
		static const uint8_t INTEGER_BODY[] = {0x02, 0x01, 0x00};
		// Разбор обязан отказать
		ASSERT_NE(cmp::requests(view_t(INTEGER_BODY, sizeof(INTEGER_BODY)), requests), cmp::error_t::NONE);
	}
}

/**
 * @brief Проверка отказов разборщика отзывов revoked
 *
 */
TEST(CmpTest, RevokedRefusals) {
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
	// Сведения о статусе отзыва
	cmp::status_info_t status;
	// Статус принятия
	status.status = cmp::status_t::ACCEPTED;
	// Запись сообщения
	std::vector <uint8_t> record;
	// Собираем ответ rp
	ASSERT_EQ(cmp::revoked(view(sender), view(recipient), {status}, signer, digest::hash_t::SHA256, record), cmp::error_t::NONE);
	// Разбираем запись сообщения
	cmp::message_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cmp::error_t::NONE);
	// Пустое тело отвергается
	{
		// Ответ отзыва
		cmp::revoked_t revoked;
		// Разбор обязан отказать пустой записью
		ASSERT_EQ(cmp::revoked(view_t(), revoked), cmp::error_t::EMPTY);
	}
	// Обрезанное тело отвергается
	{
		// Ответ отзыва
		cmp::revoked_t revoked;
		// Обрезанная запись тела
		view_t truncated(parsed.body().data, parsed.body().size / 2);
		// Разбор обязан отказать
		ASSERT_NE(cmp::revoked(truncated, revoked), cmp::error_t::NONE);
	}
	// Тело не SEQUENCE отвергается
	{
		// Ответ отзыва
		cmp::revoked_t revoked;
		// Запись не SEQUENCE
		static const uint8_t INTEGER_BODY[] = {0x02, 0x01, 0x00};
		// Разбор обязан отказать
		ASSERT_NE(cmp::revoked(view_t(INTEGER_BODY, sizeof(INTEGER_BODY)), revoked), cmp::error_t::NONE);
	}
}

/**
 * @brief Проверка отказов разборщика восстановления recovery
 *
 */
TEST(CmpTest, RecoveryRefusals) {
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
	// Ответ восстановления ключа
	cmp::recovery_t recovery;
	// Статус принятия
	recovery.status.status = cmp::status_t::ACCEPTED;
	// Запись нового сертификата подписи
	recovery.certificate = view(blocks[0].data);
	// Запись сообщения
	std::vector <uint8_t> record;
	// Собираем ответ krp
	ASSERT_EQ(cmp::recovered(view(sender), view(recipient), recovery, signer, digest::hash_t::SHA256, record), cmp::error_t::NONE);
	// Разбираем запись сообщения
	cmp::message_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cmp::error_t::NONE);
	// Пустое тело отвергается
	{
		// Ответ восстановления
		cmp::recovery_t parsedRecovery;
		// Разбор обязан отказать пустой записью
		ASSERT_EQ(cmp::recovery(view_t(), parsedRecovery), cmp::error_t::EMPTY);
	}
	// Обрезанное тело отвергается
	{
		// Ответ восстановления
		cmp::recovery_t parsedRecovery;
		// Обрезанная запись тела
		view_t truncated(parsed.body().data, parsed.body().size / 2);
		// Разбор обязан отказать
		ASSERT_NE(cmp::recovery(truncated, parsedRecovery), cmp::error_t::NONE);
	}
	// Тело не SEQUENCE отвергается
	{
		// Ответ восстановления
		cmp::recovery_t parsedRecovery;
		// Запись не SEQUENCE
		static const uint8_t INTEGER_BODY[] = {0x02, 0x01, 0x00};
		// Разбор обязан отказать
		ASSERT_NE(cmp::recovery(view_t(INTEGER_BODY, sizeof(INTEGER_BODY)), parsedRecovery), cmp::error_t::NONE);
	}
}

/**
 * @brief Проверка отказов разборщика сведений infos
 *
 */
TEST(CmpTest, InfosRefusals) {
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
	// Пустое тело отвергается
	{
		// Сведения
		std::vector <cmp::info_t> infos;
		// Разбор обязан отказать пустой записью
		ASSERT_EQ(cmp::infos(view_t(), infos), cmp::error_t::EMPTY);
	}
	// Обрезанное тело отвергается
	{
		// Сведения
		std::vector <cmp::info_t> infos;
		// Обрезанная запись тела
		view_t truncated(parsed.body().data, parsed.body().size / 2);
		// Разбор обязан отказать
		ASSERT_NE(cmp::infos(truncated, infos), cmp::error_t::NONE);
	}
	// Тело не SEQUENCE отвергается
	{
		// Сведения
		std::vector <cmp::info_t> infos;
		// Запись не SEQUENCE
		static const uint8_t INTEGER_BODY[] = {0x02, 0x01, 0x00};
		// Разбор обязан отказать
		ASSERT_NE(cmp::infos(view_t(INTEGER_BODY, sizeof(INTEGER_BODY)), infos), cmp::error_t::NONE);
	}
}

/**
 * @brief Проверка отказов разборщика вызовов challenges
 *
 */
TEST(CmpTest, ChallengesRefusals) {
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
	nameOf("cmp-ca", sender);
	nameOf("cmp-client", recipient);
	// Вызов подтверждения владения
	cmp::challenge_t challenge;
	// Свидетель и вызов
	static const uint8_t WITNESS[] = {0x01, 0x02, 0x03, 0x04};
	static const uint8_t CHALLENGE[] = {0x05, 0x06, 0x07, 0x08};
	// Запоминаем свидетеля и вызов
	challenge.witness = view_t(WITNESS, sizeof(WITNESS));
	challenge.challenge = view_t(CHALLENGE, sizeof(CHALLENGE));
	// Запись сообщения
	std::vector <uint8_t> record;
	// Собираем вызовы popdecc
	ASSERT_EQ(cmp::challenge(view(sender), view(recipient), {challenge}, signer, digest::hash_t::SHA256, record), cmp::error_t::NONE);
	// Разбираем запись сообщения
	cmp::message_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cmp::error_t::NONE);
	// Пустое тело отвергается
	{
		// Вызовы
		std::vector <cmp::challenge_t> challenges;
		// Разбор обязан отказать пустой записью
		ASSERT_EQ(cmp::challenges(view_t(), challenges), cmp::error_t::EMPTY);
	}
	// Обрезанное тело отвергается
	{
		// Вызовы
		std::vector <cmp::challenge_t> challenges;
		// Обрезанная запись тела
		view_t truncated(parsed.body().data, parsed.body().size / 2);
		// Разбор обязан отказать
		ASSERT_NE(cmp::challenges(truncated, challenges), cmp::error_t::NONE);
	}
	// Тело не SEQUENCE отвергается
	{
		// Вызовы
		std::vector <cmp::challenge_t> challenges;
		// Запись не SEQUENCE
		static const uint8_t INTEGER_BODY[] = {0x02, 0x01, 0x00};
		// Разбор обязан отказать
		ASSERT_NE(cmp::challenges(view_t(INTEGER_BODY, sizeof(INTEGER_BODY)), challenges), cmp::error_t::NONE);
	}
}

/**
 * @brief Проверка отказов разборщика объявления announcement
 *
 */
TEST(CmpTest, AnnouncementRefusals) {
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
	// Объявление отзыва
	cmp::announcement_t announcement;
	// Статус извещения об отзыве
	announcement.status = cmp::status_t::REVOCATION_NOTIFICATION;
	// Время занесения и компрометации
	announcement.willBeRevokedAt = 1780000000;
	announcement.badSinceDate = 1770000000;
	// Запись опознавателя сертификата (хранится вне блока записчика)
	std::vector <uint8_t> certIdRecord;
	{
		// Записчик записи CertId
		asn1::writer_t certId;
		// Открываем запись CertId
		ASSERT_TRUE(certId.open(asn1::tag_t::SEQUENCE));
		// Переносим запись имени издателя под явной меткой [4] (directoryName)
		ASSERT_TRUE(certId.open(asn1::cls_t::CONTEXT, 4));
		// Разборщик записи имени издателя
		asn1::reader_t reader(certificate.issuers().element);
		// Элемент записи имени
		asn1::element_t name;
		// Разбор обязан удаться
		ASSERT_TRUE(reader.next(name));
		// Переносим содержимое имени
		ASSERT_TRUE(certId.element(name.cls, name.constructed, name.tag, name.content));
		// Закрываем явную метку [4]
		ASSERT_TRUE(certId.close());
		// Записываем порядковый номер
		ASSERT_TRUE(certId.element(asn1::cls_t::UNIVERSAL, false, static_cast <uint32_t> (asn1::tag_t::INTEGER), certificate.number()));
		// Закрываем запись CertId
		ASSERT_TRUE(certId.close());
		// Переносим запись опознавателя в набор байтов
		certIdRecord.assign(certId.data().data, certId.data().data + certId.data().size);
	}
	// Запоминаем запись опознавателя
	announcement.certificate = view(certIdRecord);
	// Запись сообщения
	std::vector <uint8_t> record;
	// Собираем объявление отзыва
	ASSERT_EQ(cmp::announceRevocation(view(sender), view(recipient), announcement, signer, digest::hash_t::SHA256, record), cmp::error_t::NONE);
	// Разбираем запись сообщения
	cmp::message_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(record)), cmp::error_t::NONE);
	// Пустое тело отвергается
	{
		// Объявление
		cmp::announcement_t parsedAnnouncement;
		// Разбор обязан отказать пустой записью
		ASSERT_EQ(cmp::announcement(view_t(), parsedAnnouncement), cmp::error_t::EMPTY);
	}
	// Обрезанное тело отвергается
	{
		// Объявление
		cmp::announcement_t parsedAnnouncement;
		// Обрезанная запись тела
		view_t truncated(parsed.body().data, parsed.body().size / 2);
		// Разбор обязан отказать
		ASSERT_NE(cmp::announcement(truncated, parsedAnnouncement), cmp::error_t::NONE);
	}
	// Тело не SEQUENCE отвергается
	{
		// Объявление
		cmp::announcement_t parsedAnnouncement;
		// Запись не SEQUENCE
		static const uint8_t INTEGER_BODY[] = {0x02, 0x01, 0x00};
		// Разбор обязан отказать
		ASSERT_NE(cmp::announcement(view_t(INTEGER_BODY, sizeof(INTEGER_BODY)), parsedAnnouncement), cmp::error_t::NONE);
	}
}

/**
 * @brief Проверка отказов разборщика опроса poll
 *
 */
TEST(CmpTest, PollRefusals) {
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
	// Запись сообщения pollReq
	std::vector <uint8_t> pollReq;
	// Собираем запрос опроса
	ASSERT_EQ(cmp::pollRequest(view(sender), view(recipient), {0, 1}, signer, digest::hash_t::SHA256, pollReq), cmp::error_t::NONE);
	// Разбираем запись сообщения
	cmp::message_t parsed;
	// Разбор обязан удаться
	ASSERT_EQ(parsed.parse(view(pollReq)), cmp::error_t::NONE);
	// Пустое тело отвергается
	{
		// Записи опроса
		std::vector <cmp::poll_t> reqs;
		// Разбор обязан отказать пустой записью
		ASSERT_EQ(cmp::poll(view_t(), reqs), cmp::error_t::EMPTY);
	}
	// Обрезанное тело отвергается
	{
		// Записи опроса
		std::vector <cmp::poll_t> reqs;
		// Обрезанная запись тела
		view_t truncated(parsed.body().data, parsed.body().size / 2);
		// Разбор обязан отказать
		ASSERT_NE(cmp::poll(truncated, reqs), cmp::error_t::NONE);
	}
	// Тело не SEQUENCE отвергается
	{
		// Записи опроса
		std::vector <cmp::poll_t> reqs;
		// Запись не SEQUENCE
		static const uint8_t INTEGER_BODY[] = {0x02, 0x01, 0x00};
		// Разбор обязан отказать
		ASSERT_NE(cmp::poll(view_t(INTEGER_BODY, sizeof(INTEGER_BODY)), reqs), cmp::error_t::NONE);
	}
}

/**
 * @brief Проверка отказов строителя respond
 *
 */
TEST(CmpTest, RespondRefusals) {
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
	// Вид тела не из ответов отвергается
	ASSERT_EQ(cmp::respond(cmp::body_t::IR, view(sender), view(recipient), {response}, signer, digest::hash_t::SHA256, record), cmp::error_t::EMPTY);
	// Пустой набор ответов отвергается
	ASSERT_EQ(cmp::respond(cmp::body_t::IP, view(sender), view(recipient), {}, signer, digest::hash_t::SHA256, record), cmp::error_t::EMPTY);
}

/**
 * @brief Проверка устойчивости сборки и разбора сообщения к нехватке памяти
 *
 */
TEST(CmpTest, Starved) {
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
	// Запись шаблона сертификата
	std::vector <uint8_t> certTemplate;
	// Собираем шаблон сертификата: имя владельца и открытый ключ из сертификата
	ASSERT_EQ(cmp::certTemplate(certificate.subjects().element, certificate.key().element, certTemplate), cmp::error_t::NONE);
	// Эталонная запись запроса ir с защитой подписью
	std::vector <uint8_t> record;
	// Собираем запрос ir с защитой подписью
	ASSERT_EQ(cmp::request(cmp::body_t::IR, view(sender), view(recipient), {view(certTemplate)}, signer, digest::hash_t::SHA256, record), cmp::error_t::NONE);
	// Набор шаблонов запроса: заводится заранее, чтобы его сборка не попала под подмену выделений
	const std::vector <view_t> templates = {view(certTemplate)};
	// Признак того, что нехватка памяти хоть раз объявлена отказом
	bool starved = false;
	/**
	 * Выполняем перебор запасов выделений: на всяком запасе сборка и разбор обязаны
	 * ответить либо успехом, либо отказом памяти, но не прерыванием исполнения
	 */
	for(size_t budget = 0; budget < 256; budget++){
		// Итог сборки при отмеренном запасе
		cmp::error_t built = cmp::error_t::NONE;
		// Запись собранного сообщения
		std::vector <uint8_t> made;
		{
			// Отмеряем запас выделений на время сборки
			starve::ration_t ration(budget);
			// Выполняем сборку запроса при отмеренном запасе
			built = cmp::request(cmp::body_t::IR, view(sender), view(recipient), templates, signer, digest::hash_t::SHA256, made);
		}
		// Проверяем, что сборка ответила успехом либо отказом памяти
		ASSERT_TRUE((built == cmp::error_t::NONE) || (built == cmp::error_t::MEMORY)) << "запас " << budget << ", отказ сборки " << static_cast <int> (built);
		// Запоминаем объявленный отказ памяти
		starved = (starved || (built == cmp::error_t::MEMORY));
		// Итог разбора эталонной записи при отмеренном запасе
		cmp::error_t parsed = cmp::error_t::NONE;
		{
			// Отмеряем запас выделений на время разбора
			starve::ration_t ration(budget);
			// Разборщик сообщения
			cmp::message_t message;
			// Выполняем разбор эталонной записи при отмеренном запасе
			parsed = message.parse(view(record));
		}
		// Проверяем, что разбор ответил успехом либо отказом памяти
		ASSERT_TRUE((parsed == cmp::error_t::NONE) || (parsed == cmp::error_t::MEMORY)) << "запас " << budget << ", отказ разбора " << static_cast <int> (parsed);
		// Запоминаем объявленный отказ памяти
		starved = (starved || (parsed == cmp::error_t::MEMORY));
	}
	// Проверяем, что нехватка памяти объявлена отказом хоть раз
	ASSERT_TRUE(starved);
}
