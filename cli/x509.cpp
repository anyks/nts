/**
 * @file x509.cpp
 * @date 2026-11-19
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
 * @brief Команды сертификатов консольной утилиты a-nts — запрос PKCS #10, выпуск
 *        и просмотр сертификатов, список отзыва и контейнер PKCS #12
 *
 * @details Команды повторяют устройство openssl: req, x509, ca, crl и pkcs12. Запрос
 *          собирается кодеком x509::request, сертификат выпускается x509::issue
 *          самоподписанным либо подписью удостоверяющего центра, а разбор записей идёт
 *          разборщиками x509::certificate_t, x509::request_t и x509::crl_t
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные модули
 */
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include "common.hpp"
#include "x509.hpp"
#include "sys/wipe.hpp"
#include "asn1/asn1.hpp"
#include "pem/pem.hpp"
#include "keys/keys.hpp"
#include "digest/hash.hpp"
#include "entropy/entropy.hpp"
#include "x509/x509.hpp"
#include "x509/issue.hpp"
#include "x509/request.hpp"
#include "x509/crl.hpp"

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Внутренние служебные объекты
 *
 */
namespace {
	/**
	 * @brief Функция подбора алгоритма хеширования по флагам командной строки
	 *
	 * @param argc длина списка параметров
	 * @param argv список параметров
	 * @return     алгоритм хеширования, SHA-256 по умолчанию
	 *
	 */
	digest::hash_t __nts_hash_kind__(const int argc, const char * const argv[]) noexcept {
		// Если запрошен SHA-1
		if(cli::flag(argc, argv, "-sha1"))
			// Выводим алгоритм SHA-1
			return digest::hash_t::SHA1;
		// Если запрошен SHA-256
		if(cli::flag(argc, argv, "-sha256"))
			// Выводим алгоритм SHA-256
			return digest::hash_t::SHA256;
		// Если запрошен SHA-384
		if(cli::flag(argc, argv, "-sha384"))
			// Выводим алгоритм SHA-384
			return digest::hash_t::SHA384;
		// Если запрошен SHA-512
		if(cli::flag(argc, argv, "-sha512"))
			// Выводим алгоритм SHA-512
			return digest::hash_t::SHA512;
		// Выводим алгоритм по умолчанию SHA-256
		return digest::hash_t::SHA256;
	}

	/**
	 * @brief Функция получения пароля из источника openssl
	 *
	 * @param source источник пароля вида pass:... либо file:..., пустой без пароля
	 * @param result место, в которое помещается пароль
	 * @return       признак успешности получения пароля
	 *
	 */
	bool __nts_password__(const char * source, string & result) noexcept {
		// Если источника пароля нет
		if((source == nullptr) || (source[0] == '\0'))
			// Пароля нет
			return true;
		// Если пароль задан прямо
		if(::strncmp(source, "pass:", 5) == 0){
			// Запоминаем пароль
			result = (source + 5);
			// Выводим успешность получения пароля
			return true;
		}
		// Если пароль задан файлом
		if(::strncmp(source, "file:", 5) == 0){
			// Область прочитанного файла
			vector <uint8_t> bytes;
			// Если файл прочитать не удалось
			if(!cli::readBytes(source + 5, bytes))
				// Выводим отказ получения пароля
				return false;
			// Пароль из прочитанных байтов
			result.assign(reinterpret_cast <const char *> (bytes.data()), bytes.size());
			// Убираем завершающий перевод строки
			if(!result.empty() && (result.back() == '\n'))
				// Убираем перевод строки
				result.pop_back();
			// Выводим успешность получения пароля
			return true;
		}
		// Иначе пароль задан прямо
		result = source;
		// Выводим успешность получения пароля
		return true;
	}

	/**
	 * @brief Функция чтения записи PEM либо DER из файла либо стандартного ввода
	 *
	 * @param path  путь к файлу, пустой для стандартного ввода
	 * @param label метка отбираемой записи PEM, пустая для записи DER
	 * @param result место, в которое помещается тело записи
	 * @return       признак успешности чтения
	 *
	 */
	bool __nts_read_record__(const char * path, const char * label, vector <uint8_t> & result) noexcept {
		// Область прочитанного файла
		vector <uint8_t> bytes;
		// Если ввод прочитать не удалось
		if(!cli::readBytes(path, bytes))
			// Выводим отказ чтения
			return false;
		// Если метка записи не задана, принимаем запись DER как есть
		if((label == nullptr) || (label[0] == '\0')){
			// Запоминаем запись
			result = bytes;
			// Выводим успешность чтения
			return true;
		}
		// Текст записи PEM
		const string text(reinterpret_cast <const char *> (bytes.data()), bytes.size());
		// Набор записей выбранной метки
		vector <vector <uint8_t>> records;
		// Если записи разобрать не удалось либо их нет
		if((pem::decode(text, label, records) != pem::error_t::NONE) || records.empty())
			// Выводим отказ чтения
			return false;
		// Запоминаем тело первой записи
		result = records.front();
		// Выводим успешность чтения
		return true;
	}

	/**
	 * @brief Функция записи тела в обёртку PEM файлом либо на стандартный вывод
	 *
	 * @param path  путь к файлу, пустой для стандартного вывода
	 * @param label метка записи PEM
	 * @param der   записываемое тело записи
	 * @return      признак успешности записи
	 *
	 */
	bool __nts_write_record__(const char * path, const char * label, const vector <uint8_t> & der) noexcept {
		// Запись PEM
		pem::block_t block;
		// Метка записи
		block.label = label;
		// Тело записи
		block.data = der;
		// Текст записи PEM
		string text;
		// Если запись PEM составить не удалось
		if(pem::encode(block, text) != pem::error_t::NONE)
			// Выводим отказ записи
			return false;
		// Выводим итог записи текста
		return cli::writeBytes(path, reinterpret_cast <const uint8_t *> (text.data()), text.size());
	}

	/**
	 * @brief Функция подготовки подписывающего ключа из файла
	 *
	 * @param path     путь к файлу ключа
	 * @param password пароль зашифрованного ключа
	 * @param signer   подготавливаемый подписывающий ключ
	 * @return         признак успешности подготовки
	 *
	 */
	bool __nts_prepare_signer__(const char * path, const string & password, keys::signer_t & signer) noexcept {
		// Область прочитанного файла ключа
		vector <uint8_t> bytes;
		// Если ключ прочитать не удалось
		if(!cli::readBytes(path, bytes))
			// Выводим отказ подготовки
			return false;
		// Текст записи ключа
		const string text(reinterpret_cast <const char *> (bytes.data()), bytes.size());
		// Разобранный ключ
		keys::key_t key;
		// Пароль последовательностью октетов
		const view_t secret(reinterpret_cast <const uint8_t *> (password.data()), password.size());
		// Если ключ разобрать не удалось
		if(keys::decode(text, secret, key) != keys::error_t::NONE)
			// Выводим отказ подготовки
			return false;
		// Запись секретного ключа в кодировке DER
		vector <uint8_t> der;
		// Если секретный ключ в DER записать не удалось
		if(keys::encodePrivateKeyInfo(key, der) != keys::error_t::NONE)
			// Выводим отказ подготовки
			return false;
		// Выводим итог подготовки подписывающего ключа
		return signer.prepare(view_t(der.data(), der.size())) == keys::error_t::NONE;
	}

	/**
	 * @brief Функция построения сведений об открытом ключе из разобранного ключа
	 *
	 * @param source разобранный ключ
	 * @param spki   место, в которое помещается запись SubjectPublicKeyInfo
	 * @param result сведения об открытом ключе, просмотры внутрь spki
	 * @return       признак успешности построения
	 *
	 */
	bool __nts_public_key__(const keys::key_t & source, vector <uint8_t> & spki, x509::key_t & result) noexcept {
		// Если запись SubjectPublicKeyInfo составить не удалось
		if(keys::encodeSubjectPublicKeyInfo(source, spki) != keys::error_t::NONE)
			// Выводим отказ построения
			return false;
		// Разборщик записи SubjectPublicKeyInfo
		asn1::reader_t top(view_t(spki.data(), spki.size()));
		// Разобранный элемент записи
		asn1::element_t element;
		// Если запись SubjectPublicKeyInfo разобрать не удалось
		if(!top.next(asn1::tag_t::SEQUENCE, element))
			// Выводим отказ построения
			return false;
		// Запоминаем запись сведений об открытом ключе целиком
		result.element = element.element;
		// Разборщик содержимого сведений об открытом ключе
		asn1::reader_t info(element.content);
		// Если опознаватель алгоритма разобрать не удалось
		if(!info.next(asn1::tag_t::SEQUENCE, element))
			// Выводим отказ построения
			return false;
		// Разборщик опознавателя алгоритма
		asn1::reader_t algorithm(element.content);
		// Если опознаватель алгоритма разобрать не удалось
		if(!algorithm.next(asn1::tag_t::OBJECT, element))
			// Выводим отказ построения
			return false;
		// Если опознаватель алгоритма извлечь не удалось
		if(asn1::oid(element, result.algorithm) != asn1::error_t::NONE)
			// Выводим отказ построения
			return false;
		// Если настройки алгоритма есть
		if(!algorithm.empty()){
			// Если настройки алгоритма разобрать не удалось
			if(!algorithm.next(element))
				// Выводим отказ построения
				return false;
			// Запоминаем запись настроек алгоритма
			result.parameters = element.element;
		}
		// Если открытый ключ разобрать не удалось
		if(!info.next(asn1::tag_t::BIT_STRING, element))
			// Выводим отказ построения
			return false;
		// Если открытый ключ извлечь не удалось
		if(asn1::bits(element, result.key, result.unused) != asn1::error_t::NONE)
			// Выводим отказ построения
			return false;
		// Выводим успешность построения
		return true;
	}

	/**
	 * @brief Функция построения отличительного имени из строки openssl
	 *
	 * @param text   строка имени вида /C=RU/CN=название
	 * @param result имя, в которое помещается итог разбора
	 * @return       признак успешности разбора
	 *
	 */
	bool __nts_subject__(const char * text, x509::name_t & result) noexcept {
		// Если строки имени нет
		if((text == nullptr) || (text[0] == '\0'))
			// Выводим отказ разбора
			return false;
		// Строка имени
		const string source(text);
		// Разбираемое имя
		x509::name_t name;
		// Смещение разбора строки
		size_t offset = 0;
		/**
		 * Разбираем составляющие имени, разделённые слэшем
		 */
		while(offset < source.size()){
			// Пропускаем разделитель
			if(source[offset] == '/')
				// Переходим к следующему знаку
				offset++;
			// Конец текущей составляющей
			const size_t end = source.find('/', offset);
			// Длина текущей составляющей
			const size_t length = ((end == string::npos) ? (source.size() - offset) : (end - offset));
			// Если составляющая пустая
			if(length == 0)
				// Прерываем разбор
				break;
			// Составляющая имени
			const string item = source.substr(offset, length);
			// Позиция знака равенства
			const size_t equal = item.find('=');
			// Если знака равенства нет
			if(equal == string::npos)
				// Выводим отказ разбора
				return false;
			// Короткое обозначение признака
			const string shortName = item.substr(0, equal);
			// Значение признака
			const string value = item.substr(equal + 1);
			// Опознаватель признака
			const char * oid = nullptr;
			// Если признак CN
			if(shortName == "CN")
				// Опознаватель CN
				oid = "2.5.4.3";
			// Иначе если признак C
			else if(shortName == "C")
				// Опознаватель C
				oid = "2.5.4.6";
			// Иначе если признак L
			else if(shortName == "L")
				// Опознаватель L
				oid = "2.5.4.7";
			// Иначе если признак ST
			else if(shortName == "ST")
				// Опознаватель ST
				oid = "2.5.4.8";
			// Иначе если признак O
			else if(shortName == "O")
				// Опознаватель O
				oid = "2.5.4.10";
			// Иначе если признак OU
			else if(shortName == "OU")
				// Опознаватель OU
				oid = "2.5.4.11";
			// Иначе если признак emailAddress
			else if(shortName == "emailAddress")
				// Опознаватель emailAddress
				oid = "1.2.840.113549.1.9.1";
			// Иначе признак неизвестен
			else return false;
			// Признак имени
			x509::attribute_t attribute;
			// Вид записи значения признака
			attribute.type = asn1::tag_t::UTF8_STRING;
			// Опознаватель признака
			attribute.oid = oid;
			// Значение признака
			attribute.value = value;
			// Составляющая имени
			vector <x509::attribute_t> part;
			// Приписываем признак составляющей
			part.push_back(attribute);
			// Приписываем составляющую имени
			name.parts.push_back(part);
			// Если конец строки не найден
			if(end == string::npos)
				// Прерываем разбор
				break;
			// Переходим к следующей составляющей
			offset = end;
		}
		// Если составляющих имени нет
		if(name.parts.empty())
			// Выводим отказ разбора
			return false;
		// Запоминаем разобранное имя
		result = name;
		// Выводим успешность разбора
		return true;
	}

	/**
	 * @brief Функция выработки случайного порядкового номера
	 *
	 * @param result место, в которое помещается порядковый номер
	 * @return       признак успешности выработки
	 *
	 */
	bool __nts_serial__(vector <uint8_t> & result) noexcept {
		// Отводим место под порядковый номер
		result.assign(16, 0);
		// Если случайные байты выработать не удалось
		if(!entropy::bytes(result.data(), result.size()))
			// Выводим отказ выработки
			return false;
		// Старший бит снимаем: порядковый номер остаётся положительным
		result[0] &= 0x7F;
		// Если номер нулевой, ставим единицу
		if(result[0] == 0)
			// Единица в старшем байте
			result[0] = 1;
		// Выводим успешность выработки
		return true;
	}

	/**
	 * @brief Функция вывода сертификата текстом в виде openssl
	 *
	 * @param certificate выводимый сертификат
	 *
	 */
	void __nts_print_certificate__(const x509::certificate_t & certificate) noexcept {
		// Выводим заголовок сертификата
		cout << "Certificate:" << endl;
		// Выводим раздел сведений
		cout << "    Data:" << endl;
		// Выводим издание сертификата
		cout << "        Version: " << (static_cast <uint32_t> (certificate.release()) + 1) << endl;
		// Порядковый номер сертификата
		const view_t & number = certificate.number();
		// Выводим заголовок порядкового номера
		cout << "        Serial Number:" << endl;
		// Выводим порядковый номер
		cout << "            " << cli::hex(number.data, number.size) << endl;
		// Имя владельца сертификата
		string subject;
		// Если имя владельца собрать не удалось
		if(x509::text(certificate.subjects(), subject) != x509::error_t::NONE)
			// Подставляем пустое имя
			subject.clear();
		// Выводим имя владельца сертификата
		cout << "        Subject: " << subject << endl;
		// Имя издателя сертификата
		string issuer;
		// Если имя издателя собрать не удалось
		if(x509::text(certificate.issuers(), issuer) != x509::error_t::NONE)
			// Подставляем пустое имя
			issuer.clear();
		// Выводим имя издателя сертификата
		cout << "        Issuer: " << issuer << endl;
		// Начало и окончание срока действия
		int64_t before = 0, after = 0;
		// Извлекаем срок действия сертификата
		certificate.validity(before, after);
		// Выводим заголовок срока действия
		cout << "        Validity" << endl;
		// Выводим начало срока действия
		cout << "            Not Before: " << before << endl;
		// Выводим окончание срока действия
		cout << "            Not After : " << after << endl;
		// Выводим опознаватель алгоритма открытого ключа
		cout << "        Subject Public Key Info:" << endl;
		// Выводим опознаватель алгоритма ключа
		cout << "            Public Key Algorithm: " << certificate.key().algorithm << endl;
		// Если расширения сертификата есть
		if(!certificate.extension().empty()){
			// Выводим заголовок расширений
			cout << "        X509v3 extensions:" << endl;
			/**
			 * Перебираем расширения сертификата
			 */
			for(size_t i = 0; i < certificate.extension().size(); i++)
				// Выводим очередное расширение
				cout << "            " << certificate.extension()[i].oid << ": " << (certificate.extension()[i].critical ? "critical" : "") << endl;
		}
	}

	/**
	 * @brief Функция вывода запроса на сертификат текстом
	 *
	 * @param request выводимый запрос
	 *
	 */
	void __nts_print_request__(const x509::request_t & request) noexcept {
		// Выводим заголовок запроса
		cout << "Certificate Request:" << endl;
		// Выводим раздел сведений
		cout << "    Data:" << endl;
		// Имя владельца запроса
		string subject;
		// Если имя владельца собрать не удалось
		if(x509::text(request.subjects(), subject) != x509::error_t::NONE)
			// Подставляем пустое имя
			subject.clear();
		// Выводим имя владельца запроса
		cout << "        Subject: " << subject << endl;
		// Выводим опознаватель алгоритма открытого ключа
		cout << "        Subject Public Key Info:" << endl;
		// Выводим опознаватель алгоритма ключа
		cout << "            Public Key Algorithm: " << request.key().algorithm << endl;
	}

	/**
	 * @brief Функция разбора количества дней срока действия
	 *
	 * @param argc длина списка параметров
	 * @param argv список параметров
	 * @return     количество дней срока действия, тридцать по умолчанию
	 *
	 */
	int64_t __nts_days__(const int argc, const char * const argv[]) noexcept {
		// Значение флага срока действия
		const char * days = cli::value(argc, argv, "-days");
		// Если срок действия не задан
		if((days == nullptr) || (days[0] == '\0'))
			// Срок действия по умолчанию
			return 30;
		// Разобранное количество дней
		const int64_t result = static_cast <int64_t> (::strtoll(days, nullptr, 10));
		// Выводим количество дней, не меньшее единицы
		return ((result < 1) ? 30 : result);
	}
};

/**
 * @brief Функция создания запроса на сертификат
 *
 * @param argc длина списка параметров
 * @param argv список параметров
 * @return     код выхода из команды
 *
 */
int nts::cli::req(const int argc, const char * const argv[]) noexcept {
	// Имя файла ключа
	const char * key = cli::value(argc, argv, "-key");
	// Имя файла вывода
	const char * out = cli::value(argc, argv, "-out");
	// Строка имени владельца
	const char * subj = cli::value(argc, argv, "-subj");
	// Признак вывода запроса текстом
	const bool text = cli::flag(argc, argv, "-text");
	// Пароль чтения ключа
	string passin;
	// Если пароль чтения получить не удалось
	if(!__nts_password__(cli::value(argc, argv, "-passin"), passin)){
		// Печатаем сообщение об отказе получения пароля
		cout << "Получить пароль не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Алгоритм хеширования подписи запроса
	const digest::hash_t hash = __nts_hash_kind__(argc, argv);
	// Если ключ либо вывод не заданы
	if(((key == nullptr) || (key[0] == '\0')) || ((out == nullptr) || (out[0] == '\0'))){
		// Печатаем подсказку команды
		cout << "применение: a-nts req -new -key файл -out файл -subj \"/C=RU/CN=название\" [-sha256]" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Подписывающий ключ запроса
	keys::signer_t signer;
	// Если подписывающий ключ подготовить не удалось
	if(!__nts_prepare_signer__(key, passin, signer)){
		// Печатаем сообщение об отказе подготовки ключа
		cout << "Подготовить ключ не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Имя владельца запроса
	x509::name_t subject;
	// Если имя владельца собрать не удалось
	if(!__nts_subject__(subj, subject)){
		// Печатаем сообщение об отказе разбора имени
		cout << "Разобрать имя владельца не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Разобранный ключ запроса
	keys::key_t decoded;
	// Область прочитанного файла ключа
	vector <uint8_t> bytes;
	// Если ключ прочитать не удалось
	if(!cli::readBytes(key, bytes)){
		// Печатаем сообщение об отказе чтения
		cout << "Прочитать ключ не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Текст записи ключа
	const string keyText(reinterpret_cast <const char *> (bytes.data()), bytes.size());
	// Пароль последовательностью октетов
	const view_t secret(reinterpret_cast <const uint8_t *> (passin.data()), passin.size());
	// Если ключ разобрать не удалось
	if(keys::decode(keyText, secret, decoded) != keys::error_t::NONE){
		// Печатаем сообщение об отказе разбора ключа
		cout << "Разобрать ключ не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Запись SubjectPublicKeyInfo ключа
	vector <uint8_t> spki;
	// Сведения об открытом ключе запроса
	x509::key_t publicKey;
	// Если сведения об открытом ключе построить не удалось
	if(!__nts_public_key__(decoded, spki, publicKey)){
		// Печатаем сообщение об отказе построения ключа
		cout << "Построить сведения об открытом ключе не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Запись запроса в кодировке DER
	vector <uint8_t> der;
	// Если запрос записать не удалось
	if(x509::encode(subject, publicKey, vector <x509::extension_t> (), signer, hash, der) != x509::error_t::NONE){
		// Печатаем сообщение об отказе записи запроса
		cout << "Записать запрос не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Если запрос записать в файл не удалось
	if(!__nts_write_record__(out, "CERTIFICATE REQUEST", der)){
		// Печатаем сообщение об отказе записи
		cout << "Записать запрос не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Если запрошен вывод запроса текстом
	if(text){
		// Разобранный запрос
		x509::request_t request;
		// Если запрос разобрать не удалось
		if(request.parse(view_t(der.data(), der.size())) == x509::error_t::NONE)
			// Выводим запрос текстом
			__nts_print_request__(request);
	}
	// Затираем пароль
	sys::wipe(passin);
	// Сообщаем об успешности команды
	return EXIT_SUCCESS;
}

/**
 * @brief Функция действий над сертификатом
 *
 * @param argc длина списка параметров
 * @param argv список параметров
 * @return     код выхода из команды
 *
 */
int nts::cli::x509(const int argc, const char * const argv[]) noexcept {
	// Признак работы с запросом на сертификат
	const bool byRequest = cli::flag(argc, argv, "-req");
	// Признак вывода текстом
	const bool text = cli::flag(argc, argv, "-text");
	// Признак отказа от вывода записи
	const bool noout = cli::flag(argc, argv, "-noout");
	// Имя файла ввода
	const char * in = cli::value(argc, argv, "-in");
	// Имя файла вывода
	const char * out = cli::value(argc, argv, "-out");
	// Алгоритм хеширования подписи
	const digest::hash_t hash = __nts_hash_kind__(argc, argv);
	// Если запрошена работа с запросом
	if(byRequest){
		// Если ввод либо вывод не заданы
		if(((in == nullptr) || (in[0] == '\0')) || ((out == nullptr) || (out[0] == '\0'))){
			// Печатаем подсказку команды
			cout << "применение: a-nts x509 -req -in запрос -signkey ключ | -CA ca -CAkey ca.key -out сертификат [-days дней]" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
		// Тело записи запроса
		vector <uint8_t> der;
		// Если запрос прочитать не удалось
		if(!__nts_read_record__(in, "CERTIFICATE REQUEST", der)){
			// Печатаем сообщение об отказе чтения запроса
			cout << "Прочитать запрос не удалось" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
		// Разобранный запрос
		x509::request_t request;
		// Если запрос разобрать не удалось
		if(request.parse(view_t(der.data(), der.size())) != x509::error_t::NONE){
			// Печатаем сообщение об отказе разбора запроса
			cout << "Разобрать запрос не удалось" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
		// Начало и окончание срока действия
		const int64_t before = static_cast <int64_t> (::time(nullptr));
		// Окончание срока действия
		const int64_t after = before + (__nts_days__(argc, argv) * 86400);
		// Порядковый номер сертификата
		vector <uint8_t> serial;
		// Если порядковый номер выработать не удалось
		if(!__nts_serial__(serial)){
			// Печатаем сообщение об отказе выработки номера
			cout << "Выработать порядковый номер не удалось" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
		// Выпущенный сертификат
		vector <uint8_t> issued;
		// Имя ключа самоподписи
		const char * signkey = cli::value(argc, argv, "-signkey");
		// Имя сертификата издателя
		const char * caCert = cli::value(argc, argv, "-CA");
		// Имя ключа издателя
		const char * caKey = cli::value(argc, argv, "-CAkey");
		// Если задан ключ самоподписи
		if((signkey != nullptr) && (signkey[0] != '\0')){
			// Подписывающий ключ
			keys::signer_t signer;
			// Пароль чтения ключа
			string passin;
			// Если пароль чтения получить не удалось
			if(!__nts_password__(cli::value(argc, argv, "-passin"), passin)){
				// Печатаем сообщение об отказе получения пароля
				cout << "Получить пароль не удалось" << endl;
				// Сообщаем об отказе команды
				return EXIT_FAILURE;
			}
			// Если подписывающий ключ подготовить не удалось
			if(!__nts_prepare_signer__(signkey, passin, signer)){
				// Печатаем сообщение об отказе подготовки ключа
				cout << "Подготовить ключ не удалось" << endl;
				// Сообщаем об отказе команды
				return EXIT_FAILURE;
			}
			// Если самоподписанный сертификат выпустить не удалось
			if(x509::issueSelfSigned(request.subjects(), request.key(), signer, hash, view_t(serial.data(), serial.size()), before, after, request.extension(), issued) != x509::error_t::NONE){
				// Печатаем сообщение об отказе выпуска
				cout << "Выпустить сертификат не удалось" << endl;
				// Сообщаем об отказе команды
				return EXIT_FAILURE;
			}
		// Иначе если заданы сертификат и ключ издателя
		} else if(((caCert != nullptr) && (caCert[0] != '\0')) && ((caKey != nullptr) && (caKey[0] != '\0'))){
			// Тело записи сертификата издателя
			vector <uint8_t> caDer;
			// Если сертификат издателя прочитать не удалось
			if(!__nts_read_record__(caCert, "CERTIFICATE", caDer)){
				// Печатаем сообщение об отказе чтения сертификата издателя
				cout << "Прочитать сертификат издателя не удалось" << endl;
				// Сообщаем об отказе команды
				return EXIT_FAILURE;
			}
			// Сертификат издателя
			x509::certificate_t issuer;
			// Если сертификат издателя разобрать не удалось
			if(issuer.parse(view_t(caDer.data(), caDer.size())) != x509::error_t::NONE){
				// Печатаем сообщение об отказе разбора сертификата издателя
				cout << "Разобрать сертификат издателя не удалось" << endl;
				// Сообщаем об отказе команды
				return EXIT_FAILURE;
			}
			// Подписывающий ключ издателя
			keys::signer_t signer;
			// Пароль чтения ключа
			string passin;
			// Если пароль чтения получить не удалось
			if(!__nts_password__(cli::value(argc, argv, "-passin"), passin)){
				// Печатаем сообщение об отказе получения пароля
				cout << "Получить пароль не удалось" << endl;
				// Сообщаем об отказе команды
				return EXIT_FAILURE;
			}
			// Если подписывающий ключ издателя подготовить не удалось
			if(!__nts_prepare_signer__(caKey, passin, signer)){
				// Печатаем сообщение об отказе подготовки ключа
				cout << "Подготовить ключ издателя не удалось" << endl;
				// Сообщаем об отказе команды
				return EXIT_FAILURE;
			}
			// Если сертификат подписью издателя выпустить не удалось
			if(x509::issueByCA(request, issuer.subjects(), signer, hash, view_t(serial.data(), serial.size()), before, after, request.extension(), issued) != x509::error_t::NONE){
				// Печатаем сообщение об отказе выпуска
				cout << "Выпустить сертификат не удалось" << endl;
				// Сообщаем об отказе команды
				return EXIT_FAILURE;
			}
		// Иначе ключ подписи не задан
		} else {
			// Печатаем подсказку команды
			cout << "применение: a-nts x509 -req -in запрос -signkey ключ | -CA ca -CAkey ca.key -out сертификат" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
		// Если сертификат записать не удалось
		if(!__nts_write_record__(out, "CERTIFICATE", issued)){
			// Печатаем сообщение об отказе записи
			cout << "Записать сертификат не удалось" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
		// Если запрошен вывод текстом
		if(text){
			// Разобранный сертификат
			x509::certificate_t certificate;
			// Если сертификат разобрать не удалось
			if(certificate.parse(view_t(issued.data(), issued.size())) == x509::error_t::NONE)
				// Выводим сертификат текстом
				__nts_print_certificate__(certificate);
		}
	// Иначе работаем с готовым сертификатом
	} else {
		// Если ввод не задан
		if((in == nullptr) || (in[0] == '\0')){
			// Печатаем подсказку команды
			cout << "применение: a-nts x509 -in сертификат [-text] [-noout]" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
		// Тело записи сертификата
		vector <uint8_t> der;
		// Если сертификат прочитать не удалось
		if(!__nts_read_record__(in, "CERTIFICATE", der)){
			// Печатаем сообщение об отказе чтения сертификата
			cout << "Прочитать сертификат не удалось" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
		// Разобранный сертификат
		x509::certificate_t certificate;
		// Если сертификат разобрать не удалось
		if(certificate.parse(view_t(der.data(), der.size())) != x509::error_t::NONE){
			// Печатаем сообщение об отказе разбора сертификата
			cout << "Разобрать сертификат не удалось" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
		// Если запрошен вывод текстом
		if(text)
			// Выводим сертификат текстом
			__nts_print_certificate__(certificate);
		// Если вывод записи не запрещён и вывод задан
		if(!noout && (out != nullptr) && (out[0] != '\0')){
			// Если сертификат записать не удалось
			if(!__nts_write_record__(out, "CERTIFICATE", der)){
				// Печатаем сообщение об отказе записи
				cout << "Записать сертификат не удалось" << endl;
				// Сообщаем об отказе команды
				return EXIT_FAILURE;
			}
		}
	}
	// Сообщаем об успешности команды
	return EXIT_SUCCESS;
}

/**
 * @brief Функция выпуска сертификата удостоверяющим центром
 *
 * @param argc длина списка параметров
 * @param argv список параметров
 * @return     код выхода из команды
 *
 */
int nts::cli::issueCa(const int argc, const char * const argv[]) noexcept {
	// Имя файла запроса
	const char * in = cli::value(argc, argv, "-in");
	// Имя файла вывода
	const char * out = cli::value(argc, argv, "-out");
	// Имя сертификата издателя
	const char * caCert = cli::value(argc, argv, "-cert");
	// Имя ключа издателя
	const char * caKey = cli::value(argc, argv, "-keyfile");
	// Если параметры команды не заданы
	if(((in == nullptr) || (in[0] == '\0')) || ((out == nullptr) || (out[0] == '\0')) || ((caCert == nullptr) || (caCert[0] == '\0')) || ((caKey == nullptr) || (caKey[0] == '\0'))){
		// Печатаем подсказку команды
		cout << "применение: a-nts ca -in запрос -cert ca -keyfile ca.key -out сертификат [-days дней]" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Тело записи запроса
	vector <uint8_t> der;
	// Если запрос прочитать не удалось
	if(!__nts_read_record__(in, "CERTIFICATE REQUEST", der)){
		// Печатаем сообщение об отказе чтения запроса
		cout << "Прочитать запрос не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Разобранный запрос
	x509::request_t request;
	// Если запрос разобрать не удалось
	if(request.parse(view_t(der.data(), der.size())) != x509::error_t::NONE){
		// Печатаем сообщение об отказе разбора запроса
		cout << "Разобрать запрос не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Тело записи сертификата издателя
	vector <uint8_t> caDer;
	// Если сертификат издателя прочитать не удалось
	if(!__nts_read_record__(caCert, "CERTIFICATE", caDer)){
		// Печатаем сообщение об отказе чтения сертификата издателя
		cout << "Прочитать сертификат издателя не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Сертификат издателя
	x509::certificate_t issuer;
	// Если сертификат издателя разобрать не удалось
	if(issuer.parse(view_t(caDer.data(), caDer.size())) != x509::error_t::NONE){
		// Печатаем сообщение об отказе разбора сертификата издателя
		cout << "Разобрать сертификат издателя не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Подписывающий ключ издателя
	keys::signer_t signer;
	// Пароль чтения ключа
	string passin;
	// Если пароль чтения получить не удалось
	if(!__nts_password__(cli::value(argc, argv, "-passin"), passin)){
		// Печатаем сообщение об отказе получения пароля
		cout << "Получить пароль не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Если подписывающий ключ издателя подготовить не удалось
	if(!__nts_prepare_signer__(caKey, passin, signer)){
		// Печатаем сообщение об отказе подготовки ключа
		cout << "Подготовить ключ издателя не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Алгоритм хеширования подписи
	const digest::hash_t hash = __nts_hash_kind__(argc, argv);
	// Начало срока действия
	const int64_t before = static_cast <int64_t> (::time(nullptr));
	// Окончание срока действия
	const int64_t after = before + (__nts_days__(argc, argv) * 86400);
	// Порядковый номер сертификата
	vector <uint8_t> serial;
	// Если порядковый номер выработать не удалось
	if(!__nts_serial__(serial)){
		// Печатаем сообщение об отказе выработки номера
		cout << "Выработать порядковый номер не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Выпущенный сертификат
	vector <uint8_t> issued;
	// Если сертификат выпустить не удалось
	if(x509::issueByCA(request, issuer.subjects(), signer, hash, view_t(serial.data(), serial.size()), before, after, request.extension(), issued) != x509::error_t::NONE){
		// Печатаем сообщение об отказе выпуска
		cout << "Выпустить сертификат не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Если сертификат записать не удалось
	if(!__nts_write_record__(out, "CERTIFICATE", issued)){
		// Печатаем сообщение об отказе записи
		cout << "Записать сертификат не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Затираем пароль
	sys::wipe(passin);
	// Сообщаем об успешности команды
	return EXIT_SUCCESS;
}

/**
 * @brief Функция действий над списком отзыва
 *
 * @param argc длина списка параметров
 * @param argv список параметров
 * @return     код выхода из команды
 *
 */
int nts::cli::crl(const int argc, const char * const argv[]) noexcept {
	// Имя файла ввода
	const char * in = cli::value(argc, argv, "-in");
	// Признак вывода текстом
	const bool text = cli::flag(argc, argv, "-text");
	// Если ввод не задан
	if((in == nullptr) || (in[0] == '\0')){
		// Печатаем подсказку команды
		cout << "применение: a-nts crl -in список [-text]" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Тело записи списка отзыва
	vector <uint8_t> der;
	// Если список отзыва прочитать не удалось
	if(!__nts_read_record__(in, "X509 CRL", der)){
		// Печатаем сообщение об отказе чтения списка
		cout << "Прочитать список отзыва не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Разобранный список отзыва
	x509::crl_t crl;
	// Если список отзыва разобрать не удалось
	if(crl.parse(view_t(der.data(), der.size())) != x509::error_t::NONE){
		// Печатаем сообщение об отказе разбора списка
		cout << "Разобрать список отзыва не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Если запрошен вывод текстом
	if(text){
		// Выводим заголовок списка отзыва
		cout << "Certificate Revocation List (CRL):" << endl;
		// Имя издателя списка
		string issuer;
		// Если имя издателя собрать не удалось
		if(x509::text(crl.issuers(), issuer) != x509::error_t::NONE)
			// Подставляем пустое имя
			issuer.clear();
		// Выводим имя издателя списка
		cout << "        Issuer: " << issuer << endl;
		// Дата выпуска и следующего обновления
		int64_t thisUpdate = 0, nextUpdate = 0;
		// Извлекаем даты списка
		crl.updates(thisUpdate, nextUpdate);
		// Выводим дату выпуска
		cout << "        Last Update: " << thisUpdate << endl;
		// Выводим дату следующего обновления
		cout << "        Next Update: " << nextUpdate << endl;
		// Если отозванные сертификаты есть
		if(!crl.revoked().empty()){
			// Выводим заголовок отозванных сертификатов
			cout << "Revoked Certificates:" << endl;
			/**
			 * Перебираем отозванные сертификаты
			 */
			for(size_t i = 0; i < crl.revoked().size(); i++)
				// Выводим очередной отозванный номер
				cout << "    Serial Number: " << cli::hex(crl.revoked()[i].serial.data, crl.revoked()[i].serial.size) << endl;
		}
	}
	// Сообщаем об успешности команды
	return EXIT_SUCCESS;
}

/**
 * @brief Функция действий над контейнером PKCS #12
 *
 * @param argc длина списка параметров
 * @param argv список параметров
 * @return     код выхода из команды
 *
 */
int nts::cli::pkcs12(const int argc, const char * const argv[]) noexcept {
	// Имя файла ввода
	const char * in = cli::value(argc, argv, "-in");
	// Имя файла вывода ключа
	const char * out = cli::value(argc, argv, "-out");
	// Если ввод не задан
	if((in == nullptr) || (in[0] == '\0')){
		// Печатаем подсказку команды
		cout << "применение: a-nts pkcs12 -in контейнер -passin пароль -out ключ" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Пароль контейнера
	string passin;
	// Если пароль получить не удалось
	if(!__nts_password__(cli::value(argc, argv, "-passin"), passin)){
		// Печатаем сообщение об отказе получения пароля
		cout << "Получить пароль не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Область прочитанного контейнера
	vector <uint8_t> bytes;
	// Если контейнер прочитать не удалось
	if(!cli::readBytes(in, bytes)){
		// Печатаем сообщение об отказе чтения
		cout << "Прочитать контейнер не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Разобранный ключ контейнера
	keys::key_t key;
	// Цепочка сертификатов контейнера
	vector <vector <uint8_t>> chain;
	// Пароль последовательностью октетов
	const view_t secret(reinterpret_cast <const uint8_t *> (passin.data()), passin.size());
	// Если контейнер разобрать не удалось
	if(keys::decodePkcs12(view_t(bytes.data(), bytes.size()), secret, key, chain) != keys::error_t::NONE){
		// Печатаем сообщение об отказе разбора контейнера
		cout << "Разобрать контейнер не удалось" << endl;
		// Сообщаем об отказе команды
		return EXIT_FAILURE;
	}
	// Если вывод ключа задан
	if((out != nullptr) && (out[0] != '\0')){
		// Текст записи ключа
		string text;
		// Если ключ записать в PEM не удалось
		if(keys::encode(key, keys::container_t::PRIVATE, text) != keys::error_t::NONE){
			// Печатаем сообщение об отказе записи ключа
			cout << "Записать ключ не удалось" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
		// Если ключ записать не удалось
		if(!cli::writeBytes(out, reinterpret_cast <const uint8_t *> (text.data()), text.size())){
			// Печатаем сообщение об отказе записи
			cout << "Записать ключ не удалось" << endl;
			// Сообщаем об отказе команды
			return EXIT_FAILURE;
		}
	}
	// Затираем пароль
	sys::wipe(passin);
	// Сообщаем об успешности команды
	return EXIT_SUCCESS;
}
