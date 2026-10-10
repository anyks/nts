/**
 * @file acme.cpp
 * @date 2026-10-12
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
 * @brief Пример работы с протоколом ACME по RFC 8555 — разбор ответа ресурса
 *        directory, сборка запроса newAccount с телом JWS (подпись ключом учётной
 *        записи) и проверка подписи собранного запроса
 *
 * @details Запрос собирается по разделу 6.2 RFC 8555: заголовок JWS несёт члены
 *          alg, nonce, url и jwk, полезная нагрузка и подпись кодируются в
 *          base64url. Транспортом (HTTPS) модуль не занимается: запрос уходит
 *          строкой тела application/jose+json. Ключ учётной записи берётся из
 *          набора tests/corpus: порождать его на месте образцу не по чину
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные модули
 */
#include <string>
#include <vector>
#include <cstring>
#include <fstream>
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <jws/jws.hpp>
#include <acme/acme.hpp>
#include <keys/keys.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Пространство имён образца
 *
 */
namespace {
	/**
	 * @brief Метод получения просмотра строки знаков
	 *
	 * @param text строка знаков, на которую заводится просмотр
	 *
	 * @return     просмотр области байтов строки знаков
	 *
	 */
	view_t text(const string & text) noexcept {
		// Выводим просмотр области байтов строки знаков
		return view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size());
	}
	/**
	 * @brief Метод чтения файла набора целиком
	 *
	 * @param name имя файла в наборе
	 *
	 * @return     содержимое файла, пустое при отказе чтения
	 *
	 */
	string corpus(const char * name) noexcept {
		// Содержимое файла
		string result;
		/**
		 * Выполняем чтение файла: поток и накопитель занимают память
		 */
		try {
			// Поток чтения файла набора
			ifstream file(string(ANTS_CORPUS) + "/" + name, ios::binary);
			// Если файл открыт
			if(file.is_open())
				// Читаем файл целиком
				result.assign(istreambuf_iterator <char> (file), istreambuf_iterator <char> ());
		/**
		 * Если памяти под файл не хватило
		 */
		} catch(const bad_alloc &) {
			// Файл не прочитан
			result.clear();
		}
		// Выводим содержимое файла
		return result;
	}
};

/**
 * @brief Функция запуска приложения
 *
 * @param argc длина массива параметров
 * @param argv массив параметров
 *
 * @return     код выхода из приложения
 *
 */
int main(int argc, char * argv[]) noexcept {
	// Не используем параметры приложения
	(void) argc;
	// Не используем параметры приложения
	(void) argv;
	// Ответ ресурса directory раздела 7.1.1 RFC 8555
	static const char * ANSWER =
		"{"
		"\"newNonce\": \"https://example.com/acme/new-nonce\","
		"\"newAccount\": \"https://example.com/acme/new-account\","
		"\"newOrder\": \"https://example.com/acme/new-order\","
		"\"newAuthz\": \"https://example.com/acme/new-authz\","
		"\"revokeCert\": \"https://example.com/acme/revoke-cert\","
		"\"keyChange\": \"https://example.com/acme/key-change\""
		"}";
	// Разбираемая запись каталога службы
	acme::directory_t directory;
	/**
	 * Выполняем разбор ответа ресурса directory
	 *
	 * @details Ответ несёт адреса ресурсов службы: у него на месте обязаны быть
	 *          newNonce, newAccount, newOrder и revokeCert
	 */
	if(directory.parse(::text(ANSWER)) != acme::error_t::NONE){
		// Выводим сообщение об отказе разбора ответа
		cout << "Разобрать ответ directory не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим адреса ресурсов службы
	cout << "Каталог службы     : newNonce " << directory.newNonce << endl;
	cout << "                   : newAccount " << directory.newAccount << endl;
	cout << "                   : newOrder " << directory.newOrder << endl;
	// Ключ учётной записи
	keys::key_t key;
	// Выполняем разбор ключа учётной записи из записи набора
	if(keys::decode(::corpus("ca-ec.key"), view_t(), key) != keys::error_t::NONE){
		// Выводим сообщение об отказе разбора ключа
		cout << "Разобрать ключ учётной записи не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Подготовленный секретный ключ учётной записи
	keys::signer_t signer;
	// Выполняем подготовку ключа подписи из записи набора
	if(signer.prepare(::text(::corpus("ca-ec.key"))) != keys::error_t::NONE){
		// Выводим сообщение об отказе подготовки ключа
		cout << "Подготовить ключ учётной записи не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Полезная нагрузка заведения учётной записи
	string payload;
	/**
	 * Выполняем сборку полезной нагрузки запроса newAccount по разделу 7.3 RFC 8555
	 */
	acme::newAccount({"mailto:admin@example.org"}, true, false, payload);
	// Выводим собранную полезную нагрузку
	cout << "Полезная нагрузка  : " << payload << endl;
	// Тело запроса application/jose+json
	string body;
	/**
	 * Выполняем сборку запроса newAccount
	 *
	 * @details Адрес учётной записи пуст, оттого заголовок JWS несёт запись ключа
	 *          jwk целиком, как велит раздел 6.2 RFC 8555 для запросов newAccount
	 */
	if(acme::request(directory.newAccount, "6S8IqOGY7eL2lsGoTZYifg", "", key, ::text(payload), signer, body) != acme::error_t::NONE){
		// Выводим сообщение об отказе сборки запроса
		cout << "Собрать запрос newAccount не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим размер тела запроса
	cout << "Тело запроса       : " << body.size() << " байт application/jose+json" << endl;
	// Позиции членов тела запроса
	const size_t head = body.find("\"protected\":\"");
	const size_t middle = body.find("\",\"payload\":\"", head);
	const size_t tail = body.find("\",\"signature\":\"", middle);
	// Если члены тела не найдены
	if((head == string::npos) || (middle == string::npos) || (tail == string::npos)){
		// Выводим сообщение о чужом устройстве тела
		cout << "Тело запроса не несёт членов JWS" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Собираем компактную запись JWS из членов тела: protected '.' payload '.' signature
	const string compact =
		body.substr(head + 13, middle - head - 13) + "." +
		body.substr(middle + 13, tail - middle - 13) + "." +
		body.substr(tail + 15, body.size() - tail - 17);
	// Разбираемая запись JWS
	jws::signature_t signature;
	/**
	 * Выполняем разбор компактной записи JWS
	 *
	 * @details Запись разбирается по разделу 7.2.2 RFC 7515: заголовок декодируется,
	 *          просмотры полезной нагрузки и подписи указывают внутрь текста записи
	 */
	if(signature.parse(::text(compact)) != jws::error_t::NONE){
		// Выводим сообщение об отказе разбора записи
		cout << "Разобрать запись JWS не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим заголовок записи
	cout << "Заголовок JWS      : " << signature.header() << endl;
	// Выполняем проверку подписи записи ключом учётной записи
	if(signature.verify(key) != jws::error_t::NONE){
		// Выводим сообщение об отказе проверки подписи
		cout << "Подпись запроса не сошлась" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим сообщение об успешной проверке подписи
	cout << "Проверка подписи   : подпись сошлась" << endl;
	// Извлечённая полезная нагрузка записи
	vector <uint8_t> extracted;
	// Выполняем извлечение полезной нагрузки записи
	if(signature.payload(extracted) != jws::error_t::NONE){
		// Выводим сообщение об отказе извлечения нагрузки
		cout << "Извлечь полезную нагрузку не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Если полезная нагрузка совпала с собранной
	if((extracted.size() == payload.size()) && (::memcmp(extracted.data(), payload.data(), payload.size()) == 0))
		// Выводим сообщение о совпадении полезной нагрузки
		cout << "Полезная нагрузка  : совпала с собранной" << endl;
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
