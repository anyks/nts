/**
 * @file request.cpp
 * @date 2026-10-21
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
 * @brief Пример работы с запросом на сертификат PKCS #10 по RFC 2986 — разбор
 *        эталонного запроса, запись нового запроса и проверка его подписи
 *
 * @details Запрос собирается из имени владельца, сведений об открытом ключе и
 *          набора запрашиваемых расширений, подписывается секретным ключом
 *          владельца, и подпись его проверяется тем открытым ключом, что лежит
 *          в самом запросе: так издатель удостоверяется, что проситель владеет
 *          секретным ключом
 *
 * @note Ключи и эталонный запрос берутся из набора tests/corpus, выработанного
 *       openssl: путь к набору передаётся сборкой определением ANTS_CORPUS
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные модули
 */
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <fstream>
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <pem/pem.hpp>
#include <keys/keys.hpp>
#include <digest/hash.hpp>
#include <x509/x509.hpp>
#include <x509/request.hpp>

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
	 * @brief Функция вывода области байтов шестнадцатеричной записью
	 *
	 * @param title заголовок выводимой области байтов
	 * @param data  выводимая область байтов
	 * @param size  размер выводимой области байтов
	 *
	 */
	void print(const char * title, const uint8_t * data, const size_t size) noexcept {
		// Выводим заголовок области байтов
		cout << title << ": ";
		/**
		 * Выполняем перебор байтов выводимой области
		 */
		for(size_t i = 0; i < size; i++)
			// Выводим очередной байт шестнадцатеричной записью
			cout << hex << setw(2) << setfill('0') << static_cast <uint32_t> (data[i]);
		// Выполняем перевод строки за областью байтов
		cout << dec << endl;
	}
	/**
	 * @brief Функция чтения файла набора целиком
	 *
	 * @param name имя файла в наборе
	 * @return     содержимое файла, пустое при отказе чтения
	 *
	 */
	vector <uint8_t> corpus(const char * name) noexcept {
		// Содержимое файла
		vector <uint8_t> result;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Поток чтения файла набора
			ifstream file(string(ANTS_CORPUS) + "/" + name, ios::binary);
			// Если файл открыт
			if(file.is_open())
				// Читаем файл целиком
				result.assign(istreambuf_iterator <char> (file), istreambuf_iterator <char> ());
		/**
		 * Выполняем перехват ошибок
		 */
		} catch(const bad_alloc &) {
			// Файл не прочитан
			result.clear();
		}
		// Выводим содержимое файла
		return result;
	}
	/**
	 * @brief Функция извлечения тела первой записи PEM
	 *
	 * @param text разбираемый текст записи PEM
	 * @return     тело первой записи в кодировке DER, пустое при отказе
	 *
	 */
	vector <uint8_t> body(const vector <uint8_t> & text) noexcept {
		// Разобранные записи текста
		vector <pem::block_t> blocks;
		// Если записи разобрать не удалось либо их нет
		if(text.empty() || (pem::decode(string(text.begin(), text.end()), blocks) != pem::error_t::NONE) || blocks.empty())
			// Выводим пустое тело
			return vector <uint8_t> ();
		// Выводим тело первой записи
		return blocks.front().data;
	}
};

/**
 * @brief Функция запуска приложения
 *
 * @param argc длина массива параметров
 * @param argv массив параметров
 * @return     код выхода из приложения
 *
 */
int main(int argc, char * argv[]) noexcept {
	// Не используем параметры приложения
	(void) argc;
	// Не используем параметры приложения
	(void) argv;
	// Тело записи эталонного запроса в кодировке DER
	const vector <uint8_t> der = ::body(::corpus("leaf-rsa.csr"));
	// Если запись запроса не прочитана
	if(der.empty()){
		// Выводим сообщение об отказе чтения запроса
		cout << "Прочитать запрос набора не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Эталонный запрос
	x509::request_t reference;
	// Выполняем разбор записи эталонного запроса
	if(reference.parse(view_t(der.data(), der.size())) != x509::error_t::NONE){
		// Выводим сообщение об отказе разбора запроса
		cout << "Разобрать запрос не удалось: причина " << static_cast <uint32_t> (reference.err()) << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Запись имени владельца запроса строкой по RFC 4514
	string subject;
	// Собираем запись имени владельца
	if(x509::text(reference.subjects(), subject) == x509::error_t::NONE)
		// Выводим имя владельца запроса
		cout << "Владелец           : " << subject << endl;
	// Выводим опознаватель алгоритма открытого ключа запроса
	cout << "Алгоритм ключа     : " << reference.key().algorithm << endl;
	// Выводим опознаватель алгоритма подписи запроса
	cout << "Алгоритм подписи   : " << reference.algorithms() << endl;
	/**
	 * Выполняем проверку подписи эталонного запроса
	 *
	 * @details Подпись запроса проверяется тем открытым ключом, что лежит в
	 *          сведениях об открытом ключе самого запроса
	 *
	 */
	if(x509::verify(reference, reference.key()) != x509::error_t::NONE){
		// Выводим сообщение о несошедшейся подписи
		cout << "Проверка подписи   : подпись не сошлась" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим сообщение об успешной проверке подписи
	cout << "Проверка подписи   : подпись сошлась" << endl;
	// Подготовленный секретный ключ владельца запроса
	keys::signer_t signer;
	// Секретный ключ владельца запроса
	const vector <uint8_t> secret = ::corpus("leaf-rsa.key");
	// Если ключ не прочитан либо не подготовлен
	if(secret.empty() || (signer.prepare(view_t(secret.data(), secret.size())) != keys::error_t::NONE)){
		// Выводим сообщение об отказе подготовки ключа
		cout << "Подготовить секретный ключ не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Запрашиваемое расширение: основные ограничения, необязательное
	x509::extension_t extension;
	// Устанавливаем опознаватель основных ограничений
	extension.oid = "2.5.29.19";
	// Содержимое расширения: пустой набор - владелец не издатель
	const uint8_t constraints[] = {0x30, 0x00};
	// Устанавливаем содержимое расширения
	extension.value = view_t(constraints, sizeof(constraints));
	// Набор запрашиваемых расширений
	const vector <x509::extension_t> extensions(1, extension);
	// Записанный запрос в кодировке DER
	vector <uint8_t> encoded;
	/**
	 * Выполняем запись запроса на сертификат
	 *
	 * @details Собирается CertificationRequestInfo {version, subject, subjectPKInfo,
	 *          attributes [0]}, подписывается ключом владельца, и оборачивается в
	 *          CertificationRequest. Атрибут extensionRequest записывается всегда,
	 *          даже при пустом наборе расширений - так велит раздел 4 RFC 2986
	 *
	 */
	if(x509::encode(reference.subjects(), reference.key(), extensions, signer, digest::hash_t::SHA256, encoded) != x509::error_t::NONE){
		// Выводим сообщение об отказе записи запроса
		cout << "Записать запрос не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим размер записанного запроса
	cout << "Записан запрос     : " << encoded.size() << " байтов" << endl;
	// Разбираемый записанный запрос
	x509::request_t request;
	// Выполняем разбор записанного запроса обратно
	if(request.parse(view_t(encoded.data(), encoded.size())) != x509::error_t::NONE){
		// Выводим сообщение об отказе разбора записанного запроса
		cout << "Разобрать записанный запрос не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим число запрошенных расширений записанного запроса
	cout << "Расширений запрошено: " << request.extension().size() << endl;
	// Число неиспользуемых разрядов последнего байта подписи
	uint8_t unused = 0;
	// Извлекаем подпись записанного запроса
	const view_t & signature = request.sign(unused);
	// Выводим подпись записанного запроса
	::print("Подпись запроса    ", signature.data, signature.size);
	// Выполняем проверку подписи записанного запроса
	if(x509::verify(request, request.key()) != x509::error_t::NONE){
		// Выводим сообщение о несошедшейся подписи
		cout << "Проверка записи    : подпись записанного запроса не сошлась" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим сообщение об успешной проверке записанного запроса
	cout << "Проверка записи    : подпись записанного запроса сошлась" << endl;
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
