/**
 * @file issue.cpp
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
 * @brief Пример выпуска сертификатов X.509 — самоподписанный сертификат
 *        и сертификат по запросу PKCS #10 подписью удостоверяющего центра
 *
 * @details Собирается TBSCertificate {version, serialNumber, signature, issuer,
 *          validity, subject, subjectPublicKeyInfo, extensions [3]}, подписывается
 *          ключом издателя, и оборачивается в Certificate. При самоподписи издатель
 *          и владелец совпадают; при выпуске по запросу имя и ключ владельца берутся
 *          из запроса, а подпись ставится ключом издателя
 *
 * @note Ключи, запрос и сертификат издателя берутся из набора tests/corpus,
 *       выработанного openssl: путь к набору передаётся сборкой определением
 *       ANTS_CORPUS
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
#include <x509/issue.hpp>
#include <x509/request.hpp>
#include <x509/signature.hpp>

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
	/**
	 * @brief Функция подготовки секретного ключа из записи набора
	 *
	 * @param name   имя файла ключа в наборе
	 * @param signer подготавливаемый секретный ключ подписи
	 * @return       признак успешности подготовки ключа
	 *
	 */
	bool signer(const char * name, keys::signer_t & signer) noexcept {
		// Секретный ключ набора
		const vector <uint8_t> secret = corpus(name);
		// Выводим успешность подготовки ключа
		return (!secret.empty() && (signer.prepare(view_t(secret.data(), secret.size())) == keys::error_t::NONE));
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
	// Тело записи эталонного сертификата владельца
	const vector <uint8_t> der = ::body(::corpus("leaf-rsa.crt"));
	// Если запись сертификата не прочитана
	if(der.empty()){
		// Выводим сообщение об отказе чтения сертификата
		cout << "Прочитать сертификат набора не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Эталонный сертификат владельца
	x509::certificate_t reference;
	// Выполняем разбор эталонного сертификата
	if(reference.parse(view_t(der.data(), der.size())) != x509::error_t::NONE){
		// Выводим сообщение об отказе разбора сертификата
		cout << "Разобрать сертификат не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Подготовленный секретный ключ владельца
	keys::signer_t signer;
	// Выполняем подготовку ключа владельца из записи набора
	if(!::signer("leaf-rsa.key", signer)){
		// Выводим сообщение об отказе подготовки ключа
		cout << "Подготовить секретный ключ не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Порядковый номер выдаваемого сертификата
	const uint8_t serial[] = {0x01, 0x02, 0x03, 0x04};
	// Расширение основных ограничений: владелец не издатель
	x509::extension_t constraints;
	// Устанавливаем опознаватель основных ограничений
	constraints.oid = "2.5.29.19";
	// Содержимое расширения: пустой набор
	const uint8_t empty[] = {0x30, 0x00};
	// Устанавливаем содержимое расширения
	constraints.value = view_t(empty, sizeof(empty));
	// Набор расширений выдаваемого сертификата
	const vector <x509::extension_t> extensions(1, constraints);
	// Выпущенный самоподписанный сертификат
	vector <uint8_t> issued;
	/**
	 * Выполняем выпуск самоподписанного сертификата сроком с 2026-01-01 по 2030-01-01
	 *
	 * @details Имя издателя совпадает с именем владельца, а подпись ставится тем же
	 *          ключом, чьи сведения лежат в сертификате. Расширения есть - сертификат
	 *          выходит третьего издания
	 *
	 */
	if(x509::issueSelfSigned(reference.subjects(), reference.key(), signer, digest::hash_t::SHA256, view_t(serial, sizeof(serial)), 1767225600, 1893456000, extensions, issued) != x509::error_t::NONE){
		// Выводим сообщение об отказе выпуска сертификата
		cout << "Выпустить самоподписанный сертификат не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим размер записи выпущенного сертификата
	cout << "Самоподписанный    : " << issued.size() << " байтов" << endl;
	// Разбираемый выпущенный сертификат
	x509::certificate_t self;
	// Выполняем разбор выпущенного сертификата обратно
	if(self.parse(view_t(issued.data(), issued.size())) != x509::error_t::NONE){
		// Выводим сообщение об отказе разбора выпущенного сертификата
		cout << "Разобрать выпущенный сертификат не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим порядковый номер выпущенного сертификата
	::print("Порядковый номер   ", self.number().data, self.number().size);
	// Выполняем проверку подписи самоподписанного сертификата его же ключом
	if(x509::verify(self, self.key()) != x509::error_t::NONE){
		// Выводим сообщение о несошедшейся подписи
		cout << "Проверка самоподписи: подпись не сошлась" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим сообщение об успешной проверке самоподписи
	cout << "Проверка самоподписи: подпись сошлась" << endl;
	// Тело записи запроса владельца
	const vector <uint8_t> requestDer = ::body(::corpus("leaf-rsa.csr"));
	// Разбираемый запрос владельца
	x509::request_t request;
	// Если запрос не прочитан либо не разобран
	if(requestDer.empty() || (request.parse(view_t(requestDer.data(), requestDer.size())) != x509::error_t::NONE)){
		// Выводим сообщение об отказе разбора запроса
		cout << "Разобрать запрос набора не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем проверку подписи запроса ключом самого запроса
	if(x509::verify(request, request.key()) != x509::error_t::NONE){
		// Выводим сообщение о несошедшейся подписи запроса
		cout << "Подпись запроса не сошлась" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Тело записи сертификата издателя
	const vector <uint8_t> caDer = ::body(::corpus("ca-rsa.crt"));
	// Сертификат издателя
	x509::certificate_t ca;
	// Если сертификат издателя не прочитан либо не разобран
	if(caDer.empty() || (ca.parse(view_t(caDer.data(), caDer.size())) != x509::error_t::NONE)){
		// Выводим сообщение об отказе разбора сертификата издателя
		cout << "Разобрать сертификат издателя не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Подготовленный секретный ключ издателя
	keys::signer_t issuer;
	// Выполняем подготовку ключа издателя из записи набора
	if(!::signer("ca-rsa.key", issuer)){
		// Выводим сообщение об отказе подготовки ключа издателя
		cout << "Подготовить ключ издателя не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Порядковый номер сертификата, выдаваемого издателем
	const uint8_t number[] = {0x0A, 0x0B};
	// Выпущенный издателем сертификат
	vector <uint8_t> signed_;
	/**
	 * Выполняем выпуск сертификата по запросу подписью издателя
	 *
	 * @details Имя владельца и сведения об открытом ключе берутся из запроса,
	 *          имя издателя - из сертификата издателя. Расширения запроса не
	 *          копируются: вызывающий сам решает, какие расширения выдать
	 *
	 */
	if(x509::issueByCA(request, ca.subjects(), issuer, digest::hash_t::SHA256, view_t(number, sizeof(number)), 1767225600, 1893456000, vector <x509::extension_t> (), signed_) != x509::error_t::NONE){
		// Выводим сообщение об отказе выпуска сертификата
		cout << "Выпустить сертификат подписью издателя не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим размер записи выданного издателем сертификата
	cout << "Подписан издателем : " << signed_.size() << " байтов" << endl;
	// Разбираемый выданный сертификат
	x509::certificate_t certificate;
	// Выполняем разбор выданного сертификата обратно
	if(certificate.parse(view_t(signed_.data(), signed_.size())) != x509::error_t::NONE){
		// Выводим сообщение об отказе разбора выданного сертификата
		cout << "Разобрать выданный сертификат не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Запись имени издателя выданного сертификата строкой по RFC 4514
	string name;
	// Собираем запись имени издателя
	if(x509::text(certificate.issuers(), name) == x509::error_t::NONE)
		// Выводим имя издателя выданного сертификата
		cout << "Издатель           : " << name << endl;
	// Выполняем проверку подписи выданного сертификата ключом издателя
	if(x509::verify(certificate, ca.key()) != x509::error_t::NONE){
		// Выводим сообщение о несошедшейся подписи
		cout << "Проверка издателя  : подпись не сошлась" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим сообщение об успешной проверке подписи издателя
	cout << "Проверка издателя  : подпись сошлась" << endl;
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
