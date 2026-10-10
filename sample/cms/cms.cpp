/**
 * @file cms.cpp
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
 * @brief Пример работы с синтаксисом криптографических сообщений по RFC 5652 —
 *        сборка подписанного сообщения SignedData и проверка его подписи,
 *        сборка зашифрованного сообщения EnvelopedData с передачей ключа по RSA
 *        и его расшифрование
 *
 * @details Запись ContentInfo собирается и разбирается в кодировке DER, транспортом
 *          (S/MIME, файлы) модуль не занимается. Ключ и сертификат подписывающего
 *          берутся из набора tests/corpus: порождать их на месте образцу не по чину
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
#include <iomanip>
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <pem/pem.hpp>
#include <cms/cms.hpp>
#include <keys/keys.hpp>
#include <x509/x509.hpp>

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
	 * @brief Метод вывода области байтов шестнадцатеричной записью
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
	 * @brief Метод получения просмотра набора байтов
	 *
	 * @param data набор байтов, на который заводится просмотр
	 *
	 * @return     просмотр области байтов набора
	 *
	 */
	view_t view(const vector <uint8_t> & data) noexcept {
		// Выводим просмотр области байтов набора
		return view_t(data.data(), data.size());
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
	/**
	 * @brief Метод разбора сертификата набора из записи PEM
	 *
	 * @param name  имя файла сертификата в наборе
	 * @param der   место, в которое помещается запись сертификата в кодировке DER
	 * @param result сертификат, в который помещается итог разбора
	 *
	 * @return      признак успешности разбора
	 *
	 */
	bool certified(const char * name, vector <uint8_t> & der, x509::certificate_t & result) noexcept {
		// Блоки записи PEM
		vector <pem::block_t> blocks;
		// Если запись PEM не разобрана
		if(pem::decode(corpus(name), blocks) != pem::error_t::NONE)
			// Выводим отказ разбора
			return false;
		// Запоминаем запись сертификата в кодировке DER
		der = blocks[0].data;
		// Выводим итог разбора сертификата
		return (result.parse(::view(der)) == x509::error_t::NONE);
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
	// Запись сертификата подписывающего в кодировке DER
	vector <uint8_t> der;
	// Сертификат подписывающего
	x509::certificate_t certificate;
	// Если сертификат набора не разобран
	if(!::certified("leaf-rsa.crt", der, certificate)){
		// Выводим сообщение об отказе разбора сертификата
		cout << "Разобрать сертификат набора не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Подготовленный секретный ключ подписи
	keys::signer_t signer;
	// Выполняем подготовку ключа подписи из записи набора
	if(signer.prepare(::text(::corpus("leaf-rsa.key"))) != keys::error_t::NONE){
		// Выводим сообщение об отказе подготовки ключа
		cout << "Подготовить ключ подписи не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Подписываемое содержимое образца
	const string content = "Содержимое, подписываемое записью CMS";
	// Место, в которое помещается запись ContentInfo
	vector <uint8_t> record;
	/**
	 * Выполняем сборку подписанного сообщения
	 *
	 * @details Собирается SignedData с подписанными атрибутами contentType и
	 *          messageDigest по разделу 11 RFC 5652: подпись ставится под записью
	 *          атрибутов, содержимое вкладывается в запись, первым в наборе идёт
	 *          сертификат подписывающего
	 */
	if(cms::sign({::view(der)}, certificate.issuers().element, certificate.number(), ::text(content), signer, digest::hash_t::SHA256, record) != cms::error_t::NONE){
		// Выводим сообщение об отказе сборки подписанного сообщения
		cout << "Собрать подписанное сообщение не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим начало записи ContentInfo
	::print("Запись SignedData  ", record.data(), (record.size() < 32) ? record.size() : 32);
	// Если вид записи не id-signedData
	if(cms::content(::view(record)) != cms::content_t::SIGNED){
		// Выводим сообщение о чужом виде записи
		cout << "Вид записи не id-signedData" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Разбираемое подписанное сообщение
	cms::signed_t parsed;
	// Выполняем разбор записи
	if(parsed.parse(::view(record)) != cms::error_t::NONE){
		// Выводим сообщение об отказе разбора записи
		cout << "Разобрать подписанное сообщение не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим число сертификатов и подписывающих записи
	cout << "Разбор             : сертификатов " << parsed.certificates().size() << ", подписывающих " << parsed.signers().size() << endl;
	// Выводим алгоритмы подписывающего
	cout << "Подписывающий      : хеш " << parsed.signers()[0].digest << ", подпись " << parsed.signers()[0].algorithm << endl;
	/**
	 * Выполняем проверку подписи записи
	 *
	 * @details Сперва сверяется хеш содержимого из атрибута messageDigest, затем
	 *          проверяется подпись под записью атрибутов по разделу 5.4 RFC 5652;
	 *          содержимое вложено в запись, оттого отдельный просмотр пуст
	 */
	if(cms::verify(parsed, parsed.signers()[0], view_t(), certificate.key()) != cms::error_t::NONE){
		// Выводим сообщение об отказе проверки подписи
		cout << "Подпись сообщения не сошлась" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим сообщение об успешной проверке подписи
	cout << "Проверка подписи   : подпись сошлась" << endl;
	// Если содержимое записи совпало с подписанным
	if((parsed.content().size == content.size()) && (::memcmp(parsed.content().data, content.data(), content.size()) == 0))
		// Выводим сообщение о совпадении содержимого
		cout << "Содержимое         : совпало с подписанным" << endl;
	// Место, в которое помещается зашифрованная запись ContentInfo
	vector <uint8_t> enveloped;
	/**
	 * Выполняем сборку зашифрованного сообщения с передачей ключа по RSA
	 *
	 * @details Содержимое зашифровывается AES-256-CBC со случайным ключом, ключ
	 *          передаётся получателю в KeyTransRecipientInfo по схеме RSA PKCS #1 v1.5
	 *          (раздел 6.2.1 RFC 5652)
	 */
	if(cms::envelop(::text(content), certificate.issuers().element, certificate.number(), certificate.key(), enveloped) != cms::error_t::NONE){
		// Выводим сообщение об отказе сборки зашифрованного сообщения
		cout << "Собрать зашифрованное сообщение не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим начало зашифрованной записи ContentInfo
	::print("Запись Enveloped   ", enveloped.data(), (enveloped.size() < 32) ? enveloped.size() : 32);
	// Разбираемое зашифрованное сообщение
	cms::enveloped_t sealed;
	// Выполняем разбор записи
	if(sealed.parse(::view(enveloped)) != cms::error_t::NONE){
		// Выводим сообщение об отказе разбора записи
		cout << "Разобрать зашифрованное сообщение не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим шифр содержимого и число получателей записи
	cout << "Разбор             : шифр содержимого " << sealed.algorithm() << ", получателей " << sealed.recipients().size() << endl;
	// Секретный ключ получателя
	keys::key_t key;
	// Выполняем разбор ключа получателя из записи набора
	if(keys::decode(::corpus("leaf-rsa.key"), view_t(), key) != keys::error_t::NONE){
		// Выводим сообщение об отказе разбора ключа
		cout << "Разобрать ключ получателя не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Место, в которое помещается расшифрованное содержимое
	vector <uint8_t> opened;
	// Выполняем расшифрование содержимого ключом получателя
	if(cms::unenvelop(sealed, key, opened) != cms::error_t::NONE){
		// Выводим сообщение об отказе расшифрования
		cout << "Расшифровать сообщение не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Если расшифрованное содержимое совпало с исходным
	if((opened.size() == content.size()) && (::memcmp(opened.data(), content.data(), opened.size()) == 0))
		// Выводим сообщение о совпадении содержимого
		cout << "Расшифрование      : содержимое совпало с исходным" << endl;
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
