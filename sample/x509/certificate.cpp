/**
 * @file certificate.cpp
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
 * @brief Пример разбора сертификата X.509 по RFC 5280 — издание, порядковый номер,
 *        имена владельца и издателя, срок действия, открытый ключ и расширения
 *
 * @details Разбор ничего не копирует сверх необходимого: двоичные поля отдаются
 *          просмотром внутрь разбираемой записи, и время жизни записи обязан
 *          обеспечить вызывающий. Подпись проверяется отдельным вызовом verify
 *          сведениями об открытом ключе издателя; самоподписанный сертификат
 *          проверяется его собственным ключом
 *
 * @note Сертификат берётся из набора tests/corpus, выработанного openssl: путь
 *       к набору передаётся сборкой определением ANTS_CORPUS
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
#include <x509/x509.hpp>
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
	 * @brief Метод чтения файла набора целиком
	 *
	 * @param name имя файла в наборе
	 *
	 * @return     содержимое файла, пустое при отказе чтения
	 *
	 */
	vector <uint8_t> corpus(const char * name) noexcept {
		// Содержимое файла
		vector <uint8_t> result;
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
	 * @brief Метод чтения сертификата набора в кодировке DER из записи PEM
	 *
	 * @param name имя файла сертификата в наборе
	 *
	 * @return     запись сертификата в кодировке DER, пустая при отказе
	 *
	 */
	vector <uint8_t> certified(const char * name) noexcept {
		// Текст сертификата в записи PEM
		const vector <uint8_t> text = corpus(name);
		// Разобранные сертификаты записи
		vector <vector <uint8_t>> chain;
		// Если сертификат не прочитан либо не разобран
		if(text.empty() || (pem::certificates(string(text.begin(), text.end()), chain) != pem::error_t::NONE) || chain.empty())
			// Выводим пустую запись
			return vector <uint8_t> ();
		// Выводим первый сертификат записи
		return chain.front();
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
	// Запись сертификата набора в кодировке DER
	const vector <uint8_t> der = ::certified("ca-rsa.crt");
	// Если запись сертификата не прочитана
	if(der.empty()){
		// Выводим сообщение об отказе чтения сертификата
		cout << "Прочитать сертификат набора не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Разбираемый сертификат
	x509::certificate_t certificate;
	/**
	 * Выполняем разбор записи сертификата
	 *
	 * @details Просмотры разобранных полей указывают внутрь записи der, поэтому
	 *          запись обязана пережить объект сертификата
	 */
	if(certificate.parse(view_t(der.data(), der.size())) != x509::error_t::NONE){
		// Выводим сообщение об отказе разбора сертификата
		cout << "Разобрать сертификат не удалось: причина " << static_cast <uint32_t> (certificate.err()) << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим издание сертификата: нулём записано третье
	cout << "Издание            : v" << (static_cast <uint32_t> (certificate.release()) + 1) << endl;
	// Выводим порядковый номер сертификата
	::print("Порядковый номер   ", certificate.number().data, certificate.number().size);
	// Запись имени издателя строкой по RFC 4514
	string issuer;
	// Собираем запись имени издателя
	if(x509::text(certificate.issuers(), issuer) == x509::error_t::NONE)
		// Выводим имя издателя сертификата
		cout << "Издатель           : " << issuer << endl;
	// Запись имени владельца строкой по RFC 4514
	string subject;
	// Собираем запись имени владельца
	if(x509::text(certificate.subjects(), subject) == x509::error_t::NONE)
		// Выводим имя владельца сертификата
		cout << "Владелец           : " << subject << endl;
	// Срок действия сертификата в секундах от начала эпохи
	int64_t before = 0, after = 0;
	// Извлекаем срок действия сертификата
	certificate.validity(before, after);
	// Выводим срок действия сертификата
	cout << "Срок действия      : с " << before << " по " << after << endl;
	// Выводим опознаватель алгоритма подписи сертификата
	cout << "Алгоритм подписи   : " << certificate.algorithms() << endl;
	// Выводим опознаватель алгоритма открытого ключа
	cout << "Алгоритм ключа     : " << certificate.key().algorithm << endl;
	// Выводим запись открытого ключа
	::print("Открытый ключ      ", certificate.key().key.data, certificate.key().key.size);
	/**
	 * Выполняем перебор расширений сертификата
	 */
	for(size_t i = 0; i < certificate.extension().size(); i++){
		// Расширение сертификата
		const x509::extension_t & extension = certificate.extension()[i];
		// Выводим опознаватель расширения и признак его обязательности
		cout << "Расширение         : " << extension.oid << (extension.critical ? " (обязательное)" : "") << endl;
	}
	// Расширение основных ограничений
	const x509::extension_t * constraints = certificate.extension("2.5.29.19");
	// Если расширение основных ограничений найдено
	if(constraints != nullptr){
		// Признак принадлежности сертификата удостоверяющему центру
		bool authority = false;
		// Предельная глубина цепочки
		int64_t depth = -1;
		// Извлекаем основные ограничения сертификата
		if(x509::constraints(*constraints, authority, depth) == x509::error_t::NONE)
			// Выводим основные ограничения сертификата
			cout << "Основные ограничения: издатель " << (authority ? "да" : "нет") << ", глубина " << depth << endl;
	}
	/**
	 * Выполняем проверку подписи сертификата
	 *
	 * @details Сертификат набора самоподписанный, поэтому проверяется он
	 *          собственными сведениями об открытом ключе
	 */
	if(x509::verify(certificate, certificate.key()) != x509::error_t::NONE){
		// Выводим сообщение о несошедшейся подписи
		cout << "Проверка подписи   : подпись не сошлась" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим сообщение об успешной проверке подписи
	cout << "Проверка подписи   : подпись сошлась" << endl;
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
