/**
 * @file crl.cpp
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
 * @brief Пример разбора списка отзыва сертификатов по разделу 5 RFC 5280 —
 *        имя издателя, даты списка, записи отозванных сертификатов и проверка
 *        подписи списка
 *
 * @details Разобранный список хранит просмотры внутрь разбираемой записи: запись
 *          обязана пережить объект. Подпись списка проверяется отдельным вызовом
 *          verify сведениями об открытом ключе издателя, взятыми из его сертификата
 *
 * @note Список и сертификат издателя берутся из набора tests/corpus, выработанного
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
#include <x509/crl.hpp>
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
	// Тело записи списка отзыва в кодировке DER
	const vector <uint8_t> der = ::body(::corpus("ca-rsa.crl"));
	// Если запись списка не прочитана
	if(der.empty()){
		// Выводим сообщение об отказе чтения списка
		cout << "Прочитать список набора не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Разбираемый список отзыва
	x509::crl_t crl;
	// Выполняем разбор записи списка отзыва
	if(crl.parse(view_t(der.data(), der.size())) != x509::error_t::NONE){
		// Выводим сообщение об отказе разбора списка
		cout << "Разобрать список не удалось: причина " << static_cast <uint32_t> (crl.err()) << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Запись имени издателя списка строкой по RFC 4514
	string issuer;
	// Собираем запись имени издателя
	if(x509::text(crl.issuers(), issuer) == x509::error_t::NONE)
		// Выводим имя издателя списка
		cout << "Издатель           : " << issuer << endl;
	// Даты списка в секундах от начала эпохи
	int64_t thisUpdate = 0, nextUpdate = 0;
	// Извлекаем даты списка
	crl.updates(thisUpdate, nextUpdate);
	// Выводим дату выдачи списка
	cout << "Выдан              : " << thisUpdate << endl;
	// Выводим дату следующего списка
	cout << "Следующий          : " << nextUpdate << endl;
	// Выводим опознаватель алгоритма подписи списка
	cout << "Алгоритм подписи   : " << crl.algorithms() << endl;
	// Выводим число записей отозванных сертификатов
	cout << "Отозвано           : " << crl.revoked().size() << endl;
	/**
	 * Выполняем перебор записей отозванных сертификатов
	 */
	for(size_t i = 0; i < crl.revoked().size(); i++){
		// Запись отозванного сертификата
		const x509::revoked_t & revoked = crl.revoked()[i];
		// Выводим порядковый номер отозванного сертификата
		::print("  Серийник         ", revoked.serial.data, revoked.serial.size);
		// Выводим дату отзыва сертификата
		cout << "  Дата отзыва      : " << revoked.date << endl;
	}
	// Порядковый номер разыскиваемого сертификата
	const uint8_t sought[] = {0x03};
	// Признак нахождения отозванного серийника
	bool found = false;
	/**
	 * Выполняем розыск отозванного сертификата по порядковому номеру
	 */
	for(size_t i = 0; i < crl.revoked().size(); i++){
		// Если серийник записи совпал с разыскиваемым
		if((crl.revoked()[i].serial.size == sizeof(sought)) && (::memcmp(crl.revoked()[i].serial.data, sought, sizeof(sought)) == 0))
			// Запоминаем нахождение
			found = true;
	}
	// Выводим итог розыска отозванного сертификата
	cout << "Розыск серийника 03: " << (found ? "отозван" : "не найден") << endl;
	// Тело записи сертификата издателя
	const vector <uint8_t> caDer = ::body(::corpus("ca-rsa.crt"));
	// Сертификат издателя списка
	x509::certificate_t ca;
	// Если сертификат издателя не прочитан либо не разобран
	if(caDer.empty() || (ca.parse(view_t(caDer.data(), caDer.size())) != x509::error_t::NONE)){
		// Выводим сообщение об отказе разбора сертификата издателя
		cout << "Разобрать сертификат издателя не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	/**
	 * Выполняем проверку подписи списка отзыва
	 *
	 * @details Подпись списка проверяется сведениями об открытом ключе издателя,
	 *          взятыми из его сертификата
	 *
	 */
	if(x509::verify(crl, ca.key()) != x509::error_t::NONE){
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
