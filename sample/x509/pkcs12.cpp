/**
 * @file pkcs12.cpp
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
 * @brief Пример разбора контейнера PKCS #12 по RFC 7292 — секретный ключ
 *        и цепочка сертификатов под паролем
 *
 * @details Разбираются мешки keyBag, pkcs8ShroudedKeyBag и certBag: ключ выходит
 *          разбором PrivateKeyInfo, сертификаты - записями X.509. Мешки, защищённые
 *          паролем, расшифровываются схемой PBES2 по RFC 8018, а целостность записи
 *          сверяется имитовставкой HMAC по разделу 6 RFC 7292: неверный пароль
 *          различается ею
 *
 * @note Контейнер берётся из набора tests/corpus, выработанного openssl: путь
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
	 * @brief Функция получения просмотра строки знаков
	 *
	 * @param text строка знаков, на которую заводится просмотр
	 * @return     просмотр области байтов строки знаков
	 *
	 */
	view_t text(const char * text) noexcept {
		// Выводим просмотр области байтов строки знаков
		return view_t(reinterpret_cast <const uint8_t *> (text), ::strlen(text));
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
	// Запись PKCS #12 набора в кодировке DER
	const vector <uint8_t> der = ::corpus("test.p12");
	// Если запись не прочитана
	if(der.empty()){
		// Выводим сообщение об отказе чтения записи
		cout << "Прочитать запись набора не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Разобранный ключ
	keys::key_t key;
	// Разобранная цепочка сертификатов
	vector <vector <uint8_t>> chain;
	/**
	 * Выполняем разбор записи PKCS #12 паролем набора
	 *
	 * @details Пароль подаётся октетами и обращается в строку BMPString самим
	 *          разбором; неверный пароль различается имитовставкой записи
	 *
	 */
	if(keys::decodePkcs12(view_t(der.data(), der.size()), ::text("secret"), key, chain) != keys::error_t::NONE){
		// Выводим сообщение об отказе разбора записи
		cout << "Разобрать запись PKCS #12 не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим вид разобранного ключа
	cout << "Вид ключа          : " << static_cast <uint32_t> (key.kind) << endl;
	// Выводим опознаватель кривой ключа
	cout << "Кривая ключа       : " << key.oid << endl;
	// Выводим признак наличия секретной части ключа
	cout << "Секретная часть    : " << (key.secret() ? "есть" : "нет") << endl;
	// Выводим первую координату открытого ключа
	::print("Открытый ключ x    ", key.x.data(), key.x.size());
	// Выводим число сертификатов цепочки
	cout << "Сертификатов       : " << chain.size() << endl;
	// Если цепочка не пуста
	if(!chain.empty()){
		// Разбираемый сертификат цепочки
		x509::certificate_t certificate;
		// Выполняем разбор первого сертификата цепочки
		if(certificate.parse(view_t(chain.front().data(), chain.front().size())) == x509::error_t::NONE){
			// Запись имени владельца сертификата строкой по RFC 4514
			string subject;
			// Собираем запись имени владельца
			if(x509::text(certificate.subjects(), subject) == x509::error_t::NONE)
				// Выводим имя владельца сертификата цепочки
				cout << "Владелец           : " << subject << endl;
			// Выводим порядковый номер сертификата цепочки
			::print("Порядковый номер   ", certificate.number().data, certificate.number().size);
		}
	}
	// Ключ чужого пароля
	keys::key_t foreign;
	// Цепочка чужого пароля
	vector <vector <uint8_t>> foreignChain;
	/**
	 * Выполняем разбор записи чужим паролем: имитовставка записи не сходится
	 */
	if(keys::decodePkcs12(view_t(der.data(), der.size()), ::text("другой"), foreign, foreignChain) == keys::error_t::PASSWORD)
		// Выводим сообщение об отвержении чужого пароля
		cout << "Чужой пароль       : отвергнут имитовставкой" << endl;
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
