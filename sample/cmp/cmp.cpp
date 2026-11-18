/**
 * @file cmp.cpp
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
 * @brief Пример работы с протоколом управления сертификатами по RFC 4210 —
 *        сборка запроса инициализации ir с защитой подписью и запроса
 *        сертификата cr с парольной имитовставкой PBM, их разбор и проверка
 *
 * @details Запись PKIMessage собирается и разбирается в кодировке DER, транспортом
 *          (HTTP) модуль не занимается. Ключ и сертификат владельца берутся из
 *          набора tests/corpus: порождать их на месте образцу не по чину
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
#include "pem/pem.hpp"
#include "cmp/cmp.hpp"
#include "keys/keys.hpp"
#include "asn1/asn1.hpp"
#include "x509/x509.hpp"

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
	void __nts_print__(const char * title, const uint8_t * data, const size_t size) noexcept {
		// Выводим заголовок области байтов
		cout << title << ": ";
		/**
		 * Перебираем байтов выводимой области
		 */
		for(size_t i = 0; i < size; i++)
			// Выводим очередной байт шестнадцатеричной записью
			cout << hex << setw(2) << setfill('0') << static_cast <uint32_t> (data[i]);
		// Переводим строки за областью байтов
		cout << dec << endl;
	}
	/**
	 * @brief Функция получения просмотра строки знаков
	 *
	 * @param text строка знаков, на которую заводится просмотр
	 * @return     просмотр области байтов строки знаков
	 *
	 */
	view_t __nts_text__(const string & text) noexcept {
		// Выводим просмотр области байтов строки знаков
		return view_t(reinterpret_cast <const uint8_t *> (text.data()), text.size());
	}
	/**
	 * @brief Функция получения просмотра набора байтов
	 *
	 * @param data набор байтов, на который заводится просмотр
	 * @return     просмотр области байтов набора
	 *
	 */
	view_t __nts_view__(const vector <uint8_t> & data) noexcept {
		// Выводим просмотр области байтов набора
		return view_t(data.data(), data.size());
	}
	/**
	 * @brief Функция чтения файла набора целиком
	 *
	 * @param name имя файла в наборе
	 * @return     содержимое файла, пустое при отказе чтения
	 *
	 */
	string __nts_corpus__(const char * name) noexcept {
		// Содержимое файла
		string result;
		/**
		 * Выполняем перехват ошибок
		 */
		try {
			// Поток чтения файла набора
			ifstream file(string(NTS_CORPUS) + "/" + name, ios::binary);
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
	 * @brief Функция сборки записи GeneralName вида directoryName из общего имени
	 *
	 * @param common общее имя стороны
	 * @param result место, в которое помещается запись GeneralName
	 * @return       признак успешности сборки
	 *
	 */
	bool __nts_name_of__(const char * common, vector <uint8_t> & result) noexcept {
		// Записчик записи имени
		asn1::writer_t name;
		// Если запись имени не открыта
		if(!name.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ сборки
			return false;
		// Если набор составляющих не открыт
		if(!name.open(asn1::tag_t::SET))
			// Выводим отказ сборки
			return false;
		// Если запись составляющей не открыта
		if(!name.open(asn1::tag_t::SEQUENCE))
			// Выводим отказ сборки
			return false;
		// Если опознаватель общего имени не записан
		if(!name.oid("2.5.4.3"))
			// Выводим отказ сборки
			return false;
		// Если значение общего имени не записано
		if(!name.text(asn1::tag_t::UTF8_STRING, common))
			// Выводим отказ сборки
			return false;
		// Если запись составляющей, набор и запись имени не закрыты
		if(!name.close() || !name.close() || !name.close())
			// Выводим отказ сборки
			return false;
		// Выводим итог сборки записи GeneralName
		return (cmp::directoryName(name.data(), result) == cmp::error_t::NONE);
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
	// Блоки записи PEM сертификата владельца
	vector <pem::block_t> blocks;
	// Если запись PEM сертификата не разобрана
	if(pem::decode(::__nts_corpus__("leaf-rsa.crt"), blocks) != pem::error_t::NONE){
		// Выводим сообщение об отказе разбора записи
		cout << "Разобрать запись сертификата не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Сертификат владельца
	x509::certificate_t certificate;
	// Разбираем сертификата владельца
	if(certificate.parse(::__nts_view__(blocks[0].data)) != x509::error_t::NONE){
		// Выводим сообщение об отказе разбора сертификата
		cout << "Разобрать сертификат набора не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Подготовленный секретный ключ защиты подписью
	keys::signer_t signer;
	// Готовим ключа подписи из записи набора
	if(signer.prepare(::__nts_text__(::__nts_corpus__("leaf-rsa.key"))) != keys::error_t::NONE){
		// Выводим сообщение об отказе подготовки ключа
		cout << "Подготовить ключ подписи не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Записи имён отправителя и получателя
	vector <uint8_t> sender, recipient;
	// Собираем имён отправителя и получателя
	if(!::__nts_name_of__("cmp-client", sender) || !::__nts_name_of__("cmp-ca", recipient)){
		// Выводим сообщение об отказе сборки имён
		cout << "Собрать имена сторон не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Запись шаблона сертификата
	vector <uint8_t> certTemplate;
	/**
	 * Собираем шаблона сертификата
	 *
	 * @details Шаблон несёт имя владельца и сведения об открытом ключе: оба поля
	 *          берутся записями из сертификата владельца набора
	 *
	 */
	if(cmp::certTemplate(certificate.subjects().element, certificate.key().element, certTemplate) != cmp::error_t::NONE){
		// Выводим сообщение об отказе сборки шаблона
		cout << "Собрать шаблон сертификата не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Место, в которое помещается запись PKIMessage
	vector <uint8_t> record;
	/**
	 * Собираем запроса инициализации ir с защитой подписью
	 *
	 * @details Подтверждение владения ставится видом signature по разделу 5.2.8.4:
	 *          подпись ключом защиты над записью CertReq, как велит примечание к
	 *          POPOSigningKey в RFC 4211
	 *
	 */
	if(cmp::request(cmp::body_t::IR, ::__nts_view__(sender), ::__nts_view__(recipient), {::__nts_view__(certTemplate)}, signer, digest::hash_t::SHA256, record) != cmp::error_t::NONE){
		// Выводим сообщение об отказе сборки запроса
		cout << "Собрать запрос ir не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим начало записи PKIMessage
	::__nts_print__("Запрос ir          ", record.data(), (record.size() < 32) ? record.size() : 32);
	// Разбираемое сообщение
	cmp::message_t parsed;
	// Разбираем записи сообщения
	if(parsed.parse(::__nts_view__(record)) != cmp::error_t::NONE){
		// Выводим сообщение об отказе разбора записи
		cout << "Разобрать запрос ir не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим издание протокола и алгоритм защиты заголовка
	cout << "Заголовок          : издание cmp" << (parsed.header().pvno == 2 ? "2000" : "?") << ", защита " << parsed.header().protection << endl;
	// Запросы сертификатов тела
	vector <cmp::request_t> requests;
	// Разбираем запросов тела
	if(cmp::requests(parsed.body(), requests) != cmp::error_t::NONE){
		// Выводим сообщение об отказе разбора тела
		cout << "Разобрать тело запроса не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим число запросов и опознаватель первого
	cout << "Тело               : запросов " << requests.size() << ", опознаватель первого " << requests[0].id << endl;
	// Проверяем защиты сообщения ключом владельца
	if(cmp::verify(parsed, certificate.key()) != cmp::error_t::NONE){
		// Выводим сообщение об отказе проверки защиты
		cout << "Защита подписью не сошлась" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим сообщение об успешной проверке защиты
	cout << "Проверка защиты    : подпись сошлась" << endl;
	// Пароль общего секрета
	const string password = "cmp-shared-secret";
	// Опознаватель ключа отправителя
	const string kid = "client-1";
	// Место, в которое помещается запись PKIMessage под защитой PBM
	vector <uint8_t> pbm;
	/**
	 * Собираем запроса сертификата cr с защитой парольной имитовставкой PBM
	 *
	 * @details Имитовставка вырабатывается по разделу 5.1.3.1 RFC 4210: пароль с
	 *          затравкой пропускается через одностороннюю функцию, итоговый ключ
	 *          идёт в HMAC над защищаемой частью сообщения
	 *
	 */
	if(cmp::request(cmp::body_t::CR, ::__nts_view__(sender), ::__nts_view__(recipient), {::__nts_view__(certTemplate)}, ::__nts_text__(kid), ::__nts_text__(password), digest::hash_t::SHA256, pbm) != cmp::error_t::NONE){
		// Выводим сообщение об отказе сборки запроса
		cout << "Собрать запрос cr не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Разбираемое сообщение под защитой PBM
	cmp::message_t parsedPbm;
	// Разбираем записи сообщения
	if(parsedPbm.parse(::__nts_view__(pbm)) != cmp::error_t::NONE){
		// Выводим сообщение об отказе разбора записи
		cout << "Разобрать запрос cr не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим алгоритм защиты заголовка
	cout << "Защита PBM         : " << parsedPbm.header().protection << endl;
	// Проверяем защиты паролем общего секрета
	if(cmp::verify(parsedPbm, ::__nts_text__(password)) != cmp::error_t::NONE){
		// Выводим сообщение об отказе проверки защиты
		cout << "Защита PBM не сошлась" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим сообщение об успешной проверке защиты
	cout << "Проверка защиты    : имитовставка PBM сошлась" << endl;
	// Если проверка чужим паролем отвергнута
	if(cmp::verify(parsedPbm, ::__nts_text__("foreign-secret")) == cmp::error_t::PROTECTION)
		// Выводим сообщение об отвержении чужого пароля
		cout << "Проверка подмены   : чужой пароль отвергнут" << endl;
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
