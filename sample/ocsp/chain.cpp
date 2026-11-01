/**
 * @file chain.cpp
 * @date 2026-10-07
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
 * @brief Пример проверки состояния сертификатов цепочки по ответам OCSP (RFC 6960)
 *        со сшивкой в рукопожатие (раздел 4.4.2.1 RFC 8446): для каждого звена
 *        цепочки с непустым ответом издатель разыскивается по имени сперва в
 *        остальных звеньях цепочки, потом самим сертификатом, если он самоподписанный,
 *        и в запасе доверенных
 *
 * @details Ответы здесь берутся из набора tests/corpus, выработанного openssl;
 *          сроки судятся заданным мигом, а не часами, оттого набор не стареет
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
#include <pem/pem.hpp>
#include <ocsp/ocsp.hpp>
#include <trust/trust.hpp>

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
	 * @brief Функция вывода состояния сертификата
	 *
	 * @param status состояние сертификата
	 * @return       строковое представление состояния
	 *
	 */
	const char * status(const ocsp::status_t status) noexcept {
		/**
		 * Выполняем разбор состояния сертификата
		 */
		switch(status){
			// Сертификат годен
			case ocsp::status_t::GOOD: return "GOOD";
			// Сертификат отозван
			case ocsp::status_t::REVOKED: return "REVOKED";
			// Состояние сертификата неизвестно
			case ocsp::status_t::UNKNOWN: return "UNKNOWN";
			// Ответа нет
			case ocsp::status_t::NONE: return "NONE";
		}
		// Состояние неизвестно
		return "UNKNOWN";
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
	// Читаем цепочку сертификатов из записи PEM: лист, промежуточный, корневой
	const vector <uint8_t> text = ::corpus("chain-ec.pem");
	// Если цепочка не прочитана
	if(text.empty()){
		// Выводим сообщение об отказе чтения цепочки
		cout << "Цепочка сертификатов не прочитана" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Цепочка сертификатов: лист, промежуточный, корневой
	vector <vector <uint8_t>> chain;
	// Разбираем цепочку сертификатов из записи PEM
	if(pem::certificates(string(text.begin(), text.end()), chain) != pem::error_t::NONE){
		// Выводим сообщение об отказе разбора цепочки
		cout << "Разобрать цепочку сертификатов не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Если цепочка не из трёх звеньев
	if(chain.size() != 3){
		// Выводим сообщение о неожиданной длине цепочки
		cout << "Цепочка сертификатов не из трёх звеньев: " << chain.size() << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Ответы OCSP по местам цепочки: лист и промежуточный имеют ответы, корневой — нет
	vector <vector <uint8_t>> statuses;
	// Место листа в statuses не используется: ответ листа подаётся отдельно
	statuses.push_back(vector <uint8_t> ());
	// Читаем ответ промежуточного издателя
	statuses.push_back(::corpus("ocsp/mid-ec.good.der"));
	// Место корневого издателя пусто: ответа нет
	statuses.push_back(vector <uint8_t> ());
	// Ответ листа подаётся отдельно
	const vector <uint8_t> status = ::corpus("ocsp/leaf-ec.good.der");
	// Если ответы не прочитаны
	if(status.empty() || statuses[1].empty()){
		// Выводим сообщение об отказе чтения ответов
		cout << "Ответы OCSP не прочитаны" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Запас доверенных сертификатов: корневой издатель
	vector <vector <uint8_t>> anchors;
	// Читаем корневой сертификат в запас доверенных
	anchors.push_back(::corpus("ca-ec.crt"));
	// Состояния сертификатов по местам цепочки
	vector <ocsp::status_t> results;
	/**
	 * Выполняем проверку ответов OCSP цепочки
	 *
	 * @details Для каждого места с непустым ответом издатель разыскивается по имени
	 *          сперва в остальных звеньях цепочки, потом самим сертификатом, если он
	 *          самоподписанный, и в запасе доверенных; ответ проверяется вызовом
	 *          проверки против сертификата и издателя, состояния отдаются по местам
	 *          (без ответа — NONE). Ответ листа подаётся отдельно (связь хранит его
	 *          раздельно от мест в statuses). Миг ноль: сроки не судятся, ответ
	 *          промежуточного выработан позже мига проверки листа
	 *
	 */
	const ocsp::error_t error = ocsp::verify(chain, status, statuses, anchors, 0, 0, results);
	// Если проверка не удалась
	if(error != ocsp::error_t::NONE){
		// Выводим сообщение об отказе проверки
		cout << "Проверка ответов OCSP не удалась: " << static_cast <uint32_t> (error) << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим состояния сертификатов по местам цепочки
	cout << "Состояние листа        : " << ::status(results[0]) << endl;
	// Выводим состояние промежуточного сертификата
	cout << "Состояние промежуточного: " << ::status(results[1]) << endl;
	// Выводим состояние корневого сертификата
	cout << "Состояние корневого     : " << ::status(results[2]) << endl;
	// Если все состояния годные
	if((results[0] == ocsp::status_t::GOOD) && (results[1] == ocsp::status_t::GOOD) && (results[2] == ocsp::status_t::NONE))
		// Выводим сообщение об успешной проверке цепочки
		cout << "Проверка цепочки    : все ответы годные" << endl;
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
