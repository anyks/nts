/**
 * @file log.cpp
 * @date 2026-09-17
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
 * @brief Пример подключения стока журнала — переходник на статический журнал потребителя
 *        (как у AWH), молчание без стока и сообщение об обрыве связи
 *
 * @details Библиотека журнала не ведёт: у неё один сток, который потребитель ставит при
 *          старте. У AWH журнал - набор статических функций, потому переходник это одна
 *          функция, переводящая уровень A-NTS в вид сообщения журнала. Чужой проект без
 *          журнала не ставит ничего, и библиотека молчит, не собирая строк
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные модули
 */
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <string_view>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/log.hpp>
#include <client/client.hpp>
#include <server/server.hpp>
#include <pem/pem.hpp>
#include <alert/alert.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Журнал потребителя: подобие статического журнала AWH (набор статических функций)
 *
 */
namespace journal {
	/**
	 * @brief Вид сообщения журнала потребителя
	 *
	 */
	enum class flag_t : uint8_t {
		INFO     = 0x01, // Сведение
		WARNING  = 0x02, // Предупреждение
		CRITICAL = 0x03  // Отказ
	};
	/**
	 * @brief Статическая функция печати журнала потребителя
	 *
	 * @param flag вид сообщения
	 * @param text текст сообщения
	 *
	 */
	static void print(const flag_t flag, string_view text) noexcept {
		// Подпись вида сообщения
		const char * kind = ((flag == flag_t::CRITICAL) ? "ОТКАЗ" : ((flag == flag_t::WARNING) ? "ПРЕДУПРЕЖДЕНИЕ" : "СВЕДЕНИЕ"));
		// Печатаем сообщение журнала
		cout << "[журнал потребителя] " << kind << ": " << text << endl;
	}
};

/**
 * @brief Переходник: сток A-NTS → статический журнал потребителя
 *
 * @details Ровно так AWH подключает журнал при своём старте: одна функция, ни объекта,
 *          ни времени жизни, ни заголовков AWH внутри A-NTS
 *
 * @param level   уровень сообщения A-NTS
 * @param text    строка сообщения
 * @param context контекст потребителя (здесь не нужен)
 *
 */
static void bridge(const sys::log::level_t level, const char * text, void * context) noexcept {
	// Контекст не нужен: журнал статический
	(void) context;
	// Переводим уровень A-NTS в вид сообщения журнала
	const journal::flag_t flag = ((level == sys::log::level_t::CRITICAL) ? journal::flag_t::CRITICAL : ((level == sys::log::level_t::WARNING) ? journal::flag_t::WARNING : journal::flag_t::INFO));
	// Передаём сообщение журналу потребителя
	journal::print(flag, text);
}

/**
 * @brief Помощник переноса байтов между сторонами связи в памяти
 *
 * @param client клиент
 * @param server сервер
 * @return       признак того, что байты переданы
 *
 */
/**
 * @brief Чтение файла из набора проверок: вырабатывать сертификат на месте образцу не по чину
 *
 * @param name имя файла в наборе
 * @return     содержимое файла
 *
 */
static vector <uint8_t> corpus(const char * name) noexcept {
	// Содержимое файла
	vector <uint8_t> result;
	/**
	 * Выполняем перехват ошибок
	 */
	try {
		// Открываем файл набора
		ifstream file(string(ANTS_CORPUS) + "/" + name, ios::binary);
		// Если файл открыт
		if(file.is_open())
			// Читаем файл целиком
			result.assign(istreambuf_iterator <char> (file), istreambuf_iterator <char> ());
	// Перехватываем нехватку памяти
	/**
	 * Выполняем перехват ошибок
	 */
	} catch(const bad_alloc &){
		// Опустошаем итог
		result.clear();
	}
	// Выводим содержимое файла
	return result;
}

/**
 * @brief Подлинность сервера образца из набора проверок
 *
 * @param result подлинность, в которую помещается итог
 * @return       признак успеха чтения
 *
 */
static bool forge(context::credential_t & result) noexcept {
	// Читаем закрытый ключ
	result.secret = corpus("ec256.pem");
	// Читаем цепочку сертификатов
	const vector <uint8_t> text = corpus("ec256.crt");
	// Если ключ либо цепочка не прочитаны
	if(result.secret.empty() || text.empty())
		// Сообщаем об отказе
		return false;
	// Опустошаем цепочку
	result.chain.clear();
	// Разбираем цепочку из текста PEM
	return (pem::certificates(string(text.begin(), text.end()), result.chain) == pem::error_t::NONE);
}

/**
 * @brief Точка входа образца
 *
 * @param argc число доводов
 * @param argv доводы
 * @return     код завершения: нуль при успехе
 *
 */
int main(int argc, char * argv[]) noexcept {
	// Доводы образцу не нужны
	(void) argc;
	// Не используем доводы приложения
	(void) argv;
	/**
	 * Без стока: библиотека молчит, строки не собираются вовсе - цена одного сравнения
	 */
	cout << "Сток не поставлен: " << (sys::log::enabled() ? "поставлен" : "библиотека молчит") << endl;
	/**
	 * Ставим сток переходником на журнал потребителя: с этого мига отказы библиотеки
	 * видны в её журнале. У AWH эта строка стоит при старте приложения
	 */
	sys::log::sink(&bridge);
	// Печатаем состояние стока
	cout << "Сток поставлен: " << (sys::log::enabled() ? "да" : "нет") << endl;
	/**
	 * Связь, обречённая на обрыв: ответ сервера портится по дороге на один байт, защита
	 * записи у клиента не сходится, и клиент обрывает связь извещением - обрыв уходит в
	 * журнал потребителя отказом с именем извещения, без единого байта тайны
	 */
	client::context_t client;
	// Связь стороны сервера
	server::context_t server;
	// Серверу нужна подлинность: без неё он не заведётся; берём образец из набора проверок
	context::credential_t credentials;
	// Если подлинность выработать не удалось
	if(!::forge(credentials)){
		// Печатаем отказ
		cout << "Выработать подлинность стороны сервера не удалось" << endl;
		// Выходим с отказом
		return EXIT_FAILURE;
	}
	// Устанавливаем подлинность сервера
	server.credential(credentials);
	// Заводим стороны
	if((server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Первый залп клиента серверу
	const view_t hello = client.output();
	// Копируем залп клиента в передаваемый массив
	const vector <uint8_t> greeting(hello.data, hello.data + hello.size);
	// Снимаем залп с накопителя клиента
	client.consume(greeting.size());
	// Передаём залп серверу
	server.push(view_t(greeting.data(), greeting.size()));
	// Ответ сервера, испорченный по дороге на один байт
	const view_t data = server.output();
	// Копируем ответ сервера в портимый массив
	vector <uint8_t> buffer(data.data, data.data + data.size);
	// Снимаем ответ с накопителя сервера
	server.consume(buffer.size());
	// Портим последний байт ответа
	buffer[buffer.size() - 1] ^= 0x01;
	// Передаём испорченный ответ клиенту
	client.push(view_t(buffer.data(), buffer.size()));
	// Печатаем состояние клиента
	cout << "Состояние клиента: " << ((client.state() == context::state_t::FAILED) ? "обрыв" : "иное") << ", отказ " << static_cast <unsigned> (client.error()) << ", извещение " << alert::name(client.alert().description) << endl;
	// Снимаем сток: дальше библиотека снова молчит
	sys::log::sink(nullptr);
	// Печатаем состояние стока
	cout << "Сток снят: " << (sys::log::enabled() ? "поставлен" : "библиотека молчит") << endl;
	// Выходим с успехом
	return EXIT_SUCCESS;
}
