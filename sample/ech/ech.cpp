/**
 * @file ech.cpp
 * @date 2026-09-07
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
 * @brief Образец зашифрованного приветствия клиента ECH: сервер складывает конфигурацию для
 *        DNS, клиент прячет имя узла, сервер раскрывает внутреннее приветствие; затем отказ ECH
 *        с запасными конфигурациями и повтор связи
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <string>
#include <vector>
#include <fstream>
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <pem/pem.hpp>
#include <ech/ech.hpp>
#include <client/client.hpp>
#include <server/server.hpp>
#include <fingerprint/fingerprint.hpp>

/**
 * Подписываемся на стандартное пространство имён
 */
using namespace std;

/**
 * Пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Служебные объекты образца
 *
 */
namespace {
	/**
	 * Путь к набору ключей
	 */
	static const char * CORPUS = ANTS_CORPUS;
	/**
	 * @brief Метод чтения файла целиком
	 *
	 * @param path путь к файлу
	 * @return     содержимое файла
	 *
	 */
	static vector <uint8_t> slurp(const string & path) noexcept {
		// Открываем файл на чтение
		ifstream file(path, ios::binary);
		// Содержимое файла
		vector <uint8_t> result;
		// Если файл открыт
		if(file.is_open())
			// Переносим содержимое
			result.assign(istreambuf_iterator <char> (file), istreambuf_iterator <char> ());
		// Выводим содержимое
		return result;
	}
	/**
	 * @brief Метод передачи байтов между сторонами связи
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 * @return       признак того, что байты передавались
	 *
	 */
	static bool pump(client::context_t & client, server::context_t & server) noexcept {
		// Признак передачи
		bool moved = false;
		// Байты клиента
		view_t data = client.output();
		// Если клиенту есть что отправить
		if(data.size > 0){
			// Переносим байты
			const vector <uint8_t> buffer(data.data, data.data + data.size);
			// Снимаем байты с накопителя
			client.consume(buffer.size());
			// Подаём байты серверу
			server.push(view_t(buffer.data(), buffer.size()));
			// Запоминаем передачу
			moved = true;
		}
		// Байты сервера
		data = server.output();
		// Если серверу есть что отправить
		if(data.size > 0){
			// Переносим байты
			const vector <uint8_t> buffer(data.data, data.data + data.size);
			// Снимаем байты с накопителя
			server.consume(buffer.size());
			// Подаём байты клиенту
			client.push(view_t(buffer.data(), buffer.size()));
			// Запоминаем передачу
			moved = true;
		}
		// Выводим признак передачи
		return moved;
	}
	/**
	 * @brief Метод проведения связи с печатью итога
	 *
	 * @param title      заголовок случая
	 * @param client     связь стороны клиента
	 * @param server     связь стороны сервера
	 * @param credential подлинность сервера
	 * @return           результат заведения сторон
	 *
	 */
	static bool converse(const char * title, client::context_t & client, server::context_t & server, const context::credential_t & credential) noexcept {
		// Подлинность сервера
		server.credential(credential);
		// Тайное имя узла у клиента
		client.name("secret.example");
		// Заводим стороны
		if((server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE))
			// Выводим отказ
			return false;
		// Профиль внешнего приветствия, как оно идёт на провод
		fingerprint::profile_t outer;
		// Имя на проводе
		string named = "(нет)";
		// Если приветствие разобрано
		if(fingerprint::parse(client.output(), outer) == fingerprint::error_t::NONE){
			/**
			 * Выполняем перебор расширений
			 */
			for(size_t i = 0; i < outer.extensions.size(); i++){
				// Если расширение есть имя узла
				if((outer.extensions[i].type == 0x0000) && !outer.extensions[i].names.empty())
					// Запоминаем имя на проводе
					named = outer.extensions[i].names[0];
			}
		}
		/**
		 * Выполняем рукопожатие
		 */
		for(size_t i = 0; (i < 16) && pump(client, server); i++)
			// Продолжаем передачу
			continue;
		// Печатаем итог случая
		cout << title << endl;
		cout << "  имя на проводе:       " << named << endl;
		cout << "  ECH принят клиентом:  " << (client.shrouded() ? "да" : "нет") << endl;
		cout << "  ECH принят сервером:  " << (server.shrouded() ? "да" : "нет") << endl;
		cout << "  имя, увиденное сервером: " << server.name() << endl;
		cout << "  связь установлена:    " << ((client.established() && server.established()) ? "да" : "нет") << endl;
		cout << "  отказ клиента:        " << static_cast <int> (client.error()) << " (извещение " << static_cast <int> (client.alert().description) << ")" << endl;
		cout << "  имя для удостоверения: " << (client.shrouded() ? string("name() = secret.example") : (string("visible() = ") + client.visible())) << endl;
		cout << "  запасных конфигураций: " << client.retry().size() << " байтов" << endl;
		// Выводим успешность
		return true;
	}
}

/**
 * @brief Точка входа образца
 *
 * @return код завершения
 *
 */
int main(){
	// Подлинность сервера
	context::credential_t credential;
	// Читаем ключ сервера
	credential.secret = slurp(string(CORPUS) + "/ec256.pem");
	// Сертификат сервера
	const vector <uint8_t> certificate = slurp(string(CORPUS) + "/ec256.crt");
	// Если цепочку разобрать не удалось
	if(credential.secret.empty() || (pem::certificates(string(certificate.begin(), certificate.end()), credential.chain) != pem::error_t::NONE)){
		// Сообщаем об отказе
		cerr << "Подлинность сервера не прочитана" << endl;
		// Выходим с отказом
		return 1;
	}
	// Сервер, служащий ECH: ключ порождается, публичное имя public.example
	server::context_t served;
	// Ставим ключ ECH
	if(served.ech(vector <uint8_t> (), "public.example", 7, 64) != context::error_t::NONE){
		// Сообщаем об отказе
		cerr << "Ключ ECH серверу не поставлен" << endl;
		// Выходим с отказом
		return 1;
	}
	// Перечень конфигураций для записи DNS HTTPS
	const vector <uint8_t> published = served.ech();
	// Разобранные конфигурации
	vector <ech::config_t> configs;
	// Разбираем перечень
	if(ech::parse(view_t(published.data(), published.size()), configs) != ech::error_t::NONE){
		// Сообщаем об отказе
		cerr << "Перечень конфигураций не разобран" << endl;
		// Выходим с отказом
		return 1;
	}
	// Печатаем конфигурацию
	cout << "Конфигурация ECH для DNS: " << published.size() << " байтов, config_id " << static_cast <int> (configs[0].id) << ", публичное имя " << configs[0].name << ", наборов HPKE " << configs[0].suites.size() << endl;
	{
		// Клиент с конфигурациями сервера
		client::context_t client;
		// Ставим конфигурации
		if(client.ech(published) != context::error_t::NONE){
			// Сообщаем об отказе
			cerr << "Конфигурации клиенту не поставлены" << endl;
			// Выходим с отказом
			return 1;
		}
		// Проводим связь: ECH принимается
		if(!converse("Случай 1: сервер с тем же ключом - ECH принят", client, served, credential))
			// Выходим с отказом
			return 1;
	}
	{
		// Сервер с другим ключом, но тем же публичным именем
		server::context_t foreign;
		// Ставим ключ
		if(foreign.ech(vector <uint8_t> (), "public.example", 7, 64) != context::error_t::NONE)
			// Выходим с отказом
			return 1;
		// Клиент с прежними конфигурациями
		client::context_t client;
		// Ставим конфигурации
		if(client.ech(published) != context::error_t::NONE)
			// Выходим с отказом
			return 1;
		// Проводим связь: ECH отвергается, приходят запасные конфигурации, связь обрывается ech_required
		if(!converse("Случай 2: сервер с чужим ключом - ECH отвергнут, retry_configs", client, foreign, credential))
			// Выходим с отказом
			return 1;
		// Повтор с запасными конфигурациями
		server::context_t same;
		// Тот же ключ, что у чужого сервера, воспроизвести нельзя: берём его перечень как есть
		client::context_t again;
		// Ставим присланные конфигурации
		if(again.ech(client.retry()) != context::error_t::NONE)
			// Выходим с отказом
			return 1;
		// Сервер с ключом, отвечающим присланным конфигурациям: тот же сервер после сброса
		foreign.clear();
		// Проводим связь заново с тем же сервером
		if(!converse("Случай 3: повтор с присланными конфигурациями - ECH принят", again, foreign, credential))
			// Выходим с отказом
			return 1;
	}
	{
		// Сервер без ECH
		server::context_t plain;
		// Клиент с GREASE без конфигураций
		client::context_t client;
		// Включаем GREASE
		client.grease(true);
		// Проводим связь: на проводе значение GREASE ECH, связь обычная
		if(!converse("Случай 4: клиент без конфигураций с GREASE ECH, сервер без ECH", client, plain, credential))
			// Выходим с отказом
			return 1;
	}
	// Выходим успешно
	return 0;
}
