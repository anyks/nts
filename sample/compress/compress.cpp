/**
 * @file compress.cpp
 * @date 2026-09-06
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
 * @brief Пример сжатия цепочки сертификатов (RFC 8879) - кодек предоставляет потребитель
 *        двумя вызовами без состояния, связь зовёт его по опознавателю алгоритма и
 *        объявляет, каким алгоритмом цепочка ушла и пришла
 *
 * @details Библиотека ни zlib, ни Brotli, ни Zstandard не несёт: алгоритм подаётся
 *          вызовами codecs с опознавателем по реестру RFC 8879. Здесь кодек свой -
 *          честное сжатие повторами по образу LZ77 из lz77.hpp под частным
 *          опознавателем 16384, а рядом, если системный zlib найден сборкой, - настоящий
 *          zlib под опознавателем 1. Цепочка из трёх сертификатов ECDSA берётся из набора
 *          tests/corpus: повторы имён издателя и опознавателей в ней настоящие
 *
 * @note Сжатие вправе отказать - цепочка тогда уходит несжатой, как велит раздел 4 RFC
 *       8879; распаковка обязана выдать ровно ожидаемую длину, иначе цепочка отвергается
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
 * Если системный zlib найден сборкой
 */
#ifdef ANTS_SAMPLE_ZLIB
	/**
	 * Подключаем заголовочный файл zlib
	 */
	#include <zlib.h>
#endif // ANTS_SAMPLE_ZLIB

/**
 * Подключаем заголовочные файлы проекта
 */
#include <pem/pem.hpp>
#include <client/client.hpp>
#include <server/server.hpp>

/**
 * Подключаем частный кодек сжатия повторами
 */
#include "lz77.hpp"

/**
 * @brief Пространство имён образца
 *
 */
namespace {
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
	 * @brief Метод составления подлинности стороны из цепочки набора
	 *
	 * @param result подлинность, в которую помещается итог
	 *
	 * @return       признак успешности составления подлинности
	 *
	 */
	bool chained(context::credential_t & result) noexcept {
		// Читаем секретный ключ листа цепочки в записи PEM
		result.secret = corpus("leaf-ec.key");
		// Читаем цепочку набора в записи PEM: лист, посредник и корень
		const vector <uint8_t> text = corpus("chain-ec.pem");
		// Если ключ либо цепочка не прочитаны
		if(result.secret.empty() || text.empty())
			// Выводим отказ составления подлинности
			return false;
		// Выполняем сброс цепочки сертификатов
		result.chain.clear();
		// Выводим итог разбора цепочки сертификатов из записи PEM
		return ((pem::certificates(string(text.begin(), text.end()), result.chain) == pem::error_t::NONE) && (result.chain.size() == 3));
	}
	/**
	 * @brief Метод передачи накопленных байтов между сторонами связи
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 * @return       признак того, что байты между сторонами передавались
	 *
	 */
	bool pump(client::context_t & client, server::context_t & server) noexcept {
		// Признак того, что байты между сторонами передавались
		bool moved = false;
		// Получаем байты, отправляемые клиентом
		view_t data = client.output();
		// Если клиенту есть что отправить серверу
		if(data.size > 0){
			// Выполняем перенос отправляемых байтов
			const vector <uint8_t> buffer(data.data, data.data + data.size);
			// Снимаем отправленные байты с накопителя клиента
			client.consume(buffer.size());
			// Выполняем подачу отправленных байтов серверу
			server.push(view_t(buffer.data(), buffer.size()));
			// Запоминаем, что байты между сторонами передавались
			moved = true;
		}
		// Получаем байты, отправляемые сервером
		data = server.output();
		// Если серверу есть что отправить клиенту
		if(data.size > 0){
			// Выполняем перенос отправляемых байтов
			const vector <uint8_t> buffer(data.data, data.data + data.size);
			// Снимаем отправленные байты с накопителя сервера
			server.consume(buffer.size());
			// Выполняем подачу отправленных байтов клиенту
			client.push(view_t(buffer.data(), buffer.size()));
			// Запоминаем, что байты между сторонами передавались
			moved = true;
		}
		// Выводим признак того, что байты между сторонами передавались
		return moved;
	}
	/**
	 * @brief Метод проведения связи сторон до тишины с подсчётом байтов залпа сервера
	 *
	 * @param client связь стороны клиента
	 * @param server связь стороны сервера
	 *
	 * @return       число байтов, отправленных сервером за рукопожатие
	 *
	 */
	size_t converse(client::context_t & client, server::context_t & server) noexcept {
		// Число байтов, отправленных сервером
		size_t sent = 0;
		/**
		 * Выполняем передачу байтов между сторонами, пока им есть что сказать
		 */
		for(size_t i = 0; i < 16; i++){
			// Получаем байты, отправляемые клиентом
			const view_t data = client.output();
			// Признак того, что байты между сторонами передавались
			bool moved = (data.size > 0);
			// Если клиенту есть что отправить серверу
			if(moved){
				// Выполняем перенос отправляемых байтов
				const vector <uint8_t> buffer(data.data, data.data + data.size);
				// Снимаем отправленные байты с накопителя клиента
				client.consume(buffer.size());
				// Выполняем подачу отправленных байтов серверу: ответ складывается тотчас
				server.push(view_t(buffer.data(), buffer.size()));
			}
			// Считаем байты, накопленные сервером к отправке
			sent += server.output().size;
			// Переносим ответ сервера клиенту
			moved = (pump(client, server) || moved);
			// Если байты между сторонами не передавались
			if(!moved)
				// Прекращаем передачу
				break;
		}
		// Выводим число байтов, отправленных сервером
		return sent;
	}
	/**
	 * Если системный zlib найден сборкой
	 */
	#ifdef ANTS_SAMPLE_ZLIB
		/**
		 * @brief Вызов сжатия цепочки сертификатов системным zlib
		 *
		 * @param source  сжимаемое тело сообщения цепочки
		 * @param result  накопитель, в который складывается сжатый поток
		 * @param context указатель счётчика работы кодека
		 *
		 * @return        признак успешности сжатия
		 *
		 */
		bool zlibCompress(const view_t & source, vector <uint8_t> & result, void * context) {
			// Верхний предел длины сжатого потока
			uLongf length = ::compressBound(static_cast <uLong> (source.size));
			// Занимаем место под сжатый поток
			result.assign(static_cast <size_t> (length), 0);
			// Если сжатие не удалось
			if(::compress2(result.data(), &length, source.data, static_cast <uLong> (source.size), Z_BEST_COMPRESSION) != Z_OK)
				// Выводим отказ: цепочка уйдёт несжатой
				return false;
			// Усекаем накопитель до длины сжатого потока
			result.resize(static_cast <size_t> (length));
			// Счётчик работы кодека
			tally_t * tally = reinterpret_cast <tally_t *> (context);
			// Считаем вызов сжатия
			tally->compressions++;
			// Запоминаем длину сжимаемого тела
			tally->source = source.size;
			// Запоминаем длину сжатого тела
			tally->packed = result.size();
			// Выводим успешность сжатия
			return true;
		}
		/**
		 * @brief Вызов распаковки цепочки сертификатов системным zlib
		 *
		 * @param source   распаковываемый сжатый поток
		 * @param expected ожидаемая длина тела после распаковки
		 * @param result   накопитель, в который складывается распакованное тело
		 * @param context  указатель счётчика работы кодека
		 *
		 * @return         признак успешности распаковки
		 *
		 */
		bool zlibDecompress(const view_t & source, const size_t expected, vector <uint8_t> & result, void * context) {
			// Длина распакованного тела
			uLongf length = static_cast <uLongf> (expected);
			// Занимаем место под распакованное тело
			result.assign(expected, 0);
			// Если распаковка не удалась либо длина разошлась с ожидаемой
			if((::uncompress(result.data(), &length, source.data, static_cast <uLong> (source.size)) != Z_OK) || (static_cast <size_t> (length) != expected))
				// Выводим отказ: цепочка будет отвергнута
				return false;
			// Считаем вызов распаковки
			reinterpret_cast <tally_t *> (context)->decompressions++;
			// Выводим успешность распаковки
			return true;
		}
	#endif // ANTS_SAMPLE_ZLIB
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
	// Подлинность стороны сервера: цепочка из трёх сертификатов
	context::credential_t credential;
	// Если подлинность стороны сервера прочитать не удалось
	if(!chained(credential)){
		// Выводим сообщение об отказе чтения подлинности
		cout << "Прочитать цепочку сервера из набора ключей не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Длина цепочки сертификатов
	size_t total = 0;
	/**
	 * Выполняем подсчёт длины цепочки сертификатов
	 */
	for(size_t i = 0; i < credential.chain.size(); i++)
		// Прибавляем длину очередного сертификата
		total += credential.chain[i].size();
	// Выводим состав цепочки
	cout << "Цепочка сервера     : " << credential.chain.size() << " сертификата, " << total << " байт в кодировке DER" << endl;
	// Выводим заголовок первого прогона
	cout << endl << "== Кодек сам по себе: сжатие цепочки повторами ==" << endl;
	{
		// Тело цепочки одним куском
		vector <uint8_t> body;
		/**
		 * Выполняем сборку тела цепочки
		 */
		for(size_t i = 0; i < credential.chain.size(); i++)
			// Дописываем очередной сертификат
			body.insert(body.end(), credential.chain[i].begin(), credential.chain[i].end());
		// Сжатый поток
		vector <uint8_t> packed;
		// Распакованное тело
		vector <uint8_t> unpacked;
		// Если сжатие либо распаковка не сошлись
		if(!lz77Compress(view_t(body.data(), body.size()), packed, nullptr) || !lz77Decompress(view_t(packed.data(), packed.size()), body.size(), unpacked, nullptr) || (unpacked != body)){
			// Выводим сообщение об отказе кодека
			cout << "Кодек не сошёлся сам с собой" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Выводим итог работы кодека
		cout << "LZ77 (16384)        : " << body.size() << " → " << packed.size() << " байт (" << ((packed.size() * 100) / body.size()) << " %), распаковка сошлась байт в байт" << endl;
		// Порченый поток: усечённый на байт
		const vector <uint8_t> truncated(packed.begin(), packed.end() - 1);
		// Распаковка порченого потока
		vector <uint8_t> spoiled;
		// Выводим итог распаковки усечённого потока: длина не сошлась - отказ
		cout << "Усечённый поток     : распаковка " << (lz77Decompress(view_t(truncated.data(), truncated.size()), body.size(), spoiled, nullptr) ? "прошла" : "отказала - длина не сошлась с ожидаемой") << endl;
	}
	// Выводим заголовок прогона со сжатием в рукопожатии
	cout << endl << "== Сжатие цепочки в рукопожатии ==" << endl;
	// Счётчики работы кодека у клиента и у сервера
	tally_t ours, theirs;
	// Число байтов залпа сервера без сжатия и со сжатием
	size_t plain = 0, squeezed = 0;
	/**
	 * Выполняем перебор: без кодеков и с кодеками
	 */
	for(size_t pass = 0; pass < 2; pass++){
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Подлинность сервера
		server.credential(credential);
		// Если кодеки подаются
		if(pass == 1){
			// Алгоритмы клиента в порядке предпочтения
			vector <context::codec_t> mine;
			// Алгоритмы сервера
			vector <context::codec_t> yours;
			/**
			 * Если системный zlib найден сборкой: клиент предпочитает его
			 */
			#ifdef ANTS_SAMPLE_ZLIB
				// Добавляем zlib клиенту под опознавателем 1 реестра RFC 8879
				mine.push_back(context::codec_t(static_cast <uint16_t> (extension::compression_t::ZLIB), zlibCompress, zlibDecompress, &ours));
			#endif // ANTS_SAMPLE_ZLIB
			// Добавляем частный кодек клиенту
			mine.push_back(context::codec_t(LZ77_ALGORITHM, lz77Compress, lz77Decompress, &ours));
			// Сервер знает лишь частный кодек: общий алгоритм найдётся по нему
			yours.push_back(context::codec_t(LZ77_ALGORITHM, lz77Compress, lz77Decompress, &theirs));
			// Устанавливаем алгоритмы клиенту с умолчанием предела распаковки
			client.codecs(mine, 0);
			// Устанавливаем алгоритмы серверу
			server.codecs(yours, 0);
		}
		// Если связь завести не удалось
		if((server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE)){
			// Выводим сообщение об отказе заведения связи
			cout << "Завести связь не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Проводим рукопожатие со счётом байтов сервера
		const size_t sent = converse(client, server);
		// Если рукопожатие не пройдено
		if(!client.established() || !server.established()){
			// Выводим сообщение об отказе рукопожатия
			cout << "Рукопожатие не прошло: отказы " << static_cast <int> (client.error()) << " и " << static_cast <int> (server.error()) << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Если кодеков нет
		if(pass == 0){
			// Запоминаем байты залпа без сжатия
			plain = sent;
			// Выводим итог: цепочка пришла обычным сообщением Certificate
			cout << "Без кодеков         : залп сервера " << sent << " байт, compression(READ) у клиента = " << client.compression(context::direction_t::READ) << " (сообщение Certificate)" << endl;
		// Если кодеки поданы
		} else {
			// Запоминаем байты залпа со сжатием
			squeezed = sent;
			// Если сжатие не состоялось
			if((client.compression(context::direction_t::READ) != LZ77_ALGORITHM) || (server.compression(context::direction_t::WRITE) != LZ77_ALGORITHM) || (theirs.compressions != 1) || (ours.decompressions != 1)){
				// Выводим сообщение о расхождении
				cout << "Цепочка ушла несжатой: алгоритм " << client.compression(context::direction_t::READ) << endl;
				// Выходим из приложения с признаком отказа
				return EXIT_FAILURE;
			}
			// Выводим итог: цепочка пришла сообщением CompressedCertificate
			cout << "С кодеками          : залп сервера " << sent << " байт, compression(READ) у клиента = " << client.compression(context::direction_t::READ) << ", compression(WRITE) у сервера = " << server.compression(context::direction_t::WRITE) << endl;
			// Выводим работу кодека сервера
			cout << "Кодек сервера       : сжатий " << theirs.compressions << ", тело цепочки " << theirs.source << " → " << theirs.packed << " байт" << endl;
			// Выводим работу кодека клиента
			cout << "Кодек клиента       : распаковок " << ours.decompressions << ", сжатий " << ours.compressions << " (подлинности клиента сервер не просил)" << endl;
			// Выводим прикладной итог: у клиента цепочка та же
			cout << "Цепочка у клиента   : " << client.peer().size() << " сертификата, " << ((client.peer() == credential.chain) ? "байт в байт" : "расходится") << endl;
		}
	}
	// Выводим сбережение залпа
	cout << "Сбережение          : " << ((plain > squeezed) ? (plain - squeezed) : 0) << " байт залпа сервера" << endl;
	/**
	 * Если системный zlib найден сборкой: сличаем с настоящим zlib
	 */
	#ifdef ANTS_SAMPLE_ZLIB
		// Выводим заголовок прогона с zlib
		cout << endl << "== Системный zlib (опознаватель 1 реестра RFC 8879) ==" << endl;
		{
			// Связь стороны клиента
			client::context_t client;
			// Связь стороны сервера
			server::context_t server;
			// Подлинность сервера
			server.credential(credential);
			// Счётчики работы zlib
			tally_t zipped, unzipped;
			// Обе стороны знают zlib
			client.codecs(vector <context::codec_t> {context::codec_t(static_cast <uint16_t> (extension::compression_t::ZLIB), zlibCompress, zlibDecompress, &unzipped)}, 0);
			// Алгоритмы сервера
			server.codecs(vector <context::codec_t> {context::codec_t(static_cast <uint16_t> (extension::compression_t::ZLIB), zlibCompress, zlibDecompress, &zipped)}, 0);
			// Если связь завести не удалось
			if((server.start() != context::error_t::NONE) || (client.start() != context::error_t::NONE)){
				// Выводим сообщение об отказе заведения связи
				cout << "Завести связь с zlib не удалось" << endl;
				// Выходим из приложения с признаком отказа
				return EXIT_FAILURE;
			}
			// Проводим рукопожатие
			const size_t sent = converse(client, server);
			// Если рукопожатие не пройдено либо сжатие не zlib
			if(!client.established() || (client.compression(context::direction_t::READ) != static_cast <uint16_t> (extension::compression_t::ZLIB))){
				// Выводим сообщение об отказе
				cout << "Рукопожатие с zlib не прошло: отказ " << static_cast <int> (client.error()) << endl;
				// Выходим из приложения с признаком отказа
				return EXIT_FAILURE;
			}
			// Выводим итог сжатия zlib
			cout << "zlib                : тело цепочки " << zipped.source << " → " << zipped.packed << " байт, залп сервера " << sent << " байт, распаковок у клиента " << unzipped.decompressions << endl;
		}
	#endif // ANTS_SAMPLE_ZLIB
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
