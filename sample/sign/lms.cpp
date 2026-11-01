/**
 * @file lms.cpp
 * @date 2026-10-10
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
 * @brief Пример проверки подписи Лейтона-Микали — проверка подписи HSS по RFC 8554
 *        и SP 800-208 на контрольном примере приложения F RFC 8554
 *
 * @details Подпись LMS носит состояние - номер листа дерева Меркла, потому выработка
 *          её модулем сознательно не делается: назначение модуля - проверка подписей
 *          прошивок по CNSA 2.0, где подписывает изготовитель, а проверяет сторона
 *          загрузки. Проверяется контрольный пример из набора tests/corpus/lms
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
#include <iterator>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sign/lms.hpp>

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
	 * @brief Функция чтения файла набора данных целиком
	 *
	 * @param name имя файла набора данных
	 * @return     содержимое файла набора данных
	 *
	 */
	vector <uint8_t> slurp(const char * name) noexcept {
		// Содержимое файла набора данных
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
	// Открытый ключ контрольного примера приложения F RFC 8554
	const vector <uint8_t> key = ::slurp("lms/pubkey.bin");
	// Сообщение контрольного примера
	const vector <uint8_t> message = ::slurp("lms/message.bin");
	// Подпись контрольного примера: двухуровневая HSS
	const vector <uint8_t> signature = ::slurp("lms/signature.bin");
	// Если записи контрольного примера прочитать не удалось
	if(key.empty() || message.empty() || signature.empty()){
		// Выводим сообщение об отказе чтения набора
		cout << "Прочитать набор tests/corpus/lms не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим начало открытого ключа контрольного примера
	::print("Открытый ключ      ", key.data(), 16);
	// Выводим начало подписи контрольного примера
	::print("Подпись HSS        ", signature.data(), 16);
	/**
	 * Выполняем проверку подписи HSS контрольного примера
	 *
	 * @details Алгоритмы 4б, 6 и 6а RFC 8554: по подписи LM-OTS вычисляется ключ-кандидат
	 *          цепочками Винтерница, по нему и пути Меркла - корень-кандидат дерева, который
	 *          сличается с открытым ключом; у HSS подпись нижнего уровня заверяется открытым
	 *          ключом, подписанным уровнем выше
	 *
	 */
	if(!sign::lms::verify(view_t(key.data(), key.size()), view_t(message.data(), message.size()), view_t(signature.data(), signature.size()))){
		// Выводим сообщение об отказе проверки подписи
		cout << "Подпись контрольного примера не сошлась" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим сообщение об успешной проверке подписи
	cout << "Проверка подписи   : подпись HSS сошлась" << endl;
	// Подделанное сообщение: портим один байт
	vector <uint8_t> forged(message);
	// Искажаем первый байт копии
	forged[0] ^= 0x01;
	// Если подпись подделанного сообщения отвергнута
	if(!sign::lms::verify(view_t(key.data(), key.size()), view_t(forged.data(), forged.size()), view_t(signature.data(), signature.size())))
		// Выводим сообщение об отвержении подписи подделанного сообщения
		cout << "Проверка подмены   : подпись подменённого сообщения отвергнута" << endl;
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
