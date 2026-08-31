/**
 * @file bench.cpp
 * @date 2026-08-30
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
 * @brief Исходный файл набора замеров со сличением с эталоном
 *
 * @details Замеряется своё, а рядом - то же по роду работы у OpenSSL: хеш против хеша,
 *          поточное шифрование против поточного, шифрование с проверкой целостности
 *          против такого же, подпись и обмен ключами на кривой против кривой. Алгоритмы
 *          при этом разные - ГОСТ у нас и не ГОСТ у эталона, - и сличается здесь не
 *          совпадение итога, а цена работы одного рода.
 *
 * @note Замер берётся лучшим из нескольких прогонов, а не средним: середина ряда ловит
 *       чужую нагрузку машины, тогда как лучший прогон - это цена работы, а не цена
 *       соседства
 *
 * @note Собирать замеры отладочной сборкой бестолку: она замедляет всё разом и ровно,
 *       изображая точечную просадку там, где её нет
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные модули
 */
#include <string>
#include <vector>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <functional>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sign/gost.hpp>
#include <cipher/mgm.hpp>
#include <cipher/mode.hpp>
#include <agreement/ecdhe.hpp>
#include <cipher/kuznyechik.hpp>
#include <digest/streebog.hpp>
#include <entropy/entropy.hpp>
#include <curve/parameters.hpp>
#include <client/client.hpp>
#include <server/server.hpp>

/**
 * Если сличение с эталоном OpenSSL включено
 */
#ifdef ANTS_BENCH_OPENSSL
	/**
	 * Подключаем заголовочные файлы эталона
	 */
	#include <openssl/evp.h>
	#include <openssl/ec.h>
	#include <openssl/rand.h>
#endif // ANTS_BENCH_OPENSSL

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Пространство имён набора замеров
 *
 */
namespace {
	/**
	 * Размер области байтов, на которой меряется полоса
	 */
	static constexpr size_t VOLUME = (1 << 20);

	/**
	 * Число прогонов, лучший из которых и берётся замером
	 */
	static constexpr size_t ROUNDS = 6;

	/**
	 * @brief Метод дополнения названия замера до заданной ширины
	 *
	 * @param name  дополняемое название замера
	 * @param width ширина, до которой название дополняется
	 *
	 * @return      дополненное название замера
	 *
	 * @note Ширина считается знаками, а не байтами: русское название занимает по два
	 *       байта на знак, и дополнение по длине записи разъехалось бы столбцами
	 *
	 */
	string pad(const string & name, const size_t width) noexcept {
		// Число знаков в названии замера
		size_t length = 0;
		/**
		 * Выполняем перебор всех байтов названия замера
		 */
		for(size_t i = 0; i < name.length(); i++){
			// Если байт названия не является продолжением знака
			if((static_cast <uint8_t> (name[i]) & 0xC0) != 0x80)
				// Считаем знаки названия замера
				length++;
		}
		// Выводим название замера, дополненное до заданной ширины
		return (name + string(((length < width) ? (width - length) : 0), ' '));
	}
	/**
	 * @brief Метод замера числа проходов работы за секунду
	 *
	 * @param count число проходов работы в одном прогоне
	 * @param work  замеряемая работа
	 *
	 * @return      лучшее число проходов работы за секунду
	 *
	 */
	double rate(const size_t count, const function <void (void)> & work) noexcept {
		// Лучшее число проходов работы за секунду
		double result = 0.;
		/**
		 * Выполняем перебор прогонов замеряемой работы
		 */
		for(size_t i = 0; i < ROUNDS; i++){
			// Запоминаем миг начала прогона
			const auto begin = chrono::steady_clock::now();
			/**
			 * Выполняем проходы замеряемой работы
			 */
			for(size_t j = 0; j < count; j++)
				// Выполняем очередной проход замеряемой работы
				work();
			// Получаем длительность прогона в наносекундах
			const double elapsed = static_cast <double> (chrono::duration_cast <chrono::nanoseconds> (chrono::steady_clock::now() - begin).count());
			// Если прогон прошёл быстрее, чем часы его меряют
			if(elapsed <= 0.)
				// Переходим к следующему прогону замеряемой работы
				continue;
			// Получаем число проходов работы за секунду
			const double outcome = ((static_cast <double> (count) * 1e9) / elapsed);
			// Если прогон вышел лучше прежних
			if(outcome > result)
				// Запоминаем лучшее число проходов работы за секунду
				result = outcome;
		}
		// Выводим лучшее число проходов работы за секунду
		return result;
	}
	/**
	 * @brief Метод вывода замера полосы
	 *
	 * @param name   название замеряемой работы
	 * @param count  число проходов работы в одном прогоне
	 * @param volume размер области байтов одного прохода работы
	 * @param work   замеряемая работа
	 *
	 * @return       полоса замеряемой работы в мегабайтах за секунду
	 *
	 */
	double band(const string & name, const size_t count, const size_t volume, const function <void (void)> & work) noexcept {
		// Выполняем замер числа проходов работы за секунду
		const double outcome = ((rate(count, work) * static_cast <double> (volume)) / static_cast <double> (1 << 20));
		// Выводим название замеряемой работы
		cout << pad(name, 28) << setw(12) << right << fixed << setprecision(1) << outcome << " МБ/с" << endl;
		// Выводим полосу замеряемой работы
		return outcome;
	}
	/**
	 * @brief Метод вывода замера числа проходов работы
	 *
	 * @param name  название замеряемой работы
	 * @param count число проходов работы в одном прогоне
	 * @param work  замеряемая работа
	 *
	 * @return      число проходов замеряемой работы за секунду
	 *
	 */
	double count(const string & name, const size_t count, const function <void (void)> & work) noexcept {
		// Выполняем замер числа проходов работы за секунду
		const double outcome = rate(count, work);
		// Выводим название замеряемой работы
		cout << pad(name, 28) << setw(12) << right << fixed << setprecision(0) << outcome << " раз/с" << endl;
		// Выводим число проходов замеряемой работы за секунду
		return outcome;
	}
	/**
	 * @brief Метод вывода отношения замеров одного рода работы
	 *
	 * @param name название сличаемого рода работы
	 * @param ours замер своей работы
	 * @param them замер работы эталона
	 *
	 * @note Отношение выводится отставанием, а не долей: доля отставания в полторы тысячи
	 *       раз округляется в ноль и перестаёт что-либо говорить
	 *
	 */
	void relation(const string & name, const double ours, const double them) noexcept {
		// Если сличать замеры не с чем
		if((ours <= 0.) || (them <= 0.))
			// Выходим из вывода отношения замеров
			return;
		// Выводим название сличаемого рода работы
		cout << pad(name, 28) << setw(12) << right << fixed << setprecision(1) << (them / ours) << " раз медленнее" << endl;
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
		/**
		 * Выполняем перебор направлений передачи байтов между сторонами связи
		 */
		for(size_t i = 0; i < 2; i++){
			// Получаем байты, отправляемые стороной связи
			const view_t data = ((i == 0) ? client.output() : server.output());
			// Если стороне связи отправлять нечего
			if(data.size == 0)
				// Переходим к встречному направлению передачи байтов
				continue;
			// Выполняем перенос отправляемых байтов
			const vector <uint8_t> buffer(data.data, data.data + data.size);
			// Если байты передаются от клиента серверу
			if(i == 0){
				// Снимаем отправленные байты с накопителя клиента
				client.consume(buffer.size());
				// Выполняем подачу отправленных байтов серверу
				server.push(view_t(buffer.data(), buffer.size()));
			// Если байты передаются от сервера клиенту
			} else {
				// Снимаем отправленные байты с накопителя сервера
				server.consume(buffer.size());
				// Выполняем подачу отправленных байтов клиенту
				client.push(view_t(buffer.data(), buffer.size()));
			}
			// Запоминаем, что байты между сторонами передавались
			moved = true;
		}
		// Выводим признак того, что байты между сторонами передавались
		return moved;
	}
};

/**
 * Подключаем заголовочный файл выработки подлинности стороны связи
 */
#include "identity.hpp"

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
	// Область байтов, на которой меряется полоса
	vector <uint8_t> data(VOLUME, 0x5A);
	// Место, в которое помещается итог работы над областью байтов
	vector <uint8_t> result(VOLUME, 0);
	// Выводим заголовок замеров своей работы
	cout << "Замеры ANYKS TLS" << endl << endl;
	// Место, в которое помещается хеш области байтов
	uint8_t hash[64];
	/**
	 * Замеряемая работа обязана удаваться: молчаливый отказ её меряется мгновением и
	 * выдаёт полосу, которой не бывает
	 */
	if(!digest::streebog(digest::type_t::SHORT, view_t(data.data(), data.size()), hash, 32)){
		// Выводим сообщение об отказе хеширования области байтов
		cout << "Выработать хеш области байтов не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер полосы хеширования «Стрибог» с длиной хеша 256 разрядов
	const double streebog = band("Стрибог-256", 16, VOLUME, [&data, &hash]() noexcept -> void {
		// Выполняем хеширование области байтов
		digest::streebog(digest::type_t::SHORT, view_t(data.data(), data.size()), hash, 32);
	});
	// Выполняем замер полосы хеширования «Стрибог» с длиной хеша 512 разрядов
	band("Стрибог-512", 16, VOLUME, [&data, &hash]() noexcept -> void {
		// Выполняем хеширование области байтов
		digest::streebog(digest::type_t::LONG, view_t(data.data(), data.size()), hash, 64);
	});
	// Ключ блочного шифрования области байтов
	uint8_t key[32];
	// Выполняем выработку ключа блочного шифрования
	entropy::bytes(key, sizeof(key));
	// Объект блочного шифра «Кузнечик»
	cipher::kuznyechik_t kuznyechik;
	// Если ключ блочного шифра установить не удалось
	if(!kuznyechik.key(view_t(key, sizeof(key)))){
		// Выводим сообщение об отказе установки ключа
		cout << "Установить ключ блочного шифра не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Описание базового алгоритма блочного шифрования
	const cipher::block_t block(kuznyechik);
	// Вектор замены поточного шифрования
	uint8_t nonce[8];
	// Выполняем выработку вектора замены поточного шифрования
	entropy::bytes(nonce, sizeof(nonce));
	// Объект режима гаммирования
	cipher::counter_t counter;
	// Если режим гаммирования завести не удалось
	if(!counter.start(block, view_t(nonce, sizeof(nonce)))){
		// Выводим сообщение об отказе заведения режима
		cout << "Завести режим гаммирования не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Если поточное шифрование области байтов не удалось
	if(!counter.encrypt(view_t(data.data(), data.size()), result.data())){
		// Выводим сообщение об отказе поточного шифрования
		cout << "Выполнить поточное шифрование не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер полосы поточного шифрования «Кузнечик»
	const double stream = band("Кузнечик-CTR", 8, VOLUME, [&counter, &data, &result]() noexcept -> void {
		// Выполняем поточное шифрование области байтов
		counter.encrypt(view_t(data.data(), data.size()), result.data());
	});
	// Место, в которое помещается имитовставка шифрования
	uint8_t tag[16];
	// Начальное заполнение счётчика шифрования с проверкой целостности
	uint8_t seed[cipher::KUZNYECHIK_BLOCK];
	// Выполняем выработку начального заполнения счётчика
	entropy::bytes(seed, sizeof(seed));
	/**
	 * Раздел 4.2 RFC 9058 велит держать старший разряд начального заполнения нулевым
	 */
	seed[0] &= 0x7F;
	// Объект режима шифрования с проверкой целостности
	cipher::galois_t galois;
	// Если режим шифрования с проверкой целостности завести не удалось
	if(!galois.start(block, view_t(seed, sizeof(seed))) || !galois.encrypt(view_t(nullptr, 0), view_t(data.data(), data.size()), result.data(), tag)){
		// Выводим сообщение об отказе шифрования с проверкой целостности
		cout << "Завести шифрование с проверкой целостности не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер полосы шифрования с проверкой целостности
	const double sealed = band("Кузнечик-MGM", 8, VOLUME, [&galois, &block, &seed, &data, &result, &tag]() noexcept -> void {
		// Выполняем заведение режима шифрования с проверкой целостности
		galois.start(block, view_t(seed, sizeof(seed)));
		// Выполняем шифрование области байтов с проверкой целостности
		galois.encrypt(view_t(nullptr, 0), view_t(data.data(), data.size()), result.data(), tag);
	});
	// Эллиптическая кривая подписи и обмена ключами
	curve::curve_t curve;
	// Если кривую подписи и обмена ключами завести не удалось
	if(!curve::parameters("1.2.643.2.2.35.1", curve)){
		// Выводим сообщение об отказе заведения кривой
		cout << "Завести кривую подписи не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Секретный ключ подписи
	uint8_t secret[32];
	// Открытый ключ обмена
	uint8_t opened[64];
	// Если мимолётную пару ключей выработать не удалось
	if(!agreement::generate(curve, secret, opened)){
		// Выводим сообщение об отказе выработки пары ключей
		cout << "Выработать пару ключей не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Объект модуля электронной подписи
	sign::gost_t gost;
	// Если кривую подписи установить не удалось
	if(!gost.start(curve) || !gost.secret(view_t(secret, sizeof(secret)))){
		// Выводим сообщение об отказе заведения подписи
		cout << "Завести подпись не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Место, в которое помещается подпись хеша
	uint8_t signature[64];
	// Выполняем замер числа подписей за секунду
	const double signing = count("ГОСТ 34.10 подпись", 200, [&gost, &hash, &signature]() noexcept -> void {
		// Выполняем выработку подписи хеша
		gost.make(view_t(hash, 32), signature);
	});
	// Если подпись хеша выработать не удалось
	if(!gost.make(view_t(hash, 32), signature)){
		// Выводим сообщение об отказе выработки подписи
		cout << "Выработать подпись не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Если подпись хеша сличить не удалось
	if(!gost.check(view_t(hash, 32), view_t(signature, sizeof(signature)))){
		// Выводим сообщение об отказе сличения подписи
		cout << "Сличить подпись хеша не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер числа сличений подписи за секунду
	const double checking = count("ГОСТ 34.10 сличение", 200, [&gost, &hash, &signature]() noexcept -> void {
		// Выполняем сличение подписи хеша
		gost.check(view_t(hash, 32), view_t(signature, sizeof(signature)));
	});
	// Место, в которое помещается общее значение обмена ключами
	uint8_t shared[32];
	// Если общее значение обмена ключами выработать не удалось
	if(!agreement::ecdhe(curve, view_t(secret, sizeof(secret)), view_t(opened, sizeof(opened)), shared)){
		// Выводим сообщение об отказе обмена ключами
		cout << "Выработать общее значение обмена ключами не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер числа обменов мимолётными ключами за секунду
	const double exchange = count("Обмен ключами ECDHE", 200, [&curve, &secret, &opened, &shared]() noexcept -> void {
		// Выполняем выработку общего значения обмена ключами
		agreement::ecdhe(curve, view_t(secret, sizeof(secret)), view_t(opened, sizeof(opened)), shared);
	});
	// Подлинность стороны сервера
	context::credential_t credentials;
	// Если подлинность стороны сервера выработать не удалось
	if(!identity("anyks.com", credentials)){
		// Выводим сообщение об отказе выработки подлинности
		cout << "Выработать подлинность стороны сервера не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выполняем замер числа рукопожатий за секунду
	count("Рукопожатие TLS 1.3", 50, [&credentials]() noexcept -> void {
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Устанавливаем подлинность стороны сервера
		server.credential(credentials);
		// Выполняем заведение связи стороны сервера
		server.start();
		// Выполняем заведение связи стороны клиента
		client.start();
		/**
		 * Выполняем передачу байтов между сторонами, пока им есть что сказать
		 */
		for(size_t i = 0; (i < 16) && pump(client, server); i++)
			// Продолжаем передачу байтов между сторонами связи
			continue;
	});
	/**
	 * Если сличение с эталоном OpenSSL включено
	 */
	#ifdef ANTS_BENCH_OPENSSL
		// Выводим заголовок замеров работы эталона
		cout << endl << "Замеры эталона OpenSSL " << OPENSSL_VERSION_TEXT << endl << endl;
		// Выполняем замер полосы хеширования SHA-256
		const double sha = band("SHA-256", 16, VOLUME, [&data, &hash]() noexcept -> void {
			// Длина выработанного хеша области байтов
			unsigned int length = 0;
			// Выполняем хеширование области байтов
			::EVP_Digest(data.data(), data.size(), hash, &length, ::EVP_sha256(), nullptr);
		});
		// Объект поточного шифрования эталона
		EVP_CIPHER_CTX * context = ::EVP_CIPHER_CTX_new();
		// Выполняем замер полосы поточного шифрования AES-256-CTR
		const double aes = band("AES-256-CTR", 8, VOLUME, [&context, &key, &nonce, &data, &result]() noexcept -> void {
			// Длина зашифрованной области байтов
			int length = 0;
			// Вектор замены поточного шифрования эталона
			uint8_t iv[16] = {0};
			// Переносим вектор замены поточного шифрования
			::memcpy(iv, nonce, sizeof(nonce));
			// Выполняем заведение поточного шифрования области байтов
			::EVP_EncryptInit_ex(context, ::EVP_aes_256_ctr(), nullptr, key, iv);
			// Выполняем поточное шифрование области байтов
			::EVP_EncryptUpdate(context, result.data(), &length, data.data(), static_cast <int> (data.size()));
		});
		// Выполняем замер полосы шифрования с проверкой целостности AES-256-GCM
		const double gcm = band("AES-256-GCM", 8, VOLUME, [&context, &key, &nonce, &data, &result, &tag]() noexcept -> void {
			// Длина зашифрованной области байтов
			int length = 0;
			// Выполняем заведение шифрования области байтов
			::EVP_EncryptInit_ex(context, ::EVP_aes_256_gcm(), nullptr, key, nonce);
			// Выполняем шифрование области байтов
			::EVP_EncryptUpdate(context, result.data(), &length, data.data(), static_cast <int> (data.size()));
			// Выполняем завершение шифрования области байтов
			::EVP_EncryptFinal_ex(context, result.data() + length, &length);
			// Выполняем извлечение имитовставки шифрования
			::EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, 16, tag);
		});
		// Выполняем освобождение объекта поточного шифрования эталона
		::EVP_CIPHER_CTX_free(context);
		// Ключевая пара кривой P-256 эталона
		EVP_PKEY * pair = ::EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
		// Если ключевую пару кривой эталона выработать не удалось
		if(pair == nullptr){
			// Выводим сообщение об отказе выработки пары ключей
			cout << "Выработать ключевую пару эталона не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
		// Место, в которое помещается подпись эталона
		vector <uint8_t> sealing(128, 0);
		// Длина выработанной подписи эталона
		size_t length = sealing.size();
		// Объект работы с подписью эталона
		EVP_MD_CTX * digest = ::EVP_MD_CTX_new();
		// Выполняем замер числа подписей эталона за секунду
		const double ecdsa = count("ECDSA P-256 подпись", 200, [&digest, &pair, &hash, &sealing, &length]() noexcept -> void {
			// Восстанавливаем длину места под подпись эталона
			length = sealing.size();
			// Выполняем заведение выработки подписи эталона
			::EVP_DigestSignInit(digest, nullptr, nullptr, nullptr, pair);
			// Выполняем выработку подписи эталона
			::EVP_DigestSign(digest, sealing.data(), &length, hash, 32);
		});
		// Выполняем выработку подписи эталона для сличения
		::EVP_DigestSignInit(digest, nullptr, nullptr, nullptr, pair);
		// Выполняем выработку подписи эталона
		::EVP_DigestSign(digest, sealing.data(), &length, hash, 32);
		// Выполняем замер числа сличений подписи эталона за секунду
		const double verify = count("ECDSA P-256 сличение", 200, [&digest, &pair, &hash, &sealing, &length]() noexcept -> void {
			// Выполняем заведение сличения подписи эталона
			::EVP_DigestVerifyInit(digest, nullptr, nullptr, nullptr, pair);
			// Выполняем сличение подписи эталона
			::EVP_DigestVerify(digest, sealing.data(), length, hash, 32);
		});
		// Выполняем освобождение объекта работы с подписью эталона
		::EVP_MD_CTX_free(digest);
		// Место, в которое помещается общее значение обмена эталона
		vector <uint8_t> common(32, 0);
		// Выполняем замер числа обменов ключами эталона за секунду
		const double ecdh = count("Обмен ключами ECDH P-256", 200, [&pair, &common]() noexcept -> void {
			// Длина общего значения обмена эталона
			size_t size = common.size();
			// Объект обмена ключами эталона
			EVP_PKEY_CTX * exchange = ::EVP_PKEY_CTX_new(pair, nullptr);
			// Выполняем заведение обмена ключами эталона
			::EVP_PKEY_derive_init(exchange);
			// Устанавливаем открытый ключ встречной стороны обмена
			::EVP_PKEY_derive_set_peer(exchange, pair);
			// Выполняем выработку общего значения обмена
			::EVP_PKEY_derive(exchange, common.data(), &size);
			// Выполняем освобождение объекта обмена ключами эталона
			::EVP_PKEY_CTX_free(exchange);
		});
		// Выполняем освобождение ключевой пары кривой эталона
		::EVP_PKEY_free(pair);
		// Выводим заголовок отношений замеров одного рода работы
		cout << endl << "Отставание от эталона" << endl << endl;
		// Выводим отношение замеров хеширования
		relation("Хеш 256 разрядов", streebog, sha);
		// Выводим отношение замеров поточного шифрования
		relation("Поточное шифрование", stream, aes);
		// Выводим отношение замеров шифрования с целостностью
		relation("Шифрование с целостностью", sealed, gcm);
		// Выводим отношение замеров выработки подписи
		relation("Подпись", signing, ecdsa);
		// Выводим отношение замеров сличения подписи
		relation("Сличение подписи", checking, verify);
		// Выводим отношение замеров обмена ключами
		relation("Обмен ключами", exchange, ecdh);
		/**
		 * Эталон на этой машине шифрует и хеширует машинными командами, которых у ГОСТ
		 * нет ни на одной: чтобы сличить сами алгоритмы, а не оснастку под них, эталон
		 * запускается с отключённым ускорением
		 */
		cout << endl << "Эталон здесь идёт машинными командами ускорения. Для сличения самих" << endl;
		// Выводим способ отключения ускорения эталона
		cout << "алгоритмов запускать замеры так: OPENSSL_armcap=0 (ARM) либо" << endl;
		// Выводим способ отключения ускорения эталона
		cout << "OPENSSL_ia32cap=~0x200000200000000 (x86-64)" << endl;
	#else
		// Не используем замер хеширования при отключённом сличении
		(void) streebog;
		// Не используем замер поточного шифрования при отключённом сличении
		(void) stream;
		// Не используем замер шифрования с целостностью при отключённом сличении
		(void) sealed;
		// Не используем замер выработки подписи при отключённом сличении
		(void) signing;
		// Не используем замер сличения подписи при отключённом сличении
		(void) checking;
		// Не используем замер обмена ключами при отключённом сличении
		(void) exchange;
	#endif // ANTS_BENCH_OPENSSL
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
