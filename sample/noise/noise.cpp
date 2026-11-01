/**
 * @file noise.cpp
 * @date 2026-09-08
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
 * @brief Пример каркаса Noise (ревизия 34) — рукопожатие XX с обменом сообщениями, раскол на
 *        два состояния шифрования и перенос данных, затем то же постквантовым узором pqXX
 *
 * @details Узор XX не требует знать ключи собеседника заранее: статические ключи идут в самих
 *          сообщениях; PQNoise заменяет обмен Диффи-Хеллмана упаковкой ключа
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные модули
 */
#include <cstring>
#include <iomanip>
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <noise/noise.hpp>
#include <noise/cipher.hpp>
#include <noise/handshake.hpp>
#include <entropy/entropy.hpp>
#include <sys/wipe.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * Подписываемся на пространство имён библиотеки
 */
using namespace nts;

/**
 * @brief Служебные объекты образца
 *
 */
namespace {
	/**
	 * @brief Функция получения просмотра текста
	 *
	 * @param text текст
	 * @return     просмотр
	 *
	 */
	view_t text(const char * text) noexcept {
		// Выводим просмотр текста
		return view_t(reinterpret_cast <const uint8_t *> (text), ::strlen(text));
	}
	/**
	 * @brief Функция проведения рукопожатия двух сторон до конца
	 *
	 * @param a сторона инициатора
	 * @param b сторона отвечающего
	 * @return  признак успешности рукопожатия
	 *
	 */
	bool converse(noise::handshake_t & a, noise::handshake_t & b) noexcept {
		// Место под сообщение рукопожатия
		static uint8_t message[noise::MESSAGE];
		// Место под полезную нагрузку
		static uint8_t payload[noise::MESSAGE];
		/**
		 * Выполняем шаги рукопожатия, пока обе стороны не завершат
		 */
		for(size_t round = 0; round < 8; round++){
			// Сторона, чей черёд писать, и сторона, чей черёд читать
			noise::handshake_t & writer = ((a.step() == noise::step_t::WRITE) ? a : b);
			// Определяем сторону, чей черёд читать
			noise::handshake_t & reader = ((a.step() == noise::step_t::WRITE) ? b : a);
			// Если рукопожатие завершено обеими сторонами
			if((a.step() == noise::step_t::DONE) && (b.step() == noise::step_t::DONE))
				// Сообщаем об успешном завершении рукопожатия
				return true;
			// Длина сообщения
			size_t size = sizeof(message);
			// Нагрузка сообщения: номер шага
			const string note = "шаг " + to_string(round + 1);
			// Если сообщение записать не удалось
			if(!writer.write(view_t(reinterpret_cast <const uint8_t *> (note.data()), note.size()), message, size))
				// Выводим отрицательный результат - сообщение не записано
				return false;
			// Длина нагрузки
			size_t length = sizeof(payload);
			// Если сообщение прочитать не удалось
			if(!reader.read(view_t(message, size), payload, length))
				// Выводим отрицательный результат - сообщение не прочитано
				return false;
			// Печатаем шаг
			cout << "  сообщение " << (round + 1) << ": " << size << " байтов, нагрузка «" << string(reinterpret_cast <const char *> (payload), length) << "»" << endl;
		}
		// Выводим итог
		return ((a.step() == noise::step_t::DONE) && (b.step() == noise::step_t::DONE));
	}
	/**
	 * @brief Функция переноса данных расколотыми состояниями шифрования
	 *
	 * @param a сторона инициатора
	 * @param b сторона отвечающего
	 * @return  признак того, что данные дошли в обе стороны
	 *
	 */
	bool transfer(noise::handshake_t & a, noise::handshake_t & b) noexcept {
		// Состояния шифрования сторон: первое - от инициатора, второе - к нему
		noise::cipher_t sendA, receiveA, sendB, receiveB;
		// Если раскол не удался
		if(!a.split(sendA, receiveA) || !b.split(receiveB, sendB))
			// Выводим отрицательный результат - раскол не удался
			return false;
		// Сообщение, шифртекст, метка и вскрытое
		const view_t message = ::text("данные после рукопожатия");
		// Места шифртекста, метки и вскрытого текста
		uint8_t cipher[64], tag[noise::TAG], plain[64];
		// Если инициатор зашифровать не смог
		if(!sendA.encrypt(view_t(), message, cipher, tag))
			// Выводим отрицательный результат - инициатор не зашифровал
			return false;
		// Если отвечающий расшифровать не смог
		if(!receiveB.decrypt(view_t(), view_t(cipher, message.size), view_t(tag, sizeof(tag)), plain))
			// Выводим отрицательный результат - отвечающий не расшифровал
			return false;
		// Печатаем переданное
		cout << "  перенос: «" << string(reinterpret_cast <const char *> (plain), message.size) << "»" << endl;
		// Ответ отвечающего инициатору
		const view_t answer = ::text("ответ в обратную сторону");
		// Если отвечающий зашифровать не смог
		if(!sendB.encrypt(view_t(), answer, cipher, tag))
			// Выводим отрицательный результат - отвечающий не зашифровал
			return false;
		// Если инициатор расшифровать не смог
		if(!receiveA.decrypt(view_t(), view_t(cipher, answer.size), view_t(tag, sizeof(tag)), plain))
			// Выводим отрицательный результат - инициатор не расшифровал
			return false;
		// Печатаем ответ
		cout << "  ответ: «" << string(reinterpret_cast <const char *> (plain), answer.size) << "»" << endl;
		// Сообщаем об успешном обмене после рукопожатия
		return true;
	}
};

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
	// Пролог, известный обеим сторонам
	const view_t prologue = ::text("образец Noise A-NTS");
	// Статические ключи сторон X25519
	uint8_t secretA[32], publicA[32], secretB[32], publicB[32];
	// Если ключи породить не удалось
	if(!noise::generate(noise::dh_t::X25519, secretA, publicA) || !noise::generate(noise::dh_t::X25519, secretB, publicB))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Печатаем узор
	cout << "Noise_XX_25519_ChaChaPoly_SHA256" << endl;
	// Рукопожатия сторон
	noise::handshake_t a, b;
	// Если рукопожатия завести не удалось
	if(!a.start(::text("Noise_XX_25519_ChaChaPoly_SHA256"), noise::role_t::INITIATOR, prologue) || !b.start(::text("Noise_XX_25519_ChaChaPoly_SHA256"), noise::role_t::RESPONDER, prologue))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Ставим статические ключи: узор XX доставит их собеседнику сам
	if(!a.statics(view_t(secretA, sizeof(secretA))) || !b.statics(view_t(secretB, sizeof(secretB))))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Если рукопожатие либо перенос не удались
	if(!::converse(a, b) || !::transfer(a, b))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Хеши рукопожатия сторон обязаны сойтись: ими привязывают канал
	uint8_t digestA[64], digestB[64];
	// Если хеши разошлись
	if(!a.digest(digestA) || !b.digest(digestB) || (::memcmp(digestA, digestB, a.length()) != 0))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Печатаем сличение
	cout << "  хеши рукопожатия сторон сошлись" << endl;
	// Постквантовый узор pqXX на составном KEM X25519MLKEM768 (Angel и др., CCS 2022)
	cout << "PQNoise_pqXX_X25519MLKEM768_ChaChaPoly_SHA256" << endl;
	// Длина зерна пары KEM: у составного механизма 96 байтов (d ‖ z ‖ секрет X25519)
	const size_t seed = noise::kemlength(noise::kem_t::X25519MLKEM768, noise::part_t::SEED);
	// Зёрна статических пар KEM сторон: пара выводится из зерна детерминированно, хранить достаточно зерно
	uint8_t kemSecretA[128], kemSecretB[128];
	// Если зёрна выработать не удалось
	if((seed == 0) || (seed > sizeof(kemSecretA)) || !entropy::bytes(kemSecretA, seed) || !entropy::bytes(kemSecretB, seed))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Рукопожатия PQNoise
	noise::handshake_t pa, pb;
	// Если рукопожатия завести не удалось
	if(!pa.start(::text("PQNoise_pqXX_X25519MLKEM768_ChaChaPoly_SHA256"), noise::role_t::INITIATOR, prologue) || !pb.start(::text("PQNoise_pqXX_X25519MLKEM768_ChaChaPoly_SHA256"), noise::role_t::RESPONDER, prologue))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Ставим статические зёрна KEM: открытый ключ рукопожатие выводит само
	if(!pa.statics(view_t(kemSecretA, seed)) || !pb.statics(view_t(kemSecretB, seed)))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Если рукопожатие либо перенос не удались
	if(!::converse(pa, pb) || !::transfer(pa, pb))
		// Выходим с отказом
		return EXIT_FAILURE;
	// Затираем тайны
	sys::wipe(secretA, sizeof(secretA));
	sys::wipe(secretB, sizeof(secretB));
	sys::wipe(kemSecretA, sizeof(kemSecretA));
	sys::wipe(kemSecretB, sizeof(kemSecretB));
	// Выходим успешно
	return EXIT_SUCCESS;
}
