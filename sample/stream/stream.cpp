/**
 * @file stream.cpp
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
 * @brief Пример поточного шифрования - обёртка cipher::stream_t кусками любой длины с
 *        вектором в голове потока и меткой GCM в хвосте, режим гаммирования с обратной
 *        связью без метки, шифрование с проверкой целостности ChaCha20-Poly1305 (RFC
 *        8439) разом и потоком, и затирание тайн sys::wipe
 *
 * @details Поток не знает, какими кусками к нему придут данные: файл читается страницами,
 *          сеть отдаёт что пришло, и нарезка на итог не влияет - зашифрованное кусками
 *          по семь байтов расшифровывается кусками по тысяче. Метка GCM сличается на
 *          завершении: порченый поток расшифровывается до конца и лишь там отвергается,
 *          оттого выдачу поточного расшифрования нельзя считать подлинной до finish
 *
 * @note Ключи и пароли по завершении работы затираются: обычный memset собиратель вправе
 *       выбросить как бесполезный, а sys::wipe пишет через изменчивый указатель и
 *       выброшен быть не может
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
#include <iostream>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/wipe.hpp>
#include <cipher/aes.hpp>
#include <cipher/mode.hpp>
#include <cipher/stream.hpp>
#include <cipher/chachapoly.hpp>
#include <entropy/entropy.hpp>

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
	 * @brief Функция порождения открытого текста заданной длины
	 *
	 * @param size длина текста
	 * @return     порождённый текст
	 *
	 */
	vector <uint8_t> plain(const size_t size) noexcept {
		// Порождаемый текст
		vector <uint8_t> result(size);
		/**
		 * Выполняем заполнение текста
		 */
		for(size_t i = 0; i < size; i++)
			// Записываем очередной байт
			result[i] = static_cast <uint8_t> ((i * 31) + 7);
		// Выводим текст
		return result;
	}
	/**
	 * @brief Функция пропуска данных через поток кусками заданного размера
	 *
	 * @param stream    объект потока, уже заведённый
	 * @param source    пропускаемые данные
	 * @param chunk     размер куска
	 * @param result    накопитель выхода потока
	 * @return          признак успешности пропуска и завершения
	 *
	 */
	bool pass(cipher::stream_t & stream, const vector <uint8_t> & source, const size_t chunk, vector <uint8_t> & result) noexcept {
		// Опустошаем накопитель выхода перед подачей кусков
		result.clear();
		/**
		 * Выполняем подачу данных кусками
		 */
		for(size_t offset = 0; offset < source.size(); offset += chunk){
			// Длина очередного куска
			const size_t size = (((source.size() - offset) < chunk) ? (source.size() - offset) : chunk);
			// Если подача куска не удалась
			if(!stream.update(view_t(source.data() + offset, size), result))
				// Выводим отрицательный результат - подача куска не удалась
				return false;
		}
		// Выводим итог завершения потока: метка дописывается либо сличается здесь
		return stream.finish(result);
	}
	/**
	 * @brief Функция подсчёта ненулевых байтов области
	 *
	 * @param data область байтов
	 * @param size длина области
	 * @return     число ненулевых байтов
	 *
	 */
	size_t nonzero(const uint8_t * data, const size_t size) noexcept {
		// Число ненулевых байтов
		size_t count = 0;
		/**
		 * Выполняем перебор байтов области
		 */
		for(size_t i = 0; i < size; i++)
			// Считаем ненулевой байт
			count += ((data[i] != 0) ? 1 : 0);
		// Выводим число ненулевых байтов
		return count;
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
	// Ключ AES-256
	uint8_t key[cipher::AES_KEY];
	// Если ключ выработать не удалось
	if(!entropy::bytes(key, sizeof(key))){
		// Выводим сообщение об отказе выработки ключа
		cout << "Выработать ключ не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Блочный шифр AES
	cipher::aes_t aes;
	// Если ключ шифру установить не удалось
	if(!aes.key(view_t(key, sizeof(key)))){
		// Выводим сообщение об отказе установки ключа
		cout << "Установить ключ AES не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Описание базового шифра для режимов
	const cipher::block_t block(aes);
	// Открытый текст: не кратен ни блоку, ни куску
	const vector <uint8_t> source = plain(1000);
	// Выводим заголовок первого прогона
	cout << "== Поток GCM: зашифрование кусками по 7, расшифрование кусками по 333 ==" << endl;
	// Объект потока
	cipher::stream_t stream;
	// Выход зашифрования
	vector <uint8_t> sealed;
	// Если поток на зашифрование завести либо пропустить не удалось
	if(!stream.start(cipher::direction_t::ENCRYPT, block, cipher::regime_t::GCM) || !pass(stream, source, 7, sealed)){
		// Выводим сообщение об отказе зашифрования
		cout << "Зашифровать поток не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим устройство выхода: вектор, шифртекст, метка
	cout << "Выход               : " << sealed.size() << " байт = вектор " << cipher::STREAM_NONCE << " + шифртекст " << source.size() << " + метка " << cipher::GCM_TAG << endl;
	// Выход расшифрования
	vector <uint8_t> opened;
	// Если поток на расшифрование завести либо пропустить не удалось
	if(!stream.start(cipher::direction_t::DECRYPT, block, cipher::regime_t::GCM) || !pass(stream, sealed, 333, opened) || (opened != source)){
		// Выводим сообщение об отказе расшифрования
		cout << "Расшифровать поток не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим итог расшифрования
	cout << "Расшифрование       : " << opened.size() << " байт, сошлись байт в байт, метка сличена на завершении" << endl;
	// Порченый поток: байт шифртекста посередине
	vector <uint8_t> spoiled = sealed;
	// Портим байт шифртекста
	spoiled[cipher::STREAM_NONCE + (source.size() / 2)] ^= 0x01;
	// Выход расшифрования порченого потока
	vector <uint8_t> garbage;
	// Заводим поток на расшифрование порченого
	stream.start(cipher::direction_t::DECRYPT, block, cipher::regime_t::GCM);
	// Расшифровываем порченый поток: куски проходят, отказ приходит на завершении
	const bool accepted = pass(stream, spoiled, 64, garbage);
	// Если порченый поток принят
	if(accepted){
		// Выводим сообщение о расхождении
		cout << "Порченый поток принят" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим итог: выдача до завершения подлинной не считается
	cout << "Порченый поток      : finish отказал, выдано " << garbage.size() << " байт до сличения метки - они не подлинны" << endl;
	// Выводим заголовок прогона режима без метки
	cout << endl << "== Поток гаммирования с обратной связью: без метки ==" << endl;
	// Если поток режима гаммирования завести либо пропустить не удалось
	if(!stream.start(cipher::direction_t::ENCRYPT, block, cipher::regime_t::FEEDBACK) || !pass(stream, source, 100, sealed)){
		// Выводим сообщение об отказе зашифрования
		cout << "Зашифровать поток гаммированием не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим устройство выхода: вектор и шифртекст, метки нет
	cout << "Выход               : " << sealed.size() << " байт = вектор " << (sealed.size() - source.size()) << " + шифртекст " << source.size() << ", метки нет" << endl;
	// Если поток на расшифрование завести либо пропустить не удалось
	if(!stream.start(cipher::direction_t::DECRYPT, block, cipher::regime_t::FEEDBACK) || !pass(stream, sealed, 1, opened) || (opened != source)){
		// Выводим сообщение об отказе расшифрования
		cout << "Расшифровать поток гаммированием не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим итог: без метки порча не ловится
	cout << "Расшифрование       : по байту, сошлось; порчу без метки поток не заметит - целостность здесь на совести потребителя" << endl;
	// Выводим заголовок прогона ChaCha20-Poly1305
	cout << endl << "== ChaCha20-Poly1305: разом и потоком ==" << endl;
	// Заполнение шифра: неповторимое для всякого сообщения на одном ключе
	uint8_t nonce[cipher::CHACHA_NONCE];
	// Если заполнение выработать не удалось
	if(!entropy::bytes(nonce, sizeof(nonce))){
		// Выводим сообщение об отказе выработки заполнения
		cout << "Выработать заполнение не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Связанные данные: защищаются лишь меткой
	const string associated = "заголовок записи";
	// Просмотр связанных данных
	const view_t header(reinterpret_cast <const uint8_t *> (associated.data()), associated.size());
	// Шифрование с проверкой целостности
	cipher::chachapoly_t aead;
	// Шифртекст разового зашифрования
	vector <uint8_t> once(source.size(), 0);
	// Метка разового зашифрования
	uint8_t tag[cipher::CHACHAPOLY_TAG];
	// Если разовое зашифрование не удалось
	if(!aead.start(view_t(key, sizeof(key)), view_t(nonce, sizeof(nonce))) || !aead.encrypt(header, view_t(source.data(), source.size()), once.data(), tag)){
		// Выводим сообщение об отказе зашифрования
		cout << "Зашифровать разом не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим итог разового зашифрования
	cout << "Разом               : " << once.size() << " байт шифртекста, метка " << sizeof(tag) << " байт; повтор на том же заполнении " << (aead.encrypt(header, view_t(source.data(), source.size()), once.data(), tag) ? "прошёл" : "отвергнут заслоном") << endl;
	// Шифртекст поточного зашифрования
	vector <uint8_t> piecewise(source.size(), 0);
	// Метка поточного зашифрования
	uint8_t streamed[cipher::CHACHAPOLY_TAG];
	// Если поток завести либо связанные данные подать не удалось
	if(!aead.start(view_t(key, sizeof(key)), view_t(nonce, sizeof(nonce))) || !aead.associate(header)){
		// Выводим сообщение об отказе заведения потока
		cout << "Завести поток ChaCha20-Poly1305 не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	/**
	 * Выполняем поточное зашифрование кусками по 17 байтов
	 */
	for(size_t offset = 0; offset < source.size(); offset += 17){
		// Длина очередного куска
		const size_t size = (((source.size() - offset) < 17) ? (source.size() - offset) : 17);
		// Если кусок зашифровать не удалось
		if(!aead.encrypt(view_t(source.data() + offset, size), piecewise.data() + offset)){
			// Выводим сообщение об отказе зашифрования
			cout << "Зашифровать кусок не удалось" << endl;
			// Выходим из приложения с признаком отказа
			return EXIT_FAILURE;
		}
	}
	// Если завершить поток меткой не удалось либо итог разошёлся с разовым
	if(!aead.finish(streamed) || (piecewise != once) || (::memcmp(streamed, tag, sizeof(tag)) != 0)){
		// Выводим сообщение о расхождении
		cout << "Поточное зашифрование разошлось с разовым" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим итог поточного зашифрования
	cout << "Потоком по 17       : шифртекст и метка сошлись с разовыми байт в байт" << endl;
	// Открытый текст разового расшифрования
	vector <uint8_t> restored(source.size(), 0xFF);
	// Если разовое расшифрование не удалось
	if(!aead.start(view_t(key, sizeof(key)), view_t(nonce, sizeof(nonce))) || !aead.decrypt(header, view_t(once.data(), once.size()), restored.data(), view_t(tag, sizeof(tag))) || (restored != source)){
		// Выводим сообщение об отказе расшифрования
		cout << "Расшифровать разом не удалось" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим итог разового расшифрования
	cout << "Расшифрование разом : сошлось" << endl;
	// Портим метку
	tag[0] ^= 0x01;
	// Открытый текст расшифрования с порченой меткой
	vector <uint8_t> untouched(source.size(), 0xFF);
	// Расшифрование с порченой меткой: выход обязан остаться нетронутым
	const bool verified = (aead.start(view_t(key, sizeof(key)), view_t(nonce, sizeof(nonce))) && aead.decrypt(header, view_t(once.data(), once.size()), untouched.data(), view_t(tag, sizeof(tag))));
	// Если порченая метка принята либо выход тронут
	if(verified || (nonzero(untouched.data(), untouched.size()) != untouched.size())){
		// Выводим сообщение о расхождении
		cout << "Порченая метка принята либо выход тронут" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выводим итог: метка сличается прежде снятия гаммы
	cout << "Порченая метка      : отвергнута, выход не тронут (метка сличается прежде снятия гаммы)" << endl;
	// Выводим заголовок прогона затирания
	cout << endl << "== Затирание тайн ==" << endl;
	// Выводим ненулевые байты ключа до затирания
	cout << "Ключ до затирания   : " << nonzero(key, sizeof(key)) << " ненулевых байтов из " << sizeof(key) << endl;
	// Затираем ключ через изменчивый указатель
	sys::wipe(key, sizeof(key));
	// Выводим ненулевые байты ключа после затирания
	cout << "Ключ после          : " << nonzero(key, sizeof(key)) << " ненулевых байтов" << endl;
	// Набор байтов с тайной
	vector <uint8_t> hoard(source);
	// Ёмкость набора до затирания
	const size_t capacity = hoard.capacity();
	// Затираем набор: он опустошается, а буфер остаётся у него нулевым
	sys::wipe(hoard);
	// Выводим итог затирания набора
	cout << "Набор байтов        : размер " << hoard.size() << ", ёмкость " << hoard.capacity() << " (была " << capacity << ") - буфер затёрт, не освобождён" << endl;
	// Пароль строкой длиннее короткого запаса
	string password = "пароль, который нельзя оставлять в памяти";
	// Затираем пароль
	sys::wipe(password);
	// Выводим итог затирания строки
	cout << "Строка              : размер " << password.size() << ", " << (password.empty() ? "пуста" : "не пуста") << endl;
	// Если ключ затёрт не целиком
	if(nonzero(key, sizeof(key)) != 0){
		// Выводим сообщение о расхождении
		cout << "Ключ затёрт не целиком" << endl;
		// Выходим из приложения с признаком отказа
		return EXIT_FAILURE;
	}
	// Выходим из приложения с признаком успеха
	return EXIT_SUCCESS;
}
