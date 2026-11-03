/**
 * @file differential.cpp
 * @date 2026-11-03
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
 * @brief Сличитель машин состояний TLS и DTLS с эталоном OpenSSL
 *
 * @note Один и тот же сценарий исполняют пара связей A-NTS и пара связей OpenSSL:
 *       управляющие байты задают протокол, нарезку потока либо размер дейтаграммы,
 *       потери, повторы, перестановку, обрыв и порчу, а стадии рукопожатия,
 *       возобновления, смены ключей, обмена и закрытия сличаются по итогу, ибо
 *       побайтовое совпадение двух несходных реализаций не бывает
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <new>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <deque>
#include <fstream>
#include <algorithm>
#include <iterator>

/**
 * Системные заголовочные файлы
 */
#include <sys/time.h>
#include <unistd.h>

/**
 * Подключаем заголовочные файлы проекта и проверочной оснастки
 */
#include <pem/pem.hpp>
#include <client/client.hpp>
#include <server/server.hpp>

/**
 * Подключаем заголовочные файлы эталона сличения
 */
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

/**
 * Используем пространство имён проекта
 */
using namespace nts;

/**
 * Служебные объекты сличителя машин состояний
 */
namespace {
	/**
	 * Путь к набору проверочных ключей
	 */
	static const char * CORPUS = ANTS_CORPUS;
	/**
	 * Управляющие разряды сценария младшего байта
	 */
	// Намеренный обрыв рукопожатия
	static constexpr uint16_t TRUNCATE      = 0x0001;
	// Повтор приветствия TLS либо перестановка дейтаграмм
	static constexpr uint16_t REORDER       = 0x0002;
	// Периодические потери дейтаграмм
	static constexpr uint16_t LOSS          = 0x0004;
	// Намеренная порча байта переноса
	static constexpr uint16_t DAMAGE        = 0x0008;
	// Выдача и проверка билета возобновления
	static constexpr uint16_t RESUME        = 0x0010;
	// Смена ключей клиентом издания TLS 1.3
	static constexpr uint16_t CLIENT_UPDATE = 0x0020;
	// Смена ключей сервером издания TLS 1.3
	static constexpr uint16_t SERVER_UPDATE = 0x0040;
	// Закрытие связи после прикладного обмена
	static constexpr uint16_t CLOSE         = 0x0080;
	/**
	 * Управляющие разряды сценария старшего байта
	 */
	// Повтор всякой перенесённой дейтаграммы
	static constexpr uint16_t DUPLICATE     = 0x0100;
	/**
	 * Разряды итога сценария
	 */
	// Рукопожатие доведено до установления связи
	static constexpr uint8_t ESTABLISHED = 0x01;
	// Возобновление билетом доведено до обмена
	static constexpr uint8_t RESUMED     = 0x02;
	// Заказанные смены ключей доставлены
	static constexpr uint8_t UPDATED     = 0x04;
	// Прикладной обмен доставлен без искажения
	static constexpr uint8_t EXCHANGED   = 0x08;
	// Извещение о закрытии получено стороной сервера
	static constexpr uint8_t CLOSED      = 0x10;
	/**
	 * Издания единой шкалы для зажима сторон сличения
	 */
	// Издание TLS 1.3 потокового переноса
	static constexpr uint16_t TLS13 = 0x0304;
	// Издание DTLS 1.2 переносного зажима в единой шкале изданий
	static constexpr uint16_t TLS12 = 0x0303;
	/**
	 * Ключ билетов возобновления издания DTLS 1.2
	 */
	static const uint8_t VAULT[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
	/**
	 * Подлинность сторон, составляемая один раз на процесс сличителя
	 */
	context::credential_t credentials;
	/**
	 * Признак готовности подлинности и настроек эталона
	 */
	bool ready = false;
	/**
	 * Способы переноса эталона: поток и дейтаграммы
	 */
	BIO_METHOD * methods[2] = {};
	/**
	 * Настройки клиентов эталона: потоковый и дейтаграммный
	 */
	SSL_CTX * clients[2] = {};
	/**
	 * Настройки серверов эталона: потоковый и дейтаграммный
	 */
	SSL_CTX * servers[2] = {};
	/**
	 * Настройки переноса одного сценария
	 */
	typedef struct Settings {
		// Управляющие разряды сценария
		uint16_t flags;
		// Длина куска потока TLS
		size_t chunk;
		// Размер дейтаграммы DTLS
		size_t mtu;
		// Круг намеренного обрыва
		size_t stop;
		// Круг повтора либо порчи
		size_t special;
		// Период потерь дейтаграмм
		size_t period;
		// Смещение портимого байта
		size_t offset;
	} settings_t;
	/**
	 * Накопитель переноса одной стороны эталона
	 */
	typedef struct Channel {
		// Признак переноса дейтаграммами
		bool datagram;
		// Ограничение размера дейтаграммы
		size_t mtu;
		// Накопитель потока
		std::vector <uint8_t> stream;
		// Очередь дейтаграмм
		std::deque <std::vector <uint8_t>> packets;
	} channel_t;
	/**
	 * @brief Функция чтения файла набора проверочных ключей целиком
	 *
	 * @param name имя файла набора проверочных ключей
	 * @return     содержимое файла набора проверочных ключей
	 *
	 */
	std::vector <uint8_t> keydata(const std::string & name) noexcept {
		// Открываем файл набора проверочных ключей
		std::ifstream file(std::string(CORPUS) + "/" + name, std::ios::binary);
		// Накопитель содержимого файла
		std::vector <uint8_t> result;
		// Если файл набора открыт
		if(file.is_open())
			// Считываем файл целиком
			result.assign(std::istreambuf_iterator <char> (file), std::istreambuf_iterator <char> ());
		// Выводим содержимое файла
		return result;
	}
	/**
	 * @brief Функция составления подлинности из ключей ec256
	 *
	 * @param result подлинность, в которую помещаются ключ и цепочка
	 * @return       признак успешности составления подлинности
	 *
	 */
	bool keyfile(context::credential_t & result) noexcept {
		// Считываем секретный ключ ec256
		result.secret = keydata("ec256.pem");
		// Считываем сертификат ec256
		const std::vector <uint8_t> text = keydata("ec256.crt");
		// Если ключ либо сертификат не прочитан
		if(result.secret.empty() || text.empty())
			// Выводим отказ чтения
			return false;
		// Выполняем сброс цепочки сертификатов
		result.chain.clear();
		// Выводим итог разбора цепочки сертификатов из записи PEM
		return (pem::certificates(std::string(text.begin(), text.end()), result.chain) == pem::error_t::NONE);
	}
	/**
	 * @brief Функция создания накопителя переноса стороны эталона
	 *
	 * @param bio дескриптор способа переноса эталона
	 * @return    признак успешности создания накопителя
	 *
	 */
	int bioCreate(BIO * bio) noexcept {
		// Занимаем накопитель переноса стороны эталона
		channel_t * channel = new (std::nothrow) channel_t();
		// Если накопитель занять не удалось
		if(channel == nullptr)
			// Выводим отказ создания
			return 0;
		// Присоединяем накопитель к дескриптору переноса
		BIO_set_data(bio, channel);
		// Помечаем дескриптор готовым к работе
		BIO_set_init(bio, 1);
		// Выводим успешность создания
		return 1;
	}
	/**
	 * @brief Функция освобождения накопителя переноса стороны эталона
	 *
	 * @param bio дескриптор способа переноса эталона
	 * @return    признак успешности освобождения
	 *
	 */
	int bioDestroy(BIO * bio) noexcept {
		// Получаем накопитель переноса стороны эталона
		channel_t * channel = static_cast <channel_t *> (BIO_get_data(bio));
		// Если накопитель был создан
		if(channel != nullptr)
			// Освобождаем накопитель переноса
			delete channel;
		// Отсоединяем накопитель от дескриптора переноса
		BIO_set_data(bio, nullptr);
		// Помечаем дескриптор освободившимся
		BIO_set_init(bio, 0);
		// Выводим успешность освобождения
		return 1;
	}
	/**
	 * @brief Функция чтения переноса из накопителя стороны эталона
	 *
	 * @param bio    дескриптор способа переноса эталона
	 * @param buffer место, в которое читается перенос
	 * @param length размер места чтения переноса
	 * @return       число прочитанных байтов либо отказ с ожиданием
	 *
	 */
	int bioRead(BIO * bio, char * buffer, const int length) noexcept {
		// Снимаем прежние отметки ожидания переноса
		BIO_clear_retry_flags(bio);
		// Получаем накопитель переноса стороны эталона
		channel_t * channel = static_cast <channel_t *> (BIO_get_data(bio));
		// Если накопитель переноса не создан либо чтение пусто
		if((channel == nullptr) || (length <= 0))
			// Выводим отказ чтения
			return -1;
		// Если перенос идёт дейтаграммами
		if(channel->datagram){
			// Если готовых дейтаграмм нет
			if(channel->packets.empty()){
				// Помечаем чтение ожиданием новых дейтаграмм
				BIO_set_retry_read(bio);
				// Выводим отказ с ожиданием
				return -1;
			}
			// Определяем длину читаемой части дейтаграммы
			const size_t size = std::min(static_cast <size_t> (length), channel->packets.front().size());
			// Переносим читаемую часть дейтаграммы
			::memcpy(buffer, channel->packets.front().data(), size);
			// Снимаем прочитанную дейтаграмму с очереди целиком, как делает перенос пакетами
			channel->packets.pop_front();
			// Выводим число прочитанных байтов
			return static_cast <int> (size);
		}
		// Если готового потока нет
		if(channel->stream.empty()){
			// Помечаем чтение ожиданием продолжения потока
			BIO_set_retry_read(bio);
			// Выводим отказ с ожиданием
			return -1;
		}
		// Определяем длину читаемой части потока
		const size_t size = std::min(static_cast <size_t> (length), channel->stream.size());
		// Переносим читаемую часть потока
		::memcpy(buffer, channel->stream.data(), size);
		// Снимаем прочитанную часть потока с накопителя
		channel->stream.erase(channel->stream.begin(), channel->stream.begin() + static_cast <ptrdiff_t> (size));
		// Выводим число прочитанных байтов
		return static_cast <int> (size);
	}
	/**
	 * @brief Функция записи переноса в накопитель стороны эталона
	 *
	 * @param bio    дескриптор способа переноса эталона
	 * @param buffer место, из которого записывается перенос
	 * @param length размер записываемого переноса
	 * @return       число записанных байтов либо отказ
	 *
	 */
	int bioWrite(BIO * bio, const char * buffer, const int length) noexcept {
		// Снимаем прежние отметки ожидания переноса
		BIO_clear_retry_flags(bio);
		// Получаем накопитель переноса стороны эталона
		channel_t * channel = static_cast <channel_t *> (BIO_get_data(bio));
		// Если накопитель переноса не создан либо запись пуста
		if((channel == nullptr) || (length <= 0))
			// Выводим отказ записи
			return -1;
		/**
		 * Выполняем перехват ошибок занятия памяти
		 */
		try {
			// Если перенос идёт дейтаграммами
			if(channel->datagram)
				// Ставим записанное в очередь одной дейтаграммой
				channel->packets.emplace_back(reinterpret_cast <const uint8_t *> (buffer), reinterpret_cast <const uint8_t *> (buffer) + length);
			else
				// Продолжаем накопитель потока записанным
				channel->stream.insert(channel->stream.end(), reinterpret_cast <const uint8_t *> (buffer), reinterpret_cast <const uint8_t *> (buffer) + length);
		/**
		 * Выполняем перехват ошибок занятия памяти
		 */
		} catch(const std::bad_alloc &) {
			// Выводим отказ записи
			return -1;
		}
		// Выводим число записанных байтов
		return length;
	}
	/**
	 * @brief Функция управления накопителем переноса стороны эталона
	 *
	 * @param bio  дескриптор способа переноса эталона
	 * @param cmd  команда управления накопителем
	 * @param num  числовой довод команды управления
	 * @param ptr  адресный довод команды управления
	 * @return     итог команды управления накопителем
	 *
	 */
	long bioCtrl(BIO * bio, const int cmd, const long num, void * ptr) noexcept {
		// Убираем предупреждение о неиспользуемом адресном доводе
		(void) ptr;
		// Получаем накопитель переноса стороны эталона
		channel_t * channel = static_cast <channel_t *> (BIO_get_data(bio));
		// Если накопитель переноса не создан
		if(channel == nullptr)
			// Выводим отказ управления
			return 0;
		// Итог команды управления накопителем
		long result = 0;
		/**
		 * Выполняем разбор команды управления накопителем
		 */
		switch(cmd){
			// Если запрашивается объём готового переноса
			case BIO_CTRL_PENDING:
				// Определяем объём по виду переноса
				result = static_cast <long> (channel->datagram ? (channel->packets.empty() ? 0 : channel->packets.front().size()) : channel->stream.size());
			break;
			// Если запрашивается сброс накопителя
			case BIO_CTRL_FLUSH:
				// Накопитель сам не задерживает запись
				result = 1;
			break;
			// Если устанавливается размер дейтаграммы
			case BIO_CTRL_DGRAM_SET_MTU:
				// Если размер дейтаграммы осмыслен
				if(num > 0){
					// Ограничиваем размер дейтаграммы
					channel->mtu = static_cast <size_t> (num);
					// Помечаем успех установки
					result = 1;
				}
			break;
			// Если запрашивается размер дейтаграммы либо запасной размер
			case BIO_CTRL_DGRAM_QUERY_MTU:
			case BIO_CTRL_DGRAM_GET_MTU:
			case BIO_CTRL_DGRAM_GET_FALLBACK_MTU:
				// Выводим действующее ограничение размера
				result = static_cast <long> (channel->mtu);
			break;
			// Если запрашивается превышал ли перенос размер дейтаграммы
			case BIO_CTRL_DGRAM_MTU_EXCEEDED:
				// Накопитель не отказывает записи по размеру
				result = 0;
			break;
			// Если помечается собеседник либо связность дейтаграмм
			case BIO_CTRL_DGRAM_CONNECT:
			case BIO_CTRL_DGRAM_SET_CONNECTED:
			case BIO_CTRL_DGRAM_SET_PEER:
				// Адрес собеседника ведёт сам сличитель
				result = 1;
			break;
			// Если запрашивается адрес собеседника
			case BIO_CTRL_DGRAM_GET_PEER:
				// Адрес собеседника у сличителя один и тот же
				result = 0;
			break;
			// Если объявляется очередной срок таймера DTLS
			case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT:
				// Часы таймеров ведёт сам сличитель
				result = 1;
			break;
			// Если запрашивается запрет фрагментации либо обнаружение пути
			case BIO_CTRL_DGRAM_MTU_DISCOVER:
			case BIO_CTRL_DGRAM_SET_DONT_FRAG:
				// Накопитель переносит всё, что ему дали
				result = 1;
			break;
			// Если запрашивается служебный довесок к размеру дейтаграммы
			case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD:
				// Заголовки переноса лежат вне накопителя
				result = 0;
			break;
			// Если устанавливается режим подсматривания дейтаграмм
			case BIO_CTRL_DGRAM_SET_PEEK_MODE:
				// Подсматривание дейтаграмм сличителю не нужно
				result = 1;
			break;
			// Для остальных команд накопителя
			default:
				// Выводим отсутствие поддержки
				result = 0;
		}
		// Выводим итог команды управления
		return result;
	}
	/**
	 * @brief Функция составления способа переноса эталона
	 *
	 * @param datagram признак переноса дейтаграммами
	 * @return         дескриптор способа переноса либо пустота
	 *
	 */
	BIO_METHOD * bioMethod(const bool datagram) noexcept {
		// Заводим способ переноса с служебным именем
		BIO_METHOD * method = BIO_meth_new(datagram ? BIO_TYPE_DGRAM : BIO_TYPE_MEM, "ants");
		// Если способ переноса завести не удалось
		if(method == nullptr)
			// Выводим пустоту
			return nullptr;
		// Если приладить чтение к способу не удалось
		if(BIO_meth_set_read(method, bioRead) != 1){
			// Освобождаем способ переноса
			BIO_meth_free(method);
			// Выводим пустоту
			return nullptr;
		}
		// Если приладить запись к способу не удалось
		if(BIO_meth_set_write(method, bioWrite) != 1){
			// Освобождаем способ переноса
			BIO_meth_free(method);
			// Выводим пустоту
			return nullptr;
		}
		// Если приладить управление к способу не удалось
		if(BIO_meth_set_ctrl(method, bioCtrl) != 1){
			// Освобождаем способ переноса
			BIO_meth_free(method);
			// Выводим пустоту
			return nullptr;
		}
		// Если приладить создание к способу не удалось
		if(BIO_meth_set_create(method, bioCreate) != 1){
			// Освобождаем способ переноса
			BIO_meth_free(method);
			// Выводим пустоту
			return nullptr;
		}
		// Если приладить освобождение к способу не удалось
		if(BIO_meth_set_destroy(method, bioDestroy) != 1){
			// Освобождаем способ переноса
			BIO_meth_free(method);
			// Выводим пустоту
			return nullptr;
		}
		// Выводим составленный способ переноса
		return method;
	}
	/**
	 * @brief Функция выбора срока таймеров DTLS эталона
	 *
	 * @param ssl      связь эталона, спрашивающая срок
	 * @param timerUs  прежний срок таймера в микросекундах
	 * @return         шестнадцать миллисекунд ожидания повторной передачи
	 *
	 * @note Обратный вызов задаёт длительность ожидания, а не показание часов.
	 *       Срок короче пятнадцати миллисекунд OpenSSL считает истёкшим при
	 *       первом же вопросе, поэтому берётся наименьший рабочий срок
	 *
	 */
	unsigned int timerClock(SSL * ssl, const unsigned int timerUs) noexcept {
		// Убираем предупреждение о неиспользуемой связи
		(void) ssl;
		// Если срок запрашивается впервые
		if(timerUs == 0)
			// Выводим начальный срок ожидания
			return 16000;
		// Выводим прежний срок ожидания без нарастания
		return timerUs;
	}
	/**
	 * @brief Функция настройки пары связей A-NTS одного сценария
	 *
	 * @param client      связь стороны клиента
	 * @param server      связь стороны сервера
	 * @param datagram    признак переноса дейтаграммами
	 * @param mtu         размер дейтаграммы
	 *
	 */
	void configure(client::context_t & client, server::context_t & server, const bool datagram, const size_t mtu) noexcept {
		// Зажимаем издание клиента выбранным протоколом
		(void) client.versions(datagram ? TLS12 : TLS13, datagram ? TLS12 : TLS13);
		// Зажимаем издание сервера выбранным протоколом
		(void) server.versions(datagram ? TLS12 : TLS13, datagram ? TLS12 : TLS13);
		// Устанавливаем подлинность стороны сервера
		server.credential(credentials);
		// Назначаем серверу ключ билетов возобновления издания 1.2
		server.vault(std::vector <uint8_t> (VAULT, VAULT + sizeof(VAULT)));
		// Если выбран перенос дейтаграммами
		if(datagram){
			// Устанавливаем перенос дейтаграммами клиенту
			client.transport(context::transport_t::DATAGRAMS);
			// Устанавливаем перенос дейтаграммами серверу
			server.transport(context::transport_t::DATAGRAMS);
			// Ограничиваем размер дейтаграмм обеих сторон
			client.mtu(mtu);
			// Ограничиваем размер дейтаграмм сервера
			server.mtu(mtu);
			// Адрес собеседника для метки возврата состояния
			static const uint8_t ADDRESS[] = {10, 0, 0, 1, 0x12, 0x34};
			// Устанавливаем адрес собеседника серверу
			server.address(view_t(ADDRESS, sizeof(ADDRESS)));
		}
	}
	/**
	 * @brief Функция передачи потока между сторонами A-NTS с заданной нарезкой
	 *
	 * @param client   связь стороны клиента
	 * @param server   связь стороны сервера
	 * @param settings настройки переноса сценария
	 * @param round    номер текущего круга
	 * @param damaged  признак уже выполненной порчи
	 * @return         признак передачи хотя бы одного выходного потока
	 *
	 */
	bool pumpStream(client::context_t & client, server::context_t & server, const settings_t & settings, const size_t round, bool & damaged) noexcept {
		// Признак передачи хотя бы одного выходного потока
		bool moved = false;
		/**
		 * Выполняем перебор направлений передачи
		 */
		for(size_t i = 0; i < 2; i++){
			// Получаем выходной поток очередной стороны
			const view_t data = ((i == 0) ? client.output() : server.output());
			// Если стороне отправлять нечего
			if(data.size == 0)
				// Переходим к встречному направлению
				continue;
			// Переносим выходной поток, чтобы снять его с накопителя
			std::vector <uint8_t> buffer(data.data, data.data + data.size);
			// Снимаем выходной поток с накопителя его стороны
			if(i == 0)
				// Снимаем выходной поток клиента
				client.consume(buffer.size());
			else
				// Снимаем выходной поток сервера
				server.consume(buffer.size());
			// Если в этом круге заказана порча потока
			if(((settings.flags & DAMAGE) != 0) && !damaged && (round == settings.special)){
				// Портим выбранный байт выходного потока
				buffer[settings.offset % buffer.size()] ^= 0x01;
				// Запоминаем, что порча уже выполнена
				damaged = true;
			}
			/**
			 * Выполняем подачу потока кусками заданной длины
			 */
			for(size_t offset = 0; offset < buffer.size(); offset += settings.chunk){
				// Определяем длину очередного куска
				const size_t size = std::min(settings.chunk, buffer.size() - offset);
				// Подаём кусок встречной стороне
				if(i == 0)
					// Подаём кусок клиента серверу
					server.push(view_t(buffer.data() + offset, size));
				else
					// Подаём кусок сервера клиенту
					client.push(view_t(buffer.data() + offset, size));
			}
			// Запоминаем передачу выходного потока
			moved = true;
		}
		// Выводим признак передачи потоков
		return moved;
	}
	/**
	 * @brief Функция проведения потокового рукопожатия A-NTS с управляемыми повреждениями
	 *
	 * @param client   связь стороны клиента
	 * @param server   связь стороны сервера
	 * @param settings настройки переноса сценария
	 *
	 */
	void converseStream(client::context_t & client, server::context_t & server, const settings_t & settings) noexcept {
		// Сохраняем первое приветствие клиента для повторной подачи
		const view_t greeting = client.output();
		// Переносим приветствие до снятия его с накопителя, если оно уже выдано
		const std::vector <uint8_t> repeated = ((greeting.size > 0) ? std::vector <uint8_t> (greeting.data, greeting.data + greeting.size) : std::vector <uint8_t> ());
		// Признак уже выполненной порчи
		bool damaged = false;
		/**
		 * Выполняем передачу потоков ограниченное число кругов
		 */
		for(size_t round = 0; round < 16; round++){
			// Если связь одной из сторон оборвана
			if((client.state() == context::state_t::FAILED) || (server.state() == context::state_t::FAILED))
				// Прекращаем перенос
				break;
			// Если заказан намеренный обрыв на этом круге
			if(((settings.flags & TRUNCATE) != 0) && (round == settings.stop))
				// Прекращаем перенос без завершения рукопожатия
				break;
			// Если заказана повторная подача первого приветствия
			if(((settings.flags & REORDER) != 0) && (round == settings.special) && !repeated.empty())
				// Подаём сохранённое приветствие повторно
				server.push(view_t(repeated.data(), repeated.size()));
			// Если потоки на этом круге не переносились
			if(!pumpStream(client, server, settings, round, damaged))
				// Прекращаем перенос
				break;
		}
	}
	/**
	 * @brief Функция передачи дейтаграмм одного направления A-NTS
	 *
	 * @param from      отправляющая сторона
	 * @param to        принимающая сторона
	 * @param settings  настройки переноса сценария
	 * @param round     номер текущего круга
	 * @param direction направление переноса для счётчика
	 * @param counters  счётчики дейтаграмм направлений
	 * @param damaged   признак уже выполненной порчи
	 * @return          признак снятия хотя бы одной дейтаграммы
	 *
	 */
	template <typename A, typename B>
	bool carry(A & from, B & to, const settings_t & settings, const size_t round, const size_t direction, size_t (& counters)[2], bool & damaged) noexcept {
		// Снятые дейтаграммы направления
		std::vector <std::vector <uint8_t>> datagrams;
		/**
		 * Выполняем снятие всех готовых дейтаграмм стороны
		 */
		while(from.output().size > 0){
			// Получаем очередную дейтаграмму
			const view_t data = from.output();
			// Переносим дейтаграмму в перечень
			datagrams.push_back(std::vector <uint8_t> (data.data, data.data + data.size));
			// Снимаем дейтаграмму с накопителя
			from.consume(data.size);
		}
		// Если переносить нечего
		if(datagrams.empty())
			// Выводим отсутствие переноса
			return false;
		// Если заказана перестановка дейтаграмм
		if((settings.flags & REORDER) != 0)
			// Переворачиваем порядок переноса
			std::reverse(datagrams.begin(), datagrams.end());
		/**
		 * Выполняем перебор снятых дейтаграмм
		 */
		for(size_t i = 0; i < datagrams.size(); i++){
			// Считаем дейтаграмму направления
			counters[direction]++;
			// Если заказана порча именно на этом круге
			if(((settings.flags & DAMAGE) != 0) && !damaged && (round == settings.special)){
				// Портим выбранный байт дейтаграммы
				datagrams[i][settings.offset % datagrams[i].size()] ^= 0x01;
				// Запоминаем, что порча уже выполнена
				damaged = true;
			}
			// Если дейтаграмма попадает в период потерь
			if(((settings.flags & LOSS) != 0) && ((counters[direction] % settings.period) == 0))
				// Пропускаем её, имитируя потерю переносом
				continue;
			// Подаём дейтаграмму принимающей стороне
			to.push(view_t(datagrams[i].data(), datagrams[i].size()));
			// Если заказан повтор дейтаграммы
			if((settings.flags & DUPLICATE) != 0)
				// Подаём ту же дейтаграмму повторно
				to.push(view_t(datagrams[i].data(), datagrams[i].size()));
		}
		// Выводим признак снятия дейтаграмм
		return true;
	}
	/**
	 * @brief Функция проведения рукопожатия A-NTS поверх дейтаграмм
	 *
	 * @param client   связь стороны клиента
	 * @param server   связь стороны сервера
	 * @param settings настройки переноса сценария
	 *
	 */
	void converseDatagrams(client::context_t & client, server::context_t & server, const settings_t & settings) noexcept {
		// Счётчики дейтаграмм направлений
		size_t counters[2] = {0, 0};
		// Признак уже выполненной порчи
		bool damaged = false;
		/**
		 * Выполняем перенос дейтаграмм и ход часов ограниченное число кругов
		 */
		for(size_t round = 0; round < 64; round++){
			// Если связь одной из сторон оборвана
			if((client.state() == context::state_t::FAILED) || (server.state() == context::state_t::FAILED))
				// Прекращаем перенос
				break;
			// Если заказан намеренный обрыв на этом круге
			if(((settings.flags & TRUNCATE) != 0) && (round == settings.stop))
				// Прекращаем перенос без завершения рукопожатия
				break;
			// Переносим дейтаграммы клиента серверу
			bool moved = carry(client, server, settings, round, 0, counters, damaged);
			// Переносим дейтаграммы сервера клиенту
			moved = (carry(server, client, settings, round, 1, counters, damaged) || moved);
			// Если дейтаграммы переносились
			if(moved)
				// Переходим к следующему кругу
				continue;
			// Признак срабатывания часов ожидания
			bool fired = false;
			// Если клиент ждёт повторной передачи
			if(client.timeout() > 0){
				// Извещаем клиента об истечении срока
				client.elapsed();
				// Запоминаем ход часов
				fired = true;
			}
			// Если сервер ждёт повторной передачи
			if(server.timeout() > 0){
				// Извещаем сервера об истечении срока
				server.elapsed();
				// Запоминаем ход часов
				fired = true;
			}
			// Если ожидание закончилось
			if(!fired)
				// Прекращаем перенос
				break;
		}
	}
	/**
	 * @brief Функция проведения связи A-NTS выбранным переносом
	 *
	 * @param client   связь стороны клиента
	 * @param server   связь стороны сервера
	 * @param settings настройки переноса сценария
	 * @param datagram признак переноса дейтаграммами
	 *
	 */
	void converse(client::context_t & client, server::context_t & server, const settings_t & settings, const bool datagram) noexcept {
		// Если выбран перенос дейтаграммами
		if(datagram)
			// Проводим связь поверх дейтаграмм
			converseDatagrams(client, server, settings);
		else
			// Проводим связь поверх потока
			converseStream(client, server, settings);
	}
	/**
	 * @brief Функция прикладного обмена A-NTS в обе стороны
	 *
	 * @param client   связь стороны клиента
	 * @param server   связь стороны сервера
	 * @param payload  данные, отправляемые клиентом
	 * @param settings настройки переноса сценария
	 * @param datagram признак переноса дейтаграммами
	 * @return         признак получения обоих сообщений без искажения
	 *
	 */
	bool exchange(client::context_t & client, server::context_t & server, const view_t & payload, const settings_t & settings, const bool datagram) noexcept {
		// Ответ сервера контрольного обмена
		static const uint8_t RESPONSE[] = {'p', 'o', 'n', 'g'};
		// Отправляем данные клиента
		if(client.write(payload) != context::error_t::NONE)
			// Выводим отказ отправки
			return false;
		// Отправляем ответ сервера
		if(server.write(view_t(RESPONSE, sizeof(RESPONSE))) != context::error_t::NONE)
			// Выводим отказ отправки
			return false;
		// Переносим прикладные записи
		converse(client, server, settings, datagram);
		// Принятые данные направлений
		std::vector <uint8_t> request, response;
		// Если сервер не принял данные клиента без искажения
		if((server.read(request) != context::error_t::NONE) || (request.size() != payload.size) || (::memcmp(request.data(), payload.data, payload.size) != 0))
			// Выводим нарушение обмена
			return false;
		// Если клиент не принял ответ сервера без искажения
		if((client.read(response) != context::error_t::NONE) || (response.size() != sizeof(RESPONSE)) || (::memcmp(response.data(), RESPONSE, sizeof(RESPONSE)) != 0))
			// Выводим нарушение обмена
			return false;
		// Выводим успешность обмена
		return true;
	}
	/**
	 * Сторона связи эталона с накопителями переноса
	 */
	typedef class Secure {
		public:
			// Связь стороны эталона
			SSL * ssl;
			// Накопитель входящего переноса стороны
			channel_t * reading;
			// Накопитель исходящего переноса стороны
			channel_t * writing;
			// Принятые прикладные данные стороны
			std::vector <uint8_t> received;
			// Признак отказа связи эталона
			bool failed;
			// Признак получения извещения о закрытии
			bool closed;
		public:
			/**
			 * @brief Конструктор
			 *
			 */
			Secure() noexcept : ssl(nullptr), reading(nullptr), writing(nullptr), failed(false), closed(false) {}
			/**
			 * @brief Деструктор
			 *
			 */
			~Secure() noexcept {
				// Если связь стороны эталона создана
				if(this->ssl != nullptr)
					// Освобождаем связь вместе с накопителями переноса
					SSL_free(this->ssl);
			}
	} secure_t;
	/**
	 * Билет возобновления эталона со счётом ссылок
	 */
	typedef class Session {
		public:
			// Билет возобновления эталона
			SSL_SESSION * value;
		public:
			/**
			 * @brief Конструктор
			 *
			 */
			Session() noexcept : value(nullptr) {}
			/**
			 * @brief Деструктор
			 *
			 */
			~Session() noexcept {
				// Если билет возобновления получен
				if(this->value != nullptr)
					// Освобождаем свою ссылку на билет
					SSL_SESSION_free(this->value);
			}
	} session_t;
	/**
	 * @brief Функция настройки переносов и сторон эталона сличения
	 *
	 * @return признак готовности эталона к сличению
	 *
	 */
	bool arrange() noexcept {
		// Если подлинность из ключей набора составить не удалось
		if(!keyfile(credentials))
			// Выводим отказ настройки
			return false;
		// Составляем потоковый способ переноса эталона
		methods[0] = bioMethod(false);
		// Составляем дейтаграммный способ переноса эталона
		methods[1] = bioMethod(true);
		// Если способы переноса составить не удалось
		if((methods[0] == nullptr) || (methods[1] == nullptr))
			// Выводим отказ настройки
			return false;
		// Путь к сертификату подлинности эталона
		const std::string certificate = std::string(CORPUS) + "/ec256.crt";
		// Путь к секретному ключу подлинности эталона
		const std::string secret = std::string(CORPUS) + "/ec256.pem";
		// Метка области возобновляемых сеансов сервера
		static const uint8_t LABEL[] = {'a', 'n', 't', 's'};
		/**
		 * Выполняем настройку потокового и дейтаграммного переносов
		 */
		for(size_t datagram = 0; datagram < 2; datagram++){
			// Способ связи клиента эталона
			const SSL_METHOD * clientMethod = (datagram != 0 ? DTLS_client_method() : TLS_client_method());
			// Способ связи сервера эталона
			const SSL_METHOD * serverMethod = (datagram != 0 ? DTLS_server_method() : TLS_server_method());
			// Заводим настройку клиента эталона
			clients[datagram] = SSL_CTX_new(clientMethod);
			// Заводим настройку сервера эталона
			servers[datagram] = SSL_CTX_new(serverMethod);
			// Если настройки сторон завести не удалось
			if((clients[datagram] == nullptr) || (servers[datagram] == nullptr))
				// Выводим отказ настройки
				return false;
			// Зажимаем нижнее издание клиента эталона
			if(SSL_CTX_set_min_proto_version(clients[datagram], datagram != 0 ? DTLS1_2_VERSION : TLS1_3_VERSION) != 1)
				// Выводим отказ настройки
				return false;
			// Зажимаем верхнее издание клиента эталона
			if(SSL_CTX_set_max_proto_version(clients[datagram], datagram != 0 ? DTLS1_2_VERSION : TLS1_3_VERSION) != 1)
				// Выводим отказ настройки
				return false;
			// Зажимаем нижнее издание сервера эталона
			if(SSL_CTX_set_min_proto_version(servers[datagram], datagram != 0 ? DTLS1_2_VERSION : TLS1_3_VERSION) != 1)
				// Выводим отказ настройки
				return false;
			// Зажимаем верхнее издание сервера эталона
			if(SSL_CTX_set_max_proto_version(servers[datagram], datagram != 0 ? DTLS1_2_VERSION : TLS1_3_VERSION) != 1)
				// Выводим отказ настройки
				return false;
			// Отключаем проверку цепочки клиента: подлинность сличается по ключу
			SSL_CTX_set_verify(clients[datagram], SSL_VERIFY_NONE, nullptr);
			// Отключаем запрос сертификата у клиента эталона
			SSL_CTX_set_verify(servers[datagram], SSL_VERIFY_NONE, nullptr);
			// Назначаем метку области возобновляемых сеансов сервера
			if(SSL_CTX_set_session_id_context(servers[datagram], LABEL, sizeof(LABEL)) != 1)
				// Выводим отказ настройки
				return false;
			// Подключаем сертификат подлинности к серверу эталона
			if(SSL_CTX_use_certificate_chain_file(servers[datagram], certificate.c_str()) != 1)
				// Выводим отказ настройки
				return false;
			// Подключаем секретный ключ подлинности к серверу эталона
			if(SSL_CTX_use_PrivateKey_file(servers[datagram], secret.c_str(), SSL_FILETYPE_PEM) != 1)
				// Выводим отказ настройки
				return false;
			// Если ключ не подходит сертификату сервера эталона
			if(SSL_CTX_check_private_key(servers[datagram]) != 1)
				// Выводим отказ настройки
				return false;
			// Если выбран потоковый перенос
			if(datagram == 0)
				// Отключаем самовольную выдачу билетов: их заказывает стадия возобновления
				(void) SSL_CTX_set_num_tickets(servers[datagram], 0);
		}
		// Выводим успешность настройки эталона
		return true;
	}
	/**
	 * @brief Функция заведения стороны эталона с накопителями переноса
	 *
	 * @param peer      заводимая сторона эталона
	 * @param context   настройка стороны эталона
	 * @param datagram  признак переноса дейтаграммами
	 * @param client    признак стороны клиента
	 * @param mtu       размер дейтаграммы
	 * @param session   билет возобновления для стороны клиента либо пустота
	 * @return          признак успешности заведения стороны
	 *
	 */
	bool start(secure_t & peer, SSL_CTX * context, const bool datagram, const bool client, const size_t mtu, SSL_SESSION * session) noexcept {
		// Заводим связь стороны эталона
		peer.ssl = SSL_new(context);
		// Если связь завести не удалось
		if(peer.ssl == nullptr)
			// Выводим отказ заведения
			return false;
		// Заводим накопитель входящего переноса стороны
		BIO * reading = BIO_new(methods[datagram ? 1 : 0]);
		// Если накопитель входящего переноса завести не удалось
		if(reading == nullptr)
			// Выводим отказ заведения
			return false;
		// Заводим накопитель исходящего переноса стороны
		BIO * writing = BIO_new(methods[datagram ? 1 : 0]);
		// Если накопитель исходящего переноса завести не удалось
		if(writing == nullptr){
			// Освобождаем накопитель входящего переноса
			BIO_free(reading);
			// Выводим отказ заведения
			return false;
		}
		// Получаем накопитель входящего переноса стороны
		channel_t * incoming = static_cast <channel_t *> (BIO_get_data(reading));
		// Получаем накопитель исходящего переноса стороны
		channel_t * outgoing = static_cast <channel_t *> (BIO_get_data(writing));
		// Помечаем накопители выбранным переносом
		incoming->datagram = outgoing->datagram = datagram;
		// Ограничиваем размер дейтаграмм обоих накопителей
		incoming->mtu = outgoing->mtu = mtu;
		// Присоединяем накопители переноса к связи стороны
		SSL_set_bio(peer.ssl, reading, writing);
		// Запоминаем накопитель входящего переноса стороны
		peer.reading = incoming;
		// Запоминаем накопитель исходящего переноса стороны
		peer.writing = outgoing;
		// Если стороне передан билет возобновления
		if(session != nullptr){
			// Принимаем билет возобновления стороной клиента
			if(SSL_set_session(peer.ssl, session) != 1)
				// Выводим отказ заведения
				return false;
		}
		// Если заводится сторона клиента
		if(client)
			// Помечаем связь стороной клиента
			SSL_set_connect_state(peer.ssl);
		else
			// Помечаем связь стороной сервера
			SSL_set_accept_state(peer.ssl);
		// Если выбран перенос дейтаграммами
		if(datagram){
			// Подменяем часы таймеров связи виртуальными часами сличителя
			DTLS_set_timer_cb(peer.ssl, timerClock);
			// Если размер дейтаграммы установить не удалось: вызов возвращает установленный размер
			if(SSL_set_mtu(peer.ssl, static_cast <int> (mtu)) < 1)
				// Выводим отказ заведения
				return false;
		}
		// Выводим успешность заведения стороны
		return true;
	}
	/**
	 * @brief Функция разбора итога операции стороны эталона
	 *
	 * @param peer   сторона эталона, выполнившая операцию
	 * @param result итог операции стороны эталона
	 * @return       признак продолжения связи без отказа
	 *
	 */
	bool diagnose(secure_t & peer, const int result) noexcept {
		// Код отказа операции стороны эталона
		const int error = SSL_get_error(peer.ssl, result);
		// Если операция ждёт чтения либо записи
		if((error == SSL_ERROR_WANT_READ) || (error == SSL_ERROR_WANT_WRITE))
			// Выводим продолжение связи
			return true;
		// Если связь получила извещение о закрытии
		if(error == SSL_ERROR_ZERO_RETURN){
			// Помечаем получение извещения о закрытии
			peer.closed = true;
			// Выводим продолжение без прикладных данных
			return true;
		}
		// Помечаем отказ связи эталона
		peer.failed = true;
		// Выводим отказ связи
		return false;
	}
	/**
	 * @brief Функция продвижения стороны эталона по рукопожатию и чтению
	 *
	 * @param peer сторона эталона
	 * @return     признак продолжения связи без отказа
	 *
	 */
	bool drive(secure_t & peer) noexcept {
		// Если связь стороны уже отказала
		if(peer.failed)
			// Выводим отказ связи
			return false;
		// Если рукопожатие стороны ещё не закончено
		if(SSL_is_init_finished(peer.ssl) != 1){
			// Выполняем очередной шаг рукопожатия стороны
			const int result = SSL_do_handshake(peer.ssl);
			// Если шаг рукопожатия не завершился
			if(result != 1)
				// Выводим разбор итога шага рукопожатия
				return diagnose(peer, result);
			// Выводим продолжение связи
			return true;
		}
		// Место чтения прикладных данных стороны
		uint8_t buffer[0x1000];
		/**
		 * Выполняем чтение всех готовых прикладных данных и сообщений после рукопожатия
		 */
		while(true){
			// Читаем очередную порцию данных стороны
			const int result = SSL_read(peer.ssl, buffer, sizeof(buffer));
			// Если порция данных получена
			if(result > 0){
				// Присоединяем порцию к принятым данным стороны
				peer.received.insert(peer.received.end(), buffer, buffer + result);
				// Переходим к чтению следующей порции
				continue;
			}
			// Выводим разбор итога чтения
			return diagnose(peer, result);
		}
	}
	/**
	 * @brief Функция передачи переноса одного направления эталона
	 *
	 * @param from      отдающая сторона эталона
	 * @param to        принимающая сторона эталона
	 * @param settings  настройки переноса сценария
	 * @param round     номер текущего круга
	 * @param direction направление переноса для счётчика
	 * @param counters  счётчики дейтаграмм направлений
	 * @param damaged   признак уже выполненной порчи
	 * @return          признак переноса хотя бы одного байта либо дейтаграммы
	 *
	 */
	bool transfer(secure_t & from, secure_t & to, const settings_t & settings, const size_t round, const size_t direction, size_t (& counters)[2], bool & damaged) noexcept {
		// Если перенос идёт дейтаграммами
		if(from.writing->datagram){
			// Снятые дейтаграммы направления
			std::vector <std::vector <uint8_t>> datagrams;
			/**
			 * Выполняем снятие всех готовых дейтаграмм стороны
			 */
			while(!from.writing->packets.empty()){
				// Переносим очередную дейтаграмму в перечень
				datagrams.push_back(std::move(from.writing->packets.front()));
				// Снимаем дейтаграмму с очереди стороны
				from.writing->packets.pop_front();
			}
			// Если переносить нечего
			if(datagrams.empty())
				// Выводим отсутствие переноса
				return false;
			// Если заказана перестановка дейтаграмм
			if((settings.flags & REORDER) != 0)
				// Переворачиваем порядок переноса
				std::reverse(datagrams.begin(), datagrams.end());
			/**
			 * Выполняем перебор снятых дейтаграмм
			 */
			for(size_t i = 0; i < datagrams.size(); i++){
				// Считаем дейтаграмму направления
				counters[direction]++;
				// Если заказана порча именно на этом круге
				if(((settings.flags & DAMAGE) != 0) && !damaged && (round == settings.special)){
					// Портим выбранный байт дейтаграммы
					datagrams[i][settings.offset % datagrams[i].size()] ^= 0x01;
					// Запоминаем, что порча уже выполнена
					damaged = true;
				}
				// Если дейтаграмма попадает в период потерь
				if(((settings.flags & LOSS) != 0) && ((counters[direction] % settings.period) == 0))
					// Пропускаем её, имитируя потерю переносом
					continue;
				// Подаём дейтаграмму принимающей стороне
				to.reading->packets.push_back(datagrams[i]);
				// Если заказан повтор дейтаграммы
				if((settings.flags & DUPLICATE) != 0)
					// Подаём ту же дейтаграмму повторно
					to.reading->packets.push_back(datagrams[i]);
			}
			// Выводим признак снятия дейтаграмм
			return true;
		}
		// Если готового потока нет
		if(from.writing->stream.empty())
			// Выводим отсутствие переноса
			return false;
		// Переносим выходной поток стороны в рабочий перечень
		std::vector <uint8_t> buffer;
		// Снимаем выходной поток с накопителя стороны
		buffer.swap(from.writing->stream);
		// Если в этом круге заказана порча потока
		if(((settings.flags & DAMAGE) != 0) && !damaged && (round == settings.special)){
			// Портим выбранный байт выходного потока
			buffer[settings.offset % buffer.size()] ^= 0x01;
			// Запоминаем, что порча уже выполнена
			damaged = true;
		}
		// Подаём поток принимающей стороне целиком: нарезка проверяется подачей в A-NTS
		to.reading->stream.insert(to.reading->stream.end(), buffer.begin(), buffer.end());
		// Выводим признак передачи потока
		return true;
	}
	/**
	 * @brief Функция проведения связи эталона выбранным переносом
	 *
	 * @param client   сторона клиента эталона
	 * @param server   сторона сервера эталона
	 * @param settings настройки переноса сценария
	 * @param datagram признак переноса дейтаграммами
	 *
	 */
	void converse(secure_t & client, secure_t & server, const settings_t & settings, const bool datagram) noexcept {
		// Счётчики дейтаграмм направлений
		size_t counters[2] = {0, 0};
		// Признак уже выполненной порчи
		bool damaged = false;
		// Сохранённое первое приветствие клиента для повторной подачи
		std::vector <uint8_t> repeated;
		/**
		 * Выполняем продвижение сторон и перенос ограниченное число кругов
		 */
		for(size_t round = 0; round < (datagram ? 64 : 16); round++){
			// Если связь одной из сторон отказала
			if(client.failed || server.failed)
				// Прекращаем перенос
				break;
			// Если заказан намеренный обрыв на этом круге
			if(((settings.flags & TRUNCATE) != 0) && (round == settings.stop))
				// Прекращаем перенос без завершения рукопожатия
				break;
			// Продвигаем клиента эталона по рукопожатию либо чтению
			const bool liveClient = drive(client);
			// Продвигаем сервер эталона по рукопожатию либо чтению
			const bool liveServer = drive(server);
			// Если одна из сторон отказала
			if(!liveClient || !liveServer)
				// Прекращаем перенос
				break;
			// Если это первый круг потокового переноса
			if((round == 0) && !datagram)
				// Сохраняем первое приветствие клиента для повторной подачи
				repeated.assign(client.writing->stream.begin(), client.writing->stream.end());
			// Если заказана повторная подача первого приветствия
			if(((settings.flags & REORDER) != 0) && !datagram && (round == settings.special) && !repeated.empty())
				// Подаём сохранённое приветствие повторно
				server.reading->stream.insert(server.reading->stream.end(), repeated.begin(), repeated.end());
			// Переносим исходящий перенос клиента серверу
			bool moved = transfer(client, server, settings, round, 0, counters, damaged);
			// Переносим исходящий перенос сервера клиенту
			moved = (transfer(server, client, settings, round, 1, counters, damaged) || moved);
			// Если перенос перемещался
			if(moved)
				// Переходим к следующему кругу
				continue;
			// Если выбран перенос дейтаграммами
			if(datagram){
				// Признак срабатывания часов ожидания
				bool fired = false;
				// Срок очередного ожидания клиента эталона
				struct timeval slice;
				// Если клиент ждёт повторной передачи
				if(DTLSv1_get_timeout(client.ssl, &slice) == 1){
					// Если срок ожидания клиента ещё не истёк
					if((slice.tv_sec != 0) || (slice.tv_usec != 0))
						// Дожидаемся оставшегося срока ожидания клиента
						::usleep(static_cast <useconds_t> ((slice.tv_sec * 1000000) + slice.tv_usec + 1000));
					// Извещаем клиента об истечении срока
					const int repeated = DTLSv1_handle_timeout(client.ssl);
					// Если повторная передача клиента не удалась
					if(repeated < 0)
						// Помечаем отказ клиента эталона
						client.failed = true;
					// Если клиент повторил передачу
					if(repeated == 1)
						// Запоминаем ход часов
						fired = true;
				}
				// Если сервер ждёт повторной передачи
				if(DTLSv1_get_timeout(server.ssl, &slice) == 1){
					// Если срок ожидания сервера ещё не истёк
					if((slice.tv_sec != 0) || (slice.tv_usec != 0))
						// Дожидаемся оставшегося срока ожидания сервера
						::usleep(static_cast <useconds_t> ((slice.tv_sec * 1000000) + slice.tv_usec + 1000));
					// Извещаем сервера об истечении срока
					const int repeated = DTLSv1_handle_timeout(server.ssl);
					// Если повторная передача сервера не удалась
					if(repeated < 0)
						// Помечаем отказ сервера эталона
						server.failed = true;
					// Если сервер повторил передачу
					if(repeated == 1)
						// Запоминаем ход часов
						fired = true;
				}
				// Если ожидание сработало
				if(fired)
					// Переходим к следующему кругу
					continue;
			}
			// Прекращаем перенос
			break;
		}
	}
	/**
	 * @brief Функция прикладного обмена эталона в обе стороны
	 *
	 * @param client   сторона клиента эталона
	 * @param server   сторона сервера эталона
	 * @param payload  данные, отправляемые клиентом
	 * @param settings настройки переноса сценария
	 * @param datagram признак переноса дейтаграммами
	 * @return         признак получения обоих сообщений без искажения
	 *
	 */
	bool exchange(secure_t & client, secure_t & server, const view_t & payload, const settings_t & settings, const bool datagram) noexcept {
		// Ответ сервера контрольного обмена
		static const uint8_t RESPONSE[] = {'p', 'o', 'n', 'g'};
		// Очищаем принятые данные клиента
		client.received.clear();
		// Очищаем принятые данные сервера
		server.received.clear();
		// Отправляем данные клиента эталона
		if(SSL_write(client.ssl, payload.data, static_cast <int> (payload.size)) != static_cast <int> (payload.size))
			// Выводим отказ отправки
			return false;
		// Отправляем ответ сервера эталона
		if(SSL_write(server.ssl, RESPONSE, sizeof(RESPONSE)) != static_cast <int> (sizeof(RESPONSE)))
			// Выводим отказ отправки
			return false;
		// Переносим прикладные записи
		converse(client, server, settings, datagram);
		// Если сервер не принял данные клиента без искажения
		if(server.failed || (server.received.size() != payload.size) || (::memcmp(server.received.data(), payload.data, payload.size) != 0))
			// Выводим нарушение обмена
			return false;
		// Если клиент не принял ответ сервера без искажения
		if(client.failed || (client.received.size() != sizeof(RESPONSE)) || (::memcmp(client.received.data(), RESPONSE, sizeof(RESPONSE)) != 0))
			// Выводим нарушение обмена
			return false;
		// Выводим успешность обмена
		return true;
	}
	/**
	 * @brief Функция выполнения одного сценария машинами состояний A-NTS
	 *
	 * @param payload  данные прикладного обмена
	 * @param settings настройки переноса сценария
	 * @param datagram признак переноса дейтаграммами
	 * @return         разряды итога выполненных стадий сценария
	 *
	 */
	uint8_t run(const view_t & payload, const settings_t & settings, const bool datagram) noexcept {
		// Связь стороны клиента
		client::context_t client;
		// Связь стороны сервера
		server::context_t server;
		// Настраиваем стороны выбранным переносом
		configure(client, server, datagram, settings.mtu);
		// Заводим сервер
		if(server.start() != context::error_t::NONE)
			// Выводим отсутствие итога
			return 0;
		// Заводим клиента
		if(client.start() != context::error_t::NONE)
			// Выводим отсутствие итога
			return 0;
		// Проводим начальное рукопожатие
		converse(client, server, settings, datagram);
		// Если рукопожатие не установилось
		if(!client.established() || !server.established())
			// Выводим итог без установления
			return 0;
		// Разряды итога выполненных стадий
		uint8_t stages = ESTABLISHED;
		// Чистые настройки для стадий после рукопожатия
		settings_t clean = settings;
		// Снимаем управляющие разряды повреждений
		clean.flags = 0;
		// Если заказано возобновление
		if((settings.flags & RESUME) != 0){
			// Если выбран потоковый перенос
			if(!datagram){
				// Выдаём билет возобновления
				if(server.issue() != context::error_t::NONE)
					// Выводим итог без возобновления
					return stages;
				// Доставляем билет клиенту
				converse(client, server, clean, datagram);
			}
			// Если клиент билета не получил
			if(client.tickets().empty())
				// Выводим итог без возобновления
				return stages;
			// Связь клиента нового возобновления
			client::context_t resuming;
			// Связь сервера нового возобновления
			server::context_t resumed;
			// Настраиваем новые стороны тем же переносом
			configure(resuming, resumed, datagram, settings.mtu);
			// Передаём клиенту билет прежней связи
			resuming.resume(client.tickets()[0]);
			// Передаём серверу признаваемые им билеты
			resumed.resume(server.tickets());
			// Заводим сервер возобновления
			if(resumed.start() != context::error_t::NONE)
				// Выводим итог без возобновления
				return stages;
			// Заводим клиента возобновления
			if(resuming.start() != context::error_t::NONE)
				// Выводим итог без возобновления
				return stages;
			// Проводим возобновление сторон
			converse(resuming, resumed, clean, datagram);
			// Если возобновление не подтверждено обеими сторонами
			if(!resuming.established() || !resumed.established() || !resuming.shared() || !resumed.shared())
				// Выводим итог без возобновления
				return stages;
			// Если прикладной обмен возобновлённой связи не удался
			if(!exchange(resuming, resumed, payload, clean, datagram))
				// Выводим итог без возобновления
				return stages;
			// Помечаем выполненное возобновление
			stages |= RESUMED;
		}
		// Если потоковому клиенту заказана смена ключей
		if(!datagram && ((settings.flags & CLIENT_UPDATE) != 0)){
			// Запрашиваем смену ключей клиентом
			if(client.update(true) != context::error_t::NONE)
				// Выводим итог без смены ключей
				return stages;
			// Доставляем смену ключей клиента
			converse(client, server, clean, datagram);
		}
		// Если потоковому серверу заказана смена ключей
		if(!datagram && ((settings.flags & SERVER_UPDATE) != 0)){
			// Запрашиваем смену ключей сервером
			if(server.update(true) != context::error_t::NONE)
				// Выводим итог без смены ключей
				return stages;
			// Доставляем смену ключей сервера
			converse(client, server, clean, datagram);
		}
		// Если заказана хоть одна смена ключей потокового переноса
		if(!datagram && ((settings.flags & (CLIENT_UPDATE | SERVER_UPDATE)) != 0)){
			// Если связь одной из сторон оборвалась
			if((client.state() == context::state_t::FAILED) || (server.state() == context::state_t::FAILED))
				// Выводим итог без смены ключей
				return stages;
			// Помечаем доставленные смены ключей
			stages |= UPDATED;
		}
		// Если прикладной обмен после всех стадий не удался
		if(!exchange(client, server, payload, clean, datagram))
			// Выводим итог без обмена
			return stages;
		// Помечаем выполненный прикладной обмен
		stages |= EXCHANGED;
		// Если заказано закрытие связи
		if((settings.flags & CLOSE) != 0){
			// Закрываем связь клиентом
			if(client.close() != context::error_t::NONE)
				// Выводим итог без закрытия
				return stages;
			// Доставляем извещение о закрытии
			converse(client, server, clean, datagram);
			// Если сервер не подтвердил закрытие
			if(server.state() != context::state_t::CLOSED)
				// Выводим итог без закрытия
				return stages;
			// Помечаем выполненное закрытие
			stages |= CLOSED;
		}
		// Выводим разряды итога сценария
		return stages;
	}
	/**
	 * @brief Функция выполнения одного сценария машинами состояний эталона
	 *
	 * @param payload  данные прикладного обмена
	 * @param settings настройки переноса сценария
	 * @param datagram признак переноса дейтаграммами
	 * @return         разряды итога выполненных стадий сценария
	 *
	 */
	uint8_t runSecure(const view_t & payload, const settings_t & settings, const bool datagram) noexcept {
		// Очищаем очередь ошибок эталона от прежних сценариев
		ERR_clear_error();
		// Сторона клиента эталона
		secure_t client;
		// Сторона сервера эталона
		secure_t server;
		// Заводим сервер эталона
		if(!start(server, servers[datagram ? 1 : 0], datagram, false, settings.mtu, nullptr))
			// Выводим отсутствие итога
			return 0;
		// Заводим клиента эталона
		if(!start(client, clients[datagram ? 1 : 0], datagram, true, settings.mtu, nullptr))
			// Выводим отсутствие итога
			return 0;
		// Проводим начальное рукопожатие
		converse(client, server, settings, datagram);
		// Если рукопожатие не установилось
		if(client.failed || server.failed || (SSL_is_init_finished(client.ssl) != 1) || (SSL_is_init_finished(server.ssl) != 1))
			// Выводим итог без установления
			return 0;
		// Разряды итога выполненных стадий
		uint8_t stages = ESTABLISHED;
		// Чистые настройки для стадий после рукопожатия
		settings_t clean = settings;
		// Снимаем управляющие разряды повреждений
		clean.flags = 0;
		// Билет возобновления прежней связи эталона
		session_t session;
		// Если заказано возобновление
		if((settings.flags & RESUME) != 0){
			// Если выбран потоковый перенос
			if(!datagram){
				// Заказываем выдачу билета возобновления
				if(SSL_new_session_ticket(server.ssl) != 1)
					// Выводим итог без возобновления
					return stages;
				// Доставляем билет клиенту
				converse(client, server, clean, datagram);
			}
			// Забираем билет возобновления у клиента эталона
			session.value = SSL_get1_session(client.ssl);
			// Если билет возобновления получить не удалось
			if(session.value == nullptr)
				// Выводим итог без возобновления
				return stages;
			// Сторона клиента нового возобновления
			secure_t resuming;
			// Сторона сервера нового возобновления
			secure_t resumed;
			// Заводим сервер возобновления
			if(!start(resumed, servers[datagram ? 1 : 0], datagram, false, settings.mtu, nullptr))
				// Выводим итог без возобновления
				return stages;
			// Заводим клиента возобновления с билетом прежней связи
			if(!start(resuming, clients[datagram ? 1 : 0], datagram, true, settings.mtu, session.value))
				// Выводим итог без возобновления
				return stages;
			// Проводим возобновление сторон
			converse(resuming, resumed, clean, datagram);
			// Если возобновление не подтверждено обеими сторонами
			if(resuming.failed || resumed.failed || (SSL_is_init_finished(resuming.ssl) != 1) || (SSL_is_init_finished(resumed.ssl) != 1) || (SSL_session_reused(resuming.ssl) != 1) || (SSL_session_reused(resumed.ssl) != 1))
				// Выводим итог без возобновления
				return stages;
			// Если прикладной обмен возобновлённой связи не удался
			if(!exchange(resuming, resumed, payload, clean, datagram))
				// Выводим итог без возобновления
				return stages;
			// Помечаем выполненное возобновление
			stages |= RESUMED;
		}
		// Если потоковому клиенту заказана смена ключей
		if(!datagram && ((settings.flags & CLIENT_UPDATE) != 0)){
			// Запрашиваем смену ключей клиентом
			if(SSL_key_update(client.ssl, SSL_KEY_UPDATE_REQUESTED) != 1)
				// Выводим итог без смены ключей
				return stages;
			// Доставляем смену ключей клиента
			converse(client, server, clean, datagram);
		}
		// Если потоковому серверу заказана смена ключей
		if(!datagram && ((settings.flags & SERVER_UPDATE) != 0)){
			// Запрашиваем смену ключей сервером
			if(SSL_key_update(server.ssl, SSL_KEY_UPDATE_REQUESTED) != 1)
				// Выводим итог без смены ключей
				return stages;
			// Доставляем смену ключей сервера
			converse(client, server, clean, datagram);
		}
		// Если заказана хоть одна смена ключей потокового переноса
		if(!datagram && ((settings.flags & (CLIENT_UPDATE | SERVER_UPDATE)) != 0)){
			// Если связь одной из сторон отказала
			if(client.failed || server.failed)
				// Выводим итог без смены ключей
				return stages;
			// Помечаем доставленные смены ключей
			stages |= UPDATED;
		}
		// Если прикладной обмен после всех стадий не удался
		if(!exchange(client, server, payload, clean, datagram))
			// Выводим итог без обмена
			return stages;
		// Помечаем выполненный прикладной обмен
		stages |= EXCHANGED;
		// Если заказано закрытие связи
		if((settings.flags & CLOSE) != 0){
			// Закрываем связь клиентом эталона
			if(SSL_shutdown(client.ssl) < 0)
				// Выводим итог без закрытия
				return stages;
			// Доставляем извещение о закрытии
			converse(client, server, clean, datagram);
			// Если сервер не получил извещение о закрытии
			if(!server.closed && ((SSL_get_shutdown(server.ssl) & SSL_RECEIVED_SHUTDOWN) == 0))
				// Выводим итог без закрытия
				return stages;
			// Помечаем выполненное закрытие
			stages |= CLOSED;
		}
		// Выводим разряды итога сценария
		return stages;
	}
}

/**
 * Поверхность вызова сличителя машин состояний
 */
extern "C" {
	/**
	 * @brief Функция подачи одного сценария обеим парам машин состояний
	 *
	 * @param data начало сценария
	 * @param size размер сценария
	 * @return     нулевой код продолжения ворошения
	 *
	 */
	int LLVMFuzzerTestOneInput(const uint8_t * data, const size_t size) noexcept {
		// Если подлинность и настройки эталона ещё не готовы
		if(!ready){
			// Составляем подлинность и настройки эталона один раз на процесс
			ready = arrange();
			// Если настройка не удалась, сличать бессмысленно
			if(!ready)
				// Останавливаем сличитель на отказе инициализации
				std::abort();
		}
		// Если сценарий короче управляющей части
		if(size < 9)
			// Продолжаем ворошение без выполнения сценария
			return 0;
		// Признак переноса дейтаграммами
		const bool datagram = ((data[0] & 0x01) != 0);
		// Настройки сценария из управляющих байтов
		settings_t settings;
		// Читаем управляющие разряды сценария
		settings.flags = static_cast <uint16_t> (data[2] | (static_cast <uint16_t> (data[3]) << 8));
		// Выбираем длину куска потока
		settings.chunk = (1 + (data[1] % 64));
		// Выбираем размер дейтаграммы в дозволенных пределах
		settings.mtu = (256 + (data[1] % 945));
		// Выбираем круг намеренного обрыва
		settings.stop = (data[4] % (datagram ? 64 : 16));
		// Выбираем круг повтора либо порчи
		settings.special = (data[5] % (datagram ? 64 : 16));
		// Выбираем период потерь дейтаграмм
		settings.period = (2 + (data[6] % 5));
		// Читаем смещение портимого байта
		settings.offset = (static_cast <size_t> (data[7]) | (static_cast <size_t> (data[8]) << 8));
		// Контрольный байт сценария без прикладных данных
		static const uint8_t FALLBACK = 0x42;
		// Определяем данные прикладного обмена
		const view_t payload = ((size > 9) ? view_t(data + 9, std::min(size - 9, static_cast <size_t> (256))) : view_t(&FALLBACK, 1));
		// Выполняем сценарий машинами состояний A-NTS
		const uint8_t ours = run(payload, settings, datagram);
		// Выполняем тот же сценарий машинами состояний эталона
		const uint8_t reference = runSecure(payload, settings, datagram);
		// Признак сценария с помехами, которым успех не обещан даже эталоном
		const bool disturbed = (((settings.flags & (TRUNCATE | REORDER | LOSS | DAMAGE)) != 0));
		// Ожидаемые разряды сценария без непредсказуемых помех переноса
		uint8_t expected = (ESTABLISHED | EXCHANGED);
		// Если заказано возобновление
		if((settings.flags & RESUME) != 0)
			// Ждём выполненного возобновления
			expected |= RESUMED;
		// Если заказано закрытие
		if((settings.flags & CLOSE) != 0)
			// Ждём выполненного закрытия
			expected |= CLOSED;
		// Если потоковому переносу заказана смена ключей
		if(!datagram && ((settings.flags & (CLIENT_UPDATE | SERVER_UPDATE)) != 0))
			// Ждём доставленной смены ключей
			expected |= UPDATED;
		// Если сценарий без непредсказуемых помех не выполнил обязательные стадии
		if(!disturbed && ((ours != expected) || (reference != expected))){
			// Сообщаем разряды итога сторон сличения
			::fprintf(stderr, "Differential stage failure: datagram=%d flags=%04x ours=%02x reference=%02x expected=%02x\n", datagram ? 1 : 0, settings.flags, ours, reference, expected);
			// Останавливаем сличитель на нарушении договора сценария
			std::abort();
		}
		// Если итоги одинакового сценария без непредсказуемых помех разошлись
		if(!disturbed && (ours != reference)){
			// Сообщаем разряды итога сторон сличения
			::fprintf(stderr, "Differential divergence: datagram=%d flags=%04x ours=%02x reference=%02x\n", datagram ? 1 : 0, settings.flags, ours, reference);
			// Печатаем сценарий для воспроизведения
			/**
			 * Выполняем перебор байтов сценария
			 */
			for(size_t i = 0; i < size; i++)
				// Печатаем очередной байт сценария
				::fprintf(stderr, "%02x", data[i]);
			// Завершаем строку сценария
			::fprintf(stderr, "\n");
			// Останавливаем сличитель на расхождении итогов
			std::abort();
		}
		// Выводим код продолжения ворошения
		return 0;
	}
}
