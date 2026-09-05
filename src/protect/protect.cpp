/**
 * @file protect.cpp
 * @date 2026-08-29
 *
 * @license{LicenseRef-A-NTS-1.0}
 *
 * @author Yuriy Lobarev
 *
 * @brief Исходный файл модуля защиты записей протокола TLS 1.3 наборами шифрования
 *        на алгоритмах ГОСТ и классическими наборами AES-GCM и ChaCha20-Poly1305
 *
 * @section Намеренные решения
 *
 * 1. Ключ записи вырабатывается заново лишь тогда, когда обрезанный постоянными
 *    порядковый номер изменился. Постоянные построения TLSTREE обрезают номер старшими
 *    разрядами, оттого у соседних записей обрезанный номер чаще всего один и тот же, а
 *    выработка ключа стоит шести хеширований. Итог от этого не меняется ни на байт.
 *
 * 2. Старший разряд одноразового значения гасится, а не отвергается вместе со всем
 *    вектором замены. Так велит раздел 4.1.1 описания наборов: разряд занят самим
 *    режимом MGM, а гашение единственного разряда вектора замены различия соседних
 *    записей не отменяет - номер записи занимает младшие восемь байтов.
 *
 * 3. Порядковый номер растёт лишь после успеха. Отказ снятия защиты смертелен для связи
 *    по разделу 5.2 RFC 8446, и продолжать приём после него всё равно не с чем.
 *
 * 4. Наложение защиты составляет целую запись вместе с заголовком. Заголовок служит
 *    связанными данными шифрования, и составить его обязан тот, кто накладывает защиту:
 *    иначе связанные данные и сама запись разъехались бы.
 *
 * 5. Классические наборы AES-GCM живут в том же объекте, что и наборы ГОСТ, и различаются
 *    лишь описанием набора: у них нет построения TLSTREE (ключ один на направление), вектор
 *    замены занимает двенадцать байтов, метка целостности - шестнадцать, а старший разряд
 *    одноразового значения не гасится (раздел 5.3 RFC 8446). Предел записей на одном ключе
 *    взят по разделу 5.5 RFC 8446: около 2^24,5 записей полной длины для AES-GCM.
 *
 * 6. Режим GCM заводится заново на всякую запись: примитив привязывает одноразовое значение
 *    при заведении, а оно у всякой записи своё. Таблица умножения при этом строится заново,
 *    и это плата за общность примитива, а не за протокол.
 *
 * 7. Набор ChaCha20-Poly1305 живёт тем же классическим путём, что и AES-GCM: одноразовое
 *    значение, связанные данные и предел длины у них общие (разделы 5.2 и 5.3 RFC 8446), а
 *    различие лишь в примитиве - AEAD берётся у chachapoly_t разовым вызовом на запись, и
 *    базовый блочный шифр ему не готовится вовсе. Предел записей на ключе взят в 2^62:
 *    раздел 5.5 RFC 8446 предела ChaCha20 не ставит (порядковый номер переполнится
 *    раньше), а недостижимый предел оставляет заслон номеров живым и не подпускает
 *    счётчик к переполнению.
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <new>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <digest/kdf.hpp>
#include <protect/protect.hpp>
#include <sys/wipe.hpp>

/**
 * Используем стандартное пространство имён
 */
using namespace std;

/**
 * @brief Внутренние служебные объекты
 *
 */
namespace {
	/**
	 * Пространство имён библиотеки
	 */
	using namespace nts;

	/**
	 * Пространство имён модуля
	 */
	using namespace nts::protect;

	/**
	 * Отказы модуля
	 */
	typedef protect::error_t error_t;

	/**
	 * Метки ярусов построения TLSTREE
	 */
	static const char * LEVELS[3] = {"level1", "level2", "level3"};

	/**
	 * Длина вектора замены наборов AES-GCM по разделу 5.3 RFC 8446
	 */
	static constexpr size_t CLASSIC_VECTOR = 12;

	/**
	 * Длина метки целостности наборов AES-GCM и ChaCha20-Poly1305
	 */
	static constexpr size_t CLASSIC_TAG = 16;

	/**
	 * Предел записей на одном ключе AES-GCM: около 2^24,5 по разделу 5.5 RFC 8446
	 */
	static constexpr uint64_t CLASSIC_LIMIT = 23726566ULL;

	/**
	 * Длина соли одноразового значения наборов AES-GCM издания TLS 1.2: раздел 3 RFC 5288
	 */
	static constexpr size_t LEGACY_SALT = 4;

	/**
	 * Длина явной части одноразового значения наборов AES-GCM издания TLS 1.2: раздел 3 RFC 5288
	 */
	static constexpr size_t LEGACY_EXPLICIT = 8;

	/**
	 * Длина связанных данных записи издания TLS 1.2: порядковый номер, вид содержимого,
	 * издание протокола и длина открытого содержимого (раздел 6.2.3.3 RFC 5246)
	 */
	static constexpr size_t LEGACY_ASSOCIATED = 13;

	/**
	 * Предел записей на одном ключе ChaCha20-Poly1305: 2^62, раздел 5.5 RFC 8446 предела
	 * не ставит, а недостижимый предел держит заслон номеров живым вдали от переполнения
	 */
	static constexpr uint64_t STREAM_LIMIT = 0x3FFFFFFFFFFFFFFFULL;

	/**
	 * @brief Описание набора шифрования
	 *
	 */
	static const struct Sample {
		// Набор шифрования
		suite_t suite;
		// Признак классического набора без построения TLSTREE
		bool classic;
		// Признак набора ChaCha20-Poly1305 без базового блочного шифра
		bool stream;
		// Постоянные обрезания порядкового номера по ярусам построения
		uint64_t masks[3];
		// Наибольший порядковый номер записи набора
		uint64_t limit;
		// Длина вектора замены набора
		size_t size;
		// Длина ключа набора
		size_t key;
		// Длина метки целостности записи набора
		size_t tag;
		// Хеш расписания ключей набора
		digest::hash_t hash;
		// Признак набора издания TLS 1.2 с защитой записей по разделу 6.2.3.3 RFC 5246
		bool legacy;
		// Алгоритм подписи, требуемый набором TLS 1.2 от сертификата
		signer_t signer;
	} SAMPLES[13] = {
		{suite_t::KUZNYECHIK_MGM_L,         false, false, {0xF800000000000000ULL, 0xFFFFFFF000000000ULL, 0xFFFFFFFFFFFFE000ULL}, 0xFFFFFFFFFFFFFFFFULL, 16, 32, 16, digest::hash_t::STREEBOG256, false, signer_t::NONE},
		{suite_t::MAGMA_MGM_L,              false, false, {0xFFE0000000000000ULL, 0xFFFFFFFFC0000000ULL, 0xFFFFFFFFFFFFFF80ULL}, 0xFFFFFFFFFFFFFFFFULL, 8,  32, 8,  digest::hash_t::STREEBOG256, false, signer_t::NONE},
		{suite_t::KUZNYECHIK_MGM_S,         false, false, {0xFFFFFFFFE0000000ULL, 0xFFFFFFFFFFFF0000ULL, 0xFFFFFFFFFFFFFFF8ULL}, 0x000003FFFFFFFFFFULL, 16, 32, 16, digest::hash_t::STREEBOG256, false, signer_t::NONE},
		{suite_t::MAGMA_MGM_S,              false, false, {0xFFFFFFFFFC000000ULL, 0xFFFFFFFFFFFFE000ULL, 0xFFFFFFFFFFFFFFFFULL}, 0x0000007FFFFFFFFFULL, 8,  32, 8,  digest::hash_t::STREEBOG256, false, signer_t::NONE},
		{suite_t::AES_128_GCM_SHA256,       true,  false, {0ULL, 0ULL, 0ULL}, CLASSIC_LIMIT, CLASSIC_VECTOR, 16, CLASSIC_TAG, digest::hash_t::SHA256, false, signer_t::NONE},
		{suite_t::AES_256_GCM_SHA384,       true,  false, {0ULL, 0ULL, 0ULL}, CLASSIC_LIMIT, CLASSIC_VECTOR, 32, CLASSIC_TAG, digest::hash_t::SHA384, false, signer_t::NONE},
		{suite_t::CHACHA20_POLY1305_SHA256, true,  true,  {0ULL, 0ULL, 0ULL}, STREAM_LIMIT,  CLASSIC_VECTOR, 32, CLASSIC_TAG, digest::hash_t::SHA256, false, signer_t::NONE},
		/**
		 * Наборы TLS 1.2 (RFC 5289, RFC 7905): у AES-GCM вектор замены занимает четыре байта
		 * соли (раздел 3 RFC 5288), у ChaCha20-Poly1305 - двенадцать (раздел 2 RFC 7905);
		 * предел записей взят недостижимым 2^62: смены ключей в TLS 1.2 нет, а раздел 6.1
		 * RFC 5246 лишь запрещает переполнение порядкового номера
		 */
		{suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256,       true, false, {0ULL, 0ULL, 0ULL}, STREAM_LIMIT, LEGACY_SALT,    16, CLASSIC_TAG, digest::hash_t::SHA256, true, signer_t::ECDSA},
		{suite_t::ECDHE_ECDSA_AES_256_GCM_SHA384,       true, false, {0ULL, 0ULL, 0ULL}, STREAM_LIMIT, LEGACY_SALT,    32, CLASSIC_TAG, digest::hash_t::SHA384, true, signer_t::ECDSA},
		{suite_t::ECDHE_RSA_AES_128_GCM_SHA256,         true, false, {0ULL, 0ULL, 0ULL}, STREAM_LIMIT, LEGACY_SALT,    16, CLASSIC_TAG, digest::hash_t::SHA256, true, signer_t::RSA},
		{suite_t::ECDHE_RSA_AES_256_GCM_SHA384,         true, false, {0ULL, 0ULL, 0ULL}, STREAM_LIMIT, LEGACY_SALT,    32, CLASSIC_TAG, digest::hash_t::SHA384, true, signer_t::RSA},
		{suite_t::ECDHE_RSA_CHACHA20_POLY1305_SHA256,   true, true,  {0ULL, 0ULL, 0ULL}, STREAM_LIMIT, CLASSIC_VECTOR, 32, CLASSIC_TAG, digest::hash_t::SHA256, true, signer_t::RSA},
		{suite_t::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256, true, true,  {0ULL, 0ULL, 0ULL}, STREAM_LIMIT, CLASSIC_VECTOR, 32, CLASSIC_TAG, digest::hash_t::SHA256, true, signer_t::ECDSA}
	};

	/**
	 * @brief Метод розыска описания набора шифрования
	 *
	 * @param suite разыскиваемый набор шифрования
	 *
	 * @return      описание набора шифрования либо nullptr у неизвестного набора
	 *
	 */
	static const Sample * search(const suite_t suite) noexcept {
		/**
		 * Выполняем перебор описаний наборов шифрования
		 */
		for(size_t i = 0; i < (sizeof(SAMPLES) / sizeof(SAMPLES[0])); i++){
			// Если описание набора шифрования найдено
			if(SAMPLES[i].suite == suite)
				// Выводим найденное описание набора шифрования
				return &SAMPLES[i];
		}
		// Выводим отсутствие описания набора шифрования
		return nullptr;
	}
	// Затирание областей памяти берётся из открытого API библиотеки
	using nts::sys::wipe;
	/**
	 * @brief Метод записи числа в сетевом порядке байтов
	 *
	 * @param value  записываемое число
	 * @param result место, в которое помещается запись числа
	 *
	 */
	static void number(const uint64_t value, uint8_t * result) noexcept {
		/**
		 * Выполняем перебор байтов записываемого числа
		 */
		for(size_t i = 0; i < 8; i++)
			// Записываем очередной байт числа от старшего к младшему
			result[i] = static_cast <uint8_t> ((value >> ((7 - i) * 8)) & 0xFF);
	}
};

/**
 * @brief Метод получения длины вектора замены набора шифрования
 *
 * @param suite набор шифрования
 *
 * @return      длина вектора замены в байтах, ноль у неизвестного набора
 *
 */
size_t nts::protect::block(const suite_t suite) noexcept {
	// Получаем описание набора шифрования
	const Sample * sample = search(suite);
	// Выводим длину вектора замены набора шифрования
	return ((sample != nullptr) ? sample->size : 0);
}
/**
 * @brief Метод получения длины ключа набора шифрования
 *
 * @param suite набор шифрования
 *
 * @return      длина ключа в байтах, ноль у неизвестного набора
 *
 */
size_t nts::protect::key(const suite_t suite) noexcept {
	// Получаем описание набора шифрования
	const Sample * sample = search(suite);
	// Выводим длину ключа набора шифрования
	return ((sample != nullptr) ? sample->key : 0);
}
/**
 * @brief Метод получения длины метки целостности записи набора шифрования
 *
 * @param suite набор шифрования
 *
 * @return      длина метки целостности в байтах, ноль у неизвестного набора
 *
 */
size_t nts::protect::tag(const suite_t suite) noexcept {
	// Получаем описание набора шифрования
	const Sample * sample = search(suite);
	// Выводим длину метки целостности набора шифрования
	return ((sample != nullptr) ? sample->tag : 0);
}
/**
 * @brief Метод получения хеша расписания ключей набора шифрования
 *
 * @param suite набор шифрования
 *
 * @return      хеш расписания ключей, NONE у неизвестного набора
 *
 */
nts::digest::hash_t nts::protect::hash(const suite_t suite) noexcept {
	// Получаем описание набора шифрования
	const Sample * sample = search(suite);
	// Выводим хеш расписания ключей набора шифрования
	return ((sample != nullptr) ? sample->hash : digest::hash_t::NONE);
}
/**
 * @brief Метод получения наибольшего порядкового номера записи набора шифрования
 *
 * @param suite набор шифрования
 *
 * @return      наибольший порядковый номер записи, ноль у неизвестного набора
 *
 */
uint64_t nts::protect::limit(const suite_t suite) noexcept {
	// Получаем описание набора шифрования
	const Sample * sample = search(suite);
	// Выводим наибольший порядковый номер записи набора шифрования
	return ((sample != nullptr) ? sample->limit : 0);
}
/**
 * @brief Метод проверки принадлежности набора шифрования изданию TLS 1.2
 *
 * @param suite набор шифрования
 *
 * @return      признак того, что набор ведёт записи по разделу 6.2.3.3 RFC 5246
 *
 */
bool nts::protect::legacy(const suite_t suite) noexcept {
	// Получаем описание набора шифрования
	const Sample * sample = search(suite);
	// Выводим признак набора издания TLS 1.2
	return ((sample != nullptr) && sample->legacy);
}
/**
 * @brief Метод получения алгоритма подписи, требуемого набором шифрования TLS 1.2
 *
 * @param suite набор шифрования
 *
 * @return      алгоритм подписи, NONE у наборов TLS 1.3 и у неизвестного набора
 *
 */
nts::protect::signer_t nts::protect::signer(const suite_t suite) noexcept {
	// Получаем описание набора шифрования
	const Sample * sample = search(suite);
	// Выводим алгоритм подписи набора шифрования
	return ((sample != nullptr) ? sample->signer : signer_t::NONE);
}
/**
 * @brief Метод выработки ключа записи построением TLSTREE
 *
 * @param suite    набор шифрования, которым заданы постоянные построения
 * @param key      корневой ключ выработки ключа записи
 * @param sequence порядковый номер записи
 * @param result   место, в которое помещается ключ записи
 *
 * @return         признак успешности выработки ключа записи
 *
 */
bool nts::protect::tree(const suite_t suite, const view_t & key, const uint64_t sequence, uint8_t * result) noexcept {
	// Если место для ключа записи не передано
	if(result == nullptr)
		// Выводим отказ выработки ключа записи
		return false;
	// Получаем описание набора шифрования
	const Sample * sample = search(suite);
	// Если набор шифрования неизвестен
	if(sample == nullptr)
		// Выводим отказ выработки ключа записи
		return false;
	// Если корневой ключ не передан либо не сходится длиной с ключом набора
	if((key.data == nullptr) || (key.size != sample->key))
		// Выводим отказ выработки ключа записи
		return false;
	// Если набор шифрования классический
	if(sample->classic){
		// Переносим корневой ключ на место ключа записи: построения у набора нет
		::memcpy(result, key.data, key.size);
		// Выводим успешность выработки ключа записи
		return true;
	}
	// Место, в которое помещается ключ очередного яруса построения
	uint8_t buffer[PROTECT_KEY];
	// Место, в которое помещается затравка очередного яруса построения
	uint8_t seed[8];
	// Признак успешности выработки ключа записи
	bool ok = true;
	// Переносим корневой ключ на место ключа первого яруса
	::memcpy(buffer, key.data, key.size);
	/**
	 * Выполняем перебор ярусов построения TLSTREE
	 */
	for(size_t i = 0; ok && (i < 3); i++){
		// Записываем порядковый номер записи, обрезанный постоянной яруса
		number((sequence & sample->masks[i]), seed);
		// Выполняем выработку ключа очередного яруса построения
		ok = digest::kdf(view_t(buffer, PROTECT_KEY), view_t(reinterpret_cast <const uint8_t *> (LEVELS[i]), ::strlen(LEVELS[i])), view_t(seed, sizeof(seed)), buffer);
	}
	// Если ключ записи выработан
	if(ok)
		// Переносим ключ записи на место итога
		::memcpy(result, buffer, PROTECT_KEY);
	// Выполняем затирание ключа яруса построения
	wipe(buffer, sizeof(buffer));
	// Выводим признак успешности выработки ключа записи
	return ok;
}
/**
 * @brief Метод подготовки базового шифра к защите записи
 *
 * @param sequence порядковый номер защищаемой записи
 * @param block    описание базового шифра, в которое помещается итог
 *
 * @return         отказ подготовки базового шифра
 *
 */
nts::protect::error_t nts::protect::Protection::prepare(const uint64_t sequence, cipher::block_t & block) noexcept {
	// Получаем описание набора шифрования
	const Sample * sample = search(this->_suite);
	// Если набор шифрования неизвестен
	if(sample == nullptr)
		// Выводим отказ подготовки базового шифра
		return error_t::STATE;
	/**
	 * Набору ChaCha20-Poly1305 базовый блочный шифр не нужен: ключ уходит примитиву AEAD
	 * прямо при наложении либо снятии защиты, а описание шифра остаётся пустым
	 */
	if(sample->stream)
		// Выводим успешность подготовки: готовить нечего
		return error_t::NONE;
	// Если набор шифрования классический
	if(sample->classic){
		// Если ключ базового шифра ещё не установлен
		if(!this->_ready){
			// Если ключ базового шифра установить не удалось
			if(!this->_aes.key(view_t(this->_key, this->_width)))
				// Выводим отказ подготовки базового шифра
				return error_t::CIPHER;
		}
		// Устанавливаем описание базового шифра AES
		block = cipher::block_t(this->_aes);
		// Выводим успешность подготовки базового шифра
		return error_t::NONE;
	}
	// Признак того, что ключ записи требуется выработать заново
	bool fresh = !this->_ready;
	/**
	 * Выполняем перебор ярусов построения TLSTREE
	 */
	for(size_t i = 0; !fresh && (i < 3); i++)
		// Проверяем изменение обрезанного порядкового номера на очередном ярусе
		fresh = ((sequence & sample->masks[i]) != (this->_derived & sample->masks[i]));
	// Если ключ записи требуется выработать заново
	if(fresh){
		// Место, в которое помещается ключ записи
		uint8_t key[PROTECT_KEY];
		// Если ключ записи выработать не удалось
		if(!nts::protect::tree(this->_suite, view_t(this->_key, this->_width), sequence, key)){
			// Выполняем затирание ключа записи
			wipe(key, sizeof(key));
			// Выводим отказ подготовки базового шифра
			return error_t::CIPHER;
		}
		// Признак успешности установки ключа базового шифра
		bool ok = false;
		// Если базовый шифр набора - «Магма»
		if(sample->size == 8)
			// Устанавливаем ключ базового шифра «Магма»
			ok = this->_magma.key(view_t(key, sizeof(key)));
		// Устанавливаем ключ базового шифра «Кузнечик»
		else ok = this->_kuznyechik.key(view_t(key, sizeof(key)));
		// Выполняем затирание ключа записи
		wipe(key, sizeof(key));
		// Если ключ базового шифра установить не удалось
		if(!ok)
			// Выводим отказ подготовки базового шифра
			return error_t::CIPHER;
		// Запоминаем порядковый номер записи, на котором выработан ключ
		this->_derived = sequence;
	}
	// Если базовый шифр набора - «Магма»
	if(sample->size == 8)
		// Устанавливаем описание базового шифра «Магма»
		block = cipher::block_t(this->_magma);
	// Устанавливаем описание базового шифра «Кузнечик»
	else block = cipher::block_t(this->_kuznyechik);
	// Выводим успешность подготовки базового шифра
	return error_t::NONE;
}
/**
 * @brief Метод выработки одноразового значения записи
 *
 * @param sequence порядковый номер защищаемой записи
 * @param result   место, в которое помещается одноразовое значение
 *
 */
void nts::protect::Protection::nonce(const uint64_t sequence, uint8_t * result) const noexcept {
	// Переносим вектор замены на место одноразового значения
	::memcpy(result, this->_vector, this->_size);
	/**
	 * Выполняем сложение вектора замены с порядковым номером записи
	 */
	for(size_t i = 0; i < 8; i++)
		// Складываем очередной байт номера с байтом вектора замены
		result[this->_size - 1 - i] ^= static_cast <uint8_t> ((sequence >> (i * 8)) & 0xFF);
	// Если набор шифрования на алгоритмах ГОСТ
	if(!this->_classic)
		// Гасим старший разряд одноразового значения, занятый самим режимом MGM
		result[0] = static_cast <uint8_t> (result[0] & 0x7F);
}
/**
 * @brief Метод проверки готовности защиты записей к работе
 *
 * @return признак того, что ключевой материал установлен
 *
 */
bool nts::protect::Protection::ready() const noexcept {
	// Выводим признак готовности защиты записей
	return this->_ready;
}
/**
 * @brief Метод получения набора шифрования, которым защищаются записи
 *
 * @return набор шифрования направления связи
 *
 */
suite_t nts::protect::Protection::suite() const noexcept {
	// Выводим набор шифрования направления связи
	return this->_suite;
}
/**
 * @brief Метод получения порядкового номера очередной записи
 *
 * @return порядковый номер очередной записи направления связи
 *
 */
uint64_t nts::protect::Protection::sequence() const noexcept {
	// Выводим порядковый номер очередной записи
	return this->_sequence;
}
/**
 * @brief Метод установки ключевого материала направления связи
 *
 * @param suite  устанавливаемый набор шифрования
 * @param key    корневой ключ направления связи
 * @param vector вектор замены направления связи
 *
 * @return       признак успешности установки ключевого материала
 *
 */
bool nts::protect::Protection::start(const suite_t suite, const view_t & key, const view_t & vector) noexcept {
	// Выполняем сброс прежнего ключевого материала
	this->clear();
	// Получаем описание набора шифрования
	const Sample * sample = search(suite);
	// Если набор шифрования неизвестен
	if(sample == nullptr)
		// Выводим отказ установки ключевого материала
		return false;
	// Если корневой ключ не передан либо не сходится длиной с ключом набора
	if((key.data == nullptr) || (key.size != sample->key))
		// Выводим отказ установки ключевого материала
		return false;
	// Если вектор замены не передан либо не сходится длиной с вектором набора
	if((vector.data == nullptr) || (vector.size != sample->size))
		// Выводим отказ установки ключевого материала
		return false;
	// Запоминаем набор шифрования направления связи
	this->_suite = suite;
	// Запоминаем длину вектора замены набора шифрования
	this->_size = sample->size;
	// Запоминаем длину метки целостности набора шифрования
	this->_tag = sample->tag;
	// Запоминаем длину ключа набора шифрования
	this->_width = sample->key;
	// Запоминаем признак классического набора шифрования
	this->_classic = sample->classic;
	// Запоминаем признак набора ChaCha20-Poly1305
	this->_stream = sample->stream;
	// Запоминаем признак набора издания TLS 1.2
	this->_legacy = sample->legacy;
	// Запоминаем наибольший порядковый номер записи набора
	this->_limit = sample->limit;
	// Переносим корневой ключ направления связи
	::memcpy(this->_key, key.data, key.size);
	// Переносим вектор замены направления связи
	::memcpy(this->_vector, vector.data, vector.size);
	// Описание базового шифра первой записи
	cipher::block_t block;
	// Если базовый шифр к первой записи подготовить не удалось
	if(this->prepare(0, block) != error_t::NONE){
		// Выполняем сброс ключевого материала
		this->clear();
		// Выводим отказ установки ключевого материала
		return false;
	}
	// Отмечаем готовность защиты записей
	this->_ready = true;
	// Выводим успешность установки ключевого материала
	return true;
}
/**
 * @brief Метод сброса ключевого материала направления связи
 *
 */
void nts::protect::Protection::clear() noexcept {
	// Выполняем затирание корневого ключа направления связи
	wipe(this->_key, sizeof(this->_key));
	// Выполняем затирание вектора замены направления связи
	wipe(this->_vector, sizeof(this->_vector));
	// Выполняем сброс базового шифра «Магма»
	this->_magma.clear();
	// Выполняем сброс базового шифра «Кузнечик»
	this->_kuznyechik.clear();
	// Выполняем сброс базового шифра AES
	this->_aes.clear();
	// Сбрасываем набор шифрования направления связи
	this->_suite = suite_t::NONE;
	// Сбрасываем длину вектора замены
	this->_size = 0;
	// Сбрасываем длину метки целостности
	this->_tag = 0;
	// Сбрасываем длину ключа набора
	this->_width = 0;
	// Сбрасываем признак классического набора
	this->_classic = false;
	// Сбрасываем признак набора ChaCha20-Poly1305
	this->_stream = false;
	// Сбрасываем признак набора издания TLS 1.2
	this->_legacy = false;
	// Сбрасываем порядковый номер очередной записи
	this->_sequence = 0;
	// Сбрасываем наибольший порядковый номер записи
	this->_limit = 0;
	// Сбрасываем порядковый номер выработки ключа записи
	this->_derived = 0;
	// Сбрасываем готовность защиты записей
	this->_ready = false;
}
/**
 * @brief Метод наложения защиты на запись
 *
 * @param type    истинный вид содержимого защищаемой записи
 * @param data    защищаемое содержимое записи
 * @param result  накопитель, в конец которого дописывается защищённая запись
 * @param padding длина дополнения, скрывающего истинную длину содержимого
 *
 * @return        отказ наложения защиты на запись
 *
 */
nts::protect::error_t nts::protect::Protection::seal(const record::type_t type, const view_t & data, vector <uint8_t> & result, const size_t padding) noexcept {
	// Если ключевой материал не установлен
	if(!this->_ready)
		// Выводим отказ наложения защиты
		return error_t::STATE;
	// Если вид содержимого записи протоколом не определён
	if(!record::known(type))
		// Выводим отказ наложения защиты
		return error_t::TYPE;
	// Если набор шифрования издания TLS 1.2: запись складывается по разделу 6.2.3.3 RFC 5246
	if(this->_legacy)
		// Выводим итог наложения защиты записи издания TLS 1.2
		return this->wrap(type, data, result);
	// Длина защищаемого содержимого записи
	const size_t total = ((data.data != nullptr) ? data.size : 0);
	// Если содержимое либо дополнение длиннее дозволенного
	if((total > record::RECORD_PLAINTEXT) || (padding > record::RECORD_CIPHERTEXT))
		// Выводим отказ наложения защиты
		return error_t::LENGTH;
	// Длина открытого текста записи вместе с видом содержимого и дополнением
	const size_t length = (total + 1 + padding);
	// Если открытый текст длиннее дозволенного
	if(length > (record::RECORD_PLAINTEXT + 1))
		// Выводим отказ наложения защиты
		return error_t::LENGTH;
	// Если защищённая запись длиннее дозволенного
	if((length + this->_tag) > record::RECORD_CIPHERTEXT)
		// Выводим отказ наложения защиты
		return error_t::LENGTH;
	// Заголовок защищённой записи
	record::header_t header;
	// Устанавливаем вид содержимого защищённой записи
	header.type = record::type_t::APPLICATION;
	// Устанавливаем издание протокола защищённой записи
	header.version = record::version_t::TLS12;
	// Устанавливаем длину содержимого защищённой записи
	header.size = (length + this->_tag);
	// Место, в которое записывается заголовок защищённой записи
	uint8_t associated[record::RECORD_HEADER];
	// Если заголовок защищённой записи составить не удалось
	if(record::build(header, associated) != record::error_t::NONE)
		// Выводим отказ наложения защиты
		return error_t::LENGTH;
	// Смещение защищённой записи в накопителе
	const size_t offset = result.size();
	/**
	 * Заголовок складывается в накопитель прежде шифртекста: он служит связанными
	 * данными, и место ему отведено впереди
	 */
	try {
		// Складываем заголовок защищённой записи в накопитель
		result.insert(result.end(), associated, associated + record::RECORD_HEADER);
	/**
	 * Если памяти под заголовок не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Выполняем наложение защиты на запись собственным порядковым номером
	const error_t outcome = this->seal(view_t(associated, record::RECORD_HEADER), this->_sequence, type, data, result, padding);
	// Если защиту наложить не удалось
	if(outcome != error_t::NONE){
		// Возвращаем накопитель к прежней длине
		result.resize(offset);
		// Выводим отказ наложения защиты на запись
		return outcome;
	}
	// Увеличиваем порядковый номер очередной записи
	this->_sequence++;
	// Выводим успешность наложения защиты на запись
	return error_t::NONE;
}
/**
 * @brief Метод снятия защиты с записи
 *
 * @param header заголовок защищённой записи
 * @param data   содержимое защищённой записи
 * @param type   место, в которое помещается истинный вид содержимого
 * @param result накопитель, в конец которого дописывается открытое содержимое
 *
 * @return       отказ снятия защиты с записи
 *
 */
nts::protect::error_t nts::protect::Protection::open(const record::header_t & header, const view_t & data, record::type_t & type, vector <uint8_t> & result) noexcept {
	// Если ключевой материал не установлен
	if(!this->_ready)
		// Выводим отказ снятия защиты
		return error_t::STATE;
	// Если набор шифрования издания TLS 1.2: запись разбирается по разделу 6.2.3.3 RFC 5246
	if(this->_legacy)
		// Выводим итог снятия защиты с записи издания TLS 1.2
		return this->unwrap(header, data, type, result);
	// Если запись не выдаёт себя за прикладные данные
	if(header.type != record::type_t::APPLICATION)
		// Выводим отказ снятия защиты
		return error_t::TYPE;
	// Если содержимое записи не передано либо не сходится длиной с заголовком
	if((data.data == nullptr) || (data.size != header.size))
		// Выводим отказ снятия защиты
		return error_t::LENGTH;
	// Место, в которое записывается заголовок защищённой записи
	uint8_t associated[record::RECORD_HEADER];
	// Если заголовок защищённой записи составить не удалось
	if(record::build(header, associated) != record::error_t::NONE)
		// Выводим отказ снятия защиты
		return error_t::LENGTH;
	// Выполняем снятие защиты с записи собственным порядковым номером
	const error_t outcome = this->open(view_t(associated, record::RECORD_HEADER), this->_sequence, data, type, result);
	// Если защиту снять не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ снятия защиты с записи
		return outcome;
	// Увеличиваем порядковый номер очередной записи
	this->_sequence++;
	// Выводим успешность снятия защиты с записи
	return error_t::NONE;
}
/**
 * @brief Метод наложения защиты на запись с заданными связанными данными и номером
 *
 * @param associated связанные данные записи: её заголовок, составленный снаружи
 * @param sequence   порядковый номер записи, задающий одноразовое значение
 * @param type       истинный вид содержимого защищаемой записи
 * @param data       защищаемое содержимое записи
 * @param result     накопитель, в конец которого дописываются шифртекст и метка целостности
 * @param padding    длина дополнения, скрывающего истинную длину содержимого
 *
 * @return           отказ наложения защиты на запись
 *
 */
nts::protect::error_t nts::protect::Protection::seal(const view_t & associated, const uint64_t sequence, const record::type_t type, const view_t & data, vector <uint8_t> & result, const size_t padding) noexcept {
	// Если ключевой материал не установлен
	if(!this->_ready)
		// Выводим отказ наложения защиты
		return error_t::STATE;
	// Если вид содержимого записи протоколом не определён
	if(!record::known(type))
		// Выводим отказ наложения защиты
		return error_t::TYPE;
	// Если связанные данные не переданы
	if((associated.data == nullptr) || (associated.size == 0))
		// Выводим отказ наложения защиты
		return error_t::LENGTH;
	// Если порядковые номера записей на этом ключе исчерпаны
	if(sequence > this->_limit)
		// Выводим отказ наложения защиты
		return error_t::SEQUENCE;
	// Длина защищаемого содержимого записи
	const size_t total = ((data.data != nullptr) ? data.size : 0);
	// Если содержимое либо дополнение длиннее дозволенного
	if((total > record::RECORD_PLAINTEXT) || (padding > record::RECORD_CIPHERTEXT))
		// Выводим отказ наложения защиты
		return error_t::LENGTH;
	// Если содержимое пусто, а вид записи пустоты не дозволяет
	if((total == 0) && !record::empty(type))
		// Выводим отказ наложения защиты
		return error_t::LENGTH;
	// Длина открытого текста записи вместе с видом содержимого и дополнением
	const size_t length = (total + 1 + padding);
	// Если открытый текст длиннее дозволенного
	if(length > (record::RECORD_PLAINTEXT + 1))
		// Выводим отказ наложения защиты
		return error_t::LENGTH;
	// Если защищённая запись длиннее дозволенного
	if((length + this->_tag) > record::RECORD_CIPHERTEXT)
		// Выводим отказ наложения защиты
		return error_t::LENGTH;
	// Описание базового шифра записи
	cipher::block_t block;
	// Выполняем подготовку базового шифра к защите записи
	const error_t error = this->prepare(sequence, block);
	// Если базовый шифр подготовить не удалось
	if(error != error_t::NONE)
		// Выводим отказ наложения защиты
		return error;
	// Место, в которое помещается одноразовое значение записи
	uint8_t nonce[PROTECT_VECTOR];
	// Выполняем выработку одноразового значения записи
	this->nonce(sequence, nonce);
	// Итог наложения защиты на запись
	error_t outcome = error_t::NONE;
	/**
	 * Открытый текст записи складывается в памяти: длина его задана содержимым и
	 * дополнением, и памяти под неё может не хватить
	 */
	try {
		// Открытый текст записи вместе с видом содержимого и дополнением
		vector <uint8_t> plain(length, 0);
		// Если содержимое записи передано
		if(total > 0)
			// Переносим содержимое записи в открытый текст
			::memcpy(plain.data(), data.data, total);
		// Записываем истинный вид содержимого следом за содержимым
		plain[total] = static_cast <uint8_t> (type);
		// Смещение шифртекста записи в накопителе
		const size_t offset = result.size();
		// Занимаем место под шифртекст и метку целостности записи
		result.resize(offset + length + this->_tag, 0);
		// Место, в которое помещается шифртекст записи
		uint8_t * cipher = (result.data() + offset);
		// Признак успешности наложения шифрования с проверкой целостности
		bool ok = false;
		// Если набор шифрования - ChaCha20-Poly1305
		if(this->_stream){
			// Объект AEAD ChaCha20-Poly1305
			cipher::chachapoly_t chachapoly;
			// Если AEAD запустить не удалось
			if(chachapoly.start(view_t(this->_key, this->_width), view_t(nonce, this->_size)))
				// Выполняем наложение шифрования с проверкой целостности
				ok = chachapoly.encrypt(associated, view_t(plain.data(), plain.size()), cipher, (cipher + length));
		// Если набор шифрования классический на AES-GCM
		} else if(this->_classic) {
			// Объект режима GCM
			cipher::gcm_t gcm;
			// Если режим GCM запустить не удалось
			if(gcm.start(block, view_t(nonce, this->_size), this->_tag))
				// Выполняем наложение шифрования с проверкой целостности
				ok = gcm.encrypt(associated, view_t(plain.data(), plain.size()), cipher, (cipher + length));
		// Если набор шифрования на алгоритмах ГОСТ
		} else {
			// Объект режима MGM
			cipher::galois_t galois;
			// Если режим MGM запустить не удалось
			if(galois.start(block, view_t(nonce, this->_size), this->_tag))
				// Выполняем наложение шифрования с проверкой целостности
				ok = galois.encrypt(associated, view_t(plain.data(), plain.size()), cipher, (cipher + length));
		}
		// Если наложить шифрование не удалось
		if(!ok){
			// Возвращаем накопитель к прежней длине
			result.resize(offset);
			// Запоминаем отказ базового шифра
			outcome = error_t::CIPHER;
		}
		// Выполняем затирание открытого текста записи
		wipe(plain.data(), plain.size());
	/**
	 * Если памяти под открытый текст либо накопитель не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Запоминаем отказ нехватки памяти
		outcome = error_t::MEMORY;
	}
	// Выполняем затирание одноразового значения
	wipe(nonce, sizeof(nonce));
	// Выводим итог наложения защиты на запись
	return outcome;
}
/**
 * @brief Метод снятия защиты с записи с заданными связанными данными и номером
 *
 * @param associated связанные данные записи: её заголовок, каким он был при наложении защиты
 * @param sequence   восстановленный порядковый номер записи
 * @param data       защищённое содержимое принятой записи
 * @param type       вид содержимого, в который помещается истинный вид содержимого записи
 * @param result     накопитель, в конец которого дописывается открытое содержимое записи
 *
 * @return           отказ снятия защиты с записи
 *
 */
nts::protect::error_t nts::protect::Protection::open(const view_t & associated, const uint64_t sequence, const view_t & data, record::type_t & type, vector <uint8_t> & result) noexcept {
	// Если ключевой материал не установлен
	if(!this->_ready)
		// Выводим отказ снятия защиты
		return error_t::STATE;
	// Если связанные данные не переданы
	if((associated.data == nullptr) || (associated.size == 0))
		// Выводим отказ снятия защиты
		return error_t::LENGTH;
	// Если порядковые номера записей на этом ключе исчерпаны
	if(sequence > this->_limit)
		// Выводим отказ снятия защиты
		return error_t::SEQUENCE;
	// Если содержимое записи не передано либо короче метки целостности
	if((data.data == nullptr) || (data.size <= this->_tag))
		// Выводим отказ снятия защиты
		return error_t::LENGTH;
	// Длина шифртекста записи без метки целостности
	const size_t length = (data.size - this->_tag);
	// Если шифртекст длиннее дозволенного
	if(length > (record::RECORD_PLAINTEXT + 1))
		// Выводим отказ снятия защиты
		return error_t::LENGTH;
	// Описание базового шифра записи
	cipher::block_t block;
	// Выполняем подготовку базового шифра к снятию защиты
	const error_t error = this->prepare(sequence, block);
	// Если базовый шифр подготовить не удалось
	if(error != error_t::NONE)
		// Выводим отказ снятия защиты
		return error;
	// Место, в которое помещается одноразовое значение записи
	uint8_t nonce[PROTECT_VECTOR];
	// Выполняем выработку одноразового значения записи
	this->nonce(sequence, nonce);
	// Итог снятия защиты с записи
	error_t outcome = error_t::NONE;
	/**
	 * Открытый текст записи складывается в памяти: длина его задана записью, и памяти
	 * под неё может не хватить
	 */
	try {
		// Открытый текст записи вместе с видом содержимого и дополнением
		vector <uint8_t> plain(length, 0);
		// Признак успешности снятия шифрования с проверкой целостности
		bool ok = false;
		// Если набор шифрования - ChaCha20-Poly1305
		if(this->_stream){
			// Объект AEAD ChaCha20-Poly1305
			cipher::chachapoly_t chachapoly;
			// Если AEAD запустить не удалось
			if(chachapoly.start(view_t(this->_key, this->_width), view_t(nonce, this->_size)))
				// Выполняем снятие шифрования с проверкой целостности
				ok = chachapoly.decrypt(associated, view_t(data.data, length), plain.data(), view_t((data.data + length), this->_tag));
		// Если набор шифрования классический на AES-GCM
		} else if(this->_classic) {
			// Объект режима GCM
			cipher::gcm_t gcm;
			// Если режим GCM запустить не удалось
			if(gcm.start(block, view_t(nonce, this->_size), this->_tag))
				// Выполняем снятие шифрования с проверкой целостности
				ok = gcm.decrypt(associated, view_t(data.data, length), plain.data(), view_t((data.data + length), this->_tag));
		// Если набор шифрования на алгоритмах ГОСТ
		} else {
			// Объект режима MGM
			cipher::galois_t galois;
			// Если режим MGM запустить не удалось
			if(galois.start(block, view_t(nonce, this->_size), this->_tag))
				// Выполняем снятие шифрования с проверкой целостности
				ok = galois.decrypt(associated, view_t(data.data, length), plain.data(), view_t((data.data + length), this->_tag));
		}
		// Если метка целостности записи не сошлась
		if(!ok)
			// Запоминаем отказ метки целостности
			outcome = error_t::TAG;
		// Если защита снята
		else {
			// Смещение истинного вида содержимого в открытом тексте
			size_t offset = length;
			/**
			 * Выполняем пропуск дополнения с конца открытого текста
			 */
			while((offset > 0) && (plain[offset - 1] == 0x00))
				// Уменьшаем смещение истинного вида содержимого
				offset--;
			// Если истинного вида содержимого в открытом тексте нет
			if(offset == 0)
				// Запоминаем отказ вида содержимого
				outcome = error_t::TYPE;
			// Если истинный вид содержимого найден
			else {
				// Получаем истинный вид содержимого записи
				const record::type_t inner = static_cast <record::type_t> (plain[offset - 1]);
				// Если вид содержимого протоколом не определён
				if(!record::known(inner))
					// Запоминаем отказ вида содержимого
					outcome = error_t::TYPE;
				// Если вид содержимого протоколом определён
				else {
					// Устанавливаем истинный вид содержимого записи
					type = inner;
					// Складываем открытое содержимое записи в накопитель
					result.insert(result.end(), plain.data(), (plain.data() + offset - 1));
				}
			}
		}
		// Выполняем затирание открытого текста записи
		wipe(plain.data(), plain.size());
	/**
	 * Если памяти под открытый текст либо накопитель не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Запоминаем отказ нехватки памяти
		outcome = error_t::MEMORY;
	}
	// Выполняем затирание одноразового значения
	wipe(nonce, sizeof(nonce));
	// Выводим итог снятия защиты с записи
	return outcome;
}
/**
 * @brief Метод составления связанных данных записи издания TLS 1.2
 *
 * @param sequence порядковый номер записи
 * @param type     вид содержимого записи
 * @param length   длина открытого содержимого записи
 * @param result   место, в которое помещаются связанные данные
 *
 */
void nts::protect::Protection::associate(const uint64_t sequence, const record::type_t type, const size_t length, uint8_t * result) const noexcept {
	// Записываем порядковый номер записи от старшего байта к младшему
	number(sequence, result);
	// Записываем вид содержимого записи
	result[8] = static_cast <uint8_t> (type);
	// Записываем старший байт издания протокола TLS 1.2
	result[9] = 0x03;
	// Записываем младший байт издания протокола TLS 1.2
	result[10] = 0x03;
	// Записываем старший байт длины открытого содержимого
	result[11] = static_cast <uint8_t> ((length >> 8) & 0xFF);
	// Записываем младший байт длины открытого содержимого
	result[12] = static_cast <uint8_t> (length & 0xFF);
}
/**
 * @brief Метод наложения защиты на запись издания TLS 1.2
 *
 * @param type   вид содержимого защищаемой записи
 * @param data   защищаемое содержимое записи
 * @param result накопитель, в конец которого дописывается защищённая запись
 *
 * @return       отказ наложения защиты на запись
 *
 */
nts::protect::error_t nts::protect::Protection::wrap(const record::type_t type, const view_t & data, vector <uint8_t> & result) noexcept {
	// Если порядковые номера записей на этом ключе исчерпаны
	if(this->_sequence > this->_limit)
		// Выводим отказ наложения защиты
		return error_t::SEQUENCE;
	// Длина защищаемого содержимого записи
	const size_t total = ((data.data != nullptr) ? data.size : 0);
	// Если содержимое длиннее дозволенного
	if(total > record::RECORD_PLAINTEXT)
		// Выводим отказ наложения защиты
		return error_t::LENGTH;
	// Если содержимое пусто, а вид записи пустоты не дозволяет
	if((total == 0) && !record::empty(type))
		// Выводим отказ наложения защиты
		return error_t::LENGTH;
	/**
	 * Раздел 3 RFC 5288: у AES-GCM перед шифртекстом идёт явная часть одноразового
	 * значения в восемь байтов; у ChaCha20-Poly1305 (раздел 2 RFC 7905) явной части нет
	 */
	const size_t prefix = (this->_stream ? 0 : LEGACY_EXPLICIT);
	// Заголовок защищённой записи: вид содержимого идёт открыто
	record::header_t header;
	// Устанавливаем вид содержимого защищённой записи
	header.type = type;
	// Устанавливаем издание протокола защищённой записи
	header.version = record::version_t::TLS12;
	// Устанавливаем длину содержимого защищённой записи
	header.size = (prefix + total + this->_tag);
	// Место, в которое записывается заголовок защищённой записи
	uint8_t written[record::RECORD_HEADER];
	// Если заголовок защищённой записи составить не удалось
	if(record::build(header, written) != record::error_t::NONE)
		// Выводим отказ наложения защиты
		return error_t::LENGTH;
	// Описание базового шифра записи
	cipher::block_t block;
	// Выполняем подготовку базового шифра к защите записи
	const error_t error = this->prepare(this->_sequence, block);
	// Если базовый шифр подготовить не удалось
	if(error != error_t::NONE)
		// Выводим отказ наложения защиты
		return error;
	// Место, в которое помещаются связанные данные записи
	uint8_t associated[LEGACY_ASSOCIATED];
	// Составляем связанные данные записи: раздел 6.2.3.3 RFC 5246
	this->associate(this->_sequence, type, total, associated);
	// Место, в которое помещается одноразовое значение записи
	uint8_t nonce[PROTECT_VECTOR];
	// Если набор шифрования - ChaCha20-Poly1305
	if(this->_stream)
		// Раздел 2 RFC 7905: одноразовое значение есть вектор замены, сложенный с номером записи
		this->nonce(this->_sequence, nonce);
	// Если набор шифрования - AES-GCM
	else {
		// Раздел 3 RFC 5288: одноразовое значение есть соль и явная часть - порядковый номер записи
		::memcpy(nonce, this->_vector, LEGACY_SALT);
		// Записываем явную часть одноразового значения
		number(this->_sequence, nonce + LEGACY_SALT);
	}
	// Смещение защищённой записи в накопителе
	const size_t offset = result.size();
	// Итог наложения защиты на запись
	error_t outcome = error_t::NONE;
	/**
	 * Выполняем складывание защищённой записи в накопитель
	 */
	try {
		// Занимаем место под заголовок, явную часть, шифртекст и метку целостности
		result.resize(offset + record::RECORD_HEADER + prefix + total + this->_tag, 0);
		// Переносим заголовок защищённой записи
		::memcpy(result.data() + offset, written, record::RECORD_HEADER);
		// Если явная часть одноразового значения положена
		if(prefix > 0)
			// Переносим явную часть одноразового значения
			::memcpy(result.data() + offset + record::RECORD_HEADER, nonce + LEGACY_SALT, prefix);
		// Место, в которое помещается шифртекст записи
		uint8_t * cipher = (result.data() + offset + record::RECORD_HEADER + prefix);
		// Признак успешности наложения шифрования с проверкой целостности
		bool ok = false;
		// Если набор шифрования - ChaCha20-Poly1305
		if(this->_stream){
			// Объект AEAD ChaCha20-Poly1305
			cipher::chachapoly_t chachapoly;
			// Если AEAD запустить не удалось
			if(chachapoly.start(view_t(this->_key, this->_width), view_t(nonce, this->_size)))
				// Выполняем наложение шифрования с проверкой целостности
				ok = chachapoly.encrypt(view_t(associated, sizeof(associated)), view_t(data.data, total), cipher, (cipher + total));
		// Если набор шифрования - AES-GCM
		} else {
			// Объект режима GCM
			cipher::gcm_t gcm;
			// Если режим GCM запустить не удалось
			if(gcm.start(block, view_t(nonce, LEGACY_SALT + LEGACY_EXPLICIT), this->_tag))
				// Выполняем наложение шифрования с проверкой целостности
				ok = gcm.encrypt(view_t(associated, sizeof(associated)), view_t(data.data, total), cipher, (cipher + total));
		}
		// Если наложить шифрование не удалось
		if(!ok){
			// Возвращаем накопитель к прежней длине
			result.resize(offset);
			// Запоминаем отказ базового шифра
			outcome = error_t::CIPHER;
		}
	/**
	 * Если памяти под накопитель не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Запоминаем отказ нехватки памяти
		outcome = error_t::MEMORY;
	}
	// Выполняем затирание одноразового значения
	wipe(nonce, sizeof(nonce));
	// Если защита наложена
	if(outcome == error_t::NONE)
		// Увеличиваем порядковый номер очередной записи
		this->_sequence++;
	// Выводим итог наложения защиты на запись
	return outcome;
}
/**
 * @brief Метод снятия защиты с записи издания TLS 1.2
 *
 * @param header заголовок принятой защищённой записи
 * @param data   защищённое содержимое принятой записи
 * @param type   вид содержимого, в который помещается вид содержимого записи
 * @param result накопитель, в конец которого дописывается открытое содержимое записи
 *
 * @return       отказ снятия защиты с записи
 *
 */
nts::protect::error_t nts::protect::Protection::unwrap(const record::header_t & header, const view_t & data, record::type_t & type, vector <uint8_t> & result) noexcept {
	// Если порядковые номера записей на этом ключе исчерпаны
	if(this->_sequence > this->_limit)
		// Выводим отказ снятия защиты
		return error_t::SEQUENCE;
	// Если вид содержимого записи протоколом не определён
	if(!record::known(header.type))
		// Выводим отказ снятия защиты
		return error_t::TYPE;
	// Если содержимое записи не передано либо не сходится длиной с заголовком
	if((data.data == nullptr) || (data.size != header.size))
		// Выводим отказ снятия защиты
		return error_t::LENGTH;
	// Длина явной части одноразового значения, идущей перед шифртекстом
	const size_t prefix = (this->_stream ? 0 : LEGACY_EXPLICIT);
	// Если содержимое записи короче явной части и метки целостности
	if(data.size < (prefix + this->_tag))
		// Выводим отказ снятия защиты
		return error_t::LENGTH;
	// Длина шифртекста записи без явной части и метки целостности
	const size_t length = (data.size - prefix - this->_tag);
	// Если шифртекст длиннее дозволенного открытому содержимому
	if(length > record::RECORD_PLAINTEXT)
		// Выводим отказ снятия защиты
		return error_t::LENGTH;
	// Если содержимое пусто, а вид записи пустоты не дозволяет
	if((length == 0) && !record::empty(header.type))
		// Выводим отказ снятия защиты
		return error_t::LENGTH;
	// Описание базового шифра записи
	cipher::block_t block;
	// Выполняем подготовку базового шифра к снятию защиты
	const error_t error = this->prepare(this->_sequence, block);
	// Если базовый шифр подготовить не удалось
	if(error != error_t::NONE)
		// Выводим отказ снятия защиты
		return error;
	// Место, в которое помещаются связанные данные записи
	uint8_t associated[LEGACY_ASSOCIATED];
	// Составляем связанные данные записи: раздел 6.2.3.3 RFC 5246
	this->associate(this->_sequence, header.type, length, associated);
	// Место, в которое помещается одноразовое значение записи
	uint8_t nonce[PROTECT_VECTOR];
	// Если набор шифрования - ChaCha20-Poly1305
	if(this->_stream)
		// Раздел 2 RFC 7905: одноразовое значение есть вектор замены, сложенный с номером записи
		this->nonce(this->_sequence, nonce);
	// Если набор шифрования - AES-GCM
	else {
		/**
		 * Раздел 3 RFC 5288: явная часть одноразового значения берётся из самой записи -
		 * собеседник вправе слать её любой, лишь бы не повторял
		 */
		::memcpy(nonce, this->_vector, LEGACY_SALT);
		// Переносим явную часть одноразового значения из записи
		::memcpy(nonce + LEGACY_SALT, data.data, LEGACY_EXPLICIT);
	}
	// Итог снятия защиты с записи
	error_t outcome = error_t::NONE;
	/**
	 * Открытый текст записи складывается в памяти: длина его задана записью, и памяти
	 * под неё может не хватить
	 */
	try {
		// Открытый текст записи
		vector <uint8_t> plain(length, 0);
		// Признак успешности снятия шифрования с проверкой целостности
		bool ok = false;
		// Если набор шифрования - ChaCha20-Poly1305
		if(this->_stream){
			// Объект AEAD ChaCha20-Poly1305
			cipher::chachapoly_t chachapoly;
			// Если AEAD запустить не удалось
			if(chachapoly.start(view_t(this->_key, this->_width), view_t(nonce, this->_size)))
				// Выполняем снятие шифрования с проверкой целостности
				ok = chachapoly.decrypt(view_t(associated, sizeof(associated)), view_t(data.data + prefix, length), plain.data(), view_t((data.data + prefix + length), this->_tag));
		// Если набор шифрования - AES-GCM
		} else {
			// Объект режима GCM
			cipher::gcm_t gcm;
			// Если режим GCM запустить не удалось
			if(gcm.start(block, view_t(nonce, LEGACY_SALT + LEGACY_EXPLICIT), this->_tag))
				// Выполняем снятие шифрования с проверкой целостности
				ok = gcm.decrypt(view_t(associated, sizeof(associated)), view_t(data.data + prefix, length), plain.data(), view_t((data.data + prefix + length), this->_tag));
		}
		// Если метка целостности записи не сошлась
		if(!ok)
			// Запоминаем отказ метки целостности
			outcome = error_t::TAG;
		// Если защита снята
		else {
			// Устанавливаем вид содержимого записи из её заголовка
			type = header.type;
			// Складываем открытое содержимое записи в накопитель
			result.insert(result.end(), plain.data(), (plain.data() + length));
		}
		// Выполняем затирание открытого текста записи
		wipe(plain.data(), plain.size());
	/**
	 * Если памяти под открытый текст либо накопитель не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Запоминаем отказ нехватки памяти
		outcome = error_t::MEMORY;
	}
	// Выполняем затирание одноразового значения
	wipe(nonce, sizeof(nonce));
	// Если защита снята
	if(outcome == error_t::NONE)
		// Увеличиваем порядковый номер очередной записи
		this->_sequence++;
	// Выводим итог снятия защиты с записи
	return outcome;
}
/**
 * @brief Конструктор
 *
 */
nts::protect::Protection::Protection() noexcept : _ready(false), _suite(suite_t::NONE), _size(0), _tag(0), _width(0), _classic(false), _stream(false), _legacy(false), _sequence(0), _limit(0), _derived(0) {
	// Обнуляем корневой ключ направления связи
	::memset(this->_key, 0, sizeof(this->_key));
	// Обнуляем вектор замены направления связи
	::memset(this->_vector, 0, sizeof(this->_vector));
}
/**
 * @brief Деструктор
 *
 */
nts::protect::Protection::~Protection() noexcept {
	// Выполняем сброс ключевого материала
	this->clear();
}
