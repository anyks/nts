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
 * 6. Режим GCM заводится один раз на ключ: таблица кратных ключа хеширования строится при
 *    установке ключевого материала, а на всякую запись меняется лишь заполнение (restart).
 *    До круга 31 (23.09.2026) режим заводился заново на каждую запись, и три затирания
 *    таблицы с её построением стоили около 0,8 мкс на запись - вчетверо дороже самого
 *    шифрования 1200 байтов. Содержимое, вид и дополнение шифруются потоком прямо из места
 *    вызова в накопитель, без сборки открытого текста в памяти; снятие защиты идёт прямо в
 *    накопитель вызывающей стороны, а хвост записи и, при отказе, весь открытый текст
 *    затираются до возврата. Наборы ГОСТ собирают открытый текст в памяти по-прежнему:
 *    у режима MGM поточного вызова нет.
 *
 * 7. Набор ChaCha20-Poly1305 живёт тем же классическим путём, что и AES-GCM: одноразовое
 *    значение, связанные данные и предел длины у них общие (разделы 5.2 и 5.3 RFC 8446), а
 *    различие лишь в примитиве - AEAD берётся у chachapoly_t на запись (его заведение - копия
 *    ключа и один блок гаммы под ключ Poly1305, чего требует сам RFC 8439), и базовый блочный
 *    шифр ему не готовится вовсе. Предел записей на ключе взят в 2^62:
 *    раздел 5.5 RFC 8446 предела ChaCha20 не ставит (порядковый номер переполнится
 *    раньше), а недостижимый предел оставляет заслон номеров живым и не подпускает
 *    счётчик к переполнению.
 *
 * 8. Наборы CBC издания TLS 1.2 (раздел 6.2.3.2 RFC 5246) ведутся тем же объектом: ключ
 *    имитовставки лежит рядом с ключом шифрования, вектор замены явный и случайный на всякую
 *    запись, а порядок «имитовставка, затем шифрование» либо «шифрование, затем имитовставка»
 *    (RFC 7366) переключается признаком etm. Снятие защиты в порядке MAC-then-encrypt идёт
 *    за постоянное время относительно длины дополнения (Lucky13): дополнение сверяется
 *    целиком под масками без ранних выходов, имитовставка над открытым текстом дополняется
 *    холостыми сжатиями хеша до числа, отвечающего наибольшей длине открытого текста записи,
 *    принятая имитовставка извлекается из расшифрованного буфера перебором окна под маской
 *    совпадения номера (окно - наибольшая длина дополнения и имитовставки, а не вся запись,
 *    чтобы цена не росла с длиной записи), и лишь итоговый признак решает судьбу записи.
 *    Ключевой материал наборов CBC векторов замены не несёт вовсе (block равен нулю): у
 *    издания 1.1 и выше вектор явный, и расписание ключей выводить его незачем.
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Стандартные заголовочные файлы
 */
#include <new>
#include <cstdint>
#include <cstring>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <digest/kdf.hpp>
#include <digest/hmac.hpp>
#include <entropy/entropy.hpp>
#include <message/message.hpp>
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
	 * @brief Метод поточного наложения защиты на запись: содержимое, истинный вид и дополнение шифруются прямо из места вызова
	 *
	 * @param aead       заведённый примитив AEAD с установленным заполнением
	 * @param associated связанные данные записи
	 * @param data       защищаемое содержимое записи
	 * @param total      длина содержимого записи
	 * @param type       истинный вид содержимого записи
	 * @param padding    длина дополнения записи
	 * @param cipher     место под шифртекст записи с меткой целостности следом
	 *
	 * @return           признак успешности наложения защиты
	 *
	 */
	template <typename T>
	static bool sealing(T & aead, const view_t & associated, const view_t & data, const size_t total, const record::type_t type, const size_t padding, uint8_t * cipher) noexcept {
		// Если связанные данные подать не удалось
		if(!aead.associate(associated))
			// Выводим отказ наложения защиты
			return false;
		// Если содержимое записи зашифровать не удалось
		if((total > 0) && !aead.encrypt(view_t(data.data, total), cipher))
			// Выводим отказ наложения защиты
			return false;
		// Истинный вид содержимого записи
		const uint8_t inner = static_cast <uint8_t> (type);
		// Если истинный вид содержимого зашифровать не удалось
		if(!aead.encrypt(view_t(&inner, 1), cipher + total))
			// Выводим отказ наложения защиты
			return false;
		// Смещение дополнения в шифртексте записи
		size_t offset = (total + 1);
		// Нулевые байты дополнения: шифруются кусками, чтобы не занимать память под всё дополнение
		static const uint8_t ZEROS[256] = {0};
		/**
		 * Выполняем шифрование дополнения кусками
		 */
		for(size_t rest = padding; rest > 0;){
			// Длина очередного куска дополнения
			const size_t piece = ((rest > sizeof(ZEROS)) ? sizeof(ZEROS) : rest);
			// Если кусок дополнения зашифровать не удалось
			if(!aead.encrypt(view_t(ZEROS, piece), cipher + offset))
				// Выводим отказ наложения защиты
				return false;
			// Сдвигаем смещение на длину куска
			offset += piece;
			// Уменьшаем остаток дополнения
			rest -= piece;
		}
		// Выводим итог выработки метки целостности следом за шифртекстом
		return aead.finish(cipher + offset);
	}

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
	 * Разряды порядкового номера записи поверх дейтаграмм: раздел 4.1 RFC 6347 отводит
	 * номеру сорок восемь разрядов, а старшие шестнадцать несут пору ключей
	 */
	static constexpr uint64_t LEGACY_ORDINAL = 0xFFFFFFFFFFFFULL;

	/**
	 * Предел записей на одном ключе ChaCha20-Poly1305: 2^62, раздел 5.5 RFC 8446 предела
	 * не ставит, а недостижимый предел держит заслон номеров живым вдали от переполнения
	 */
	static constexpr uint64_t STREAM_LIMIT = 0x3FFFFFFFFFFFFFFFULL;

	/**
	 * Длина блока AES и явного вектора замены наборов CBC: раздел 6.2.3.2 RFC 5246
	 */
	static constexpr size_t CBC_BLOCK = 16;

	/**
	 * Наибольшая длина дополнения записи CBC вместе с байтом длины: раздел 6.2.3.2 RFC 5246
	 */
	static constexpr size_t CBC_PADDING = 256;

	/**
	 * Длина блока сжатия хешей имитовставки SHA-1 и SHA-256 и длина их дополнения с полем
	 * длины сообщения: FIPS 180-4
	 */
	static constexpr size_t CBC_COMPRESSION = 64;
	static constexpr size_t CBC_TRAILER = 9;

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
		// Признак набора SM4-CCM с режимом CCM по RFC 3610 вместо GCM
		bool ccm;
		// Алгоритм подписи, требуемый набором TLS 1.2 от сертификата
		signer_t signer;
		// Способ обмена ключами набора TLS 1.2
		exchange_t exchange;
		// Хеш имитовставки набора CBC, NONE у наборов AEAD
		digest::hash_t mac;
	} SAMPLES[32] = {
		{suite_t::KUZNYECHIK_MGM_L,         false, false, {0xF800000000000000ULL, 0xFFFFFFF000000000ULL, 0xFFFFFFFFFFFFE000ULL}, 0xFFFFFFFFFFFFFFFFULL, 16, 32, 16, digest::hash_t::STREEBOG256, false, false, signer_t::NONE, exchange_t::NONE, digest::hash_t::NONE},
		{suite_t::MAGMA_MGM_L,              false, false, {0xFFE0000000000000ULL, 0xFFFFFFFFC0000000ULL, 0xFFFFFFFFFFFFFF80ULL}, 0xFFFFFFFFFFFFFFFFULL, 8,  32, 8,  digest::hash_t::STREEBOG256, false, false, signer_t::NONE, exchange_t::NONE, digest::hash_t::NONE},
		{suite_t::KUZNYECHIK_MGM_S,         false, false, {0xFFFFFFFFE0000000ULL, 0xFFFFFFFFFFFF0000ULL, 0xFFFFFFFFFFFFFFF8ULL}, 0x000003FFFFFFFFFFULL, 16, 32, 16, digest::hash_t::STREEBOG256, false, false, signer_t::NONE, exchange_t::NONE, digest::hash_t::NONE},
		{suite_t::MAGMA_MGM_S,              false, false, {0xFFFFFFFFFC000000ULL, 0xFFFFFFFFFFFFE000ULL, 0xFFFFFFFFFFFFFFFFULL}, 0x0000007FFFFFFFFFULL, 8,  32, 8,  digest::hash_t::STREEBOG256, false, false, signer_t::NONE, exchange_t::NONE, digest::hash_t::NONE},
		{suite_t::AES_128_GCM_SHA256,       true,  false, {0ULL, 0ULL, 0ULL}, CLASSIC_LIMIT, CLASSIC_VECTOR, 16, CLASSIC_TAG, digest::hash_t::SHA256, false, false, signer_t::NONE, exchange_t::NONE, digest::hash_t::NONE},
		{suite_t::AES_256_GCM_SHA384,       true,  false, {0ULL, 0ULL, 0ULL}, CLASSIC_LIMIT, CLASSIC_VECTOR, 32, CLASSIC_TAG, digest::hash_t::SHA384, false, false, signer_t::NONE, exchange_t::NONE, digest::hash_t::NONE},
		{suite_t::CHACHA20_POLY1305_SHA256, true,  true,  {0ULL, 0ULL, 0ULL}, STREAM_LIMIT,  CLASSIC_VECTOR, 32, CLASSIC_TAG, digest::hash_t::SHA256, false, false, signer_t::NONE, exchange_t::NONE, digest::hash_t::NONE},
		/**
		 * Наборы SM семейства по RFC 8998: SM4-GCM и SM4-CCM с расписанием на SM3,
		 * вектор замены в двенадцать байтов, ключ и метка по шестнадцать; предел
		 * записей тот же 2^24,5, что у AES-GCM (раздел 5.5 RFC 8446)
		 */
		{suite_t::SM4_GCM_SM3,                true,  false, {0ULL, 0ULL, 0ULL}, CLASSIC_LIMIT, CLASSIC_VECTOR, 16, CLASSIC_TAG, digest::hash_t::SM3, false, false, signer_t::NONE, exchange_t::NONE, digest::hash_t::NONE},
		{suite_t::SM4_CCM_SM3,                true,  false, {0ULL, 0ULL, 0ULL}, CLASSIC_LIMIT, CLASSIC_VECTOR, 16, CLASSIC_TAG, digest::hash_t::SM3, false, true,  signer_t::NONE, exchange_t::NONE, digest::hash_t::NONE},
		/**
		 * Наборы TLS 1.2 (RFC 5289, RFC 7905): у AES-GCM вектор замены занимает четыре байта
		 * соли (раздел 3 RFC 5288), у ChaCha20-Poly1305 - двенадцать (раздел 2 RFC 7905).
		 * Предел записей AES-GCM тот же 2^24,5 (раздел 5.5 RFC 8446): граница стойкости
		 * шифра не зависит от способа сложения одноразового значения, а смены ключей в
		 * TLS 1.2 нет - дойдя до предела, связь закрывается извещением close_notify
		 */
		{suite_t::ECDHE_ECDSA_AES_128_GCM_SHA256,       true, false, {0ULL, 0ULL, 0ULL}, CLASSIC_LIMIT, LEGACY_SALT,    16, CLASSIC_TAG, digest::hash_t::SHA256, true, false, signer_t::ECDSA, exchange_t::ECDHE, digest::hash_t::NONE},
		{suite_t::ECDHE_ECDSA_AES_256_GCM_SHA384,       true, false, {0ULL, 0ULL, 0ULL}, CLASSIC_LIMIT, LEGACY_SALT,    32, CLASSIC_TAG, digest::hash_t::SHA384, true, false, signer_t::ECDSA, exchange_t::ECDHE, digest::hash_t::NONE},
		{suite_t::ECDHE_RSA_AES_128_GCM_SHA256,         true, false, {0ULL, 0ULL, 0ULL}, CLASSIC_LIMIT, LEGACY_SALT,    16, CLASSIC_TAG, digest::hash_t::SHA256, true, false, signer_t::RSA, exchange_t::ECDHE, digest::hash_t::NONE},
		{suite_t::ECDHE_RSA_AES_256_GCM_SHA384,         true, false, {0ULL, 0ULL, 0ULL}, CLASSIC_LIMIT, LEGACY_SALT,    32, CLASSIC_TAG, digest::hash_t::SHA384, true, false, signer_t::RSA, exchange_t::ECDHE, digest::hash_t::NONE},
		{suite_t::ECDHE_RSA_CHACHA20_POLY1305_SHA256,   true, true,  {0ULL, 0ULL, 0ULL}, STREAM_LIMIT, CLASSIC_VECTOR, 32, CLASSIC_TAG, digest::hash_t::SHA256, true, false, signer_t::RSA, exchange_t::ECDHE, digest::hash_t::NONE},
		{suite_t::ECDHE_ECDSA_CHACHA20_POLY1305_SHA256, true, true,  {0ULL, 0ULL, 0ULL}, STREAM_LIMIT, CLASSIC_VECTOR, 32, CLASSIC_TAG, digest::hash_t::SHA256, true, false, signer_t::ECDSA, exchange_t::ECDHE, digest::hash_t::NONE},
		/**
		 * Наборы CBC издания TLS 1.2 (раздел 6.2.3.2 RFC 5246, RFC 5289, RFC 8422, RFC 4279, RFC 5489):
		 * вектор замены явный и в ключевой материал не входит (размер вектора ноль), длина
		 * «метки» есть длина имитовставки HMAC на хеше набора, PRF всюду на SHA-256; предел
		 * записей 2^62 - режим CBC предела стойкости по номеру не ставит, а недостижимый предел
		 * держит заслон номеров живым. Наборы обмена RSA на AES-GCM устроены как ECDHE-наборы
		 */
		{suite_t::ECDHE_ECDSA_AES_128_CBC_SHA256,       true, false, {0ULL, 0ULL, 0ULL}, STREAM_LIMIT, 0, 16, 32, digest::hash_t::SHA256, true, false, signer_t::ECDSA, exchange_t::ECDHE,     digest::hash_t::SHA256},
		{suite_t::ECDHE_RSA_AES_128_CBC_SHA256,         true, false, {0ULL, 0ULL, 0ULL}, STREAM_LIMIT, 0, 16, 32, digest::hash_t::SHA256, true, false, signer_t::RSA,   exchange_t::ECDHE,     digest::hash_t::SHA256},
		{suite_t::ECDHE_ECDSA_AES_128_CBC_SHA,          true, false, {0ULL, 0ULL, 0ULL}, STREAM_LIMIT, 0, 16, 20, digest::hash_t::SHA256, true, false, signer_t::ECDSA, exchange_t::ECDHE,     digest::hash_t::SHA1},
		{suite_t::ECDHE_ECDSA_AES_256_CBC_SHA,          true, false, {0ULL, 0ULL, 0ULL}, STREAM_LIMIT, 0, 32, 20, digest::hash_t::SHA256, true, false, signer_t::ECDSA, exchange_t::ECDHE,     digest::hash_t::SHA1},
		{suite_t::ECDHE_RSA_AES_128_CBC_SHA,            true, false, {0ULL, 0ULL, 0ULL}, STREAM_LIMIT, 0, 16, 20, digest::hash_t::SHA256, true, false, signer_t::RSA,   exchange_t::ECDHE,     digest::hash_t::SHA1},
		{suite_t::ECDHE_RSA_AES_256_CBC_SHA,            true, false, {0ULL, 0ULL, 0ULL}, STREAM_LIMIT, 0, 32, 20, digest::hash_t::SHA256, true, false, signer_t::RSA,   exchange_t::ECDHE,     digest::hash_t::SHA1},
		{suite_t::RSA_AES_128_CBC_SHA,                  true, false, {0ULL, 0ULL, 0ULL}, STREAM_LIMIT, 0, 16, 20, digest::hash_t::SHA256, true, false, signer_t::RSA,   exchange_t::RSA,       digest::hash_t::SHA1},
		{suite_t::RSA_AES_256_CBC_SHA,                  true, false, {0ULL, 0ULL, 0ULL}, STREAM_LIMIT, 0, 32, 20, digest::hash_t::SHA256, true, false, signer_t::RSA,   exchange_t::RSA,       digest::hash_t::SHA1},
		{suite_t::RSA_AES_128_CBC_SHA256,               true, false, {0ULL, 0ULL, 0ULL}, STREAM_LIMIT, 0, 16, 32, digest::hash_t::SHA256, true, false, signer_t::RSA,   exchange_t::RSA,       digest::hash_t::SHA256},
		{suite_t::RSA_AES_256_CBC_SHA256,               true, false, {0ULL, 0ULL, 0ULL}, STREAM_LIMIT, 0, 32, 32, digest::hash_t::SHA256, true, false, signer_t::RSA,   exchange_t::RSA,       digest::hash_t::SHA256},
		{suite_t::RSA_AES_128_GCM_SHA256,               true, false, {0ULL, 0ULL, 0ULL}, CLASSIC_LIMIT, LEGACY_SALT, 16, CLASSIC_TAG, digest::hash_t::SHA256, true, false, signer_t::RSA, exchange_t::RSA, digest::hash_t::NONE},
		{suite_t::RSA_AES_256_GCM_SHA384,               true, false, {0ULL, 0ULL, 0ULL}, CLASSIC_LIMIT, LEGACY_SALT, 32, CLASSIC_TAG, digest::hash_t::SHA384, true, false, signer_t::RSA, exchange_t::RSA, digest::hash_t::NONE},
		{suite_t::PSK_AES_128_CBC_SHA,                  true, false, {0ULL, 0ULL, 0ULL}, STREAM_LIMIT, 0, 16, 20, digest::hash_t::SHA256, true, false, signer_t::NONE,  exchange_t::PSK,       digest::hash_t::SHA1},
		{suite_t::PSK_AES_256_CBC_SHA,                  true, false, {0ULL, 0ULL, 0ULL}, STREAM_LIMIT, 0, 32, 20, digest::hash_t::SHA256, true, false, signer_t::NONE,  exchange_t::PSK,       digest::hash_t::SHA1},
		{suite_t::ECDHE_PSK_AES_128_CBC_SHA,            true, false, {0ULL, 0ULL, 0ULL}, STREAM_LIMIT, 0, 16, 20, digest::hash_t::SHA256, true, false, signer_t::NONE,  exchange_t::ECDHE_PSK, digest::hash_t::SHA1},
		{suite_t::ECDHE_PSK_AES_256_CBC_SHA,            true, false, {0ULL, 0ULL, 0ULL}, STREAM_LIMIT, 0, 32, 20, digest::hash_t::SHA256, true, false, signer_t::NONE,  exchange_t::ECDHE_PSK, digest::hash_t::SHA1},
		{suite_t::ECDHE_PSK_CHACHA20_POLY1305_SHA256,   true, true,  {0ULL, 0ULL, 0ULL}, STREAM_LIMIT, CLASSIC_VECTOR, 32, CLASSIC_TAG, digest::hash_t::SHA256, true, false, signer_t::NONE, exchange_t::ECDHE_PSK, digest::hash_t::NONE}
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
	/**
	 * @brief Метод получения маски равенства двух чисел за постоянное время
	 *
	 * @param first  первое число
	 * @param second второе число
	 *
	 * @return       0xFF при равенстве чисел, 0x00 иначе
	 *
	 */
	static uint8_t same(const size_t first, const size_t second) noexcept {
		// Различие чисел
		const uint64_t diff = (static_cast <uint64_t> (first) ^ static_cast <uint64_t> (second));
		// Выводим маску равенства: старший разряд выражения единичен лишь у нулевого различия
		return static_cast <uint8_t> (0xFF & (0 - (((diff - 1) & ~diff) >> 63)));
	}
	/**
	 * @brief Метод получения маски «первое не меньше второго» за постоянное время
	 *
	 * @param first  первое число
	 * @param second второе число
	 *
	 * @return       0xFF при первом не меньшем второго, 0x00 иначе
	 *
	 * @note Числа не превосходят 2^32: разность двух таких чисел в старший разряд не уходит
	 *
	 */
	static uint8_t atleast(const size_t first, const size_t second) noexcept {
		// Разность чисел: старший разряд единичен при первом меньшем второго
		const uint64_t diff = (static_cast <uint64_t> (first) - static_cast <uint64_t> (second));
		// Выводим маску: обращённый старший разряд, размноженный на весь байт
		return static_cast <uint8_t> (0xFF & (0 - ((~diff) >> 63)));
	}
	/**
	 * @brief Метод счёта сжатий хеша с блоком в 64 байта, покрывающих имитовставку HMAC
	 *
	 * @param length длина сообщения имитовставки без ключевого блока
	 *
	 * @return       число сжатий внутреннего хеша HMAC
	 *
	 * @details Внутренний хеш HMAC обрабатывает блок ключа, сообщение, байт дополнения и
	 *          восемь байтов длины; число сжатий есть их сумма, округлённая вверх до блока
	 *
	 */
	static size_t compressions(const size_t length) noexcept {
		// Выводим число сжатий, покрывающих ключевой блок, сообщение и дополнение
		return ((CBC_COMPRESSION + length + CBC_TRAILER + (CBC_COMPRESSION - 1)) / CBC_COMPRESSION);
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
 * @brief Метод получения длины явной части одноразового значения записи TLS 1.2
 *
 * @param suite набор шифрования
 *
 * @return      восемь байтов у AES-GCM, ноль у ChaCha20-Poly1305 и у наборов TLS 1.3
 *
 */
size_t nts::protect::prefix(const suite_t suite) noexcept {
	// Получаем описание набора шифрования
	const Sample * sample = search(suite);
	// Если набор неизвестен либо принадлежит изданию TLS 1.3
	if((sample == nullptr) || !sample->legacy)
		// Выводим отсутствие явной части
		return 0;
	// Раздел 6.2.3.2 RFC 5246: у наборов CBC явный вектор замены длиною в блок идёт перед шифртекстом
	if(sample->mac != digest::hash_t::NONE)
		// Выводим длину явного вектора замены
		return CBC_BLOCK;
	// Раздел 3 RFC 5288: явная часть есть лишь у AES-GCM издания TLS 1.2; у ChaCha20-Poly1305 её нет (раздел 2 RFC 7905)
	return (sample->stream ? 0 : LEGACY_EXPLICIT);
}
/**
 * @brief Метод получения способа обмена ключами набора шифрования TLS 1.2
 *
 * @param suite набор шифрования
 *
 * @return      способ обмена ключами, NONE у наборов TLS 1.3 и у неизвестного набора
 *
 */
nts::protect::exchange_t nts::protect::exchange(const suite_t suite) noexcept {
	// Получаем описание набора шифрования
	const Sample * sample = search(suite);
	// Выводим способ обмена ключами набора шифрования
	return ((sample != nullptr) ? sample->exchange : exchange_t::NONE);
}
/**
 * @brief Метод получения хеша имитовставки набора шифрования CBC
 *
 * @param suite набор шифрования
 *
 * @return      хеш имитовставки записи, NONE у наборов AEAD и у неизвестного набора
 *
 */
nts::digest::hash_t nts::protect::mac(const suite_t suite) noexcept {
	// Получаем описание набора шифрования
	const Sample * sample = search(suite);
	// Выводим хеш имитовставки набора шифрования
	return ((sample != nullptr) ? sample->mac : digest::hash_t::NONE);
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
		// Если набор шифрования - SM4-GCM либо SM4-CCM по RFC 8998
		if((this->_suite == suite_t::SM4_GCM_SM3) || (this->_suite == suite_t::SM4_CCM_SM3)){
			// Если ключ базового шифра ещё не установлен
			if(!this->_ready){
				// Если ключ базового шифра SM4 установить не удалось
				if(!this->_sm4.key(view_t(this->_key, this->_width)))
					// Выводим отказ подготовки базового шифра
					return error_t::CIPHER;
			}
			// Устанавливаем описание базового шифра SM4
			block = cipher::block_t(this->_sm4);
			// Выводим успешность подготовки базового шифра
			return error_t::NONE;
		}
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
	 * Выполняем сложение вектора замены с порядковым номером записи: не глубже длины
	 * вектора - у наборов издания 1.2 он короче восьми байтов (четыре у AES-GCM, ноль у
	 * CBC), и цикл без границы уходил бы за начало буфера
	 */
	for(size_t i = 0; (i < 8) && (i < this->_size); i++)
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
	// Выводим итог установки ключевого материала без ключа имитовставки
	return this->start(suite, key, vector, view_t(nullptr, 0));
}
/**
 * @brief Метод установки ключевого материала направления связи набора CBC
 *
 * @param suite  устанавливаемый набор шифрования
 * @param key    ключ шифрования направления связи
 * @param vector вектор замены направления связи: у наборов CBC пуст
 * @param mac    ключ имитовставки направления связи длиною в хеш набора
 *
 * @return       признак успешности установки ключевого материала
 *
 */
bool nts::protect::Protection::start(const suite_t suite, const view_t & key, const view_t & vector, const view_t & mac) noexcept {
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
	// Если вектор замены не сходится длиной с вектором набора либо объявлен непустым, но не передан
	if((vector.size != sample->size) || ((vector.size > 0) && (vector.data == nullptr)))
		// Выводим отказ установки ключевого материала
		return false;
	// Длина ключа имитовставки набора: длина хеша имитовставки, ноль у наборов AEAD
	const size_t width = digest::length(sample->mac);
	// Если ключ имитовставки не сходится длиной с хешем набора либо объявлен непустым, но не передан
	if((mac.size != width) || ((mac.size > 0) && (mac.data == nullptr)))
		// Выводим отказ установки ключевого материала
		return false;
	/**
	 * Заслон Lucky13 считает сжатия хеша блоком CBC_COMPRESSION: хеш имитовставки с иным
	 * блоком сжатия выравнивался бы неверно, и набор с таким хешем связью не ведётся
	 */
	if((width > 0) && (digest::block(sample->mac) != CBC_COMPRESSION))
		// Выводим отказ установки ключевого материала
		return false;
	// Запоминаем признак набора CBC
	this->_cbc = (sample->mac != digest::hash_t::NONE);
	// Запоминаем признак набора SM4-CCM
	this->_ccm = sample->ccm;
	// Запоминаем хеш имитовставки набора
	this->_digest = sample->mac;
	// Если ключ имитовставки положен набору
	if(width > 0)
		// Переносим ключ имитовставки направления связи
		::memcpy(this->_mac, mac.data, width);
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
	// Если вектор замены положен набору
	if(vector.size > 0)
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
	/**
	 * Классическим наборам AEAD режим GCM заводится один раз на ключ: таблица кратных
	 * ключа хеширования строится здесь, а заполнение ставится на всякую запись сменой
	 */
	if(this->_classic && !this->_stream && !this->_cbc){
		// Заполнение-заглушка: настоящее ставится на каждую запись
		uint8_t zeros[12];
		// Выполняем обнуление заглушки
		::memset(zeros, 0, sizeof(zeros));
		// Если набор шифрования - SM4-CCM по RFC 8998
		if(this->_ccm){
			// Если режим CCM завести не удалось
			if(!this->_mode.start(block, view_t(zeros, sizeof(zeros)), this->_tag)){
				// Выполняем сброс состояния защиты записей
				this->clear();
				// Выводим отказ установки ключевого материала
				return false;
			}
		// Если режим GCM завести не удалось
		} else if(!this->_gcm.start(block, view_t(zeros, sizeof(zeros)), this->_tag)){
			// Выполняем сброс состояния защиты записей
			this->clear();
			// Выводим отказ установки ключевого материала
			return false;
		}
	}
	/**
	 * Набору ChaCha20-Poly1305 режим заводится один раз на ключ: ключ ставится здесь,
	 * а заполнение ставится на всякую запись сменой - одноразовый ключ имитовставки
	 * вырабатывается заново по заполнению, а не весь режим
	 */
	if(this->_stream){
		// Заполнение-заглушка: настоящее ставится на каждую запись
		uint8_t zeros[12];
		// Выполняем обнуление заглушки
		::memset(zeros, 0, sizeof(zeros));
		// Если режим ChaCha20-Poly1305 завести не удалось
		if(!this->_chachapoly.start(view_t(this->_key, this->_width), view_t(zeros, sizeof(zeros)))){
			// Выполняем сброс состояния защиты записей
			this->clear();
			// Выводим отказ установки ключевого материала
			return false;
		}
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
	// Выполняем сброс базового шифра SM4
	this->_sm4.clear();
	// Выполняем сброс режима GCM: таблица кратных ключа хеширования затирается
	this->_gcm.clear();
	// Выполняем сброс режима ChaCha20-Poly1305: ключ и одноразовый ключ имитовставки затираются
	this->_chachapoly.clear();
	// Выполняем сброс режима CCM
	this->_mode.clear();
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
	// Сбрасываем признак набора CBC
	this->_cbc = false;
	// Сбрасываем порядок «шифрование, затем имитовставка»
	this->_etm = false;
	// Сбрасываем хеш имитовставки набора
	this->_digest = digest::hash_t::NONE;
	// Выполняем затирание ключа имитовставки направления связи
	wipe(this->_mac, sizeof(this->_mac));
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
	// Наборы издания 1.2 ходят лишь обёрткой wrap(): единой записи с присоединёнными данными у них нет
	if(this->_legacy)
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
			// Если заполнение записи установить удалось: ключ режима ставится при заведении ключа
			if(this->_chachapoly.restart(view_t(nonce, this->_size)))
				// Выполняем наложение шифрования с проверкой целостности: содержимое, вид и дополнение шифруются потоком прямо из места вызова
				ok = sealing(this->_chachapoly, associated, data, total, type, padding, cipher);
		// Если набор шифрования - SM4-CCM по RFC 8998
		} else if(this->_ccm) {
			// Открытый текст записи вместе с видом содержимого и дополнением: режиму CCM он нужен целиком
			vector <uint8_t> plain(length, 0);
			// Если содержимое записи передано
			if(total > 0)
				// Переносим содержимое записи в открытый текст
				::memcpy(plain.data(), data.data, total);
			// Записываем истинный вид содержимого следом за содержимым
			plain[total] = static_cast <uint8_t> (type);
			// Если заполнение записи установить удалось
			if(this->_mode.restart(view_t(nonce, this->_size)))
				// Выполняем наложение шифрования с проверкой целостности
				ok = this->_mode.encrypt(associated, view_t(plain.data(), plain.size()), cipher, (cipher + length));
			// Выполняем затирание открытого текста записи
			wipe(plain.data(), plain.size());
		// Если набор шифрования классический на AES-GCM либо SM4-GCM
		} else if(this->_classic) {
			// Если заполнение записи установить удалось: таблица режима построена при заведении ключа
			if(this->_gcm.restart(view_t(nonce, this->_size)))
				// Выполняем наложение шифрования с проверкой целостности
				ok = sealing(this->_gcm, associated, data, total, type, padding, cipher);
		// Если набор шифрования на алгоритмах ГОСТ
		} else {
			// Открытый текст записи вместе с видом содержимого и дополнением: режиму MGM он нужен целиком
			vector <uint8_t> plain(length, 0);
			// Если содержимое записи передано
			if(total > 0)
				// Переносим содержимое записи в открытый текст
				::memcpy(plain.data(), data.data, total);
			// Записываем истинный вид содержимого следом за содержимым
			plain[total] = static_cast <uint8_t> (type);
			// Объект режима MGM
			cipher::galois_t galois;
			// Если режим MGM запустить удалось
			if(galois.start(block, view_t(nonce, this->_size), this->_tag))
				// Выполняем наложение шифрования с проверкой целостности
				ok = galois.encrypt(associated, view_t(plain.data(), plain.size()), cipher, (cipher + length));
			// Выполняем затирание открытого текста записи
			wipe(plain.data(), plain.size());
		}
		// Если наложить шифрование не удалось
		if(!ok){
			// Возвращаем накопитель к прежней длине
			result.resize(offset);
			// Запоминаем отказ базового шифра
			outcome = error_t::CIPHER;
		}
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
	// Наборы издания 1.2 ходят лишь обёрткой unwrap(): единой записи с присоединёнными данными у них нет
	if(this->_legacy)
		// Выводим отказ снятия защиты
		return error_t::STATE;
	// Если связанные данные не переданы
	if((associated.data == nullptr) || (associated.size == 0))
		// Выводим отказ снятия защиты
		return error_t::LENGTH;
	/**
	 * Раздел 5.5 RFC 8446: предел записей на ключе - обязанность отправителя, и на
	 * приёме он не судится: иначе собеседник, не сменивший ключи, молча отбрасывался бы
	 * поверх дейтаграмм с записи за пределом, а потоком - обрывался
	 */
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
		// Смещение открытого содержимого записи в накопителе
		const size_t offset = result.size();
		// Занимаем место под открытый текст записи вместе с видом содержимого и дополнением
		result.resize(offset + length, 0);
		// Место, в которое помещается открытый текст записи
		uint8_t * plain = (result.data() + offset);
		// Признак успешности снятия шифрования с проверкой целостности
		bool ok = false;
		// Если набор шифрования - ChaCha20-Poly1305
		if(this->_stream){
			// Если заполнение записи установить удалось: ключ режима ставится при заведении ключа
			if(this->_chachapoly.restart(view_t(nonce, this->_size)))
				// Выполняем снятие шифрования с проверкой целостности прямо в накопитель
				ok = this->_chachapoly.decrypt(associated, view_t(data.data, length), plain, view_t((data.data + length), this->_tag));
		// Если набор шифрования - SM4-CCM по RFC 8998
		} else if(this->_ccm) {
			// Если заполнение записи установить удалось
			if(this->_mode.restart(view_t(nonce, this->_size)))
				// Выполняем снятие шифрования с проверкой целостности прямо в накопитель
				ok = this->_mode.decrypt(associated, view_t(data.data, length), view_t((data.data + length), this->_tag), plain);
		// Если набор шифрования классический на AES-GCM либо SM4-GCM
		} else if(this->_classic) {
			/**
			 * Снятие защиты идёт поточными вызовами: слитое ядро режима считает хеш и снимает
			 * гамму одним проходом, а метка сверяется в конце; при расхождении расшифрованное
			 * затирается ниже вместе с хвостом записи
			 */
			ok = (this->_gcm.restart(view_t(nonce, this->_size)) && this->_gcm.associate(associated) && this->_gcm.decrypt(view_t(data.data, length), plain) && this->_gcm.verify(view_t((data.data + length), this->_tag)));
		// Если набор шифрования на алгоритмах ГОСТ
		} else {
			// Объект режима MGM
			cipher::galois_t galois;
			// Если режим MGM запустить удалось
			if(galois.start(block, view_t(nonce, this->_size), this->_tag))
				// Выполняем снятие шифрования с проверкой целостности прямо в накопитель
				ok = galois.decrypt(associated, view_t(data.data, length), plain, view_t((data.data + length), this->_tag));
		}
		// Длина открытого содержимого записи без дополнения и вида: ноль остаётся при отказе
		size_t inner = 0;
		// Если метка целостности записи не сошлась
		if(!ok)
			// Запоминаем отказ метки целостности
			outcome = error_t::TAG;
		// Если защита снята
		else {
			// Смещение истинного вида содержимого в открытом тексте
			size_t position = length;
			/**
			 * Выполняем пропуск дополнения с конца открытого текста
			 */
			while((position > 0) && (plain[position - 1] == 0x00))
				// Уменьшаем смещение истинного вида содержимого
				position--;
			// Если истинного вида содержимого в открытом тексте нет
			if(position == 0)
				// Запоминаем отказ вида содержимого
				outcome = error_t::TYPE;
			// Если истинный вид содержимого найден
			else {
				// Получаем истинный вид содержимого записи
				const record::type_t found = static_cast <record::type_t> (plain[position - 1]);
				// Если вид содержимого протоколом не определён
				if(!record::known(found))
					// Запоминаем отказ вида содержимого
					outcome = error_t::TYPE;
				// Если вид содержимого протоколом определён
				else {
					// Устанавливаем истинный вид содержимого записи
					type = found;
					// Запоминаем длину открытого содержимого записи
					inner = (position - 1);
				}
			}
		}
		// Выполняем затирание хвоста открытого текста: вида и дополнения, а при отказе - всего расшифрованного
		wipe(plain + inner, (length - inner));
		// Возвращаем накопитель к длине открытого содержимого: при отказе - к прежней
		result.resize(offset + inner);
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
 * @param version  издание протокола из заголовка записи
 * @param length   длина открытого содержимого записи
 * @param result   место, в которое помещаются связанные данные
 *
 */
void nts::protect::Protection::associate(const uint64_t sequence, const record::type_t type, const record::version_t version, const size_t length, uint8_t * result) const noexcept {
	// Записываем порядковый номер записи от старшего байта к младшему
	number(sequence, result);
	// Записываем вид содержимого записи
	result[8] = static_cast <uint8_t> (type);
	/**
	 * Раздел 6.2.3.3 RFC 5246: издание идёт в связанные данные таким, каким лежит в
	 * заголовке записи по проводу, - подмена заголовка обязана рвать метку целостности
	 */
	result[9] = static_cast <uint8_t> ((static_cast <uint16_t> (version) >> 8) & 0xFF);
	// Записываем младший байт издания протокола из заголовка записи
	result[10] = static_cast <uint8_t> (static_cast <uint16_t> (version) & 0xFF);
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
	// Заголовок защищённой записи: вид содержимого идёт открыто
	record::header_t header;
	// Устанавливаем вид содержимого защищённой записи
	header.type = type;
	// Устанавливаем издание протокола защищённой записи
	header.version = record::version_t::TLS12;
	// Место, в которое записывается заголовок защищённой записи
	uint8_t written[record::RECORD_HEADER];
	// Смещение защищённой записи в накопителе
	const size_t offset = result.size();
	/**
	 * Выполняем складывание места под заголовок защищённой записи в накопитель: длина
	 * содержимого у наборов CBC известна лишь по наложении защиты (дополнение до блока)
	 */
	try {
		// Занимаем место под заголовок защищённой записи
		result.resize(offset + record::RECORD_HEADER, 0);
	/**
	 * Если памяти под накопитель не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Выводим отказ нехватки памяти
		return error_t::MEMORY;
	}
	// Итог наложения защиты на запись порядковым номером связи
	const error_t outcome = this->wrap(this->_sequence, header.version, type, data, result);
	// Если защиту наложить не удалось
	if(outcome != error_t::NONE){
		// Возвращаем накопитель к прежней длине
		result.resize(offset);
		// Выводим отказ наложения защиты
		return outcome;
	}
	// Устанавливаем длину содержимого защищённой записи: явная часть, шифртекст и метка
	header.size = (result.size() - offset - record::RECORD_HEADER);
	// Если заголовок защищённой записи составить не удалось
	if(record::build(header, written) != record::error_t::NONE){
		// Возвращаем накопитель к прежней длине
		result.resize(offset);
		// Выводим отказ наложения защиты
		return error_t::LENGTH;
	}
	// Переносим заголовок защищённой записи на занятое место
	::memcpy(result.data() + offset, written, record::RECORD_HEADER);
	// Увеличиваем порядковый номер очередной записи
	this->_sequence++;
	// Выводим успешность наложения защиты на запись
	return error_t::NONE;
}
/**
 * @brief Метод наложения защиты на запись издания TLS 1.2 с заданными номером и изданием
 *
 * @param sequence порядковый номер записи: младшие 48 разрядов - номер, старшие 16 - пора ключей DTLS
 * @param version  издание протокола из заголовка записи по проводу
 * @param type     вид содержимого защищаемой записи
 * @param data     защищаемое содержимое записи
 * @param result   накопитель, в конец которого дописываются явная часть, шифртекст и метка
 *
 * @return         отказ наложения защиты на запись
 *
 */
nts::protect::error_t nts::protect::Protection::wrap(const uint64_t sequence, const record::version_t version, const record::type_t type, const view_t & data, vector <uint8_t> & result) noexcept {
	// Если ключевой материал не установлен
	if(!this->_ready)
		// Выводим отказ негодного состояния
		return error_t::STATE;
	// Если набор шифрования не принадлежит изданию TLS 1.2
	if(!this->_legacy)
		// Выводим отказ негодного состояния
		return error_t::STATE;
	// Если вид содержимого записи протоколом не определён
	if(!record::known(type))
		// Выводим отказ наложения защиты
		return error_t::TYPE;
	// Раздел 4.1 RFC 6347: порядковый номер записи занимает сорок восемь разрядов, и предел набора судится по нему
	if((sequence & LEGACY_ORDINAL) > this->_limit)
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
	// Если набор шифрования - набор CBC: запись складывается по разделу 6.2.3.2 RFC 5246
	if(this->_cbc)
		// Выводим итог наложения защиты на запись набора CBC
		return this->chain(sequence, version, type, data, result);
	/**
	 * Раздел 3 RFC 5288: у AES-GCM перед шифртекстом идёт явная часть одноразового
	 * значения в восемь байтов; у ChaCha20-Poly1305 (раздел 2 RFC 7905) явной части нет
	 */
	const size_t prefix = (this->_stream ? 0 : LEGACY_EXPLICIT);
	// Описание базового шифра записи
	cipher::block_t block;
	// Выполняем подготовку базового шифра к защите записи
	const error_t error = this->prepare(sequence, block);
	// Если базовый шифр подготовить не удалось
	if(error != error_t::NONE)
		// Выводим отказ наложения защиты
		return error;
	// Место, в которое помещаются связанные данные записи
	uint8_t associated[LEGACY_ASSOCIATED];
	// Составляем связанные данные записи: раздел 6.2.3.3 RFC 5246 и раздел 4.1.2.1 RFC 6347
	this->associate(sequence, type, version, total, associated);
	// Место, в которое помещается одноразовое значение записи
	uint8_t nonce[PROTECT_VECTOR];
	// Если набор шифрования - ChaCha20-Poly1305
	if(this->_stream)
		// Раздел 2 RFC 7905: одноразовое значение есть вектор замены, сложенный с номером записи
		this->nonce(sequence, nonce);
	// Если набор шифрования - AES-GCM
	else {
		// Раздел 3 RFC 5288: одноразовое значение есть соль и явная часть - порядковый номер записи
		::memcpy(nonce, this->_vector, LEGACY_SALT);
		// Записываем явную часть одноразового значения
		number(sequence, nonce + LEGACY_SALT);
	}
	// Смещение защищённой записи в накопителе
	const size_t offset = result.size();
	// Итог наложения защиты на запись
	error_t outcome = error_t::NONE;
	/**
	 * Выполняем складывание защищённой записи в накопитель
	 */
	try {
		// Занимаем место под явную часть, шифртекст и метку целостности
		result.resize(offset + prefix + total + this->_tag, 0);
		// Если явная часть одноразового значения положена
		if(prefix > 0)
			// Переносим явную часть одноразового значения
			::memcpy(result.data() + offset, nonce + LEGACY_SALT, prefix);
		// Место, в которое помещается шифртекст записи
		uint8_t * cipher = (result.data() + offset + prefix);
		// Признак успешности наложения шифрования с проверкой целостности
		bool ok = false;
		// Если набор шифрования - ChaCha20-Poly1305
		if(this->_stream){
			// Если заполнение записи установить удалось: ключ режима ставится при заведении ключа
			if(this->_chachapoly.restart(view_t(nonce, this->_size)))
				// Выполняем наложение шифрования с проверкой целостности
				ok = this->_chachapoly.encrypt(view_t(associated, sizeof(associated)), view_t(data.data, total), cipher, (cipher + total));
		// Если набор шифрования - AES-GCM
		} else {
			// Если режим GCM запустить не удалось
			if(this->_gcm.restart(view_t(nonce, LEGACY_SALT + LEGACY_EXPLICIT)))
				// Выполняем наложение шифрования с проверкой целостности
				ok = this->_gcm.encrypt(view_t(associated, sizeof(associated)), view_t(data.data, total), cipher, (cipher + total));
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
	// Раздел 5.5 RFC 8446: предел записей на ключе - обязанность отправителя; на приёме судится лишь исчерпание самого номера (круг 7)
	if(this->_sequence == UINT64_MAX)
		// Выводим отказ снятия защиты
		return error_t::SEQUENCE;
	// Если содержимое записи не передано либо не сходится длиной с заголовком
	if((data.data == nullptr) || (data.size != header.size))
		// Выводим отказ снятия защиты
		return error_t::LENGTH;
	// Итог снятия защиты порядковым номером связи
	const error_t outcome = this->unwrap(this->_sequence, header.version, header.type, data, result);
	// Если защиту снять не удалось
	if(outcome != error_t::NONE)
		// Выводим отказ снятия защиты
		return outcome;
	// Устанавливаем вид содержимого записи из её заголовка
	type = header.type;
	// Увеличиваем порядковый номер очередной записи
	this->_sequence++;
	// Выводим успешность снятия защиты с записи
	return error_t::NONE;
}
/**
 * @brief Метод снятия защиты с записи издания TLS 1.2 с заданными номером и изданием
 *
 * @param sequence порядковый номер записи: младшие 48 разрядов - номер, старшие 16 - пора ключей DTLS
 * @param version  издание протокола из заголовка записи по проводу
 * @param type     вид содержимого записи из её заголовка
 * @param data     защищённое содержимое записи: явная часть, шифртекст и метка
 * @param result   накопитель, в конец которого дописывается открытое содержимое записи
 *
 * @return         отказ снятия защиты с записи
 *
 */
nts::protect::error_t nts::protect::Protection::unwrap(const uint64_t sequence, const record::version_t version, const record::type_t type, const view_t & data, vector <uint8_t> & result) noexcept {
	// Если ключевой материал не установлен
	if(!this->_ready)
		// Выводим отказ негодного состояния
		return error_t::STATE;
	// Если набор шифрования не принадлежит изданию TLS 1.2
	if(!this->_legacy)
		// Выводим отказ негодного состояния
		return error_t::STATE;
	// Раздел 5.5 RFC 8446: предел записей на ключе - обязанность отправителя, на приёме он не судится (круг 7)
	// Если вид содержимого записи протоколом не определён
	if(!record::known(type))
		// Выводим отказ снятия защиты
		return error_t::TYPE;
	// Если содержимое записи не передано
	if(data.data == nullptr)
		// Выводим отказ снятия защиты
		return error_t::LENGTH;
	// Если набор шифрования - набор CBC: запись разбирается по разделу 6.2.3.2 RFC 5246
	if(this->_cbc)
		// Выводим итог снятия защиты с записи набора CBC
		return this->unchain(sequence, version, type, data, result);
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
	if((length == 0) && !record::empty(type))
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
	// Место, в которое помещаются связанные данные записи
	uint8_t associated[LEGACY_ASSOCIATED];
	// Составляем связанные данные записи: раздел 6.2.3.3 RFC 5246 и раздел 4.1.2.1 RFC 6347
	this->associate(sequence, type, version, length, associated);
	// Место, в которое помещается одноразовое значение записи
	uint8_t nonce[PROTECT_VECTOR];
	// Если набор шифрования - ChaCha20-Poly1305
	if(this->_stream)
		// Раздел 2 RFC 7905: одноразовое значение есть вектор замены, сложенный с номером записи
		this->nonce(sequence, nonce);
	// Если набор шифрования - AES-GCM
	else {
		/**
		 * Раздел 3 RFC 5288: явная часть одноразового значения берётся из самой записи -
		 * собеседник вправе слать её любой, лишь бы не повторял. С порядковым номером она
		 * не сличается намеренно: openssl начинает её случайным значением, а не номером,
		 * повтор же записи отвергается порядковым номером в связанных данных
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
			// Если заполнение записи установить удалось: ключ режима ставится при заведении ключа
			if(this->_chachapoly.restart(view_t(nonce, this->_size)))
				// Выполняем снятие шифрования с проверкой целостности
				ok = this->_chachapoly.decrypt(view_t(associated, sizeof(associated)), view_t(data.data + prefix, length), plain.data(), view_t((data.data + prefix + length), this->_tag));
		// Если набор шифрования - AES-GCM
		} else {
			// Если режим GCM запустить не удалось
			if(this->_gcm.restart(view_t(nonce, LEGACY_SALT + LEGACY_EXPLICIT)))
				// Выполняем снятие шифрования с проверкой целостности
				ok = this->_gcm.decrypt(view_t(associated, sizeof(associated)), view_t(data.data + prefix, length), plain.data(), view_t((data.data + prefix + length), this->_tag));
		}
		// Если метка целостности записи не сошлась
		if(!ok)
			// Запоминаем отказ метки целостности
			outcome = error_t::TAG;
		// Если защита снята
		else
			// Складываем открытое содержимое записи в накопитель
			result.insert(result.end(), plain.data(), (plain.data() + length));
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
 * @brief Метод установки порядка «шифрование, затем имитовставка»
 *
 * @param etm ведётся ли защита записей CBC по RFC 7366
 *
 */
void nts::protect::Protection::etm(const bool etm) noexcept {
	// Запоминаем порядок защиты записей CBC
	this->_etm = etm;
}
/**
 * @brief Метод проверки порядка «шифрование, затем имитовставка»
 *
 * @return признак защиты записей CBC по RFC 7366
 *
 */
bool nts::protect::Protection::etm() const noexcept {
	// Выводим порядок защиты записей CBC
	return this->_etm;
}
/**
 * @brief Метод наложения защиты на запись набора CBC
 *
 * @param sequence порядковый номер записи в связанных данных
 * @param version  издание протокола из заголовка записи по проводу
 * @param type     вид содержимого защищаемой записи
 * @param data     защищаемое содержимое записи
 * @param result   накопитель, в конец которого дописываются вектор замены, шифртекст и имитовставка
 *
 * @return         отказ наложения защиты на запись
 *
 */
nts::protect::error_t nts::protect::Protection::chain(const uint64_t sequence, const record::version_t version, const record::type_t type, const view_t & data, vector <uint8_t> & result) noexcept {
	// Длина защищаемого содержимого записи
	const size_t total = ((data.data != nullptr) ? data.size : 0);
	// Длина имитовставки набора
	const size_t width = digest::length(this->_digest);
	// Описание базового шифра записи
	cipher::block_t block;
	// Выполняем подготовку базового шифра к защите записи
	const error_t error = this->prepare(sequence, block);
	// Если базовый шифр подготовить не удалось
	if(error != error_t::NONE)
		// Выводим отказ наложения защиты
		return error;
	// Место, в которое помещается явный вектор замены записи
	uint8_t iv[CBC_BLOCK];
	// Раздел 6.2.3.2 RFC 5246: вектор замены случаен на всякую запись и непредсказуем
	if(!entropy::bytes(iv, sizeof(iv)))
		// Выводим отказ базового шифра
		return error_t::CIPHER;
	/**
	 * Раздел 6.2.3.2 RFC 5246: в порядке MAC-then-encrypt шифруются содержимое, имитовставка
	 * и дополнение; раздел 2 RFC 7366: в порядке encrypt-then-MAC шифруются содержимое и
	 * дополнение, а имитовставка кладётся поверх вектора замены и шифртекста
	 */
	const size_t inner = (total + (this->_etm ? 0 : width) + 1);
	// Длина дополнения без байта длины: до кратного блоку
	const size_t padding = ((CBC_BLOCK - (inner % CBC_BLOCK)) % CBC_BLOCK);
	// Длина шифруемого текста
	const size_t length = (inner + padding);
	// Смещение защищённой записи в накопителе
	const size_t offset = result.size();
	// Итог наложения защиты на запись
	error_t outcome = error_t::NONE;
	/**
	 * Открытый текст записи складывается в памяти: длина его задана содержимым, и памяти
	 * под неё может не хватить
	 */
	try {
		// Открытый текст записи: содержимое, имитовставка (MAC-then-encrypt) и дополнение
		vector <uint8_t> plain(length, static_cast <uint8_t> (padding));
		// Если содержимое записи передано
		if(total > 0)
			// Переносим содержимое записи в открытый текст
			::memcpy(plain.data(), data.data, total);
		// Место, в которое помещаются связанные данные записи
		uint8_t associated[LEGACY_ASSOCIATED];
		// Объект выработки имитовставки записи
		digest::mac_t mac;
		// Если ключ имитовставки установить не удалось
		if(!mac.start(this->_digest, view_t(this->_mac, width)))
			// Выводим отказ базового шифра
			return error_t::CIPHER;
		// Если порядок «имитовставка, затем шифрование»
		if(!this->_etm){
			// Составляем связанные данные записи с длиной содержимого: раздел 6.2.3.1 RFC 5246
			this->associate(sequence, type, version, total, associated);
			// Подаём связанные данные имитовставке
			mac.update(view_t(associated, sizeof(associated)));
			// Подаём содержимое записи имитовставке
			mac.update(view_t(plain.data(), total));
			// Если имитовставку над содержимым снять не удалось
			if(!mac.finish(plain.data() + total, width)){
				// Выполняем затирание открытого текста записи
				wipe(plain.data(), plain.size());
				// Выводим отказ базового шифра
				return error_t::CIPHER;
			}
		}
		// Занимаем место под вектор замены, шифртекст и имитовставку (encrypt-then-MAC)
		result.resize(offset + CBC_BLOCK + length + (this->_etm ? width : 0), 0);
		// Переносим явный вектор замены
		::memcpy(result.data() + offset, iv, sizeof(iv));
		// Объект режима простой замены с зацеплением
		cipher::chaining_t chaining;
		// Если режим запустить либо зашифровать открытый текст не удалось
		if(!chaining.start(block, view_t(iv, sizeof(iv))) || !chaining.encrypt(view_t(plain.data(), plain.size()), result.data() + offset + CBC_BLOCK)){
			// Возвращаем накопитель к прежней длине
			result.resize(offset);
			// Запоминаем отказ базового шифра
			outcome = error_t::CIPHER;
		// Если порядок «шифрование, затем имитовставка»
		} else if(this->_etm) {
			// Составляем связанные данные записи с длиной вектора замены и шифртекста: раздел 2 RFC 7366
			this->associate(sequence, type, version, (CBC_BLOCK + length), associated);
			// Подаём связанные данные имитовставке
			mac.update(view_t(associated, sizeof(associated)));
			// Подаём вектор замены и шифртекст имитовставке
			mac.update(view_t(result.data() + offset, (CBC_BLOCK + length)));
			// Если имитовставку над шифртекстом снять не удалось
			if(!mac.finish(result.data() + offset + CBC_BLOCK + length, width)){
				// Возвращаем накопитель к прежней длине
				result.resize(offset);
				// Запоминаем отказ базового шифра
				outcome = error_t::CIPHER;
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
	// Выводим итог наложения защиты на запись
	return outcome;
}
/**
 * @brief Метод снятия защиты с записи набора CBC
 *
 * @param sequence порядковый номер записи в связанных данных
 * @param version  издание протокола из заголовка записи по проводу
 * @param type     вид содержимого записи из её заголовка
 * @param data     защищённое содержимое записи: вектор замены, шифртекст и имитовставка
 * @param result   накопитель, в конец которого дописывается открытое содержимое записи
 *
 * @return         отказ снятия защиты с записи
 *
 */
nts::protect::error_t nts::protect::Protection::unchain(const uint64_t sequence, const record::version_t version, const record::type_t type, const view_t & data, vector <uint8_t> & result) noexcept {
	// Длина имитовставки набора
	const size_t width = digest::length(this->_digest);
	/**
	 * Раздел 6.2.3.2 RFC 5246: за вектором замены идёт шифртекст целым числом блоков, в
	 * порядке MAC-then-encrypt не короче имитовставки с байтом длины дополнения; раздел 2
	 * RFC 7366: в порядке encrypt-then-MAC имитовставка идёт открытой за шифртекстом
	 */
	const size_t least = (CBC_BLOCK + (this->_etm ? (CBC_BLOCK + width) : (width + 1)));
	// Если содержимое записи короче наименьшего дозволенного
	if(data.size < least)
		// Выводим отказ снятия защиты
		return error_t::LENGTH;
	// Длина шифртекста без вектора замены и открытой имитовставки
	const size_t length = (data.size - CBC_BLOCK - (this->_etm ? width : 0));
	// Если шифртекст не кратен блоку
	if((length % CBC_BLOCK) != 0)
		// Выводим отказ снятия защиты
		return error_t::LENGTH;
	// Раздел 6.2.3.2 RFC 5246: содержимое, имитовставка и дополнение не шире 2^14 + 2048 байтов
	if(length > (record::RECORD_PLAINTEXT + CBC_PADDING + width))
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
	// Место, в которое помещаются связанные данные записи
	uint8_t associated[LEGACY_ASSOCIATED];
	// Место, в которое помещается ожидаемая имитовставка записи
	uint8_t expected[PROTECT_MAC];
	// Обнуляем ожидаемую имитовставку
	::memset(expected, 0, sizeof(expected));
	// Если порядок «шифрование, затем имитовставка»: раздел 2 RFC 7366 велит сличать имитовставку прежде расшифрования
	if(this->_etm){
		// Объект выработки имитовставки записи
		digest::mac_t mac;
		// Если ключ имитовставки установить не удалось
		if(!mac.start(this->_digest, view_t(this->_mac, width)))
			// Выводим отказ базового шифра
			return error_t::CIPHER;
		// Составляем связанные данные записи с длиной вектора замены и шифртекста
		this->associate(sequence, type, version, (CBC_BLOCK + length), associated);
		// Подаём связанные данные имитовставке
		mac.update(view_t(associated, sizeof(associated)));
		// Подаём вектор замены и шифртекст имитовставке
		mac.update(view_t(data.data, (CBC_BLOCK + length)));
		// Если ожидаемую имитовставку снять не удалось
		if(!mac.finish(expected, width)){
			// Выполняем затирание ожидаемой имитовставки
			wipe(expected, sizeof(expected));
			// Выводим отказ базового шифра
			return error_t::CIPHER;
		}
		// Если принятая имитовставка не сошлась с ожидаемой: сличение за постоянное время
		if(!message::compare(view_t(data.data + CBC_BLOCK + length, width), view_t(expected, width))){
			// Выполняем затирание ожидаемой имитовставки
			wipe(expected, sizeof(expected));
			// Выводим отказ метки целостности
			return error_t::TAG;
		}
	}
	// Итог снятия защиты с записи
	error_t outcome = error_t::NONE;
	/**
	 * Открытый текст записи складывается в памяти: длина его задана записью, и памяти
	 * под неё может не хватить
	 */
	try {
		// Открытый текст записи: содержимое, имитовставка и дополнение
		vector <uint8_t> plain(length, 0);
		// Объект режима простой замены с зацеплением
		cipher::chaining_t chaining;
		// Если режим запустить либо расшифровать шифртекст не удалось
		if(!chaining.start(block, view_t(data.data, CBC_BLOCK)) || !chaining.decrypt(view_t(data.data + CBC_BLOCK, length), plain.data())){
			// Выполняем затирание открытого текста записи
			wipe(plain.data(), plain.size());
			// Выполняем затирание ожидаемой имитовставки
			wipe(expected, sizeof(expected));
			// Выводим отказ базового шифра
			return error_t::CIPHER;
		}
		// Длина открытого содержимого записи
		size_t total = 0;
		// Снимаем дополнение и имитовставку за постоянное время: одна маска решает судьбу записи
		const uint8_t good = this->uncover(sequence, version, type, plain.data(), length, total);
		// Если дополнение либо имитовставка не сошлись
		if(good != 0xFF)
			// Запоминаем отказ метки целостности
			outcome = error_t::TAG;
		// Раздел 6.2.1 RFC 5246: открытое содержимое записи не шире 2^14 байтов
		else if(total > record::RECORD_PLAINTEXT)
			// Запоминаем отказ длины
			outcome = error_t::LENGTH;
		// Если содержимое пусто, а вид записи пустоты не дозволяет
		else if((total == 0) && !record::empty(type))
			// Запоминаем отказ длины
			outcome = error_t::LENGTH;
		// Если защита снята
		else
			// Складываем открытое содержимое записи в накопитель
			result.insert(result.end(), plain.data(), (plain.data() + total));
		// Выполняем затирание открытого текста записи
		wipe(plain.data(), plain.size());
	/**
	 * Если памяти под открытый текст либо накопитель не хватило
	 */
	} catch(const std::bad_alloc &) {
		// Запоминаем отказ нехватки памяти
		outcome = error_t::MEMORY;
	}
	// Выполняем затирание ожидаемой имитовставки
	wipe(expected, sizeof(expected));
	// Выводим итог снятия защиты с записи
	return outcome;
}
/**
 * @brief Метод снятия дополнения и имитовставки с расшифрованного текста записи CBC за постоянное время
 *
 * @param sequence порядковый номер записи
 * @param version  издание протокола из заголовка записи
 * @param type     вид содержимого записи
 * @param plain    расшифрованный текст записи: содержимое, имитовставка (MAC-then-encrypt) и дополнение
 * @param length   длина расшифрованного текста
 * @param total    место, в которое помещается длина открытого содержимого
 *
 * @return         маска годности: 0xFF при сошедшихся дополнении и имитовставке, 0x00 иначе
 *
 * @details Таблица масок суждения, все за постоянное время:
 *          - good    = atleast(length, padding + 1 + covered): дополнение с байтом длины и имитовставкой умещается;
 *          - inside  = atleast(declared, i): байт с номером i от конца входит в дополнение;
 *          - same(plain[length - 1 - i], declared) | ~inside: байт дополнения равен длине либо в дополнение не входит;
 *          - same(j, total + k): байт открытого текста с номером j лежит на месте байта k имитовставки;
 *          - same(diff, 0): ожидаемая и принятая имитовставки сошлись по всем байтам.
 *          Ветвей по секрету нет: перебор дополнения идёт по окну в CBC_PADDING байтов, извлечение
 *          имитовставки - по окну в MAC + CBC_PADDING байтов, а сжатия хеша выравниваются холостыми
 *
 */
uint8_t nts::protect::Protection::uncover(const uint64_t sequence, const record::version_t version, const record::type_t type, const uint8_t * plain, const size_t length, size_t & total) noexcept {
	// Длина имитовставки набора
	const size_t width = digest::length(this->_digest);
	// Длина дополнения без байта длины: последний байт открытого текста
	const size_t padding = plain[length - 1];
	// Длина хвоста, покрываемого дополнением: имитовставка при MAC-then-encrypt
	const size_t covered = (this->_etm ? 0 : width);
	/**
	 * Раздел 6.2.3.2 RFC 5246: дополнение с байтом длины и имитовставкой обязано
	 * умещаться в открытый текст; суждение идёт под маской без ранних выходов, чтобы
	 * время не выдавало длину дополнения (Lucky13)
	 */
	uint8_t good = atleast(length, (padding + 1 + covered));
	// Длина дополнения, обращённая в ноль при негодной: дальнейшие расчёты идут по ней
	const size_t declared = (padding & good);
	// Наибольшее число байтов дополнения, доступных сверке: не дальше начала открытого текста
	const size_t scope = ((length < CBC_PADDING) ? length : CBC_PADDING);
	/**
	 * Выполняем сверку всех байтов дополнения: раздел 6.2.3.2 RFC 5246 велит сверять
	 * каждый байт, а перебор идёт по всему окну независимо от длины дополнения
	 */
	for(size_t i = 1; i < scope; i++){
		// Маска «байт входит в дополнение»: номер с конца не больше объявленной длины
		const uint8_t inside = atleast(declared, i);
		// Учитываем расхождение байта дополнения с объявленной длиной под маской
		good = static_cast <uint8_t> (good & (same(plain[length - 1 - i], declared) | static_cast <uint8_t> (~inside)));
	}
	// Вычисляем длину открытого содержимого записи
	total = (length - declared - 1 - covered);
	// Если порядок «шифрование, затем имитовставка»: имитовставка сличена до расшифрования
	if(this->_etm)
		// Выводим маску годности дополнения
		return good;
	// Место, в которое помещаются связанные данные записи
	uint8_t associated[LEGACY_ASSOCIATED];
	// Место, в которое помещается ожидаемая имитовставка записи
	uint8_t expected[PROTECT_MAC];
	// Место, в которое помещается принятая имитовставка записи
	uint8_t received[PROTECT_MAC];
	// Обнуляем ожидаемую имитовставку
	::memset(expected, 0, sizeof(expected));
	// Обнуляем принятую имитовставку
	::memset(received, 0, sizeof(received));
	// Объект выработки имитовставки записи
	digest::mac_t mac;
	// Маска «имитовставка выработана»: отказ ключа либо хеша обращает годность в ноль
	uint8_t produced = static_cast <uint8_t> (0 - static_cast <uint8_t> (mac.start(this->_digest, view_t(this->_mac, width))));
	// Составляем связанные данные записи с длиной содержимого
	this->associate(sequence, type, version, total, associated);
	// Подаём связанные данные имитовставке
	mac.update(view_t(associated, sizeof(associated)));
	// Подаём содержимое записи имитовставке
	mac.update(view_t(plain, total));
	// Учитываем выработку ожидаемой имитовставки
	produced = static_cast <uint8_t> (produced & static_cast <uint8_t> (0 - static_cast <uint8_t> (mac.finish(expected, width))));
	/**
	 * Число сжатий хеша зависит от длины содержимого, а она секретна: недостающие до
	 * наибольшей длины сжатия отрабатываются вхолостую, и время выработки имитовставки
	 * перестаёт выдавать длину дополнения (RFC 7366 раздел 2 отсылает к тому же приёму)
	 */
	const size_t extra = (compressions(LEGACY_ASSOCIATED + (length - 1 - covered)) - compressions(LEGACY_ASSOCIATED + total));
	// Объект холостого хеширования
	digest::hasher_t idle(this->_digest);
	// Блок холостого хеширования
	const uint8_t filler[CBC_COMPRESSION] = {0};
	/**
	 * Выполняем холостые сжатия хеша
	 */
	for(size_t i = 0; i < extra; i++)
		// Подаём блок холостому хешированию
		idle.update(view_t(filler, sizeof(filler)));
	// Место, в которое помещается итог холостого хеширования
	uint8_t discarded[PROTECT_MAC];
	// Снимаем итог холостого хеширования: он никуда не идёт
	(void) idle.finish(discarded, width);
	/**
	 * Начало окна извлечения принятой имитовставки: наибольшая длина дополнения с байтом
	 * длины и имитовставкой от конца открытого текста; длина окна зависит лишь от длины
	 * записи, а место имитовставки внутри окна - секрет
	 */
	const size_t window = ((length > (width + CBC_PADDING)) ? (length - width - CBC_PADDING) : 0);
	/**
	 * Выполняем извлечение принятой имитовставки перебором окна под маской совпадения номера
	 */
	for(size_t j = window; j < length; j++){
		/**
		 * Выполняем перебор байтов имитовставки
		 */
		for(size_t k = 0; k < width; k++)
			// Учитываем байт открытого текста под маской совпадения номера
			received[k] = static_cast <uint8_t> (received[k] | (plain[j] & same(j, (total + k))));
	}
	// Маска расхождения имитовставок
	uint8_t diff = 0;
	/**
	 * Выполняем сличение имитовставок за постоянное время
	 */
	for(size_t k = 0; k < width; k++)
		// Накапливаем расхождение очередных байтов
		diff = static_cast <uint8_t> (diff | (expected[k] ^ received[k]));
	// Учитываем схождение имитовставок и их выработку в итоговом признаке
	good = static_cast <uint8_t> (good & same(diff, 0) & produced);
	// Выполняем затирание ожидаемой имитовставки
	wipe(expected, sizeof(expected));
	// Выполняем затирание принятой имитовставки
	wipe(received, sizeof(received));
	// Выводим маску годности записи
	return good;
}
/**
 * @brief Конструктор
 *
 */
nts::protect::Protection::Protection() noexcept : _ready(false), _suite(suite_t::NONE), _size(0), _tag(0), _width(0), _classic(false), _stream(false), _legacy(false), _cbc(false), _etm(false), _digest(digest::hash_t::NONE), _sequence(0), _limit(0), _derived(0) {
	// Обнуляем корневой ключ направления связи
	::memset(this->_key, 0, sizeof(this->_key));
	// Обнуляем вектор замены направления связи
	::memset(this->_vector, 0, sizeof(this->_vector));
	// Обнуляем ключ имитовставки направления связи
	::memset(this->_mac, 0, sizeof(this->_mac));
}
/**
 * @brief Деструктор
 *
 */
nts::protect::Protection::~Protection() noexcept {
	// Выполняем сброс ключевого материала
	this->clear();
}
