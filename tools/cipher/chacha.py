#!/usr/bin/env python3
#
# Порождатель ядер ChaCha20 на встроенном ассемблере x86-64 для
# src/internal/cipher/chacha.hpp: python3 tools/cipher/chacha.py > src/internal/cipher/chacha.hpp
#
# Устройство ядра (образец - chacha-x86_64.pl OpenSSL, текст свой): всякий вектор несёт одно
# слово состояния восьми (AVX2) либо четырёх (SSSE3, SSE2) блоков, раунды идут над всеми
# блоками пачки разом. Регистров шестнадцать, а слов состояния шестнадцать, оттого слова
# a, b и d живут в регистрах, а третьи слова c - в памяти: пара четвертьраундов ведётся
# вперемешку двумя третьими словами в регистрах и двумя временными; пара третьих слов
# столбцов и диагоналей совпадает, потому за двойной раунд третьи слова перегружаются
# лишь дважды. Вращения на 16 и 8 разрядов - перестановка байтов (pshufb) с маской в
# памяти, у SSE2 - перестановка слов и пара сдвигов; на 12 и 7 - пара сдвигов. Стол
# размноженных слов состояния строится в кадре на входе, счётчики пачки лежат в столе с
# приращениями по дорожкам и растут на пачку между итерациями; итог складывается со столом
# операндом в памяти, переставляется по блокам чередованием и накладывается на данные.
#
# Правки ядра вносятся сюда, а не в заголовок: интерпретатор ниже исполняет порождённый
# список команд на случайных состояниях и данных и сличает с переносимой блочной функцией -
# порождение отказывает, если сходимости нет.
#
# Порча векторных регистров объявляется именами xmmN и у ядра на ymm: clang без ключа -mavx2
# молча не считает «ymmN» порчей (значение, оставленное им в xmm0, переживает вставку), gcc
# считает оба имени одним регистром; имя xmmN у обоих собирателей охватывает и старшую половину ymm.
#
import random, sys

M32 = 0xFFFFFFFF

# ---------- переносимая блочная функция ----------
def rotl(x, n):
	return ((x << n) | (x >> (32 - n))) & M32

def block(state):
	x = list(state)
	def qr(a, b, c, d):
		x[a] = (x[a] + x[b]) & M32; x[d] ^= x[a]; x[d] = rotl(x[d], 16)
		x[c] = (x[c] + x[d]) & M32; x[b] ^= x[c]; x[b] = rotl(x[b], 12)
		x[a] = (x[a] + x[b]) & M32; x[d] ^= x[a]; x[d] = rotl(x[d], 8)
		x[c] = (x[c] + x[d]) & M32; x[b] ^= x[c]; x[b] = rotl(x[b], 7)
	for _ in range(10):
		qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15)
		qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14)
	return b''.join(((x[i] + state[i]) & M32).to_bytes(4, 'little') for i in range(16))

def stream(state, source, blocks):
	out = bytearray()
	for j in range(blocks):
		s = list(state); s[12] = (s[12] + j) & M32
		g = block(s)
		out += bytes(a ^ b for a, b in zip(g, source[j * 64:(j + 1) * 64]))
	return bytes(out)

# ---------- постоянные ядра ----------
# 0: маска вращения на 16 (две полосы), 32: на 8 (две полосы), 64: приращения счётчиков 0…7,
# 96: восьмёрки, 128: четвёрки
ROT16 = [2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13]
ROT8 = [3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14]
def words(vals):
	return sum(([v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF] for v in vals), [])
CONSTANTS = ROT16 * 2 + ROT8 * 2 + words(range(8)) + words([8] * 8) + words([4] * 4)
assert len(CONSTANTS) == 144

# ---------- ядро ----------
class Kernel:
	def __init__(self, tag):
		self.tag = tag
		self.vex = (tag == 'avx2')
		self.lanes = 8 if self.vex else 4
		self.V = 4 * self.lanes
		self.shuffle = (tag != 'sse2')
		self.ins = []
		self.table = 0
		self.work = 16 * self.V
		self.size = 20 * self.V
	def e(self, *ins):
		self.ins.append(ins)
	def tab(self, i):
		return ('m', 'frame', self.table + i * self.V)
	def wrk(self, j):
		return ('m', 'frame', self.work + (j - 8) * self.V)
	def rot(self, d, imm, t):
		# Вращение слов вектора d влево на imm разрядов, t - временный
		if imm == 16 and self.shuffle: self.e('shufb', d, d, ('m', 'cst', 0)); return
		if imm == 8 and self.shuffle: self.e('shufb', d, d, ('m', 'cst', 32)); return
		if imm == 16:
			self.e('shuflw', d, d, 0xB1); self.e('shufhw', d, d, 0xB1); return
		self.e('shl', t, d, imm); self.e('shr', d, d, 32 - imm); self.e('or', d, d, t)
	def qrsteps(self, a, b, c, d, t):
		# Шаги четвертьраунда списком замыканий: так две пары перемежаются шаг в шаг
		return [
			lambda: self.e('add', a, a, b), lambda: self.e('xor', d, d, a), lambda: self.rot(d, 16, t),
			lambda: self.e('add', c, c, d), lambda: self.e('xor', b, b, c), lambda: self.rot(b, 12, t),
			lambda: self.e('add', a, a, b), lambda: self.e('xor', d, d, a), lambda: self.rot(d, 8, t),
			lambda: self.e('add', c, c, d), lambda: self.e('xor', b, b, c), lambda: self.rot(b, 7, t)]
	def qr2(self, first, second):
		# Пара четвертьраундов вперемешку: временные v10 и v11
		x = self.qrsteps(*first, 'v10'); y = self.qrsteps(*second, 'v11')
		for f, g in zip(x, y):
			f(); g()
	def transpose(self, regs, temps):
		# Перестановка четырёх векторов слов по блокам чередованием: выводит регистры строк и освободившиеся
		r0, r1, r2, r3 = regs; t0, t1 = temps
		self.e('unpackl32', t0, r0, r1); self.e('unpackh32', r0, r0, r1)
		self.e('unpackl32', t1, r2, r3); self.e('unpackh32', r2, r2, r3)
		self.e('unpackl64', r1, t0, t1); self.e('unpackh64', r3, t0, t1)
		self.e('unpackl64', t0, r0, r2); self.e('unpackh64', t1, r0, r2)
		return [r1, r3, t0, t1], [r0, r2]
	def cover(self, rows, offset, temps):
		# Наложение гаммы строк на данные: строка k - слова блока k (у AVX2 и блока k + 4 старшей полосой)
		L = self.lanes
		for k in range(4):
			if self.vex:
				a, b = rows[0][k], rows[1][k]
				t = temps[0]
				self.e('perm', t, a, b, 0x20)
				self.e('xor', t, t, ('m', 'src', k * 64 + offset))
				self.e('storeu', ('m', 'dst', k * 64 + offset), t)
				self.e('perm', t, a, b, 0x31)
				self.e('xor', t, t, ('m', 'src', (k + 4) * 64 + offset))
				self.e('storeu', ('m', 'dst', (k + 4) * 64 + offset), t)
			else:
				t = temps[0]
				self.e('loadu', t, ('m', 'src', k * 64 + offset))
				self.e('xor', t, t, rows[0][k])
				self.e('storeu', ('m', 'dst', k * 64 + offset), t)
	def build(self):
		V = self.V; L = self.lanes
		a = ['v0', 'v1', 'v2', 'v3']; b = ['v4', 'v5', 'v6', 'v7']; d = ['v12', 'v13', 'v14', 'v15']
		c0, c1 = 'v8', 'v9'
		# Пролог: стол размноженных слов состояния, счётчики с приращениями по дорожкам
		for i in range(16):
			self.e('bcast', 'v0', ('m', 'state', 4 * i))
			if i == 12: self.e('add', 'v0', 'v0', ('m', 'cst', 64))
			self.e('store', self.tab(i), 'v0')
		self.e('label')
		for i in range(4):
			self.e('load', a[i], self.tab(i)); self.e('load', b[i], self.tab(4 + i)); self.e('load', d[i], self.tab(12 + i))
		# Десять двойных раундов: первый берёт третьи слова из стола, прочие - из рабочих ячеек
		for r in range(10):
			src = self.tab if r == 0 else self.wrk
			if r == 0:
				self.e('load', c0, src(8)); self.e('load', c1, src(9))
			self.qr2((a[0], b[0], c0, d[0]), (a[1], b[1], c1, d[1]))
			self.e('store', self.wrk(8), c0); self.e('store', self.wrk(9), c1)
			self.e('load', c0, src(10)); self.e('load', c1, src(11))
			self.qr2((a[2], b[2], c0, d[2]), (a[3], b[3], c1, d[3]))
			self.qr2((a[0], b[1], c0, d[3]), (a[1], b[2], c1, d[0]))
			self.e('store', self.wrk(10), c0); self.e('store', self.wrk(11), c1)
			self.e('load', c0, self.wrk(8)); self.e('load', c1, self.wrk(9))
			self.qr2((a[2], b[3], c0, d[1]), (a[3], b[0], c1, d[2]))
		self.e('store', self.wrk(8), c0); self.e('store', self.wrk(9), c1)
		# Эпилог: сложение со столом, перестановка по блокам и наложение гаммы
		for i in range(4): self.e('add', a[i], a[i], self.tab(i))
		rowsA, free = self.transpose(a, ['v10', 'v11'])
		for i in range(4): self.e('add', b[i], b[i], self.tab(4 + i))
		rowsB, free2 = self.transpose(b, free)
		temps = free2 + ['v8', 'v9']
		if self.vex:
			self.cover([rowsA, rowsB], 0, temps)
		else:
			self.cover([rowsA], 0, temps); self.cover([rowsB], 16, temps)
		# Третьи и четвёртые слова: третьи из рабочих ячеек
		freed = rowsA + rowsB + temps
		c = freed[0:4]; t2 = freed[4:6]
		for i in range(4):
			self.e('load', c[i], self.wrk(8 + i)); self.e('add', c[i], c[i], self.tab(8 + i))
		rowsC, free3 = self.transpose(c, t2)
		for i in range(4): self.e('add', d[i], d[i], self.tab(12 + i))
		rowsD, free4 = self.transpose(d, free3)
		temps = free4 + freed[6:8]
		if self.vex:
			self.cover([rowsC, rowsD], 32, temps)
		else:
			self.cover([rowsC], 32, temps); self.cover([rowsD], 48, temps)
		# Счётчики следующей пачки и продвижение указателей
		self.e('load', 'v0', self.tab(12)); self.e('add', 'v0', 'v0', ('m', 'cst', 96 if self.vex else 128)); self.e('store', self.tab(12), 'v0')
		self.e('addptr', 'src', 64 * L); self.e('addptr', 'dst', 64 * L)
		self.e('loop')
		if self.vex: self.e('zeroupper')

# ---------- вывод текста ----------
def operand(o, vex):
	if isinstance(o, tuple): return '%d(%%[%s])' % (o[2], o[1])
	if isinstance(o, int): return '$%d' % o
	return '%%%%%s%s' % ('ymm' if vex else 'xmm', o[1:])

def render(kern):
	vex = kern.vex
	R = lambda o: operand(o, vex)
	out = []
	for ins in kern.ins:
		op = ins[0]
		if op == 'label': out.append('1:'); continue
		if op == 'addptr': out.append('addq $%d, %%[%s]' % (ins[2], ins[1])); continue
		if op == 'loop': out.append('decq %[count]'); out.append('jnz 1b'); continue
		if op == 'zeroupper': out.append('vzeroupper'); continue
		if op in ('load', 'loadu'):
			out.append(('vmovdq' if vex else 'movdq') + ('a' if op == 'load' else 'u') + ' %s, %s' % (R(ins[2]), R(ins[1]))); continue
		if op in ('store', 'storeu'):
			out.append(('vmovdq' if vex else 'movdq') + ('a' if op == 'store' else 'u') + ' %s, %s' % (R(ins[2]), R(ins[1]))); continue
		if op == 'bcast':
			if vex: out.append('vpbroadcastd %s, %s' % (R(ins[2]), R(ins[1])))
			else: out.append('movd %s, %s' % (R(ins[2]), R(ins[1]))); out.append('pshufd $0, %s, %s' % (R(ins[1]), R(ins[1])))
			continue
		if op in ('add', 'xor', 'or', 'unpackl32', 'unpackh32', 'unpackl64', 'unpackh64'):
			name = {'add': 'paddd', 'xor': 'pxor', 'or': 'por', 'unpackl32': 'punpckldq', 'unpackh32': 'punpckhdq', 'unpackl64': 'punpcklqdq', 'unpackh64': 'punpckhqdq'}[op]
			_, dst, s1, s2 = ins
			if vex: out.append('v%s %s, %s, %s' % (name, R(s2), R(s1), R(dst))); continue
			commutative = op in ('add', 'xor', 'or')
			if dst == s1: out.append('%s %s, %s' % (name, R(s2), R(dst)))
			elif commutative and dst == s2: out.append('%s %s, %s' % (name, R(s1), R(dst)))
			else:
				assert dst != s2, ins
				out.append('movdqa %s, %s' % (R(s1), R(dst))); out.append('%s %s, %s' % (name, R(s2), R(dst)))
			continue
		if op in ('shl', 'shr'):
			name = 'pslld' if op == 'shl' else 'psrld'
			_, dst, s1, imm = ins
			if vex: out.append('v%s $%d, %s, %s' % (name, imm, R(s1), R(dst))); continue
			if dst != s1: out.append('movdqa %s, %s' % (R(s1), R(dst)))
			out.append('%s $%d, %s' % (name, imm, R(dst))); continue
		if op == 'shufb':
			_, dst, s1, ctrl = ins
			if vex: out.append('vpshufb %s, %s, %s' % (R(ctrl), R(s1), R(dst))); continue
			if dst != s1: out.append('movdqa %s, %s' % (R(s1), R(dst)))
			out.append('pshufb %s, %s' % (R(ctrl), R(dst))); continue
		if op in ('shuflw', 'shufhw'):
			_, dst, s1, imm = ins
			out.append('%s $%d, %s, %s' % (op.replace('shuf', 'pshuf'), imm, R(s1), R(dst))); continue
		if op == 'perm':
			_, dst, s1, s2, imm = ins
			out.append('vperm2i128 $%d, %s, %s, %s' % (imm, R(s2), R(s1), R(dst))); continue
		raise Exception(ins)
	return out

def asmtext(lines, indent):
	return '\n'.join(indent + '"' + l + '\\n\\t"' for l in lines)

def kernel_cpp(kern, name, brief):
	# порча только именами xmmN: «ymmN» clang без -mavx2 молча пропускает, а xmmN охватывает весь регистр
	regs = ', '.join('"xmm%d"' % i for i in range(16))
	head = ('\t\t\t\t/**\n\t\t\t\t * @brief %s\n\t\t\t\t *\n\t\t\t\t * @param state  состояние шифра: постоянные, ключ, счётчик первого блока, заполнение\n'
		'\t\t\t\t * @param frame  кадр ядра в %d байтов, выровненный на 32: стол слов состояния и рабочие ячейки\n'
		'\t\t\t\t * @param source покрываемые данные пачками по %d байтов\n\t\t\t\t * @param result место под покрытые данные\n'
		'\t\t\t\t * @param count  число пачек, не меньше одной\n\t\t\t\t *\n\t\t\t\t */\n' % (brief, kern.size, 64 * kern.lanes)
		+ '\t\t\t\tstatic void %s(const uint32_t * state, uint8_t * frame, const uint8_t * source, uint8_t * result, size_t count) noexcept {\n\t\t\t\t\t__asm__ __volatile__(\n' % name)
	tail = ('\n\t\t\t\t\t\t: [src] "+r" (source), [dst] "+r" (result), [count] "+r" (count)\n\t\t\t\t\t\t: [state] "r" (state), [frame] "r" (frame), [cst] "r" (CONSTANTS)\n'
		'\t\t\t\t\t\t: %s, "cc", "memory");\n\t\t\t\t}\n' % regs)
	return head + asmtext(render(kern), '\t\t\t\t\t\t') + tail

HEADER = """/**
 * @file chacha.hpp
 * @date 2026-09-28
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
 * @brief Ядра ChaCha20 на встроенном ассемблере x86-64
 *
 * @details Файл порождён сценарием tools/cipher/chacha.py и руками не правится: правки
 *          вносятся в сценарий, который исполняет порождённый список команд на случайных
 *          состояниях и данных и сличает с переносимой блочной функцией до выдачи текста.
 *          Устройство: всякий вектор несёт одно слово состояния восьми (AVX2) либо четырёх
 *          (SSSE3, SSE2) блоков; слова a, b и d живут в регистрах, третьи слова c - в памяти,
 *          пары четвертьраундов идут вперемешку двумя третьими словами в регистрах; стол
 *          размноженных слов состояния строится в кадре на входе, счётчики растут на пачку
 *          между итерациями, итог переставляется по блокам чередованием и накладывается на
 *          данные. Кадр даёт вызывающая сторона и затирает его после. Порча регистров
 *          объявлена именами xmmN и у ядра на ymm: clang без ключа -mavx2 молча не считает
 *          «ymmN» порчей, а xmmN охватывает весь регистр у обоих собирателей
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_INTERNAL_CIPHER_CHACHA__
#define __ANTS_INTERNAL_CIPHER_CHACHA__

/**
 * Стандартные заголовочные файлы
 */
#include <cstdint>
#include <cstddef>

/**
 * Подключаем заголовочные файлы проекта
 */
#include <sys/global.hpp>

/**
 * Ядра берутся у gcc и clang на x86-64; у прочих собирателей и архитектур остаются ветви на
 * интринсиках либо переносимый путь. Под ASan без оптимизации ядра не берутся (признак
 * __ANTS_ASAN_UNOPTIMIZED__ из sys/global.hpp)
 */
#if defined(__x86_64__) && defined(__GNUC__) && !defined(_MSC_VER) && !defined(__ANTS_ASAN_UNOPTIMIZED__) && !defined(ANTS_NO_MACHINE)
	/**
	 * Признак наличия ядер на ассемблере
	 */
	#define __ANTS_CHACHA_X86_64__
	/**
	 * @brief Основное пространство имён
	 *
	 */
	namespace nts {
		/**
		 * @brief Пространство имён модулей шифрования
		 *
		 */
		namespace cipher {
			/**
			 * @brief Пространство имён ядер на ассемблере
			 *
			 */
			namespace kernel {
				/**
				 * @brief Размер кадра ядра восьми блоков в байтах
				 */
				static constexpr size_t FRAME8 = %d;
				/**
				 * @brief Размер кадра ядра четырёх блоков в байтах
				 */
				static constexpr size_t FRAME4 = %d;
				/**
				 * @brief Постоянные ядер: маски вращения на 16 и 8 разрядов в двух полосах, приращения счётчиков 0…7, восьмёрки и четвёрки
				 */
				alignas(32) static const uint8_t CONSTANTS[144] = {
%s
				};
"""
FOOTER = """			}
		}
	}
#endif

#endif // __ANTS_INTERNAL_CIPHER_CHACHA__
"""

def header():
	rows = []
	for i in range(0, 144, 16):
		rows.append('\t\t\t\t\t' + ', '.join(str(v) for v in CONSTANTS[i:i + 16]) + (',' if i + 16 < 144 else ''))
	parts = [HEADER % (20 * 32, 20 * 16, '\n'.join(rows))]
	names = {'avx2': 'Метод покрытия гаммой пачек по восемь блоков ядром AVX2', 'ssse3': 'Метод покрытия гаммой пачек по четыре блока ядром SSSE3', 'sse2': 'Метод покрытия гаммой пачек по четыре блока ядром SSE2'}
	for tag in ('avx2', 'ssse3', 'sse2'):
		k = Kernel(tag); k.build(); selfcheck(k)
		print('сходимость ChaCha20 %s: команд %d' % (tag, len(k.ins)), file=sys.stderr)
		parts.append(kernel_cpp(k, 'chacha%dx%s' % (k.lanes, tag), names[tag]))
	parts.append(FOOTER)
	return ''.join(parts)

# ---------- интерпретатор ----------
def run(kern, state, source, count):
	V = kern.V; L = kern.lanes
	mem = bytearray(1 << 17)
	FRAME, CST, STATE, SRC, DST = 0x1000, 0x2000, 0x3000, 0x4000, 0x10000
	mem[CST:CST + 144] = bytes(CONSTANTS)
	mem[STATE:STATE + 64] = b''.join(w.to_bytes(4, 'little') for w in state)
	mem[SRC:SRC + len(source)] = source
	ptr = {'frame': FRAME, 'cst': CST, 'state': STATE, 'src': SRC, 'dst': DST}
	regs = {}
	cnt = count
	def addr(o):
		return ptr[o[1]] + o[2]
	def rd(o):
		if isinstance(o, tuple): return bytes(mem[addr(o):addr(o) + V])
		return regs[o]
	lanes = lambda v: [int.from_bytes(v[i:i + 4], 'little') for i in range(0, V, 4)]
	pack = lambda l: b''.join(x.to_bytes(4, 'little') for x in l)
	def per128(v, fn):
		return b''.join(fn(v[i:i + 16]) for i in range(0, V, 16))
	labels = {n for n, ins in enumerate(kern.ins) if ins[0] == 'label'}
	assert len(labels) == 1
	start = list(labels)[0]
	pc = 0
	while pc < len(kern.ins):
		ins = kern.ins[pc]; pc += 1
		op = ins[0]
		if op == 'label' or op == 'zeroupper': continue
		if op == 'addptr': ptr[ins[1]] += ins[2]; continue
		if op == 'loop':
			cnt -= 1
			if cnt != 0: pc = start + 1
			continue
		if op in ('load', 'loadu'):
			if op == 'load': assert addr(ins[2]) % V == 0, ins
			regs[ins[1]] = rd(ins[2]); continue
		if op in ('store', 'storeu'):
			if op == 'store': assert addr(ins[1]) % V == 0, ins
			mem[addr(ins[1]):addr(ins[1]) + V] = regs[ins[2]]; continue
		if op == 'bcast':
			regs[ins[1]] = bytes(mem[addr(ins[2]):addr(ins[2]) + 4]) * L; continue
		if op in ('add', 'xor', 'or'):
			x, y = lanes(rd(ins[2])), lanes(rd(ins[3]))
			f = {'add': lambda p, q: (p + q) & M32, 'xor': lambda p, q: p ^ q, 'or': lambda p, q: p | q}[op]
			regs[ins[1]] = pack([f(p, q) for p, q in zip(x, y)]); continue
		if op in ('shl', 'shr'):
			x = lanes(rd(ins[2])); n = ins[3]
			regs[ins[1]] = pack([((p << n) & M32) if op == 'shl' else (p >> n) for p in x]); continue
		if op == 'shufb':
			ctrl = rd(ins[3]); src = rd(ins[2])
			def sh(chunk, c=ctrl):
				return bytes(0)
			out = bytearray()
			for i in range(0, V, 16):
				s = src[i:i + 16]; c = ctrl[i:i + 16]
				out += bytes((0 if (c[j] & 0x80) else s[c[j] & 15]) for j in range(16))
			regs[ins[1]] = bytes(out); continue
		if op in ('shuflw', 'shufhw'):
			src = rd(ins[2]); imm = ins[3]
			out = bytearray()
			for i in range(0, V, 16):
				s = src[i:i + 16]
				lo = [s[j:j + 2] for j in range(0, 8, 2)]; hi = [s[j:j + 2] for j in range(8, 16, 2)]
				sel = [(imm >> (2 * k)) & 3 for k in range(4)]
				if op == 'shuflw': lo = [lo[k] for k in sel]
				else: hi = [hi[k] for k in sel]
				out += b''.join(lo) + b''.join(hi)
			regs[ins[1]] = bytes(out); continue
		if op in ('unpackl32', 'unpackh32', 'unpackl64', 'unpackh64'):
			x, y = rd(ins[2]), rd(ins[3])
			w = 4 if op.endswith('32') else 8
			out = bytearray()
			for i in range(0, V, 16):
				xs, ys = x[i:i + 16], y[i:i + 16]
				base = 0 if op[6] == 'l' else 8
				parts = []
				for j in range(base, base + 8, w):
					parts.append(xs[j:j + w]); parts.append(ys[j:j + w])
				out += b''.join(parts)
			regs[ins[1]] = bytes(out); continue
		if op == 'perm':
			x, y = rd(ins[2]), rd(ins[3]); imm = ins[4]
			halves = [x[0:16], x[16:32], y[0:16], y[16:32]]
			regs[ins[1]] = halves[imm & 3] + halves[(imm >> 4) & 3]; continue
		raise Exception(ins)
	assert cnt == 0
	return bytes(mem[DST:DST + count * 64 * L]), bytes(mem[FRAME:FRAME + kern.size])

def selfcheck(kern):
	rng = random.Random(42 + kern.lanes + (1 if kern.shuffle else 0))
	for trial in range(60):
		state = [rng.getrandbits(32) for _ in range(16)]
		if trial % 5 == 0: state[12] = M32 - rng.randrange(kern.lanes * 3)
		count = 1 + (trial % 3)
		blocks = count * kern.lanes
		source = bytes(rng.getrandbits(8) for _ in range(blocks * 64))
		got, frame = run(kern, state, source, count)
		want = stream(state, source, blocks)
		if got != want:
			for j in range(blocks):
				if got[j * 64:(j + 1) * 64] != want[j * 64:(j + 1) * 64]:
					raise Exception('ChaCha20 %s: расхождение в блоке %d из %d (проба %d)' % (kern.tag, j, blocks, trial))
			raise Exception('ChaCha20 %s: расхождение' % kern.tag)
		# Счётчик стола продвинут на пачки
		ctr = int.from_bytes(frame[12 * kern.V:12 * kern.V + 4], 'little')
		assert ctr == ((state[12] + blocks) & M32), (ctr, state[12], blocks)

if __name__ == '__main__':
	sys.stdout.write(header())
