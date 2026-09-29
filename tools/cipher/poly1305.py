#!/usr/bin/env python3
#
# Порождатель ядра Poly1305 на встроенном ассемблере x86-64 (AVX2) для
# src/internal/cipher/poly1305.hpp: python3 tools/cipher/poly1305.py > src/internal/cipher/poly1305.hpp
#
# Устройство ядра (образец - poly1305-x86_64.pl OpenSSL, текст свой): четыре дорожки по 64
# разряда в векторе, всякая ведёт свою сумму пятью конечностями по 26 разрядов; на каждой
# четвёрке блоков дорожки умножаются на r^4 (конечности r^4 и 5·r^4 размножены по дорожкам и
# берутся операндами в памяти), переносы проводятся двумя переплетёнными потоками, и к
# дорожкам складываются конечности новых блоков. После последней четвёрки дорожки умножаются
# на r^4, r^2, r^3 и r в порядке разбора блоков (первый, третий, второй, четвёртый), и пять
# конечностей четырёх дорожек выдаются в память - суммирование дорожек и перевод в накопитель
# ведёт вызывающая сторона. Пять конечностей дорожек, пять произведений и шесть временных
# занимают шестнадцать регистров без перегрузок; конечности блоков разбираются в регистры
# произведений после переносов.
#
# Правки ядра вносятся сюда, а не в заголовок: интерпретатор ниже исполняет порождённый
# список команд на случайных ключах и данных и сличает с числовой моделью Poly1305 -
# порождение отказывает, если сходимости нет.
#
# Порча векторных регистров объявляется именами xmmN, хотя ядро идёт на ymm: clang без ключа
# -mavx2 молча не считает «ymmN» порчей (значение, оставленное им в xmm0, переживает вставку),
# gcc считает оба имени одним регистром; имя xmmN у обоих собирателей охватывает и старшую половину ymm.
#
import random, sys

P = (1 << 130) - 5
M26 = (1 << 26) - 1
M64 = (1 << 64) - 1

# Стол ядра (байты): 0 - конечности r^4 по дорожкам (5 × 32), 160 - конечности 5·r^4 (5 × 32),
# 320 - конечности степеней r^4, r^2, r^3, r по дорожкам (5 × 32), 480 - они же на пять (5 × 32),
# 640 - маска конечности, 672 - старший разряд 2^128 по конечностям
R4, S4, RL, SL, MASK, HIBIT, TABLE = 0, 160, 320, 480, 640, 672, 704

class Kernel:
	def __init__(self):
		self.ins = []
	def e(self, *ins):
		self.ins.append(ins)
	def split(self, m, lo, hi, t):
		# Разбор четырёх блоков в пять конечностей четырёх дорожек: порядок дорожек - блоки 0, 2, 1, 3
		self.e('loadu', lo, ('m', 'data', 0)); self.e('loadu', hi, ('m', 'data', 32))
		self.e('unpackh64', t, lo, hi); self.e('unpackl64', lo, lo, hi)
		self.e('and', m[0], lo, ('m', 'tab', MASK))
		self.e('srl', m[1], lo, 26); self.e('and', m[1], m[1], ('m', 'tab', MASK))
		self.e('srl', lo, lo, 52); self.e('sll', m[2], t, 12); self.e('or', m[2], m[2], lo); self.e('and', m[2], m[2], ('m', 'tab', MASK))
		self.e('srl', m[3], t, 14); self.e('and', m[3], m[3], ('m', 'tab', MASK))
		self.e('srl', m[4], t, 40); self.e('or', m[4], m[4], ('m', 'tab', HIBIT))
	def multiply(self, h, d, t, roff, soff):
		# Произведения дорожек на множитель: d_i = сумма h_j · (r_(i-j) при j ≤ i, иначе s_(5+i-j))
		for i in range(5):
			for j in range(5):
				off = (roff + (i - j) * 32) if j <= i else (soff + (5 + i - j) * 32)
				if j == 0: self.e('mul', d[i], h[j], ('m', 'tab', off))
				else: self.e('mul', t, h[j], ('m', 'tab', off)); self.e('add', d[i], d[i], t)
	def carry(self, d, h, t, t2):
		# Переносы двумя потоками: 0 → 1, 3 → 4, 1 → 2, 4 → 0 (на пять), 2 → 3, 0 → 1, 3 → 4; итог в h
		M = ('m', 'tab', MASK)
		self.e('srl', t, d[0], 26); self.e('and', h[0], d[0], M); self.e('add', d[1], d[1], t)
		self.e('srl', t2, d[3], 26); self.e('and', h[3], d[3], M); self.e('add', d[4], d[4], t2)
		self.e('srl', t, d[1], 26); self.e('and', h[1], d[1], M); self.e('add', d[2], d[2], t)
		self.e('srl', t2, d[4], 26); self.e('and', h[4], d[4], M); self.e('sll', t, t2, 2); self.e('add', t, t, t2); self.e('add', h[0], h[0], t)
		self.e('srl', t, d[2], 26); self.e('and', h[2], d[2], M); self.e('add', h[3], h[3], t)
		self.e('srl', t2, h[0], 26); self.e('and', h[0], h[0], M); self.e('add', h[1], h[1], t2)
		self.e('srl', t, h[3], 26); self.e('and', h[3], h[3], M); self.e('add', h[4], h[4], t)
	def build(self):
		h = ['v0', 'v1', 'v2', 'v3', 'v4']; d = ['v5', 'v6', 'v7', 'v8', 'v9']
		t, t2, lo, hi, t3 = 'v10', 'v11', 'v12', 'v13', 'v14'
		# Накопитель в первую дорожку и первая четвёрка блоков
		for i in range(5): self.e('movd', h[i], ('m', 'acc', 4 * i))
		self.split(d, lo, hi, t3)
		for i in range(5): self.e('add', h[i], h[i], d[i])
		self.e('addptr', 'data', 64); self.e('dec'); self.e('jz')
		self.e('label')
		self.multiply(h, d, t, R4, S4)
		self.carry(d, h, t, t2)
		self.split(d, lo, hi, t3)
		for i in range(5): self.e('add', h[i], h[i], d[i])
		self.e('addptr', 'data', 64); self.e('dec'); self.e('jnz')
		self.e('exit')
		self.multiply(h, d, t, RL, SL)
		self.carry(d, h, t, t2)
		for i in range(5): self.e('store', ('m', 'out', 32 * i), h[i])
		self.e('zeroupper')

def operand(o):
	if isinstance(o, tuple): return '%d(%%[%s])' % (o[2], o[1])
	if isinstance(o, int): return '$%d' % o
	return '%%ymm' + o[1:]

def render(kern):
	R = operand
	out = []
	for ins in kern.ins:
		op = ins[0]
		if op == 'label': out.append('1:'); continue
		if op == 'exit': out.append('2:'); continue
		if op == 'addptr': out.append('addq $%d, %%[%s]' % (ins[2], ins[1])); continue
		if op == 'dec': out.append('decq %[count]'); continue
		if op == 'jz': out.append('jz 2f'); continue
		if op == 'jnz': out.append('jnz 1b'); continue
		if op == 'zeroupper': out.append('vzeroupper'); continue
		if op == 'loadu': out.append('vmovdqu %s, %s' % (R(ins[2]), R(ins[1]))); continue
		if op == 'store': out.append('vmovdqa %s, %s' % (R(ins[2]), R(ins[1]))); continue
		if op == 'movd': out.append('vmovd %s, %%%%xmm%s' % (R(ins[2]), ins[1][1:])); continue
		if op in ('mul', 'add', 'and', 'or', 'unpackl64', 'unpackh64'):
			name = {'mul': 'vpmuludq', 'add': 'vpaddq', 'and': 'vpand', 'or': 'vpor', 'unpackl64': 'vpunpcklqdq', 'unpackh64': 'vpunpckhqdq'}[op]
			out.append('%s %s, %s, %s' % (name, R(ins[3]), R(ins[2]), R(ins[1]))); continue
		if op in ('srl', 'sll'):
			out.append('%s $%d, %s, %s' % ('vpsrlq' if op == 'srl' else 'vpsllq', ins[3], R(ins[2]), R(ins[1]))); continue
		raise Exception(ins)
	return out

def asmtext(lines, indent):
	return '\n'.join(indent + '"' + l + '\\n\\t"' for l in lines)

HEADER = """/**
 * @file poly1305.hpp
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
 * @brief Ядро Poly1305 на встроенном ассемблере x86-64 (AVX2)
 *
 * @details Файл порождён сценарием tools/cipher/poly1305.py и руками не правится: правки
 *          вносятся в сценарий, который исполняет порождённый список команд на случайных
 *          ключах и данных и сличает с числовой моделью до выдачи текста. Устройство:
 *          четыре дорожки по 64 разряда, всякая ведёт свою сумму пятью конечностями по 26
 *          разрядов; на каждой четвёрке блоков дорожки умножаются на r^4 операндами в памяти,
 *          переносы идут двумя переплетёнными потоками, конечности новых блоков складываются
 *          к дорожкам; после последней четвёрки дорожки умножаются на r^4, r^2, r^3 и r в
 *          порядке разбора блоков и выдаются в память. Стол ядра готовит вызывающая сторона.
 *          Порча регистров объявлена именами xmmN, хотя ядро идёт на ymm: clang без ключа
 *          -mavx2 молча не считает «ymmN» порчей, а xmmN охватывает весь регистр у обоих собирателей
 *
 * @copyright Copyright © 2026
 *
 */

/**
 * Экранируем повторную инициализацию модуля
 */
#ifndef __ANTS_INTERNAL_CIPHER_POLY1305__
#define __ANTS_INTERNAL_CIPHER_POLY1305__

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
 * Ядро берётся у gcc и clang на x86-64; у прочих собирателей остаётся ветвь на интринсиках.
 * Под ASan без оптимизации ядро не берётся (признак __ANTS_ASAN_UNOPTIMIZED__ из sys/global.hpp)
 */
#if defined(__x86_64__) && defined(__GNUC__) && !defined(_MSC_VER) && !defined(__ANTS_ASAN_UNOPTIMIZED__) && !defined(ANTS_NO_MACHINE)
	/**
	 * Признак наличия ядра на ассемблере
	 */
	#define __ANTS_POLY1305_X86_64__
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
				 * @brief Смещения стола ядра в байтах: конечности r^4 по дорожкам, они же на пять, степени по дорожкам, они же на пять, маска конечности, старший разряд
				 */
				static constexpr size_t POLY_R4 = %d, POLY_S4 = %d, POLY_RL = %d, POLY_SL = %d, POLY_MASK = %d, POLY_HIBIT = %d, POLY_TABLE = %d;
				/**
				 * @brief Метод сложения четвёрок блоков ядром AVX2
				 *
				 * @param lanes       место под пять конечностей четырёх дорожек итога: 5 × 4 слова по 64 разряда, выровненное на 32
				 * @param accumulator накопитель пятью конечностями по 26 разрядов: складывается с первой дорожкой
				 * @param table       стол ядра в POLY_TABLE байтов, выровненный на 32
				 * @param data        складываемые блоки четвёрками по 64 байта
				 * @param count       число четвёрок, не меньше одной
				 *
				 */
				static void poly1305avx2(uint64_t * lanes, const uint32_t * accumulator, const uint64_t * table, const uint8_t * data, size_t count) noexcept {
					__asm__ __volatile__(
"""
FOOTER = """
						: [data] "+r" (data), [count] "+r" (count)
						: [out] "r" (lanes), [acc] "r" (accumulator), [tab] "r" (table)
						: "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "cc", "memory");
				}
			}
		}
	}
#endif

#endif // __ANTS_INTERNAL_CIPHER_POLY1305__
"""

def header():
	k = Kernel(); k.build(); selfcheck(k)
	print('сходимость Poly1305 avx2: команд %d' % len(k.ins), file=sys.stderr)
	return (HEADER % (R4, S4, RL, SL, MASK, HIBIT, TABLE)) + asmtext(render(k), '\t\t\t\t\t\t') + FOOTER

# ---------- числовая модель ----------
def limbs(x):
	# Пять конечностей по 26 разрядов; старшая не обрезается: накопитель между вызовами приведён не до конца
	return [(x >> (26 * i)) & M26 for i in range(4)] + [x >> 104]

def clamp(key):
	r = int.from_bytes(key[:16], 'little') & 0x0ffffffc0ffffffc0ffffffc0fffffff
	return r

def reference(h, r, data):
	# Обычный ход Poly1305 по блокам с накопителем h
	for i in range(0, len(data), 16):
		m = int.from_bytes(data[i:i + 16], 'little') + (1 << 128)
		h = ((h + m) * r) % P
	return h

def table(r):
	t = bytearray(TABLE)
	powers = [pow(r, e, P) for e in (1, 2, 3, 4)]
	def put(off, lane, value):
		t[off + lane * 8:off + lane * 8 + 8] = (value & M64).to_bytes(8, 'little')
	r4 = limbs(powers[3])
	for i in range(5):
		for lane in range(4):
			put(R4 + 32 * i, lane, r4[i]); put(S4 + 32 * i, lane, 5 * r4[i])
	# дорожки: блоки 0, 2, 1, 3 → степени r^4, r^2, r^3, r
	order = [powers[3], powers[1], powers[2], powers[0]]
	for lane in range(4):
		l = limbs(order[lane])
		for i in range(5):
			put(RL + 32 * i, lane, l[i]); put(SL + 32 * i, lane, 5 * l[i])
	for lane in range(4):
		put(MASK, lane, M26); put(HIBIT, lane, 1 << 24)
	return bytes(t)

def run(kern, h, tab, data, count):
	mem = bytearray(1 << 16)
	ACC, TAB, DATA, OUT = 0x100, 0x400, 0x1000, 0x8000
	hl = limbs(h)
	for i in range(5): mem[ACC + 4 * i:ACC + 4 * i + 4] = hl[i].to_bytes(4, 'little')
	mem[TAB:TAB + TABLE] = tab
	mem[DATA:DATA + len(data)] = data
	ptr = {'acc': ACC, 'tab': TAB, 'data': DATA, 'out': OUT}
	regs = {}
	cnt = count
	addr = lambda o: ptr[o[1]] + o[2]
	def rd(o):
		if isinstance(o, tuple): return bytes(mem[addr(o):addr(o) + 32])
		return regs[o]
	lanes = lambda v: [int.from_bytes(v[i:i + 8], 'little') for i in range(0, 32, 8)]
	pack = lambda l: b''.join((x & M64).to_bytes(8, 'little') for x in l)
	labels = {ins[0]: n for n, ins in enumerate(kern.ins) if ins[0] in ('label', 'exit')}
	pc = 0
	while pc < len(kern.ins):
		ins = kern.ins[pc]; pc += 1
		op = ins[0]
		if op in ('label', 'exit', 'zeroupper'): continue
		if op == 'addptr': ptr[ins[1]] += ins[2]; continue
		if op == 'dec': cnt -= 1; continue
		if op == 'jz':
			if cnt == 0: pc = labels['exit'] + 1
			continue
		if op == 'jnz':
			if cnt != 0: pc = labels['label'] + 1
			continue
		if op == 'loadu': regs[ins[1]] = rd(ins[2]); continue
		if op == 'store':
			assert addr(ins[1]) % 32 == 0
			mem[addr(ins[1]):addr(ins[1]) + 32] = regs[ins[2]]; continue
		if op == 'movd':
			regs[ins[1]] = bytes(mem[addr(ins[2]):addr(ins[2]) + 4]) + bytes(28); continue
		if op in ('mul', 'add', 'and', 'or'):
			x, y = lanes(rd(ins[2])), lanes(rd(ins[3]))
			f = {'mul': lambda p, q: (p & 0xFFFFFFFF) * (q & 0xFFFFFFFF), 'add': lambda p, q: p + q, 'and': lambda p, q: p & q, 'or': lambda p, q: p | q}[op]
			regs[ins[1]] = pack([f(p, q) for p, q in zip(x, y)]); continue
		if op in ('srl', 'sll'):
			x = lanes(rd(ins[2])); n = ins[3]
			regs[ins[1]] = pack([(p >> n) if op == 'srl' else (p << n) for p in x]); continue
		if op in ('unpackl64', 'unpackh64'):
			x, y = rd(ins[2]), rd(ins[3])
			out = bytearray()
			for i in (0, 16):
				base = i + (0 if op == 'unpackl64' else 8)
				out += x[base:base + 8] + y[base:base + 8]
			regs[ins[1]] = bytes(out); continue
		raise Exception(ins)
	assert cnt == 0
	out = [[int.from_bytes(mem[OUT + 32 * i + 8 * lane:OUT + 32 * i + 8 * lane + 8], 'little') for lane in range(4)] for i in range(5)]
	return out

def selfcheck(kern):
	rng = random.Random(1305)
	for trial in range(80):
		key = bytes(rng.getrandbits(8) for _ in range(32))
		r = clamp(key)
		if trial % 7 == 0: r = 0x0ffffffc0ffffffc0ffffffc0fffffff
		count = 1 + (trial % 9)
		data = bytes(rng.getrandbits(8) for _ in range(64 * count))
		h = rng.getrandbits(130) % P if trial % 3 else 0
		if trial % 11 == 0: h = P - 1 + (1 << 26)  # накопитель с неполным приведением
		out = run(kern, h, table(r), data, count)
		total = [sum(out[i]) for i in range(5)]
		assert all(x < (1 << 64) for x in total), 'переполнение суммы дорожек'
		got = sum(total[i] << (26 * i) for i in range(5)) % P
		want = reference(h, r, data)
		if got != want:
			raise Exception('Poly1305 avx2: расхождение (проба %d, четвёрок %d)' % (trial, count))

if __name__ == '__main__':
	sys.stdout.write(header())
