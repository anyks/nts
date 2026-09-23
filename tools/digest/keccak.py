#!/usr/bin/env python3
#
# Порождатель ядер перестановки Keccak-f[1600] на встроенном ассемблере - x86-64 и AArch64 с
# командами SHA-3 - для src/internal/digest/keccak.hpp: python3 tools/digest/keccak.py > src/internal/digest/keccak.hpp
#
# Устройство ядра (образец - keccak1600-x86_64.pl OpenSSL, текст свой): состояние лежит
# в памяти двумя накопителями по 25 полос, круг читает один и пишет другой, указатели
# меняются местами после круга (кругов чётное число, итог возвращается в состояние);
# чётности столбцов C и слагаемые D шага θ живут в регистрах, полосы выходной строки
# собираются по одной: загрузка, сложение с D, круговой сдвиг ρ на место π, затем χ
# по строке. Шесть полос хранятся инвертированными (дополнение полос, раздел 2.1 заметки
# «Keccak implementation overview» команды Keccak): тогда χ каждой строки обходится одним
# not вместо пяти, а формула каждой полосы (and либо or) и инверсии на входе и выходе
# ядра выводятся здесь из маски, а не выписываются руками. Регистров четырнадцать: rbp
# не берётся (у сборок с указателем кадра он занят), оттого указатель на константы ι
# держится в памяти. Расписание χ строк 0…3 подбирается перебором с двумя временными
# регистрами, строка 4 считается копиями прямо в регистры чётностей следующего круга.
#
# Правки ядра вносятся сюда, а не в заголовок: интерпретатор ниже исполняет порождённый
# список команд на случайных состояниях и сличает с эталонной перестановкой по FIPS 202 -
# порождение отказывает, если сходимости нет.
#
import random, sys

ROUNDS = 24
IOTA = [
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
# Сдвиги ρ по таблице 2 FIPS 202: RHO[x][y]
RHO = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
# Маска дополнения: полосы (x, y), хранимые инвертированными
MASK = {(1, 0), (2, 0), (3, 1), (2, 2), (2, 3), (0, 4)}
M64 = (1 << 64) - 1
def rol(v, n): return ((v << n) | (v >> (64 - n))) & M64 if n else v
def lane(x, y): return x + 5 * y
def off(x, y): return 8 * lane(x, y)

# ---------------- эталонная перестановка по FIPS 202 ----------------
def reference(s):
	a = list(s)
	for r in range(ROUNDS):
		c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
		d = [c[(x + 4) % 5] ^ rol(c[(x + 1) % 5], 1) for x in range(5)]
		a = [a[i] ^ d[i % 5] for i in range(25)]
		b = [0] * 25
		for x in range(5):
			for y in range(5):
				b[lane(y, (2 * x + 3 * y) % 5)] = rol(a[lane(x, y)], RHO[x][y])
		a = [b[lane(x, y)] ^ ((~b[lane((x + 1) % 5, y)] & M64) & b[lane((x + 2) % 5, y)]) for y in range(5) for x in range(5)]
		a[0] ^= IOTA[r]
	return a

# ---------------- регистры ----------------
PA, PT = 'rdi', 'rsi'
CREG = ['rax', 'rbx', 'rcx', 'rdx', 'r8']
DREG = ['r9', 'r10', 'r11', 'r12', 'r13']
TREG = ['r14', 'r15']

# ---------------- расписание χ одной строки ----------------
def chi_plan(vals, target, temps, iota_reg=None, dests=None):
	"""vals: пять (регистр, форма) полос строки после ρ и π, форма 1 - регистр держит
	инвертированную полосу; target: требуемые формы итога; temps: временные регистры под
	копии (по кругу); dests: регистры, в которые ложатся итоги строки 4 (чётности следующего
	круга). Каждая полоса χ считается в копию одного из двух операндов: домашние регистры не
	разрушаются, а инверсия второго операнда делается на месте и меняет его форму для
	последующих полос. Формула полосы выводится из форм: and даёт ~b & c при b в форме 1 и
	c в форме 0, or даёт инверсию члена при b в форме 0 и c в форме 1; итог выходит в форме
	полосы a либо в обратной. Порядок полос и выбор копируемого операнда перебираются
	(120 × 32), берётся расписание с наименьшим числом команд"""
	import itertools
	best = None
	for order in itertools.permutations(range(5)):
		for choice in range(32):
			forms = [f for (_, f) in vals]
			prog = []
			for n, i in enumerate(order):
				b, c = (i + 1) % 5, (i + 2) % 5
				dst = dests[i] if dests else temps[n % len(temps)]
				need = (target[i] == forms[i])
				fb, fc = (1, 0) if need else (0, 1)
				op = 'and' if need else 'or'
				src, other, fsrc, fother = (b, c, fb, fc) if ((choice >> n) & 1) else (c, b, fc, fb)
				prog.append(('mov', vals[src][0], dst))
				if forms[src] != fsrc: prog.append(('not', dst))
				if forms[other] != fother:
					prog.append(('not', vals[other][0])); forms[other] ^= 1
				prog.append((op, vals[other][0], dst))
				prog.append(('xor', vals[i][0], dst))
				if i == 0 and iota_reg: prog.append(('xor', ('mem', iota_reg, 0), dst))
				prog.append(('store', dst, i))
			if best is None or len(prog) < len(best): best = prog
	return best

# ---------------- порождение круга ----------------
def generate():
	prog = []
	# формы полос в памяти
	form = {(x, y): (1 if (x, y) in MASK else 0) for x in range(5) for y in range(5)}
	# θ-1: диагональ в регистры D (входы строки 0), чётности в C
	for x in range(4):
		prog.append(('mov', ('mem', PA, off(x, x)), DREG[x]))
	prog.append(('mov', CREG[4], DREG[4]))
	for x in range(5):
		for y in range(4):
			if x == y: prog.append(('xor', DREG[x], CREG[x]))
			else: prog.append(('xor', ('mem', PA, off(x, y)), CREG[x]))
	cform = [sum(form[(x, y)] for y in range(5)) % 2 for x in range(5)]
	# θ-2: D на месте C: D1 в C2, D4 в C0, D2 в C3, D0 в C1, D3 в C4 (T0 хранит исходную C2)
	prog += [('mov', CREG[2], TREG[0]), ('rol', 1, CREG[2]), ('xor', CREG[0], CREG[2]),
		('rol', 1, CREG[0]), ('xor', CREG[3], CREG[0]),
		('rol', 1, CREG[3]), ('xor', CREG[1], CREG[3]),
		('rol', 1, CREG[1]), ('xor', CREG[4], CREG[1]),
		('rol', 1, CREG[4]), ('xor', TREG[0], CREG[4])]
	dreg = {0: CREG[1], 1: CREG[2], 2: CREG[3], 3: CREG[4], 4: CREG[0]}
	dform = [cform[(x + 4) % 5] ^ cform[(x + 1) % 5] for x in range(5)]
	vreg = DREG
	nots = 0
	for Y in range(5):
		vals = []
		for j in range(5):
			x = (3 * Y + j) % 5
			if Y > 0: prog.append(('mov', ('mem', PA, off(x, j)), vreg[j]))
			prog.append(('xor', dreg[x], vreg[j]))
			if RHO[x][j]: prog.append(('rol', RHO[x][j], vreg[j]))
			vals.append((vreg[j], form[(x, j)] ^ dform[x]))
		target = [form[(i, Y)] for i in range(5)]
		if Y == 0:
			prog.append(('mov', ('op', 'iota'), TREG[1]))
			chi = chi_plan(vals, target, [TREG[0]], iota_reg=TREG[1])
		elif Y == 4:
			chi = chi_plan(vals, target, None, dests=CREG)
		else:
			chi = chi_plan(vals, target, TREG)
		for ins in chi:
			if ins[0] == 'store': prog.append(('mov', ins[1], ('mem', PT, off(ins[2], Y))))
			else:
				prog.append(ins)
				if ins[0] == 'not': nots += 1
	prog.append(('xchg', PT, PA))
	prog.append(('add', 8, ('op', 'iota')))
	prog.append(('mov', ('op', 'iota'), TREG[0]))
	prog.append(('cmp', ('op', 'end'), TREG[0]))
	return prog, nots

# ---------------- интерпретатор списка команд ----------------
def execute(state, body):
	mem = {'state': list(state), 'buffer': [0] * 25}
	regs = {r: 0 for r in [PA, PT] + CREG + DREG + TREG}
	regs[PA] = ('ptr', 'state'); regs[PT] = ('ptr', 'buffer')
	env = {'iota': 0}
	def load(src):
		if isinstance(src, str): return regs[src]
		if src[0] == 'mem':
			p = regs[src[1]]
			if p[0] == 'ptr': return mem[p[1]][src[2] // 8]
			if p[0] == 'iota': return IOTA[p[1] + src[2] // 8]
		if src[0] == 'op' and src[1] == 'iota': return ('iota', env['iota'])
		raise ValueError(src)
	def store(dst, v):
		if isinstance(dst, str): regs[dst] = v; return
		p = regs[dst[1]]; mem[p[1]][dst[2] // 8] = v
	for (x, y) in MASK: mem['state'][lane(x, y)] ^= M64
	for x in range(5): regs[CREG[x]] = mem['state'][lane(x, 4)]
	zero = False
	while True:
		for ins in body:
			op = ins[0]
			if op == 'mov': store(ins[2], load(ins[1]))
			elif op == 'rol': regs[ins[2]] = rol(regs[ins[2]], ins[1])
			elif op in ('xor', 'and', 'or'):
				a, b = load(ins[1]), load(ins[2])
				regs[ins[2]] = (a ^ b) if op == 'xor' else ((a & b) if op == 'and' else (a | b))
			elif op == 'not': regs[ins[1]] ^= M64
			elif op == 'xchg': regs[ins[1]], regs[ins[2]] = regs[ins[2]], regs[ins[1]]
			elif op == 'add': env['iota'] += 1
			elif op == 'cmp': zero = (regs[ins[2]][1] == ROUNDS)
			else: raise ValueError(ins)
		if zero: break
	assert regs[PA] == ('ptr', 'state')
	for (x, y) in MASK: mem['state'][lane(x, y)] ^= M64
	return mem['state']

# ---------------- ядро AArch64 на командах SHA-3 (EOR3, RAX1, XAR, BCAX) ----------------
# Полосы состояния лежат в младших половинах v0…v31 (двадцать пять занятых, семь свободных), все
# двадцать четыре круга развёрнуты: χ пишет итоги строки в свободные регистры, и место полосы
# меняется от круга к кругу (переименование без mov); θ считает чётности двумя eor3 на столбец
# и слагаемые D одним rax1 (C[x-1] ^ rol(C[x+1], 1)); сложение с D и сдвиг ρ - одна команда
# xar (сдвиг вправо на 64 - r), обход π - по циклу подстановки на месте с одним временным
# регистром; χ - bcax (a ^ (c & ~b)); ι - загрузка константы d-регистром из таблицы
VREGS = 32
def generate_aarch64():
	prog = []
	where = {}
	free = list(range(VREGS))
	for y in range(5):
		for x in range(5):
			r = free.pop(0); where[(x, y)] = r
			prog.append(('ldr', lane(x, y), r))
	# цикл подстановки π без неподвижной точки (0, 0)
	cycle = [(1, 0)]
	while True:
		x, y = cycle[-1]
		nxt = (y, (2 * x + 3 * y) % 5)
		if nxt == cycle[0]: break
		cycle.append(nxt)
	assert len(cycle) == 24
	for rnd in range(ROUNDS):
		# θ: чётности столбцов
		c = []
		for x in range(5):
			r = free.pop(0); c.append(r)
			prog.append(('eor3', r, where[(x, 0)], where[(x, 1)], where[(x, 2)]))
			prog.append(('eor3', r, r, where[(x, 3)], where[(x, 4)]))
		# θ: слагаемые D; D2…D4 ложатся на место отработавших чётностей
		d = [None] * 5
		d[0] = free.pop(0); prog.append(('rax1', d[0], c[4], c[1]))
		d[1] = free.pop(0); prog.append(('rax1', d[1], c[0], c[2]))
		d[2] = c[1]; prog.append(('rax1', d[2], c[1], c[3]))
		d[3] = c[2]; prog.append(('rax1', d[3], c[2], c[4]))
		d[4] = c[3]; prog.append(('rax1', d[4], c[3], c[0]))
		free += [c[0], c[4]]
		# θ + ρ + π: полоса (0, 0) без сдвига, остальные по циклу подстановки на месте
		prog.append(('eor', where[(0, 0)], where[(0, 0)], d[0]))
		t = free.pop(0)
		prog.append(('mov', t, where[cycle[0]]))
		def src(k): return cycle[k - 1]
		for k in [0] + list(range(23, 0, -1)):
			sx, sy = src(k)
			reg = t if k == 1 else where[(sx, sy)]
			prog.append(('xar', where[cycle[k]], reg, d[sx], 64 - RHO[sx][sy]))
		free += [t] + d[:2] + [c[1], c[2], c[3]]
		# χ: итоги строки в свободные регистры
		for y in range(5):
			old = [where[(i, y)] for i in range(5)]
			new = [free.pop(0) for _ in range(5)]
			for i in range(5):
				prog.append(('bcax', new[i], old[i], old[(i + 2) % 5], old[(i + 1) % 5]))
				where[(i, y)] = new[i]
			free += old
		# ι
		t = free.pop(0)
		prog.append(('iota', rnd, t))
		prog.append(('eor', where[(0, 0)], where[(0, 0)], t))
		free.append(t)
	for y in range(5):
		for x in range(5):
			prog.append(('str', where[(x, y)], lane(x, y)))
	return prog

def execute_aarch64(state, prog):
	mem = list(state)
	regs = [0] * VREGS
	for ins in prog:
		op = ins[0]
		if op == 'ldr': regs[ins[2]] = mem[ins[1]]
		elif op == 'str': mem[ins[2]] = regs[ins[1]]
		elif op == 'eor3': regs[ins[1]] = regs[ins[2]] ^ regs[ins[3]] ^ regs[ins[4]]
		elif op == 'rax1': regs[ins[1]] = regs[ins[2]] ^ rol(regs[ins[3]], 1)
		elif op == 'xar':
			v = regs[ins[2]] ^ regs[ins[3]]
			regs[ins[1]] = ((v >> ins[4]) | (v << (64 - ins[4]))) & M64
		elif op == 'eor': regs[ins[1]] = regs[ins[2]] ^ regs[ins[3]]
		elif op == 'bcax': regs[ins[1]] = regs[ins[2]] ^ (regs[ins[3]] & (~regs[ins[4]] & M64))
		elif op == 'mov': regs[ins[1]] = regs[ins[2]]
		elif op == 'iota': regs[ins[2]] = IOTA[ins[1]]
		else: raise ValueError(ins)
	return mem

def text_aarch64(ins):
	op = ins[0]
	V = lambda r: 'v%d.16b' % r
	D = lambda r: 'v%d.2d' % r
	if op == 'ldr': return 'ldr d%d, [%%[state], #%d]' % (ins[2], 8 * ins[1])
	if op == 'str': return 'str d%d, [%%[state], #%d]' % (ins[1], 8 * ins[2])
	if op == 'eor3': return 'eor3 %s, %s, %s, %s' % (V(ins[1]), V(ins[2]), V(ins[3]), V(ins[4]))
	if op == 'rax1': return 'rax1 %s, %s, %s' % (D(ins[1]), D(ins[2]), D(ins[3]))
	if op == 'xar': return 'xar %s, %s, %s, #%d' % (D(ins[1]), D(ins[2]), D(ins[3]), ins[4])
	if op == 'eor': return 'eor %s, %s, %s' % (V(ins[1]), V(ins[2]), V(ins[3]))
	if op == 'bcax': return 'bcax %s, %s, %s, %s' % (V(ins[1]), V(ins[2]), V(ins[3]), V(ins[4]))
	if op == 'mov': return 'mov %s, %s' % (V(ins[1]), V(ins[2]))
	if op == 'iota': return 'ldr d%d, [%%[iota], #%d]' % (ins[2], 8 * ins[1])
	raise ValueError(ins)

# ---------------- текст ассемблера ----------------
def operand(o):
	if isinstance(o, str): return '%%' + o
	if o[0] == 'mem': return '%d(%%%s)' % (o[2], o[1])
	if o[0] == 'op': return '%[' + ('current' if o[1] == 'iota' else o[1]) + ']'
	raise ValueError(o)
def text(ins):
	op = ins[0]
	if op == 'mov': return 'movq %s, %s' % (operand(ins[1]), operand(ins[2]))
	if op == 'rol': return 'rolq $%d, %s' % (ins[1], operand(ins[2]))
	if op in ('xor', 'and', 'or'): return '%sq %s, %s' % (op, operand(ins[1]), operand(ins[2]))
	if op == 'not': return 'notq %s' % operand(ins[1])
	if op == 'xchg': return 'xchgq %s, %s' % (operand(ins[1]), operand(ins[2]))
	if op == 'add': return 'addq $%d, %s' % (ins[1], operand(ins[2]))
	if op == 'cmp': return 'cmpq %s, %s' % (operand(ins[1]), operand(ins[2]))
	raise ValueError(ins)

def main():
	body, nots = generate()
	arm = generate_aarch64()
	random.seed(1600)
	for trial in range(300):
		if trial == 0: s = [0] * 25
		elif trial == 1: s = [M64] * 25
		else: s = [random.getrandbits(64) for _ in range(25)]
		if execute(s, body) != reference(s):
			raise SystemExit('ядро x86-64 расходится с эталоном на пробе %d' % trial)
		if execute_aarch64(s, arm) != reference(s):
			raise SystemExit('ядро AArch64 расходится с эталоном на пробе %d' % trial)
	sys.stderr.write('сходимость на 300 состояниях есть; x86-64: команд в круге %d, инверсий %d; AArch64: команд всего %d\n' % (len(body), nots, len(arm)))
	entry = [('mov', ('op', 'state'), PA), ('lea', 'buffer', PT)]
	lines = []
	def emit(s): lines.append('\t\t"' + s + '\\n\\t"')
	out = []
	out.append('/**')
	out.append(' * @file keccak.hpp')
	out.append(' * @date 2026-09-23')
	out.append(' *')
	out.append(' * @license{LicenseRef-A-NTS-1.0}')
	out.append(' *')
	out.append(' * @author Yuriy Lobarev')
	out.append(' *')
	out.append(' * @telegram{forman}')
	out.append(' * @phone{+7 (910) 983-95-90}')
	out.append(' *')
	out.append(' * @email forman@anyks.com')
	out.append(' * @site https://anyks.com')
	out.append(' *')
	out.append(' * @brief Ядро перестановки Keccak-f[1600] на встроенном ассемблере x86-64')
	out.append(' *')
	out.append(' * @details Файл порождён сценарием tools/digest/keccak.py и руками не правится: правки')
	out.append(' *          вносятся в сценарий, который сличает порождённый список команд с эталонной')
	out.append(' *          перестановкой по FIPS 202 на случайных состояниях до выдачи текста. Устройство:')
	out.append(' *          два накопителя по 25 полос, круг читает один и пишет другой; чётности столбцов')
	out.append(' *          и слагаемые θ в регистрах; шесть полос хранятся инвертированными (дополнение')
	out.append(' *          полос), оттого χ обходится одним not на строку; указатель на константы ι лежит')
	out.append(' *          в памяти, поскольку rbp не берётся. Полосы (x, y) лежат по смещению 8·(x + 5y)')
	out.append(' *')
	out.append(' * @copyright Copyright © 2026')
	out.append(' *')
	out.append(' */')
	out.append('')
	out.append('/**')
	out.append(' * Экранируем повторную инициализацию модуля')
	out.append(' */')
	out.append('#ifndef __ANTS_DIGEST_KECCAK__')
	out.append('#define __ANTS_DIGEST_KECCAK__')
	out.append('')
	out.append('/**')
	out.append(' * Стандартные заголовочные файлы')
	out.append(' */')
	out.append('#include <cstdint>')
	out.append('#include <cstddef>')
	out.append('')
	out.append('/**')
	out.append(' * Ядро берётся у gcc и clang на x86-64; у прочих собирателей и архитектур остаётся переносимая перестановка')
	out.append(' */')
	out.append('#if defined(__x86_64__) && defined(__GNUC__) && !defined(_MSC_VER)')
	out.append('\t/**')
	out.append('\t * Признак наличия ядра на ассемблере')
	out.append('\t */')
	out.append('\t#define __ANTS_KECCAK_X86_64__')
	out.append('\t/**')
	out.append('\t * @brief Основное пространство имён')
	out.append('\t *')
	out.append('\t */')
	out.append('\tnamespace nts {')
	out.append('\t\t/**')
	out.append('\t\t * @brief Пространство имён модулей хеширования')
	out.append('\t\t *')
	out.append('\t\t */')
	out.append('\t\tnamespace digest {')
	out.append('\t\t\t/**')
	out.append('\t\t\t * @brief Пространство имён ядер на ассемблере')
	out.append('\t\t\t *')
	out.append('\t\t\t */')
	out.append('\t\t\tnamespace kernel {')
	SHIFT = len(out)
	out.append('\t/**')
	out.append('\t * @brief Метод перестановки состояния ядром на ассемблере')
	out.append('\t *')
	out.append('\t * @param state состояние в 25 полос по смещению 8·(x + 5y)')
	out.append('\t * @param iota  константы ι двадцати четырёх кругов')
	out.append('\t *')
	out.append('\t */')
	out.append('\tstatic inline void keccak(uint64_t * state, const uint64_t * iota) noexcept {')
	out.append('\t\t// Второй накопитель состояния: круги пишут попеременно в состояние и в него')
	out.append('\t\tuint64_t buffer[25];')
	out.append('\t\t// Указатель на константу текущего круга и на конец таблицы')
	out.append('\t\tconst uint64_t * current = iota;')
	out.append('\t\tconst uint64_t * end = (iota + %d);' % ROUNDS)
	out.append('\t\t__asm__ __volatile__ (')
	lines.append('\t\t/* Указатели на состояние и второй накопитель */')
	emit('movq %[state], %%' + PA)
	emit('leaq %[buffer], %%' + PT)
	lines.append('\t\t/* Инверсия полос маски дополнения на входе */')
	for (x, y) in sorted(MASK, key=lambda p: lane(*p)): emit('notq %d(%%%s)' % (off(x, y), PA))
	lines.append('\t\t/* Полосы строки 4 в регистры чётностей */')
	for x in range(5): emit('movq %d(%%%s), %%%s' % (off(x, 4), PA, CREG[x]))
	lines.append('\t\t/* Круг: θ, затем строки по одной - ρ, π, χ и ι */')
	emit('1:')
	for ins in body: emit(text(ins).replace('%%', '%'))
	emit('jne 1b')
	lines.append('\t\t/* Инверсия полос маски дополнения на выходе */')
	for (x, y) in sorted(MASK, key=lambda p: lane(*p)): emit('notq %d(%%%s)' % (off(x, y), PA))
	# в тексте C++ каждый % регистра удваивается
	fixed = []
	for l in lines:
		if l.strip().startswith('/*'): fixed.append(l); continue
		s = l.replace('%%', '\x00').replace('%', '%%').replace('\x00', '%%')
		s = s.replace('%%[', '%[')
		fixed.append(s)
	out += fixed
	out.append('\t\t\t: [current] "+m" (current), [buffer] "=m" (buffer)')
	out.append('\t\t\t: [state] "m" (state), [end] "m" (end)')
	out.append('\t\t\t: "%s", "cc", "memory"' % '", "'.join([PA, PT] + CREG + DREG + TREG))
	out.append('\t\t);')
	out.append('\t}')
	out.append('\t\t\t};')
	out.append('\t\t};')
	out.append('\t};')
	out.append('#endif')
	out.append('')
	# тело функции x86-64 и вставка лежат внутри трёх пространств имён: три дополнительных отступа
	for i in range(SHIFT, len(out) - 5):
		if out[i]: out[i] = '\t\t\t' + out[i]
	out.append('/**')
	out.append(' * Ядро на командах SHA-3 (FEAT_SHA3: eor3, rax1, xar, bcax) берётся на AArch64, когда собиратель')
	out.append(' * объявляет их доступными (__ARM_FEATURE_SHA3: clang на процессорах Apple задаёт его сам, у gcc и')
	out.append(' * clang под Linux он появляется от -march=armv8.2-a+sha3) - как у MGM с __ARM_FEATURE_AES')
	out.append(' */')
	out.append('#if defined(__aarch64__) && defined(__ARM_FEATURE_SHA3) && !defined(ANTS_NO_MACHINE)')
	out.append('\t/**')
	out.append('\t * Признак наличия ядра на командах SHA-3')
	out.append('\t */')
	out.append('\t#define __ANTS_KECCAK_AARCH64__')
	out.append('\t/**')
	out.append('\t * @brief Основное пространство имён')
	out.append('\t *')
	out.append('\t */')
	out.append('\tnamespace nts {')
	out.append('\t\t/**')
	out.append('\t\t * @brief Пространство имён модулей хеширования')
	out.append('\t\t *')
	out.append('\t\t */')
	out.append('\t\tnamespace digest {')
	out.append('\t\t\t/**')
	out.append('\t\t\t * @brief Пространство имён ядер на ассемблере')
	out.append('\t\t\t *')
	out.append('\t\t\t */')
	out.append('\t\t\tnamespace kernel {')
	out.append('\t\t\t\t/**')
	out.append('\t\t\t\t * @brief Метод перестановки состояния ядром на командах SHA-3')
	out.append('\t\t\t\t *')
	out.append('\t\t\t\t * @param state состояние в 25 полос по смещению 8·(x + 5y)')
	out.append('\t\t\t\t * @param iota  константы ι двадцати четырёх кругов')
	out.append('\t\t\t\t *')
	out.append('\t\t\t\t * @note Полосы живут в младших половинах v0…v31, все круги развёрнуты, итоги χ')
	out.append('\t\t\t\t *       ложатся в свободные регистры (переименование без копий): %d команд' % len(arm))
	out.append('\t\t\t\t */')
	out.append('\t\t\t\tstatic inline void keccak(uint64_t * state, const uint64_t * iota) noexcept {')
	out.append('\t\t\t\t\t__asm__ __volatile__ (')
	for ins in arm:
		out.append('\t\t\t\t\t\t"' + text_aarch64(ins) + '\\n\\t"')
	out.append('\t\t\t\t\t\t:')
	out.append('\t\t\t\t\t\t: [state] "r" (state), [iota] "r" (iota)')
	out.append('\t\t\t\t\t\t: %s, "memory"' % ', '.join('"v%d"' % i for i in range(VREGS)))
	out.append('\t\t\t\t\t);')
	out.append('\t\t\t\t}')
	out.append('\t\t\t};')
	out.append('\t\t};')
	out.append('\t};')
	out.append('#endif')
	out.append('')
	out.append('#endif // __ANTS_DIGEST_KECCAK__')
	print('\n'.join(out))

if __name__ == '__main__':
	main()
