#!/usr/bin/env python3
#
# Порождатель ядер на восемь слов для AArch64 (модуль 2^512 - c): текст макросов
# встроенного ассемблера для src/internal/math/kernels.hpp
#
# Ядра: произведение восьми слов на восемь рядами по слову второго сомножителя со
# скользящим окном из девяти регистров (младшие половины произведений одной цепочкой
# переносов, старшие - второй, готовое младшее слово уходит в память), запись старшей
# половины, свёртка старшей половины хвостом c с условным вычитанием модуля прибавлением
# хвоста; квадрат треугольником произведений разных слов в память, удвоение цепочкой с
# диагональю квадратов слов, та же свёртка. Имена операндов: a0…a7 - слова первого
# сомножителя, w0…w8 - окно накопителя (позиция p живёт в регистре w[p mod 9]), t0…t3 -
# временные, m - слово второго сомножителя либо перенос, b - указатель на второй
# сомножитель, q - треугольник в памяти, r - итог, c - хвост модуля.
#
# Запуск: python3 tools/math/eightwords.py > kernels8.txt, затем текст переносится в
# kernels.hpp на место семи макросов __ANTS_AARCH64_*8__. Правки ядер вносятся сюда, а
# не в заголовок: сходимость проверена щупом на 300 000 входах с краями (круг 34,
# 23.09.2026); единственная ловушка при порождении - цепочка из одного элемента у
# последнего ряда треугольника, где перенос из младших половин уже учтён и складывать
# надо без него (add, не adc)
#
W = 8
def R(pos): return "%%[w%d]" % (pos % 9)
def T(k): return "%%[t%d]" % k
lines = []
def emit(s): lines.append('"' + s.replace('%%', '%') + '\\n\\t"')
# ---------------- произведение 8x8 ----------------
def product():
    out = []
    def e(s): out.append('"' + s.replace('%%', '%') + '\\n\\t"')
    for i in range(W):
        e("ldr %%[m], [%%[b], #%d]" % (8 * i))
        if i == 0:
            for j in range(W):
                e("mul %s, %%[a%d], %%[m]" % (R(j), j))
            # старшие половины
            for j in range(4): e("umulh %s, %%[a%d], %%[m]" % (T(j), j))
            e("adds %s, %s, %s" % (R(1), R(1), T(0)))
            e("adcs %s, %s, %s" % (R(2), R(2), T(1)))
            e("adcs %s, %s, %s" % (R(3), R(3), T(2)))
            e("adcs %s, %s, %s" % (R(4), R(4), T(3)))
            for j in range(4, 8): e("umulh %s, %%[a%d], %%[m]" % (T(j - 4), j))
            e("adcs %s, %s, %s" % (R(5), R(5), T(0)))
            e("adcs %s, %s, %s" % (R(6), R(6), T(1)))
            e("adcs %s, %s, %s" % (R(7), R(7), T(2)))
            e("adc %s, %s, xzr" % (R(8), T(3)))
        else:
            # младшие половины
            for j in range(4): e("mul %s, %%[a%d], %%[m]" % (T(j), j))
            e("adds %s, %s, %s" % (R(i), R(i), T(0)))
            for j in range(1, 4): e("adcs %s, %s, %s" % (R(i + j), R(i + j), T(j)))
            for j in range(4, 8): e("mul %s, %%[a%d], %%[m]" % (T(j - 4), j))
            for j in range(4, 8): e("adcs %s, %s, %s" % (R(i + j), R(i + j), T(j - 4)))
            e("adc %s, xzr, xzr" % R(i + 8))
            # старшие половины
            for j in range(4): e("umulh %s, %%[a%d], %%[m]" % (T(j), j))
            e("adds %s, %s, %s" % (R(i + 1), R(i + 1), T(0)))
            for j in range(1, 4): e("adcs %s, %s, %s" % (R(i + 1 + j), R(i + 1 + j), T(j)))
            for j in range(4, 8): e("umulh %s, %%[a%d], %%[m]" % (T(j - 4), j))
            for j in range(4, 7): e("adcs %s, %s, %s" % (R(i + 1 + j), R(i + 1 + j), T(j - 4)))
            e("adc %s, %s, %s" % (R(i + 8), R(i + 8), T(3)))
        e("str %s, [%%[r], #%d]" % (R(i), 8 * i))
    return out
# ---------------- свёртка и условное вычитание ----------------
# Старшая половина в регистрах H0..H7 (позиции 8..15 → R(8..15)); младшая в памяти r[0..7]
def fold(H):
    out = []
    def e(s): out.append('"' + s.replace('%%', '%') + '\\n\\t"')
    # младшая половина в a0..a7
    for j in range(0, 8, 2):
        e("ldp %%[a%d], %%[a%d], [%%[r], #%d]" % (j, j + 1, 8 * j))
    for j in range(4): e("mul %s, %s, %%[c]" % (T(j), H[j]))
    e("adds %%[a0], %%[a0], %s" % T(0))
    for j in range(1, 4): e("adcs %%[a%d], %%[a%d], %s" % (j, j, T(j)))
    for j in range(4, 8): e("mul %s, %s, %%[c]" % (T(j - 4), H[j]))
    for j in range(4, 8): e("adcs %%[a%d], %%[a%d], %s" % (j, j, T(j - 4)))
    e("adc %%[m], xzr, xzr")
    for j in range(4): e("umulh %s, %s, %%[c]" % (T(j), H[j]))
    e("adds %%[a1], %%[a1], %s" % T(0))
    for j in range(1, 4): e("adcs %%[a%d], %%[a%d], %s" % (j + 1, j + 1, T(j)))
    for j in range(4, 8): e("umulh %s, %s, %%[c]" % (T(j - 4), H[j]))
    for j in range(4, 7): e("adcs %%[a%d], %%[a%d], %s" % (j + 1, j + 1, T(j - 4)))
    e("adc %%[m], %%[m], %s" % T(3))
    # вторая свёртка: перенос m не превосходит c + 1, произведение умещается в слово
    e("mul %s, %%[m], %%[c]" % T(0))
    e("adds %%[a0], %%[a0], %s" % T(0))
    for j in range(1, 8): e("adcs %%[a%d], %%[a%d], xzr" % (j, j))
    e("adc %%[m], xzr, xzr")
    # условное вычитание модуля: прибавление хвоста, выход за 2^512 либо прежний перенос
    e("adds %s, %%[a0], %%[c]" % H[0])
    for j in range(1, 8): e("adcs %s, %%[a%d], xzr" % (H[j], j))
    e("adc %%[m], %%[m], xzr")
    e("cmp %%[m], #0")
    for j in range(8): e("csel %%[a%d], %s, %%[a%d], ne" % (j, H[j], j))
    for j in range(0, 8, 2):
        e("stp %%[a%d], %%[a%d], [%%[r], #%d]" % (j, j + 1, 8 * j))
    return out
# ---------------- квадрат: треугольник ----------------
def triangle():
    out = []
    def e(s): out.append('"' + s.replace('%%', '%') + '\\n\\t"')
    e("str xzr, [%[q], #0]")
    e("str xzr, [%[q], #120]")
    for i in range(W - 1):
        js = list(range(i + 1, W))
        # младшие половины
        if i == 0:
            for j in js: e("mul %s, %%[a0], %%[a%d]" % (R(j), j))
            # старшие
            grp = js
            for k in range(0, len(grp), 4):
                part = grp[k:k + 4]
                for n, j in enumerate(part): e("umulh %s, %%[a0], %%[a%d]" % (T(n), j))
                for n, j in enumerate(part):
                    pos = j + 1
                    if k == 0 and n == 0: e("adds %s, %s, %s" % (R(pos), R(pos), T(n)))
                    elif pos == 8: e("adc %s, %s, xzr" % (R(pos), T(n)))
                    else: e("adcs %s, %s, %s" % (R(pos), R(pos), T(n)))
        else:
            first = True
            for k in range(0, len(js), 4):
                part = js[k:k + 4]
                for n, j in enumerate(part): e("mul %s, %%[a%d], %%[a%d]" % (T(n), i, j))
                for n, j in enumerate(part):
                    pos = i + j
                    if first: e("adds %s, %s, %s" % (R(pos), R(pos), T(n))); first = False
                    else: e("adcs %s, %s, %s" % (R(pos), R(pos), T(n)))
            e("adc %s, xzr, xzr" % R(i + 8))
            first = True
            for k in range(0, len(js), 4):
                part = js[k:k + 4]
                for n, j in enumerate(part): e("umulh %s, %%[a%d], %%[a%d]" % (T(n), i, j))
                for n, j in enumerate(part):
                    pos = i + j + 1
                    # единственный элемент цепочки: перенос из младших уже учтён, складывать без него
                    if pos == i + 8 and first: e("add %s, %s, %s" % (R(pos), R(pos), T(n)))
                    elif pos == i + 8: e("adc %s, %s, %s" % (R(pos), R(pos), T(n)))
                    elif first: e("adds %s, %s, %s" % (R(pos), R(pos), T(n))); first = False
                    else: e("adcs %s, %s, %s" % (R(pos), R(pos), T(n)))
        e("str %s, [%%[q], #%d]" % (R(2 * i + 1), 8 * (2 * i + 1)))
        e("str %s, [%%[q], #%d]" % (R(2 * i + 2), 8 * (2 * i + 2)))
    return out
# ---------------- квадрат: удвоение, диагональ, свёртка ----------------
def diagonal():
    out = []
    def e(s): out.append('"' + s.replace('%%', '%') + '\\n\\t"')
    Tn = ["%%[w%d]" % k for k in range(8)]
    for j in range(0, 8, 2): e("ldp %s, %s, [%%[q], #%d]" % (Tn[j], Tn[j + 1], 8 * j))
    e("adds %s, %s, %s" % (Tn[0], Tn[0], Tn[0]))
    for j in range(1, 8): e("adcs %s, %s, %s" % (Tn[j], Tn[j], Tn[j]))
    e("adc %[w8], xzr, xzr")
    # диагональ младшая: a0^2..a3^2
    for k in range(2):
        for n in range(2):
            i = 2 * k + n
            e("mul %s, %%[a%d], %%[a%d]" % (T(2 * n), i, i)); e("umulh %s, %%[a%d], %%[a%d]" % (T(2 * n + 1), i, i))
        for n in range(4):
            pos = 4 * k + n
            if pos == 0: e("adds %s, %s, %s" % (Tn[pos], Tn[pos], T(n)))
            else: e("adcs %s, %s, %s" % (Tn[pos], Tn[pos], T(n)))
    e("adc %[m], xzr, xzr")
    for j in range(0, 8, 2): e("stp %s, %s, [%%[r], #%d]" % (Tn[j], Tn[j + 1], 8 * j))
    for j in range(0, 8, 2): e("ldp %s, %s, [%%[q], #%d]" % (Tn[j], Tn[j + 1], 64 + 8 * j))
    e("cmp %[w8], #1")
    for j in range(8): e("adcs %s, %s, %s" % (Tn[j], Tn[j], Tn[j]))
    e("cmp %[m], #1")
    for k in range(2):
        for n in range(2):
            i = 4 + 2 * k + n
            e("mul %s, %%[a%d], %%[a%d]" % (T(2 * n), i, i)); e("umulh %s, %%[a%d], %%[a%d]" % (T(2 * n + 1), i, i))
        for n in range(4):
            pos = 4 * k + n
            e("adcs %s, %s, %s" % (Tn[pos], Tn[pos], T(n)))
    return out
# ---------------- текст для kernels.hpp: по четыре команды в строке, имена проекта ----------------
def pack(items, per=4):
    rows = []
    for k in range(0, len(items), per):
        rows.append(" ".join(items[k:k + per]))
    return rows
def store_high(H):
    out = []
    def e(s): out.append('"' + s.replace('%%', '%') + '\\n\\t"')
    for j in range(0, 8, 2): e("stp %s, %s, [%%[r], #%d]" % (H[j], H[j + 1], 64 + 8 * j))
    return out
macros = [
    ("__ANTS_AARCH64_PRODUCT8__", product()),
    ("__ANTS_AARCH64_HIGH8_PRODUCT__", store_high([R(8 + k) for k in range(8)])),
    ("__ANTS_AARCH64_FOLD8_PRODUCT__", fold([R(8 + k) for k in range(8)])),
    ("__ANTS_AARCH64_TRIANGLE8__", triangle()),
    ("__ANTS_AARCH64_DIAGONAL8__", diagonal()),
    ("__ANTS_AARCH64_HIGH8_SQUARE__", store_high(["%%[w%d]" % k for k in range(8)])),
    ("__ANTS_AARCH64_FOLD8_SQUARE__", fold(["%%[w%d]" % k for k in range(8)])),
]
import sys
f = sys.stdout
if True:
    for name, items in macros:
        f.write("\t\t\t\t#define %s \\\n" % name)
        rows = pack(items)
        for n, row in enumerate(rows):
            f.write("\t\t\t\t\t" + row + (" \\\n" if n + 1 < len(rows) else "\n"))
