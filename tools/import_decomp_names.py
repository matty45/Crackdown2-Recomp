#!/usr/bin/env python3
"""Turn the Crackdown2-Decomp symbol CSV into a rexglue [functions] name table.

Usage:
  import_decomp_names.py <auto_names.csv> <existing_functions.toml> <out.toml>
      --pdata <pdata.csv> [--undname PATH] [--include-loose]

<pdata.csv> is the XEX exception directory as written by tools/dump_pdata.py
(address,size,prolog,exception per line). Only addresses present there are
emitted, each with its pdata size: a [functions] entry without a size takes
CONFIG authority with an unknown extent, which outranks the pdata length and
lets block discovery run past the function into whatever follows (observed:
the __restgprlr helper block after ftell got swallowed, leaving an unresolved
call that aborts at startup).

Only rows matched 'exact-strict' are used unless --include-loose is given.
Addresses already named in the existing TOML are skipped. MSVC-mangled names
are demangled with llvm-undname and reduced to Class__method identifiers;
plain C names and unqualified C++ names get a 'guest_' prefix so they never collide with host libc/CRT
symbols. Overloads that sanitize to the same identifier get the address as a
suffix. The output is a TOML fragment to list in the manifest's `includes`.
"""
import csv, re, subprocess, sys, hashlib, argparse

def sanitize(s):
    s = s.replace('::', '__')
    s = re.sub(r'[^A-Za-z0-9_]', '_', s)
    s = re.sub(r'_+', '_', s).strip('_')
    if not s:
        s = 'unnamed'
    if s[0].isdigit():
        s = '_' + s
    if len(s) > 100:
        s = s[:88] + '_' + hashlib.sha1(s.encode()).hexdigest()[:8]
    return s

CXX_KEYWORDS = set("""alignas alignof and and_eq asm auto bitand bitor bool break case catch char char8_t char16_t
char32_t class compl concept const consteval constexpr constinit const_cast continue co_await co_return co_yield
decltype default delete do double dynamic_cast else enum explicit export extern false float for friend goto if inline
int long mutable namespace new noexcept not not_eq nullptr operator or or_eq private protected public register
reinterpret_cast requires return short signed sizeof static static_assert static_cast struct switch template this
thread_local throw true try typedef typeid typename union unsigned using virtual void volatile wchar_t while xor
xor_eq main""".split())

OPERATOR_WORDS = [
    ('operator new[]', 'operator_new_array'), ('operator delete[]', 'operator_delete_array'),
    ('operator new', 'operator_new'), ('operator delete', 'operator_delete'),
    ('operator==', 'operator_eq'), ('operator!=', 'operator_ne'), ('operator<=', 'operator_le'),
    ('operator>=', 'operator_ge'), ('operator<<', 'operator_shl'), ('operator>>', 'operator_shr'),
    ('operator->', 'operator_arrow'), ('operator++', 'operator_inc'), ('operator--', 'operator_dec'),
    ('operator+=', 'operator_add_assign'), ('operator-=', 'operator_sub_assign'),
    ('operator*=', 'operator_mul_assign'), ('operator/=', 'operator_div_assign'),
    ('operator&&', 'operator_land'), ('operator||', 'operator_lor'),
    ('operator[]', 'operator_index'), ('operator()', 'operator_call'),
    ('operator=', 'operator_assign'), ('operator<', 'operator_lt'), ('operator>', 'operator_gt'),
    ('operator+', 'operator_add'), ('operator-', 'operator_sub'), ('operator*', 'operator_mul'),
    ('operator/', 'operator_div'), ('operator%', 'operator_mod'), ('operator&', 'operator_and'),
    ('operator|', 'operator_or'), ('operator^', 'operator_xor'), ('operator~', 'operator_not'),
    ('operator!', 'operator_lnot'), ('operator,', 'operator_comma'),
]

def qualified_from_demangled(d):
    """Reduce an llvm-undname line to the qualified function name.
    e.g. 'public: static void __cdecl A::B::name(int)'   -> 'A::B::name'
         "A::`scalar deleting dtor'(unsigned int)"        -> 'A::scalar_deleting_dtor'
         'bool __cdecl A::operator==(class A const &)'    -> 'A::operator_eq'"""
    d = d.strip()
    # Replace operator spellings before any splitting on punctuation.
    for spelled, word in OPERATOR_WORDS:
        if spelled in d:
            d = d.replace(spelled, word)
            break
    # Backtick names: `scalar deleting dtor', `vector deleting dtor', `default ctor closure' ...
    d = re.sub(r"`([^']*)'", lambda m: re.sub(r'[^A-Za-z0-9_]', '_', m.group(1)), d)
    # The qualified name is the identifier chain immediately before the first '(' that
    # is not inside template brackets.
    depth = 0
    cut = None
    for i, ch in enumerate(d):
        if ch == '<':
            depth += 1
        elif ch == '>':
            depth = max(0, depth - 1)
        elif ch == '(' and depth == 0:
            cut = i
            break
    head = d[:cut] if cut is not None else d
    # Walk backwards over the identifier chain (letters, digits, _, ::, ~ and balanced <>).
    j = len(head)
    depth = 0
    while j > 0:
        ch = head[j - 1]
        if ch == '>':
            depth += 1
        elif ch == '<':
            depth -= 1
        elif depth == 0 and not (ch.isalnum() or ch in '_:~'):
            break
        j -= 1
    name = head[j:].strip(': ')
    if not name:
        return None
    # Drop template argument lists for readability; the address suffix keeps overloads apart.
    name = re.sub(r'<[^<>]*>', '', name)
    while '<' in name and '>' in name:
        name = re.sub(r'<[^<>]*>', '', name)
    return name

def demangle_all(names, undname):
    out = {}
    mangled = [n for n in names if n.startswith('?')]
    if not mangled:
        return out
    proc = subprocess.run([undname], input='\n'.join(mangled) + '\n', capture_output=True, text=True)
    lines = proc.stdout.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith('?'):
            dem = lines[i + 1] if i + 1 < len(lines) else ''
            out[line] = dem if dem and not dem.startswith('?') else None
            i += 2
            while i < len(lines) and lines[i].strip() == '':
                i += 1
        else:
            i += 1
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('csv'); ap.add_argument('existing_toml'); ap.add_argument('out_toml')
    ap.add_argument('--undname', default='llvm-undname')
    ap.add_argument('--pdata', required=True, help='function table CSV from tools/dump_pdata.py')
    ap.add_argument('--include-loose', action='store_true')
    a = ap.parse_args()

    existing = open(a.existing_toml).read()
    have_addrs = set(int(m, 16) for m in re.findall(r'^0x([0-9A-Fa-f]+)\s*=', existing, re.M))
    have_names = set(re.findall(r'name\s*=\s*"([^"]+)"', existing))

    rows = [r for r in csv.DictReader(open(a.csv))
            if r['match'] == 'exact-strict' or (a.include_loose and r['match'] == 'exact-loose')]
    rows = [r for r in rows if int(r['address'], 16) not in have_addrs]
    pdata = {}
    for line in open(a.pdata):
        addr_s, size_s = line.strip().split(',')[:2]
        pdata[int(addr_s, 16)] = int(size_s)
    stats_nopdata = sum(1 for r in rows if int(r['address'], 16) not in pdata)
    rows = [r for r in rows if int(r['address'], 16) in pdata]
    dem = demangle_all([r['name'] for r in rows], a.undname)

    used = set(have_names)
    entries = []
    stats = dict(mangled=0, plain=0, failed=0, dup=0)
    for r in sorted(rows, key=lambda r: int(r['address'], 16)):
        addr = int(r['address'], 16)
        raw = r['name']
        if raw.startswith('?'):
            d = dem.get(raw)
            q = qualified_from_demangled(d) if d else None
            if not q:
                stats['failed'] += 1
                continue
            # Unqualified C++ names (terminate, swprintf_s, operator new...) live at
            # global scope on the host too and collide with the MSVC CRT headers.
            name = sanitize(q) if '::' in q else 'guest_' + sanitize(q)
            stats['mangled'] += 1
        else:
            name = 'guest_' + sanitize(raw)
            stats['plain'] += 1
        if name in CXX_KEYWORDS or name.startswith('__') or name.startswith('sub_'):
            name = 'fn_' + name.lstrip('_')
        if name in used:
            name = f'{name}_{addr:08X}'
            stats['dup'] += 1
        used.add(name)
        entries.append((addr, name, raw, pdata[addr]))

    with open(a.out_toml, 'w') as f:
        f.write('# Generated by tools/import_decomp_names.py from the Crackdown2-Decomp symbol CSV.\n')
        f.write('# Each entry carries its pdata size so the analysis matches the unnamed build.\n\n[functions]\n')
        for addr, name, raw, size in entries:
            f.write(f'0x{addr:08X} = {{ name = "{name}", size = {size} }}  # {raw}\n')
    stats['no_pdata_skipped'] = stats_nopdata
    print(f'wrote {len(entries)} entries to {a.out_toml}; stats={stats}')

if __name__ == '__main__':
    main()
