#!/usr/bin/env python3
"""Mescla nos .proto do hypermeow as definicoes protobuf de um bundle do WhatsApp Web.

Os modulos `*.pb.js` do bundle (extraidos pelo cellar) sao lidos de forma estatica: o
script interpreta so o subconjunto de JavaScript que eles usam e nunca executa o codigo.
Os .proto existentes sao a base. Os nomes ja adaptados pelo fork (stanzaID, JID etc.)
ficam como estao; o script acrescenta, altera ou remove o que mudou no bundle.

Uso (a partir de qualquer pasta):
    python3 -I protomerge.py <pasta modules do bundle> <pasta proto>            # so relata
    python3 -I protomerge.py <pasta modules do bundle> <pasta proto> --write    # grava
"""
import argparse
import os
import re
import sys

# ----------------------------------------------------------------------------
# Leitura estatica dos modulos .pb.js
# ----------------------------------------------------------------------------

TOKEN_RE = re.compile(r'''
 (?P<ws>\s+|//[^\n]*|/\*.*?\*/)
|(?P<num>0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)
|(?P<str>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')
|(?P<id>[A-Za-z_$][A-Za-z0-9_$]*)
|(?P<op>[^\sA-Za-z0-9_$"'])
''', re.X | re.S)

FLAG_REPEATED, FLAG_PACKED, FLAG_REQUIRED, TYPE_MASK = 64, 128, 256, 31
TYPES = {
    'INT32': 1, 'INT64': 2, 'UINT32': 3, 'UINT64': 4, 'SINT32': 5, 'SINT64': 6, 'BOOL': 7,
    'ENUM': 8, 'FIXED64': 9, 'SFIXED64': 10, 'DOUBLE': 11, 'STRING': 12, 'BYTES': 13,
    'MESSAGE': 14, 'FIXED32': 15, 'SFIXED32': 16, 'FLOAT': 17, 'MAP': 18,
}
TYPE_NAMES = {v: k.lower() for k, v in TYPES.items()}
T_ENUM, T_MESSAGE, T_MAP = TYPES['ENUM'], TYPES['MESSAGE'], TYPES['MAP']
SCALARS = {n for n in TYPE_NAMES.values() if n not in ('enum', 'message', 'map')}


class JSObj(dict):
    __hash__ = lambda self: id(self)
    __eq__ = lambda self, other: self is other


class RequireFn:
    pass


class ModRef:
    def __init__(self, name):
        self.name = name


class ExtRef:
    def __init__(self, mod, attr):
        self.mod, self.attr = mod, attr


class EnumObj:
    def __init__(self, values):
        self.values = values
        self.path = None


class EnumVal:
    def __init__(self, enum, name):
        self.enum, self.name = enum, name


def js_const():
    c = JSObj()
    c['FLAGS'] = JSObj(REPEATED=FLAG_REPEATED, PACKED=FLAG_PACKED, REQUIRED=FLAG_REQUIRED)
    c['TYPES'] = JSObj(TYPES)
    c['TYPE_MASK'] = TYPE_MASK
    return c


PROTO_CONST = js_const()


def tokenize(src):
    toks, pos = [], 0
    while pos < len(src):
        m = TOKEN_RE.match(src, pos)
        if not m:
            raise SyntaxError('token inesperado em %d: %r' % (pos, src[pos:pos + 30]))
        pos = m.end()
        kind = m.lastgroup
        if kind != 'ws':
            toks.append((kind, m.group()))
    toks.append(('eof', ''))
    return toks


class Parser:
    def __init__(self, toks):
        self.t, self.p = toks, 0

    def peek(self, val=None):
        tok = self.t[self.p]
        return tok[1] == val and tok[0] in ('op', 'id') if val is not None else tok

    def next(self):
        tok = self.t[self.p]
        self.p += 1
        return tok

    def expect(self, val):
        tok = self.next()
        if tok[1] != val:
            raise SyntaxError('esperava %r, veio %r (token %d)' % (val, tok[1], self.p))

    def module(self):
        self.expect('__d')
        self.expect('(')
        name = unquote(self.next()[1])
        self.expect(',')
        self.assign()
        self.expect(',')
        paren = self.peek('(')
        if paren:
            self.next()
        self.expect('function')
        self.expect('(')
        params = []
        while not self.peek(')'):
            params.append(self.next()[1])
            if self.peek(','):
                self.next()
        self.expect(')')
        self.expect('{')
        body = []
        while not self.peek('}'):
            body.append(self.statement())
        self.expect('}')
        return name, params, body

    def statement(self):
        if self.peek('function'):
            # Funcao auxiliar (nao descreve protobuf): pula o corpo inteiro.
            self.next()
            name = self.next()[1]
            while not self.peek('{'):
                self.next()
            depth = 0
            while True:
                tok = self.next()
                if tok[0] == 'eof':
                    raise SyntaxError('funcao sem fim')
                if tok == ('op', '{'):
                    depth += 1
                elif tok == ('op', '}'):
                    depth -= 1
                    if depth == 0:
                        break
            return ('var', [(name, None)])
        if self.peek('var'):
            self.next()
            decls = []
            while True:
                name = self.next()[1]
                init = None
                if self.peek('='):
                    self.next()
                    init = self.assign()
                decls.append((name, init))
                if self.peek(','):
                    self.next()
                    continue
                break
            self.expect(';')
            return ('var', decls)
        expr = self.expr()
        self.expect(';')
        return ('expr', expr)

    def expr(self):
        items = [self.assign()]
        while self.peek(','):
            self.next()
            items.append(self.assign())
        return items[0] if len(items) == 1 else ('seq', items)

    def assign(self):
        left = self.bitor()
        if self.peek('='):
            if left[0] not in ('name', 'member'):
                raise SyntaxError('atribuicao a algo que nao e variavel')
            self.next()
            return ('assign', left, self.assign())
        return left

    def bitor(self):
        left = self.unary()
        while self.peek('|'):
            self.next()
            left = ('or', left, self.unary())
        return left

    def unary(self):
        if self.peek('-'):
            self.next()
            return ('neg', self.unary())
        if self.peek('!'):
            self.next()
            return ('not', self.unary())
        return self.postfix()

    def postfix(self):
        node = self.primary()
        while True:
            if self.peek('.'):
                self.next()
                node = ('member', node, self.next()[1])
            elif self.peek('('):
                self.next()
                args = []
                while not self.peek(')'):
                    args.append(self.assign())
                    if self.peek(','):
                        self.next()
                self.expect(')')
                node = ('call', node, args)
            else:
                return node

    def primary(self):
        kind, val = self.next()
        if kind == 'num':
            if val[:2].lower() == '0x':
                return ('const', int(val, 16))
            num = float(val)
            return ('const', int(num) if num.is_integer() else num)
        if kind == 'str':
            return ('const', unquote(val))
        if kind == 'id':
            if val in ('function', 'new', 'typeof', 'void', 'delete'):
                raise SyntaxError('construcao nao suportada: %s' % val)
            return ('name', val)
        if val == '(':
            node = self.expr()
            self.expect(')')
            return node
        if val == '{':
            props = []
            while not self.peek('}'):
                k_kind, k_val = self.next()
                key = unquote(k_val) if k_kind == 'str' else k_val
                self.expect(':')
                props.append((key, self.assign()))
                if self.peek(','):
                    self.next()
            self.expect('}')
            return ('obj', props)
        if val == '[':
            elems = []
            while not self.peek(']'):
                elems.append(self.assign())
                if self.peek(','):
                    self.next()
            self.expect(']')
            return ('arr', elems)
        raise SyntaxError('expressao inesperada: %r (token %d)' % (val, self.p))


def unquote(s):
    body = s[1:-1]
    return re.sub(r'\\(u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)',
                  lambda m: chr(int(m.group(1)[1:], 16)) if m.group(1)[0] in 'ux' and len(m.group(1)) > 1
                  else {'n': '\n', 't': '\t'}.get(m.group(1), m.group(1)), body)


class Interp:
    def __init__(self, params):
        self.env = {}
        self.exports = JSObj()
        self.msg_order = []
        self.enum_order = []
        for idx, name in enumerate(params):
            if idx in (1, 2, 3):
                self.env[name] = RequireFn()
        if len(params) >= 6:
            self.env[params[-1]] = self.exports

    def run(self, body):
        for kind, payload in body:
            if kind == 'var':
                for name, init in payload:
                    self.env[name] = self.ev(init) if init is not None else None
            else:
                self.ev(payload)

    def ev(self, node):
        op = node[0]
        if op == 'const':
            return node[1]
        if op == 'name':
            if node[1] in ('undefined', 'null'):
                return None
            return self.env[node[1]]
        if op == 'seq':
            val = None
            for item in node[1]:
                val = self.ev(item)
            return val
        if op == 'or':
            return self.ev(node[1]) | self.ev(node[2])
        if op == 'neg':
            return -self.ev(node[1])
        if op == 'not':
            return not self.ev(node[1])
        if op == 'obj':
            obj = JSObj()
            for key, val in node[1]:
                obj[key] = self.ev(val)
            return obj
        if op == 'arr':
            return [self.ev(e) for e in node[1]]
        if op == 'member':
            base = self.ev(node[1])
            if isinstance(base, ModRef):
                if base.name == 'WAProtoConst':
                    return PROTO_CONST[node[2]]
                return ExtRef(base.name, node[2])
            if isinstance(base, (EnumObj, ExtRef)):
                return EnumVal(base, node[2])
            if isinstance(base, JSObj):
                return base.get(node[2])
            raise TypeError('acesso .%s em %r' % (node[2], base))
        if op == 'call':
            fn = self.ev(node[1])
            args = [self.ev(a) for a in node[2]]
            if isinstance(fn, RequireFn):
                return ModRef(args[0])
            if isinstance(fn, ModRef) and fn.name == '$InternalEnum':
                enum = EnumObj(dict(args[0]))
                self.enum_order.append(enum)
                return enum
            raise TypeError('chamada nao suportada: %r' % (node[1],))
        if op == 'assign':
            val = self.ev(node[2])
            target = node[1]
            if target[0] == 'name':
                self.env[target[1]] = val
            else:
                base = self.ev(target[1])
                if not isinstance(base, JSObj):
                    raise TypeError('atribuicao em %r' % (base,))
                base[target[2]] = val
                if target[2] == 'name' and base not in self.msg_order:
                    self.msg_order.append(base)
            return val
        raise TypeError('no desconhecido %r' % (op,))


class BField:
    def __init__(self, name, num):
        self.name, self.num = name, num
        self.label, self.packed, self.oneof = 'optional', False, None
        self.kind, self.scalar, self.target, self.map = None, None, None, None


class BMsg:
    def __init__(self, path):
        self.path, self.fields, self.oneofs = path, [], {}


def camel(tokens):
    return ''.join(t[:1].upper() + t[1:].lower() for t in tokens)


class BModule:
    """Mensagens e enums de um modulo .pb.js."""

    def __init__(self, name, path):
        self.name = name
        with open(path, encoding='utf-8') as fh:
            mod_name, params, body = Parser(tokenize(fh.read())).module()
        interp = Interp(params)
        interp.run(body)
        self.enums, self.msgs, self.exports = {}, {}, {}
        self.plain_enums = {}
        objs = [o for o in interp.msg_order if 'internalSpec' in o]
        flat = {''.join(o['name'].split('$')).lower(): tuple(o['name'].split('$')) for o in objs}
        for key, val in interp.exports.items():
            val = self.as_enum(val)
            if isinstance(val, EnumObj):
                if not all(isinstance(v, int) for v in val.values.values()):
                    continue
                if val.path is None:
                    val.path = self.enum_path(key, flat)
                    self.enums[val.path] = val
                self.exports[key] = val.path
            elif isinstance(val, JSObj) and 'name' in val:
                self.exports[key[:-4] if key.endswith('Spec') else key] = tuple(val['name'].split('$'))
        for obj in objs:
            msg = BMsg(tuple(obj['name'].split('$')))
            spec = obj['internalSpec']
            for oname, members in (spec.get('__oneofs__') or {}).items():
                msg.oneofs[oname] = list(members)
            member_of = {m: o for o, ms in msg.oneofs.items() for m in ms}
            for fname, fspec in spec.items():
                if fname.startswith('__'):
                    continue
                field = BField(fname, fspec[0])
                flags, ftype = fspec[1] & ~TYPE_MASK, fspec[1] & TYPE_MASK
                field.packed = bool(flags & FLAG_PACKED)
                field.oneof = member_of.get(fname)
                if flags & FLAG_REQUIRED:
                    field.label = 'required'
                elif flags & FLAG_REPEATED:
                    field.label = 'repeated'
                if field.oneof:
                    field.label = ''
                if ftype == T_MAP:
                    field.kind, field.label = 'map', ''
                    ktype, vtype = fspec[2]
                    field.map = (TYPE_NAMES[ktype],
                                 ('scalar', TYPE_NAMES[vtype]) if isinstance(vtype, int) else ('ref', self.target_of(vtype)))
                elif ftype in (T_ENUM, T_MESSAGE):
                    field.kind = 'ref'
                    field.target = self.target_of(fspec[2])
                else:
                    field.kind, field.scalar = 'scalar', TYPE_NAMES[ftype]
                msg.fields.append(field)
            self.msgs[msg.path] = msg

    @staticmethod
    def enum_path(key, flat):
        """Caminho do enum. Os modulos que nao sao WAWeb exportam ARMADILLO_CONTENT_X_TYPE."""
        if '$' in key or not re.fullmatch(r'[A-Z0-9_]+', key):
            return tuple(key.split('$'))
        tokens = key.split('_')
        for cut in range(len(tokens) - 1, 0, -1):
            parent = flat.get(''.join(tokens[:cut]).lower())
            if parent:
                return parent + (camel(tokens[cut:]),)
        return (camel(tokens),)

    def as_enum(self, val):
        """Alguns modulos declaram o enum como objeto simples, sem $InternalEnum."""
        if isinstance(val, JSObj) and val and 'internalSpec' not in val and 'name' not in val \
                and all(isinstance(v, int) for v in val.values()):
            if id(val) not in self.plain_enums:
                values = dict(val)
                if 0 not in values.values():
                    # Nestes modulos o valor 0 aparece como -1.
                    values = {k: 0 if v == -1 else v for k, v in values.items()}
                self.plain_enums[id(val)] = EnumObj(values)
            return self.plain_enums[id(val)]
        return val

    def target_of(self, ref):
        """Devolve (modulo, nome exportado) ou (modulo, caminho) do tipo referenciado."""
        if isinstance(ref, ExtRef):
            attr = ref.attr[:-4] if ref.attr.endswith('Spec') else ref.attr
            return ('attr', ref.mod[:-3] if ref.mod.endswith('.pb') else ref.mod, attr)
        ref = self.as_enum(ref)
        if isinstance(ref, EnumObj):
            if ref.path is None:
                raise ValueError('%s: enum referenciado sem nome exportado' % self.name)
            return ('path', self.name, ref.path)
        if isinstance(ref, JSObj) and 'name' in ref:
            return ('path', self.name, tuple(ref['name'].split('$')))
        raise ValueError('%s: referencia de tipo desconhecida %r' % (self.name, ref))


# ----------------------------------------------------------------------------
# Leitura e escrita dos .proto
# ----------------------------------------------------------------------------

BLOCK_RE = re.compile(r'^(message|enum|oneof) (\w+) \{$')
FIELD_RE = re.compile(r'^(?:(optional|repeated|required) )?(map<\w+, [\w.]+>|[\w.]+) (\w+) = (\d+)(?: \[(.*)\])?;$')
VALUE_RE = re.compile(r'^(\w+) = (-?\d+);$')


class Raw:
    def __init__(self, text):
        self.text = text


class PField:
    def __init__(self, label, type_, name, num, opts=None):
        self.label, self.type, self.name, self.num, self.opts = label or '', type_, name, num, opts

    def render(self):
        return '%s%s %s = %d%s;' % (self.label + ' ' if self.label else '', self.type, self.name, self.num,
                                    ' [%s]' % self.opts if self.opts else '')


class PValue:
    def __init__(self, name, num):
        self.name, self.num = name, num

    def render(self):
        return '%s = %d;' % (self.name, self.num)


class PBlock:
    def __init__(self, kind, name):
        self.kind, self.name, self.items = kind, name, []
        self.skipped = set()
        self.dirty = False

    def blocks(self, kind):
        return [i for i in self.items if isinstance(i, PBlock) and i.kind == kind]

    def fields(self):
        return [i for i in self.items if isinstance(i, PField)]


def is_blank(item):
    return isinstance(item, Raw) and not item.text.strip()


def tidy(items):
    """Uma linha em branco em volta de cada bloco, nenhuma entre campos."""
    out = []
    for item in items:
        if is_blank(item):
            continue
        if out and (isinstance(item, PBlock) or isinstance(out[-1], PBlock)):
            out.append(Raw(''))
        out.append(item)
    return out


class PFile:
    def __init__(self, path):
        self.path = path
        self.rel = None
        self.base = None
        self.items = []
        self.package = None
        self.changed = False
        self.proto3 = False
        with open(path, encoding='utf-8') as fh:
            self.original = fh.read()
        stack = [self]
        in_comment = False
        for lineno, line in enumerate(self.original.split('\n')[:-1], 1):
            text = line.strip()
            top = stack[-1]
            if in_comment or text.startswith('/*'):
                in_comment = '*/' not in text
                top.items.append(Raw(line))
                continue
            m = BLOCK_RE.match(text)
            if m:
                block = PBlock(m.group(1), m.group(2))
                top.items.append(block)
                stack.append(block)
                continue
            if text == '}':
                stack.pop()
                continue
            if len(stack) > 1 and top.kind == 'enum':
                m = VALUE_RE.match(text)
                if m:
                    top.items.append(PValue(m.group(1), int(m.group(2))))
                    continue
            elif len(stack) > 1:
                m = FIELD_RE.match(text)
                if m:
                    top.items.append(PField(m.group(1), m.group(2), m.group(3), int(m.group(4)), m.group(5)))
                    continue
            if text and not text.startswith('//') and len(stack) > 1:
                raise SyntaxError('%s:%d: linha nao reconhecida: %s' % (path, lineno, text))
            if text.startswith('//'):
                m = FIELD_RE.match(text[2:].strip())
                if m and len(stack) > 1:
                    top.skipped.add(int(m.group(4)))
            if len(stack) == 1:
                m = re.match(r'^package ([\w.]+);$', text)
                if m:
                    self.package = m.group(1)
                if text == 'syntax = "proto3";':
                    self.proto3 = True
            top.items.append(Raw(line))
        if self.render() != self.original:
            raise SyntaxError('%s: a releitura nao reproduz o arquivo' % path)
        self.reindex()

    def reindex(self):
        self.index = {}

        def walk(block, path):
            for item in block.items:
                if isinstance(item, PBlock) and item.kind != 'oneof':
                    sub = path + (item.name,)
                    self.index[sub] = item
                    walk(item, sub)
        walk(self, ())
        self.lower = {lk(p): p for p in self.index}

    def render(self):
        out = []

        def walk(items, depth):
            for item in items:
                if isinstance(item, Raw):
                    out.append(item.text)
                elif isinstance(item, PBlock):
                    out.append('\t' * depth + '%s %s {' % (item.kind, item.name))
                    walk(item.items, depth + 1)
                    out.append('\t' * depth + '}')
                else:
                    out.append('\t' * depth + item.render())
        walk(self.items, 0)
        return '\n'.join(out) + '\n'

    def imports(self):
        return [re.match(r'^import "(.+)";$', i.text).group(1) for i in self.items
                if isinstance(i, Raw) and i.text.startswith('import ')]

    def add_import(self, rel):
        if rel in self.imports():
            return False
        line = Raw('import "%s";' % rel)
        idxs = [n for n, i in enumerate(self.items) if isinstance(i, Raw) and i.text.startswith('import ')]
        if idxs:
            self.items.insert(idxs[-1] + 1, line)
        else:
            opt = [n for n, i in enumerate(self.items) if isinstance(i, Raw) and i.text.startswith('option ')][-1]
            self.items[opt + 1:opt + 1] = [Raw(''), line]
        self.changed = True
        return True


def lk(path):
    return tuple(p.lower() for p in path)


# ----------------------------------------------------------------------------
# Mescla
# ----------------------------------------------------------------------------

# Modulos extras que alimentam um .proto, alem do modulo de mesmo nome e do par
# WAWebProtobufs<X> de um WA<X>. O primeiro modulo que descreve um tipo manda nele;
# os seguintes so acrescentam o que falta.
EXTRA_SOURCES = {'WACommon': ['WAWebProtobufsProtocol', 'WAProtocol']}
# .proto mantidos a mao, com tipos que o bundle nao descreve: recebem acrescimos, nunca remocoes.
KEEP_EXTRAS = {'WAWebProtobufsReporting'}

# Siglas que o fork escreve em maiusculas nos nomes de campo.
ACRONYMS = ['ID', 'JID', 'LID', 'URL', 'JSON', 'MS', 'SHA256', 'JPEG', 'CDN', 'TS', 'MAC', 'IV', 'HMAC', 'FBID', 'PTT', 'DSM']
NAME_FIXES = []


def build_name_fixes():
    del NAME_FIXES[:]
    for acr in sorted(ACRONYMS, key=len, reverse=True):
        word = acr[0] + acr[1:].lower()
        NAME_FIXES.append((re.compile(word + r'(?=[A-Z0-9_]|s?$|s[A-Z])'), acr))
        NAME_FIXES.append((re.compile('^' + acr.lower() + r'(?=s?$)'), acr))


build_name_fixes()


def fix_name(name):
    for rx, rep in NAME_FIXES:
        name = rx.sub(rep, name)
    return name


class Merger:
    def __init__(self, bundle_dir, proto_dir, prune):
        self.bundle_dir, self.proto_dir, self.prune = bundle_dir, proto_dir, prune
        self.files = {}       # nome base -> PFile
        self.by_pkg = {}      # pacote -> PFile
        self.modules = {}     # nome do modulo -> BModule
        self.sources = {}     # nome base -> [BModule]
        self.home = {}        # nome do modulo -> PFile
        self.maps = {}        # nome do modulo -> {(tipo, caminho no bundle): caminho no .proto}
        self.owner = {}       # (PFile, caminho no .proto) -> modulo que manda no tipo
        self.seen = {}        # (PFile, caminho no .proto) -> numeros vistos no bundle
        self.report = []
        self.name_pairs = []
        self.unsourced = []
        for sub in sorted(os.listdir(proto_dir)):
            folder = os.path.join(proto_dir, sub)
            if not os.path.isdir(folder):
                continue
            for fname in sorted(os.listdir(folder)):
                if fname.endswith('.proto'):
                    pf = PFile(os.path.join(folder, fname))
                    pf.rel = '%s/%s' % (sub, fname)
                    pf.base = fname[:-6]
                    self.files[pf.base] = pf
                    self.by_pkg[pf.package] = pf
        for base, pf in self.files.items():
            cands = []
            if base.startswith('WA') and not base.startswith('WAWeb'):
                cands.append('WAWebProtobufs' + base[2:])
            cands += EXTRA_SOURCES.get(base, []) + [base]
            mods = [self.module(c) for c in cands if self.module(c)]
            if mods:
                self.sources[base] = mods
                for mod in mods:
                    self.home[mod.name] = pf
            else:
                self.unsourced.append(base)

    def module(self, name):
        if name not in self.modules:
            path = os.path.join(self.bundle_dir, name + '.pb.js')
            self.modules[name] = BModule(name, path) if os.path.isfile(path) else None
        return self.modules[name]

    def note(self, pf, text):
        self.report.append((pf.rel, text))

    # -- casamento entre os tipos do bundle e os do .proto -------------------

    def build_map(self, pf, mod):
        items = [('message', p) for p in mod.msgs] + [('enum', p) for p in mod.enums]
        items.sort(key=lambda kp: len(kp[1]))
        mp, claimed = {}, set()
        for kind, path in items:
            hit = pf.lower.get(lk(path))
            if hit and pf.index[hit].kind == kind:
                mp[(kind, path)] = hit
                claimed.add(hit)
        for kind, path in items:
            if (kind, path) in mp:
                continue
            cands = []
            parent = mp.get(('message', path[:-1]))
            if parent is not None:
                cands.append(parent + path[-1:])
            cands += [path[cut:] for cut in range(1, len(path))]
            hits = [pf.lower.get(lk(cand)) for cand in cands]
            # Ultimo recurso: mesmo nome com outra divisao (CTA.ButtonType x CtaButtonType).
            hits += [p for p in pf.index if ''.join(p).lower() == ''.join(path).lower()]
            for hit in hits:
                if hit and pf.index[hit].kind == kind and hit not in claimed:
                    mp[(kind, path)] = hit
                    claimed.add(hit)
                    break
        self.maps[mod.name] = mp
        return mp

    def add_blocks(self, pf, mod):
        mp = self.maps[mod.name]
        items = [('message', p) for p in mod.msgs] + [('enum', p) for p in mod.enums]
        items.sort(key=lambda kp: len(kp[1]))
        for kind, path in items:
            if (kind, path) in mp:
                continue
            # Os irmaos dizem onde o fork guarda os filhos deste pai (aninhado ou no nivel de cima).
            homes = {}
            for (okind, opath), opp in mp.items():
                if len(opath) == len(path) and opath[:-1] == path[:-1]:
                    homes[opp[:-1]] = homes.get(opp[:-1], 0) + 1
            if len(path) == 1:
                home = ()
            elif homes:
                home = max(homes, key=homes.get)
            else:
                home = mp[('message', path[:-1])]
            if home + path[-1:] in pf.index or lk(home + path[-1:]) in pf.lower:
                self.note(pf, '! %s %s: ja existe outro tipo com esse nome em %s' % (kind, '.'.join(path), '.'.join(home) or 'nivel de cima'))
                continue
            parent = pf if not home else pf.index[home]
            block = PBlock(kind, path[-1])
            block.dirty = True
            ordered = [p for p in (mod.msgs if kind == 'message' else mod.enums)
                       if len(p) == len(path) and p[:-1] == path[:-1]]
            prev = None
            for sib in ordered[:ordered.index(path)][::-1]:
                spath = mp.get((kind, sib))
                if spath and spath[:-1] == home:
                    prev = pf.index[spath]
                    break
            items_ = parent.items
            same = [n for n, i in enumerate(items_) if isinstance(i, PBlock) and i.kind == kind]
            enums_at = [n for n, i in enumerate(items_) if isinstance(i, PBlock) and i.kind == 'enum']
            if prev is not None:
                at = items_.index(prev) + 1
            elif same and kind == 'message':
                at = same[-1] + 1
            elif same:
                at = same[0]
            elif kind == 'message' and enums_at:
                at = enums_at[-1] + 1
            elif parent is pf:
                at = len(items_)
            else:
                at = 0
            if parent is pf:
                if at >= len(items_):
                    items_[at:at] = [Raw(''), block]
                else:
                    while at < len(items_) and is_blank(items_[at]):
                        at += 1
                    items_[at:at] = [block, Raw('')]
            else:
                items_.insert(at, block)
                parent.dirty = True
            pf.reindex()
            mp[(kind, path)] = home + path[-1:]
            self.note(pf, '+ %s %s' % (kind, '.'.join(home + path[-1:])))

    # -- resolucao de nomes --------------------------------------------------

    def resolve(self, pf, scope, type_str):
        """Tipo escrito no .proto -> (PFile, caminho) ou None."""
        parts = tuple(type_str.split('.'))
        for depth in range(len(scope), -1, -1):
            if scope[:depth] + parts[:1] in pf.index:
                full = scope[:depth] + parts
                return (pf, full) if full in pf.index else None
        if parts[0] in self.by_pkg and len(parts) > 1:
            other = self.by_pkg[parts[0]]
            return (other, parts[1:]) if parts[1:] in other.index else None
        return None

    def locate(self, btarget):
        """Tipo do bundle -> (PFile, caminho no .proto)."""
        how, mod_name, what = btarget
        mod = self.module(mod_name)
        other = self.home.get(mod_name)
        if mod is None or other is None:
            raise LookupError('o modulo %s nao tem .proto' % mod_name)
        path = mod.exports.get(what) if how == 'attr' else what
        if path is None:
            raise LookupError('%s nao exporta %s' % (mod_name, what))
        mp = self.maps[mod_name]
        hit = mp.get(('message', path)) or mp.get(('enum', path))
        if hit is None:
            raise LookupError('tipo %s.%s nao existe nos .proto' % (mod_name, '.'.join(path)))
        return (other, hit)

    def type_string(self, pf, scope, btarget):
        other, actual = self.locate(btarget)
        if other is not pf:
            if pf.add_import(other.rel):
                self.note(pf, '+ import "%s"' % other.rel)
            return other.package + '.' + '.'.join(actual)
        for start in range(len(actual) - 1, -1, -1):
            cand = '.'.join(actual[start:])
            if self.resolve(pf, scope, cand) == (pf, actual):
                return cand
        raise LookupError('nao ha como referenciar %s a partir de %s' % ('.'.join(actual), '.'.join(scope)))

    def field_type(self, pf, scope, bf):
        if bf.kind == 'scalar':
            return bf.scalar
        if bf.kind == 'ref':
            return self.type_string(pf, scope, bf.target)
        vkind, vval = bf.map[1]
        return 'map<%s, %s>' % (bf.map[0], vval if vkind == 'scalar' else self.type_string(pf, scope, vval))

    def same_type(self, pf, scope, pfield, bf):
        if bf.kind == 'scalar':
            return pfield.type == bf.scalar
        if bf.kind == 'map':
            m = re.match(r'^map<(\w+), ([\w.]+)>$', pfield.type)
            if not m or m.group(1) != bf.map[0]:
                return False
            vkind, vval = bf.map[1]
            if vkind == 'scalar':
                return m.group(2) == vval
            return self.resolve(pf, scope, m.group(2)) == self.locate(vval)
        if pfield.type in SCALARS or pfield.type.startswith('map<'):
            return False
        return self.resolve(pf, scope, pfield.type) == self.locate(bf.target)

    # -- passos --------------------------------------------------------------

    def run(self):
        for base, mods in self.sources.items():
            for mod in mods:
                self.build_map(self.files[base], mod)
                self.add_blocks(self.files[base], mod)
        for base, mods in self.sources.items():
            pf = self.files[base]
            for mod in mods:
                mp = self.maps[mod.name]
                for path, enum in mod.enums.items():
                    if ('enum', path) in mp:
                        self.merge_enum(pf, mod, mp[('enum', path)], enum)
                for path, msg in mod.msgs.items():
                    if ('message', path) in mp:
                        self.merge_msg(pf, mod, mp[('message', path)], msg)
        for base in self.sources:
            self.drop_gone(self.files[base])
        for pf in self.files.values():
            for block in pf.index.values():
                if block.dirty:
                    block.items = tidy(block.items)
                    for one in block.blocks('oneof'):
                        one.items = tidy(one.items)
            if pf.render() != pf.original:
                pf.changed = True

    def claim(self, pf, mod, path):
        """True se este modulo manda no tipo; os outros so acrescentam."""
        return self.owner.setdefault((pf, path), mod.name) == mod.name

    def merge_enum(self, pf, mod, path, enum):
        block = pf.index[path]
        name = '.'.join(path)
        full = self.claim(pf, mod, path)
        seen = self.seen.setdefault((pf, path), set())
        seen.update(enum.values.values())
        have = {v.num: v for v in block.items if isinstance(v, PValue)}
        ordered = list(enum.values.items())
        for idx, (vname, vnum) in enumerate(ordered):
            cur = have.get(vnum)
            if cur is None:
                prev = next((have[n] for _, n in ordered[:idx][::-1] if n in have), None)
                val = PValue(vname, vnum)
                block.items.insert(block.items.index(prev) + 1 if prev else 0, val)
                have[vnum] = val
                block.dirty = True
                self.note(pf, '+ valor %s.%s = %d' % (name, vname, vnum))
            elif cur.name != vname and full and vname not in cur.name:
                self.note(pf, '~ valor %s.%s = %d passa a %s' % (name, cur.name, vnum, vname))
                cur.name = vname
                block.dirty = True

    def merge_msg(self, pf, mod, scope, msg):
        block = pf.index[scope]
        name = '.'.join(scope)
        full = self.claim(pf, mod, scope)
        self.seen.setdefault((pf, scope), set()).update(f.num for f in msg.fields)
        where = {}
        for item in block.items:
            if isinstance(item, PField):
                where[item.num] = (item, block)
            elif isinstance(item, PBlock) and item.kind == 'oneof':
                for sub in item.fields():
                    where[sub.num] = (sub, item)
        oneofs = {o.name.lower(): o for o in block.blocks('oneof')}
        for idx, bf in enumerate(msg.fields):
            if bf.num in block.skipped:
                continue
            try:
                found = where.get(bf.num)
                if found is None:
                    self.add_field(pf, scope, block, oneofs, where, msg, idx)
                    continue
                if not full:
                    continue
                cur, holder = found
                if cur.name != bf.name:
                    self.name_pairs.append((bf.name, cur.name))
                if cur.name.lower() != bf.name.lower():
                    self.note(pf, '~ nome %s.%s = %d passa a %s' % (name, cur.name, bf.num, fix_name(bf.name)))
                    cur.name = fix_name(bf.name)
                    block.dirty = True
                if not self.same_type(pf, scope, cur, bf):
                    new_type = self.field_type(pf, scope, bf)
                    self.note(pf, '~ tipo %s.%s = %d: %s -> %s' % (name, cur.name, bf.num, cur.type, new_type))
                    cur.type = new_type
                    block.dirty = True
                want_holder = oneofs.get(bf.oneof.lower()) if bf.oneof else block
                if holder is not want_holder:
                    self.note(pf, '~ oneof %s.%s = %d: %s -> %s' % (name, cur.name, bf.num,
                                                                 holder.name if holder is not block else '-', bf.oneof or '-'))
                    holder.items.remove(cur)
                    del where[bf.num]
                    self.add_field(pf, scope, block, oneofs, where, msg, idx, keep=cur, quiet=True)
                    continue
                if cur.label != self.label(pf, bf):
                    self.note(pf, '~ rotulo %s.%s = %d: %s -> %s' % (name, cur.name, bf.num, cur.label or '-', self.label(pf, bf) or '-'))
                    cur.label = self.label(pf, bf)
                    block.dirty = True
                opts = 'packed=true' if bf.packed else None
                if cur.opts != opts:
                    self.note(pf, '~ opcoes %s.%s = %d: %s -> %s' % (name, cur.name, bf.num, cur.opts, opts))
                    cur.opts = opts
                    block.dirty = True
            except LookupError as err:
                self.note(pf, '! %s.%s = %d: %s' % (name, bf.name, bf.num, err))

    @staticmethod
    def label(pf, bf):
        return '' if pf.proto3 and bf.label != 'repeated' else bf.label

    def add_field(self, pf, scope, block, oneofs, where, msg, idx, keep=None, quiet=False):
        bf = msg.fields[idx]
        field = PField(self.label(pf, bf), self.field_type(pf, scope, bf), keep.name if keep else fix_name(bf.name), bf.num,
                       'packed=true' if bf.packed else None)
        if bf.oneof:
            holder = oneofs.get(bf.oneof.lower())
            if holder is None:
                holder = PBlock('oneof', bf.oneof)
                oneofs[bf.oneof.lower()] = holder
                firsts = [n for n, i in enumerate(block.items) if isinstance(i, PField)]
                block.items.insert(firsts[0] if firsts else len(block.items), holder)
        else:
            holder = block
        prev = None
        for other in msg.fields[:idx][::-1]:
            found = where.get(other.num)
            if found and found[1] is holder:
                prev = found[0]
                break
        if prev is not None:
            at = holder.items.index(prev) + 1
        else:
            firsts = [n for n, i in enumerate(holder.items) if isinstance(i, PField)]
            at = firsts[0] if firsts else len(holder.items)
        holder.items.insert(at, field)
        where[bf.num] = (field, holder)
        block.dirty = True
        if not quiet:
            self.note(pf, '+ campo %s.%s = %d (%s)%s' % ('.'.join(scope), field.name, bf.num, field.type,
                                                        ' em oneof %s' % bf.oneof if bf.oneof else ''))

    def drop_gone(self, pf):
        """Relata (e remove, salvo --keep-removed) o que nenhum modulo do bundle descreve mais."""
        kept = '' if self.prune and pf.base not in KEEP_EXTRAS else '  (mantido)'
        prune = self.prune and pf.base not in KEEP_EXTRAS
        mapped = set()
        for mod in self.sources[pf.base]:
            mapped.update(self.maps[mod.name].values())
        for path in sorted(pf.index, key=len):
            if path not in pf.index:
                continue
            block = pf.index[path]
            name = '.'.join(path)
            if path not in mapped:
                self.note(pf, '- %s %s%s' % (block.kind, name, kept))
                if prune:
                    parent = pf if len(path) == 1 else pf.index[path[:-1]]
                    at = parent.items.index(block)
                    del parent.items[at]
                    if parent is pf:
                        if at < len(parent.items) and is_blank(parent.items[at]):
                            del parent.items[at]
                        elif at and is_blank(parent.items[at - 1]):
                            del parent.items[at - 1]
                    else:
                        parent.dirty = True
                    pf.reindex()
                continue
            seen = self.seen.get((pf, path), set())
            if block.kind == 'enum':
                for val in [v for v in block.items if isinstance(v, PValue) and v.num not in seen]:
                    self.note(pf, '- valor %s.%s = %d%s' % (name, val.name, val.num, kept))
                    if prune:
                        block.items.remove(val)
                        block.dirty = True
                continue
            for holder in [block] + block.blocks('oneof'):
                for cur in [f for f in holder.fields() if f.num not in seen]:
                    self.note(pf, '- campo %s.%s = %d%s' % (name, cur.name, cur.num, kept))
                    if prune:
                        holder.items.remove(cur)
                        block.dirty = True
                if holder is not block and not holder.fields():
                    block.items.remove(holder)
                    block.dirty = True


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('bundle', help='pasta modules do bundle (cellar)')
    ap.add_argument('proto', help='pasta proto do hypermeow')
    ap.add_argument('--write', action='store_true', help='grava os .proto alterados')
    ap.add_argument('--keep-removed', action='store_true', help='mantem o que o bundle removeu')
    ap.add_argument('--names', action='store_true', help='lista os campos que o fork renomeou (para rever as siglas)')
    args = ap.parse_args()
    merger = Merger(args.bundle, args.proto, prune=not args.keep_removed)
    merger.run()
    if args.names:
        for old, new in sorted(set(merger.name_pairs)):
            print('%s\t%s%s' % (old, new, '' if fix_name(old) == new else '\t<- a regra de siglas nao gera este nome'))
        return 0
    last = None
    for rel, text in merger.report:
        if rel != last:
            print('\n== %s' % rel)
            last = rel
        print('  ' + text)
    changed = [pf for pf in merger.files.values() if pf.changed]
    print('\nSem modulo no bundle (intocados): %s' % ', '.join(sorted(merger.unsourced)))
    print('Arquivos alterados: %d' % len(changed))
    for pf in changed:
        print('  ' + pf.rel)
        if args.write:
            with open(pf.path, 'w', encoding='utf-8') as fh:
                fh.write(pf.render())
    if any(text.startswith('!') for _, text in merger.report):
        print('\nHa itens marcados com "!" que pedem ajuste manual.')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
