"""Generates one wiki page per public class/struct/enum from the headers.

The headers are the source of truth: every public declaration in this library carries a Javadoc
block, so the reference content is extracted rather than retyped. Each page records the commit it
was generated from, which is the whole mitigation for a wiki not being versioned with the code --
a stale page can be regenerated, and says which commit it came from so you can tell that it is
stale.

Examples are NOT generated. They are written by hand into examples/<Type>.md beside this script
and spliced in, because a generated example is a lie about having been checked.
"""

import io
import os
import re
import subprocess
import sys

# The repository root is this script's parent directory, so a clone anywhere works.
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__))).replace(os.sep, '/')
INCLUDE = REPO + '/include'


def commit():
    out = subprocess.run(['git', '-C', REPO, 'rev-parse', '--short', 'HEAD'],
                         capture_output=True, text=True)
    return out.stdout.strip() or 'unknown'


def version():
    s = io.open(REPO + '/CMakeLists.txt', encoding='utf-8').read()
    m = re.search(r'VERSION\s+(\d+\.\d+\.\d+)', s)
    return m.group(1) if m else '?'


def cleanDoc(block):
    """Turns a /** ... */ block into Markdown: strips the comment furniture, keeps @param/@return
    as a list, and preserves paragraph breaks."""
    if not block:
        return '', [], ''

    body = block
    body = re.sub(r'^\s*/\*\*+', '', body)
    body = re.sub(r'\*+/\s*$', '', body)

    lines = []
    for raw in body.split('\n'):
        line = re.sub(r'^\s*\*ic?\s?', '', raw)
        line = re.sub(r'^\s*\*\s?', '', line)
        lines.append(line.rstrip())

    text = '\n'.join(lines).strip('\n')

    # Split the prose from the @param/@return tail.
    params, ret = [], ''
    prose = []
    current = None
    for line in text.split('\n'):
        m = re.match(r'\s*@param\s+(\S+)\s*(.*)', line)
        if m:
            current = ['param', m.group(1), m.group(2)]
            params.append(current)
            continue
        m = re.match(r'\s*@(?:return|returns)\s*(.*)', line)
        if m:
            current = ['return', '', m.group(1)]
            ret = m.group(1)
            continue
        m = re.match(r'\s*@brief\s*(.*)', line)
        if m:
            current = None
            prose.append(m.group(1))
            continue
        if current:
            # continuation of a @param/@return
            if line.strip():
                current[2] += ' ' + line.strip()
                if current[0] == 'return':
                    ret = current[2]
            continue
        prose.append(line)

    proseText = '\n'.join(prose).strip()
    proseText = re.sub(r'\n{3,}', '\n\n', proseText)
    return proseText, [(p[1], p[2].strip()) for p in params if p[0] == 'param'], ret.strip()


DOC = r'(?:/\*\*(?:[^*]|\*(?!/))*\*/\s*)?'


def parseHeader(path):
    """Extracts the public entities from one header."""
    s = io.open(path, encoding='utf-8', errors='replace').read()
    entities = []

    # --- enums -------------------------------------------------------------------------------
    for m in re.finditer(DOC + r'enum\s+([A-Z]\w+)\s*\{(.*?)\};', s, re.S):
        dm = re.match(r'\s*(/\*\*(?:[^*]|\*(?!/))*\*/)', m.group(0))
        doc = dm.group(1) if dm else ''
        name = m.group(1)
        members = []
        for line in m.group(2).split('\n'):
            mm = re.match(r'\s*([A-Z][A-Z0-9_]*)\s*(?:=\s*([^,/]+?))?\s*,?\s*(?:/\*\*?<\s*(.*?)\s*\*/|//\s*-->\s*(.*)|//\s*(.*))?\s*$', line)
            if mm and mm.group(1):
                members.append((mm.group(1), (mm.group(2) or '').strip(),
                                (mm.group(3) or mm.group(4) or mm.group(5) or '').strip()))
        entities.append({'kind': 'enum', 'name': name, 'doc': doc, 'members': members,
                         'header': path, 'declAt': m.start(),
                         'nested': None, 'nestedAt': -1})

    # --- classes and structs -----------------------------------------------------------------
    for m in re.finditer(
        DOC + r'(?:template\s*<([^>]*)>\s*)?(class|struct)\s+(?:CERTPP_API\s+)?([A-Z]\w+)'
        r'\s*(?::\s*(?:public\s+)?([\w:<>]+))?\s*\{', s):
        whole = m.group(0)
        dm = re.match(r'\s*(/\*\*(?:[^*]|\*(?!/))*\*/)', whole)
        doc = dm.group(1) if dm else ''
        entities.append({
            'kind': m.group(2), 'name': m.group(3), 'doc': doc,
            'template': m.group(1), 'base': m.group(4),
            'header': path, 'bodyAt': m.end(), 'declAt': m.start(),
            'bodyEnd': bodyEndOf(s, m.end()), 'nested': None, 'nestedAt': -1,
        })

    # Pull the public members of each class/struct out of its body.
    for e in entities:
        if e['kind'] == 'enum':
            continue
        e['members'] = publicMembers(s, e['bodyAt'], e['kind'])

    # A type declared inside another type's body belongs on that type's page, not on one of its
    # own -- 14 hashers each carry a nested `Context`, and 14 pages called `Context` would be
    # 13 pages about the wrong hasher.
    outers = [e for e in entities if e['kind'] != 'enum']
    for e in entities:
        at = e['declAt']
        for o in outers:
            if o is e:
                continue
            if o['bodyAt'] <= at < o['bodyEnd']:
                if e['nested'] is None or o['bodyAt'] > e['nestedAt']:
                    e['nested'], e['nestedAt'] = o['name'], o['bodyAt']

    return entities


def bodyEndOf(s, at):
    """Returns the offset just past the closing brace of a body that starts at `at`."""
    depth = 1
    i = at
    while i < len(s) and depth > 0:
        if s[i] == '{':
            depth += 1
        elif s[i] == '}':
            depth -= 1
        i += 1
    return i


def publicMembers(s, at, kind):
    """Walks a class body, collecting declarations that are in a public section."""
    depth = 1
    i = at
    # struct members are public by default; class members are not.
    isPublic = (kind == 'struct')
    out = []
    buf = []

    while i < len(s) and depth > 0:
        ch = s[i]
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                break
        if depth == 1:
            buf.append(ch)
        elif depth > 1:
            buf.append(ch)
        i += 1

    body = ''.join(buf)

    # Split into access sections.
    parts = re.split(r'\n\s*(public|private|protected)\s*:', body)
    sections = []
    if len(parts) == 1:
        sections.append((isPublic, parts[0]))
    else:
        sections.append((isPublic, parts[0]))
        for k in range(1, len(parts) - 1, 2):
            sections.append((parts[k] == 'public', parts[k + 1]))

    for pub, text in sections:
        if not pub:
            continue
        # Nested braces are skipped so an inline body's contents are not mistaken for members.
        text = stripNestedBodies(text)
        out.extend(memberDecls(text))

    return out


JAVADOC = re.compile(r'/\*\*(?:[^*]|\*(?!/))*\*/')
BLOCKCOMMENT = re.compile(r'/\*(?:[^*]|\*(?!/))*\*/')


def memberDecls(text):
    """Splits a brace-stripped class body into (declaration, docBlock) pairs.

    A member ends at `;` *or* at the `{}` that `stripNestedBodies` left standing for an inline
    body -- this library defines a great deal inline (`TSpan`, `CTag`, `Fe25519`), and a splitter
    that only recognises `;` silently drops every one of those methods. Javadoc is consumed as a
    token rather than split on, because a `;` inside a comment is not a declaration boundary.
    """
    out = []
    pending = ''
    buf = []
    i, n = 0, len(text)

    while i < n:
        if text.startswith('/**', i):
            m = JAVADOC.match(text, i)
            if m:
                # A doc block interrupting a half-collected declaration means what came before
                # was furniture (a label, a macro), not a declaration.
                buf = []
                pending = m.group(0)
                i = m.end()
                continue
        if text.startswith('/*', i):
            m = BLOCKCOMMENT.match(text, i)
            if m:
                i = m.end()
                continue
        if text.startswith('//', i):
            j = text.find('\n', i)
            i = n if j < 0 else j
            continue

        ch = text[i]
        if ch == ';' or ch == '{':
            decl = ''.join(buf)
            if ch == '{':
                i += 1
                if i < n and text[i] == '}':
                    i += 1
            else:
                i += 1
            decl = cleanDecl(decl)
            if decl:
                # `size_t size;    // --> Number of elements.` -- this library documents short
                # members with a trailing `// -->` instead of a Javadoc block, so a reader that
                # only looks for `/** */` loses the description entirely.
                doc = pending
                if not doc:
                    eol = text.find('\n', i)
                    rest = text[i:eol if eol >= 0 else len(text)]
                    tm = re.match(r'\s*//\s*-->\s*(.+?)\s*$', rest)
                    if tm:
                        doc = '/** ' + tm.group(1) + ' */'
                out.append((decl, doc))
            pending = ''
            buf = []
            continue

        buf.append(ch)
        i += 1

    return out


def cleanDecl(decl):
    """Normalises one declaration's whitespace and drops a constructor initialiser list."""
    decl = re.sub(r'\s+', ' ', decl).strip()
    if not decl:
        return ''
    # `Ctor(args) noexcept : a(a), b(b)` -> `Ctor(args) noexcept`. The cut has to start from the
    # leftmost `)`, not the rightmost: the rightmost one is inside the initialiser list itself.
    m = re.search(r'\)((?:\s+(?:const|noexcept|override|final))*)\s*:\s', decl)
    if m:
        decl = (decl[:m.start()] + ')' + m.group(1)).strip()
    return decl


def stripNestedBodies(text):
    """Replaces the contents of every nested { ... } with a placeholder, so inline method bodies
    do not leak their statements into the member list."""
    out = []
    depth = 0
    for ch in text:
        if ch == '{':
            depth += 1
            if depth == 1:
                out.append('{')
            continue
        if ch == '}':
            if depth == 1:
                out.append('}')
            depth -= 1
            continue
        if depth == 0:
            out.append(ch)
    return ''.join(out)


# ---------------------------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------------------------

def includePath(header):
    return header[header.index('include/') + len('include/'):]


def namespaceOf(header):
    rel = includePath(header)
    parts = rel.split('/')
    if len(parts) >= 3 and parts[0] == 'certpp':
        mod = parts[1]
        if mod in ('asn1', 'crypto', 'x509', 'dnssec'):
            return 'certpp::' + mod
    return 'certpp'


def isConstant(decl):
    return decl.startswith('static constexpr') or decl.startswith('static const ')


def isMethod(decl):
    return '(' in decl


def renderEnum(e, stamp):
    prose, _, _ = cleanDoc(e['doc'])
    out = ['# ' + e['name'], '']
    out.append('`#include <%s>` --- `%s`' % (includePath(e['header']), namespaceOf(e['header'])))
    out.append('')
    if prose:
        out.append(prose)
        out.append('')
    out.append('## Enumerators')
    out.append('')
    out.append('| Enumerator | Value | Meaning |')
    out.append('| --- | --- | --- |')
    for name, value, desc in e['members']:
        out.append('| `%s` | %s | %s |' % (name, ('`%s`' % value) if value else '', desc or ''))
    out.append('')
    return out


def renderType(e, stamp):
    prose, _, _ = cleanDoc(e['doc'])
    title = e['name']
    if e.get('template'):
        title += '<...>'

    out = ['# ' + title, '']
    hdr = '`#include <%s>` --- `%s`' % (includePath(e['header']), namespaceOf(e['header']))
    if e.get('base'):
        hdr += ' --- implements `%s`' % e['base']
    out.append(hdr)
    out.append('')
    if e.get('template'):
        out.append('Template: `template <%s>`' % e['template'])
        out.append('')
    if prose:
        out.append(prose)
        out.append('')

    constants = [(d, b) for d, b in e['members'] if isConstant(d)]
    methods = [(d, b) for d, b in e['members'] if isMethod(d) and not isConstant(d)]
    fields = [(d, b) for d, b in e['members']
              if not isMethod(d) and not isConstant(d)
              and not d.startswith(('using ', 'friend ', 'typedef ', 'enum '))]

    if constants:
        out.append('## Constants')
        out.append('')
        for d, b in constants:
            p, _, _ = cleanDoc(b)
            out.append('- `%s`%s' % (d, (' --- ' + p.replace('\n', ' ')) if p else ''))
        out.append('')

    if fields:
        out.append('## Fields')
        out.append('')
        for d, b in fields:
            p, _, _ = cleanDoc(b)
            out.append('- `%s`%s' % (d, (' --- ' + p.replace('\n', ' ')) if p else ''))
        out.append('')

    if methods:
        out.append('## Methods')
        out.append('')
        for d, b in methods:
            p, params, ret = cleanDoc(b)
            out.append('### `%s`' % d)
            out.append('')
            if p:
                out.append(p)
                out.append('')
            if params:
                for pn, pd in params:
                    out.append('- **`%s`** --- %s' % (pn, pd))
                out.append('')
            if ret:
                out.append('**Returns:** ' + ret)
                out.append('')
    return out


def stampLines(stamp, header):
    return [
        '---',
        '',
        '*Reference generated from [`%s`](https://github.com/jay94ks/libcertpp/blob/main/%s) '
        'at commit `%s` (v%s). The header is authoritative --- if this page disagrees with it, '
        'the header is right and this page needs regenerating.*'
        % (includePath(header), header[header.index('include/'):], stamp[0], stamp[1]),
    ]


# ---------------------------------------------------------------------------------------------
# Collection and emission
# ---------------------------------------------------------------------------------------------

MODULES = [
    ('Core', 'certpp/'),
    ('io', 'certpp/io/'),
    ('utils', 'certpp/utils/'),
    ('asn1', 'certpp/asn1/'),
    ('crypto', 'certpp/crypto/'),
    ('x509', 'certpp/x509/'),
    ('dnssec', 'certpp/dnssec/'),
]


MODULE_TITLES = {
    'Core': '`certpp` --- the top-level headers',
    'io': '`certpp/io/` --- namespace `certpp`',
    'utils': '`certpp/utils/` --- namespace `certpp`',
    'asn1': '`certpp::asn1`',
    'crypto': '`certpp::crypto`',
    'x509': '`certpp::x509`',
    'dnssec': '`certpp::dnssec`',
}


def moduleOf(header):
    rel = includePath(header)
    best = None
    for name, prefix in MODULES:
        if rel.startswith(prefix):
            if best is None or len(prefix) > len(best[1]):
                best = (name, prefix)
    return best[0] if best else 'Core'


def collect():
    """Parses every public header and returns the entities, module-grouped."""
    out = []
    for root, dirs, files in os.walk(INCLUDE + '/certpp'):
        for f in sorted(files):
            if not f.endswith('.hpp'):
                continue
            p = os.path.join(root, f).replace(os.sep, '/')
            out.extend(parseHeader(p))
    out.sort(key=lambda e: (moduleOf(e['header']), e['name']))
    return out


def exampleFor(name):
    p = REPO + '/examples/wiki/snippets/' + name + '.md'
    if os.path.exists(p):
        return io.open(p, encoding='utf-8').read().strip()
    return None


def emit(outDir):
    stamp = (commit(), version())
    ents = collect()

    nestedBy = {}
    for e in ents:
        if e['nested']:
            nestedBy.setdefault(e['nested'], []).append(e)

    seen = {}
    for e in ents:
        if e['nested']:
            continue
        seen.setdefault(e['name'], []).append(e)

    written, missing, dup = [], [], []
    for name, group in sorted(seen.items()):
        if len(group) > 1:
            dup.append((name, [includePath(g['header']) for g in group]))
        e = group[0]

        lines = renderEnum(e, stamp) if e['kind'] == 'enum' else renderType(e, stamp)

        inner = [n for n in nestedBy.get(name, []) if n['header'] == e['header']]
        if inner:
            lines.append('## Nested types')
            lines.append('')
            for n in inner:
                prose, _, _ = cleanDoc(n['doc'])
                lines.append('- `%s %s::%s`%s'
                             % (n['kind'], name, n['name'],
                                (' --- ' + prose.replace(chr(10), ' ')) if prose else ''))
            lines.append('')

        ex = exampleFor(name)
        lines.append('## Example')
        lines.append('')
        if ex:
            lines.append(ex)
        else:
            missing.append(name)
            lines.append('_No example yet._')
        lines.append('')
        lines.extend(stampLines(stamp, e['header']))

        path = outDir + '/' + name + '.md'
        io.open(path, 'w', encoding='utf-8', newline='\n').write('\n'.join(lines) + '\n')
        written.append((moduleOf(e['header']), e['kind'], name, includePath(e['header'])))

    # --- the index --------------------------------------------------------------------------
    idx = ['# API Reference', '']
    idx.append('One page per public class, struct and enum, generated from the headers at commit '
               '`%s` (v%s).' % stamp)
    idx.append('')
    idx.append('The headers carry the Javadoc these pages are built from, so a header and a page '
               'that disagree means the page is stale --- trust the header. Each page links to the '
               'one it came from.')
    idx.append('')
    for mod, _ in MODULES:
        rows = [w for w in written if w[0] == mod]
        if not rows:
            continue
        idx.append('## ' + MODULE_TITLES[mod])
        idx.append('')
        idx.append('| Name | Kind | Header |')
        idx.append('| --- | --- | --- |')
        for _, kind, name, hdr in sorted(rows, key=lambda r: (r[1], r[2])):
            idx.append('| [%s](%s) | %s | `%s` |' % (name, name, kind, hdr))
        idx.append('')
    io.open(outDir + '/API-Reference.md', 'w', encoding='utf-8', newline='\n').write(
        '\n'.join(idx) + '\n')

    return written, missing, dup


if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'emit'

    if mode == 'list':
        for e in collect():
            print('%-8s %-7s %-28s members=%3d  %s'
                  % (moduleOf(e['header']), e['kind'], e['name'],
                     len(e.get('members', [])), includePath(e['header'])))
        sys.exit(0)

    outDir = sys.argv[2] if len(sys.argv) > 2 else (REPO + '/build/wiki')
    written, missing, dup = emit(outDir)
    print('commit %s v%s -> %d pages in %s' % (commit(), version(), len(written), outDir))
    for mod, _ in MODULES:
        n = len([w for w in written if w[0] == mod])
        if n:
            print('   %-8s %3d' % (mod, n))
    if dup:
        print('\nname collisions (only the first was written):')
        for name, hdrs in dup:
            print('   %-28s %s' % (name, ', '.join(hdrs)))
    print('\n%d pages without an example' % len(missing))
