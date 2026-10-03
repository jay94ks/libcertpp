"""Turns the compiled example harness into the per-type Markdown the wiki generator splices in.

The published example is therefore literally the code a compiler accepted and a linker resolved:
the snippet and the verified source are the same text, so they cannot drift apart.

Harness format, in wikiex/<module>/examples.cpp:

    // === CCertCollection ===
    // Optional prose, one or more comment lines, shown above the snippet.
    void exampleCCertCollection() {
        ...                                 <- this body becomes the snippet
    }
"""

import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__)).replace(os.sep, '/')
REPO = os.path.dirname(HERE)
HARNESS = REPO + '/examples/wiki'
MARKER = re.compile(r'^// === (\w+) ===\s*$')


def dedent(body):
    lines = body.split('\n')
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    indents = [len(l) - len(l.lstrip()) for l in lines if l.strip()]
    cut = min(indents) if indents else 0
    return '\n'.join(l[cut:] if l.strip() else '' for l in lines)


def split(path):
    """Returns [(name, prose, snippet)] for one harness translation unit."""
    src = io.open(path, encoding='utf-8').read().split('\n')
    out = []
    i = 0
    while i < len(src):
        m = MARKER.match(src[i])
        if not m:
            i += 1
            continue
        name = m.group(1)
        i += 1

        prose = []
        while i < len(src) and src[i].strip().startswith('//'):
            prose.append(src[i].strip()[2:].strip())
            i += 1

        # Collect the signature, then the body from its opening brace to the matching close.
        sig = []
        while i < len(src) and '{' not in src[i]:
            sig.append(src[i])
            i += 1
        if i >= len(src):
            break
        sig.append(src[i][:src[i].index('{')])
        given = paramsOf(' '.join(x.strip() for x in sig))
        depth = 0
        body = []
        started = False
        while i < len(src):
            line = src[i]
            opens, closes = line.count('{'), line.count('}')
            if not started:
                depth = opens - closes
                started = True
                after = line[line.index('{') + 1:]
                if after.strip():
                    body.append(after)
                i += 1
                if depth <= 0:
                    break
                continue
            depth += opens - closes
            if depth <= 0:
                before = line[:line.rindex('}')]
                if before.strip():
                    body.append(before)
                i += 1
                break
            body.append(line)
            i += 1

        snippet = dedent('\n'.join(body))
        if given:
            snippet = '// given: ' + given + '\n' + snippet
        out.append((name, ' '.join(prose).strip(), snippet))
    return out


def paramsOf(signature):
    """Returns an example function's parameter list, normalised, or '' when it takes none."""
    if '(' not in signature:
        return ''
    inner = signature[signature.index('(') + 1:]
    if ')' in inner:
        inner = inner[:inner.rindex(')')]
    inner = re.sub(r'\s+', ' ', inner).strip()
    return '' if inner in ('', 'void') else inner


def run(outDir):
    if not os.path.isdir(outDir):
        os.makedirs(outDir)

    total = 0
    for root, dirs, files in os.walk(HARNESS):
        if 'snippets' in root.replace(os.sep, '/').split('/'):
            continue
        for f in sorted(files):
            if not f.endswith('.cpp') or f == 'main.cpp':
                continue
            p = os.path.join(root, f).replace(os.sep, '/')
            for name, prose, snippet in split(p):
                if not snippet.strip():
                    print('   EMPTY  %s (%s)' % (name, p))
                    continue
                md = []
                if prose:
                    md.append(prose)
                    md.append('')
                md.append('```cpp')
                md.append(snippet)
                md.append('```')
                io.open(outDir + '/' + name + '.md', 'w',
                        encoding='utf-8', newline='\n').write('\n'.join(md) + '\n')
                total += 1
    print('%d examples extracted into %s' % (total, outDir))


if __name__ == '__main__':
    run(sys.argv[1] if len(sys.argv) > 1 else HARNESS + '/snippets')
