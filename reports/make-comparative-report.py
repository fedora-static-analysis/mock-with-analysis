from difflib import SequenceMatcher, HtmlDiff
from pprint import pprint
import re
import sys

from reports import get_filename, ResultsDir, AnalysisIssue, AnalysisFailure, \
    Model, \
    SourceHighlighter, write_common_css, \
    make_issue_note, make_failure_note, \
    get_internal_filename, \
    write_issue_table_for_file, write_failure_table_for_file, \
    html_escape

class Comparison:
    """
    Comparison of a pair of lists of item : what's new, what's
    fixed, etc
    """
    def __init__(self, itemsA, itemsB):
        self.itemsA = itemsA
        self.itemsB = itemsB

        itemsA = self.gather_items_by_key(itemsA)
        itemsB = self.gather_items_by_key(itemsB)

        self.fixed = set() # of itemA
        self.inboth = set() # of (itemA, itemB) pairs
        self.new = set() # of itemB

        for key in set(itemsA.keys() + itemsB.keys()):
            if key in itemsA:
                if key in itemsB:
                    # Items found in both old and new:
                    for itemA in itemsA[key]:
                        for itemB in itemsB[key]:
                            self.inboth.add( (itemA, itemB) )
                else:
                    # Items found in old but not in new:
                    for itemA in itemsA[key]:
                        self.fixed.add(itemA)
            else:
                # Issue found in new but not in old:
                assert key in itemsB
                for itemB in itemsB[key]:
                    self.new.add(itemB)

    def gather_items_by_key(self, items):
        raise NotImplementedError

class ComparativeIssues(Comparison):
    """
    Comparison of a pair of lists of AnalysisIssue : what's new, what's
    fixed, etc
    """
    def gather_items_by_key(self, items):
        result = {}
        for ai in items:
            # Some cpychecker reports append the location to the message:
            # e.g. 'calling PyTuple_SetItem with NULL as argument 1 (args) at python-ethtool/ethtool.c:328'
            # Strip it off if necessary:
            text = ai.message.text
            m  = re.match('^(.+) at (.+):[0-9]+$', text)
            if m:
                text = m.group(1)

            key = (ai.generator.name, ai.testid, ai.internal_filename, ai.function, text)

            if key in result:
                result[key].add(ai)
            else:
                result[key] = set([ai])
        return result

class ComparativeFailures(Comparison):
    """
    Comparison of a pair of lists of AnalysisFailure : what's new, what's
    fixed, etc
    """
    def gather_items_by_key(self, items):
        result = {}
        for af in items:
            if af.failureid == 'python-exception':
                tb = af.customfields['traceback']
                # cpychecker tracebacks can be large and contain slightly
                # changing data, so compare on just the first and last 50
                # chars for now:
                detail = tb[50] + tb[-50]
            else:
                detail = None
            key = (af.generator.name, af.failureid, af.message, af.function, detail)

            if key in result:
                result[key].add(af)
            else:
                result[key] = set([af])
        return result


def write_html_diff(f, modelA, modelB, fileA, fileB, aisA, aisB, afsA, afsB, sh):
    if fileA is not None:
        srcA = modelA.get_file_content(fileA)
    else:
        srcA = ''
    if fileB is not None:
        srcB = modelB.get_file_content(fileB)
    else:
        srcB = ''
    # For now, just work line-by-line
    s = SequenceMatcher(None,
                        srcA.splitlines(), srcB.splitlines())
    htmlA = sh.highlight_file(fileA, modelA).splitlines()
    htmlB = sh.highlight_file(fileB, modelB).splitlines()

    f.write('<table>\n')
    for tag, i1, i2, j1, j2 in s.get_opcodes():
        def get_td(idx, html, ais, afs):
            if idx is not None:
                linenotes = ''
                for ai in ais:
                    if ai.line == idx + 1:
                        linenotes += make_issue_note(ai)
                for af in afs:
                    if af.line == idx + 1:
                        linenotes += make_failure_note(af)
                return '<td width="50%%"><pre>%s</pre>%s</td>' % (html[idx], linenotes)
            else:
                return '<td width="50%%"></td>'

        def add_line(class_, idxA, idxB):
            f.write('<tr class="%s">%s%s</tr>\n'
                    % (class_,
                       get_td(idxA, htmlA, aisA, afsA),
                       get_td(idxB, htmlB, aisB, afsB)))

        if tag == 'replace':
            # There's no guarantee that they have equal lengths,
            # so we can't directly use zip on the ranges.
            # Instead, calculate which has the longer range of lines
            # and keep interating, filling the other with blank lines
            maxlen = max(i2 - i1, j2 - j1)
            for i, j in zip(range(i1, i1 + maxlen),
                            range(j1, j1 + maxlen)):
                add_line('replace',
                         i if i < i2 else None,
                         j if j < j2 else None)
        elif tag == 'delete':
            for i in range(i1, i2):
                add_line('delete', i, None)
        elif tag == 'insert':
            for j in range(j1, j2):
                add_line('insert', None, j)
        elif tag == 'equal':
            for i, j in zip(range(i1, i2), range(j1, j2)):
                add_line('equal', i, j)
    f.write('</table>\n')

def make_html(modelA, modelB, f):
    sh = SourceHighlighter()

    # Approach: find peer files:
    sourcesA = modelA.get_source_files()
    sourcesB = modelB.get_source_files()

    #pprint(sourcesA)
    #pprint(sourcesB)
    # how to match?  givenpath may be good enough for our example
    sourcesA_by_internal_path = {}
    for fileA in sourcesA:
        sourcesA_by_internal_path[get_internal_filename(fileA)] = fileA
    sourcesB_by_internal_path = {}
    for fileB in sourcesB:
        sourcesB_by_internal_path[get_internal_filename(fileB)] = fileB
    internal_paths = set(sourcesA_by_internal_path.keys()
                         + sourcesB_by_internal_path.keys())

    sutA = list(modelA.iter_analyses())[0].metadata.sut
    sutB = list(modelB.iter_analyses())[0].metadata.sut

    title = '%s - comparison view' % sutA.name
    f.write('<html><head><title>%s</title>\n' % title)

    f.write('    <style type="text/css">\n')

    write_common_css(f)

    f.write(sh.formatter.get_style_defs())

    f.write('      </style>\n')

    f.write('</head>\n')

    f.write('  <body>\n')

    generatorsA = modelA.get_generators()
    generatorsB = modelB.get_generators()
    generators = sorted(set(generatorsA + generatorsB))

    aisA_by_source_and_generator = modelA.get_analysis_issues_by_source_and_generator()
    aisB_by_source_and_generator = modelB.get_analysis_issues_by_source_and_generator()

    afsA_by_source = modelA.get_analysis_failures_by_source()
    afsB_by_source = modelB.get_analysis_failures_by_source()

    f.write('<p>Old build: <b>%s</b></p>' % sutA)
    f.write('<p>New build: <b>%s</b></p>' % sutB)

    f.write('    <table>\n')
    if 1:
        f.write('    <tr>\n')
        f.write('      <th>Old file</th>\n')
        f.write('      <th>New file</th>\n')
        for generator in generators:
            f.write('      <th>%s</th>\n' % generator.name)
        f.write('      <th>Notes</th>\n')
        f.write('    </tr>\n')
    for internal_path in sorted(internal_paths):
        fileA = sourcesA_by_internal_path.get(internal_path, None)
        fileB = sourcesB_by_internal_path.get(internal_path, None)
        f.write('    <tr>\n')
        if fileA:
            f.write('      <td><a href="#file-%s">%s</a></td>\n'
                    % (fileA.hash_.hexdigest, get_filename(fileA)))
        else:
            f.write('      <td></td>\n')
        if fileB:
            f.write('      <td><a href="#file-%s">%s</a></td>\n'
                    % (fileB.hash_.hexdigest, get_filename(fileB)))
        else:
            f.write('      <td></td>\n')
        for generator in generators:
            keyA = (fileA, generator)
            aisA = aisA_by_source_and_generator.get(keyA, set())
            keyB = (fileB, generator)
            aisB = aisB_by_source_and_generator.get(keyB, set())
            class_ = 'has_issues' if aisA or aisB else 'no_issues'
            f.write('      <td class="%s">%s / %s</td>\n' % (class_, len(aisA), len(aisB)))
        afsA = afsA_by_source.get(fileA, [])
        afsB = afsB_by_source.get(fileB, [])
        if afsA or afsB:
            f.write('      <td>Incomplete coverage: old has %i analysis failure(s), new has %i analysis failure(s)</td>\n'
                    % (len(afsA), len(afsB)))
        else:
            f.write('      <td></td>\n')

        f.write('    </tr>\n')
    f.write('    </table>\n')

    for internal_path in sorted(internal_paths):
        fileA = sourcesA_by_internal_path.get(internal_path, None)
        fileB = sourcesB_by_internal_path.get(internal_path, None)

        aisA = modelA.get_analysis_issues_by_source().get(fileA, set())
        aisB = modelB.get_analysis_issues_by_source().get(fileB, set())

        afsA = afsA_by_source.get(fileA, [])
        afsB = afsB_by_source.get(fileB, [])

        if fileA is not None:
            f.write('<a id="file-%s"/>' % fileA.hash_.hexdigest)
            if fileB is not None:
                f.write('<a id="file-%s"/>' % fileB.hash_.hexdigest)
                f.write('<h1>Comparison of old/new %s</h1>\n' % get_internal_filename(fileA))
            else:
                f.write('<h1>Removed file: %s</h1>\n' % get_internal_filename(fileA))
        else:
            assert fileB is not None
            f.write('<a id="file-%s"/>' % fileB.hash_.hexdigest)
            f.write('<h1>Added file: %s</h1>\n' % get_internal_filename(fileB))

        ci = ComparativeIssues(aisA, aisB)
        if ci.new:
            f.write('<h2>New issues</h2>')
            write_issue_table_for_file(f, fileB, ci.new)

        if ci.fixed:
            f.write('<h2>Fixed issues</h2>')
            write_issue_table_for_file(f, fileA, ci.fixed)

        if ci.inboth:
            f.write('<h2>Issues in both old/new</h2>')
            f.write('    <table>\n')
            f.write('    <tr>\n')
            f.write('      <th>Old location</th>\n')
            f.write('      <th>New location</th>\n')
            f.write('      <th>Tool</th>\n')
            f.write('      <th>Test ID</th>\n')
            f.write('      <th>Function</th>\n')
            f.write('      <th>Issue</th>\n')
            f.write('    </tr>\n')
            for aiA, aiB in sorted(ci.inboth,
                                   lambda ab1, ab2: AnalysisIssue.cmp(ab1[1], ab2[1])):
                f.write('    <tr>\n')
                f.write('      <td>%s:%i:%i</td>\n'
                        % (aiA.givenpath,
                           aiA.line,
                           aiA.column))
                f.write('      <td>%s:%i:%i</td>\n'
                        % (aiB.givenpath,
                           aiB.line,
                           aiB.column))
                f.write('      <td>%s</td>\n' % aiB.generator.name)
                f.write('      <td>%s</td>\n' % (aiB.testid if aiB.testid else ''))
                f.write('      <td>%s</td>\n' % (aiB.function.name if aiB.function else '')),
                f.write('      <td><a href="%s">%s</a></td>\n'
                        % ('#file-%s-line-%i' % (fileB.hash_.hexdigest, aiB.line),
                           aiB.message.text))
                f.write('    </tr>\n')
            f.write('    </table>\n')

        cf = ComparativeFailures(afsA, afsB)
        if cf.new:
            f.write('<h2>New failures</h2>')
            write_failure_table_for_file(f, fileB, cf.new)

        if cf.fixed:
            f.write('<h2>Fixed failures</h2>')
            write_failure_table_for_file(f, fileA, cf.fixed)

        if cf.inboth:
            f.write('<h2>Failures in both old/new</h2>')
            f.write('    <table>\n')
            f.write('    <tr>\n')
            f.write('      <th>Tool</th>\n')
            f.write('      <th>Failure ID</th>\n')
            f.write('      <th>Old location</th>\n')
            f.write('      <th>New location</th>\n')
            f.write('      <th>Function</th>\n')
            f.write('      <th>Message</th>\n')
            f.write('      <th>Data</th>\n')
            f.write('    </tr>\n')
            for afA, afB in sorted(cf.inboth,
                                   lambda ab1, ab2: AnalysisFailure.cmp(ab1[1], ab2[1])):
                f.write('    <tr>\n')
                f.write('      <td>%s</td>\n' % afB.generator.name)
                f.write('      <td>%s</td>\n' % afB.failureid)
                f.write('      <td>%s:%i:%i</td>\n'
                        % (afA.givenpath,
                           afA.line,
                           afA.column))
                f.write('      <td>%s:%i:%i</td>\n'
                        % (afB.givenpath,
                           afB.line,
                           afB.column))
                f.write('      <td>%s</td>\n' % (afB.function.name if afB.function else '')),
                f.write('      <td><a href="%s">%s</a></td>\n'
                        % ('#file-%s-line-%i' % (fileB.hash_.hexdigest, afB.line),
                           html_escape(str(afB.message))))
                f.write('      <td>%s</td>\n' % (html_escape(afB.customfields)) if afB.customfields else '')
                f.write('    </tr>\n')
            f.write('    </table>\n')

        write_html_diff(f, modelA, modelB, fileA, fileB, aisA, aisB, afsA, afsB, sh)

    f.write('  </body>\n')
    f.write('</html>\n')

def main(argv):
    pathA = argv[1]
    pathB = argv[2]
    rdirA = ResultsDir(pathA)
    rdirB = ResultsDir(pathB)
    modelA = Model(rdirA)
    modelB = Model(rdirB)
    with open('index.html', 'w') as f:
        make_html(modelA, modelB, f)

main(sys.argv)

