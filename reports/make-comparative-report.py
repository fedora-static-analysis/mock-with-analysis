from difflib import SequenceMatcher, HtmlDiff
from pprint import pprint
import re
import sys

from reports import get_filename, ResultsDir, AnalysisIssue, Model, \
    SourceHighlighter, make_issue_note, get_internal_filename, \
    write_issue_table_for_file

class ComparativeIssues:
    """
    Comparison of a pair of lists of AnalysisIssue : what's new, what's
    fixed, etc
    """
    def __init__(self, aisA, aisB):
        self.aisA = aisA
        self.aisB = aisB

        def gather_issues_by_key(ais):
            result = {}
            for ai in ais:
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

        issuesA = gather_issues_by_key(aisA)
        issuesB = gather_issues_by_key(aisB)

        self.fixed = set() # of aiA
        self.inboth = set() # of (aiA, aiB) pairs
        self.new = set() # of aiB

        for key in set(issuesA.keys() + issuesB.keys()):
            if key in issuesA:
                if key in issuesB:
                    # Issues found in both old and new:
                    for aiA in issuesA[key]:
                        for aiB in issuesB[key]:
                            self.inboth.add( (aiA, aiB) )
                else:
                    # Issues found in old but not in new:
                    for aiA in issuesA[key]:
                        self.fixed.add(aiA)
            else:
                # Issue found in new but not in old:
                assert key in issuesB
                for aiB in issuesB[key]:
                    self.new.add(aiB)

def write_html_diff(f, modelA, modelB, fileA, fileB, aisA, aisB, sh):
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
        def get_td(idx, html, ais):
            if idx is not None:
                linenotes = ''
                for ai in ais:
                    if ai.line == idx + 1:
                        linenotes += make_issue_note(ai)
                return '<td width="50%%"><pre>%s</pre>%s</td>' % (html[idx], linenotes)
            else:
                return '<td width="50%%"></td>'

        def add_line(class_, idxA, idxB):
            f.write('<tr class="%s">%s%s</tr>\n'
                    % (class_,
                       get_td(idxA, htmlA, aisA),
                       get_td(idxB, htmlB, aisB)))

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

    f.write('''    <style type="text/css">
th {
    background-color: lightgrey;
}

.has_issues {
background-color: red;
}

.inline-error-report {
    #border: 0.1em dotted #ddffdd;
    #padding: 1em;
    border: 0.1em solid #ccc;
    -moz-box-shadow: 2px 2px 2px #ccc;
    -webkit-box-shadow: 2px 2px 2px #ccc;
    box-shadow: 2px 2px 2px #ccc;
    margin-left: 5em;
    font-family: proportional;
    font-style: italic;
    font-size: 90%;
}

.inline-error-report-message {
    font-weight: bold;
    font-size: 120%;
}

.replace {
    background-color: #e0ffff;
}

.insert {
    background-color: #ffe0ff;
}

.delete {
    background-color: #ffffe0;
}


''')
    f.write(sh.formatter.get_style_defs())

    f.write('      </style>\n')

    f.write('</head>\n')

    f.write('  <body>\n')

    generatorsA = modelA.get_generators()
    generatorsB = modelB.get_generators()
    generators = sorted(set(generatorsA + generatorsB))

    aisA_by_source_and_generator = modelA.get_analysis_issues_by_source_and_generator()
    aisB_by_source_and_generator = modelB.get_analysis_issues_by_source_and_generator()

    f.write('<p>Old build: <b>%s</b></p>' % sutA)
    f.write('<p>New build: <b>%s</b></p>' % sutB)

    f.write('    <table>\n')
    if 1:
        f.write('    <tr>\n')
        f.write('      <th>Old file</th>\n')
        f.write('      <th>New file</th>\n')
        for generator in generators:
            f.write('      <th>%s</th>\n' % generator.name)
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
        f.write('    </tr>\n')
    f.write('    </table>\n')

    for internal_path in sorted(internal_paths):
        fileA = sourcesA_by_internal_path.get(internal_path, None)
        fileB = sourcesB_by_internal_path.get(internal_path, None)

        aisA = modelA.get_analysis_issues_by_source().get(fileA, set())
        aisB = modelB.get_analysis_issues_by_source().get(fileB, set())

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

        write_html_diff(f, modelA, modelB, fileA, fileB, aisA, aisB, sh)

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

