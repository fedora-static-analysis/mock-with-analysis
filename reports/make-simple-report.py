import sys

from reports import get_filename, ResultsDir, AnalysisIssue, Model, \
    SourceHighlighter

def make_html(model, f):
    sh = SourceHighlighter()

    analyses = list(model.iter_analyses())

    title = ''
    f.write('<html><head><title>%s</title>\n' % title)

    f.write('''    <style type="text/css">
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


''')
    f.write(sh.formatter.get_style_defs())

    f.write('      </style>\n')

    f.write('</head>\n')

    f.write('  <body>\n')

    sources = model.get_source_files()
    generators = model.get_generators()
    ais_by_source = model.get_analysis_issues_by_source()
    ais_by_source_and_generator = model.get_analysis_issues_by_source_and_generator()

    f.write('    <table>\n')
    if 1:
        f.write('    <tr>\n')
        f.write('      <th>Source file</th>\n')
        for generator in generators:
            f.write('      <th>%s</th>\n' % generator.name)
        f.write('    </tr>\n')
    for file_ in sources:
        f.write('    <tr>\n')
        f.write('      <td><a href="#file-%s">%s</a></td>\n'
                % (file_.hash_.hexdigest, get_filename(file_)))
        for generator in generators:
            key = (file_, generator)
            ais = ais_by_source_and_generator.get(key, set())
            class_ = 'has_issues' if ais else 'no_issues'
            f.write('      <td class="%s">%s</td>\n' % (class_, len(ais)))
        f.write('    </tr>\n')
    f.write('    </table>\n')

    for file_ in sources:
        f.write('<h2><a id="file-%s">%s</h2>\n' % (file_.hash_.hexdigest, get_filename(file_)))
        ais = ais_by_source.get(file_, set())
        if ais:
            f.write('    <table>\n')
            f.write('    <tr>\n')
            f.write('      <th>Location</th>\n')
            f.write('      <th>Tool</th>\n')
            f.write('      <th>Test ID</th>\n')
            f.write('      <th>Function</th>\n')
            f.write('      <th>Issue</th>\n')
            f.write('    </tr>\n')
            for ai in sorted(ais, AnalysisIssue.cmp):
                f.write('    <tr>\n')
                f.write('      <td>%s:%i:%i</td>\n'
                        % (ai.givenpath,
                           ai.line,
                           ai.column))
                f.write('      <td>%s</td>\n' % ai.generator.name)
                f.write('      <td>%s</td>\n' % (ai.testid if ai.testid else ''))
                f.write('      <td>%s</td>\n' % (ai.function.name if ai.function else '')),
                f.write('      <td><a href="%s">%s</a></td>\n'
                        % ('#file-%s-line-%i' % (file_.hash_.hexdigest, ai.line),
                           ai.message.text))
                f.write('    </tr>\n')
            f.write('    </table>\n')
        else:
            f.write('<p>No issues found</p>')
        # Include source inline:
        with model.open_file(file_) as sourcefile:
            code = sourcefile.read()
        for i, line in enumerate(sh.highlight(code).splitlines()):
            f.write('<a id="file-%s-line-%i"/>' % (file_.hash_.hexdigest, i + 1))
            f.write(line)
            f.write('\n')
            for ai in ais:
                if ai.line == i + 1:
                    f.write('<div class="inline-error-report">')
                    f.write('   <div class="inline-error-report-message">%s</div>' % ai.message.text)
                    if ai.notes:
                        f.write('   <div class="inline-error-report-notes">%s</div>' % ai.notes.text)
                    f.write('   <div class="inline-error-report-generator">(emitted by %s)</div>' % ai.generator.name)
                    if ai.trace:
                        f.write('<p>TODO: a detailed trace is available in the data model (not yet rendered in this report)</p>')
                    f.write('</div>')

    f.write('  </body>\n')
    f.write('</html>\n')

def main(argv):
    path = argv[1]
    rdir = ResultsDir(path)
    model = Model(rdir)
    with open('index.html', 'w') as f:
        make_html(model, f)

main(sys.argv)

