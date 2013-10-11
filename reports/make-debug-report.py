from collections import namedtuple
import glob
import os

from firehose.model import Analysis, Issue

class Result(namedtuple('Result',
                        ['filename', 'analysis', 'issue'])):
    def cmp(self, other):
        c = cmp(self.issue.location.file.abspath,
                other.issue.location.file.abspath)
        if c:
            return c
        c = cmp(self.issue.location.line,
                other.issue.location.line)
        if c:
            return c
        return 0

def get_analyses(mockdir):
    analyses = []
    for filename in glob.glob(os.path.join(mockdir, 'reports', '*.xml')):
        r = Analysis.from_xml(filename)
        analyses.append( (filename, r) )
    return analyses

def get_issues(analyses):
    result = []
    for filename, analysis in analyses:
        for issue in analysis.results:
            result.append(Result(filename, analysis, issue))
    return sorted(result, cmp=Result.cmp)

def cmp_analysis(fa1, fa2):
    f1, a1 = fa1
    f2, a2 = fa2

    c = cmp((a1.metadata.file_.abspath if a1.metadata.file_ else ''),
            (a2.metadata.file_.abspath if a2.metadata.file_ else ''))
    if c:
        return c

    c = cmp(a1.metadata.generator.name,
            a2.metadata.generator.name)
    return c

def make_html(f, analyses):
    title = ''
    f.write('<html><head><title>%s</title></head>\n' % title)
    f.write('  <body>\n')

    results = get_issues(analyses)

    f.write('<h1>What tools were run</h1>\n')
    f.write('    <table>\n')
    if 1:
        f.write('    <tr>\n')
        f.write('      <th>Source file</th>\n')
        f.write('      <th>Tool</th>\n')
        f.write('      <th>Result filename</th>\n')
        f.write('      <th>Issues found</th>\n')
        f.write('      <th>Wall-clock time</th>\n')
        f.write('    </tr>\n')
    for filename, a in sorted(analyses, cmp_analysis):
        f.write('    <tr>\n')
        f.write('      <td>%s</td>\n' % (a.metadata.file_.abspath if a.metadata.file_ else ''))
        f.write('      <td>%s</td>\n' % a.metadata.generator.name)
        f.write('      <td>%s</td>\n' % filename)
        f.write('      <td>%s</td>\n' % len(a.results))
        f.write('      <td>%s</td>\n' % a.metadata.stats.wallclocktime)
        f.write('    </tr>\n')
    f.write('    </table>\n')
    f.write('  </body>\n')
    f.write('</html>\n')

    f.write('<h1>What issues were found</h1>\n')
    f.write('    <table>\n')
    if 1:
        f.write('    <tr>\n')
        f.write('      <th>Location</th>\n')
        f.write('      <th>Tool</th>\n')
        f.write('      <th>Test</th>\n')
        f.write('      <th>Tool Version</th>\n')
        f.write('      <th>Function</th>\n')
        f.write('      <th>Message</th>\n')
        # TODO: notes and trace
        f.write('      <th>repr(Issue)</th>\n')
        f.write('      <th>within filename</th>\n')
        f.write('    </tr>\n')
    for pi in results:
        a = pi.analysis
        w = pi.issue
        f.write('    <tr>\n')
        f.write('      <td>%s:%i:%i</td>\n'
                % (w.location.file.givenpath,
                   w.location.line,
                   w.location.column))
        f.write('      <td>%s</td>\n' % a.metadata.generator.name)
        f.write('      <td>%s</td>\n' % w.testid)
        f.write('      <td>%s</td>\n' % a.metadata.generator.version)
        f.write('      <td>%s</td>\n' % (w.location.function.name if w.location.function else '')),
        f.write('      <td>%s</td>\n' % w.message.text)
        # TODO: notes and trace
        f.write('      <td>%s</td>\n' % repr(w))
        f.write('      <td>%s</td>\n' % pi.filename)
        f.write('    </tr>\n')
    f.write('    </table>\n')
    f.write('  </body>\n')
    f.write('</html>\n')


mockdir = '/var/lib/mock/fedora-17-x86_64/result/static-analysis'
analyses = get_analyses(mockdir)
with open('index.html', 'w') as f:
    make_html(f, analyses)

