from collections import namedtuple
import glob
import os
from xml.sax.saxutils import escape

from bs4 import UnicodeDammit # python-beautifulsoup4 on Fedora

from firehose.report import Analysis, Issue, Failure, Visitor

# escape() and unescape() takes care of &, < and >.
html_escape_table = {
    '"': "&quot;",
    "'": "&apos;"
}

def html_escape(text):
    return escape(text, html_escape_table)

def get_filename(file_):
    return file_.abspath.strip('/build/builddir/BUILD')

def get_internal_filename(file_):
    '''
    Given a File with an absolute path within an unpacked tarball within a
    buildroot:
    e.g.:
       '/builddir/build/BUILD/python-ethtool-0.7/python-ethtool/etherinfo.c'

    split out the trailing path fragment relative to the top of the tarball
    e.g.:
       'python-ethtool/etherinfo.c'

    The aim is to support comparisons between builds of different versions
    of the code.
    '''
    path = file_.abspath.strip('/build/builddir/BUILD')
    components = path.split('/')
    return os.path.join(*components[1:])

class ResultsDir:
    """
    Models a 'static-analysis' subdir as emitted by mock-with-analysis
    """
    def __init__(self, path):
        self.path = path

    def get_reports_dir(self):
        return os.path.join(self.path, 'reports')

    def get_sources_dir(self):
        return os.path.join(self.path, 'sources')

    def get_analyses(self):
        analyses = []
        for filename in glob.glob(os.path.join(self.get_reports_dir(), '*.xml')):
            r = Analysis.from_xml(filename)
            analyses.append( (filename, r) )
        return analyses

class AnalysisIssue(namedtuple('AnalysisIssue',
                               ['analysis', 'issue'])):
    def cmp(self, other):
        c = cmp(self.abspath,
                other.abspath)
        if c:
            return c
        c = cmp(self.line,
                other.line)
        if c:
            return c
        return 0

    @property
    def message(self):
        return self.issue.message

    @property
    def notes(self):
        return self.issue.notes

    @property
    def generator(self):
        return self.analysis.metadata.generator

    @property
    def testid(self):
        return self.issue.testid

    @property
    def givenpath(self):
        return self.issue.location.file.givenpath

    @property
    def abspath(self):
        return self.issue.location.file.abspath

    @property
    def internal_filename(self):
        return get_internal_filename(self.file_)

    @property
    def function(self):
        return self.issue.location.function

    @property
    def line(self):
        return self.issue.location.line

    @property
    def column(self):
        return self.issue.location.column

    @property
    def file_(self):
        return self.issue.location.file

    @property
    def trace(self):
        return self.issue.trace

class AnalysisFailure(namedtuple('AnalysisFailure',
                               ['analysis', 'failure'])):
    def cmp(self, other):
        c = cmp(self.abspath,
                other.abspath)
        if c:
            return c
        c = cmp(self.line,
                other.line)
        if c:
            return c
        return 0

    @property
    def generator(self):
        return self.analysis.metadata.generator

    @property
    def failureid(self):
        return self.failure.failureid

    @property
    def message(self):
        return self.failure.message

    @property
    def customfields(self):
        return self.failure.customfields

    @property
    def givenpath(self):
        return self.failure.location.file.givenpath

    @property
    def abspath(self):
        return self.failure.location.file.abspath

    @property
    def internal_filename(self):
        return get_internal_filename(self.file_)

    @property
    def function(self):
        return self.failure.location.function

    @property
    def line(self):
        return self.failure.location.line

    @property
    def column(self):
        return self.failure.location.column

    @property
    def file_(self):
        return self.failure.location.file

class Model:
    def __init__(self, rdir):
        self.rdir = rdir
        self._analyses = [r for (filename, r) in self.rdir.get_analyses()]

    def iter_analyses(self):
        return self._analyses

    def _open_file(self, file_):
        """
        Get a file-like object for reading the content of the source file
        as bytes
        """
        path = os.path.join(self.rdir.get_sources_dir(), file_.hash_.hexdigest)
        return open(path)

    def get_file_content(self, file_):
        """
        Get a unicode instance containing the content of the source file,
        making best guess as to the encoding(s)
        """
        with self._open_file(file_) as sourcefile:
            bytes_ = sourcefile.read()
            unicode_ = UnicodeDammit(bytes_).unicode_markup
            return unicode_

    def iter_analysis_issues(self):
        for analysis in self._analyses:
            for result in analysis.results:
                if isinstance(result, Issue):
                    yield AnalysisIssue(analysis, result)

    def iter_analysis_failures(self):
        for analysis in self._analyses:
            for result in analysis.results:
                if isinstance(result, Failure):
                    yield AnalysisFailure(analysis, result)

    def get_source_files(self):
        """
        Get a sorted list of all File instances of interest
        """
        result = set()
        for a in self.iter_analyses():
            class FindFiles(Visitor):
                def visit_file(self, file_):
                    result.add(file_)
            a.accept(FindFiles())
        return sorted(list(result),
                      lambda f1, f2: cmp(f1.abspath, f2.abspath))

    def get_generators(self):
        """
        Get all Generator instances that were run
        """
        result = set()
        for a in self.iter_analyses():
            class FindGenerators(Visitor):
                def visit_generator(self, generator):
                    result.add(generator)
            a.accept(FindGenerators())
        return sorted(list(result),
                      lambda f1, f2: cmp(f1.name, f2.name))

    def get_analysis_issues_by_source(self):
        result = {}
        for ai in self.iter_analysis_issues():
            key = ai.file_
            if key in result:
                result[key].add(ai)
            else:
                result[key] = set([ai])
        return result

    def get_analysis_issues_by_source_and_generator(self):
        result = {}
        for ai in self.iter_analysis_issues():
            key = (ai.file_, ai.generator)
            if key in result:
                result[key].add(ai)
            else:
                result[key] = set([ai])
        return result

    def get_analysis_failures_by_source(self):
        result = {}
        for af in self.iter_analysis_failures():
            key = af.file_
            if key in result:
                result[key].add(af)
            else:
                result[key] = set([af])
        return result

class SourceHighlighter:
    def __init__(self):
        from pygments.styles import get_style_by_name
        from pygments.formatters import HtmlFormatter

        # Get ready to use Pygments:
        self.style = get_style_by_name('default')
        self.formatter = HtmlFormatter(classprefix='source_',
                                       linenos='inline')

    def highlight(self, code):
        from pygments import highlight
        from pygments.lexers import CLexer
        html = highlight(code,
                         CLexer(),
                         # FIXME: ^^^ this hardcodes the source language
                         # (e.g. what about C++?)
                         self.formatter)
        return html

    def highlight_file(self, file_, model):
        if file_ is None:
            return ''
        result = ''
        code = model.get_file_content(file_)
        for i, line in enumerate(self.highlight(code).splitlines()):
            result += '<a id="file-%s-line-%i"/>' % (file_.hash_.hexdigest, i + 1)
            result += line
            result += '\n'
        return result

def make_issue_note(ai):
    html = '<div class="inline-error-report">'
    html += '   <div class="inline-error-report-message">%s</div>' % ai.message.text
    if ai.notes:
        html += '   <div class="inline-error-report-notes">%s</div>' % ai.notes.text
    html += '   <div class="inline-error-report-generator">(emitted by %s)</div>' % ai.generator.name
    if ai.trace:
        html += '<p>TODO: a detailed trace is available in the data model (not yet rendered in this report)</p>'
    html += '</div>'
    return html

def make_failure_note(af):
    html = '<div class="inline-failure-report">'
    html += ('   <div class="inline-failure-report-message">Failure running %s %s</div>'
             % (af.generator.name,
                (' (%r)' % af.failureid) if af.failureid is not None else ''))
    if af.message:
        html += '   <div class="inline-failure-report-title">Message</div>'
        html += '   <div class="inline-failure-report-field">%s</div>' % html_escape(af.message.text)
    if af.customfields:
        for key, value in af.customfields.iteritems():
            html += '   <span class="inline-failure-report-title">%s</span>:' % html_escape(key)
            html += '   <span class="inline-failure-report-field">%s</span>' % html_escape(str(value))
    html += '</div>'
    return html

def write_common_meta(f):
    f.write('<meta http-equiv="Content-Type" content="text/html; charset=utf-8">\n')

COMMON_CSS = '''
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

.inline-failure-report {
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

.inline-failure-report-message {
    font-weight: bold;
    font-size: 120%;
}

.inline-failure-report-title {
    font-weight: bold;
}

.inline-failure-report-field {
    font-weight: bold;
}

'''

def write_common_css(f):
    f.write(COMMON_CSS)

def write_issue_table_for_file(f, file_, ais):
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
                   html_escape(ai.message.text)))
        f.write('    </tr>\n')
    f.write('    </table>\n')

def write_failure_table_for_file(f, file_, afs):
    f.write('    <h3>Incomplete coverage</h3>\n')
    f.write('    <table>\n')
    f.write('    <tr>\n')
    f.write('      <th>Tool</th>\n')
    f.write('      <th>Failure ID</th>\n')
    f.write('      <th>Location</th>\n')
    f.write('      <th>Function</th>\n')
    f.write('      <th>Message</th>\n')
    f.write('      <th>Data</th>\n')
    f.write('    </tr>\n')
    for af in sorted(afs, AnalysisFailure.cmp):
        f.write('    <tr>\n')
        f.write('      <td>%s</td>\n' % af.generator.name)
        f.write('      <td>%s</td>\n' % af.failureid)
        f.write('      <td>%s:%i:%i</td>\n'
                % (af.givenpath,
                   af.line,
                   af.column))
        f.write('      <td>%s</td>\n' % (af.function.name if af.function else '')),
        f.write('      <td><a href="%s">%s</a></td>\n'
                % ('#file-%s-line-%i' % (file_.hash_.hexdigest, af.line),
                   html_escape(str(af.message))))
        f.write('      <td>%s</td>\n' % af.customfields)
        f.write('    </tr>\n')
    f.write('    </table>\n')
