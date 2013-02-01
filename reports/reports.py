from collections import namedtuple
import glob
import os

from firehose.report import Analysis, Issue, Visitor

def get_filename(file_):
    return file_.abspath.strip('/build/builddir/BUILD')

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

class Model:
    def __init__(self, rdir):
        self.rdir = rdir
        self._analyses = [r for (filename, r) in self.rdir.get_analyses()]

    def iter_analyses(self):
        return self._analyses

    def open_file(self, file_):
        path = os.path.join(self.rdir.get_sources_dir(), file_.hash_.hexdigest)
        return open(path)

    def iter_analysis_issues(self):
        for analysis in self._analyses:
            for result in analysis.results:
                if isinstance(result, Issue):
                    yield AnalysisIssue(analysis, result)

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

