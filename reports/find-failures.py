import glob
import os
import re

from reports import get_filename, ResultsDir, AnalysisIssue, Model, \
    AnalysisFailure, Failure, Issue

GLOBPATH='2013-02-12-fedora-17-mass-run/*/*/*/*/static-analysis'

def iter_reports(globpath):
    for path in glob.glob(globpath):
        print(path)
        rdir = ResultsDir(path)
        model = Model(rdir)
        for a in model.iter_analyses():
            for result in a.results:
                if isinstance(result, Issue):
                    yield model, AnalysisIssue(a, result)
                if isinstance(result, Failure):
                    yield model, AnalysisFailure(a, result)

def extract_exception(af):
    assert af.failureid == 'python-exception'
    finalline = af.customfields['traceback'].splitlines()[-1]
    m = re.match('^(\S+): (.+) at (\S+):([0-9]+)$', finalline)
    print m.groups()

def show_all_failures(globpath):
    for model, af in iter_reports(globpath):
        if isinstance(af, AnalysisFailure):
            print('%s' % (af.sut, ))
            print(' %s:%s' % (af.generator.name, af.failureid))
            if af.location:
                if af.location.file:
                    print(" %s" % af.location.file.abspath)
                if af.location.function:
                    print("  In function '%s':"
                          % af.location.function.name)

            if af.failureid == 'python-exception':
                print('    %s' % af.customfields['traceback'].splitlines()[-1])

            if af.location:
                if af.location.file:
                    code = model.get_file_content(af.location.file)
                    lines = code.splitlines()
                    print('\n'.join(('    %05i%s| %s '
                                     % (linenum,
                                        '>' if linenum == af.location.line else ' ',
                                        lines[linenum - 1]))
                                    for linenum in range(max(0, af.location.line - 5),
                                                         min(af.location.line + 6, len(lines)))))
                    print('full source: %s' % os.path.abspath(model._get_file_path(af.location.file)))

def show_all_tracebacks(globpath):
    for model, af in iter_reports(globpath):
        if isinstance(af, AnalysisFailure):
            if af.failureid == 'python-exception':
                print('%s' % af.customfields['traceback'].splitlines()[-1])

show_all_failures(GLOBPATH)
#show_all_tracebacks(GLOBPATH)
