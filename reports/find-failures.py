import glob

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

def show_all_failures(globpath):
    for model, af in iter_reports(globpath):
        if isinstance(af, AnalysisFailure):
            print('%s:%s' % (af.generator.name, af.failureid))
            if af.location:
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

show_all_failures(GLOBPATH)
