import glob

from reports import get_filename, ResultsDir, AnalysisIssue, Model, \
    AnalysisFailure, Failure

for path in glob.glob('2013-02-12-fedora-17-mass-run/*/*/*/*/static-analysis'):
    print(path)
    rdir = ResultsDir(path)
    model = Model(rdir)
    for a in model.iter_analyses():
        for result in a.results:
            if isinstance(result, Failure):
                print('%s:%s' % (a.metadata.generator.name, result.failureid))
                if result.location:
                    if result.location.function:
                        print("  In function '%s':"
                              % result.location.function.name)

                if result.failureid == 'python-exception':
                    print('    %s' % result.customfields['traceback'].splitlines()[-1])

                if result.location:
                    if result.location.file:
                        code = model.get_file_content(result.location.file)
                        lines = code.splitlines()
                        print('\n'.join(('    %05i%s| %s '
                                         % (linenum,
                                            '>' if linenum == result.location.line else ' ',
                                            lines[linenum - 1]))
                                        for linenum in range(max(0, result.location.line - 5),
                                                             min(result.location.line + 6, len(lines)))))
