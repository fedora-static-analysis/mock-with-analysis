mock-with-analysis
==================

Uses the "mock" tool to rebuild a srpm within a chroot, but injects various
static analyzers into the build as side effects, gathering the results as
`Firehose https://github.com/fedora-static-analysis/firehose`_ XML files.

The following analyzers are currently run:
* `http://cppcheck.sourceforge.net/ cppcheck`_
as well as gathering gcc warnings.

Currently under heavy development

TODO:
* add `https://gcc-python-plugin.readthedocs.org/en/latest/cpychecker.html cpychecker`_
* invoke `clang static analyzer http://clang-analyzer.llvm.org/`_
* add other analyzers (which?)

