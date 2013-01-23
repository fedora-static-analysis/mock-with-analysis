mock-with-analysis
==================

Uses the `"mock" <http://fedoraproject.org/wiki/Projects/Mock>`_ tool to
rebuild a srpm within a chroot, but injects various static analyzers into
the build as side effects, gathering the results as
`Firehose <https://github.com/fedora-static-analysis/firehose>`_ XML files.

The following analyzers are currently run:

  * `cppcheck <http://cppcheck.sourceforge.net/>`_
  * `clang static analyzer <http://clang-analyzer.llvm.org/>`_

as well as gathering gcc warnings.

Currently under heavy development

TODO:
  * add `cpychecker <https://gcc-python-plugin.readthedocs.org/en/latest/cpychecker.html>`_
  * add other analyzers (which?)

