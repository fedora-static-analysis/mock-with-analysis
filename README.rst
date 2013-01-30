mock-with-analysis
==================

Uses the `"mock" <http://fedoraproject.org/wiki/Projects/Mock>`_ tool to
rebuild a srpm within a chroot, but injects various static analyzers into
the build as side effects, gathering the results as
`Firehose <https://github.com/fedora-static-analysis/firehose>`_ XML files.

The following analyzers are currently run:

  * `cppcheck <http://cppcheck.sourceforge.net/>`_
  * `clang static analyzer <http://clang-analyzer.llvm.org/>`_
  * `cpychecker <https://gcc-python-plugin.readthedocs.org/en/latest/cpychecker.html>`_

as well as gathering gcc warnings.

The results are scraped out to the mock's results dir in a new
"static-analysis" directory:

::

  /var/lib/mock/CONFIG/result/state.log
                              root.log
                              build.log
                              BUILT-RPMS
                              static-analysis/ <=== this and below are new
                                             /reports/*.xml
                                             /sources/

where "static-analysis/reports/" contains the firehose XML files, and
"static-analysis/sources/" contains all relevant source files, named after
their SHA-1 digest.

Currently under heavy development

TODO:
  * add other analyzers (which?)
  * make more robust

    * capture analysis failures in the XML

      * gcc warnings that we can't parse
      * crashes of an analysis tool

    * add timeouts: if a checker takes too long, kill it (and capture it
      within in the XML)

