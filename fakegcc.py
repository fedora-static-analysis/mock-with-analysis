#!/usr/bin/env python
#   Copyright 2012, 2013, 2015 David Malcolm <dmalcolm@redhat.com>
#   Copyright 2012, 2013, 2015 Red Hat, Inc.
#
#   This is free software: you can redistribute it and/or modify it
#   under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful, but
#   WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#   General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see
#   <http://www.gnu.org/licenses/>.

# Harness for invoking GCC whilst injecting extra side-effects
# (e.g. static code analyzers)
#
# This code assumes that it is /usr/bin/gcc and that the real GCC has been
# moved to /usr/bin/the-real-gcc
#
# Note that we can't write log messages to stdout if we're pretending
# to be gcc, since some tools parse the stdout of gcc
# For example, this failure from a configure script:
#     checking for ld used by gcc... no
#     configure: error: no acceptable ld found in $PATH
# turned out to be due to it capturing stdout from this invocation:
#     cc -print-prog-name=ld
# which naturally went wrong when run with an earlier version of
# fakegcc.py that sent debug log messages to stdout.

import glob
import hashlib
import logging
import os
import re
import StringIO
import sys
import tempfile
import time
import traceback
import unittest

# http://pypi.python.org/pypi/subprocess32
# so that we can use timeouts
from subprocess32 import Popen, PIPE, STDOUT, TimeoutExpired

from firehose.model import Analysis, Generator, Metadata, Failure, \
    Location, File, Message, Issue, Trace

from gccinvocation import GccInvocation

def in_chroot():
    return os.path.exists('/builddir')

def make_file(givenpath):
    from firehose.model import File
    return File(givenpath=givenpath,
                abspath=None,
                hash_=None)

def make_stats(timer):
    from firehose.model import Stats
    return Stats(wallclocktime=timer.get_elapsed_time())

class Timer:
    """
    Simple measurement of wallclock time taken
    """
    def __init__(self):
        self.starttime = time.time()

    def get_elapsed_time(self):
        """Get elapsed time in seconds as a float"""
        curtime = time.time()
        return curtime - self.starttime

    def elapsed_time_as_str(self):
        """Get elapsed time as a string (with units)"""
        elapsed = self.get_elapsed_time()
        result = '%0.3f seconds' % elapsed
        if elapsed > 120:
            result += ' (%i minutes)' % int(elapsed / 60)
        return result

class Context:
    def __init__(self, enable_logging=False):
        self.enable_logging = enable_logging
        if self.enable_logging:
            if in_chroot():
                logging.basicConfig(format='%(asctime)s %(message)s',
                                    datefmt='%H:%M:%S',
                                    level=logging.INFO,
                                    filename='/builddir/fakegcc.log')
            else:
                logging.basicConfig(format='%(asctime)s %(message)s',
                                    #datefmt='%H:%M:%S',
                                    level=logging.INFO,
                                    stream=sys.stdout)
            self.log('logging initialized')

        self.stdout = sys.stdout
        self.stderr = sys.stderr
        self.returncode = None

    def log(self, msg):
        if self.enable_logging:
            logging.info(msg)

    def write_streams(self, toolname, out, err):
        for line in out.splitlines():
            self.log('stdout from %r: %s\n' % (toolname, line))
        for line in err.splitlines():
            self.log('stderr from %r: %s\n' % (toolname, line))

class Driver:
    """
    A drop-in substitute for the "gcc" driver which runs a series of
    "side-effect" tools before performing the real driver.
    """
    def __init__(self, ctxt, side_effects=None, real_driver='gcc',
                 capture_exceptions=False, outputdir='/builddir'):
        self.ctxt = ctxt
        if side_effects is None:
            side_effects =  [InvokeCppcheck(ctxt),
                             InvokeClangAnalyzer(ctxt),
                             InvokeCpychecker(ctxt),
                             InvokeRealGcc(real_driver, ctxt)]
        self.side_effects = side_effects
        self.real_driver = real_driver
        self.capture_exceptions = capture_exceptions
        self.outputdir = outputdir

    def log(self, msg):
        self.ctxt.log(msg)

    def invoke(self, argv):
        """FIXME"""
        self.log("Driver.invoke: %s"
            % ' '.join(sys.argv))

        gccinv = GccInvocation(argv)

        self.log('  gccinv.sources: %r' % gccinv.sources)

        # Run the side effects on each source file:
        for sourcefile in gccinv.sources:
            self.log('    sourcefile: %r' % sourcefile)
            if sourcefile.endswith('.c'): # FIXME: other extensions?
                single_source_gccinv = gccinv.restrict_to_one_source(sourcefile)

                # Avoid linker errors due to splitting up the build into
                # multiple gcc invocations:
                single_source_gccinv.argv += ['-c']

                self.log('    single_source_gccinv: %r' % single_source_gccinv)
                for side_effect in self.side_effects:
                    analysis = self.invoke_tool(side_effect,
                                                single_source_gccinv,
                                                sourcefile)
                    #analysis.set_custom_field('gcc-invocation', ' '.join(argv))
                    self.write_analysis_as_xml(analysis)

        # Now run the real driver.
        # Note that we already ran the real gcc earlier as a
        # side-effect per source-file, capturing warnings there.
        # We have to do it separately from here since the invocation
        # might cover multiple source files.

        argv = [self.real_driver] + gccinv.argv[1:]
        env=os.environ.copy()
        # FIXME: this probably shouldn't be hardcoded
        env['LANG'] = 'C'
        p = Popen(argv,
                  stdout=PIPE, stderr=PIPE, env=env)
        out, err = p.communicate()
        self.ctxt.stdout.write(out)
        self.ctxt.stderr.write(err)
        self.returncode = p.returncode

    def invoke_tool(self, tool, gccinv, sourcefile):
        """
        Call "invoke" on the side-effect, handling exceptions.
        Return an Analysis instance.
        """
        assert len(gccinv.sources) == 1
        try:
            self.log('about to invoke: %s with %r' % (tool.name, gccinv))
            analysis = tool.invoke(gccinv, sourcefile)
        except TimeoutExpired:
            analysis = (
                tool._make_failed_analysis(sourcefile, t,
                                                  msgtext='Timeout running %s' % tool.name,
                                                  failureid='timeout'))
            analysis.set_custom_field('timeout', TIMEOUT)
        except Exception, exc:
            # Capture the exception as a Failure instance.
            # Alternatively when debugging such failures, it can
            # be easier to re-raise the exception:
            if not self.capture_exceptions:
                raise
            analysis = \
                tool._make_failed_analysis(
                    sourcefile, None,
                    msgtext=('Exception running %s: %s'
                             % (tool.name, exc)),
                    failureid='exception')
            tb_str = traceback.format_exc()
            analysis.set_custom_field('traceback', tb_str)
        if sourcefile:
            analysis.metadata.file_.givenpath = sourcefile
            analysis.metadata.file_.abspath = os.path.join(os.getcwd(),
                                                           sourcefile)
        return analysis

    def write_analysis_as_xml(self, analysis, dstxmlpath=None):
        # Ensure we have absolute paths (within the chroot) and SHA-1 hashes
        # of all files referred to in the report:
        if analysis.metadata.file_:
            if os.path.exists(analysis.metadata.file_.givenpath):
                analysis.fixup_files(os.getcwd(), 'sha1')

        xml_bytes = analysis.to_xml_bytes()

        # Dump the XML to stdout, so it's visible in the logs:
        self.log('resulting XML: %s\n' % xml_bytes)

        if dstxmlpath is None:
            # Use the SHA-1 hash of the report to create a unique filename
            # and dump it in an absolute location in the chroot:
            hexdigest = hashlib.sha1(xml_bytes).hexdigest()
            dstxmlpath = os.path.join(self.outputdir, '%s.xml' % hexdigest)

        with open(dstxmlpath, 'w') as f:
            f.write(xml_bytes)

############################################################################
def get_real_executable(argv):
    apparentcmd = argv[0]
    if in_chroot():
        dir_, basename = os.path.split(apparentcmd)
        return os.path.join(dir_, 'the-real-%s' % basename)
    else:
        return apparentcmd

############################################################################

class SubprocessResult:
    """
    A bundle of information relating to a subprocess invocation.
    """
    def __init__(self, sourcefile, argv, returncode, out, err, timer):
        self.sourcefile = sourcefile
        self.argv = argv
        self.returncode = returncode
        self.out = out
        self.err = err
        self.timer = timer

    def set_custom_fields(self, analysis):
        analysis.set_custom_field('returncode', self.returncode)
        analysis.set_custom_field('stdout', self.out.decode('utf-8'))
        analysis.set_custom_field('stderr', self.err.decode('utf-8'))

class Tool:
    def __init__(self, name, ctxt):
        self.name = name
        self.timeout = 60
        self.ctxt = ctxt

    def log(self, msg):
        self.ctxt.log(msg)

    def invoke(self, gccinv, sourcefile):
        """
        Run the tool, with a timeout, returning an Analysis instance.
        May well raise an exception if something major went wrong.
        """
        raise NotImplementedError

    def handle_output(self, result):
        """
        Given a SubprocessResult, return an Analysis instance.
        """
        raise NotImplementedError

    def _make_failed_analysis(self, sourcefile, t, msgtext, failureid):
        """
        Something went wrong; build a failure report.
        """
        generator = Generator(name=self.name,
                              version=None)
        if t:
            stats = make_stats(t)
        else:
            stats = None

        metadata = Metadata(generator=generator,
                            sut=None,
                            file_ = make_file(sourcefile),
                            stats=stats)
        file_ = File(givenpath=sourcefile,
                     abspath=None,
                     hash_=None)
        location = Location(file=file_,
                            function=None,
                            point=None,
                            range_=None)
        message = Message(msgtext)
        results = [Failure(failureid=failureid,
                           location=location,
                           message=message,
                           customfields=None)]
        analysis = Analysis(metadata, results)
        return analysis

    def _run_subprocess(self, sourcefile, argv, env=None):
        """
        Support for running the bulk of the side effect in a subprocess,
        with timeout support.
        """
        self.log('%s: _run_subprocess(%r, %r)' % (self.name, sourcefile, argv))
        if 0:
            self.log('env: %s' % env)
        p = Popen(argv,
                  stdout=PIPE, stderr=PIPE, env=env)
        try:
            t = Timer()
            out, err = p.communicate(timeout=self.timeout)
            self.ctxt.write_streams(argv[0], out, err)
            result = SubprocessResult(sourcefile, argv, p.returncode, out, err, t)
            analysis = self.handle_output(result)
            return analysis
        except TimeoutExpired:
            analysis = self._make_failed_analysis(sourcefile, t,
                                                  msgtext='Timeout running %s' % self.name,
                                                  failureid='timeout')
            analysis.set_custom_field('timeout', self.timeout)
            analysis.set_custom_field('command-line', ' '.join(argv))
            return analysis

############################################################################
# Tool subclasses
############################################################################

class InvokeRealGcc(Tool):
    """
    Tool subclass that invokes a real gcc driver binary
    """
    def __init__(self, executable, ctxt, extra_args=None, extra_env=None):
        Tool.__init__(self, 'gcc', ctxt)
        self.executable = executable
        self.extra_args = extra_args
        self.extra_env = extra_env
        # We are only ever invoked with individual input files.
        # Override any -o, to ensure we don't interfere with the output
        # from the real compiler:
        self.output_file = tempfile.NamedTemporaryFile()

    def invoke(self, gccinv, sourcefile):
        args = [self.executable] + gccinv.argv[1:]
        if self.extra_args:
            args += self.extra_args
        args += ['-o', self.output_file.name]

        # The result parser requires the C locale
        env = os.environ.copy()
        env['LANG'] = 'C'
        if self.extra_env:
            for key, value in self.extra_env.iteritems():
                env[key] = value
        return self._run_subprocess(sourcefile, args, env=env)

    def handle_output(self, result):
        from firehose.parsers.gcc import parse_file

        f = StringIO.StringIO(result.err)
        analysis = parse_file(f, stats=make_stats(result.timer))
        if result.sourcefile:
            analysis.metadata.file_ = File(givenpath=result.sourcefile,
                                           abspath=None)
        self.set_custom_fields(result, analysis)

        self.result = result

        return analysis

    def set_custom_fields(self, result, analysis):
        analysis.set_custom_field('gcc-invocation',
                                  ' '.join(result.argv))
        result.set_custom_fields(analysis)


class InvokeCustomGcc(InvokeRealGcc):
    """
    Tool subclass that invokes a custom build of gcc 6 I have.
    This is a patched version of gcc that writes out a file
    to DUMPBASE.custom-dump.txt, containing a series of
    lines of the form
       KEY: VALUE
    """
    def __init__(self, executable, ctxt, extra_args=None, extra_env=None):
        InvokeRealGcc.__init__(self, executable, ctxt, extra_args, extra_env)
        self.name = 'custom-gcc'

    def handle_output(self, result):
        analysis = InvokeRealGcc.handle_output(self, result)
        analysis.metadata.generator.name = 'custom-gcc'
        dumpbase = os.path.join(os.path.dirname(self.output_file.name),
                                os.path.basename(result.sourcefile))
        dumpfile_path = dumpbase + '.custom-dump.txt'
        if os.path.exists(dumpfile_path):
            self.log('found custom dumpfile: %s' % dumpfile_path)
            with open(dumpfile_path) as f:
                for line in f:
                    self.log(line)
                    # Expect lines of the form "KEY: VALUE"
                    m = re.match('^(.+): (.+)$', line)
                    self.log(str(m.groups()))
                    key, value = m.groups()
                    analysis.set_custom_field(key, value)
        else:
            self.log('could not find custom dumpfile: %s' % dumpfile_path)
        return analysis

class InvokeCppcheck(Tool):
    """
    Tool subclass that invokes "cppcheck"
    """
    def __init__(self, ctxt):
        Tool.__init__(self, 'cppcheck', ctxt)

    def invoke(self, gccinv, sourcefile):
        args = ['cppcheck',
                '--xml', '--xml-version=2',
                sourcefile]
        return self._run_subprocess(sourcefile, args)

    def handle_output(self, result):
        from firehose.parsers.cppcheck import parse_file

        if result.returncode:
            analysis = self._make_failed_analysis(result.sourcefile, result.timer,
                                                  msgtext='Bad exit code running %s' % self.name,
                                                  failureid='bad-exit-code')
            self.set_custom_fields(result, analysis)
            return analysis

        # (there doesn't seem to be a way to have cppcheck directly
        # save its XML output to a given location)

        with tempfile.NamedTemporaryFile() as outfile:
            outfile.write(result.err)
            outfile.flush()

            with open(outfile.name) as infile:
                # Parse stderr into firehose XML format and save:
                analysis = parse_file(infile,
                                      file_=make_file(result.sourcefile),
                                      stats=make_stats(result.timer))
                self.set_custom_fields(result, analysis)
                return analysis

    def set_custom_fields(self, result, analysis):
        analysis.set_custom_field('cppcheck-invocation',
                                  ' '.join(result.argv))
        result.set_custom_fields(analysis)

class InvokeClangAnalyzer(Tool):
    """
    Tool subclass that invokes the clang analyzer
    """
    def __init__(self, ctxt):
        Tool.__init__(self, 'clang-analyzer', ctxt)

    def invoke(self, gccinv, sourcefile):
        self.resultdir = tempfile.mkdtemp()
        args = ['scan-build', '-v', '-plist',
                '--use-analyzer', '/usr/bin/clang', # rhbz 923834
                '-o', self.resultdir,
                get_real_executable(gccinv.argv)] + gccinv.argv[1:]
        return self._run_subprocess(sourcefile, args)

    def handle_output(self, result):
        from firehose.parsers.clanganalyzer import parse_plist

        if result.returncode:
            analysis = self._make_failed_analysis(result.sourcefile, result.timer,
                                                  msgtext='Bad exit code running %s' % self.name,
                                                  failureid='bad-exit-code')
            self.set_custom_fields(result, analysis)
            return analysis

        # Given e.g. resultdir='/tmp/tmpQW2l2B', the plist files
        # are an extra level deep e.g.:
        #  '/tmp/tmpQW2l2B/2013-01-22-1/report-MlwJri.plist'
        self.log(self.resultdir)
        for plistpath in glob.glob(os.path.join(self.resultdir,
                                                '*/*.plist')):
            analysis = parse_plist(plistpath,
                                   file_=make_file(result.sourcefile),
                                   stats=make_stats(result.timer))
            self.set_custom_fields(result, analysis)
            analysis.set_custom_field('plistpath', plistpath)
            return analysis # could there be more than one?

        # Not found?
        analysis = self._make_failed_analysis(
            result.sourcefile, result.timer,
            msgtext='Unable to locate plist file',
            failureid='plist-not-found')
        self.set_custom_fields(result, analysis)
        return analysis

    def set_custom_fields(self, result, analysis):
        analysis.set_custom_field('scan-build-invocation',
                                  ' '.join(result.argv))
        result.set_custom_fields(analysis)

class InvokeCpychecker(Tool):
    """
    Tool subclass that invoke the gcc-python-plugin's "cpychecker" code.

    This currently requires the "firehose" branch of gcc-python-plugin
    """

    def __init__(self, ctxt):
        Tool.__init__(self, 'cpychecker', ctxt)

    def invoke(self, gccinv, sourcefile):
        # Invoke the plugin, but for robustness, do it in an entirely
        # separate gcc invocation
        argv = gccinv.argv[:]

        self.outputxmlpath = '%s.firehose.xml' % sourcefile

        # The plugin needs to be able to find its own modules, or we get:
        #   ImportError: No module named libcpychecker
        # We can either set PYTHONPATH in the environment,
        # or provide a full path to the plugin in the invocation line:
        # in the latter case, gcc-python.c:setup_sys sets up sys.path
        # inside the plugin to include the directory containing the plugin
        # if we provide a full path to the plugin here.

        # That said, the plugin's Makefile installs the plugin
        # as "python.so" to $(GCCPLUGINS_DIR)
        # and the support modules to $(GCCPLUGINS_DIR)/$(PLUGIN_DIR)
        # So let's do it via PYTHONPATH

        # FIXME: hacked in path:
        plugin_path = '/home/david/coding/gcc-python/gcc-python/cpychecker-firehose-output/'
        plugin_gcc_c_api_path = '/home/david/coding/gcc-python/gcc-python/cpychecker-firehose-output/gcc-c-api'
        plugin_sys_path = '/home/david/coding/gcc-python/gcc-python/cpychecker-firehose-output/'
        plugin_full_name = os.path.join(plugin_path, 'python.so')
        env = os.environ.copy()
        env['PYTHONPATH'] = plugin_sys_path
        env['LD_LIBRARY_PATH'] = plugin_gcc_c_api_path

        # We would use the regular keyword argument syntax:
        #   outputxmlpath='foo'
        # but unfortunately gcc's option parser seems to not be able to
        # cope with '='  within an option's value.  So we do it using
        # dictionary syntax instead:
        pycmd = ('from libcpychecker import main, Options; '
                 'main(Options(**{"outputxmlpath":"%s", '
                 '"verify_refcounting": True, '
                 '"maxtrans": 1024, '
                 '}))' % self.outputxmlpath)
        # Note that some RPMs also rename the plugin from
        # "python.so" to "python2.so", which would require further work.
        argv += ['-fplugin=%s' % plugin_full_name,
                 '-fplugin-arg-python-command=%s' % pycmd]

        args = [get_real_executable(argv)] + argv[1:]

        return self._run_subprocess(sourcefile, args, env)

    def handle_output(self, result):
        if os.path.exists(self.outputxmlpath):
            with open(self.outputxmlpath) as f:
                analysis = Analysis.from_xml(f)
                analysis.metadata.file_ = make_file(result.sourcefile)
                analysis.metadata.stats = make_stats(result.timer)
        else:
            analysis = \
                self._make_failed_analysis(
                    result.sourcefile, result.timer,
                    msgtext=('Unable to locate XML output from %s'
                             % self.name),
                    failureid='no-output-found')
        analysis.set_custom_field('cpychecker-invocation',
                                  ' '.join(result.argv))
        result.set_custom_fields(analysis)
        return analysis

############################################################################
# Test suite
############################################################################

class ToolTests(unittest.TestCase):
    def make_ctxt(self):
        return Context(enable_logging=0)

    def make_driver(self):
        ctxt = self.make_ctxt()
        se = self.make_tool(ctxt)
        driver = Driver(ctxt, side_effects=[se])
        return se, driver

    def make_tool(self, ctxt):
        """Hook for self.make_driver()"""
        raise NotImplementedError

    def verify_basic_metadata(self, analysis, sourcefile):
        """Hook for self.invoke()"""
        raise NotImplementedError

    def invoke(self, sourcefile, extraargs = None):
        """Invoke just one side effect and sanity-check the result"""
        se, driver = self.make_driver()
        argv = ['gcc', '-c', sourcefile]
        if extraargs:
            argv += extraargs
        gccinv = GccInvocation(argv)
        analysis = driver.invoke_tool(se, gccinv, sourcefile)

        if 0:
            print(analysis)

        # Call a subclass hook to check basic metadata:
        self.verify_basic_metadata(analysis, sourcefile)

        # Verify that we can serialize to XML:
        xml_bytes = analysis.to_xml_bytes()
        self.assert_(xml_bytes.startswith(b'<analysis>'))

        return analysis

    def assert_metadata(self, analysis,
                        expected_generator_name, expected_given_path):
        self.assertEqual(analysis.metadata.generator.name,
                         expected_generator_name)
        self.assertEqual(analysis.metadata.file_.givenpath, expected_given_path)
        self.assertIn(expected_given_path, analysis.metadata.file_.abspath)

    def assert_has_custom_field(self, analysis, name):
        self.assert_(analysis.customfields)
        self.assert_(name in analysis.customfields)

class BuggyToolTests(ToolTests):
    def make_driver(self):
        """
        Override base class impl, so that we can enable
        exception-capture (and provide a custom tool)
        """
        class BuggyTool(Tool):
            def invoke(self, gccinv, sourcefile):
                raise ValueError('test of raising an exception')

        ctxt = self.make_ctxt()
        se = BuggyTool('buggy', ctxt)
        driver = Driver(ctxt, side_effects=[se], capture_exceptions=True)
        return se, driver

    def verify_basic_metadata(self, analysis, sourcefile):
         self.assert_metadata(analysis, 'buggy', sourcefile)

    def test_exception_handling(self):
        analysis = self.invoke('test-sources/harmless.c')
        #print(analysis)
        self.assertEqual(len(analysis.results), 1)
        r0 = analysis.results[0]
        self.assertIsInstance(r0, Failure)
        self.assertEqual(r0.failureid, 'exception')
        self.assertEqual(r0.message.text,
                         ('Exception running buggy:'
                          ' test of raising an exception'))
        self.assert_(analysis.customfields['traceback'].startswith(
            'Traceback (most recent call last):\n'))

class RealGccTests(ToolTests):
    def make_tool(self, ctxt):
        return InvokeRealGcc('gcc', ctxt)

    def verify_basic_metadata(self, analysis, sourcefile):
        # Verify basic metadata:
        self.assert_metadata(analysis, 'gcc', sourcefile)
        self.assert_has_custom_field(analysis, 'gcc-invocation')
        self.assert_has_custom_field(analysis, 'stdout')
        self.assert_has_custom_field(analysis, 'stderr')

    def test_file_not_found(self):
        analysis = self.invoke('does-not-exist.c')
        #print(analysis)
        # Currently this gives no output:
        self.assertEqual(len(analysis.results), 0)

    def test_timeout(self):
        sourcefile = 'test-sources/harmless.c'
        se, driver = self.make_driver()
        se.timeout = 0
        gccinv = GccInvocation(['gcc', sourcefile])
        analysis = driver.invoke_tool(se, gccinv, sourcefile)
        self.assert_metadata(analysis, se.name, sourcefile)
        self.assertEqual(len(analysis.results), 1)
        r0 = analysis.results[0]
        self.assertIsInstance(r0, Failure)
        self.assertEqual(r0.failureid, 'timeout')
        self.assert_has_custom_field(analysis, 'timeout')
        self.assert_has_custom_field(analysis, 'command-line')

    def test_harmless_file(self):
        analysis = self.invoke('test-sources/harmless.c')
        #print(analysis)
        self.assertEqual(len(analysis.results), 0)

    def test_divide_by_zero(self):
        analysis = self.invoke('test-sources/divide-by-zero.c', ['-Wall'])
        self.assertEqual(len(analysis.results), 1)
        r0 = analysis.results[0]
        self.assertIsInstance(r0, Issue)
        self.assertEqual(r0.testid, 'div-by-zero')
        self.assertEqual(r0.location.file.givenpath,
                         'test-sources/divide-by-zero.c')
        self.assertEqual(r0.location.function.name, 'divide_by_zero')
        self.assertEqual(r0.location.point.line, 3)
        self.assertEqual(r0.message.text, 'division by zero')
        self.assertEqual(r0.severity, None)

class CustomGccTests(RealGccTests):
    def make_tool(self, ctxt):
        # FIXME: hardcoded paths
        DRIVER_PATH= '/home/david/coding-3/gcc-git-rich-errors/build/gcc/xgcc'
        EXTRA_ARGS=['-B/home/david/coding-3/gcc-git-rich-errors/build/gcc']
        EXTRA_ENV={'LD_LIBRARY_PATH':'/home/david/coding/gcc-python/gcc-build-new-cloog/dep-prefix/lib:'}

        # Exercise the new '-Wmisleading-indentation' warning (to see how
        # often it occurs in a large corpus of code):
        EXTRA_ARGS += ['-Wmisleading-indentation']

        return InvokeCustomGcc(DRIVER_PATH, ctxt, EXTRA_ARGS, EXTRA_ENV)

    def verify_basic_metadata(self, analysis, sourcefile):
        # Similar to RealGccTests.verify_basic_metadata

        # Different name:
        self.assert_metadata(analysis, 'custom-gcc', sourcefile)
        self.assert_has_custom_field(analysis, 'gcc-invocation')
        self.assert_has_custom_field(analysis, 'stdout')
        self.assert_has_custom_field(analysis, 'stderr')

        # Also, look for custom data from my hacked-up gcc:
        if os.path.exists(sourcefile):
            self.assert_has_custom_field(analysis,
                                         'line_table->highest_location')
            self.assert_has_custom_field(analysis,
                                         'LINEMAPS_MACRO_LOWEST_LOCATION')

    def test_misleading_indentation(self):
        """
        Verify that we're exercising the new -Wmisleading-indentation code
        and capturing the results
        """
        analysis = self.invoke('test-sources/goto-fail.c')
        self.assertEqual(len(analysis.results), 1)
        r0 = analysis.results[0]
        self.assertIsInstance(r0, Issue)
        self.assertEqual(r0.testid, 'misleading-indentation')
        self.assertEqual(r0.location.file.givenpath,
                         'test-sources/goto-fail.c')
        self.assertEqual(r0.location.function.name, 'test')
        self.assertEqual(r0.location.point.line, 14)
        self.assertEqual(r0.message.text,
                         'statement is indented as if it were guarded by...')
        # Ideally the other information would have been captured within
        # the message.
        # For now, verify that we have it in the stderr:
        self.assertIn("note: ...this 'if' clause, but it is not",
                      analysis.customfields['stderr'])

class CppcheckTests(ToolTests):
    def make_tool(self, ctxt):
        return InvokeCppcheck(ctxt)

    def verify_basic_metadata(self, analysis, sourcefile):
        # Verify basic metadata:
        self.assert_metadata(analysis, 'cppcheck', sourcefile)
        self.assert_has_custom_field(analysis, 'cppcheck-invocation')
        self.assert_has_custom_field(analysis, 'stdout')
        self.assert_has_custom_field(analysis, 'stderr')

    def test_file_not_found(self):
        analysis = self.invoke('does-not-exist.c')
        #print(analysis)
        self.assertEqual(len(analysis.results), 1)
        self.assertIsInstance(analysis.results[0], Failure)
        self.assertEqual(analysis.results[0].failureid, 'bad-exit-code')

    def test_timeout(self):
        sourcefile = 'test-sources/harmless.c'
        se, driver = self.make_driver()
        se.timeout = 0
        gccinv = GccInvocation(['gcc', sourcefile])
        analysis = driver.invoke_tool(se, gccinv, sourcefile)
        self.assert_metadata(analysis, 'cppcheck', sourcefile)
        self.assertEqual(len(analysis.results), 1)
        r0 = analysis.results[0]
        self.assertIsInstance(r0, Failure)
        self.assertEqual(r0.failureid, 'timeout')
        self.assert_has_custom_field(analysis, 'timeout')
        self.assert_has_custom_field(analysis, 'command-line')

    def test_harmless_file(self):
        analysis = self.invoke('test-sources/harmless.c')
        #print(analysis)
        self.assertEqual(len(analysis.results), 0)

    def test_read_through_null(self):
        analysis = self.invoke('test-sources/read-through-null.c')
        self.assertEqual(len(analysis.results), 1)
        r0 = analysis.results[0]
        self.assertIsInstance(r0, Issue)
        self.assertEqual(r0.testid, 'nullPointer')
        self.assertEqual(r0.location.file.givenpath,
                         'test-sources/read-through-null.c')
        self.assertEqual(r0.location.point.line, 3)
        self.assertEqual(r0.message.text,
                         "Null pointer dereference")
        self.assertEqual(r0.severity, 'error')

    def test_out_of_bounds(self):
        analysis = self.invoke('test-sources/out-of-bounds.c')
        #print(analysis)
        self.assertEqual(len(analysis.results), 2)

        r0 = analysis.results[0]
        self.assertIsInstance(r0, Issue)
        self.assertEqual(r0.testid, 'arrayIndexOutOfBounds')
        self.assertEqual(r0.location.file.givenpath,
                         'test-sources/out-of-bounds.c')
        self.assertEqual(r0.location.point.line, 5)
        self.assertEqual(
            r0.message.text,
            "Array 'arr[10]' accessed at index 15, which is out of bounds.")
        self.assertEqual(r0.severity, 'error')

        r1 = analysis.results[1]
        self.assertIsInstance(r1, Issue)
        self.assertEqual(r1.testid, 'uninitvar')
        # etc

class ClangAnalyzerTests(ToolTests):
    def make_tool(self, ctxt):
        return InvokeClangAnalyzer(ctxt)

    def verify_basic_metadata(self, analysis, sourcefile):
        # Verify basic metadata:
        self.assert_metadata(analysis, 'clang-analyzer', sourcefile)
        self.assert_has_custom_field(analysis, 'scan-build-invocation')
        self.assert_has_custom_field(analysis, 'stdout')
        self.assert_has_custom_field(analysis, 'stderr')

    def test_file_not_found(self):
        analysis = self.invoke('does-not-exist.c')
        #print(analysis)
        self.assertEqual(len(analysis.results), 1)
        self.assertIsInstance(analysis.results[0], Failure)
        self.assertEqual(analysis.results[0].failureid, 'bad-exit-code')

    def test_timeout(self):
        sourcefile = 'test-sources/harmless.c'
        se, driver = self.make_driver()
        se.timeout = 0
        gccinv = GccInvocation(['gcc', sourcefile])
        analysis = driver.invoke_tool(se, gccinv, sourcefile)
        self.assert_metadata(analysis, 'clang-analyzer', sourcefile)
        self.assertEqual(len(analysis.results), 1)
        r0 = analysis.results[0]
        self.assertIsInstance(r0, Failure)
        self.assertEqual(r0.failureid, 'timeout')
        self.assert_has_custom_field(analysis, 'timeout')
        self.assert_has_custom_field(analysis, 'command-line')

    def test_harmless_file(self):
        analysis = self.invoke('test-sources/harmless.c')
        #print(analysis)
        self.assertEqual(len(analysis.results), 0)

    def test_read_through_null(self):
        analysis = self.invoke('test-sources/read-through-null.c')
        #print(analysis)
        self.assertEqual(len(analysis.results), 1)
        r0 = analysis.results[0]
        self.assertIsInstance(r0, Issue)
        self.assertEqual(r0.testid, None)
        self.assertEqual(r0.location.file.givenpath,
                         'test-sources/read-through-null.c')
        self.assertEqual(r0.location.point.line, 3)
        self.assertEqual(r0.message.text,
                         "Dereference of null pointer")
        self.assertEqual(r0.severity, None)
        self.assertIsInstance(r0.trace, Trace)

    def test_out_of_bounds(self):
        analysis = self.invoke('test-sources/out-of-bounds.c')
        #print(analysis)
        self.assertEqual(len(analysis.results), 1)

        r0 = analysis.results[0]
        self.assertIsInstance(r0, Issue)
        self.assertEqual(r0.testid, None)
        self.assertEqual(r0.location.file.givenpath,
                         'test-sources/out-of-bounds.c')
        self.assertEqual(r0.location.point.line, 5)
        self.assertEqual(r0.message.text,
                         "Undefined or garbage value returned to caller")
        self.assertEqual(r0.severity, None)
        self.assertIsInstance(r0.trace, Trace)

class CpycheckerTests(ToolTests):
    def make_tool(self, ctxt):
        return InvokeCpychecker(ctxt)

    def verify_basic_metadata(self, analysis, sourcefile):
        # Verify basic metadata:
        self.assert_metadata(analysis, 'cpychecker', sourcefile)
        self.assert_has_custom_field(analysis, 'cpychecker-invocation')
        self.assert_has_custom_field(analysis, 'stdout')
        self.assert_has_custom_field(analysis, 'stderr')

    def test_file_not_found(self):
        analysis = self.invoke('does-not-exist.c')
        #print(analysis)
        self.assertEqual(len(analysis.results), 1)
        self.assertIsInstance(analysis.results[0], Failure)
        self.assertEqual(analysis.results[0].failureid, 'no-output-found')

    def test_timeout(self):
        sourcefile = 'test-sources/harmless.c'
        se, driver = self.make_driver()
        se.timeout = 0
        gccinv = GccInvocation(['gcc', sourcefile])
        analysis = driver.invoke_tool(se, gccinv, sourcefile)
        self.assert_metadata(analysis, 'cpychecker', sourcefile)
        self.assertEqual(len(analysis.results), 1)
        r0 = analysis.results[0]
        self.assertIsInstance(r0, Failure)
        self.assertEqual(r0.failureid, 'timeout')
        self.assert_has_custom_field(analysis, 'timeout')
        self.assert_has_custom_field(analysis, 'command-line')

    def test_harmless_file(self):
        analysis = self.invoke('test-sources/harmless.c')
        #print(analysis)
        self.assertEqual(len(analysis.results), 0)

    def test_read_through_null(self):
        analysis = self.invoke('test-sources/read-through-null.c')
        #print(analysis)
        # cpychecker doesn't detect this
        self.assertEqual(len(analysis.results), 0)

    def test_out_of_bounds(self):
        analysis = self.invoke('test-sources/out-of-bounds.c')
        #print(analysis)
        # cpychecker doesn't detect this
        self.assertEqual(len(analysis.results), 0)

    def test_cpychecker_demo(self):
        analysis = self.invoke('test-sources/cpychecker-demo.c',
                               extraargs=['-I/usr/include/python2.7'])
        #print(analysis)
        self.assertEqual(len(analysis.results), 7)

        r0 = analysis.results[0]
        self.assertIsInstance(r0, Issue)
        self.assertEqual(r0.testid, 'mismatching-type-in-format-string')
        self.assertEqual(r0.location.file.givenpath,
                         'test-sources/cpychecker-demo.c')
        self.assertEqual(
            r0.message.text,
            ('Mismatching type in call to PyArg_ParseTuple'
             ' with format code "i:htons"'))
        self.assertEqual(r0.severity, None)
        self.assertEqual(r0.trace, None)
        self.assertEqual(r0.customfields['function'], 'PyArg_ParseTuple')
        self.assertEqual(r0.customfields['format-code'], 'i')
        self.assertEqual(r0.customfields['full-format-string'], 'i:htons')
        # etc

class DriverTests(unittest.TestCase):
    """
    Driver tests, verifying that XML analysis files are written as a
    side-effect, and that stdout/stderr/returncode are as expected.
    """
    def make_driver(self):
        ctxt = Context(enable_logging=0)

        # Capture stdout and stderr:
        ctxt.stdout = StringIO.StringIO()
        ctxt.stderr = StringIO.StringIO()

        outputdir=tempfile.mkdtemp()
        ctxt.log(outputdir)
        driver = Driver(ctxt,
                        outputdir=outputdir)
        return driver

    def invoke(self, sourcefile, extraargs=None):
        driver = self.make_driver()
        args = ['gcc', '-c', sourcefile]
        if extraargs:
            args += extraargs
        r = driver.invoke(args)

        if sourcefile and os.path.exists(sourcefile):
            with open(sourcefile) as f:
                content = f.read()
            expected_hexdigest = hashlib.sha1(content).hexdigest()
        else:
            expected_hexdigest = None

        # Verify that it wrote out "firehose" XML files to 'outputdir':
        analyses = []
        for xmlpath in glob.glob(os.path.join(driver.outputdir, '*.xml')):
            with open(xmlpath) as f:
                analysis = Analysis.from_xml(f)
            if 0:
                print(analysis)
            if expected_hexdigest:
                self.assertEqual(analysis.metadata.file_.hash_.alg, 'sha1')
                self.assertEqual(analysis.metadata.file_.hash_.hexdigest,
                                 expected_hexdigest)
            analyses.append(analysis)
            os.unlink(xmlpath)
        self.assertEqual(len(analyses), 4)

        os.rmdir(driver.outputdir)

        return driver

    def test_file_not_found(self):
        driver = self.invoke('does-not-exist.c')
        self.assertEqual(driver.ctxt.stdout.getvalue(), '')
        self.assertEqual(
            driver.ctxt.stderr.getvalue(),
            ('gcc: error: does-not-exist.c: No such file or directory\n'
             'gcc: fatal error: no input files\n'
             'compilation terminated.\n'))
        self.assertEqual(driver.returncode, 4)

    def test_nonharmless_file(self):
        driver = self.invoke('test-sources/harmless.c')
        self.assertEqual(driver.ctxt.stdout.getvalue(), '')
        self.assertEqual(driver.ctxt.stderr.getvalue(), '')
        self.assertEqual(driver.returncode, 0)

    def test_divide_by_zero(self):
        driver = self.invoke('test-sources/divide-by-zero.c', ['-Werror'])
        self.assertEqual(driver.ctxt.stdout.getvalue(), '')
        self.assertEqual(
            driver.ctxt.stderr.getvalue(),
            ("test-sources/divide-by-zero.c: In function 'divide_by_zero':\n"
             "test-sources/divide-by-zero.c:3:12: error: division by zero"
             " [-Werror=div-by-zero]\n"
             "   return i / 0;\n"
             "            ^\n"
             "cc1: all warnings being treated as errors\n"))
        self.assertEqual(driver.returncode, 1)

    def test_no_source_files(self):
        driver = self.make_driver()
        r = driver.invoke(['gcc'])
        self.assertEqual(driver.ctxt.stdout.getvalue(), '')
        self.assertEqual(driver.ctxt.stderr.getvalue(),
                         ('gcc: fatal error: no input files\n'
                          'compilation terminated.\n'))
        self.assertEqual(driver.returncode, 4)

    def test_get_version(self):
        driver = self.make_driver()
        r = driver.invoke(['gcc', '--version'])
        self.assertIn(' (GCC) ', driver.ctxt.stdout.getvalue())
        self.assertEqual(driver.ctxt.stderr.getvalue(), '')
        self.assertEqual(driver.returncode, 0)

    def test_multiple_source_files(self):
        """
        Verify invocations that cover multiple source files, linking
        to an executable.
        """
        driver = self.make_driver()
        args = ['gcc',
                'test-sources/multiple-1.c',
                'test-sources/multiple-2.c',
                '-o', 'multiple.exe']
        r = driver.invoke(args)
        self.assertEqual(driver.ctxt.stderr.getvalue(), '')
        self.assertEqual(driver.returncode, 0)

        # Verify that it wrote out "firehose" XML files to 'outputdir':
        analyses = []
        for xmlpath in glob.glob(os.path.join(driver.outputdir, '*.xml')):
            with open(xmlpath) as f:
                analysis = Analysis.from_xml(f)
            analyses.append(analysis)
            # Verify that none of the side-effects failed (e.g. with
            # linker errors):
            self.assertEqual(analysis.customfields['returncode'], 0)
            os.unlink(xmlpath)
        self.assertEqual(len(analyses), 8)

        # We should have a ./multiple.exe that we can run
        self.assertTrue(os.path.exists('./multiple.exe'))
        os.unlink('./multiple.exe')

        os.rmdir(driver.outputdir)

############################################################################
# Entrypoint
############################################################################

def main(argv):
    # If we're invoked with "unittest" as the first param,
    # run the unit test suite:
    if len(argv) >= 2:
        if argv[1] == 'unittest':
            sys.argv = [argv[0]] + argv[2:]
            return unittest.main()

    # Otherwise, pretend to be gcc
    ctxt = Context(enable_logging=True)
    try:
        real_driver = get_real_executable(argv)
        driver = Driver(ctxt,
                        capture_exceptions=True,
                        real_driver=real_driver)
        if 1:
            CUSTOM_GCC='/opt/custom-gcc/bin/gcc'
            EXTRA_ARGS=['-B/opt/custom-gcc']
            custom_gcc = InvokeCustomGcc(CUSTOM_GCC,
                                         ctxt,
                                         EXTRA_ARGS)
            driver.side_effects.append(custom_gcc)
            driver.invoke(argv)
            return driver.returncode
    except Exception, exc:
        tb_str = traceback.format_exc()
        for line in tb_str.splitlines():
            ctxt.log(line)

if __name__ == '__main__':
    sys.exit(main(sys.argv))
