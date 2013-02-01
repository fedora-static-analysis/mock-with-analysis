#!/usr/bin/env python
#   Copyright 2012, 2013 David Malcolm <dmalcolm@redhat.com>
#   Copyright 2012, 2013 Red Hat, Inc.
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

import glob
import hashlib
import os
import StringIO
from subprocess import Popen, PIPE, STDOUT
import sys
import tempfile
import time

from gccinvocation import GccInvocation

def log(msg):
    sys.stdout.write('FAKE-GCC: %s\n' % msg)

def write_analysis_as_xml(analysis):
    # Ensure we have absolute paths (within the chroot) and SHA-1 hashes
    # of all files referred to in the report:
    analysis.fixup_files(os.getcwd(), 'sha1')

    xmlstr = analysis.to_xml_str()

    # Dump the XML to stdout, so it's visible in the logs:
    log('resulting XML: %s\n' % xmlstr)

    # Use the SHA-1 hash of the report to create a unique filename
    # and dump it in an absolute location in the chroot:
    hexdigest = hashlib.sha1(xmlstr).hexdigest()
    filename = '/builddir/%s.xml' % hexdigest
    with open(filename, 'w') as f:
        f.write(xmlstr)

def make_file(givenpath):
    from firehose.report import File
    return File(givenpath=givenpath,
                abspath=None,
                hash_=None)

def make_stats(timer):
    from firehose.report import Stats
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

def write_streams(toolname, out, err):
    for line in out.splitlines():
        sys.stdout.write('FAKE-GCC: stdout from %r: %s\n' % (toolname, line))
    for line in err.splitlines():
        sys.stderr.write('FAKE-GCC: stderr from %r: %s\n' % (toolname, line))

def invoke_cppcheck(gccinv):
    from firehose.parsers.cppcheck import parse_file

    log('invoke_cppcheck for %s' % gccinv)

    for sourcefile in gccinv.sources:
        if sourcefile.endswith('.c'): # FIXME: other extensions?
            # Invoke cppcheck, capturing output in its XML format
            t = Timer()
            p = Popen(['cppcheck',
                       '--xml', '--xml-version=2',
                       sourcefile],
                      stdout=PIPE, stderr=PIPE)
            out, err = p.communicate()
            write_streams('cppcheck', out, err)

            # (there doesn't seem to be a way to have cppcheck directly
            # save its XML output to a given location)

            with tempfile.NamedTemporaryFile() as outfile:
                outfile.write(err)
                outfile.flush()

                with open(outfile.name) as infile:
                    # Parse stderr into firehose XML format and save:
                    analysis = parse_file(infile,
                                          file_=make_file(sourcefile),
                                          stats=make_stats(t))
                    write_analysis_as_xml(analysis)

def invoke_clang_analyzer(gccinv):
    from firehose.parsers.clanganalyzer import parse_plist

    log('invoke_clang_analyzer for %s' % gccinv)

    for sourcefile in gccinv.sources:
        if sourcefile.endswith('.c'): # FIXME: other extensions?
            t = Timer()
            resultdir = tempfile.mkdtemp()
            args = ['scan-build', '-v', '-plist',
                    '-o', resultdir,
                    get_real_executable(gccinv.argv)] + gccinv.argv[1:]
            log(args)
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            out, err = p.communicate()
            write_streams('scan-build (clang_analyzer)', out, err)

            # Given e.g. resultdir='/tmp/tmpQW2l2B', the plist files
            # are an extra level deep e.g.:
            #  '/tmp/tmpQW2l2B/2013-01-22-1/report-MlwJri.plist'
            for plistpath in glob.glob(os.path.join(resultdir,
                                                    '*/*.plist')):
                analysis = parse_plist(plistpath,
                                       file_=make_file(sourcefile),
                                       stats=make_stats(t))
                write_analysis_as_xml(analysis)

def invoke_cpychecker(gccinv):
    from firehose.report import Analysis

    log('invoke_cpychecker for %s' % gccinv)
    for sourcefile in gccinv.sources:
        if sourcefile.endswith('.c'): # FIXME: other extensions?
            # invoke the plugin, but for robustness, do it in an entirely separate gcc invocation
            # strip away -o; add -S or -c?
            # or set -o to a dummy location?
            # latter seems more robust
            #gccinv = gccinv.restrict_source(sourcefile)

            assert len(gccinv.sources) == 1 # for now

            argv = gccinv.argv[:]

            outputxmlpath = '%s.firehose.xml' % sourcefile

            # We would use the regular keyword argument syntax:
            #   outputxmlpath='foo'
            # but unfortunately gcc's option parser seems to not be able to cope with '='
            # within an option's value.  So we do it using dictionary syntax instead:
            pycmd = ('from libcpychecker import main, Options; '
                     'main(Options(**{"outputxmlpath":"%s", '
                     '"verify_refcounting": True}))' % outputxmlpath)
            argv += ['-fplugin=python2',
                     '-fplugin-arg-python2-command=%s' % pycmd]

            args = [get_real_executable(argv)] + argv[1:]
            if 1:
                log(' '.join(args))
            p = Popen(args, stderr=PIPE)
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            try:
                t = Timer()
                out, err = p.communicate()
                write_streams('cpychecker', out, err)
            except KeyboardInterrupt:
                pass

            with open(outputxmlpath) as f:
                analysis = Analysis.from_xml(f)
            analysis.metadata.file_ = make_file(sourcefile)
            analysis.metadata.stats = make_stats(t)
            write_analysis_as_xml(analysis)

def invoke_side_effects(argv):
    log("invoke_side_effects: %s"
        % ' '.join(sys.argv))

    gccinv = GccInvocation(argv)
    invoke_cppcheck(gccinv)
    invoke_clang_analyzer(gccinv)
    invoke_cpychecker(gccinv)

def parse_gcc_stderr(stderr, stats):
    from firehose.parsers.gcc import parse_file

    log('parse_gcc_stderr(stderr=%r)' % stderr)

    f = StringIO.StringIO(stderr)
    analysis = parse_file(f, stats=stats)
    write_analysis_as_xml(analysis)

def get_real_executable(argv):
    apparentcmd = argv[0]
    dir_, basename = os.path.split(apparentcmd)
    return os.path.join(dir_, 'the-real-%s' % basename)

def invoke_real_executable(argv):
    args = [get_real_executable(argv)] + argv[1:]
    if 0:
        log(' '.join(args))
    p = Popen(args, stderr=PIPE)
    try:
        t = Timer()
        out, err = p.communicate()
        sys.stderr.write(err)
        parse_gcc_stderr(err,
                         stats=make_stats(t))
    except KeyboardInterrupt:
        pass
    return p.returncode


invoke_side_effects(sys.argv)
r = invoke_real_executable(sys.argv)
sys.exit(r)
