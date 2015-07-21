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
import os
import StringIO
import sys
import tempfile
import time
import logging

# http://pypi.python.org/pypi/subprocess32
# so that we can use timeouts
from subprocess32 import Popen, PIPE, STDOUT, TimeoutExpired

from firehose.model import Analysis, Generator, Metadata, Failure, \
    Location, File, Message

from gccinvocation import GccInvocation

def init_log():
    logging.basicConfig(format='%(asctime)s %(message)s',
                        datefmt='%H:%M:%S',
                        level=logging.INFO,
                        filename='/builddir/fakegcc.log')

def log(msg):
    logging.info(msg)

def write_analysis_as_xml(analysis, dstxmlpath=None):
    # Ensure we have absolute paths (within the chroot) and SHA-1 hashes
    # of all files referred to in the report:
    analysis.fixup_files(os.getcwd(), 'sha1')

    xmlstr = analysis.to_xml_bytes()

    # Dump the XML to stdout, so it's visible in the logs:
    log('resulting XML: %s\n' % xmlstr)

    if dstxmlpath is None:
        # Use the SHA-1 hash of the report to create a unique filename
        # and dump it in an absolute location in the chroot:
        hexdigest = hashlib.sha1(xmlstr).hexdigest()
        dstxmlpath = '/builddir/%s.xml' % hexdigest

    with open(dstxmlpath, 'w') as f:
        f.write(xmlstr)

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

def write_streams(toolname, out, err):
    for line in out.splitlines():
        log('stdout from %r: %s\n' % (toolname, line))
    for line in err.splitlines():
        log('stderr from %r: %s\n' % (toolname, line))

def make_failed_analysis(genname, sourcefile, t, msgtext, failureid):
    # Something went wrong; write a failure report:
    generator = Generator(name=genname,
                          version=None)
    metadata = Metadata(generator=generator,
                        sut=None,
                        file_ = make_file(sourcefile),
                        stats = make_stats(t))
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

def invoke_side_effects(argv):
    log("invoke_side_effects: %s"
        % ' '.join(sys.argv))

    gccinv = GccInvocation(argv)

    # Try to run each side effect in a subprocess, passing in a path
    # for the XML results to be written to.
    # Cover a multitude of possible failures by detecting if no output
    # was written, and capturing *that* as a failure
    for sourcefile in gccinv.sources:
        if sourcefile.endswith('.c'): # FIXME: other extensions?
            for script, genname in [('invoke-cppcheck', 'cppcheck'),
                                    ('invoke-clang-analyzer', 'clang-analyzer'),
                                    ('invoke-cpychecker', 'cpychecker'),

                                    # Uncomment the following to test a
                                    # checker that fails to write any XML:
                                    # ('echo', 'failing-checker'),

                                    ]:
                with tempfile.NamedTemporaryFile() as f:
                    dstxmlpath = f.name
                assert not os.path.exists(dstxmlpath)

                # Restrict the invocation to just one source file at a
                # time:
                singleinv = gccinv.restrict_to_one_source(sourcefile)
                singleargv = singleinv.argv

                TIMEOUT=60
                t = Timer()

                args = [script, dstxmlpath] + singleargv
                log('invoking args: %r' % args)
                p = Popen(args,
                          stdout=PIPE, stderr=PIPE)
                try:
                    out, err = p.communicate(timeout=TIMEOUT)
                    write_streams(script, out, err)

                    if os.path.exists(dstxmlpath):
                        with open(dstxmlpath) as f:
                            analysis = Analysis.from_xml(f)
                    else:
                        analysis = make_failed_analysis(genname, sourcefile, t,
                                                        msgtext=('Unable to locate XML output from %s'
                                                                 % script),
                                                        failureid='no-output-found')
                        analysis.set_custom_field('stdout', out)
                        analysis.set_custom_field('stderr', err)
                        analysis.set_custom_field('returncode', p.returncode)
                except TimeoutExpired:
                    analysis = make_failed_analysis(genname, sourcefile, t,
                                                    msgtext='Timeout running %s' % genname,
                                                    failureid='timeout')
                    analysis.set_custom_field('timeout', TIMEOUT)
                analysis.set_custom_field('gcc-invocation', ' '.join(argv))
                write_analysis_as_xml(analysis)

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

if __name__ == '__main__':
    init_log()
    try:
        invoke_side_effects(sys.argv)
        r = invoke_real_executable(sys.argv)
        sys.exit(r)
    except Exception, e:
        log(e)
        raise e
