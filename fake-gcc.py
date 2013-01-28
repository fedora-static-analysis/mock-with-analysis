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

from gccinvocation import GccInvocation

def log(msg):
    sys.stdout.write('FAKE-GCC: %s\n' % msg)

def write_report_as_xml(report):
    # Ensure we have absolute paths (within the chroot) and SHA-1 hashes
    # of all files referred to in the report:
    report.fixup_files(os.getcwd(), 'sha1')

    xmlstr = report.to_xml_str()

    # Dump the XML to stdout, so it's visible in the logs:
    sys.stdout.write(xmlstr)

    # Use the SHA-1 hash of the report to create a unique filename
    # and dump it in an absolute location in the chroot:
    hexdigest = hashlib.sha1(xmlstr).hexdigest()
    filename = '/builddir/%s.xml' % hexdigest
    with open(filename, 'w') as f:
        f.write(xmlstr)

def invoke_cppchecker(gccinv):
    from firehose.parsers.cppcheck import parse_file

    log('invoke_cppchecker for %s' % gccinv)

    for sourcefile in gccinv.sources:
        if sourcefile.endswith('.c'): # FIXME: other extensions?
            # Invoke cppcheck, capturing output in its XML format
            p = Popen(['cppcheck',
                       '--xml', '--xml-version=2',
                       sourcefile],
                      stderr=PIPE)
            out, err = p.communicate()
            sys.stdout.write(err)

            # (there doesn't seem to be a way to have cppcheck directly
            # save its XML output to a given location)

            with tempfile.NamedTemporaryFile() as outfile:
                outfile.write(err)
                outfile.flush()

                with open(outfile.name) as infile:
                    # Parse stderr into firehose XML format and save:
                    for report in parse_file(infile, sut=None):
                        write_report_as_xml(report)

def invoke_clang_analyzer(gccinv):
    from firehose.parsers.clanganalyzer import parse_plist

    log('invoke_clang_analyzer for %s' % gccinv)

    for sourcefile in gccinv.sources:
        if sourcefile.endswith('.c'): # FIXME: other extensions?
            resultdir = tempfile.mkdtemp()
            args = ['scan-build', '-v', '-plist',
                    '-o', resultdir,
                    get_real_executable(gccinv.argv)] + gccinv.argv[1:]
            log(args)
            p = Popen(args)
            out, err = p.communicate()

            # Given e.g. resultdir='/tmp/tmpQW2l2B', the plist files
            # are an extra level deep e.g.:
            #  '/tmp/tmpQW2l2B/2013-01-22-1/report-MlwJri.plist'
            for plistpath in glob.glob(os.path.join(resultdir,
                                                    '*/*.plist')):
                for report in parse_plist(plistpath,
                                          analyzerversion=None,
                                          sut=None):
                    write_report_as_xml(report)

def invoke_side_effects(argv):
    log("invoke_side_effects: %s"
        % ' '.join(sys.argv))

    gccinv = GccInvocation(argv)
    invoke_cppchecker(gccinv)
    invoke_clang_analyzer(gccinv)

def parse_gcc_stderr(stderr):
    from firehose.parsers.gcc import parse_file

    log('parse_gcc_stderr(%r)' % stderr)

    f = StringIO.StringIO(stderr)
    for report in parse_file(f, gccversion=None, sut=None):
        write_report_as_xml(report)

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
        out, err = p.communicate()
        sys.stderr.write(err)
        parse_gcc_stderr(err)
    except KeyboardInterrupt:
        pass
    return p.returncode


invoke_side_effects(sys.argv)
r = invoke_real_executable(sys.argv)
sys.exit(r)
