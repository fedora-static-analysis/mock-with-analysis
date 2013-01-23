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

import hashlib
import os
import StringIO
from subprocess import Popen, PIPE, STDOUT
import sys
import tempfile

from gccinvocation import GccInvocation

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

    print('invoke_cppchecker for %s' % gccinv)

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
    print('invoke_clang_analyzer for %s' % gccinv)
    # TODO

def invoke_side_effects(argv):
    print("I would be invoking side effects for the command: %s"
          % ' '.join(sys.argv))

    gccinv = GccInvocation(argv)
    invoke_cppchecker(gccinv)
    invoke_clang_analyzer(gccinv)

def parse_gcc_stderr(stderr):
    from firehose.parsers.gcc import parse_file

    print('parse_gcc_stderr(%r)' % stderr)

    f = StringIO.StringIO(stderr)
    for report in parse_file(f, gccversion=None, sut=None):
        write_report_as_xml(report)

def invoke_real_executable(argv):
    apparentcmd = argv[0]
    dir_, basename = os.path.split(apparentcmd)
    args = [os.path.join(dir_,
                         'the-real-%s' % basename)]
    args += argv[1:]
    if 0:
        print(' '.join(args))
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
