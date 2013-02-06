TEST_SRPM=python-ethtool-0.7-4.fc19.src.rpm

run-mock-with-analysis: local_rpms
	PYTHONPATH=../firehose \
	./mock-with-analysis \
	  fedora-17-x86_64 \
	  $(TEST_SRPM)

run-mock-without-analysis:
	mock \
	  -r fedora-17-x86_64 \
	  $(TEST_SRPM)

# Currently mock-with-analysis assumes you have rebuilt rpms
# of the newer dependencies (which are under heavy development)
# These should be checked out in sister directories:
local_rpms: firehose_rpm gccinvocation_rpm # gcc-python-plugin_rpm

# https://github.com/fedora-static-analysis/firehose
firehose_rpm:
	cd ../firehose && rm -rf build && python setup.py bdist_rpm

# https://github.com/fedora-static-analysis/gccinvocation
gccinvocation_rpm:
	cd ../gccinvocation && make unittests && rm -rf build && python setup.py bdist_rpm

# need the firehose branch:
# http://git.fedorahosted.org/cgit/gcc-python-plugin.git/log/?h=firehose
gcc-python-plugin_rpm:
	cd ../gcc-python/cpychecker-firehose-output && rm $(HOME)/rpmbuild/SOURCES/gcc-python-plugin-0.11.firehose.tar.gz && make VERSION=0.11.firehose tarball rpm

# firehose-saved-data:
#   https://github.com/fedora-static-analysis/firehose-saved-data
html:
	PYTHONPATH=../firehose \
	python reports/make-simple-report.py \
	  ../firehose-saved-data/python-ethtool/0.7/4.fc19/x86_64/003

html-comparison:
	PYTHONPATH=../firehose \
	python reports/make-comparative-report.py \
	  ../firehose-saved-data/python-ethtool/0.7/4.fc19/x86_64/003 \
	  ../firehose-saved-data/python-ethtool/0.8/0.dc309d6b2781dc3810021d2e4e2d669f40227b63.fc17/x86_64/002
