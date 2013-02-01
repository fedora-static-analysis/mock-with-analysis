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
	cd ../firehose && python setup.py bdist_rpm

# https://github.com/fedora-static-analysis/gccinvocation
gccinvocation_rpm:
	cd ../gccinvocation && make unittests && python setup.py bdist_rpm

# need the firehose branch:
# http://git.fedorahosted.org/cgit/gcc-python-plugin.git/log/?h=firehose
gcc-python-plugin_rpm:
	cd ../gcc-python/cpychecker-firehose-output && make VERSION=0.11.firehose tarball rpm

html:
	PYTHONPATH=../firehose \
	python reports/make-simple-report.py \
	  saved-results/policycoreutils-2.1.13-27.2.fc17.src.rpm-001
