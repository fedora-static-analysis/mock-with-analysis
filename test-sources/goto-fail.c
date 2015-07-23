/* Based on CVE-2014-1266 aka "goto fail" */

extern int foo(int);

int test(int a, int b, int c)
{
	int err;

	/* ... */
	if ((err = foo(a)) != 0)
		goto fail;
	if ((err = foo(b)) != 0)
		goto fail;
		goto fail;
	if ((err = foo(c)) != 0)
		goto fail;
	/* ... */

fail:
	return err;
}
