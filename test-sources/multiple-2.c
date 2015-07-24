#include <stdio.h>

int helper (int argc, const char **argv)
{
  int i;
  for (i = 0; i < argc; i++)
    printf ("argv[%i]: %s\n", i, argv[i]);
  return 0;
}
