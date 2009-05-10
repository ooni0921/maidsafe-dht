#include <fstream>
#include <iostream>
#include <stdio.h>
#include <gtest/gtest.h>
#include "base/config.h"

TEST(FindPlatform, BEH_BASE_DetectPlatform) {
  int macflag(0);
  int posixflag(0);
  int winflag(0);

  #if defined (MAIDSAFE_APPLE)
    ++macflag;
  #elif defined (MAIDSAFE_POSIX)
    ++posixflag;
  #elif defined (MAIDSAFE_WIN32)
    ++winflag;
  #endif

  ASSERT_EQ(1, macflag + posixflag + winflag);

  printf("We have cunningly detected your platform as being ");
  if(macflag)
    printf("APPLE.\n");
  if(posixflag)
    printf("POSIX.\n");
  if(winflag)
    printf("WIN32.\n");
}

