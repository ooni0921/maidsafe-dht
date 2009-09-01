#include <gtest/gtest.h>
#include "maidsafe/config.h"
int main(int argc, char **argv) {
  // Initialising logging
  google::InitGoogleLogging(argv[0]);
  // setting output to be stderr
#ifndef HAVE_GLOG
  bool FLAGS_logtostderr;
#endif
  FLAGS_logtostderr = true;
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
