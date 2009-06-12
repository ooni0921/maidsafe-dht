/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Test for base/calllatertimer.cc
* Version:      1.0
* Created:      2009-06-12-02.54.48
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#include <gtest/gtest.h>
#include <boost/scoped_ptr.hpp>
#include <boost/thread/thread.hpp>

#include "base/calllatertimer.h"

namespace base {

class Lynyrd {
 public:
  Lynyrd() : count_(0) /*, mutex_()*/ {}
  ~Lynyrd() { printf("Dtor\n"); }
  void Skynyrd() {
//    boost::mutex::scoped_lock guard(mutex_);
    ++count_;
    printf("*");
  }
  void Alabama() {
    Skynyrd();
  }
  int count() { return count_; }
 private:
  Lynyrd(const Lynyrd&);
  Lynyrd& operator=(const Lynyrd&);
  int count_;
//  boost::mutex mutex_;
};

class CallLaterTest : public testing::Test {
 protected:
  CallLaterTest() : clt_() {}
  virtual ~CallLaterTest() {}
  virtual void SetUp() {}
  virtual void TearDown() {}
  CallLaterTimer clt_;
 private:
  CallLaterTest(const CallLaterTest&);
  CallLaterTest& operator=(const CallLaterTest&);
};

TEST_F(CallLaterTest, BEH_BASE_AddCallLater) {
  // Most basic test - create object on stack and call a method later.
  ASSERT_TRUE(clt_.IsStarted());
  Lynyrd sweethome;
  clt_.AddCallLater(50, boost::bind(&Lynyrd::Skynyrd, &sweethome));
  EXPECT_EQ(0, sweethome.count());
  boost::this_thread::sleep(boost::posix_time::milliseconds(250));
  EXPECT_EQ(1, sweethome.count());
}

TEST_F(CallLaterTest, BEH_BASE_AddDestroyCallLater) {
  // Create object on stack, set up call later, then before called, destroy
  // object.
  ASSERT_TRUE(clt_.IsStarted());
  {
    Lynyrd sweethome;
    clt_.AddCallLater(20, boost::bind(&Lynyrd::Skynyrd, &sweethome));
  }
  boost::this_thread::sleep(boost::posix_time::milliseconds(250));
}

TEST_F(CallLaterTest, BEH_BASE_AddDestroyAgainCallLater) {
  // As above, except call a method which itself calls a method of the destroyed
  // object.
  ASSERT_TRUE(clt_.IsStarted());
  {
    Lynyrd sweethome;
    clt_.AddCallLater(20, boost::bind(&Lynyrd::Alabama, &sweethome));
  }
  boost::this_thread::sleep(boost::posix_time::milliseconds(250));
}

TEST_F(CallLaterTest, BEH_BASE_AddManyCallLaters) {
  // Set up 100 calls fairly closely spaced
  ASSERT_TRUE(clt_.IsStarted());
  Lynyrd sweethome;
  for (int i = 0; i < 100; ++i)
    clt_.AddCallLater(50 + (20*i), boost::bind(&Lynyrd::Skynyrd, &sweethome));
  EXPECT_EQ(0, sweethome.count());
  boost::this_thread::sleep(boost::posix_time::milliseconds(2500));
  EXPECT_EQ(100, sweethome.count());
  printf("\n");
  // Set up 100 calls very closely spaced
  for (int j = 0; j < 100; ++j)
    clt_.AddCallLater(50, boost::bind(&Lynyrd::Skynyrd, &sweethome));
  boost::this_thread::sleep(boost::posix_time::milliseconds(2500));
  EXPECT_EQ(200, sweethome.count());
}

TEST_F(CallLaterTest, BEH_BASE_AddRemoveCallLaters) {
  // Set up 100 calls and remove 50 of them before they start
  ASSERT_TRUE(clt_.IsStarted());
  Lynyrd sweethome;
  std::vector<int> call_ids;
  for (int i = 0; i < 100; ++i)
    call_ids.push_back(clt_.AddCallLater(250 + (20*i),
        boost::bind(&Lynyrd::Skynyrd, &sweethome)));
  EXPECT_EQ(0, sweethome.count());
  for (int j = 0; j < 50; ++j)
    EXPECT_TRUE(clt_.CancelOne(call_ids[j]));
  boost::this_thread::sleep(boost::posix_time::milliseconds(2450));
  EXPECT_EQ(50, sweethome.count());
  // Set up 100 calls again, then remove them all before they start
  for (int k = 0; k < 100; ++k)
    clt_.AddCallLater(250 + (20*k), boost::bind(&Lynyrd::Skynyrd, &sweethome));
  clt_.CancelAll();
  boost::this_thread::sleep(boost::posix_time::milliseconds(2450));
  EXPECT_EQ(50, sweethome.count());
  // Set up 100 calls again, then remove them all while they're being run.
  for (int l = 0; l < 100; ++l)
    clt_.AddCallLater(10*l, boost::bind(&Lynyrd::Skynyrd, &sweethome));
  boost::this_thread::sleep(boost::posix_time::milliseconds(50));
  clt_.CancelAll();
  boost::this_thread::sleep(boost::posix_time::milliseconds(2450));
}

TEST_F(CallLaterTest, BEH_BASE_AddPtrCallLater) {
  // Basic call later, but this time to method of object created on heap.
  ASSERT_TRUE(clt_.IsStarted());
  boost::scoped_ptr<Lynyrd> sweethome(new Lynyrd());
  clt_.AddCallLater(20, boost::bind(&Lynyrd::Skynyrd, sweethome.get()));
  EXPECT_EQ(0, sweethome->count());
  boost::this_thread::sleep(boost::posix_time::milliseconds(250));
  EXPECT_EQ(1, sweethome->count());
}

TEST_F(CallLaterTest, BEH_BASE_AddDestroyPtrCallLater) {
  // Create object on heap, set up call later, then before called, destroy
  // object.
  ASSERT_TRUE(clt_.IsStarted());
  {
    boost::scoped_ptr<Lynyrd> sweethome(new Lynyrd());
    clt_.AddCallLater(20, boost::bind(&Lynyrd::Skynyrd, sweethome.get()));
  }
  boost::this_thread::sleep(boost::posix_time::milliseconds(250));
}

TEST_F(CallLaterTest, BEH_BASE_AddDestroyAgainPtrCallLater) {
  // As above, except call a method which itself calls a method of the destroyed
  // object.
  ASSERT_TRUE(clt_.IsStarted());
  {
    boost::scoped_ptr<Lynyrd> sweethome(new Lynyrd());
    clt_.AddCallLater(20, boost::bind(&Lynyrd::Alabama, sweethome.get()));
  }
  boost::this_thread::sleep(boost::posix_time::milliseconds(250));
  Lynyrd sweethome1;
  clt_.AddCallLater(50, boost::bind(&Lynyrd::Skynyrd, &sweethome1));
  EXPECT_EQ(0, sweethome1.count());
  boost::this_thread::sleep(boost::posix_time::milliseconds(250));
  EXPECT_EQ(1, sweethome1.count());
}

}  // namespace base
