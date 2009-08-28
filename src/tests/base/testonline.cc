/* Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <gtest/gtest.h>
#include "base/calllatertimer.h"
#include "maidsafe/maidsafe-dht_config.h"
#include "maidsafe/online.h"

TEST(OnlineControllerTest, BEH_SingletonAddress) {
  base::OnlineController *olc1 = base::OnlineController::instance();
  base::OnlineController *olc2 = base::OnlineController::instance();
  ASSERT_EQ(olc1, olc2);
  olc1 = olc2 = NULL;
}

TEST(OnlineControllerTest, BEH_SetGetOnline) {
  base::OnlineController *olc1 = base::OnlineController::instance();
  base::OnlineController *olc2 = base::OnlineController::instance();
  ASSERT_EQ(olc1, olc2);
  ASSERT_FALSE(olc1->Online());
  ASSERT_FALSE(olc2->Online());

  olc1->SetOnline(true);
  ASSERT_TRUE(olc1->Online());
  ASSERT_TRUE(olc2->Online());

  olc2->SetOnline(false);
  ASSERT_FALSE(olc1->Online());
  ASSERT_FALSE(olc2->Online());

  olc2->SetOnline(true);
  ASSERT_TRUE(olc1->Online());
  ASSERT_TRUE(olc2->Online());

  olc2->SetOnline(false);
  ASSERT_FALSE(olc1->Online());
  ASSERT_FALSE(olc2->Online());

  olc1 = olc2 = NULL;
}

TEST(OnlineControllerTest, BEH_ThreadedSetGetOnline) {
  base::OnlineController *olc1 = base::OnlineController::instance();
  base::OnlineController *olc2 = base::OnlineController::instance();
  ASSERT_EQ(olc1, olc2);
  ASSERT_FALSE(olc1->Online());
  ASSERT_FALSE(olc2->Online());

  base::CallLaterTimer clt_;
  ASSERT_TRUE(clt_.IsStarted());
  clt_.CancelAll();
  clt_.AddCallLater(500, boost::bind(&base::OnlineController::SetOnline,
                    olc1, true));

  while (!olc2->Online())
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));

  ASSERT_TRUE(olc1->Online());
  ASSERT_TRUE(olc2->Online());

  clt_.AddCallLater(500, boost::bind(&base::OnlineController::SetOnline,
                    olc2, false));

  while (olc1->Online())
    boost::this_thread::sleep(boost::posix_time::milliseconds(100));

  ASSERT_FALSE(olc1->Online());
  ASSERT_FALSE(olc2->Online());

  olc1 = olc2 = NULL;
}
