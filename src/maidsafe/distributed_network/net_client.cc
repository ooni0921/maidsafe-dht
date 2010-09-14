/* Copyright (c) 2010 maidsafe.net limited
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

#include "maidsafe/base/utils.h"
#include "maidsafe/distributed_network/mysqlppwrap.h"

namespace net_client {

void RunSmallTest() {
  MySqlppWrap msw;
  msw.Init("kademlia_network_test", "127.0.0.1", "root", "m41ds4f3",
           "kademliavalues");

  int n = msw.Delete("", "");
  printf("Deleted %d previous entries.\n", n);

  std::vector<std::string> values;
  n = msw.Get("", &values);
  if (n != 0 || !values.empty()) {
    printf("Failed in Get #1: %d\n", n);
    return;
  }

  std::string k("key1");
  for (int a = 0; a < 10; ++a) {
    std::string v("value_" + base::IntToString(a));
    n = msw.Insert(k, v);
    if (n != 0) {
      printf("Failed inserting #1 value %d\n", a);
      return;
    }
  }

  n = msw.Get("", &values);
  if (n != 0 || values.size() != size_t(10)) {
    printf("Failed in Get #2\n");
    return;
  }

  n = msw.Get("key1", &values);
  if (n != 0 || values.size() != size_t(10)) {
    printf("Failed in Get #3\n");
    return;
  }

  k = "key2";
  for (int a = 0; a < 5; ++a) {
    std::string v("value_" + base::IntToString(a));
    n = msw.Insert(k, v);
    if (n != 0) {
      printf("Failed inserting #2 value %d\n", a);
      return;
    }
  }

  n = msw.Get("", &values);
  if (n != 0 || values.size() != size_t(15)) {
    printf("Failed in Get #4\n");
    return;
  }

  n = msw.Get("key2", &values);
  if (n != 0 || values.size() != size_t(5)) {
    printf("Failed in Get #5\n");
    return;
  }

  n = msw.Delete("key1", "");
  if (n != 10) {
    printf("Failed in Delete #2\n");
    return;
  }

  n = msw.Get("", &values);
  if (n != 0 || values.size() != size_t(5)) {
    printf("Failed in Get #4\n");
    return;
  }

  n = msw.Get("key2", &values);
  if (n != 0 || values.size() != size_t(5)) {
    printf("Failed in Get #5\n");
    return;
  }

  n = msw.Update("key2", "value_0", "value_5");
  if (n != 0) {
    printf("Failed in Update #1\n");
    return;
  }

  n = msw.Get("key2", &values);
  if (n != 0 || values.size() != size_t(5)) {
    printf("Failed in Get #5\n");
    return;
  }

  std::set<std::string> s(values.begin(), values.end());
  values = std::vector<std::string>(s.begin(), s.end());
  for (size_t y = 0; y < values.size(); ++y) {
    if (values[y] != std::string("value_" + base::IntToString(y+1))) {
      printf("Checking update #1 at value %d\n", y);
      return;
    }
  }

  n = msw.Delete("key2", "value_1");
  if (n != 1) {
    printf("Failed in Delete #3\n");
    return;
  }

  n = msw.Get("key2", &values);
  if (n != 0 || values.size() != size_t(4)) {
    printf("Failed in Get #6\n");
    return;
  }

  s = std::set<std::string>(values.begin(), values.end());
  values = std::vector<std::string>(s.begin(), s.end());
  for (size_t y = 0; y < values.size(); ++y) {
    if (values[y] != std::string("value_" + base::IntToString(y+2))) {
      printf("Checking delete #3 at value %d\n", y);
      return;
    }
  }
}

}  // namespace net_client

int main() {
  net_client::RunSmallTest();
  return 0;
}

