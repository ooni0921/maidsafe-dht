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
#include <stdio.h>
#include "maidsafe/maidsafe-dht.h"
#include "base/config.h"
#include "base/cppsqlite3.h"

class CppSQLite3Test: public testing::Test {
 protected:
  CppSQLite3Test() {
  }
  virtual ~CppSQLite3Test() {
  }
  virtual void SetUp() {
  }
  virtual void TearDown() {
  }
};

TEST_F(CppSQLite3Test, BEH_BASE_CppSqliteErrors) {
  // SQLITE errors defined from 0 - 26
  for (int n = 0; n < 27; ++n) {
    std::string error(CppSQLite3Exception::errorCodeAsString(n));
    ASSERT_EQ("SQLITE", error.substr(0, 6)) << "Vuelta: " << n;
  }

  // SQLITE errors 100 and 101
  std::string error(CppSQLite3Exception::errorCodeAsString(100));
  ASSERT_EQ("SQLITE", error.substr(0, 6));
  error = std::string(CppSQLite3Exception::errorCodeAsString(101));
  ASSERT_EQ("SQLITE", error.substr(0, 6));

  // CPPSQLITE error 1000
  error = std::string(CppSQLite3Exception::errorCodeAsString(1000));
  ASSERT_EQ("CPPSQLITE_ERROR", error);

  // Random number to go over the defined messages
  boost::uint32_t i = (base::random_32bit_uinteger() % 1000) + 102;
  error = std::string(CppSQLite3Exception::errorCodeAsString(i));
  ASSERT_EQ("UNKNOWN_ERROR", error);
}

TEST_F(CppSQLite3Test, BEH_BASE_CppSqliteException) {
  std::string maidsafe_dht_error("MAIDSAFE-DHT_ERROR");
  int error_code((base::random_32bit_uinteger() % 2000) + 1001);
  CppSQLite3Exception csle(error_code,
                           const_cast<char*>(maidsafe_dht_error.c_str()),
                           false);
  ASSERT_EQ(error_code, csle.errorCode());
  std::string error(csle.errorMessage());
  std::string built_error(CppSQLite3Exception::errorCodeAsString(error_code));
  built_error += std::string("[") + base::itos(error_code) + std::string("]: ")
              +  maidsafe_dht_error;

  ASSERT_EQ(built_error, error);
}
