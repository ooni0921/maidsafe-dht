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
#include <boost/timer.hpp>
#include <boost/progress.hpp>
#include <cstdlib>
// #include <iostream>
#include "maidsafe/maidsafe-dht_config.h"
#include "maidsafe/utils.h"


namespace {

}  // namespace

TEST(UtilsTest, BEH_BASE_TidyPath) {
  const std::string dirty_path_ = "/dirty/dirty/boy";
  ASSERT_EQ("dirty/dirty/boy", base::TidyPath(dirty_path_)) <<
            "Failed to tidy path.";
  const std::string dirty_path_1 = "dirty/dirty/boy/";
  ASSERT_EQ("dirty/dirty/boy", base::TidyPath(dirty_path_1)) <<
            "Failed to tidy path.";
  const std::string dirty_path_2 = "/dirty/dirty/boy/";
  ASSERT_EQ("dirty/dirty/boy", base::TidyPath(dirty_path_2)) <<
            "Failed to tidy path.";
  const std::string dirty_path_3 = "dirty/dirty/boy";
  ASSERT_EQ("dirty/dirty/boy", base::TidyPath(dirty_path_3)) <<
            "Changed path which was already tidy.";
  const std::string dirty_path_4 = "\\dirty\\dirty\\boy";
  ASSERT_EQ("dirty\\dirty\\boy", base::TidyPath(dirty_path_4)) <<
            "Failed to tidy path.";
  const std::string dirty_path_5 = "dirty\\dirty\\boy\\";
  ASSERT_EQ("dirty\\dirty\\boy", base::TidyPath(dirty_path_5)) <<
            "Failed to tidy path.";
  const std::string dirty_path_6 = "\\dirty\\dirty\\boy\\";
  ASSERT_EQ("dirty\\dirty\\boy", base::TidyPath(dirty_path_6)) <<
            "Failed to tidy path.";
  const std::string dirty_path_7 = "dirty\\dirty\\boy";
  ASSERT_EQ("dirty\\dirty\\boy", base::TidyPath(dirty_path_7)) <<
            "Changed path which was already tidy.";
  const std::string dirty_path_8 = "/";
  ASSERT_EQ("/", base::TidyPath(dirty_path_8)) <<
            "Changed path which was already tidy.";
  const std::string dirty_path_9 = "\\";
  ASSERT_EQ("\\", base::TidyPath(dirty_path_9)) <<
            "Changed path which was already tidy.";
}

TEST(UtilsTest, BEH_BASE_IntegersAndStrings) {
  std::string p_str, n_str, l_str, ul_str, ull_str;

  int p = 1234567890;
  int n = -1234567890;
  boost::int32_t l = -2147483647;
  boost::uint32_t ul = 4294967295UL;
  // This next constant is not part of c++98, so I'm commenting it out
  // boost::uint64_t ull = 18446744073709551615ULL;

  p_str = "1234567890";
  n_str = "-1234567890";
  l_str = "2147483647";
  ul_str = "4294967295";
  // ull_str = "18446744073709551615";

  ASSERT_EQ(p, base::stoi(base::itos(p))) <<
            "int -> string -> int failed for positive int.";
  ASSERT_EQ(n, base::stoi(base::itos(n))) <<
            "int -> string -> int failed for negative int.";
  ASSERT_EQ(l, base::stoi_l(base::itos_l(l))) <<
            "int -> string -> int failed for negative int32_t.";
  ASSERT_EQ(ul, base::stoi_ul(base::itos_ul(ul))) <<
            "int -> string -> int failed for uint32_t.";

  ASSERT_EQ(p_str, base::itos(base::stoi(p_str))) <<
            "string -> int -> string failed for positive int.";
  ASSERT_EQ(n_str, base::itos(base::stoi(n_str))) <<
            "string -> int -> string failed for negative int.";
  ASSERT_EQ(l_str, base::itos_l(base::stoi_l(l_str))) <<
            "string -> int -> string failed for negative int32_t.";
  ASSERT_EQ(ul_str, base::itos_ul(base::stoi_ul(ul_str))) <<
            "string -> int -> string failed failed for uint32_t.";
}

TEST(UtilsTest, BEH_BASE_RandomString) {
  unsigned int length = 4096;
  std::string first = base::RandomString(length);
  std::string second = base::RandomString(length);
  ASSERT_EQ(length, first.length()) <<
            "Size of first string is not the requested size: " << length;
  ASSERT_EQ(length, second.length()) <<
            "Size of second string is not the requested size: " << length;
  ASSERT_NE(first, second) << "The two 'random' strings are the same.";
  for (int i = 0; i < static_cast<int>(length); i++) {
    ASSERT_GT(127, static_cast<int>(first[i]));
    ASSERT_GT(127, static_cast<int>(second[i]));
    // checking all characters are asci characters
    ASSERT_TRUE(((47 < static_cast<int>(first[i])) &&
                 (static_cast<int>(first[i] <  58))) ||
                ((64 < static_cast<int>(first[i])) &&
                 (static_cast<int>(first[i] < 91))) ||
                ((96 < static_cast<int>(first[i])) &&
                 (static_cast<int>(first[i]) < 123)));
    ASSERT_TRUE(((47 < static_cast<int>(second[i])) &&
                 (static_cast<int>(second[i] <  58))) ||
                ((64 < static_cast<int>(second[i])) &&
                 (static_cast<int>(second[i] < 91))) ||
                ((96 < static_cast<int>(second[i])) &&
                 (static_cast<int>(second[i]) < 123)));
  }
}

TEST(UtilsTest, BEH_BASE_HexEncodeDecode) {
  const std::string str("Hello world! And hello nurse!!");
  std::string encoded = base::EncodeToHex(str);
  ASSERT_EQ(str.size() * 2, encoded.size()) << "Encoding failed.";
  std::string decoded = base::DecodeFromHex(encoded);
  ASSERT_EQ(encoded.size(), decoded.size() * 2) << "Decoding failed.";
  ASSERT_EQ(str, decoded) << "encoded -> decoded failed.";
}

TEST(UtilsTest, BEH_BASE_BoostAndAscii) {
  std::string dotted("132.248.59.1");
  ASSERT_EQ(dotted, base::inet_btoa(base::inet_atob(dotted))) <<
            "ASCII -> Boost IPv4 -> ASCII failed.";
}

TEST(UtilsTest, BEH_BASE_TimeFunctions) {
  boost::uint64_t s, ms, ns;
  ms = base::get_epoch_milliseconds();
  ns = base::get_epoch_nanoseconds();
  s = base::get_epoch_time();

  // Within a second
  ASSERT_NEAR(s*1000, ms, 1000) << "s vs. ms failed.";
  // Within a second
  ASSERT_NEAR(s*1000000000, ns, 1000000000) << "s vs. ns failed.";
  // Within quarter of a second
  ASSERT_NEAR(ms*1000000, ns, 250000000) << "ms vs. ns failed.";
}

TEST(UtilsTest, BEH_BASE_NextTransactionId) {
  boost::uint32_t id1 = base::generate_next_transaction_id(0);
  boost::uint32_t id2 = base::generate_next_transaction_id(0);

  ASSERT_NE(static_cast<boost::uint32_t>(0), id1) <<
            "Transaction id1 came back as 0.";
  ASSERT_NE(static_cast<boost::uint32_t>(0), id2) <<
            "Transaction id2 came back as 0.";
  ASSERT_NE(id1, id2) << "Transaction id1 and id2 came back the same.";

  id1 = 2147483646;
  id2 = base::generate_next_transaction_id(id1);
  ASSERT_EQ(static_cast<boost::uint32_t>(1), id2) <<
            "Transaction id2 came back different from 1: " << id2;
}

TEST(UtilsTest, BEH_BASE_DecimalAndAscii) {
  std::string dotted("121.12.121.1");
  char *ipbuf = new char[32];
  boost::uint32_t n = base::inet_aton(dotted.c_str());
  boost::uint32_t g = 2030860545;
  ASSERT_EQ(g, n) << "Conversion to decimal failed.";
  base::inet_ntoa(n, ipbuf);
  std::string reformed(ipbuf);
  ASSERT_EQ(dotted, reformed) << "Conversion to ASCII failed.";
  delete []ipbuf;
}

TEST(UtilsTest, BEH_BASE_NetworkInterfaces) {
  std::vector<base::device_struct> alldevices;
  base::get_net_interfaces(&alldevices);
  ASSERT_NE(static_cast<boost::uint32_t>(0), alldevices.size());
  for (unsigned int n = 0; n < alldevices.size(); n++) {
    base::device_struct ds = alldevices[n];
    printf("%s\n", ds.interface_.c_str());
  }
}

TEST(UtilsTest, BEH_BASE_NameValidation) {
  std::string back_slash("hola\\mundo");
  std::string forward_slash("hola/mundo");
  std::string colon("hola:mundo");
  std::string asterisc("hola*mundo");
  std::string question_mark("hola?mundo");
  std::string double_quotes("hola\"mundo");
  std::string less_than("hola<mundo");
  std::string greater_than("hola>mundo");
  std::string pipe("hola|mundo");

  std::string control("hola mundo");

  ASSERT_TRUE(base::ValidateName(control)) << "Error with the control string";

  ASSERT_FALSE(base::ValidateName(back_slash)) << "Error with back slashes";
  ASSERT_FALSE(base::ValidateName(forward_slash)) <<
               "Error with forward slashes";
  ASSERT_FALSE(base::ValidateName(colon)) << "Error with back colons";
  ASSERT_FALSE(base::ValidateName(asterisc)) << "Error with back asteriscs";
  ASSERT_FALSE(base::ValidateName(question_mark)) <<
               "Error with question marks";
  ASSERT_FALSE(base::ValidateName(double_quotes)) << "Error with double quotes";
  ASSERT_FALSE(base::ValidateName(less_than)) << "Error with less thans";
  ASSERT_FALSE(base::ValidateName(greater_than)) << "Error with greater thans";
  ASSERT_FALSE(base::ValidateName(pipe)) << "Error with back pipes";
}

TEST(UtilsTest, BEH_BASE_RandomNumberGen) {
  int i = 1;
  while (i < 10) {
    boost::uint32_t urandnum1 = base::random_32bit_uinteger();
    boost::uint32_t urandnum2 = base::random_32bit_uinteger();
    ASSERT_NE(urandnum1, urandnum2);
    ASSERT_NE(urandnum1, boost::uint32_t(0));
    ASSERT_NE(urandnum2, boost::uint32_t(0));
    ++i;
  }
  int j = 1;
  while (j < 10) {
    int randnum1 = base::random_32bit_integer();
    int randnum2 = base::random_32bit_integer();
    ASSERT_NE(randnum1, randnum2);
    ASSERT_NE(randnum1, 0);
    ASSERT_NE(randnum2, 0);
    ++j;
  }
}

TEST(UtilsTest, BEH_BASE_TestStrToLwr) {
  std::string all_upper("HELLO WORLD");
  std::string result = base::StrToLwr(all_upper);
  ASSERT_EQ("hello world", result);
  std::string some_upper("Hello WoRlD");
  result = base::StrToLwr(all_upper);
  ASSERT_EQ("hello world", result);
}
