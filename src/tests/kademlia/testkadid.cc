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
#include "kademlia/kadid.h"
#include "base/utils.h"


std::string increasehex(char hex_char) {
  std::string res;
  switch (hex_char) {
    case '0' : res = "1"; break;
    case '1' : res = "2"; break;
    case '2' : res = "3"; break;
    case '3' : res = "4"; break;
    case '4' : res = "5"; break;
    case '5' : res = "6"; break;
    case '6' : res = "7"; break;
    case '7' : res = "8"; break;
    case '8' : res = "9"; break;
    case '9' : res = "a"; break;
    case 'a' : res = "b"; break;
    case 'b' : res = "c"; break;
    case 'c' : res = "d"; break;
    case 'd' : res = "e"; break;
    case 'e' : res = "f"; break;
    case 'f' : res = "ff"; break;
    default: res = "0";
  }
  return res;
};

TEST(TestKadId, BEH_KAD_ToBinary) {
  std::string id1, id2, binid1, binid2;
  for (kad::id_size_type i = 0; i < kad::bitToByteCount(kad::ID_BITS_SIZE) * 2;
       ++i) {
    id1 += "f";
    binid1 += "1111";
    if (i % 2 == 0) {
      id2 += "a";
      binid2 += "1010";
    } else {
      id2 += "2";
      binid2 += "0010";
    }
  }
  kad::KadId kadid1(id1, true), kadid2(id2, true);
  ASSERT_EQ(binid1, kadid1.ToStringBinary());
  ASSERT_EQ(binid2, kadid2.ToStringBinary());
}

TEST(TestKadId, BEH_KAD_ToHexEncoded_Decoded) {
  std::string id1;
  for (kad::id_size_type i = 0; i < kad::bitToByteCount(kad::ID_BITS_SIZE) * 2;
       ++i) {
    if (i % 2 == 0) {
      id1 += "a";
    } else {
      id1 += "2";
    }
  }
  kad::KadId kadid1(id1, true), kadid2;
  ASSERT_EQ(id1, kadid1.ToStringEncoded());
  std::string id1_dec(base::DecodeFromHex(id1));
  ASSERT_EQ(id1_dec, kadid1.ToStringDecoded());
  std::vector<unsigned char> raw_id2 = kadid2.raw_id();
  std::string id2_dec(raw_id2.begin(), raw_id2.end());
  ASSERT_EQ(id2_dec, kadid2.ToStringDecoded());
  std::string id2_enc = base::EncodeToHex(id2_dec);
  ASSERT_EQ(id2_enc, kadid2.ToStringEncoded());
}

TEST(TestKadId, BEH_KAD_OperatorEqual) {
  kad::KadId kadid1(kad::RANDOM_ID);
  std::string id(kadid1.ToStringDecoded());
  kad::KadId kadid2(id, false);
  ASSERT_TRUE(kadid1 == kadid2) << "kadid1 = " << kadid1.ToStringBinary() <<
    std::endl << "kadid2 = " << kadid2.ToStringBinary() << std::endl;
  std::string id1;
  for (kad::id_size_type i = 0; i < kad::bitToByteCount(kad::ID_BITS_SIZE) * 2;
       ++i) {
    id1 += "f";
  }
  kad::KadId kadid3(id1, true);
  ASSERT_FALSE(kadid1 == kadid3) << "kadid1 = " << kadid1.ToStringBinary() <<
    std::endl << "kadid3 = " << kadid3.ToStringBinary() << std::endl;
}

TEST(TestKadId, BEH_KAD_OperatorDifferent) {
  kad::KadId kadid1(kad::RANDOM_ID);
  std::string id(kadid1.ToStringDecoded());
  kad::KadId kadid2(id, false);
  ASSERT_FALSE(kadid1 != kadid2) << "kadid1 = " << kadid1.ToStringBinary() <<
    std::endl << "kadid2 = " << kadid2.ToStringBinary() << std::endl;
  std::string id1;
  for (kad::id_size_type i = 0; i < kad::bitToByteCount(kad::ID_BITS_SIZE) * 2;
       ++i) {
    id1 += "f";
  }
  kad::KadId kadid3(id1, true);
  ASSERT_TRUE(kadid1 != kadid3) << "kadid1 = " << kadid1.ToStringBinary() <<
    std::endl << "kadid3 = " << kadid3.ToStringBinary() << std::endl;
}

TEST(TestKadId, BEH_KAD_OperatorGreaterThan) {
  kad::KadId kadid1(kad::RANDOM_ID);
  std::string id(kadid1.ToStringEncoded());
  kad::KadId kadid2(id, true);
  ASSERT_FALSE(kadid1 > kadid2) << "kadid1 = " << kadid1.ToStringBinary() <<
    std::endl << "kadid2 = " << kadid2.ToStringBinary() << std::endl;
  char first = id[0];
  std::string rep(increasehex(first));
  if (first == 'f') {
    id.replace(0, 2, rep);
  } else {
    id.replace(0, 1, rep);
  }
  kad::KadId kadid3(id, true);
  ASSERT_TRUE(kadid3 > kadid1) << "kadid3 = " << kadid3.ToStringBinary() <<
    std::endl << "kadid1 = " << kadid1.ToStringBinary() << std::endl;
  ASSERT_FALSE(kadid1 > kadid3) << "kadid1 = " << kadid1.ToStringBinary() <<
    std::endl << "kadid3 = " << kadid3.ToStringBinary() << std::endl;
}

TEST(TestKadId, BEH_KAD_OperatorLessThan) {
  kad::KadId kadid1(kad::RANDOM_ID);
  std::string id(kadid1.ToStringEncoded());
  kad::KadId kadid2(id, true);
  ASSERT_FALSE(kadid1 < kadid2) << "kadid1 = " << kadid1.ToStringBinary() <<
    std::endl << "kadid2 = " << kadid2.ToStringBinary() << std::endl;
  char first = id[0];
  std::string rep = increasehex(first);
  if (first == 'f') {
    id.replace(0, 2, rep);
  } else {
    id.replace(0, 1, rep);
  }
  kad::KadId kadid3(id, true);
  ASSERT_TRUE(kadid1 < kadid3) << "kadid1 = " << kadid1.ToStringBinary() <<
    std::endl << "kadid3 = " << kadid3.ToStringBinary() << std::endl;
  ASSERT_FALSE(kadid3 < kadid1) << "kadid3 = " << kadid3.ToStringBinary() <<
    std::endl << "kadid1 = " << kadid1.ToStringBinary() << std::endl;
}

TEST(TestKadId, BEH_KAD_OperatorGreaterEqual) {
  kad::KadId kadid1(kad::RANDOM_ID);
  std::string id(kadid1.ToStringEncoded());
  kad::KadId kadid2(id, true);
  ASSERT_TRUE(kadid1 >= kadid2) << "kadid1 = " << kadid1.ToStringBinary() <<
    std::endl << "kadid2 = " << kadid2.ToStringBinary() << std::endl;
  char first = id[0];
  std::string rep(increasehex(first));
  if (first == 'f') {
    id.replace(0, 2, rep);
  } else {
    id.replace(0, 1, rep);
  }
  kad::KadId kadid3(id, true);
  ASSERT_TRUE(kadid3 >= kadid1) << "kadid3 = " << kadid3.ToStringBinary() <<
    std::endl << "kadid1 = " << kadid1.ToStringBinary() << std::endl;
}

TEST(TestKadId, BEH_KAD_OperatorLessEqual) {
  kad::KadId kadid1(kad::RANDOM_ID);
  std::string id(kadid1.ToStringEncoded());
  kad::KadId kadid2(id, true);
  ASSERT_TRUE(kadid1 <= kadid2) << "kadid1 = " << kadid1.ToStringBinary() <<
    std::endl << "kadid2 = " << kadid2.ToStringBinary() << std::endl;
  char first = id[0];
  std::string rep(increasehex(first));
  if (first == 'f') {
    id.replace(0, 2, rep);
  } else {
    id.replace(0, 1, rep);
  }
  kad::KadId kadid3(id, true);
  ASSERT_TRUE(kadid1 <= kadid3) << "kadid1 = " << kadid1.ToStringBinary() <<
    std::endl << "kadid3 = " << kadid3.ToStringBinary() << std::endl;
}

TEST(TestKadId, BEH_KAD_OperatorXOR) {
  kad::KadId kadid1(kad::RANDOM_ID), kadid2(kad::RANDOM_ID);
  kad::KadId kadid3(kadid1 ^ kadid2);
  std::string binid1(kadid1.ToStringBinary());
  std::string binid2(kadid2.ToStringBinary());
  std::string binresult;
  for (size_t i = 0; i < binid1.size(); ++i) {
    if (binid1[i] == binid2[i]) {
      binresult += "0";
    } else {
      binresult += "1";
    }
  }
  std::string binzero;
  for (size_t i = 0; i < binid1.size(); ++i)
    binzero += "0";
  ASSERT_NE(binzero, kadid3.ToStringBinary());
  ASSERT_EQ(binresult, kadid3.ToStringBinary());
  kad::KadId kadid4(kadid2 ^ kadid1);
  ASSERT_EQ(binresult, kadid4.ToStringBinary());
  kad::KadId kadid5(kadid1.ToStringDecoded(), false);
  kad::KadId kadid6(kadid1 ^ kadid5);
  ASSERT_EQ(binzero, kadid6.ToStringBinary());
  kad::id_container zero(kadid6.raw_id());
  ASSERT_EQ(kad::bitToByteCount(kad::ID_BITS_SIZE), zero.size());
  for (kad::id_size_type i = 0; i < zero.size(); ++i)
    ASSERT_EQ('\0', zero[i]);
}

TEST(TestKadId, BEH_KAD_CtrPower) {
  try {
    kad::KadId kadid(-2);
  } catch(const kad::KadIdException &e) {
    ASSERT_EQ(kad::OUT_OF_RANGE, e.err_no());
    printf("exception: %s  %d\n", e.what(), e.err_no());
  }
  try {
    kad::KadId kadid(kad::ID_BITS_SIZE + 1);
  } catch(const kad::KadIdException &e) {
    ASSERT_EQ(kad::OUT_OF_RANGE, e.err_no());
    printf("exception: %s\n", e.what());
  }
  try {
    kad::KadId kadid = kad::KadId::MaxIdUpToPower(kad::ID_BITS_SIZE + 1);
  } catch(const kad::KadIdException &e) {
    ASSERT_EQ(kad::OUT_OF_RANGE, e.err_no());
    printf("exception: %s\n", e.what());
  }
  try {
    kad::KadId kadid = kad::KadId::MaxIdUpToPower(-2);
  } catch(const kad::KadIdException &e) {
    ASSERT_EQ(kad::OUT_OF_RANGE, e.err_no());
    printf("exception: %s\n", e.what());
  }
  std::string bin_id(kad::ID_BITS_SIZE, '0');
  for (boost::int16_t i = 0; i < kad::ID_BITS_SIZE; ++i) {
    kad::KadId kadid(i);
    bin_id[kad::ID_BITS_SIZE - 1 - i] = '1';
    ASSERT_EQ(bin_id, kadid.ToStringBinary()) << "Fail to construct 2^" << i
      << std::endl;
    bin_id[kad::ID_BITS_SIZE - 1 - i] = '0';
  }
  for (boost::int16_t i = 0; i < kad::ID_BITS_SIZE; ++i) {
    kad::KadId kadid = kad::KadId::MaxIdUpToPower(i);
    for (boost::int16_t j = kad::ID_BITS_SIZE - i; j < kad::ID_BITS_SIZE; ++j) {
      bin_id[j] = '1';
    }
    ASSERT_EQ(bin_id, kadid.ToStringBinary()) << "Fail to construct 2^" << i
      << "-1" << std::endl;
    for (boost::int16_t j = kad::ID_BITS_SIZE - i; j < kad::ID_BITS_SIZE; ++j) {
      bin_id[j] = '0';
    }
  }
}

TEST(TestKadId, BEH_KAD_CtrBetweenPowersExceptions) {
  try {
    kad::KadId kadid(-2, 10);
  } catch(const kad::KadIdException &e) {
    ASSERT_EQ(kad::OUT_OF_RANGE, e.err_no());
    printf("exception: %s\n", e.what());
  }
  try {
    kad::KadId kadid(0, kad::ID_BITS_SIZE + 1);
  } catch(const kad::KadIdException &e) {
    ASSERT_EQ(kad::OUT_OF_RANGE, e.err_no());
    printf("exception: %s\n", e.what());
  }
  try {
    kad::KadId kadid(-2, kad::ID_BITS_SIZE + 1);
  } catch(const kad::KadIdException &e) {
    ASSERT_EQ(kad::OUT_OF_RANGE, e.err_no());
    printf("exception: %s\n", e.what());
  }
  try {
    kad::KadId kadid(100, 50);
  } catch(const kad::KadIdException &e) {
    ASSERT_EQ(kad::LLIMIT_GT_ULIMIT, e.err_no());
    printf("exception: %s\n", e.what());
  }
}

TEST(TestKadId, BEH_KAD_CtrBetweenPowersRandom) {
  std::string bin_id1(kad::ID_BITS_SIZE, '0');
  std::string bin_id2(kad::ID_BITS_SIZE, '0');
  boost::int16_t lpower = (base::RandomInt32() % kad::ID_BITS_SIZE);
  bin_id1[kad::ID_BITS_SIZE - 1 - lpower] = '1';
  for (boost::int16_t i = lpower + 1; i <= kad::ID_BITS_SIZE; ++i) {
    kad::KadId id(lpower, i);
    if (i < kad::ID_BITS_SIZE) {
      bin_id2[kad::ID_BITS_SIZE - 1 - i] = '1';
      ASSERT_EQ('0', id.ToStringBinary()[kad::ID_BITS_SIZE - 1 - i]) <<
        "id bigger than 2^" << i << std::endl << bin_id2 << std::endl <<
        "value" << std::endl << id.ToStringBinary() << std::endl;
      bin_id2[kad::ID_BITS_SIZE - 1 - i] = '0';
    }
    bool higher_bit_bigger = false;
    for (boost::int16_t j = 0; j <= kad::ID_BITS_SIZE - 1 - lpower &&
                               !higher_bit_bigger; ++j)
      if ('1' == id.ToStringBinary()[j])
        higher_bit_bigger = true;
    ASSERT_TRUE(higher_bit_bigger) << "id smaller than 2^" << lpower <<
      std::endl << bin_id1 << std::endl << "value" << std::endl <<
      id.ToStringBinary() << std::endl;
    bin_id1[kad::ID_BITS_SIZE - 1 - lpower] = '0';
  }
}

TEST(TestKadId, BEH_KAD_CtrBewtweenConsecutivePowers) {
  std::string bin_id1(kad::ID_BITS_SIZE, '0');
  std::string bin_id2(kad::ID_BITS_SIZE, '0');
  for (boost::int16_t i = 0; i < kad::ID_BITS_SIZE; ++i) {
    boost::int16_t j = i+1;
    kad::KadId id(i, j);
    if (j < kad::ID_BITS_SIZE) {
      bin_id2[kad::ID_BITS_SIZE - 1 - j] = '1';
      ASSERT_EQ('0', id.ToStringBinary()[kad::ID_BITS_SIZE - 1 - j]) <<
        "id bigger than 2^" << j << std::endl << bin_id2 << std::endl <<
        "value" << std::endl << id.ToStringBinary() << std::endl;
      bin_id2[kad::ID_BITS_SIZE - 1 - j] = '0';
    }
    bin_id1[kad::ID_BITS_SIZE - 1 - i] = '1';
    bool higher_bit_bigger = false;
    for (int k = 0; k <= kad::ID_BITS_SIZE - 1 - i &&
                             !higher_bit_bigger; ++k)
      if ('1' == id.ToStringBinary()[k])
        higher_bit_bigger = true;
    ASSERT_TRUE(higher_bit_bigger) << "id smaller than 2^" << i <<
      std::endl << bin_id1 << std::endl << "value" << std::endl <<
      id.ToStringBinary() << std::endl << id.ToStringEncoded();
    bin_id1[kad::ID_BITS_SIZE - 1 - i] = '0';
  }
}

TEST(TestKadId, BEH_KAD_CtrFromStringExceptions) {
  try {
    kad::KadId kadid("abcde", true);
  } catch(const kad::KadIdException &e) {
    ASSERT_EQ(kad::INVALID_STRING, e.err_no());
    printf("exception: %s\n", e.what());
  }
  try {
    kad::KadId kadid("013abc", false);
  } catch(const kad::KadIdException &e) {
    ASSERT_EQ(kad::INVALID_STRING, e.err_no());
    printf("exception: %s\n", e.what());
  }
}

TEST(TestKadId, BEH_KAD_CopyCtr) {
  kad::KadId kadid1(kad::RANDOM_ID);
  kad::KadId kadid2(kadid1);
  ASSERT_TRUE(kadid1 == kadid2);
  for (kad::id_size_type i = 0; i < kadid1.raw_id().size(); ++i)
    ASSERT_EQ(kadid1.raw_id()[i], kadid2.raw_id()[i]);
  ASSERT_EQ(kadid1.ToStringBinary(), kadid2.ToStringBinary());
  ASSERT_EQ(kadid1.ToStringEncoded(), kadid2.ToStringEncoded());
  ASSERT_EQ(kadid1.ToStringDecoded(), kadid2.ToStringDecoded());
}

TEST(TestKadId, BEH_KAD_DefaultCtr) {
  kad::KadId kadid;
  for (kad::id_size_type i = 0; i < kadid.raw_id().size(); ++i)
    ASSERT_EQ('\0', kadid.raw_id()[i]);
  std::string id(kad::bitToByteCount(kad::ID_BITS_SIZE) * 2, '0');
  ASSERT_EQ(id, kadid.ToStringEncoded());
  std::string bin_id;
  for (boost::int16_t i = 0; i < kad::ID_BITS_SIZE; ++i) {
    bin_id += "0";
  }
  ASSERT_EQ(bin_id, kadid.ToStringBinary());
}

TEST(TestKadId, BEH_KAD_OperatorEql) {
  kad::KadId kadid1(kad::RANDOM_ID), kadid2;
  kadid2 = kadid1;
  ASSERT_TRUE(kadid1 == kadid2);
  for (kad::id_size_type i = 0; i < kadid1.raw_id().size(); ++i)
    ASSERT_EQ(kadid1.raw_id()[i], kadid2.raw_id()[i]);
  ASSERT_EQ(kadid1.ToStringBinary(), kadid2.ToStringBinary());
  ASSERT_EQ(kadid1.ToStringEncoded(), kadid2.ToStringEncoded());
  ASSERT_EQ(kadid1.ToStringDecoded(), kadid2.ToStringDecoded());
}

TEST(TestKadId, BEH_KAD_GenerateMaxId) {
  kad::KadId kadid(kad::MAX_ID);
  for (kad::id_size_type i = 0; i < kadid.raw_id().size(); ++i)
    ASSERT_EQ(0xff, kadid.raw_id()[i]);
  std::string id(kad::bitToByteCount(kad::ID_BITS_SIZE) * 2, 'f');
  ASSERT_EQ(id, kadid.ToStringEncoded());
  std::string bin_id;
  for (boost::int16_t i = 0; i < kad::ID_BITS_SIZE; ++i) {
    bin_id += "1";
  }
  ASSERT_EQ(bin_id, kadid.ToStringBinary());
}

TEST(TestKadId, BEH_KAD_SplitRange) {
  kad::KadId min, max1, min1, max(kad::MAX_ID);
  kad::KadId::SplitRange(min, max, &max1, &min1);
  std::string exp_min(kad::ID_BITS_SIZE, '0');
  exp_min[0] = '1';
  std::string exp_max(kad::ID_BITS_SIZE, '1');
  exp_max[0] = '0';
  EXPECT_EQ(exp_min, min1.ToStringBinary());
  EXPECT_EQ(exp_max, max1.ToStringBinary());

  kad::KadId min2, max2;
  exp_min[0] = '0';
  exp_min[1] = '1';
  exp_max[1] = '0';
  kad::KadId::SplitRange(min, max1, &max2, &min2);
  EXPECT_EQ(exp_min, min2.ToStringBinary());
  EXPECT_EQ(exp_max, max2.ToStringBinary());

  kad::KadId min3, max3;
  exp_min[0] = '1';
  exp_max[0] = '1';
  kad::KadId::SplitRange(min1, max, &max3, &min3);
  EXPECT_EQ(exp_min, min3.ToStringBinary());
  EXPECT_EQ(exp_max, max3.ToStringBinary());

  kad::KadId min4, max4;
  exp_min[1] = '0';
  exp_min[2] = '1';
  exp_max[1] = '0';
  exp_max[2] = '0';
  kad::KadId::SplitRange(min1, max3, &max4, &min4);
  EXPECT_EQ(exp_min, min4.ToStringBinary());
  EXPECT_EQ(exp_max, max4.ToStringBinary());

  kad::KadId min5, max5;
  exp_min[0] = '0';
  exp_max[0] = '0';
  kad::KadId::SplitRange(min, max2, &max5, &min5);
  EXPECT_EQ(exp_min, min5.ToStringBinary());
  EXPECT_EQ(exp_max, max5.ToStringBinary());

  kad::KadId min6, max6;
  exp_min[2] = '0';
  exp_min[3] = '1';
  exp_max[3] = '0';
  kad::KadId::SplitRange(min, max5, &max6, &min6);
  EXPECT_EQ(exp_min, min6.ToStringBinary());
  EXPECT_EQ(exp_max, max6.ToStringBinary());
}

TEST(TestKadId, BEH_KAD_CtrBetweenIdsOK) {
  kad::KadId id1(kad::RANDOM_ID), id2(kad::RANDOM_ID);
  if (id1 < id2) {
    kad::KadId id(id1, id2);
    ASSERT_TRUE(id >= id1);
    ASSERT_TRUE(id <= id2);
  } else {
    kad::KadId id(id2, id1);
    ASSERT_TRUE(id >= id2);
    ASSERT_TRUE(id <= id1);
  }
  kad::KadId maxid(kad::MAX_ID);
  kad::KadId resid1(id1, maxid);
  ASSERT_TRUE(resid1 >= id1);
  ASSERT_TRUE(resid1 <= maxid);

  kad::KadId id3(0, 50), id4(70, 200);
  kad::KadId resid2(id3, id4);
  ASSERT_TRUE(resid2 >= id3);
  ASSERT_TRUE(resid2 <= id4);
}

TEST(TestKadId, BEH_KAD_CtrBetweenIdsExceptions) {
  kad::KadId id1(kad::RANDOM_ID), id2(kad::RANDOM_ID);
  if (id1 < id2) {
    try {
      kad::KadId kadid(id2, id1);
    } catch(const kad::KadIdException &e) {
      ASSERT_EQ(kad::INVALID_RANGE, e.err_no());
      printf("exception: %s\n", e.what());
    }
  } else {
    try {
      kad::KadId kadid(id1, id2);
    } catch(const kad::KadIdException &e) {
      ASSERT_EQ(kad::INVALID_RANGE, e.err_no());
      printf("exception: %s\n", e.what());
    }
  }
}
