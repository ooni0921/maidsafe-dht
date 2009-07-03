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

#include <boost/cstdint.hpp>
#include <boost/filesystem.hpp>
#include <gtest/gtest.h>
#include <string>
#include <vector>
#include "base/crypto.h"
#include "kademlia/datastore.h"
#include "maidsafe/maidsafe-dht.h"

class DataStoreTest: public testing::Test {
 protected:
  DataStoreTest() : test_ds_(), cry_obj_(), db_name_("") {
    cry_obj_.set_symm_algorithm("AES_256");
    cry_obj_.set_hash_algorithm("SHA512");
  }

  virtual ~DataStoreTest() {
  }

  virtual void SetUp() {
    db_name_ = std::string("testdatastore") + boost::lexical_cast<std::string>(
                base::random_32bit_uinteger()) + std::string(".db");
    test_ds_ = new kad::DataStore();
    boost::filesystem::path db_file(db_name_);
    ASSERT_TRUE(test_ds_->Init(db_file.string()));
  }

  virtual void TearDown() {
    test_ds_->Close();
    delete test_ds_;
    try {
      boost::filesystem::remove(boost::filesystem::path(db_name_));
    } catch(std::exception &) {
      printf("Couldn't remove database.\n");
    }
  }
  kad::DataStore *test_ds_;
  crypto::Crypto cry_obj_;
  std::string db_name_;
  DataStoreTest(const DataStoreTest&);
  DataStoreTest &operator=(const DataStoreTest&);
};

TEST_F(DataStoreTest, FUNC_KAD_StoreValidData) {
  std::vector<std::string> keys;
  ASSERT_TRUE(test_ds_->Keys(&keys));
  ASSERT_EQ(0, static_cast<int>(keys.size()));
  std::string key1 = cry_obj_.Hash("abc123vvd32sfdf", "", crypto::STRING_STRING,
      false);
  std::string key2 = cry_obj_.Hash("ccccxxxfff212121", "",
      crypto::STRING_STRING, false);
  std::string value1 = cry_obj_.Hash("vfdsfdasfdasfdsaferrfd", "",
      crypto::STRING_STRING, false);
  std::string value2 = base::RandomString(5 * 1024 * 1024);  // big value 5MB
  boost::int32_t now = base::get_epoch_time();
  ASSERT_TRUE(test_ds_->StoreItem(key1, value1, now, now));
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2, now, now));
  ASSERT_TRUE(test_ds_->Keys(&keys));
  ASSERT_EQ(2, static_cast<int>(keys.size()));
  int key_num = 0;
  for (int i = 0; i < static_cast<int>(keys.size()); i++) {
    if (keys[i] == key1)
      key_num++;
    else if (keys[i] == key2)
      key_num++;
  }
  ASSERT_EQ(2, key_num);
}

TEST_F(DataStoreTest, BEH_KAD_StoreInvalidData) {
  boost::int32_t now = base::get_epoch_time();
  // invalid key
  std::string value1 = cry_obj_.Hash("bb33", "",
      crypto::STRING_STRING, false);
  ASSERT_FALSE(test_ds_->StoreItem("", value1, now, now));
  // invalid value
  std::string key1 = cry_obj_.Hash("xxe22", "", crypto::STRING_STRING,
        false);
  ASSERT_FALSE(test_ds_->StoreItem(key1, "", now, now));
  // invalid key&value
  ASSERT_FALSE(test_ds_->StoreItem("", "", now, now));
}

TEST_F(DataStoreTest, FUNC_KAD_LoadExistingData) {
  // one value under a key
  std::string key1 = cry_obj_.Hash("nssfsreeedxx", "", crypto::STRING_STRING,
      false);
  std::string value1 = cry_obj_.Hash("oybbggjhhtytyerterter", "",
      crypto::STRING_STRING, false);
  boost::int32_t now = base::get_epoch_time();
  ASSERT_TRUE(test_ds_->StoreItem(key1, value1, now, now));
  std::vector<std::string> values;
  ASSERT_TRUE(test_ds_->LoadItem(key1, values));
  ASSERT_EQ(1, static_cast<int>(values.size()));
  ASSERT_EQ(value1, values[0]);
  // multiple values under a key
  std::string key2 = cry_obj_.Hash("erraaaaa4334223", "", crypto::STRING_STRING,
      false);
  std::string value2_1 = base::RandomString(3*1024*1024);  // big value
  std::string value2_2 = base::RandomString(5);  // small value
  std::string value2_3 = cry_obj_.Hash("vvvx12xxxzzzz3322", "",
      crypto::STRING_STRING, false);
  now = base::get_epoch_time();
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2_1, now, now));
  now = base::get_epoch_time();
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2_2, now, now));
  now = base::get_epoch_time();
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2_3, now, now));
  ASSERT_TRUE(test_ds_->LoadItem(key2, values));
  ASSERT_EQ(3, static_cast<int>(values.size()));
  int value_num = 0;
  for (int i = 0; i < static_cast<int>(values.size()); i++) {
    if (values[i] == value2_1)
      value_num++;
    else if (values[i] == value2_2)
      value_num++;
    else if (values[i] == value2_3)
      value_num++;
  }
  ASSERT_EQ(3, value_num);
}

TEST_F(DataStoreTest, BEH_KAD_LoadNonExistingData) {
  std::string key1 = cry_obj_.Hash("11222xc", "", crypto::STRING_STRING,
      false);
  std::vector<std::string> values;
  ASSERT_TRUE(test_ds_->LoadItem(key1, values));
  ASSERT_EQ(0, static_cast<int>(values.size()));
}

TEST_F(DataStoreTest, BEH_KAD_UpdateData) {
  std::string key1 = cry_obj_.Hash("663efsxx33d", "", crypto::STRING_STRING,
      false);
  std::string value1 = base::RandomString(500);
  boost::int32_t now1 = base::get_epoch_time();
  ASSERT_TRUE(test_ds_->StoreItem(key1, value1, now1, now1));
  ASSERT_EQ(static_cast<boost::uint32_t>(now1),
            test_ds_->LastPublishedTime(key1, value1));
  ASSERT_EQ(static_cast<boost::uint32_t>(now1),
            test_ds_->OriginalPublishedTime(key1, value1));
  std::vector<std::string> values;
  ASSERT_TRUE(test_ds_->LoadItem(key1, values));
  ASSERT_EQ(1, static_cast<int>(values.size()));
  ASSERT_EQ(value1, values[0]);
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  boost::int32_t now2 = base::get_epoch_time();
  ASSERT_TRUE(test_ds_->StoreItem(key1, value1, now2, now2));
  ASSERT_EQ(static_cast<boost::uint32_t>(now2),
            test_ds_->LastPublishedTime(key1, value1));
  ASSERT_EQ(static_cast<boost::uint32_t>(now1),
            test_ds_->OriginalPublishedTime(key1, value1));
  values.clear();
  ASSERT_TRUE(test_ds_->LoadItem(key1, values));
  ASSERT_EQ(1, static_cast<int>(values.size()));
  ASSERT_EQ(value1, values[0]);
}

TEST_F(DataStoreTest, BEH_KAD_DeleteKey) {
  // store one key
  std::string key1 = cry_obj_.Hash("hdvahyr54345t456d", "",
      crypto::STRING_STRING, false);
  std::string value1 = base::RandomString(100);
  boost::int32_t now = base::get_epoch_time();
  ASSERT_TRUE(test_ds_->StoreItem(key1, value1, now, now));
  // store another key with 3 values
  std::string key2 = cry_obj_.Hash("hrerc4334cr", "", crypto::STRING_STRING,
      false);
  std::string value2_1 = base::RandomString(24);
  std::string value2_2 = base::RandomString(500);
  std::string value2_3 = cry_obj_.Hash("hneffddcx33xxx", "",
      crypto::STRING_STRING, false);
  now = base::get_epoch_time();
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2_1, now, now));
  now = base::get_epoch_time();
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2_2, now, now));
  now = base::get_epoch_time();
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2_3, now, now));
  // there should be 2 keys
  std::vector<std::string> keys;
  ASSERT_TRUE(test_ds_->Keys(&keys));
  ASSERT_EQ(2, static_cast<int>(keys.size()));
  // delete one key
  ASSERT_TRUE(test_ds_->DeleteKey(key2));
  // there should be only one key left
  ASSERT_TRUE(test_ds_->Keys(&keys));
  ASSERT_EQ(1, static_cast<int>(keys.size()));
  ASSERT_EQ(key1, keys[0]);
  // delete another key
  ASSERT_TRUE(test_ds_->DeleteKey(key1));
  ASSERT_TRUE(test_ds_->Keys(&keys));
  ASSERT_EQ(0, static_cast<int>(keys.size()));
  // delete non-existing key
  ASSERT_FALSE(test_ds_->DeleteKey(key1));
}

TEST_F(DataStoreTest, BEH_KAD_DeleteItem) {
  // store one key
  std::string key1 = cry_obj_.Hash("vxxsdasde", "", crypto::STRING_STRING,
      false);
  std::string value1 = base::RandomString(200);
  boost::int32_t now = base::get_epoch_time();
  ASSERT_TRUE(test_ds_->StoreItem(key1, value1, now, now));
  std::vector<std::string> values;
  ASSERT_TRUE(test_ds_->LoadItem(key1, values));
  ASSERT_EQ(1, static_cast<int>(values.size()));
  // store another key with 3 values
  std::string key2 = cry_obj_.Hash("vvxxxee1", "", crypto::STRING_STRING,
      false);
  std::string value2_1 = base::RandomString(10);
  std::string value2_2 = base::RandomString(2);
  std::string value2_3 = cry_obj_.Hash("jjrtfccvvdsss", "",
      crypto::STRING_STRING, false);
  now = base::get_epoch_time();
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2_1, now, now));
  now = base::get_epoch_time();
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2_2, now, now));
  now = base::get_epoch_time();
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2_3, now, now));
  ASSERT_TRUE(test_ds_->LoadItem(key2, values));
  ASSERT_EQ(3, static_cast<int>(values.size()));
  // delete an item with key2 and value2_1
  ASSERT_TRUE(test_ds_->DeleteItem(key2, value2_1));
  ASSERT_TRUE(test_ds_->LoadItem(key2, values));
  ASSERT_EQ(2, static_cast<int>(values.size()));
  // value2_1 should be gone
  int value_num = 0;
  for (int i = 0; i < static_cast<int>(values.size()); i++) {
    if (values[i] == value2_1)
      value_num++;
  }
  ASSERT_EQ(0, value_num);
  ASSERT_FALSE(test_ds_->DeleteItem(key2, value2_1));
  // delete an item with key1 and value1
  ASSERT_TRUE(test_ds_->DeleteItem(key1, value1));
  ASSERT_TRUE(test_ds_->LoadItem(key1, values));
  ASSERT_EQ(0, static_cast<int>(values.size()));
  ASSERT_FALSE(test_ds_->DeleteItem(key1, value1));
}

TEST_F(DataStoreTest, BEH_KAD_DeleteValue) {
  // store 2 records with the same value
  std::string key1 = cry_obj_.Hash("ccc333", "", crypto::STRING_STRING,
      false);
  std::string value1 = base::RandomString(300);
  boost::int32_t now = base::get_epoch_time();
  ASSERT_TRUE(test_ds_->StoreItem(key1, value1, now, now));
  std::string key2 = cry_obj_.Hash("vvvvxsss", "", crypto::STRING_STRING,
      false);
  ASSERT_TRUE(test_ds_->StoreItem(key2, value1, now, now));
  std::vector<std::string> keys;
  ASSERT_TRUE(test_ds_->Keys(&keys));
  ASSERT_EQ(2, static_cast<int>(keys.size()));
  ASSERT_TRUE(test_ds_->DeleteValue(value1));
  ASSERT_TRUE(test_ds_->Keys(&keys));
  ASSERT_EQ(0, static_cast<int>(keys.size()));
  ASSERT_FALSE(test_ds_->DeleteValue(value1));
}

TEST_F(DataStoreTest, BEH_KAD_ReuseDatabase) {
  // prepare the data
  std::string key1 = cry_obj_.Hash("vvcccss", "", crypto::STRING_STRING,
      false);
  std::string value1 = base::RandomString(500);
  boost::int32_t now = base::get_epoch_time();
  std::vector<std::string> keys;
  // create a new data store with reuse disabled
  {
  kad::DataStore test_ds_1;
  boost::filesystem::path db_file(db_name_);
  ASSERT_TRUE(test_ds_1.Init(db_file.string()));
  ASSERT_TRUE(test_ds_1.StoreItem(key1, value1, now, now));
  ASSERT_TRUE(test_ds_1.Keys(&keys));
  ASSERT_EQ(1, static_cast<int>(keys.size()));
  ASSERT_TRUE(test_ds_1.Close());
  }
  // create another data store with reuse disabled
  {
  kad::DataStore test_ds_2;
  boost::filesystem::path db_file(db_name_);
  ASSERT_TRUE(test_ds_2.Init(db_file.string()));
  ASSERT_TRUE(test_ds_2.Keys(&keys));
  ASSERT_EQ(0, static_cast<int>(keys.size()));
  // store something
  ASSERT_TRUE(test_ds_2.StoreItem(key1, value1, now, now));
  ASSERT_TRUE(test_ds_2.Close());
  }
  // create 3rd data store with reuse enabled
  {
  kad::DataStore test_ds_3;
  boost::filesystem::path db_file(db_name_);
  ASSERT_TRUE(test_ds_3.Init(db_file.string(), true));
  ASSERT_TRUE(test_ds_3.Keys(&keys));
  ASSERT_EQ(1, static_cast<int>(keys.size()));
  ASSERT_EQ(key1, keys[0]);
  ASSERT_TRUE(test_ds_3.Close());
  }
}

TEST_F(DataStoreTest, BEH_KAD_StoreMultipleValues) {
  std::vector<std::string> keys;
  ASSERT_TRUE(test_ds_->Keys(&keys));
  ASSERT_EQ(0, static_cast<int>(keys.size()));
  std::string key1 = cry_obj_.Hash("abc123vvd32sfdf", "", crypto::STRING_STRING,
      false);
  std::string value1 = cry_obj_.Hash("vfdsfdasfdasfdsaferrfd", "",
      crypto::STRING_STRING, false);
  std::string value2 = base::RandomString(1024 * 1024);  // big value 1MB
  boost::int32_t now = base::get_epoch_time();
  ASSERT_TRUE(test_ds_->StoreItem(key1, value1, now, now));
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  now = base::get_epoch_time();
  ASSERT_TRUE(test_ds_->StoreItem(key1, value2, now, now));
  std::vector<std::string> values;
  ASSERT_TRUE(test_ds_->LoadItem(key1, values));
  ASSERT_EQ(static_cast<unsigned int>(2), values.size());
  int i = 0;
  for (unsigned int j = 0; j < values.size(); j++) {
    if (values[j] == value1 || values[j] == value2)
      i++;
  }
  ASSERT_EQ(2, i);
}
