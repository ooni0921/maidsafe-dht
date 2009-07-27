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
#include <boost/shared_ptr.hpp>
#include <gtest/gtest.h>
#include <string>
#include <vector>
#include "kademlia/datastore.h"
#include "maidsafe/crypto.h"
#include "maidsafe/maidsafe-dht.h"

class DataStoreTest: public testing::Test {
 protected:
  DataStoreTest() : test_ds_(), cry_obj_() {
    cry_obj_.set_symm_algorithm(crypto::AES_256);
    cry_obj_.set_hash_algorithm(crypto::SHA_512);
  }

  virtual void SetUp() {
    test_ds_.reset(new kad::DataStore(kad::kRefreshTime));
  }

  boost::shared_ptr<kad::DataStore> test_ds_;
  crypto::Crypto cry_obj_;
  DataStoreTest(const DataStoreTest&);
  DataStoreTest &operator=(const DataStoreTest&);
};

TEST_F(DataStoreTest, FUNC_KAD_StoreValidData) {
  std::set<std::string> keys;
  ASSERT_TRUE(test_ds_->Keys(&keys));
  ASSERT_EQ(0, static_cast<int>(keys.size()));
  std::string key1 = cry_obj_.Hash("abc123vvd32sfdf", "", crypto::STRING_STRING,
      false);
  std::string key2 = cry_obj_.Hash("ccccxxxfff212121", "",
      crypto::STRING_STRING, false);
  std::string value1 = cry_obj_.Hash("vfdsfdasfdasfdsaferrfd", "",
      crypto::STRING_STRING, false);
  std::string value2 = base::RandomString(5 * 1024 * 1024);  // big value 5MB
  ASSERT_TRUE(test_ds_->StoreItem(key1, value1, 3600*24, true));
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2, 3600*24, true));
  ASSERT_TRUE(test_ds_->Keys(&keys));
  ASSERT_EQ(2, static_cast<int>(keys.size()));
  int key_num = 0;
  for (std::set<std::string>::iterator it = keys.begin();
       it != keys.end(); it++) {
    if (*it == key1)
      key_num++;
    else if (*it == key2)
      key_num++;
  }
  ASSERT_EQ(2, key_num);
}

TEST_F(DataStoreTest, BEH_KAD_StoreInvalidData) {
  // invalid key
  std::string value1 = cry_obj_.Hash("bb33", "",
      crypto::STRING_STRING, false);
  ASSERT_FALSE(test_ds_->StoreItem("", value1, 3600*24, true));
  // invalid value
  std::string key1 = cry_obj_.Hash("xxe22", value1, crypto::STRING_STRING,
        false);
  // invalid key&value
  ASSERT_FALSE(test_ds_->StoreItem("", "", 3600*24, true));
  // invalid time to live
  ASSERT_FALSE(test_ds_->StoreItem("", value1, 0, true));
}

TEST_F(DataStoreTest, FUNC_KAD_LoadExistingData) {
  // one value under a key
  std::string key1 = cry_obj_.Hash("nssfsreeedxx", "", crypto::STRING_STRING,
      false);
  std::string value1 = cry_obj_.Hash("oybbggjhhtytyerterter", "",
      crypto::STRING_STRING, false);
  boost::int32_t now = base::get_epoch_time();
  ASSERT_TRUE(test_ds_->StoreItem(key1, value1, 3600*24, true));
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
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2_1, 3600*24, true));
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2_2, 3600*24, true));
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2_3, 3600*24, true));
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
  ASSERT_FALSE(test_ds_->LoadItem(key1, values));
  ASSERT_TRUE(values.empty());
}

TEST_F(DataStoreTest, BEH_KAD_UpdateData) {
  std::string key1 = cry_obj_.Hash("663efsxx33d", "", crypto::STRING_STRING,
      false);
  std::string value1 = base::RandomString(500);
  boost::int32_t t_refresh1, t_refresh2, t_expire1, t_expire2, ttl1, ttl2;
  ttl1 = 3600*24;
  ttl2 = 3600*25;
  ASSERT_TRUE(test_ds_->StoreItem(key1, value1, ttl1, true));
  t_refresh1 = test_ds_->LastRefreshTime(key1, value1);
  t_expire1 = test_ds_->ExpireTime(key1, value1);
  ASSERT_NE(0, t_refresh1);
  ASSERT_NE(0, t_expire1);
  std::vector<std::string> values;
  ASSERT_TRUE(test_ds_->LoadItem(key1, values));
  ASSERT_EQ(1, static_cast<int>(values.size()));
  ASSERT_EQ(value1, values[0]);
  ASSERT_EQ(ttl1, test_ds_->TimeToLive(key1, value1));
  boost::this_thread::sleep(boost::posix_time::seconds(1));

  ASSERT_TRUE(test_ds_->StoreItem(key1, value1, ttl2, true));
  t_refresh2 = test_ds_->LastRefreshTime(key1, value1);
  t_expire2 = test_ds_->ExpireTime(key1, value1);
  ASSERT_LT(t_refresh1, t_refresh2);
  ASSERT_LT(t_expire1, t_expire2);
  values.clear();
  ASSERT_TRUE(test_ds_->LoadItem(key1, values));
  ASSERT_EQ(1, static_cast<int>(values.size()));
  ASSERT_EQ(value1, values[0]);
  ASSERT_EQ(ttl2, test_ds_->TimeToLive(key1, value1));
}

TEST_F(DataStoreTest, BEH_KAD_DeleteKey) {
  // store one key
  std::string key1 = cry_obj_.Hash("hdvahyr54345t456d", "",
      crypto::STRING_STRING, false);
  std::string value1 = base::RandomString(100);
  ASSERT_TRUE(test_ds_->StoreItem(key1, value1, 3600*24, true));
  // store another key with 3 values
  std::string key2 = cry_obj_.Hash("hrerc4334cr", "", crypto::STRING_STRING,
      false);
  std::string value2_1 = base::RandomString(24);
  std::string value2_2 = base::RandomString(500);
  std::string value2_3 = cry_obj_.Hash("hneffddcx33xxx", "",
      crypto::STRING_STRING, false);
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2_1, 3600*24, true));
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2_2, 3600*24, true));
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2_3, 3600*24, true));
  // there should be 2 keys
  std::set<std::string> keys;
  ASSERT_TRUE(test_ds_->Keys(&keys));
  ASSERT_EQ(2, static_cast<int>(keys.size()));
  // delete one key
  ASSERT_TRUE(test_ds_->DeleteKey(key2));
  // there should be only one key left
  ASSERT_TRUE(test_ds_->Keys(&keys));
  ASSERT_EQ(1, static_cast<int>(keys.size()));
  ASSERT_TRUE(keys.end() != keys.find(key1));
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
  ASSERT_TRUE(test_ds_->StoreItem(key1, value1, 3600*24, true));
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

  ASSERT_TRUE(test_ds_->StoreItem(key2, value2_1, 3600*24, true));
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2_2, 3600*24, true));
  ASSERT_TRUE(test_ds_->StoreItem(key2, value2_3, 3600*24, true));
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
  ASSERT_FALSE(test_ds_->LoadItem(key1, values));
  ASSERT_TRUE(values.empty());
  ASSERT_FALSE(test_ds_->DeleteItem(key1, value1));
}

TEST_F(DataStoreTest, BEH_KAD_StoreMultipleValues) {
  std::set<std::string> keys;
  ASSERT_TRUE(test_ds_->Keys(&keys));
  ASSERT_TRUE(keys.empty());
  std::string key1 = cry_obj_.Hash("abc123vvd32sfdf", "", crypto::STRING_STRING,
      false);
  std::vector<std::string> values1;
  values1.push_back(cry_obj_.Hash("vfdsfdasfdasfdsaferrfd", "",
      crypto::STRING_STRING, false));
  values1.push_back(base::RandomString(1024 * 1024));  // big value 1MB
  for (unsigned int i = 0; i < values1.size(); i++)
    ASSERT_TRUE(test_ds_->StoreItem(key1, values1[i], 3600*24, true));
  std::vector<std::string> values;
  ASSERT_TRUE(test_ds_->LoadItem(key1, values));
  ASSERT_EQ(static_cast<unsigned int>(2), values.size());
  int i = 0;
  for (unsigned int j = 0; j < values.size(); j++) {
    if (values[j] == values1[0] || values[j] == values1[1])
      i++;
  }
  ASSERT_EQ(2, i);
}

TEST_F(DataStoreTest, BEH_KAD_RefreshKeyValue) {
  std::string key1 = cry_obj_.Hash("663efsxx33d", "", crypto::STRING_STRING,
      false);
  std::string value1 = base::RandomString(500);
  ASSERT_EQ(boost::uint32_t(0),  test_ds_->LastRefreshTime(key1, value1));
  ASSERT_EQ(boost::uint32_t(0),  test_ds_->ExpireTime(key1, value1));
  boost::int32_t t_refresh1, t_refresh2, t_expire1, t_expire2;
  ASSERT_TRUE(test_ds_->StoreItem(key1, value1, 3600*24, true));
  t_refresh1 = test_ds_->LastRefreshTime(key1, value1);
  t_expire1 = test_ds_->ExpireTime(key1, value1);
  ASSERT_NE(0, t_refresh1);
  ASSERT_NE(0, t_expire1);
  std::vector<std::string> values;
  ASSERT_TRUE(test_ds_->LoadItem(key1, values));
  ASSERT_EQ(1, static_cast<int>(values.size()));
  ASSERT_EQ(value1, values[0]);
  boost::this_thread::sleep(boost::posix_time::milliseconds(1500));
  // refreshing the value
  ASSERT_TRUE(test_ds_->StoreItem(key1, value1, 3600*24, false));
  t_refresh2 = test_ds_->LastRefreshTime(key1, value1);
  t_expire2 = test_ds_->ExpireTime(key1, value1);
  ASSERT_LT(t_refresh1, t_refresh2);
  ASSERT_EQ(t_expire1, t_expire2);
  values.clear();
  ASSERT_TRUE(test_ds_->LoadItem(key1, values));
  ASSERT_EQ(1, static_cast<int>(values.size()));
  ASSERT_EQ(value1, values[0]);
}

TEST_F(DataStoreTest, BEH_KAD_RepublishKeyValue) {
  std::string key1 = cry_obj_.Hash("663efsxx33d", "", crypto::STRING_STRING,
      false);
  std::string value1 = base::RandomString(500);
  ASSERT_EQ(boost::uint32_t(0),  test_ds_->LastRefreshTime(key1, value1));
  ASSERT_EQ(boost::uint32_t(0),  test_ds_->ExpireTime(key1, value1));
  ASSERT_EQ(boost::uint32_t(0),  test_ds_->TimeToLive(key1, value1));
  boost::int32_t t_refresh1, t_refresh2, t_expire1, t_expire2;
  ASSERT_TRUE(test_ds_->StoreItem(key1, value1, 3600*24, true));
  t_refresh1 = test_ds_->LastRefreshTime(key1, value1);
  t_expire1 = test_ds_->ExpireTime(key1, value1);
  ASSERT_NE(0, t_refresh1);
  ASSERT_NE(0, t_expire1);
  std::vector<std::string> values;
  ASSERT_TRUE(test_ds_->LoadItem(key1, values));
  ASSERT_EQ(1, static_cast<int>(values.size()));
  ASSERT_EQ(value1, values[0]);
  boost::this_thread::sleep(boost::posix_time::milliseconds(1500));
  // republishing the value
  ASSERT_TRUE(test_ds_->StoreItem(key1, value1, 3600*24, true));
  t_refresh2 = test_ds_->LastRefreshTime(key1, value1);
  t_expire2 = test_ds_->ExpireTime(key1, value1);
  ASSERT_LT(t_refresh1, t_refresh2);
  ASSERT_LT(t_expire1, t_expire2);
  values.clear();
  ASSERT_TRUE(test_ds_->LoadItem(key1, values));
  ASSERT_EQ(1, static_cast<int>(values.size()));
  ASSERT_EQ(value1, values[0]);
}

TEST_F(DataStoreTest, FUNC_KAD_GetValuesToRefresh) {
  // data store with refresh time set to 3 seconds for test
  kad::DataStore ds(3);
  std::vector<kad::refresh_value> refvalues;
  std::vector<std::string> keys, values;
  for (unsigned int i = 0; i < 6; i++) {
    keys.push_back(cry_obj_.Hash(base::itos(i), "", crypto::STRING_STRING,
      false));
    values.push_back(base::RandomString(500));
  }

  for (unsigned int i = 0; i < 4; i++) {
    if (i == 2) {
      ASSERT_TRUE(ds.StoreItem(keys[i], values[i]+"EXTRA", 3600*24, true));
    }
    ASSERT_TRUE(ds.StoreItem(keys[i], values[i], 3600*24, true));
  }

  boost::this_thread::sleep(boost::posix_time::seconds(ds.t_refresh()+1));

  for (unsigned int i = 4; i < keys.size(); i++) {
    ASSERT_TRUE(ds.StoreItem(keys[i], values[i], 3600*24, true));
  }
  // refreshing key[0] so it does not apperat in keys to refresh
  ASSERT_TRUE(ds.StoreItem(keys[0], values[0], 3600*24, false));
  refvalues = ds.ValuesToRefresh();
  for (unsigned int i = 0; i < refvalues.size(); i++) {
    ASSERT_NE(keys[0], refvalues[i].key_);
    ASSERT_NE(values[0], refvalues[i].value_);
  }
  for (unsigned int i = 4; i < keys.size(); i++) {
    bool found = false;
    for (unsigned int j = 0; j < refvalues.size(); j++) {
      if (keys[i] == refvalues[j].key_ && values[i] == refvalues[j].value_) {
        found = true;
        break;
      }
      ASSERT_FALSE(found);
    }
  }
  for (unsigned int i = 1; i < 4; i++) {
    bool found = false;
    for (unsigned int j = 0; j < refvalues.size(); j++) {
      if (keys[i] == refvalues[j].key_ && values[i] == refvalues[j].value_) {
        found = true;
        break;
      }
    }
    ASSERT_TRUE(found);
  }
}

TEST_F(DataStoreTest, FUNC_KAD_DeleteExpiredValues) {
  std::vector<std::string> keys, values;
  std::vector<boost::uint32_t> ttl;
  // creating 10 key/values
  for (int i = 0; i < 10; i++) {
    keys.push_back(base::itos(i));
    values.push_back(base::RandomString(100));
    ttl.push_back(i+5);  // TTL = i + 5 seconds
  }
  for (unsigned int i = 0; i < keys.size(); i++)
    test_ds_->StoreItem(keys[i], values[i], ttl[i], true);
  // waiting 9 seconds  values 0, 1, and 3 are expired and should be deleted
  boost::this_thread::sleep(boost::posix_time::seconds(4));
  // republishing value 2 with TTL 7
  test_ds_->StoreItem(keys[2], values[2], ttl[2], true);
  // refreshing value 3 with TTL 8
  test_ds_->StoreItem(keys[3], values[3], ttl[3], false);
  boost::this_thread::sleep(boost::posix_time::seconds(5));
  test_ds_->DeleteExpiredValues();
  boost::uint32_t now = base::get_epoch_time();
  std::set<std::string> rec_keys;
  ASSERT_TRUE(test_ds_->Keys(&rec_keys));
  ASSERT_EQ(keys.size()-3, rec_keys.size());
  for (std::set<std::string>::iterator it = rec_keys.begin();
       it != rec_keys.end(); it++) {
    std::string value;
    for (unsigned int j = 0; j < keys.size(); j++) {
      if (*it == keys[j]) {
        value = values[j];
        break;
      }
    }
    ASSERT_LE(now, test_ds_->ExpireTime(*it, value));
  }
  // checking correct keys have been deleted
  std::vector<std::string> del_keys;
  del_keys.push_back(keys[0]);
  del_keys.push_back(keys[1]);
  del_keys.push_back(keys[3]);
  for (unsigned int j = 0; j < del_keys.size(); j++) {
    ASSERT_TRUE(rec_keys.end() == rec_keys.find(del_keys[j]));
  }
}

TEST_F(DataStoreTest, BEH_KAD_ClearDataStore) {
  std::set<std::string> keys;
  // creating 10 key/values
  for (int i = 0; i < 10; i++) {
    std::string key = cry_obj_.Hash(base::itos(i), "", crypto::STRING_STRING,
      false);
    test_ds_->StoreItem(key, base::RandomString(100), 3600*24, true);
  }
  test_ds_->Keys(&keys);
  ASSERT_EQ(10, keys.size());
  test_ds_->Clear();
  keys.clear();
  test_ds_->Keys(&keys);
  ASSERT_EQ(0, keys.size());
}
