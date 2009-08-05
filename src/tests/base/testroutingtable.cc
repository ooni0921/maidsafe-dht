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
#include "base/routingtable.h"
#include "maidsafe/maidsafe-dht_config.h"

TEST(PDRoutingTableHandlerTest, BEH_BASE_AddTuple) {
  std::string kademlia_id = base::RandomString(64);
  std::string host_ip("192.168.1.188");
  boost::uint16_t host_port = 8888;
  std::string rendezvous_ip("81.149.64.82");
  boost::uint16_t rendezvous_port = 5555;
  std::string public_key = base::RandomString(64);
  float rtt = 200;
  boost::uint16_t rank = 5;
  boost::uint32_t space = 55555;
  base::PDRoutingTableTuple tuple_to_store(kademlia_id, host_ip, host_port,
      rendezvous_ip, rendezvous_port, public_key, rtt, rank, space);
  base::PDRoutingTableHandler rt_handler;
  ASSERT_EQ(0, rt_handler.AddTuple(tuple_to_store));
  ASSERT_EQ(0, rt_handler.AddTuple(tuple_to_store));

  base::PDRoutingTableHandler rt_handler1;
  ASSERT_EQ(0, rt_handler1.AddTuple(tuple_to_store));
  ASSERT_EQ(0, rt_handler1.AddTuple(tuple_to_store));
  rt_handler.Clear();
  rt_handler1.Clear();
}

TEST(PDRoutingTableHandlerTest, BEH_BASE_ReadTuple) {
  std::string kademlia_id = base::RandomString(64);
  std::string host_ip("192.168.1.188");
  boost::uint16_t host_port = 8888;
  std::string rendezvous_ip("81.149.64.82");
  boost::uint16_t rendezvous_port = 5555;
  std::string public_key = base::RandomString(64);
  float rtt = 200;
  boost::uint16_t rank = 5;
  boost::uint32_t space = 55555;
  base::PDRoutingTableTuple tuple_to_store(kademlia_id, host_ip, host_port,
      rendezvous_ip, rendezvous_port, public_key, rtt, rank, space);

  base::PDRoutingTableHandler rt_handler;

  base::PDRoutingTableTuple non_existing_tuple;
  ASSERT_EQ(1, rt_handler.GetTupleInfo(kademlia_id, &non_existing_tuple));
  ASSERT_EQ(0, rt_handler.AddTuple(tuple_to_store));
  base::PDRoutingTableTuple retrieved_tuple;
  ASSERT_EQ(0, rt_handler.GetTupleInfo(kademlia_id, &retrieved_tuple));
  ASSERT_EQ(tuple_to_store.kademlia_id(), retrieved_tuple.kademlia_id());
  ASSERT_EQ(tuple_to_store.rendezvous_ip(), retrieved_tuple.rendezvous_ip());
  ASSERT_EQ(tuple_to_store.rendezvous_port(),
    retrieved_tuple.rendezvous_port());
  ASSERT_EQ(tuple_to_store.public_key(), retrieved_tuple.public_key());
  ASSERT_EQ(tuple_to_store.rtt(), retrieved_tuple.rtt());
  ASSERT_EQ(tuple_to_store.rank(), retrieved_tuple.rank());
  ASSERT_EQ(tuple_to_store.space(), retrieved_tuple.space());

  base::PDRoutingTableTuple tuple_to_store1(kademlia_id, host_ip, host_port + 1,
      rendezvous_ip, rendezvous_port + 1, public_key, rtt + 1, rank, space + 1);

  ASSERT_EQ(0, rt_handler.AddTuple(tuple_to_store1));
  base::PDRoutingTableTuple retrieved_tuple1;
  ASSERT_EQ(0, rt_handler.GetTupleInfo(kademlia_id, &retrieved_tuple1));
  ASSERT_EQ(tuple_to_store1.kademlia_id(), retrieved_tuple1.kademlia_id());
  ASSERT_EQ(tuple_to_store1.rendezvous_ip(), retrieved_tuple1.rendezvous_ip());
  ASSERT_EQ(tuple_to_store1.rendezvous_port(),
    retrieved_tuple1.rendezvous_port());
  ASSERT_EQ(tuple_to_store1.public_key(), retrieved_tuple1.public_key());
  ASSERT_EQ(tuple_to_store1.rtt(), retrieved_tuple1.rtt());
  ASSERT_EQ(tuple_to_store1.rank(), retrieved_tuple1.rank());
  ASSERT_EQ(tuple_to_store1.space(), retrieved_tuple1.space());

  rt_handler.Clear();
}

TEST(PDRoutingTableHandlerTest, BEH_BASE_DeleteTuple) {
  std::string kademlia_id = base::RandomString(64);
  std::string host_ip("192.168.1.188");
  boost::uint16_t host_port = 8888;
  std::string rendezvous_ip("81.149.64.82");
  boost::uint16_t rendezvous_port = 5555;
  std::string public_key = base::RandomString(64);
  float rtt = 32;
  boost::uint16_t rank = 5;
  boost::uint32_t space = 3232;
  base::PDRoutingTableTuple tuple_to_store(kademlia_id, host_ip, host_port,
      rendezvous_ip, rendezvous_port, public_key, rtt, rank, space);

  base::PDRoutingTableHandler rt_handler;

  ASSERT_EQ(0, rt_handler.AddTuple(tuple_to_store));
  base::PDRoutingTableTuple retrieved_tuple;
  ASSERT_EQ(0, rt_handler.GetTupleInfo(kademlia_id, &retrieved_tuple));
  ASSERT_EQ(0, rt_handler.DeleteTupleByKadId(kademlia_id));
  ASSERT_EQ(1, rt_handler.GetTupleInfo(kademlia_id, &retrieved_tuple));

  rt_handler.Clear();
}

TEST(PDRoutingTableHandlerTest, BEH_BASE_UpdateTuple) {
  std::string kademlia_id = base::RandomString(64);
  std::string host_ip("192.168.1.188");
  boost::uint16_t host_port = 8888;
  std::string rendezvous_ip("81.149.64.82");
  boost::uint16_t rendezvous_port = 5555;
  std::string public_key = base::RandomString(64);
  float rtt = 32;
  boost::uint16_t rank = 5;
  boost::uint32_t space = 3232;
  base::PDRoutingTableTuple tuple_to_store(kademlia_id, host_ip, host_port,
      rendezvous_ip, rendezvous_port, public_key, rtt, rank, space);
  base::PDRoutingTableHandler rt_handler;

  ASSERT_EQ(2, rt_handler.ContactLocal(kademlia_id));
  ASSERT_EQ(0, rt_handler.AddTuple(tuple_to_store));
  ASSERT_EQ(2, rt_handler.ContactLocal(kademlia_id));
  ASSERT_EQ(0, rt_handler.UpdateHostIp(kademlia_id, "211.11.11.11"));
  ASSERT_EQ(0, rt_handler.UpdateHostPort(kademlia_id, 9999));
  ASSERT_EQ(0, rt_handler.UpdateRendezvousIp(kademlia_id, "86.11.11.11"));
  ASSERT_EQ(0, rt_handler.UpdateRendezvousPort(kademlia_id, 888));
  ASSERT_EQ(0, rt_handler.UpdatePublicKey(kademlia_id, "fafevcddc"));
  ASSERT_EQ(0, rt_handler.UpdateRtt(kademlia_id, 50));
  ASSERT_EQ(0, rt_handler.UpdateRank(kademlia_id, 10));
  ASSERT_EQ(0, rt_handler.UpdateSpace(kademlia_id, 6666));
  ASSERT_EQ(0, rt_handler.UpdateContactLocal(kademlia_id, 0));
  ASSERT_EQ(0, rt_handler.ContactLocal(kademlia_id));
  base::PDRoutingTableTuple retrieved_tuple;
  ASSERT_EQ(0, rt_handler.GetTupleInfo(kademlia_id, &retrieved_tuple));
  ASSERT_EQ("211.11.11.11", retrieved_tuple.host_ip());
  ASSERT_EQ(9999, retrieved_tuple.host_port());
  ASSERT_EQ("86.11.11.11", retrieved_tuple.rendezvous_ip());
  ASSERT_EQ(888, retrieved_tuple.rendezvous_port());
  ASSERT_EQ("fafevcddc", retrieved_tuple.public_key());
  ASSERT_EQ(static_cast<boost::uint32_t>(50), retrieved_tuple.rtt());
  ASSERT_EQ(static_cast<boost::uint16_t>(10), retrieved_tuple.rank());
  ASSERT_EQ(static_cast<boost::uint32_t>(6666), retrieved_tuple.space());

  rt_handler.Clear();
}

TEST(PDRoutingTableTest, BEH_BASE_MultipleHandlers) {
  std::string dbname1("routingtable");
  dbname1 += boost::lexical_cast<std::string>(base::random_32bit_uinteger()) +
            std::string(".db");
  std::string dbname2("routingtable");
  dbname2 += boost::lexical_cast<std::string>(base::random_32bit_uinteger()) +
            std::string(".db");
  ASSERT_NE(dbname1, dbname2);
  std::string kademlia_id1 = base::RandomString(64);
  std::string kademlia_id2 = base::RandomString(64);
  ASSERT_NE(kademlia_id1, kademlia_id2);
  std::string host_ip("192.168.1.188");
  boost::uint16_t host_port = 8888;
  std::string rendezvous_ip("81.149.64.82");
  boost::uint16_t rendezvous_port = 5555;
  std::string public_key = base::RandomString(64);
  float rtt = 200;
  boost::uint16_t rank = 5;
  boost::uint32_t space = 55555;
  base::PDRoutingTableTuple tuple_to_store1(kademlia_id1, host_ip, host_port,
      rendezvous_ip, rendezvous_port, public_key, rtt, rank, space);
  ASSERT_EQ(0, base::PDRoutingTable::getInstance()[dbname1]->AddTuple(
      tuple_to_store1));
  base::PDRoutingTableTuple tuple_to_store2(kademlia_id2, host_ip, host_port-1,
      rendezvous_ip, rendezvous_port-1, public_key, rtt-100, rank-2, space);
  ASSERT_EQ(0, base::PDRoutingTable::getInstance()[dbname2]->AddTuple(
      tuple_to_store2));

  base::PDRoutingTableTuple rec_tuple_1, rec_tuple_2;
  ASSERT_EQ(1, base::PDRoutingTable::getInstance()[dbname1]->GetTupleInfo(
      kademlia_id2, &rec_tuple_1));
  ASSERT_EQ(0, base::PDRoutingTable::getInstance()[dbname1]->GetTupleInfo(
      kademlia_id1, &rec_tuple_1));
  ASSERT_EQ(tuple_to_store1.kademlia_id(), rec_tuple_1.kademlia_id());
  ASSERT_EQ(tuple_to_store1.rendezvous_ip(), rec_tuple_1.rendezvous_ip());
  ASSERT_EQ(tuple_to_store1.rendezvous_port(), rec_tuple_1.rendezvous_port());
  ASSERT_EQ(tuple_to_store1.public_key(), rec_tuple_1.public_key());
  ASSERT_EQ(tuple_to_store1.rtt(), rec_tuple_1.rtt());
  ASSERT_EQ(tuple_to_store1.rank(), rec_tuple_1.rank());
  ASSERT_EQ(tuple_to_store1.space(), rec_tuple_1.space());

  ASSERT_EQ(1, base::PDRoutingTable::getInstance()[dbname2]->GetTupleInfo(
      kademlia_id1, &rec_tuple_2));
  ASSERT_EQ(0, base::PDRoutingTable::getInstance()[dbname2]->GetTupleInfo(
      kademlia_id2, &rec_tuple_2));
  ASSERT_EQ(tuple_to_store2.kademlia_id(), rec_tuple_2.kademlia_id());
  ASSERT_EQ(tuple_to_store2.rendezvous_ip(), rec_tuple_2.rendezvous_ip());
  ASSERT_EQ(tuple_to_store2.rendezvous_port(), rec_tuple_2.rendezvous_port());
  ASSERT_EQ(tuple_to_store2.public_key(), rec_tuple_2.public_key());
  ASSERT_EQ(tuple_to_store2.rtt(), rec_tuple_2.rtt());
  ASSERT_EQ(tuple_to_store2.rank(), rec_tuple_2.rank());
  ASSERT_EQ(tuple_to_store2.space(), rec_tuple_2.space());
}
