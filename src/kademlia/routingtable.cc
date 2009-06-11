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
#include "kademlia/routingtable.h"
#include "kademlia/kbucket.h"
#include "kademlia/kadutils.h"
#include "maidsafe/maidsafe-dht_config.h"

namespace kad {

RoutingTable::RoutingTable(const std::string &holder_id)
    : k_buckets_(),
      bucket_upper_address_(),
      holder_id_(holder_id),
      bucket_of_holder_(0),
      brother_bucket_of_holder_(-1),
      address_space_upper_address_("2") {
  BigInt min_range(0);
  address_space_upper_address_.pow(kKeySizeBytes*8);
  address_space_upper_address_--;
  boost::shared_ptr<KBucket> kbucket(new KBucket(min_range,
                                                 address_space_upper_address_));
  k_buckets_.push_back(kbucket);
  bucket_upper_address_.insert(std::pair<BigInt, int>
                               (address_space_upper_address_, 0));
}

RoutingTable::~RoutingTable() {
  k_buckets_.clear();
}

int RoutingTable::KBucketIndex(const std::string &key) {
//  bool found = false;
//  int result;
//  for (result = 0; (result < static_cast<int>(k_buckets_.size()))&& (!found);
//      result++)
//    if (k_buckets_[result]->KeyInRange(key))
//      found = true;
//  return result-1;
  BigInt bint = StrToBigInt(key);
  if (bint > address_space_upper_address_)
    return -1;
  std::map<BigInt, int>::iterator lower_bound_iter =
      bucket_upper_address_.lower_bound(bint);
  return (*lower_bound_iter).second;
}

std::vector<int> RoutingTable::SortBucketsByDistance(const std::string &key) {
  BigInt bint = StrToBigInt(key);
  std::map<BigInt, int> distance;
  // For a given k-bucket, all contacts are either all closer to or all further
  // from a given key than every other contact outwith that k-bucket.  Hence we
  // iterate through each k-bucket's max id and insert xor distance to map.
  for (std::map<BigInt, int>::iterator iter = bucket_upper_address_.begin();
       iter != bucket_upper_address_.end(); ++iter)
    distance.insert(std::pair<BigInt, int>(((*iter).first ^ bint),
                                           (*iter).second));
  std::vector<int> indices;
  for (std::map<BigInt, int>::iterator dist_iter = distance.begin();
       dist_iter != distance.end(); ++dist_iter)
    indices.push_back((*dist_iter).second);
  return indices;
}

int RoutingTable::SortContactsByDistance(const std::string &key,
                                         std::vector<Contact> *contacts) {
  boost::uint32_t number_of_contacts = contacts->size();
  BigInt bint = StrToBigInt(key);
  std::map<BigInt, Contact> distance;
  for (boost::uint32_t i = 0; i < contacts->size(); ++i)
    distance.insert(std::pair<BigInt, Contact>
        ((StrToBigInt(contacts->at(i).node_id()) ^ bint), contacts->at(i)));
  contacts->clear();
  for (std::map<BigInt, Contact>::iterator dist_iter = distance.begin();
       dist_iter != distance.end(); ++dist_iter)
    contacts->push_back((*dist_iter).second);
  return contacts->size() == number_of_contacts ? 0 : -1;
}

bool RoutingTable::GetContact(const std::string &node_id, Contact *contact) {
  int index = KBucketIndex(node_id);
  if (index < 0)
    return false;
  if (!k_buckets_[index]->GetContact(node_id, contact))
    return false;
  return true;
}

void RoutingTable::TouchKBucket(const std::string &node_id) {
  int index = KBucketIndex(node_id);
  if (index < 0)
    return;
  k_buckets_[index]->set_last_accessed(base::get_epoch_time());
}

void RoutingTable::RemoveContact(const std::string &node_id,
  const bool &force) {
  int index = KBucketIndex(node_id);
  if (index < 0)
    return;
  k_buckets_[index]->RemoveContact(node_id, force);
}

void RoutingTable::SplitKbucket(const int &index) {
  BigInt split_point = k_buckets_[index]->range_max()-
    ((k_buckets_[index]->range_max()-k_buckets_[index]->range_min())/2);
  BigInt range_min_kb_left = k_buckets_[index]->range_min();
  BigInt range_max_kb_left = split_point-1;
  BigInt range_min_kb_right = split_point;
  BigInt range_max_kb_right = k_buckets_[index]->range_max();
  boost::shared_ptr<KBucket> kb_left(new KBucket
      (range_min_kb_left, range_max_kb_left));
  boost::shared_ptr<KBucket> kb_right(new KBucket
      (range_min_kb_right, range_max_kb_right));
  // Getting all contacts of the kbucket to be split
  std::vector<Contact> contacts, ex_contacts;
  k_buckets_[index]->GetContacts(K, ex_contacts, &contacts);
  for (int i = contacts.size()-1; i > -1; --i) {
    Contact contact = contacts[i];
    KBucketExitCode exitcode;
    if (kb_left->KeyInRange(contact.node_id()))
      exitcode = kb_left->AddContact(contact);
    else
      exitcode = kb_right->AddContact(contact);
  }
  // delete k_buckets_[index];
  k_buckets_.erase(k_buckets_.begin()+index);
  k_buckets_.insert(k_buckets_.begin()+index, kb_left);
  k_buckets_.insert(k_buckets_.begin()+index+1, kb_right);
  bucket_upper_address_.clear();
  for (boost::uint32_t j = 0; j < k_buckets_.size(); ++j)
  bucket_upper_address_.insert(std::pair<BigInt, int>
      (k_buckets_[j]->range_max(), j));
  // Implement Force K algorithm
  // Keep tracking the bucket of the peer and brother bucket of the peer
  if (k_buckets_[index]->KeyInRange(holder_id_)) {
    bucket_of_holder_ = index;
    brother_bucket_of_holder_ = index + 1;
  } else {
    bucket_of_holder_ = index + 1;
    brother_bucket_of_holder_ = index;
  }
}

int RoutingTable::AddContact(const Contact &new_contact) {
  int index = KBucketIndex(new_contact.node_id());
  KBucketExitCode exitcode = FAIL;
  if (index >= 0)
    exitcode = k_buckets_[index]->AddContact(new_contact);
  switch (exitcode) {
    case SUCCEED: return 0;
    case FULL: if (!k_buckets_[index]->KeyInRange(holder_id_)) {
                 if (index == brother_bucket_of_holder_) {
                   // Force a peer always accept peers belonging to the brother
                   // bucket of the peer in case they are amongst k closet
                   // neighbours
                   if (ForceKAcceptNewPeer(new_contact) != 0) {
                     return 2;
                   } else {
                     return 0;
                   }
                 }
                 return 2;
               }
               SplitKbucket(index);
               return AddContact(new_contact);
    case FAIL:
    default: return -2;
  }
}

void RoutingTable::FindCloseNodes(
    const std::string &key,
    int count,
    std::vector<Contact> *close_nodes,
    const std::vector<Contact> &exclude_contacts) {
  int index = KBucketIndex(key);
  if (index < 0)
    return;
  k_buckets_[index]->GetContacts(count, exclude_contacts, close_nodes);
  bool full = (count == static_cast<int>(close_nodes->size()));
  if (full)
    return;
  std::vector<int> indices = SortBucketsByDistance(key);
  // Start for loop at 1, as we have already added contacts from closest bucket.
  for (boost::uint32_t index_no = 1; index_no < indices.size(); ++index_no) {
    std::vector<Contact> contacts;
    k_buckets_[index_no]->GetContacts(K, exclude_contacts, &contacts);
    if (0 != SortContactsByDistance(key, &contacts))
      continue;
    boost::uint32_t iter(0);
    while (!full && iter < contacts.size()) {
      close_nodes->push_back(contacts[iter]);
      ++iter;
      full = (count == static_cast<int>(close_nodes->size()));
    }
    if (full)
      return;
  }
}

void RoutingTable::GetRefreshList(std::vector<std::string> *ids,
  const int &start_kbucket, const bool &force) {
  boost::uint32_t curr_time = base::get_epoch_time();
  for (int i = start_kbucket; i < static_cast<int>(k_buckets_.size()); i++)
    if (force || static_cast<int>(curr_time-k_buckets_[i]->last_accessed())
        > kRefreshTime) {
      std::string random_id = random_kademlia_id(k_buckets_[i]->range_min(),
        k_buckets_[i]->range_max());
      ids->push_back(random_id);
    }
}

int RoutingTable::KbucketSize() const { return k_buckets_.size(); }

int RoutingTable::Size() const {
  int size = 0;
  for (int i = 0; i < static_cast<int>(k_buckets_.size()); i++)
    size += k_buckets_[i]->Size();
  return size;
}

bool RoutingTable::GetContacts(const int &index,
  std::vector<Contact> *contacts,
  const std::vector<Contact> &exclude_contacts) {
  if (index > static_cast<int>(k_buckets_.size()))
    return false;
  contacts->clear();
  k_buckets_[index]->GetContacts(K, exclude_contacts, contacts);
  return true;
}

void RoutingTable::Clear() {
  k_buckets_.clear();
}

namespace detail {
  struct ForceKEntry {
    Contact contact;
    int score;
  };

  struct ContactWithTargetPeer {
    Contact contact;
    std::string holder_id;
  };

  bool compare_distance(const ContactWithTargetPeer &first,
      const ContactWithTargetPeer &second) {
    if (first.contact.node_id() == "") return true;
    if (second.contact.node_id() == "") return false;
    if (kademlia_distance(first.contact.node_id(), first.holder_id) <
        kademlia_distance(second.contact.node_id(), second.holder_id))
      return true;
    else
      return false;
  }

  bool compare_time(const ContactWithTargetPeer &first,
      const ContactWithTargetPeer &second) {
    if (first.contact.last_seen() > second.contact.last_seen())
      return true;
    else
      return false;
  }

  bool compare_score(const ForceKEntry &first, const ForceKEntry &second) {
    if (first.score > second.score)
      return true;
    else
      return false;
  }

  bool get_least_useful_contact(std::list<ContactWithTargetPeer> l,
      Contact *least_useful_contact) {
    l.sort(compare_distance);
    std::list<ForceKEntry> l_score;
    int d = 1;
    for (std::list<ContactWithTargetPeer>::iterator it = l.begin();
        it != l.end(); it++) {
      ForceKEntry entry = {it->contact, d++};
      l_score.push_back(entry);
    }
    l.sort(compare_time);
    int t = 1;
    for (std::list<ContactWithTargetPeer>::iterator it = l.begin();
        it != l.end(); it++) {
      for (std::list<ForceKEntry>::iterator it1 = l_score.begin();
          it1 != l_score.end(); it1++) {
        if (it->contact == it1->contact) it1->score += t++;
      }
    }
    l_score.sort(compare_score);
    if (!l_score.empty()) {
      // return the contact with the highest score
      *least_useful_contact = l_score.front().contact;
      return true;
    } else {
      return false;
    }
  }
}  // namespace detail

int RoutingTable::ForceKAcceptNewPeer(const Contact &new_contact) {
  // Calculate how many k closest neighbours belong to the brother bucket of
  // the peer
  int v = K - k_buckets_[bucket_of_holder_]->Size();
  if (v == 0)
    return 1;
  // Getting all contacts of the brother kbucket of the peer
  std::vector<Contact> contacts, ex_contacts;
  k_buckets_[brother_bucket_of_holder_]->GetContacts(K, ex_contacts, &contacts);
  std::list<detail::ContactWithTargetPeer> candidates_for_l;
  for (boost::uint16_t i = 0; i < contacts.size(); ++i) {
    detail::ContactWithTargetPeer entry = {contacts[i], holder_id_};
    candidates_for_l.push_back(entry);
  }
  candidates_for_l.sort(detail::compare_distance);
  // Check whether the new peer is among the v nodes
  std::list<detail::ContactWithTargetPeer>::iterator it =
    candidates_for_l.begin();
  advance(it, v-1);
  if (it == candidates_for_l.end())
    return 1;
  if (kademlia_distance(new_contact.node_id(), holder_id_) >=
      kademlia_distance(it->contact.node_id(), holder_id_)) {
    // new peer isn't among the k closest neighbours
    return 1;
  }
  // new peer is among the k closest neighbours
  // put all entries of Bp , which are not among the k closest peers into a
  // list l and drop the peer which is the least useful
  std::list<detail::ContactWithTargetPeer> l;
  for (; it != candidates_for_l.end(); it++)
    l.push_back(*it);
  Contact least_useful_contact;
  if (detail::get_least_useful_contact(l, &least_useful_contact)) {
    k_buckets_[brother_bucket_of_holder_]->RemoveContact(
      least_useful_contact.node_id(), true);
    k_buckets_[brother_bucket_of_holder_]->AddContact(new_contact);
    return 0;
  }
  return -1;
}

Contact RoutingTable::GetLastSeenContact(const int &kbucket_index) {
  Contact last_seen;
  if (kbucket_index > static_cast<int>(k_buckets_.size()) - 1)
    return last_seen;
  return k_buckets_[kbucket_index]->LastSeenContact();
}
}  // namespace kad
