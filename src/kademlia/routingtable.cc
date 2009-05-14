/*
 * copyright maidsafe.net limited 2008
 * The following source code is property of maidsafe.net limited and
 * is not meant for external use. The use of this code is governed
 * by the license file LICENSE.TXT found in teh root of this directory and also
 * on www.maidsafe.net.
 *
 * You are not free to copy, amend or otherwise use this source code without
 * explicit written permission of the board of directors of maidsafe.net
 *
 *  Created on: Sep 29, 2008
 *      Author: haiyang
 */

#include <boost/cstdint.hpp>
#include "base/utils.h"
#include "kademlia/routingtable.h"
#include "kademlia/contact.h"
#include "kademlia/kbucket.h"
#include "kademlia/kadutils.h"

namespace kad {

RoutingTable::RoutingTable(const std::string &holder_id)
  : k_buckets_(),
    holder_id_(holder_id),
    bucket_of_p_(0),
    brother_bucket_of_p_(-1) {
  BigInt min_range(0);
  BigInt max_range("2");
  max_range.pow(kKeySizeBytes*8);
  max_range--;
  boost::shared_ptr<KBucket> kbucket(new KBucket(min_range, max_range));
  k_buckets_.push_back(kbucket);
}

RoutingTable::~RoutingTable() {
//   printf("In RoutingTable destructor.\n");
  k_buckets_.clear();
}

int RoutingTable::KBucketIndex(const std::string &key) {
  bool found = false;
  int result;
  for (result = 0; (result < static_cast<int>(k_buckets_.size()))&& (!found);
      result++)
    if (k_buckets_[result]->KeyInRange(key))
      found = true;
  return result-1;
}

bool RoutingTable::GetContact(const std::string &node_id, Contact *contact) {
  int index = KBucketIndex(node_id);
  if (!k_buckets_[index]->GetContact(node_id, contact))
    return false;
  return true;
}

void RoutingTable::TouchKBucket(const std::string &node_id) {
  int index = KBucketIndex(node_id);
  k_buckets_[index]->set_last_accessed(base::get_epoch_time());
}

void RoutingTable::RemoveContact(const std::string &node_id,
  const bool &force) {
  int index = KBucketIndex(node_id);
  k_buckets_[index]->RemoveContact(node_id, force);
}

void RoutingTable::SplitKbucket(const int &index) {
  // std::cout << "splitting kbucket "<< index << std::endl;
  BigInt split_point = k_buckets_[index]->range_max()-
    ((k_buckets_[index]->range_max()-k_buckets_[index]->range_min())/2);
  BigInt range_min_kb_left = k_buckets_[index]->range_min();
  BigInt range_max_kb_left = split_point;
  BigInt range_min_kb_right = split_point;
  BigInt range_max_kb_right = k_buckets_[index]->range_max();
  boost::shared_ptr<KBucket> kb_left(new KBucket
      (range_min_kb_left, range_max_kb_left));
  boost::shared_ptr<KBucket> kb_right(new KBucket
      (range_min_kb_right, range_max_kb_right));
  // Getting all contacts of the kbucket to be splitted
  std::vector<Contact> contacts, ex_contacts;
  k_buckets_[index]->GetContacts(K, ex_contacts, &contacts);
  for (int i = contacts.size()-1; i > -1; i--) {
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
  // Implement Force K algorithm
  // Keep tracking the bucket of the peer and brother bucket of the peer
  if (k_buckets_[index]->KeyInRange(holder_id_)) {
    bucket_of_p_ = index;
    brother_bucket_of_p_ = index + 1;
  } else {
    bucket_of_p_ = index + 1;
    brother_bucket_of_p_ = index;
  }
}

bool RoutingTable::AddContact(const Contact &new_contact) {
  int index = KBucketIndex(new_contact.node_id());
  KBucketExitCode exitcode = k_buckets_[index]->AddContact(new_contact);
  switch (exitcode) {
    case SUCCEED: return true;
    case FULL: if (!k_buckets_[index]->KeyInRange(holder_id_))  {
                 if (index == brother_bucket_of_p_) {
                   // Force a peer always accept peers belonging to the brother
                   // bucket of the peer in case they are amongst k closet
                   // neighbours
                   return ForceKAcceptNewPeer(new_contact);
                 }
                 return false;
               }
               SplitKbucket(index);
               return AddContact(new_contact);
    case FAIL: return false;
    default: return false;
  }
}

void RoutingTable::FindCloseNodes(const std::string &key, int count,
  std::vector<Contact> *close_nodes, const std::vector<Contact>
  &exclude_contacts) {
  int index = KBucketIndex(key);
  k_buckets_[index]->GetContacts(count, exclude_contacts, close_nodes);
  if (count == static_cast<int>(close_nodes->size()))
    return;

  int i = 1;
  while ((count > static_cast<int>(close_nodes->size())) && (index-i >= 0 ||
    index+i < static_cast<int>(k_buckets_.size()))) {
    if (index-i >= 0)
      k_buckets_[index-i]->GetContacts(count-close_nodes->size(),
                                       exclude_contacts,
                                       close_nodes);
    if (index+i < static_cast<int>(k_buckets_.size())
        && (count > static_cast<int>(close_nodes->size())))
      k_buckets_[index+i]->GetContacts(count-close_nodes->size(),
                                       exclude_contacts,
                                       close_nodes);
    i++;
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

bool RoutingTable::ForceKAcceptNewPeer(const Contact &new_contact) {
  // Calculate how many k closest neighbours belong to the brother bucket of
  // the peer
  int v = K - k_buckets_[bucket_of_p_]->Size();
  if (v == 0) return false;
  // Getting all contacts of the brother kbucket of the peer
  std::vector<Contact> contacts, ex_contacts;
  k_buckets_[brother_bucket_of_p_]->GetContacts(K, ex_contacts, &contacts);
  std::list<detail::ContactWithTargetPeer> candidates_for_l;
  for (int i = 0; i < static_cast<int>(contacts.size()); i++) {
    detail::ContactWithTargetPeer entry = {contacts[i], holder_id_};
    candidates_for_l.push_back(entry);
  }
  candidates_for_l.sort(detail::compare_distance);
  // Check whether the new peer is among the v nodes
  std::list<detail::ContactWithTargetPeer>::iterator it =
    candidates_for_l.begin();
  advance(it, v-1);
  if (it == candidates_for_l.end()) return false;
  if (kademlia_distance(new_contact.node_id(), holder_id_) >=
      kademlia_distance(it->contact.node_id(), holder_id_))
    // new peer isn't among the k closest neighbours
    return false;
  // new peer is among the k closest neighbours
  // put all entries of Bp , which are not among the k closest peers into a
  // list l and drop the peer which is the least useful
  std::list<detail::ContactWithTargetPeer> l;
  for (; it != candidates_for_l.end(); it++) {
    l.push_back(*it);
  }
  Contact least_useful_contact;
  if (detail::get_least_useful_contact(l, &least_useful_contact)) {
    k_buckets_[brother_bucket_of_p_]->RemoveContact(
      least_useful_contact.node_id(), true);
    k_buckets_[brother_bucket_of_p_]->AddContact(new_contact);
    return true;
  }
  return false;
}
}  // namespace kad
