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

#ifndef KADEMLIA_KBUCKET_H_
#define KADEMLIA_KBUCKET_H_

#include <list>
#include <vector>
#include <string>
#include "kademlia/kademlia.h"


namespace kad {

class Contact;

class KBucket {
 public:
  // The lower and upper boundary for the range in the 160-bit ID
  // space covered by this k-bucket
  KBucket(const BigInt &range_min, const BigInt &range_max);
  ~KBucket();
  // add a new contact to the k-bucket
  KBucketExitCode AddContact(const Contact &new_contact);
  // return an existing contact pointer with the specified node_id
  bool GetContact(const std::string &node_id, Contact *contact);
  // Returns a list containing up to the first count number of contacts
  // excluding the list of contacts provided.
  void GetContacts(int count, const std::vector<Contact> &exclude_contacts,
      std::vector<Contact> *contacts);
  // remove the existing contact with the specified node_id
  void RemoveContact(const std::string &node_id, const bool &force);
  // Tests whether the specified key (i.e. node ID) is in the range
  // of the 160-bit ID space covered by this k-bucket (in otherwords, it
  // returns whether or not the specified key should be placed in this
  // k-bucket)
  bool KeyInRange(const std::string &key);
  // return the number of contacts in this k-bucket
  int Size() const;
  boost::uint32_t last_accessed() const;
  void set_last_accessed(const boost::uint32_t &time_accessed);
  BigInt range_min() const;
  BigInt range_max() const;

 private:
  boost::uint32_t last_accessed_;
  std::list<Contact> contacts_;
  BigInt range_min_;
  BigInt range_max_;
};
}  // namespace kad

#endif  // KADEMLIA_KBUCKET_H_
