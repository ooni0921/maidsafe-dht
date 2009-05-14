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

#ifndef KADEMLIA_ROUTINGTABLE_H_
#define KADEMLIA_ROUTINGTABLE_H_

#include <boost/mp_math/mp_int.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/cstdint.hpp>
#include <string>
#include <vector>
#include <list>

namespace kad {
class KBucket;
class Contact;

class RoutingTable {
 public:
  explicit RoutingTable(const std::string &holder_id);
  ~RoutingTable();
  // Add the given contact to the correct k-bucket; if it already
  // exists, its status will be updated
  bool AddContact(const Contact &new_contact);
  // Returns true and the contact if it is stored in one Kbucket
  // otherwise it returns false
  bool GetContact(const std::string &node_id, Contact *contact);
  // Remove the contact with the specified node ID from the routing table
  void RemoveContact(const std::string &node_id, const bool &force);
  // Update the "last accessed" timestamp of the k-bucket which covers
  // the range containing the specified key in the key/ID space
  void TouchKBucket(const std::string &node_id);
  // Finds a number of known nodes closest to the node/value with the
  // specified key.
  void FindCloseNodes(const std::string &key, int count,
      std::vector<Contact> *close_nodes,
      const std::vector<Contact> &exclude_contacts);
  // Finds all k-buckets that need refreshing, starting at the k-bucket with
  // the specified index, and returns IDs to be searched for in order to
  // refresh those k-buckets
  void GetRefreshList(std::vector<std::string> *ids,
      const int &start_kbucket, const bool &force);
  // Get all contacts of a specified k_bucket
  bool GetContacts(const int &index, std::vector<Contact> *contacts,
    const std::vector<Contact> &exclude_contacts);
  int KbucketSize() const;
  int Size() const;
  void Clear();

 private:
  std::vector< boost::shared_ptr<KBucket> > k_buckets_;
  std::string holder_id_;  // holder's node_id
  int bucket_of_p_;
  int brother_bucket_of_p_;
  // Calculate the index of the k-bucket which is responsible for the specified
  // key (or ID)
  int KBucketIndex(const std::string &key);
  // Split the kbucket in the specified index into two new ones
  void SplitKbucket(const int &index);
  bool ForceKAcceptNewPeer(const Contact &new_contact);
};
}  // namespace kad
#endif  // KADEMLIA_ROUTINGTABLE_H_
