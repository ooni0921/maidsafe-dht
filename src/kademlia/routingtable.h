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
  int AddContact(const Contact &new_contact);
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
  int ForceKAcceptNewPeer(const Contact &new_contact);
};
}  // namespace kad
#endif  // KADEMLIA_ROUTINGTABLE_H_
