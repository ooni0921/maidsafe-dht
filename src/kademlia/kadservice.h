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
 *  Created on: Feb 16, 2009
 *      Author: Jose
 */
#ifndef KADEMLIA_KADSERVICE_H_
#define KADEMLIA_KADSERVICE_H_
#include <string>
#include <memory>
#include "kademlia/contact.h"
#include "protobuf/kademlia_service.pb.h"
#include "base/routingtable.h"

namespace kad {
class KademliaInterface;

struct NatDetectionData {
  std::string sender_id;
  Contact newcomer;
  std::string bootstrap_node;
  Contact node_c;
  BootstrapResponse *response;
  google::protobuf::Closure *done;
  google::protobuf::RpcController *controller;
};

struct NatDetectionPingData {
  std::string sender_id;
  NatDetectionResponse *response;
  google::protobuf::Closure *done;
  google::protobuf::RpcController *controller;
};

class KadService : public KademliaService {
 public:
  explicit KadService(KademliaInterface *knode);
  virtual void Ping(google::protobuf::RpcController *controller,
      const PingRequest *request, PingResponse *response,
      google::protobuf::Closure *done);
  virtual void FindValue(google::protobuf::RpcController *controller,
      const FindRequest *request, FindResponse *response,
      google::protobuf::Closure *done);
  virtual void FindNode(google::protobuf::RpcController *controller,
      const FindRequest *request, FindResponse *response,
      google::protobuf::Closure *done);
  virtual void Store(google::protobuf::RpcController *controller,
      const StoreRequest *request, StoreResponse *response,
      google::protobuf::Closure *done);
  virtual void Downlist(google::protobuf::RpcController *controller,
      const DownlistRequest *request, DownlistResponse *response,
      google::protobuf::Closure *done);
  virtual void NatDetection(google::protobuf::RpcController *controller,
      const NatDetectionRequest *request, NatDetectionResponse *response,
      google::protobuf::Closure *done);
  virtual void NatDetectionPing(google::protobuf::RpcController *controller,
      const NatDetectionPingRequest *request,
      NatDetectionPingResponse *response,
      google::protobuf::Closure *done);
  virtual void Bootstrap(google::protobuf::RpcController *controller,
      const BootstrapRequest *request, BootstrapResponse *response,
      google::protobuf::Closure *done);
 private:
  bool ValidateSignedRequest(const std::string &public_key, const std::string
      &signed_public_key, const std::string &signed_request, const std::string
      &key);
  bool GetSender(const ContactInfo &sender_info, Contact *sender);
  void RpcDownlist_Remove(const std::string &ser_response, Contact dead_node);
  void GetSenderAddress(const std::string &res);
  void Bootstrap_NatDetectionRv(const NatDetectionResponse *response,
      struct NatDetectionData data);
  void Bootstrap_NatDetection(const NatDetectionResponse *response,
      struct NatDetectionData data);
  void Bootstrap_NatDetectionPing(const NatDetectionPingResponse *response,
      struct NatDetectionPingData data);
  void Bootstrap_NatDetectionRzPing(
      const NatDetectionPingResponse *response,
      struct NatDetectionPingData data);
  KademliaInterface *knode_;
  // boost::shared_ptr<base::PDRoutingTableHandler> routingtable_;
  KadService(const KadService&);
  KadService& operator=(const KadService&);
};
}  // namespace
#endif  // KADEMLIA_KADSERVICE_H_
