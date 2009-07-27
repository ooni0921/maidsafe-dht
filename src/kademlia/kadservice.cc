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

#include "kademlia/kadservice.h"
#include "base/routingtable.h"
#include "kademlia/kadrpc.h"
#include "kademlia/kadutils.h"
#include "kademlia/knodeimpl.h"
#include "maidsafe/crypto.h"
#include "maidsafe/maidsafe-dht.h"
#include "maidsafe/utils.h"
#include "rpcprotocol/channelimpl.h"

namespace kad {
KadService::KadService(KNodeImpl *knode) : knode_(knode) {}

void KadService::GetSenderAddress(const std::string &res) {
  FindNodeResult result_msg;
  Contact sender_contact;
  if (result_msg.ParseFromString(res) && result_msg.has_contact() &&
      sender_contact.ParseFromString(result_msg.contact())) {
    knode_->AddContact(sender_contact, false);
  }
}

void KadService::Bootstrap_NatDetectionRv(const NatDetectionResponse *response,
                                          struct NatDetectionData data) {
  Contact sender(data.newcomer.node_id(), data.newcomer.host_ip(),
      data.newcomer.host_port(), knode_->host_ip(), knode_->host_port());
  if (response->IsInitialized()) {
    if (response->result() == kRpcResultSuccess) {
      // Node B replies to A with A's external IP and PORT and a flag stating A
      // can only be contacted via rendezvous - END
      data.response->set_nat_type(2);
    } else {
      // Node B replies to node A with a flag stating no communication} - END
      // (later we can do tunneling for clients if needed)
      data.response->set_nat_type(3);
    }
    knode_->AddContact(sender, false);
    data.done->Run();
  } else {
    data.ex_contacts.push_back(data.node_c);
    SendNatDetection(data);
  }
}

void KadService::Bootstrap_NatDetection(const NatDetectionResponse *response,
                                        struct NatDetectionData data) {
  if (response->IsInitialized()) {
    if (response->result() == kRpcResultSuccess) {
      // If true - node B replies to node A - DIRECT connected - END
      data.response->set_nat_type(1);
      // Try to get the sender's address from the local routingtable
      // if find no result in the local routingtable, do a find node
      Contact sender(data.newcomer.node_id(), data.newcomer.host_ip(),
          data.newcomer.host_port(), data.newcomer.local_ip(),
          data.newcomer.local_port());  // No rendezvous info
      knode_->AddContact(sender, false);
  //    printf("%d -- Bootstrap_NatDetection -- returning Bootstrap response\n",
  //      knode_->host_port());
      data.done->Run();
    } else {
      // Node B asks C to try a rendezvous to A with B as rendezvous
      // printf("node A is not directly connected, ");
      // printf("sending B request to ping via rend\n");
      // printf("newcomer data\n %s", data.newcomer.ToString().c_str());
      NatDetectionResponse *resp = new NatDetectionResponse();
      google::protobuf::Closure *done = google::protobuf::NewCallback<
        KadService, const NatDetectionResponse*, struct NatDetectionData>(this,
        &KadService::Bootstrap_NatDetectionRv, resp, data);
      std::string newcomer_str;
      data.newcomer.SerialiseToString(&newcomer_str);
      knode_->kadrpcs()->NatDetection(newcomer_str,
                                      data.bootstrap_node,
                                      2,
                                      knode_->node_id(),
                                      data.node_c.host_ip(),
                                      data.node_c.host_port(),
                                      resp,
                                      done);
    }
  } else {
    data.ex_contacts.push_back(data.node_c);
    SendNatDetection(data);
  }
}

void KadService::Ping(google::protobuf::RpcController *,
                      const PingRequest *request,
                      PingResponse *response,
                      google::protobuf::Closure *done) {
  Contact sender;
  if (!request->IsInitialized()) {
    response->set_result(kRpcResultFailure);
  } else if (request->ping() == "ping" &&
             GetSender(request->sender_info(), &sender)) {
    response->set_echo("pong");
    response->set_result(kRpcResultSuccess);
    knode_->AddContact(sender, false);
  } else {
    response->set_result(kRpcResultFailure);
  }
  response->set_node_id(knode_->node_id());
  done->Run();
}

void KadService::FindNode(google::protobuf::RpcController *,
                          const FindRequest *request,
                          FindResponse *response,
                          google::protobuf::Closure *done) {
  Contact sender;
//  printf("%d --- KadService::FindNode\n", knode_->host_port());
  if (!request->IsInitialized()) {
    response->set_result(kRpcResultFailure);
  } else if (GetSender(request->sender_info(), &sender)) {
    std::vector<Contact> closest_contacts, exclude_contacts;
    std::string key = request->key();
    exclude_contacts.push_back(sender);
    knode_->FindKClosestNodes(key, &closest_contacts, exclude_contacts);
    bool found_node = false;
    for (int i = 0; i < static_cast<int>(closest_contacts.size()); ++i) {
      std::string contact_str;
      closest_contacts[i].SerialiseToString(&contact_str);
      response->add_closest_nodes(contact_str);
      if (key == closest_contacts[i].node_id())
        found_node = true;
    }
    if (!found_node) {
      Contact key_node;
      if (knode_->GetContact(key, &key_node)) {
        std::string str_key_contact;
        key_node.SerialiseToString(&str_key_contact);
        response->add_closest_nodes(str_key_contact);
      }
    }
    response->set_result(kRpcResultSuccess);
    knode_->AddContact(sender, false);
  } else {
    response->set_result(kRpcResultFailure);
  }
#ifdef DEBUG
  printf("%d --- KadService::FindNode Returning response\n",
         knode_->host_port());
#endif
  response->set_node_id(knode_->node_id());
  done->Run();
}

void KadService::FindValue(google::protobuf::RpcController *controller,
                           const FindRequest *request,
                           FindResponse *response,
                           google::protobuf::Closure *done) {
  Contact sender;
  if (!request->IsInitialized()) {
    response->set_result(kRpcResultFailure);
  } else if (GetSender(request->sender_info(), &sender)) {
    // Get the values under the specified key if present in this node's data
    // store, otherwise execute find_node for this key.
    std::string key = request->key();
#ifdef DEBUG
    std::string hex_key("");
    base::encode_to_hex(key, &hex_key);
//    printf("**************************************************\n");
//    printf("Sought value in KadService::FindValue: %s\n", hex_key.c_str());
//    printf("**************************************************\n");
#endif
    std::vector<std::string> values_str;
    if (knode_->FindValueLocal(key, values_str)) {
      for (int i = 0; i < static_cast<int>(values_str.size()); i++) {
        response->add_values(values_str[i]);
      }
      response->set_result(kRpcResultSuccess);
      knode_->AddContact(sender, false);
    } else {
      FindNode(controller, request, response, done);
      return;
    }
  } else {
    response->set_result(kRpcResultFailure);
  }
  response->set_node_id(knode_->node_id());
  done->Run();
}

void KadService::Store(google::protobuf::RpcController *,
                       const StoreRequest *request,
                       StoreResponse *response,
                       google::protobuf::Closure *done) {
  Contact sender;
  if (!CheckStoreRequest(request, &sender)) {
    response->set_result(kRpcResultFailure);
  } else if (knode_->HasRSAKeys()) {
    if (!ValidateSignedRequest(request->public_key(),
                               request->signed_public_key(),
                               request->signed_request(), request->key())) {
#ifdef DEBUG
      printf("failed to validate request for kad value\n");
#endif
      response->set_result(kRpcResultFailure);
    } else {
      std::vector<std::string> curr_values;
      knode_->FindValueLocal(request->key(), curr_values);
      if (curr_values.size() != 1) {
        StoreValueLocal(request, sender, response);
      } else {
        crypto::Crypto checker;
        checker.set_hash_algorithm(crypto::SHA_512);
        std::string hash_currvalue = checker.Hash(curr_values[0], "",
            crypto::STRING_STRING, false);
        if (hash_currvalue == request->key() &&
            hash_currvalue == request->value()) {
          StoreValueLocal(request, sender, response);
        } else if (hash_currvalue != request->key()) {
          StoreValueLocal(request, sender, response);
        } else {
          response->set_result(kRpcResultFailure);
        }
      }
    }
  } else {
    StoreValueLocal(request, sender, response);
  }
  response->set_node_id(knode_->node_id());
  done->Run();
}

void KadService::Downlist(google::protobuf::RpcController *,
                          const DownlistRequest *request,
                          DownlistResponse *response,
                          google::protobuf::Closure *done) {
  Contact sender;
  if (!request->IsInitialized()) {
    response->set_result(kRpcResultFailure);
  } else if (GetSender(request->sender_info(), &sender)) {
    for (int i = 0; i < request->downlist_size(); i++) {
      Contact dead_node;
      if (!dead_node.ParseFromString(request->downlist(i)))
        continue;
    // A sophisticated attacker possibly send a random downlist. We only verify
    // the offline status of the nodes in our routing table.
      Contact contact_to_ping;
      response->set_result(kRpcResultSuccess);
      if (knode_->GetContact(dead_node.node_id(), &contact_to_ping)) {
        knode_->Ping(dead_node, boost::bind(&KadService::RpcDownlist_Remove,
            this, _1, dead_node));
      }
    }
    knode_->AddContact(sender, false);
  } else {
    response->set_result(kRpcResultFailure);
  }
  response->set_node_id(knode_->node_id());
  done->Run();
}

bool KadService::ValidateSignedRequest(const std::string &public_key,
                                       const std::string &signed_public_key,
                                       const std::string &signed_request,
                                       const std::string &key) {
  if (signed_request == kAnonymousSignedRequest)
    return true;
  crypto::Crypto checker;
  checker.set_symm_algorithm(crypto::AES_256);
  if (checker.AsymCheckSig(public_key, signed_public_key, public_key,
                           crypto::STRING_STRING)) {
    checker.set_hash_algorithm(crypto::SHA_512);
//    std::string encoded_key("");
//    base::encode_to_hex(key, &encoded_key);
    return checker.AsymCheckSig(checker.Hash(public_key + signed_public_key +
      key, "", crypto::STRING_STRING, true), signed_request, public_key,
      crypto::STRING_STRING);
  } else {
#ifdef DEBUG
    printf("failed to check sig KadService::ValidateSignedRequest\n");
#endif
    return false;
  }
}

bool KadService::GetSender(const ContactInfo &sender_info, Contact *sender) {
  std::string ser_info;
  sender_info.SerializeToString(&ser_info);
  return sender->ParseFromString(ser_info);
}

void KadService::RpcDownlist_Remove(const std::string &ser_response,
                                    Contact dead_node) {
  PingResponse result_msg;
  if (!result_msg.ParseFromString(ser_response) ||
      (result_msg.result() == kRpcResultFailure)) {
    knode_->RemoveContact(dead_node.node_id());
  }
}

void KadService::Bootstrap_NatDetectionPing(
    const NatDetectionPingResponse *response,
    struct NatDetectionPingData data) {
  if (response->IsInitialized() && response->result() == kRpcResultSuccess) {
    data.response->set_result(kRpcResultSuccess);
  } else {
    data.response->set_result(kRpcResultFailure);
  }
//  printf("%d --- Bootstrap_NatDetectionPingreturning NatDetection response\n",
//      knode_->host_port());
  data.done->Run();
}

void KadService::Bootstrap_NatDetectionRzPing(
    const NatDetectionPingResponse *response,
    struct NatDetectionPingData data) {
  Bootstrap_NatDetectionPing(response, data);
}

void KadService::NatDetection(google::protobuf::RpcController *controller,
                              const NatDetectionRequest *request,
                              NatDetectionResponse *response,
                              google::protobuf::Closure *done) {
//  printf("%d --- KadService::NatDetection\n", knode_->host_port());
  if (request->IsInitialized()) {
    if (request->type() == 1) {
      // C tries to ping A
      Contact node_a;
      if (node_a.ParseFromString(request->newcomer())) {
        NatDetectionPingResponse *resp = new NatDetectionPingResponse();
        struct NatDetectionPingData data = {request->sender_id(), response,
                                            done, controller};
        google::protobuf::Closure *done =
            google::protobuf::NewCallback<KadService,
            const NatDetectionPingResponse*, struct NatDetectionPingData>
            (this, &KadService::Bootstrap_NatDetectionPing, resp, data);
        knode_->kadrpcs()->NatDetectionPing(node_a.host_ip(),
            node_a.host_port(), resp, done);
        return;
      }
    } else if (request->type() == 2) {
      // C tries a rendezvous to A with B as rendezvous
      Contact node_b;
      Contact node_a;
      if (node_a.ParseFromString(request->newcomer()) &&
          node_b.ParseFromString(request->bootstrap_node()) &&
          node_a.node_id() != client_node_id()) {
        knode_->AddContact(node_a, true);
        NatDetectionPingResponse *resp = new NatDetectionPingResponse();
        struct NatDetectionPingData data =
          {request->sender_id(), response, done, controller};
        google::protobuf::Closure *done =
          google::protobuf::NewCallback<KadService,
            const NatDetectionPingResponse*,
            struct NatDetectionPingData>(this,
              &KadService::Bootstrap_NatDetectionRzPing,
              resp,
              data);
        knode_->kadrpcs()->NatDetectionPing(node_a.host_ip(),
          node_a.host_port(), resp, done);
        return;
      }
    }
  }
  response->set_result(kRpcResultFailure);
  done->Run();
}

void KadService::NatDetectionPing(google::protobuf::RpcController *,
                                  const NatDetectionPingRequest *request,
                                  NatDetectionPingResponse *response,
                                  google::protobuf::Closure *done) {
  Contact sender;
  if (!request->IsInitialized()) {
    response->set_result(kRpcResultFailure);
  } else if (request->ping() == "nat_detection_ping" &&
             GetSender(request->sender_info(), &sender)) {
    response->set_echo("pong");
    response->set_result(kRpcResultSuccess);
    knode_->AddContact(sender, false);
  } else {
    response->set_result(kRpcResultFailure);
  }
//  printf("%d -- KadService::NatDetectionPing returning response\n",
//    knode_->host_port());
  response->set_node_id(knode_->node_id());
  done->Run();
}

void KadService::Bootstrap(google::protobuf::RpcController *controller,
                           const BootstrapRequest *request,
                           BootstrapResponse *response,
                           google::protobuf::Closure *done) {
//  printf("%d -- KadService::Bootstrap\n", knode_->host_port());
  if (!request->IsInitialized()) {
    // Can we reply? This is a bootstrapping message from a newcomer,
    // Can we find any contact from the local/network routingtable?
    return;
  }
  // Checking if it is a client to return its external ip/port
  if (request->newcomer_id() == client_node_id()) {
    response->set_bootstrap_id(knode_->node_id());
    response->set_newcomer_ext_ip(request->newcomer_ext_ip());
    response->set_newcomer_ext_port(request->newcomer_ext_port());
    response->set_result(kRpcResultSuccess);
    done->Run();
    return;
  }
  Contact newcomer;
  // set rendezvous IP/Port
  if (request->newcomer_ext_ip() == request->newcomer_local_ip()
      &&request->newcomer_ext_port() == request->newcomer_local_port()) {
    // Newcomer is directly connected to the Internet
    newcomer = Contact(request->newcomer_id(),
                       request->newcomer_local_ip(),
                       request->newcomer_local_port(),
                       request->newcomer_local_ip(),
                       request->newcomer_local_port());
  } else {
    // Behind firewall
    newcomer = Contact(request->newcomer_id(),
                       request->newcomer_ext_ip(),
                       request->newcomer_ext_port(),
                       request->newcomer_local_ip(),
                       request->newcomer_local_port(),
                       knode_->host_ip(),
                       knode_->host_port());
  }
  response->set_bootstrap_id(knode_->node_id());
  response->set_newcomer_ext_ip(request->newcomer_ext_ip());
  response->set_newcomer_ext_port(request->newcomer_ext_port());
  response->set_result(kRpcResultSuccess);

  Contact this_node(knode_->node_id(), knode_->host_ip(),
      knode_->host_port(), knode_->local_host_ip(), knode_->local_host_port(),
      knode_->rv_ip(), knode_->rv_port());
  std::string this_node_str;
  this_node.SerialiseToString(&this_node_str);
  Contact node_c;
  std::vector<Contact> ex_contacs;
  ex_contacs.push_back(newcomer);
  struct NatDetectionData data = {newcomer, this_node_str, node_c,
      response, done, controller, ex_contacs};
  SendNatDetection(data);
//  // Node C - is any random node B knows of.
//  std::vector<Contact> exclude_contacts;
//  std::vector<Contact> random_contacts;
//  knode_->GetRandomContacts(1, exclude_contacts, &random_contacts);
//  // printf("newcomer \n%s", newcomer.ToString().c_str());
//  if (random_contacts.size() == 1
//      && random_contacts.front() != newcomer ) {
//    Contact node_c = random_contacts.front();
//    // printf("node c\n%s", node_c.ToString().c_str());
//    // Node B asks C to try ping A
//    Contact this_node(knode_->node_id(), knode_->host_ip(),
//      knode_->host_port(), knode_->local_host_ip(), knode_->local_host_port(),
//      knode_->rv_ip(), knode_->rv_port());
//    std::string this_node_str;
//    this_node.SerialiseToString(&this_node_str);
//    std::string newcomer_str;
//    newcomer.SerialiseToString(&newcomer_str);
//    struct NatDetectionData data = {/*newcomer.node_id(), */newcomer,
//      this_node_str, node_c, response, done, controller};
//    NatDetectionResponse *resp = new NatDetectionResponse();
//    google::protobuf::Closure *done1 = google::protobuf::NewCallback<
//      KadService, const NatDetectionResponse*, struct NatDetectionData>(this,
//      &KadService::Bootstrap_NatDetection, resp, data);
//    knode_->kadrpcs()->NatDetection(newcomer_str,
//                                    this_node_str,
//                                    1,
//                                    knode_->node_id(),
//                                    node_c.host_ip(),
//                                    node_c.host_port(),
//                                    resp,
//                                    done1);
//  } else {
//    if (typeid(*controller) == typeid(rpcprotocol::Controller)) {
//      rpcprotocol::Controller* rpc_controller =
//        dynamic_cast<rpcprotocol::Controller*>(controller);  // NOLINT
//      rpc_controller->set_remote_ip(newcomer.host_ip());
//      rpc_controller->set_remote_port(newcomer.host_port());
//    }
//    // printf("still no random nodes\n");
//    done->Run();
//  }
}

void KadService::SendNatDetection(struct NatDetectionData data) {
  std::vector<Contact> random_contacts;
  knode_->GetRandomContacts(1, data.ex_contacts, &random_contacts);
  if (random_contacts.size() != 1) {
    if (data.ex_contacts.size() > 1)
      data.response->set_result(kRpcResultFailure);
//    printf("%d -- SendNatDetection -- returning Bootstrap response\n",
//      knode_->host_port());
    data.done->Run();
  } else {
    Contact node_c = random_contacts.front();
    data.node_c = node_c;
//     printf("node c %s", node_c.ToString().c_str());
    // Node B asks C to try ping A
    std::string newcomer_str;
    data.newcomer.SerialiseToString(&newcomer_str);
    NatDetectionResponse *resp = new NatDetectionResponse();
    google::protobuf::Closure *done = google::protobuf::NewCallback<
      KadService, const NatDetectionResponse*, struct NatDetectionData>(this,
      &KadService::Bootstrap_NatDetection, resp, data);
    knode_->kadrpcs()->NatDetection(newcomer_str,
                                    data.bootstrap_node,
                                    1,
                                    knode_->node_id(),
                                    node_c.host_ip(),
                                    node_c.host_port(),
                                    resp,
                                    done);
  }
}

bool KadService::CheckStoreRequest(const StoreRequest *request,
      Contact *sender) {
  if (!request->IsInitialized())
    return false;
  if (knode_->HasRSAKeys())
    if (!request->has_public_key() || !request->has_signed_public_key() ||
        !request->has_signed_request())
      return false;
  return GetSender(request->sender_info(), sender);
}

void KadService::StoreValueLocal(const StoreRequest *request, Contact sender,
      StoreResponse *response) {
  if (knode_->StoreValueLocal(request->key(), request->value(),
      request->publish(), request->ttl())) {
    response->set_result(kRpcResultSuccess);
    knode_->AddContact(sender, false);
  } else {
    response->set_result(kRpcResultFailure);
  }
}

}  // namespace kad
