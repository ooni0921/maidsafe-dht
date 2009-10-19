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

#include "maidsafe/config.h"
#include "kademlia/kadservice.h"
#include "kademlia/kadrpc.h"
#include "kademlia/kadutils.h"
#include "kademlia/knodeimpl.h"
#include "kademlia/datastore.h"
#include "maidsafe/alternativestore.h"
#include "maidsafe/knode.h"
#include "maidsafe/channel.h"
#include "protobuf/signed_kadvalue.pb.h"

namespace kad {

static void downlist_ping_cb(const std::string&) {}

KadService::KadService(const NatRpcs &nat_rpcs,
      boost::shared_ptr<DataStore> datastore, const bool &hasRSAkeys,
      add_contact_function add_cts, get_random_contacts_function rand_cts,
      get_contact_function get_ctc, get_closestK_function get_kcts,
      ping_function ping) : nat_rpcs_(nat_rpcs), pdatastore_(datastore),
      node_joined_(false), node_hasRSAkeys_(hasRSAkeys), node_info_(),
      alternative_store_(NULL), add_contact_(add_cts),
      get_random_contacts_(rand_cts), get_contact_(get_ctc),
      get_closestK_contacts_(get_kcts), ping_(ping) {}

void KadService::Bootstrap_NatDetectionRv(const NatDetectionResponse *response,
      struct NatDetectionData data) {
  Contact sender(data.newcomer.node_id(), data.newcomer.host_ip(),
      data.newcomer.host_port(), node_info_.ip(), node_info_.port());
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
    if (data.controller != NULL) {
      add_contact_(sender, data.controller->rtt(), false);
    } else {
      add_contact_(sender, 0.0, false);
    }
    delete response;
    if (data.controller != NULL) {
      delete data.controller;
      data.controller = NULL;
    }
    data.done->Run();
  } else {
    data.ex_contacts.push_back(data.node_c);
    if (data.controller != NULL) {
      delete data.controller;
      data.controller = NULL;
    }
    delete response;
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
      if (data.controller != NULL) {
        add_contact_(sender, data.controller->rtt(), false);
      } else {
        add_contact_(sender, 0.0, false);
      }
      delete data.controller;
      data.controller = NULL;
      data.done->Run();
    } else {
      // Node B asks C to try a rendezvous to A with B as rendezvous
      NatDetectionResponse *resp = new NatDetectionResponse;
      google::protobuf::Closure *done = google::protobuf::NewCallback<
        KadService, const NatDetectionResponse*, struct NatDetectionData>(this,
        &KadService::Bootstrap_NatDetectionRv, resp, data);
      std::string newcomer_str;
      data.newcomer.SerialiseToString(&newcomer_str);
      // no need to send using rendezvous server of node C because it has
      // already made contact with it, it can connect to it directly
      nat_rpcs_.NatDetection(newcomer_str, data.bootstrap_node, 2,
          node_info_.node_id(), data.node_c.host_ip(), data.node_c.host_port(),
          "", 0, resp, data.controller, done);
    }
  } else {
    delete data.controller;
    data.controller = NULL;
    data.ex_contacts.push_back(data.node_c);
    SendNatDetection(data);
  }
  delete response;
}

void KadService::Ping(google::protobuf::RpcController *controller,
      const PingRequest *request, PingResponse *response,
      google::protobuf::Closure *done) {
  if (!node_joined_) {
    response->set_result(kRpcResultFailure);
    done->Run();
    return;
  }
  Contact sender;
  if (!request->IsInitialized()) {
    response->set_result(kRpcResultFailure);
  } else if (request->ping() == "ping" &&
             GetSender(request->sender_info(), &sender)) {
    response->set_echo("pong");
    response->set_result(kRpcResultSuccess);
    rpcprotocol::Controller *ctrl = static_cast<rpcprotocol::Controller*>
        (controller);
    if (ctrl != NULL) {
      add_contact_(sender, ctrl->rtt(), false);
    } else {
      add_contact_(sender, 0.0, false);
    }
  } else {
    response->set_result(kRpcResultFailure);
  }
  response->set_node_id(node_info_.node_id());
  done->Run();
}

void KadService::FindNode(google::protobuf::RpcController *controller,
      const FindRequest *request, FindResponse *response,
      google::protobuf::Closure *done) {
  if (!node_joined_) {
    response->set_result(kRpcResultFailure);
    done->Run();
    return;
  }
  Contact sender;
  if (!request->IsInitialized()) {
    response->set_result(kRpcResultFailure);
  } else if (GetSender(request->sender_info(), &sender)) {
    std::vector<Contact> closest_contacts, exclude_contacts;
    std::string key = request->key();
    exclude_contacts.push_back(sender);
    get_closestK_contacts_(key, &closest_contacts, exclude_contacts);
    bool found_node = false;
    for (unsigned int i = 0; i < closest_contacts.size(); ++i) {
      std::string contact_str;
      closest_contacts[i].SerialiseToString(&contact_str);
      response->add_closest_nodes(contact_str);
      if (key == closest_contacts[i].node_id())
        found_node = true;
    }
    if (!found_node) {
      Contact key_node;
      if (get_contact_(key, &key_node)) {
        std::string str_key_contact;
        key_node.SerialiseToString(&str_key_contact);
        response->add_closest_nodes(str_key_contact);
      }
    }
    response->set_result(kRpcResultSuccess);
    rpcprotocol::Controller *ctrl = static_cast<rpcprotocol::Controller*>
        (controller);
    if (ctrl != NULL) {
      add_contact_(sender, ctrl->rtt(), false);
    } else {
      add_contact_(sender, 0.0, false);
    }
  } else {
    response->set_result(kRpcResultFailure);
  }
  response->set_node_id(node_info_.node_id());
  done->Run();
}

void KadService::FindValue(google::protobuf::RpcController *controller,
      const FindRequest *request, FindResponse *response,
      google::protobuf::Closure *done) {
  if (!node_joined_) {
    response->set_result(kRpcResultFailure);
    done->Run();
    return;
  }
  Contact sender;
  if (!request->IsInitialized()) {
    response->set_result(kRpcResultFailure);
  } else if (GetSender(request->sender_info(), &sender)) {
    // If the value exists in the alternative store, add our contact details to
    // field alternative_value_holder.  If not, get the values if present in
    // this node's data store, otherwise execute find_node for this key.
    std::string key = request->key();
    std::vector<std::string> values_str;
    if (alternative_store_ != NULL) {
      if (alternative_store_->Has(key)) {
        *(response->mutable_alternative_value_holder()) = node_info_;
        response->set_result(kRpcResultSuccess);
        response->set_node_id(node_info_.node_id());
        done->Run();
        return;
      }
    }
    if (pdatastore_->LoadItem(key, &values_str)) {
      if (node_hasRSAkeys_) {
        for (unsigned int i = 0; i < values_str.size(); i++) {
          SignedValue signed_value;
          if (signed_value.ParseFromString(values_str[i]))
            response->add_values(signed_value.value());
        }
      } else {
        for (unsigned int i = 0; i < values_str.size(); i++)
          response->add_values(values_str[i]);
      }
      response->set_result(kRpcResultSuccess);
      rpcprotocol::Controller *ctrl = static_cast<rpcprotocol::Controller*>
        (controller);
      if (ctrl != NULL) {
        add_contact_(sender, ctrl->rtt(), false);
      } else  {
        add_contact_(sender, 0.0, false);
      }
    } else {
      FindNode(controller, request, response, done);
      return;
    }
  } else {
    response->set_result(kRpcResultFailure);
  }
  response->set_node_id(node_info_.node_id());
  done->Run();
}

void KadService::Store(google::protobuf::RpcController *controller,
      const StoreRequest *request, StoreResponse *response,
      google::protobuf::Closure *done) {
  if (!node_joined_) {
    response->set_result(kRpcResultFailure);
    done->Run();
    return;
  }
  Contact sender;
  rpcprotocol::Controller *ctrl = static_cast<rpcprotocol::Controller*>
        (controller);
  if (!CheckStoreRequest(request, &sender)) {
    response->set_result(kRpcResultFailure);
  } else if (node_hasRSAkeys_) {
    if (!ValidateSignedRequest(request->public_key(),
        request->signed_public_key(), request->signed_request(),
        request->key())) {
      DLOG(WARNING) << "Failed to validate Store request for kad value"
           << std::endl;
      response->set_result(kRpcResultFailure);
    } else {
      StoreValueLocal(request->key(), request->sig_value(), sender,
          request->ttl(), request->publish(), response, ctrl);
    }
  } else {
    StoreValueLocal(request->key(), request->value(), sender, request->ttl(),
        request->publish(), response, ctrl);
  }
  response->set_node_id(node_info_.node_id());
  done->Run();
}

void KadService::Downlist(google::protobuf::RpcController *controller,
      const DownlistRequest *request, DownlistResponse *response,
      google::protobuf::Closure *done) {
  if (!node_joined_) {
    response->set_result(kRpcResultFailure);
    done->Run();
    return;
  }
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
      if (get_contact_(dead_node.node_id(), &contact_to_ping)) {
        ping_(dead_node, boost::bind(&downlist_ping_cb, _1));
      }
    }
    rpcprotocol::Controller *ctrl = static_cast<rpcprotocol::Controller*>
        (controller);
    if (ctrl != NULL) {
      add_contact_(sender, ctrl->rtt(), false);
    } else {
      add_contact_(sender, 0.0, false);
    }
  } else {
    response->set_result(kRpcResultFailure);
  }
  response->set_node_id(node_info_.node_id());
  done->Run();
}

bool KadService::ValidateSignedRequest(const std::string &public_key,
      const std::string &signed_public_key, const std::string &signed_request,
      const std::string &key) {
  if (signed_request == kAnonymousSignedRequest)
    return true;
  crypto::Crypto checker;
  checker.set_symm_algorithm(crypto::AES_256);
  checker.set_hash_algorithm(crypto::SHA_512);
  return checker.AsymCheckSig(checker.Hash(public_key + signed_public_key + key,
      "", crypto::STRING_STRING, true), signed_request, public_key,
      crypto::STRING_STRING);
}

bool KadService::GetSender(const ContactInfo &sender_info, Contact *sender) {
  std::string ser_info;
  sender_info.SerializeToString(&ser_info);
  return sender->ParseFromString(ser_info);
}

void KadService::Bootstrap_NatDetectionPing(
    const NatDetectionPingResponse *response,
    struct NatDetectionPingData data) {
  if (response->IsInitialized() && response->result() == kRpcResultSuccess) {
    data.response->set_result(kRpcResultSuccess);
  } else {
    data.response->set_result(kRpcResultFailure);
  }
  delete data.controller;
  delete response;
  data.done->Run();
}

void KadService::Bootstrap_NatDetectionRzPing(
    const NatDetectionPingResponse *response,
    struct NatDetectionPingData data) {
  Bootstrap_NatDetectionPing(response, data);
}

void KadService::NatDetection(google::protobuf::RpcController *,
      const NatDetectionRequest *request, NatDetectionResponse *response,
      google::protobuf::Closure *done) {
  if (request->IsInitialized()) {
    if (request->type() == 1) {
      // C tries to ping A
      Contact node_a;
      if (node_a.ParseFromString(request->newcomer())) {
        NatDetectionPingResponse *resp = new NatDetectionPingResponse;
        struct NatDetectionPingData data = {request->sender_id(), response,
            done, NULL};
        data.controller = new rpcprotocol::Controller;
        google::protobuf::Closure *done =
            google::protobuf::NewCallback<KadService,
            const NatDetectionPingResponse*, struct NatDetectionPingData>
            (this, &KadService::Bootstrap_NatDetectionPing, resp, data);
        nat_rpcs_.NatDetectionPing(node_a.host_ip(), node_a.host_port(), "", 0,
            resp, data.controller, done);
        return;
      }
    } else if (request->type() == 2) {
      // C tries a rendezvous to A with B as rendezvous
      Contact node_b;
      Contact node_a;
      if (node_a.ParseFromString(request->newcomer()) &&
          node_b.ParseFromString(request->bootstrap_node()) &&
          node_a.node_id() != client_node_id()) {
        NatDetectionPingResponse *resp = new NatDetectionPingResponse;
        struct NatDetectionPingData data =
          {request->sender_id(), response, done, NULL};
        data.controller = new rpcprotocol::Controller;
        google::protobuf::Closure *done =
          google::protobuf::NewCallback<KadService,
            const NatDetectionPingResponse*,
            struct NatDetectionPingData>(this,
              &KadService::Bootstrap_NatDetectionRzPing,
              resp,
              data);
        nat_rpcs_.NatDetectionPing(node_a.host_ip(), node_a.host_port(),
            node_a.rendezvous_ip(), node_a.rendezvous_port(), resp,
            data.controller, done);
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
  } else if (request->ping() == "nat_detection_ping") {
    response->set_echo("pong");
    response->set_result(kRpcResultSuccess);
  } else {
    response->set_result(kRpcResultFailure);
  }
  response->set_node_id(node_info_.node_id());
  done->Run();
}

void KadService::Bootstrap(google::protobuf::RpcController *,
      const BootstrapRequest *request, BootstrapResponse *response,
      google::protobuf::Closure *done) {
  if (!request->IsInitialized() || !node_joined_) {
    response->set_result(kRpcResultFailure);
    done->Run();
    return;
  }
  // Checking if it is a client to return its external ip/port
  if (request->newcomer_id() == client_node_id()) {
    response->set_bootstrap_id(node_info_.node_id());
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
    newcomer = Contact(request->newcomer_id(), request->newcomer_local_ip(),
        request->newcomer_local_port(), request->newcomer_local_ip(),
        request->newcomer_local_port());
  } else {
    // Behind firewall
    newcomer = Contact(request->newcomer_id(), request->newcomer_ext_ip(),
          request->newcomer_ext_port(), request->newcomer_local_ip(),
          request->newcomer_local_port(), node_info_.ip(), node_info_.port());
  }
  response->set_bootstrap_id(node_info_.node_id());
  response->set_newcomer_ext_ip(request->newcomer_ext_ip());
  response->set_newcomer_ext_port(request->newcomer_ext_port());
  response->set_result(kRpcResultSuccess);

  std::string this_node_str = node_info_.SerializeAsString();
  Contact node_c;
  std::vector<Contact> ex_contacs;
  ex_contacs.push_back(newcomer);
  struct NatDetectionData data = {newcomer, this_node_str, node_c,
      response, done, NULL, ex_contacs};
  SendNatDetection(data);
}

void KadService::SendNatDetection(struct NatDetectionData data) {
  std::vector<Contact> random_contacts;
  get_random_contacts_(1, data.ex_contacts, &random_contacts);
  if (random_contacts.size() != 1) {
    if (data.ex_contacts.size() > 1) {
      data.response->set_result(kRpcResultFailure);
    }
    data.done->Run();
  } else {
    Contact node_c = random_contacts.front();
    data.node_c = node_c;
    // Node B asks C to try ping A
    std::string newcomer_str;
    data.newcomer.SerialiseToString(&newcomer_str);
    data.controller = new rpcprotocol::Controller;
    NatDetectionResponse *resp = new NatDetectionResponse;
    google::protobuf::Closure *done = google::protobuf::NewCallback<
      KadService, const NatDetectionResponse*, struct NatDetectionData>(this,
      &KadService::Bootstrap_NatDetection, resp, data);
    nat_rpcs_.NatDetection(newcomer_str, data.bootstrap_node, 1,
        node_info_.node_id(), node_c.host_ip(), node_c.host_port(),
        node_c.rendezvous_ip(), node_c.rendezvous_port(), resp,
        data.controller, done);
  }
}

bool KadService::CheckStoreRequest(const StoreRequest *request,
      Contact *sender) {
  if (!request->IsInitialized())
    return false;
  if (node_hasRSAkeys_) {
    if (!request->has_public_key() || !request->has_signed_public_key() ||
        !request->has_signed_request() || !request->has_sig_value())
      return false;
  } else {
    if (!request->has_value())
      return false;
  }
  return GetSender(request->sender_info(), sender);
}

void KadService::StoreValueLocal(const std::string &key,
      const std::string &value, Contact sender, const boost::uint32_t &ttl,
      const bool &publish, StoreResponse *response,
      rpcprotocol::Controller *ctrl) {
  bool result;
  if (publish) {
    result = pdatastore_->StoreItem(key, value, ttl, false);
  } else {
    result = pdatastore_->RefreshItem(key, value);
    if (!result)
      result = pdatastore_->StoreItem(key, value, ttl, false);
  }
  if (result) {
    response->set_result(kRpcResultSuccess);
    if (ctrl != NULL) {
      add_contact_(sender, ctrl->rtt(), false);
    } else {
      add_contact_(sender, 0.0, false);
    }
  } else {
    response->set_result(kRpcResultFailure);
  }
}

void KadService::StoreValueLocal(const std::string &key,
      const SignedValue &value, Contact sender, const boost::uint32_t &ttl,
      const bool &publish, StoreResponse *response,
      rpcprotocol::Controller *ctrl) {
  bool result, hashable;
  std::string ser_value = value.SerializeAsString();
  if (publish) {
    if (CanStoreSignedValueHashable(key, ser_value, &hashable))
      result = pdatastore_->StoreItem(key, ser_value, ttl, hashable);
    else
      result = false;
  } else {
    result = pdatastore_->RefreshItem(key, ser_value);
    if (!result && CanStoreSignedValueHashable(key, ser_value, &hashable))
      result = pdatastore_->StoreItem(key, ser_value, ttl, hashable);
  }
  if (result) {
    response->set_result(kRpcResultSuccess);
    if (ctrl != NULL) {
      add_contact_(sender, ctrl->rtt(), false);
    } else {
      add_contact_(sender, 0.0, false);
    }
  } else {
    response->set_result(kRpcResultFailure);
  }
}

bool KadService::CanStoreSignedValueHashable(const std::string &key,
      const std::string &value, bool *hashable) {
  std::vector< std::pair<std::string, bool> > attr;
  attr = pdatastore_->LoadKeyAppendableAttr(key);
  *hashable = false;
  if (attr.empty()) {
    crypto::Crypto cobj;
    cobj.set_hash_algorithm(crypto::SHA_512);
    if (key == cobj.Hash(value, "", crypto::STRING_STRING, false))
      *hashable = true;
  } else if (attr.size() == 1) {
    *hashable = attr[0].second;
    if (*hashable && value != attr[0].first)
      return false;
  }
  return true;
}
}  // namespace kad
