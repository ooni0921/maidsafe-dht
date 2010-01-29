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

/*******************************************************************************
 * This is the API for maidsafe-dht and is the only program access for         *
 * developers.  The maidsafe-dht_config.h file included is where configuration *
 * may be saved.  You MUST link the maidsafe-dht library.                      *
 *                                                                             *
 * NOTE: These APIs may be amended or deleted in future releases until this    *
 * notice is removed.                                                          *
 ******************************************************************************/

#ifndef MAIDSAFE_CHANNELMANAGER_API_H_
#define MAIDSAFE_CHANNELMANAGER_API_H_

#include <string>
#include "maidsafe/maidsafe-dht_config.h"

#if MAIDSAFE_DHT_VERSION < 15
#error This API is not compatible with the installed library.
#error Please update the maidsafe-dht library.
#endif

// RPC
namespace rpcprotocol {

class RpcMessage;

// Ensure that a one-to-one relationship is maintained between channelmanager &
// knode.
/**
* @class ChannelManager
* This object is responsible for handling the RPC messages that come in through
* the Transport object and handle them accordingly to their type: REQUEST or
* RESPONSE.  It also keeps all the pending requests of the RPCs sent and makes
* sure to call the response when the response arrives or the time set for
* timeout expires.
* Ensure that a one-to-one relationship is maintained between ChannelManager
* and KNode.
*/

class ChannelManager {
 public:
  /**
  * Constructor
  * @param ptransport_handler Pointer to a transport handler object.
  */
  explicit ChannelManager(transport::TransportHandler *ptrans_handler);
  ~ChannelManager();
  /**
  * Registers a channel and identifies it with the name of the RPC service that
  * uses that Channel to receive requests.
  * @param service_name name that identifies the channel
  * @param channel pointer to a Channel object
  */
  void RegisterChannel(const std::string &service_name, Channel* channel);
  /**
  * Removes a previously registered channel.
  * @param service_name name that identifies the channel
  */
  void UnRegisterChannel(const std::string &service_name);
  /**
  * Removes all the channels that have been registered.
  */
  void ClearChannels();
  /**
  * Clears the list of all RPC requests sent that are waiting for their response
  * and have not time out.
  */
  void ClearCallLaters();
  /**
  * Sets status as not stopped if the Transport object has been started.
  * @return 0 if success otherwise 1
  */
  int Start();
  /**
  * Sets status of the ChannelManager as stopped and clears pending requests
  * and registered channels.
  * @return 1 if success and 0 if the status when called was stopped.
  */
  int Stop();
  /**
  * Registeres the notifier to receive RPC messages with the Transport object
  * and the notifier to now when a message has been sent.
  * @return True if it succeeds in registering the notifiers, False otherwise
  */
  bool RegisterNotifiersToTransport();
  /**
  * Creates a new id for the pending requests.
  * @return the id created
  */
  boost::uint32_t CreateNewId();
  /**
  * Adds a new pending request after an RPC has been sent.
  * @param req_id id to identify the request
  * @param req structure holding all the information of the request
  */
  void AddPendingRequest(const boost::uint32_t &req_id, PendingReq req);
  /**
  * Removes a pending request from the list and calls the callback of the
  * request with status Cancelled.
  * @param req_id id of the request
  * @return True if success, False if status of the object is stopped or
  * no request was found for the id.
  */
  bool DeletePendingRequest(const boost::uint32_t &req_id);
  /**
  * Removes a pending request from the list.
  * @param req_id id of the request
  * @return True if success, False if status of the object is stopped or
  * no request was found for the id.
  */
  bool CancelPendingRequest(const boost::uint32_t &req_id);
  /**
  * Adds a request to the timer to check when it times out.
  * @param req_id id of the request
  * @param timeout milliseconds after which the request times out
  */
  void AddReqToTimer(const boost::uint32_t &req_id, const int &timeout);
  /**
  * Adds a request to a list that holds all request that haven't been
  * completely sent via the transport.
  * @param connection_id id of the connection used to send the request
  * @param req_id id of the request
  * @param timeout milliseconds after which the request times out
  */
  void AddTimeOutRequest(const boost::uint32_t &connection_id,
    const boost::uint32_t &req_id, const int &timeout);
  /**
  * Creates and adds the id of a Channel to a list that holds all the channels
  * using the objet.
  * @param id pointer where the id created is returned
  */
  void AddChannelId(boost::uint32_t *id);
  /**
  * Removes the id of a Channel registered with using the objet.
  * @param id pointer where the id created is returned
  */
  void RemoveChannelId(const boost::uint32_t &id);
 private:
  boost::shared_ptr<ChannelManagerImpl> pimpl_;
};
}  // namespace rpcprotocol

#endif  // MAIDSAFE_CHANNELMANAGER_API_H_
