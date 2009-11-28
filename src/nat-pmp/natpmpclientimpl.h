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

Created by Julian Cain on 11/3/09.

*/

#ifndef UPNP_NATPMPCLIENTIMPL_H_
#define UPNP_NATPMPCLIENTIMPL_H_

#include <deque>
#include <vector>

#include <boost/asio.hpp>
#include <boost/cstdint.hpp>

#include "nat-pmp/natpmpprotocol.h"

namespace natpmp {

    typedef boost::function<
        void (
        boost::uint16_t protocol, boost::uint16_t private_port,
        boost::uint16_t public_port
        )
    > nat_pmp_map_port_success_cb_t;

    /**
     * Implements the underlying NAT-PMP client implementation.
     */
    class natpmpclientimpl
    {
        public:

            /**
             * Constructor
             * @param ios The boost::asio::io_service object to use.
             */
            explicit natpmpclientimpl(boost::asio::io_service & ios);

            /**
             * Destructor
             */
            ~natpmpclientimpl();

            /**
             * Start the nat-pmp client.
             */
            void start();

            /**
             * Stops the nat-pmp client removing all mappings.
             */
            void stop();

            /**
             * Set the port map success callback.
             */
            void set_map_port_success_callback(
                const nat_pmp_map_port_success_cb_t & map_port_success_cb
            );

            /**
             * Sends a mapping request by posting it to the
             * boost::asio::io_service object with the given protocol,
             * private port, public port and lifetime.
             * @param protocol
             * @param private_port
             * @param public_port
             * @param lifetime
             * @note thread-safe
             */
            void send_mapping_request(
                boost::uint16_t protocol, boost::uint16_t private_port,
                boost::uint16_t public_port, boost::uint32_t lifetime
            );

        private:

            /**
             * Sends a mapping.
             */
            void do_send_mapping_request(
                boost::uint16_t protocol, boost::uint16_t private_port,
                boost::uint16_t public_port, boost::uint32_t lifetime
            );

            /**
             * Sends a public address request to the gateway.
             */
            void send_public_address_request();

            /**
             * Performs a public address request re-transmission.
             */
            void retransmit_public_adddress_request(
                const boost::system::error_code & ec
            );

            /**
             * Sends a request to the gateway.
             */
            void send_request(protocol::mapping_request & req);

            /**
             * Sends any queued requests.
             */
            void send_queued_requests();

            /**
             * Sends buf of size len to the gateway.
             */
            void send(const char * buf, std::size_t len);

            /**
             * Asynchronous send handler.
             */
            void handle_send(
                const boost::system::error_code & ec, std::size_t bytes
            );

            /**
             * Asynchronous cannot handler.
             */
            void handle_connect(const boost::system::error_code & ec);

            /**
             * Asynchronous receive from handler.
             */
            void handle_receive_from(
                const boost::system::error_code & ec, std::size_t bytes
            );

            /**
             * Asynchronous response handler.
             */
            void handle_response(const char * buf, std::size_t len);

            /**
             * The ip address of the gateway.
             */
            boost::asio::ip::address m_gateway_address;

            /**
             * The ip address on thw WAN side of the gateway.
             */
            boost::asio::ip::address m_public_ip_address;

        protected:

            /**
             * A reference to the boost::asio::io_service.
             */
            boost::asio::io_service & io_service_;

            /**
             * The request retry timer.
             */
            boost::asio::deadline_timer retry_timer_;

            /**
             * The udp socket.
             */
            boost::shared_ptr<boost::asio::ip::udp::socket> socket_;

            /**
             * The gateway endpoint.
             */
            boost::asio::ip::udp::endpoint endpoint_;

            /**
             * The non-parallel public ip address request.
             */
            protocol::mapping_request public_ip_request_;

            /**
             * The parallel reuqest queue.
             */
            std::deque<protocol::mapping_request> request_queue_;

            /**
             * The receive buffer length.
             */
            enum
            {
                receive_buffer_length = 512
            };

            /**
             * The receive buffer.
             */
            char data_[receive_buffer_length];

            /**
             * Mappings that we are responsible for.
             */
            std::vector<
                std::pair<protocol::mapping_request, protocol::mapping_response>
            > mappings_;

            /**
             * Map port success callback.
             */
            nat_pmp_map_port_success_cb_t nat_pmp_map_port_success_cb_;
    };

}  // namespace natpmp

#endif  // UPNP_NATPMPCLIENTIMPL_H_
