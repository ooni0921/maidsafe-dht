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

#ifndef NATPMPCLIENT_H_
#define NATPMPCLIENT_H_

#include <boost/asio.hpp>
#include <boost/function.hpp>
#include <boost/shared_ptr.hpp>

#include "nat-pmp/natpmpclientimpl.h"

namespace natpmp {

    /**
     * Implements a NAT-PMP client.
     */
    class natpmpclient
    {
        public:

            /**
             * Constructor
             * @param ios The boost::asio::io_service object to use.
             */
            explicit natpmpclient(boost::asio::io_service & ios);

            /**
             * Destructor
             */
            ~natpmpclient();

            /**
             * Start the underlying subsystem.
             */
            void start();

            /**
             * Stop the underlying subsystem.
             */
            void stop();

            /**
             * Set the port map success callback.
             */
            void set_map_port_success_callback(
                const nat_pmp_map_port_success_cb_t & map_port_success_cb
            );

            /**
             * Maps a private port to a public port of the given protocol and
             * lifetime.
             * @param protocol
             * @param private_port
             * @param public_port
             * @param lifetime
             */
            void map_port(
                unsigned int protocol, unsigned short private_port,
                unsigned short public_port, long long lifetime = 3600
            );

        protected:

            // ...

        protected:

            /**
             * Reference to the boost::asio::io_service object.
             */
            boost::asio::io_service & io_service_;

            /**
             * The underlying nat-pmp implementation.
             */
            boost::shared_ptr<natpmpclientimpl> impl_;
    };

}  // namespace natpmp

#endif  // NATPMP_NATPMPCLIENT_H_
