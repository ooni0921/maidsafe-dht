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

#include <stdexcept>

#include "nat-pmp/natpmpclient.h"
#include "nat-pmp/natpmpprotocol.h"

namespace natpmp {

natpmpclient::natpmpclient(boost::asio::io_service & ios)
    : io_service_(ios)
{
    // ...
}

natpmpclient::~natpmpclient()
{
    // ...
}

void natpmpclient::start()
{
    if (impl_)
    {
        // ...
    }
    else
    {
        /**
         * Allocate the implementation.
         */
        impl_.reset(new natpmpclientimpl(io_service_));

        /**
         * Start the implementation.
         */
        impl_->start();
    }
}

void natpmpclient::stop()
{
    if (impl_)
    {
        /**
         * Stop the implementation.
         */
        impl_->stop();

        /**
         * Cleanup
         */
        impl_.reset();
    }
    else
    {
        // ...
    }
}

void natpmpclient::set_map_port_success_callback(
    const nat_pmp_map_port_success_cb_t & map_port_success_cb
    )
{
    if (impl_)
    {
        impl_->set_map_port_success_callback(map_port_success_cb);
    }
    else
    {
        std::cerr <<
            "Cannot set NAT-PMP success callback with null impl." <<
        std::endl;
    }
}

void natpmpclient::map_port(
    unsigned int protocol, unsigned short private_port,
    unsigned short public_port, long long lifetime
    )
{
	if (protocol != protocol::tcp && protocol != protocol::udp)
    {
        throw std::runtime_error(
            protocol::string_from_opcode(protocol::error_invalid_args)
        );
    }

    if (impl_)
    {
        impl_->send_mapping_request(
            protocol, private_port, public_port, lifetime
        );
    }
    else
    {
        throw std::runtime_error(
            "Attempted to map nat-pmp port while subsystem is not started."
        );
    }
}

}  // namespace natpmp
