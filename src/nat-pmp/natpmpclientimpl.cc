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

#include <boost/bind.hpp>

#include "base/gateway.h"
#include "nat-pmp/natpmpclientimpl.h"

namespace natpmp {

natpmpclientimpl::natpmpclientimpl(boost::asio::io_service & ios)
    : m_public_ip_address(boost::asio::ip::address_v4::any())
    , io_service_(ios)
    , retry_timer_(ios)
{
    // ...
}
            
natpmpclientimpl::~natpmpclientimpl()
{
    /**
     * If the socket is valid call stop.
     */
    if (socket_)
    {
        stop();
    }
    
    /**
     * Clear the mappings.
     */
    mappings_.clear();
    
    /**
     * Clear the request queue.
     */
    request_queue_.clear();
}
            
void natpmpclientimpl::start()
{
    if (socket_)
    {
        throw std::runtime_error(
            "Attempted to start nat-pmp client while socket is in use."
        );
    }
    else
    {
        /**
         * Allocate the socket.
         */
        socket_.reset(new boost::asio::ip::udp::socket(io_service_));

        boost::system::error_code ec;
                
        /**
         * Obtain the default gateway/route.
         */
        m_gateway_address = base::gateway::default_route(io_service_, ec);
        
        if (ec)
        {
            throw std::runtime_error(ec.message()); 
        }
        else
        {
            std::cout << 
                "Started NAT-PMP client, default route to gateway is " << 
                m_gateway_address << "." << 
           std::endl;   
        }
        
        boost::asio::ip::udp::endpoint ep(m_gateway_address, protocol::port);
        
        /**
         * Connect the socket so that we receive ICMP errors.
         */
        socket_->lowest_layer().async_connect(
            ep, boost::bind(
                &natpmpclientimpl::handle_connect, this, 
                boost::asio::placeholders::error
            )
        );
    }
}
            
void natpmpclientimpl::stop()
{
    if (socket_ && socket_->is_open())
    {
        std::cout << "Stopping NAT-PMP client..." << std::endl;

        std::vector< std::pair<
            protocol::mapping_request, protocol::mapping_response
        > >::iterator it = mappings_.begin();
     
        for (; it != mappings_.end(); ++it)
        {
            std::cout << "Removing NAT-PMP mapping: " << 
                (unsigned int)(*it).first.buffer[1] << ":" <<  
                (*it).second.private_port << ":" << 
                (*it).second.public_port << 
            std::endl;
            
            /**
             * Send the mapping request with a lifetime of 0.
             */
            send_mapping_request(
                (*it).first.buffer[1], (*it).second.private_port, 
                (*it).second.public_port, 0
            );
        }
        
        /**
         * Close the socket.
         */
        socket_->close();
        
        /**
         * Cleanup.
         */
        socket_.reset();
        
        std::cout << "NAT-PMP client stop complete." << std::endl;
    }
    else
    {
        std::cerr << "NAT-PMP client is already stopped." << std::endl;   
    }
}

void natpmpclientimpl::set_map_port_success_callback(
    const nat_pmp_map_port_success_cb_t & map_port_success_cb
    )
{
    nat_pmp_map_port_success_cb_ = map_port_success_cb;
}

void natpmpclientimpl::send_mapping_request(
    boost::uint16_t protocol, boost::uint16_t private_port, 
    boost::uint16_t public_port, boost::uint32_t lifetime
    )
{
    io_service_.post(
        boost::bind(
            &natpmpclientimpl::do_send_mapping_request, this, protocol, 
            private_port, public_port, lifetime
        )
    );    
}

void natpmpclientimpl::do_send_mapping_request(
    boost::uint16_t protocol, boost::uint16_t private_port, 
    boost::uint16_t public_port, boost::uint32_t lifetime
    )
{
    if (socket_ && socket_->is_open())
    {
        std::cout << 
            "Queueing mapping request for protocol = " << protocol << 
            ", private_port = " << private_port << ", public_port = " << 
            public_port << ", lifetime = " << lifetime << 
        std::endl;
        
        protocol::mapping_request r;
        
        r.buffer[0] = 0;
    	r.buffer[1] = protocol;
    	r.buffer[2] = 0;
    	r.buffer[3] = 0;
    	
        *((boost::uint16_t *)(r.buffer + 4)) = htons(private_port);
    	*((boost::uint16_t *)(r.buffer + 6)) = htons(public_port);
    	*((boost::uint32_t *)(r.buffer + 8)) = htonl(lifetime);
    
        r.length = 12;
        r.retry_count = 0;
        
        request_queue_.push_back(r);
    }
}

void natpmpclientimpl::send_public_address_request()
{
    std::cout << 
        "NAT-PMP client sending public address request to gateway device." << 
    std::endl;
    
    public_ip_request_.buffer[0] = 0;
    public_ip_request_.buffer[1] = 0;
    public_ip_request_.length = 2;
    /*
    public_ip_request_.retry_time = 
        boost::posix_time::microsec_clock::universal_time() + 
        boost::posix_time::milliseconds(250)
    ;
    */
    public_ip_request_.retry_count = 1;
    
    send_request(public_ip_request_);
    
    retry_timer_.expires_from_now(boost::posix_time::milliseconds(
        250 * public_ip_request_.retry_count)
    );
    
    retry_timer_.async_wait(boost::bind(
        &natpmpclientimpl::retransmit_public_adddress_request, this, _1)
    );
}

void natpmpclientimpl::retransmit_public_adddress_request(
    const boost::system::error_code & ec
    )
{
    if (ec)
    {
        // operation aborted
    }
    else if (public_ip_request_.retry_count >= 9)
    {
        std::cerr << 
            "No NAT-PMP gateway device found, calling stop." << 
        std::endl;
        
        retry_timer_.cancel();
        
        stop();   
    }
    else if (m_public_ip_address == boost::asio::ip::address_v4::any())
    {                
        /**
         * Increment retry count.
         */
        ++public_ip_request_.retry_count;
        
        /**
         * Retransmit the request.
         */
        send_request(public_ip_request_);
        
        std::cout << 
            "Retransmitting public address request, retry = " << 
            (unsigned int)public_ip_request_.retry_count << "." << 
        std::endl;
        
        retry_timer_.expires_from_now(boost::posix_time::milliseconds(
            250 * public_ip_request_.retry_count)
        );
        
        retry_timer_.async_wait(boost::bind(
            &natpmpclientimpl::retransmit_public_adddress_request, this, _1)
        );
    }
}

void natpmpclientimpl::send_request(protocol::mapping_request & req)
{
    if (socket_ && socket_->is_open())
    {
        send(reinterpret_cast<const char *>(req.buffer), req.length);
    }
    else
    {
        std::cerr << 
            "Cannot send NAT-PMP request while not started!" << 
        std::endl;
    }
}

void natpmpclientimpl::send_queued_requests()
{
    if (socket_ && socket_->is_open())
    {        
        if (!request_queue_.empty())
        {
            std::cout << 
                "Sending queued NAT-PMP requests, " << request_queue_.size() << 
                " remaing."<< 
            std::endl;
            protocol::mapping_request r = request_queue_.front();
            
            send_request(r);
        }
    }
}

void natpmpclientimpl::send(const char * buf, std::size_t len)
{
    socket_->async_send(
        boost::asio::buffer(buf, len), boost::bind(
            &natpmpclientimpl::handle_send, this, 
            boost::asio::placeholders::error, 
            boost::asio::placeholders::bytes_transferred
        )
    );
}

void natpmpclientimpl::handle_send(
    const boost::system::error_code & ec, std::size_t bytes
    )
{
    if (ec == boost::asio::error::operation_aborted)
    {
        // ...
    }
    else if (ec)
    {
        std::cerr << 
            protocol::string_from_opcode(protocol::error_send) << 
            " : "<< ec.message() << 
        std::endl;
    }
    else
    {
        socket_->async_receive_from(
            boost::asio::buffer(data_, receive_buffer_length), endpoint_,
            boost::bind(&natpmpclientimpl::handle_receive_from, this, 
            boost::asio::placeholders::error, 
            boost::asio::placeholders::bytes_transferred)
        );
    }
}

void natpmpclientimpl::handle_connect(const boost::system::error_code & ec)
{
    if (ec == boost::asio::error::operation_aborted)
    {
        // ...
    }
    else if (ec)
    {
        std::cerr << 
            "No NAT-PMP compatible gateway found, calling stop." <<
        std::endl;
        
        /**
         * Call stop.
         */
        stop();
    }
    else
    {
        std::cout << "Sending public address request to gateway." << std::endl;
        
        /**
         * Send a request for the NAT-PMP gateway's public ip address. This is
         * also used to determine if the gateway is valid.
         */
        send_public_address_request();
    }  
}

void natpmpclientimpl::handle_receive_from(
    const boost::system::error_code & ec, std::size_t bytes
    )
{
    if (ec == boost::asio::error::operation_aborted)
    {
        // ...
    }
    else if (ec)
    {
#if NDEBUG
        std::cerr << 
            protocol::string_from_opcode(protocol::error_receive_from) << 
            " : " << ec.message() << 
        std::endl;
#endif
#ifndef NDEBUG
        std::cerr << 
            "No NAT-PMP compatible gateway found, calling stop." <<
        std::endl;
#endif
        /**
         * Call stop.
         */
        stop();
    }
    else
    {
        /**
         * Handle the response.
         */
        handle_response(data_, bytes);
        
        socket_->async_receive_from(
            boost::asio::buffer(data_, receive_buffer_length), endpoint_,
            boost::bind(&natpmpclientimpl::handle_receive_from, this, 
            boost::asio::placeholders::error, 
            boost::asio::placeholders::bytes_transferred)
        );
    }
}

void natpmpclientimpl::handle_response(const char * buf, std::size_t len)
{
    unsigned int opcode = 0;
    
    protocol::mapping_response response;
    
    if (endpoint_.address() == m_gateway_address)
    {
    	response.result_code = ntohs(*((boost::uint16_t *)(buf + 2)));
        
    	response.epoch = ntohl(*((boost::uint32_t *)(buf + 4)));
        
    	if (buf[0] != 0)
        {
    		opcode = protocol::result_unsupported_version;
        }
    	else if (
    	   static_cast<unsigned char> (buf[1]) < 128 || 
    	   static_cast<unsigned char> (buf[1]) > 130
    	   )
        {
    		opcode = protocol::result_unsupported_opcode;
        }
    	else if (response.result_code != 0)
        {
    		switch (response.result_code)
            {
                case 1:
                    opcode = protocol::result_unsupported_version;
    			break;
                case 2:
                    opcode = protocol::result_not_authorized_refused;
    			break;
                case 3:
                    opcode = protocol::result_network_failure;
    			break;
                case 4:
                    opcode = protocol::result_out_of_resources;
    			break;
                case 5:
                    opcode = protocol::result_unsupported_opcode;
    			break;
                default:
                    opcode = protocol::result_undefined;
                break;
            }
    	}
        else
        {
    		response.type = static_cast<unsigned char>(buf[1]) & 0x7f;
            
    		if (static_cast<unsigned char> (buf[1]) == 128)
            {
                boost::uint32_t ip = ntohl(*((boost::uint32_t *)(buf + 8)));
    
                response.public_address = boost::asio::ip::address_v4(ip);
                
                m_public_ip_address = response.public_address;
                
                retry_timer_.cancel();
                
                std::cout << 
                    "Obtained public ip address " << response.public_address << 
                    " from NAT-PMP gateway, sending any queued requests." << 
                std::endl;
                
                /**
                 * A NAT-PMP compatible gateway has been found, send queued 
                 * requests.
                 */
                send_queued_requests();
    		}
            else
            {
    			response.private_port = ntohs(*((boost::uint16_t *)(buf + 8)));
                
    			response.public_port = ntohs(*((boost::uint16_t *)(buf + 10)));
                
    			response.lifetime = ntohl(*((boost::uint32_t *)(buf + 12)));
                
                protocol::mapping_request request = request_queue_.front();
                
                std::pair<
                    protocol::mapping_request, protocol::mapping_response
                > mapping = std::make_pair(request, response);
                
                if (
                    std::find(
                        mappings_.begin(), mappings_.end(), mapping
                        ) == mappings_.end()
                    )
                {
                    std::cout << 
                        "natpmpclientimpl::on_nat_pmp_mapping_success: " << 
                        response.public_port << ":" <<
                    std::endl;

                    if (nat_pmp_map_port_success_cb_)
                    {
                        nat_pmp_map_port_success_cb_(
                            mapping.first.buffer[1], response.private_port, 
                            response.public_port
                        );
                    }
                    
                    mappings_.push_back(mapping);
                }
                
                request_queue_.pop_front();
                
                /**
                 * Send queued requests.
                 */
                send_queued_requests();
    		}
            
    		opcode = 0;
    	}
    }
    else
    {
        opcode = protocol::error_source_conflict;
    }
    
    if (opcode)
    {
        #ifndef NDBEUG
            std::cerr << "DEBUG: NAT-PMP response opcode: " <<  
                protocol::string_from_opcode(opcode) << 
            std::endl;
        #endif
    }
}

}  // namespace natpmp
