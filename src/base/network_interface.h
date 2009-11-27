/*
 *  network_interface.hpp
 *  Created by Julian Cain on 11/3/09.
 */

#ifndef BASE_NETWORK_INTERFACE_HPP
#define BASE_NETWORK_INTERFACE_HPP

#include <string>
#include <vector>

#include <boost/asio.hpp>

namespace base {

    /**
     * Network interface utilities.
     */
    struct network_interface
    {
        /**
         * Determines if the given ip address is local.
         * @param addr The ip address to check.
         */
        static bool is_local(const boost::asio::ip::address & addr);

        /**
         * Determines if the given ip address is loopback.
         * @param addr The ip address to check.
         */
        static bool is_loopback(const boost::asio::ip::address & addr);

        /**
         * Determines if the given ip address is multicast.
         * @param addr The ip address to check.
         */
        static bool is_multicast(const boost::asio::ip::address & addr);

        /**
         * Determines if the given ip address is any.
         * @param addr The ip address to check.
         */
        static bool is_any(const boost::asio::ip::address & addr);

        /**
         * Takes an in_addr structure and returns a boost::asio::ip::address
         * object.
         * @param addr The in_addr struct to convert.
         */
        static boost::asio::ip::address inaddr_to_address(
            const in_addr * addr
        );
        
        /**
         * Takes an in6_addr structure and returns a boost::asio::ip::address
         * object.
         * @param addr The in6_addr struct to convert.
         */
        static boost::asio::ip::address inaddr6_to_address(
            const in6_addr * addr
        );
        
        /**
         * Takes an sockaddr structure and returns a boost::asio::ip::address
         * object.
         * @param addr The sockaddr struct to convert.
         */
        static boost::asio::ip::address sockaddr_to_address(
            const sockaddr * addr
        );
        
        /**
         * Returns all the network interfaces on the local system.
         * @return An std::vector of network_interface objects, one per 
         * physical or virtual network interface.
         */
        static std::vector<network_interface> local_list(
            boost::system::error_code & ec
        );
        
        /**
         * Returns the local ip address of the machine.
         * @note If the system is dualstack or multihomed this will return the
         * first valid network interface. Also this could be split into two
         * functions local_ipv4_address and local_ipv6_address respectively.
         */
        static boost::asio::ip::address local_address();

        /**
         * The destination ip address.
         */
        boost::asio::ip::address destination;
        
        /**
         * The gateway ip address.
         */
        boost::asio::ip::address gateway;
        
        /**
         * The netmask of the network interface.
         */
        boost::asio::ip::address netmask;

        /**
         * The string representation of the network interface.
         */
        char name[64];
    };
    
} // namespace base

#endif // BASE_NETWORK_INTERFACE_HPP
