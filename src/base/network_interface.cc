/*
 *  network_interface.hpp
 *  Created by Julian Cain on 11/3/09.
 */
 
#if defined (MAIDSAFE_WIN32)
    // ...
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <errno.h>
#include <netdb.h>
#endif

#include "base/network_interface.h"

using namespace base;

bool network_interface::is_local(const boost::asio::ip::address & addr)
{
    if (addr.is_v6())
    {
        return addr.to_v6().is_link_local();
    }
    else
    {
        boost::asio::ip::address_v4 a4 = addr.to_v4();
        
        unsigned long ip = a4.to_ulong();
        
        return (
            (ip & 0xff000000) == 0x0a000000 || 
            (ip & 0xfff00000) == 0xac100000 || 
            (ip & 0xffff0000) == 0xc0a80000
        );
    }
    
    return false;
}

bool network_interface::is_loopback(const boost::asio::ip::address & addr)
{
    if (addr.is_v4())
    {
        return addr.to_v4() == boost::asio::ip::address_v4::loopback();
    }
    else
    {
        return addr.to_v6() == boost::asio::ip::address_v6::loopback();
    }
}

bool network_interface::is_multicast(const boost::asio::ip::address & addr)
{
    if (addr.is_v4())
    {
        return addr.to_v4().is_multicast();
    }
    else
    {
        return addr.to_v6().is_multicast();
    }
}

bool network_interface::is_any(const boost::asio::ip::address & addr)
{
    if (addr.is_v4())
    {
        return addr.to_v4() == boost::asio::ip::address_v4::any();
    }
    else
    {
        return addr.to_v6() == boost::asio::ip::address_v6::any();
    }
}

boost::asio::ip::address network_interface::inaddr_to_address(
    const in_addr * addr
    )
{
    typedef boost::asio::ip::address_v4::bytes_type bytes_t;
    bytes_t b;
    std::memcpy(&b[0], addr, b.size());
    return boost::asio::ip::address_v4(b);
}

boost::asio::ip::address network_interface::inaddr6_to_address(
    const in6_addr * addr
    )
{
    typedef boost::asio::ip::address_v6::bytes_type bytes_t;
    bytes_t b;
    std::memcpy(&b[0], addr, b.size());
    return boost::asio::ip::address_v6(b);
}

boost::asio::ip::address network_interface::sockaddr_to_address(
    const sockaddr * addr
    )
{
    if (addr->sa_family == AF_INET)
    {
        return inaddr_to_address(&((const sockaddr_in *)addr)->sin_addr);
    }
    else if (addr->sa_family == AF_INET6)
    {
        return inaddr6_to_address(&((const sockaddr_in6 *)addr)->sin6_addr);
    }
    return boost::asio::ip::address();
}

#if defined (MAIDSAFE_POSIX) || defined (MAIDSAFE_APPLE)
static bool verify_sockaddr(sockaddr_in * sin)
{
    return 
        (sin->sin_len == sizeof(sockaddr_in) && sin->sin_family == AF_INET) || 
        (sin->sin_len == sizeof(sockaddr_in6) && sin->sin_family == AF_INET6)
    ;
}
#endif // defined (MAIDSAFE_POSIX) || defined (MAIDSAFE_APPLE)

boost::asio::ip::address network_interface::local_address()
{
    boost::system::error_code ec;
    boost::asio::ip::address ret = boost::asio::ip::address_v4::any();
    
    const std::vector<network_interface> & interfaces = local_list(ec);
        
    std::vector<network_interface>::const_iterator it = interfaces.begin();
        
    for (; it != interfaces.end(); ++it)
    {
        const boost::asio::ip::address & a = (*it).destination;
            
        /**
         * Skip loopback, multicast and any.
         */
        if (is_loopback(a)|| is_multicast(a) || is_any(a))
        {
            continue;
        }
        
        /**
         * :NOTE: Other properties could be checked here such as the IFF_UP 
         * flag.
         */

        /**
         * Prefer an ipv4 address over v6.
         */
        if (a.is_v4())
        {
            ret = a;
            break;
        }

        /**
         * If this one is not any then return it.
         */
        if (ret != boost::asio::ip::address_v4::any())
        {
            ret = a;
        }
    }
    
    return ret;
}

std::vector<network_interface> network_interface::local_list(
    boost::system::error_code & ec
    )
{
    std::vector<network_interface> ret;
    
    /**
     * :FIXME: No define for MAIDSAFE_LINUX?
     */
#if defined __linux__ || (defined MAIDSAFE_APPLE || __MACH__)

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    
    if (s < 0)
    {
        ec = boost::asio::error::fault;
        return ret;
    }
    
    ifconf ifc;
    char buf[1024];
    
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    
    if (ioctl(s, SIOCGIFCONF, &ifc) < 0)
    {
        ec = boost::system::error_code(
            errno, boost::asio::error::system_category
        );
        
        close(s);
        
        return ret;
    }

    char *ifr = (char *)ifc.ifc_req;
    
    int remaining = ifc.ifc_len;

    while (remaining)
    {
        const ifreq & item = *reinterpret_cast<ifreq *>(ifr);

        if (
            item.ifr_addr.sa_family == AF_INET || 
            item.ifr_addr.sa_family == AF_INET6
            )
        {
            network_interface iface;

            iface.destination = sockaddr_to_address(&item.ifr_addr);
            
            strcpy(iface.name, item.ifr_name);

            ifreq netmask = item;
            
            if (ioctl(s, SIOCGIFNETMASK, &netmask) < 0)
            {
                if (iface.destination.is_v6())
                {
                    iface.netmask = boost::asio::ip::address_v6::any();
                }
                else
                {
                    ec = boost::system::error_code(
                        errno, boost::asio::error::system_category
                    );
                    
                    close(s);
                    
                    return ret;
                }
            }
            else
            {
                iface.netmask = sockaddr_to_address(
                    &netmask.ifr_addr
                );
            }
            ret.push_back(iface);
        }

#if (defined MAIDSAFE_APPLE || MAIDSAFE_POSIX || __MACH__)
        std::size_t if_size = item.ifr_addr.sa_len + IFNAMSIZ;
    /**
     * :FIXME: No define for MAIDSAFE_LINUX?
     */
#elif defined __linux__
        std::size_t if_size = sizeof(ifreq);
#endif
			ifr += if_size;
			remaining -= if_size;
		}
        
		close(s);

#elif defined (MAIDSAFE_WIN32)

		SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
        
		if (s == SOCKET_ERROR)
		{
			ec = boost::system::error_code(
                WSAGetLastError(), boost::asio::error::system_category
            );
            
			return ret;
		}

		INTERFACE_INFO buf[30];
        
		DWORD size;
	
        int err = WSAIoctl(
            s, SIO_GET_INTERFACE_LIST, 0, 0, buf, sizeof(buf), &size, 0, 0
        );
    
		if (err != 0)
		{
			ec = boost::system::error_code(
                WSAGetLastError(), boost::asio::error::system_category
            );
			
            closesocket(s);
			
            return ret;
		}
        
		closesocket(s);

		std::size_t n = size / sizeof(INTERFACE_INFO);

		network_interface iface;
        
		for (std::size_t i = 0; i < n; ++i)
		{
			iface.address = sockaddr_to_address(&buf[i].iiAddress.Address);
            
			iface.netmask = sockaddr_to_address(&buf[i].iiNetmask.Address);
            
			iface.name[0] = 0;
			
            if (iface.address == boost::asio::ip::address_v4::any())
            {
                continue;
            }
			ret.push_back(iface);
		}
#else
#error "Unsupported Device or Platform."
#endif
    return ret;
}
