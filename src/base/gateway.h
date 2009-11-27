
#ifndef BASE_GATEWAY_H_
#define BASE_GATEWAY_H_

#include <vector>

#include <boost/asio.hpp>

#include "base/network_interface.h"

#if (defined MAIDSAFE_APPLE || MAIDSAFE_POSIX || __MACH__)
struct rt_msghdr;
#elif defined(MAIDSAFE_LINUX)
struct nlmsghdr;
#endif

namespace base {
    
    class gateway
    {
        public:
        
            /**
             * Returns the default gateway address.
             * @param ios
             * @param ec
             */
            static boost::asio::ip::address default_route(
                boost::asio::io_service & ios, 
                boost::system::error_code & ec
            );
            
        private:
        
            /**
             * Enumerates and returns ip routes.
             */
            static std::vector<network_interface> routes(
                boost::asio::io_service & ios, boost::system::error_code & ec
            );   
            
        protected:
        
#if (defined MAIDSAFE_APPLE || MAIDSAFE_POSIX || __MACH__)
            /**
             * Parse a rt_msghdr and assign it to rt_if.
             * @param rtm
             * @param rt_info
             */
            static bool parse_rt_msghdr(
                rt_msghdr * rtm, network_interface & rt_if
            );
#elif defined (MAIDSAFE_LINUX)
        
            /**
             * Parse a nlmsghdr and assign it to rt_if.
             * @param nl_hdr
             * @param rt_info
             */
        static bool parse_nlmsghdr(nlmsghdr * nl_hdr, network_interface & rt_if);
#endif

    };
    
} // namespace base

#endif // BASE_GATEWAY_H_
