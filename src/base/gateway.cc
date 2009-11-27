
#if (defined MAIDSAFE_APPLE || MAIDSAFE_POSIX || __MACH__)
#include <net/route.h>
#include <sys/sysctl.h>
#include <boost/scoped_ptr.hpp>
#elif (defined MAIDSAFE_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif // WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <iphlpapi.h>
#elif (defined MAIDSAFE_LINUX)
#include <asm/types.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#include <boost/bind.hpp>

#include "base/gateway.h"

namespace base {
    
boost::asio::ip::address gateway::default_route(
    boost::asio::io_service & ios, boost::system::error_code & ec
    )
{
    std::vector<network_interface> ret = routes(ios, ec);
#if (defined MAIDSAFE_WIN32)
    std::vector<network_interface>::iterator it = std::find_if(
        ret.begin(), ret.end(), boost::bind(&network_interface::is_loopback, 
        boost::bind(&network_interface::destination, _1))
    );
#else
    std::vector<network_interface>::iterator it = std::find_if(
        ret.begin(), ret.end(), boost::bind(&network_interface::destination, _1
        ) == boost::asio::ip::address()
    );
#endif
    if (it == ret.end())
    {
        return boost::asio::ip::address();
    }
        
    return it->gateway;
}


#if (defined MAIDSAFE_APPLE || MAIDSAFE_POSIX || __MACH__)

inline long round_up(long val)
{
    return 
        ((val) > 0 ? (1 + (((val) - 1) | (sizeof(long) - 1))) : sizeof(long))
    ;
}

bool gateway::parse_rt_msghdr(rt_msghdr * rtm, network_interface & rt_if)
{
    sockaddr * rti_info[RTAX_MAX];
    sockaddr * sa = (sockaddr*)(rtm + 1);
        
    for (unsigned int i = 0; i < RTAX_MAX; ++i)
    {
        if ((rtm->rtm_addrs & (1 << i)) == 0)
        {
            rti_info[i] = 0;
            continue;
        }
        
        rti_info[i] = sa;

        sa = (sockaddr *)((char *)(sa) + round_up(sa->sa_len));
    }

    sa = rti_info[RTAX_GATEWAY];
        
    if (
        sa == 0 || rti_info[RTAX_DST] == 0 || rti_info[RTAX_NETMASK] == 0 || 
        (sa->sa_family != AF_INET && sa->sa_family != AF_INET6)
        )
    {
        return false;
    }

    rt_if.gateway = network_interface::sockaddr_to_address(
        rti_info[RTAX_GATEWAY]
    );
    
    rt_if.netmask = network_interface::sockaddr_to_address(
        rti_info[RTAX_NETMASK]
    );
    
    rt_if.destination = network_interface::sockaddr_to_address(
        rti_info[RTAX_DST]
    );
    
    if_indextoname(rtm->rtm_index, rt_if.name);
        
    return true;
}

#elif defined(MAIDSAFE_LINUX)

static int read_nl_sock(int sock, char * buf, int len, int seq, int pid)
{
    nlmsghdr * nl_hdr;

    int msg_len = 0;

    do
    {
        int read_len = recv(sock, buf, len - msg_len, 0);
            
        if (read_len < 0)
        {
            return -1;
        }

        nl_hdr = (nlmsghdr *)buf;

        if (
            (NLMSG_OK(nl_hdr, read_len) == 0) || 
            (nl_hdr->nlmsg_type == NLMSG_ERROR)
            )
        {
            return -1;
        }

        if (nl_hdr->nlmsg_type == NLMSG_DONE)
        {
            break;
        }

        buf += read_len;
            
        msg_len += read_len;

        if ((nl_hdr->nlmsg_flags & NLM_F_MULTI) == 0)
        {
            break;
        }

    } while ((nl_hdr->nlmsg_seq != seq) || (nl_hdr->nlmsg_pid != pid));
        
    return msg_len;
}

bool gateway::parse_nlmsghdr(nlmsghdr * nl_hdr, network_interface & rt_if)
{
    rtmsg * rt_msg = (rtmsg *)NLMSG_DATA(nl_hdr);

    if ((rt_msg->rtm_family != AF_INET) || (rt_msg->rtm_table != RT_TABLE_MAIN))
    {
        return false;
    }

    int rt_len = RTM_PAYLOAD(nl_hdr);
        
    rtattr * rt_attr = (rtattr *)RTM_RTA(rt_msg);
    
    for (; RTA_OK(rt_attr, rt_len); rt_attr = RTA_NEXT(rt_attr, rt_len))
    {
        switch (rt_attr->rta_type)
        {
            case RTA_OIF:
                if_indextoname(*(int*)RTA_DATA(rt_attr), rt_if->name);
            break;
            case RTA_GATEWAY:
                rt_if->gateway = boost::asio::ip::address_v4(
                    ntohl(*(u_int*)RTA_DATA(rt_attr))
                );
            break;
            case RTA_DST:
                rt_if->destination = boost::asio::ip::address_v4(
                    ntohl(*(u_int*)RTA_DATA(rt_attr))
                );
            break;
        }
    }
    return true;
}

#endif

std::vector<network_interface> gateway::routes(
    boost::asio::io_service & ios, boost::system::error_code & ec
    )
{
    std::vector<network_interface> ret;
    
#if (defined MAIDSAFE_APPLE || MAIDSAFE_POSIX || __MACH__)

    int mib[6] = { CTL_NET, PF_ROUTE, 0, AF_UNSPEC, NET_RT_DUMP, 0 };

    std::size_t needed = 0;
	
    if (sysctl(mib, 6, 0, &needed, 0, 0) < 0)
    {
        ec = boost::system::error_code(
            errno, boost::asio::error::system_category
        );
        return std::vector<network_interface>();
    }

    if (needed <= 0)
    {
        return std::vector<network_interface>();
    }

    boost::scoped_ptr<char> buf(new char[needed]);

    if (sysctl(mib, 6, buf.get(), &needed, 0, 0) < 0)
    {
        ec = boost::system::error_code(
            errno, boost::asio::error::system_category
        );
        return std::vector<network_interface>();
    }

    char * end = buf.get() + needed;

    rt_msghdr * rtm;
	
    for (char * next = buf.get(); next < end; next += rtm->rtm_msglen)
    {
        rtm = (rt_msghdr *)next;
            
        if (rtm->rtm_version != RTM_VERSION)
        {
            continue;
        }
		
        network_interface r;
        
        if (parse_rt_msghdr(rtm, r))
        {
            ret.push_back(r);
        }
    }
	
#elif defined(WIN32) || defined(_WIN32)

    HMODULE iphlp = LoadLibraryA("Iphlpapi.dll");
        
    if (!iphlp)
    {
        ec = boost::asio::error::operation_not_supported;
        return std::vector<network_interface>();
    }

    typedef DWORD(WINAPI *GetAdaptersInfo_t)(PIP_ADAPTER_INFO, PULONG);
        
    GetAdaptersInfo_t GetAdaptersInfo = (GetAdaptersInfo_t)GetProcAddress(
        iphlp, "GetAdaptersInfo"
    );
        
    if (!GetAdaptersInfo)
    {
        FreeLibrary(iphlp);
        ec = boost::asio::error::operation_not_supported;
        return std::vector<network_interface>();
    }

    PIP_ADAPTER_INFO adapter_info = 0;
        
    ULONG out_buf_size = 0;
   
    if (GetAdaptersInfo(adapter_info, &out_buf_size) != ERROR_BUFFER_OVERFLOW)
    {
        FreeLibrary(iphlp);
        ec = boost::asio::error::operation_not_supported;
        return std::vector<network_interface>();
    }

    adapter_info = new IP_ADAPTER_INFO[out_buf_size];

    if (GetAdaptersInfo(adapter_info, &out_buf_size) == NO_ERROR)
    {
        for (
            PIP_ADAPTER_INFO adapter = adapter_info; adapter != 0; 
            adapter = adapter->Next
            )
        {
            network_interface r;
				
			r.destination = boost::asio::ip::address::from_string(
                adapter->IpAddressList.IpAddress.String, ec
            );
                
			r.gateway =  boost::asio::ip::address::from_string(
                adapter->GatewayList.IpAddress.String, ec
            );
                
			r.netmask =  boost::asio::ip::address::from_string(
                adapter->IpAddressList.IpMask.String, ec
            );
				
            strncpy(r.name, adapter->AdapterName, sizeof(r.name));

            if (ec)
            {
                ec = boost::system::error_code();
                continue;
            }
            ret.push_back(r);
        }
    }
   
    delete adapter_info, adapter_info = 0;
    FreeLibrary(iphlp);

#elif defined (MAIDSAFE_LINUX)

    enum { BUFSIZE = 8192 };

    int sock = socket(PF_ROUTE, SOCK_DGRAM, NETLINK_ROUTE);
    
    if (sock < 0)
    {
        ec = boost::system::error_code(errno, boost::asio::error::system_category);
        return std::vector<network_interface>();
    }

    int seq = 0;

    char msg[BUFSIZE];
        
    std::memset(msg, 0, BUFSIZE);
        
    nlmsghdr * nl_msg = (nlmsghdr*)msg;

    nl_msg->nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
    nl_msg->nlmsg_type = RTM_GETROUTE;
    nl_msg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
    nl_msg->nlmsg_seq = seq++;
    nl_msg->nlmsg_pid = getpid();

    if (send(sock, nl_msg, nl_msg->nlmsg_len, 0) < 0)
    {
        ec = boost::system::error_code(errno, boost::asio::error::system_category);
        
        close(sock);
        
        return std::vector<network_interface>();
    }

    int len = read_nl_sock(sock, msg, BUFSIZE, seq, getpid());
        
    if (len < 0)
    {
        ec = boost::system::error_code(errno, boost::asio::error::system_category);
        
        close(sock);
        
        return std::vector<network_interface>();
    }

    for (; NLMSG_OK(nl_msg, len); nl_msg = NLMSG_NEXT(nl_msg, len))
    {
        network_interface intf;
        
        if (parse_nlmsghdr(nl_msg, &intf))
        {
            ret.push_back(intf);
        }
    }
    close(sock);

#endif
    return ret;
}
        
} // namespace base
