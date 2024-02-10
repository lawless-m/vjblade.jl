using Sockets

const AF_PACKET = 17
const SOCK_RAW = 3

struct sockaddr
    sa_family::UInt16
    sa_data::NTuple{14, UInt8}
end

struct ifaddrs
    ifa_next::Ptr{ifaddrs}
    ifa_name::Ptr{Cchar}
    ifa_flags::Cuint
    ifa_addr::Ptr{sockaddr}
    ifa_netmask::Ptr{sockaddr}
    ifa_dstaddr::Ptr{sockaddr}
    ifa_data::Ptr{Cvoid}
end

struct sockaddr_ll
    sll_family::UInt16   # Always AF_PACKET
    sll_protocol::UInt16 # Physical-layer protocol
    sll_ifindex::Int32   # Interface number
    sll_hatype::UInt16   # Header type
    sll_pkttype::UInt8   # Packet type
    sll_halen::UInt8     # Length of address
    sll_addr::NTuple{8, UInt8} # Physical-layer address
end

# Define the getifaddrs function using ccall
function getifaddrs()
    addrs = Ref{Ptr{ifaddrs}}(C_NULL)
    ret = ccall((:getifaddrs, "libc.so.6"), Cint, (Ptr{Ptr{ifaddrs}},), addrs)
    if ret != 0
        error("getifaddrs() failed")
    end

    # Initialize an empty list to store the ifaddrs structures
    ifaddr_list = []

    # Loop through the linked list
    addr_ptr = addrs[]
    while addr_ptr != C_NULL
        current_ifaddr = unsafe_load(addr_ptr)
        push!(ifaddr_list, current_ifaddr)
        addr_ptr = current_ifaddr.ifa_next
    end

    return ifaddr_list
end

function getifaddrs_with_mac()
    addrs = Ref{Ptr{ifaddrs}}(C_NULL)
    ret = ccall((:getifaddrs, "libc.so.6"), Cint, (Ptr{Ptr{ifaddrs}},), addrs)
    if ret != 0
        error("getifaddrs() failed")
    end

    # Initialize an empty list to store the ifaddrs structures along with MAC addresses
    ifaddr_list = []

    # Loop through the linked list
    addr_ptr = addrs[]
    while addr_ptr != C_NULL
        current_ifaddr = unsafe_load(addr_ptr)
        # Check if the current address is a packet address (AF_PACKET)
        if current_ifaddr.ifa_addr != C_NULL && unsafe_load(current_ifaddr.ifa_addr).sa_family == AF_PACKET
            # Cast the sockaddr pointer to sockaddr_ll to access the MAC address
            sll_ptr = reinterpret(Ptr{sockaddr_ll}, current_ifaddr.ifa_addr)
            sll = unsafe_load(sll_ptr)
            mac = sll.sll_addr[1:6]  # Extract the MAC address (first 6 bytes of sll_addr)
            push!(ifaddr_list, (current_ifaddr, mac))
        else
            push!(ifaddr_list, (current_ifaddr, (0,0,0,0,0,0)))
        end
        addr_ptr = current_ifaddr.ifa_next
    end
    return ifaddr_list
end

function find_interface_index(ifaddrs_list, interface_name::String)
    for (ifaddr, mac) in ifaddrs_list
        name = unsafe_string(ifaddr.ifa_name)
        if name == interface_name
            # Assuming you want to extract the interface index from the ifaddr structure
            # You might need to adjust this part depending on how you intend to use the interface index
            # This is a placeholder for whatever operation you need to perform
            index = ccall(:if_nametoindex, Cuint, (Ptr{Cchar},), ifaddr.ifa_name)
            return (Int32(index), mac)
        end
    end
    error("Interface $interface_name not found")
end

function raw_socket(interfacename::String, proto::Vector{UInt8})
    if length(proto) != 2
        error("Protocol vector must have exactly two UInt8 elements")
    end

    return raw_socket(interfacename, (UInt16(proto[1]) << 8) | UInt16(proto[2]))
end 

function raw_socket(interfacename::String, proto::UInt16)
    # Usage
    ifaddrs_list = getifaddrs_with_mac()
    (iface_index, mac) = find_interface_index(ifaddrs_list, interfacename)

    f = ccall(:socket, Cint, (Cint, Cint, Cint), AF_PACKET, SOCK_RAW, hton(proto))

    # Create a sockaddr_ll structure
    sll = sockaddr_ll(
        AF_PACKET, # sll_family
        hton(proto), # sll_protocol, assuming AOE is correctly defined
        iface_index, # sll_ifindex, obtained from your network interface
        0, # sll_hatype, adjust as necessary
        0, # sll_pkttype, adjust as necessary
        0, # sll_halen, adjust as necessary
        (0,0,0,0,0,0,0,0) # sll_addr, adjust as necessary
    )

    # Bind the socket to the interface
    ccall(:bind, Cint, (Cint, Ptr{sockaddr_ll}, Cuint), f, Ref(sll), sizeof(sll))

    return (fdio(f), mac)
end


