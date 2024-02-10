include("raw.jl")

const AOE = UInt8[0x88, 0xA2]

(io, mac) =  raw_socket("eno0", UInt8[0x88, 0xA2])



bcast = UInt8[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]

struct aoe_header
    dest::NTuple{6, UInt8}
    src::NTuple{6, UInt8}
    eth::NTuple{2, UInt8}
    flags::UInt8
    error::UInt8
    major::UInt16
    minor::UInt8
    command::UInt8
    tag::UInt32
end

function show(io::IO, header::aoe_header)
    println(io, "aoe_header:")
    print(io, "  dest: ", join(map(x -> string(x, base=16, pad=2), header.dest), " "))
    print(io, "\n  src: ", join(map(x -> string(x, base=16, pad=2), header.src), " "))
    print(io, "\n  eth: ", join(map(x -> string(x, base=16, pad=2), header.eth), " "))
    print(io, "\n  flags: ", string(header.flags, base=16, pad=2))
    print(io, "\n  error: ", string(header.error, base=16, pad=2))
    print(io, "\n  major: ", string(header.major, base=16, pad=4))
    print(io, "\n  minor: ", string(header.minor, base=16, pad=2))
    print(io, "\n  command: ", string(header.command, base=16, pad=2))
    print(io, "\n  tag: ", string(header.tag, base=16, pad=8))
end

# Example usage:

function read_aoe_header(io::IO)
    dest = tuple(read(io, 6)...)  # Convert the array to a tuple
    src = tuple(read(io, 6)...)
    eth = tuple(read(io, 2)...)
    verflags = read(io, UInt8)
    flags = verflags & 0x00ff
    error = read(io, UInt8)
    major = bswap(read(io, UInt16)) # Assuming network byte order
    minor = read(io, UInt8)
    command = read(io, UInt8)
    tag = bswap(read(io, UInt32)) # Assuming network byte order

    return aoe_header(dest, src, eth, flags, error, major, minor, command, tag)
end

function write_aoe_header(io::IO, aoeh::aoe_header)
    write(io, aoeh.dest...)
    write(io, aoeh.src...)
    write(io, aoeh.eth...)
    write(io, 0x01 << 3 + aoeh.flags)
    write(io, aoeh.error)
    write(io, bswap(aoeh.major))
    write(io, aoeh.minor)
    write(io, aoeh.command)
    write(io, bswap(aoeh.tag))
end


announce = aoe_header(
    (0xff, 0xff, 0xff, 0xff, 0xff, 0xff),
    mac,
    (0x88, 0xA2),
    0x00,
    0x00,
    UInt16(1),
    UInt8(5),
    0x01,
    UInt32(0x1112)
)

println(announce)

write_aoe_header(io, announce)

r = read_aoe_header(io)
println(r)

bytes_to_read = bytesavailable(io)
rest = read(io, bytes_to_read)

close(io)
