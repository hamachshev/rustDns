use std::{
    io::{Error, ErrorKind, Result, Write},
    net::{Ipv4Addr, Ipv6Addr, UdpSocket},
    usize,
};

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketBuffer {
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }

    fn pos(&self) -> usize {
        self.pos
    }

    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;
        Ok(())
    }
    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;
        Ok(())
    }

    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            Err(Error::new(ErrorKind::Other, "End of buffer"))
        } else {
            let result = self.buf[self.pos];
            self.pos += 1;
            Ok(result)
        }
    }
    fn get(&self, pos: usize) -> Result<u8> {
        if self.pos >= 512 {
            Err(Error::new(ErrorKind::Other, "End of buffer"))
        } else {
            Ok(self.buf[pos])
        }
    }
    fn get_range(&self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            Err(Error::new(ErrorKind::Other, "End of buffer"))
        } else {
            Ok(&self.buf[start..start + len])
        }
    }
    fn read_u16(&mut self) -> Result<u16> {
        let res = (self.read()? as u16) << 8 | (self.read()? as u16);
        Ok(res)
    }
    fn read_u32(&mut self) -> Result<u32> {
        let res = (self.read()? as u32) << 24
            | (self.read()? as u32) << 16
            | (self.read()? as u32) << 8
            | (self.read()? as u32);
        Ok(res)
    }
    /// Will take something like [3]www[6]google[3]com[0] and append
    /// www.google.com to outstr.
    fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        let mut delimiter = "";
        let mut pos = self.pos();

        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        loop {
            if jumps_performed > max_jumps {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!("Limit of {} jumps exceeded", max_jumps),
                ));
            }

            let len = self.get(pos)?;

            if (len & 0xc0) == 0xc0 {
                if !jumped {
                    self.seek(pos + 2)?;
                }
                let jump = (((len ^ 0xc0) as u16) << 8) | (self.get(pos + 1)? as u16);
                pos = jump as usize;

                jumped = true;
                jumps_performed += 1;
                continue;
            } else {
                pos += 1;
                if len == 0 {
                    break;
                }
                outstr.push_str(delimiter);
                outstr.push_str(&String::from_utf8_lossy(self.get_range(pos, len as usize)?));
                delimiter = ".";

                pos += len as usize;
            }
        }
        if !jumped {
            self.seek(pos)?;
        }
        Ok(())
    }
}

impl BytePacketBuffer {
    fn set(&mut self, pos: usize, val: u8) -> Result<()> {
        self.buf[pos] = val;
        Ok(())
    }
    fn set_u16(&mut self, pos: usize, val: u16) -> Result<()> {
        self.buf[pos] = ((val >> 8) & 0xff) as u8;
        self.buf[pos + 1] = ((val >> 0) & 0xff) as u8;
        Ok(())
    }
    fn write(&mut self, val: u8) -> Result<()> {
        if self.pos >= 512 {
            return Err(Error::new(ErrorKind::Other, "End of buffer"));
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(val)?;
        Ok(())
    }
    fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xff) as u8)?;
        Ok(())
    }
    fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write(((val >> 24) & 0xff) as u8)?;
        self.write(((val >> 16) & 0xff) as u8)?;
        self.write(((val >> 8) & 0xff) as u8)?;
        self.write(((val >> 0) & 0xff) as u8)?;
        Ok(())
    }

    fn write_qname(&mut self, qname: &str) -> Result<()> {
        for name in qname.split(".") {
            let len = name.len();

            if len > 0x3f {
                return Err(Error::new(
                    ErrorKind::Other,
                    "Single label exceeds 63 characters of length",
                ));
            }

            self.write(len as u8)?;

            for byte in name.bytes() {
                self.write(byte)?;
            }
        }
        self.write(0)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}
impl From<u8> for ResultCode {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::FORMERR,
            2 => Self::SERVFAIL,
            3 => Self::NXDOMAIN,
            4 => Self::NOTIMP,
            5 => Self::REFUSED,
            0 | _ => Self::NOERROR,
        }
    }
}

impl Default for ResultCode {
    fn default() -> Self {
        Self::NOERROR
    }
}

#[derive(Default, Debug, Clone)]
pub struct DnsHeader {
    pub id: u16,
    pub query_response: bool,     // 0 for query, 1 for res
    pub opcode: u8,               // 4 bits for opcode
    pub authorative_answer: bool, // 1 bit
    pub truncated_message: bool,  // 1 bit
    pub recursion_desired: bool,  // 1 bit
    pub recursion_ava: bool,      // 1 bit
    pub reserved: bool,           // 4 bits
    pub response_code: ResultCode,
    pub checking_disabled: bool, // one bit
    pub auth_data: bool,         // one bit
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
}

impl DnsHeader {
    fn new() -> DnsHeader {
        DnsHeader::default()
    }
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.id = buffer.read_u16()?;
        let flags = buffer.read_u16()?;

        let a = (flags >> 8) as u8;
        let b = (flags & 0xff) as u8;

        self.recursion_desired = (a & 1) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authorative_answer = (a & (1 << 2)) > 0;
        self.opcode = ((a >> 3) & 0x0f) as u8;
        self.query_response = (a & (1 << 7)) > 0;

        self.response_code = ResultCode::from((b & 0xf) as u8);
        // self.reserved = ((b >> 4) & 0x07) as u8;
        // self.auth_data = (self.reserved & (1 << 1)) > 0;
        // self.checking_disabled = (self.reserved & 1) > 0;
        // self.recursion_ava = (b >> 7) > 0;
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.auth_data = (b & (1 << 5)) > 0;
        self.reserved = (b & (1 << 6)) > 0;
        self.recursion_ava = (b & (1 << 7)) > 0;

        self.question_count = buffer.read_u16()?;
        self.answer_count = buffer.read_u16()?;
        self.authority_count = buffer.read_u16()?;
        self.additional_count = buffer.read_u16()?;

        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_u16(self.id)?;
        buffer.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authorative_answer as u8) << 2)
                | ((self.opcode as u8) << 3)
                | ((self.query_response as u8) << 7),
        )?;

        buffer.write_u8(
            (self.response_code as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.auth_data as u8) << 5)
                | ((self.reserved as u8) << 6)
                | ((self.recursion_ava as u8) << 7),
        )?;

        buffer.write_u16(self.question_count)?;
        buffer.write_u16(self.answer_count)?;
        buffer.write_u16(self.authority_count)?;
        buffer.write_u16(self.additional_count)?;

        Ok(())
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum QueryType {
    UNKNOWN(u16),
    A, //1
    NS,
    CNAME,
    MX,
    AAAA,
}

impl From<u16> for QueryType {
    fn from(value: u16) -> Self {
        match value {
            1 => Self::A,
            2 => Self::NS,
            5 => Self::CNAME,
            15 => Self::MX,
            28 => Self::AAAA,
            _ => Self::UNKNOWN(value),
        }
    }
}

impl Into<u16> for QueryType {
    fn into(self) -> u16 {
        match self {
            QueryType::A => 1 as u16,
            QueryType::UNKNOWN(num) => num as u16,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub question_type: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, question_type: QueryType) -> DnsQuestion {
        DnsQuestion {
            name,
            question_type,
        }
    }
    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.question_type = QueryType::from(buffer.read_u16()?);
        let _ = buffer.read_u16()?; // class

        Ok(())
    }
}

impl DnsQuestion {
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_qname(&self.name)?;
        buffer.write_u16(self.question_type.into())?;
        buffer.write_u16(1)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    },
    A {
        domain: String,
        ttl: u32,
        ip: Ipv4Addr,
    },
    NS {
        domain: String,
        ttl: u32,
        host: String,
    },
    CNAME {
        domain: String,
        ttl: u32,
        host: String,
    },
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    },
    AAAA {
        domain: String,
        ttl: u32,
        ip: Ipv6Addr,
    },
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;
        let qtype = QueryType::from(buffer.read_u16()?);
        let _ = buffer.read_u16()?; // the class
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let ip = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xff) as u8,
                    ((raw_addr >> 16) & 0xff) as u8,
                    ((raw_addr >> 8) & 0xff) as u8,
                    (raw_addr & 0xff) as u8,
                );

                Ok(DnsRecord::A { domain, ttl, ip })
            }
            QueryType::AAAA => {
                let raw_addr1 = buffer.read_u32()?;
                let raw_addr2 = buffer.read_u32()?;
                let raw_addr3 = buffer.read_u32()?;
                let raw_addr4 = buffer.read_u32()?;

                let ip = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xffff) as u16,
                    ((raw_addr1 >> 0) & 0xffff) as u16,
                    ((raw_addr2 >> 16) & 0xffff) as u16,
                    ((raw_addr2 >> 0) & 0xffff) as u16,
                    ((raw_addr3 >> 16) & 0xffff) as u16,
                    ((raw_addr3 >> 0) & 0xffff) as u16,
                    ((raw_addr4 >> 16) & 0xffff) as u16,
                    ((raw_addr4 >> 0) & 0xffff) as u16,
                );

                Ok(DnsRecord::AAAA { domain, ttl, ip })
            }
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize)?;

                Ok(DnsRecord::UNKNOWN {
                    domain,
                    qtype: qtype.into(),
                    data_len,
                    ttl,
                })
            }
            QueryType::NS => {
                let mut host = String::new();
                buffer.read_qname(&mut host)?;

                Ok(DnsRecord::NS { domain, ttl, host })
            }
            QueryType::CNAME => {
                let mut host = String::new();
                buffer.read_qname(&mut host)?;

                Ok(DnsRecord::CNAME { domain, ttl, host })
            }
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let mut host = String::new();
                buffer.read_qname(&mut host)?;

                Ok(DnsRecord::MX {
                    domain,
                    priority,
                    host,
                    ttl,
                })
            }
        }
    }
}

impl DnsRecord {
    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        let start = buffer.pos();

        match self {
            DnsRecord::A { domain, ttl, ip } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.into())?;
                buffer.write_u16(1)?; //class
                buffer.write_u32(ttl.clone())?;
                buffer.write_u16(4)?;

                let octets = ip.octets();
                buffer.write_u8(octets[0])?;
                buffer.write_u8(octets[1])?;
                buffer.write_u8(octets[2])?;
                buffer.write_u8(octets[3])?;
            }
            DnsRecord::UNKNOWN { .. } => println!("Skipping record: {:?}", self),
            DnsRecord::NS { domain, ttl, host } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::NS.into())?;
                buffer.write_u16(1)?; //class
                buffer.write_u32(ttl.clone())?;

                let pos = buffer.pos();
                buffer.write_u16(0)?; // length for now
                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2); // +2 for the size of the size
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::CNAME { domain, ttl, host } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::CNAME.into())?;
                buffer.write_u16(1)?; //class
                buffer.write_u32(ttl.clone())?;

                let pos = buffer.pos();
                buffer.write_u16(0)?; // length for now
                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2); // +2 for the size of the size
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::MX {
                domain,
                priority,
                host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::MX.into())?;
                buffer.write_u16(1)?; //class
                buffer.write_u32(ttl.clone())?;

                let pos = buffer.pos();
                buffer.write_u16(0)?; // length for now
                buffer.write_u16(*priority)?;
                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2); // +2 for the size of the size
                buffer.set_u16(pos, size as u16)?;
            }
            DnsRecord::AAAA { domain, ttl, ip } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.into())?;
                buffer.write_u16(1)?; //class
                buffer.write_u32(ttl.clone())?;
                buffer.write_u16(16)?;

                for segment in ip.segments() {
                    buffer.write_u16(segment)?;
                }
            }
        }
        Ok(buffer.pos() - start)
    }
}

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> Self {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket> {
        let mut result = DnsPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.question_count {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            result.questions.push(question);
        }
        for _ in 0..result.header.answer_count {
            let response = DnsRecord::read(buffer)?;
            result.answers.push(response);
        }
        for _ in 0..result.header.authority_count {
            let response = DnsRecord::read(buffer)?;
            result.authorities.push(response);
        }
        for _ in 0..result.header.additional_count {
            let response = DnsRecord::read(buffer)?;
            result.resources.push(response);
        }
        Ok(result)
    }
}
impl DnsPacket {
    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.header.question_count = self.questions.len() as u16;
        self.header.answer_count = self.answers.len() as u16;
        self.header.authority_count = self.authorities.len() as u16;
        self.header.additional_count = self.resources.len() as u16;

        self.header.write(buffer)?;

        for q in self.questions.iter() {
            q.write(buffer)?;
        }
        for a in self.answers.iter() {
            a.write(buffer)?;
        }
        for a in self.authorities.iter() {
            a.write(buffer)?;
        }
        for r in self.resources.iter() {
            r.write(buffer)?;
        }

        Ok(())
    }
}
fn main() -> Result<()> {
    let qname = "yahoo.com";
    let qtype = QueryType::MX;

    let server = ("8.8.8.8", 53);
    let socket = UdpSocket::bind(("0.0.0.0", 43210))?;

    let mut packet = DnsPacket::new();

    packet.header.id = 6666;
    packet.header.question_count = 1;
    packet.header.recursion_desired = true;

    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    let mut request_buffer = BytePacketBuffer::new();

    packet.write(&mut request_buffer)?;
    let len = request_buffer.pos();

    socket.send_to(&request_buffer.buf[..len], server)?;

    let mut rec_buffer = BytePacketBuffer::new();
    socket.recv_from(&mut rec_buffer.buf)?;

    let mut f = std::fs::File::create("output.txt")?;
    f.write_all(&rec_buffer.buf)?;
    let packet = DnsPacket::from_buffer(&mut rec_buffer)?;

    println!("{:#?}", packet.header);

    for q in packet.questions {
        println!("{:#?}", q);
    }
    for a in packet.answers {
        println!("{:#?}", a);
    }
    for a in packet.authorities {
        println!("{:#?}", a);
    }
    for r in packet.resources {
        println!("{:#?}", r);
    }
    Ok(())
}
