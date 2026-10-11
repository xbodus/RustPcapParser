use std::fs::File;
use std::path::PathBuf;
use std::fmt;
use pcap_file::{DataLink, Endianness, TsResolution};
use pcap_file::pcap::PcapReader;


// 24 byte Global Header from PcapReader to check against
struct GlobalHeader {
    endianness: Endianness, // 4 bytes
    major_version: u16, // 2 bytes
    minor_version: u16, // 2 bytes
    timezone: TsResolution, // 8 bytes
    snap_len: u32, //4 bytes
    link_type: DataLink // 4 bytes
}

impl fmt::Display for GlobalHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Endianness: {:?}, Major: {:?}, Minor: {:?}, Timezone: {:?}, SnapLen: {:?}, LinkType: {:?}",
            self.endianness,
            self.major_version,
            self.minor_version,
            self.timezone,
            self.snap_len,
            self.link_type
        )
    }
}

fn parse_global_header(file: File) {
    // Happy path. Using pcap-file library to check against raw byte parsing

    // Open PCAP file and push to PCAP reader
    let pcap_reader : PcapReader<File> = PcapReader::new(file).expect("Invalid PCAP file");

    // Prepare structure for Pcap global header
    let global_header = GlobalHeader {
        endianness: pcap_reader.header().endianness,
        major_version: pcap_reader.header().version_major,
        minor_version: pcap_reader.header().version_minor,
        timezone: pcap_reader.header().ts_resolution,
        snap_len: pcap_reader.header().snaplen,
        link_type: pcap_reader.header().datalink
    };

    // Verify PCAP global header
    println!("Global Header: {}", global_header)
}

fn main() {
    // Get path to project root directory and append relative path to PCAP file
    let mut file_path : PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file_path.push("src/PcapFiles/236-XLMRat.pcap");

    // Verify path
    println!("Attempting to open {:?}...", file_path);

    let file : File = File::open(file_path).expect("Failed to open files");

    // Verify global headers from PcapReader
    parse_global_header(file);


}
