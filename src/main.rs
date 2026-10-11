use std::fs::File;
use std::path::PathBuf;
use pcap_file::pcap::PcapReader;

fn main() {
    // Get path to project root directory and append relative path to PCAP file
    let mut file_path : PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    file_path.push("src/PcapFiles/236-XLMRat.pcap");

    // Verify path
    println!("Attempting to open {:?}...", file_path);

    // Open PCAP file and push to PCAP reader
    let file : File = File::open(file_path).expect("Failed to open files");
    let pcap_reader : PcapReader<File> = PcapReader::new(file).expect("Invalid PCAP file");

    // Verify PCAP is being read properly
    println!("Global Header Snaplen: {}", pcap_reader.header().snaplen)
}
