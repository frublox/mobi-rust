use crate::lz77;
use std::fs;
use std::io;
use std::str;
use std::convert::TryInto;
use std::thread;
use std::sync::mpsc;
use std::time::Instant;

struct RecordInfoEntry {
    offset: u32,
    attributes: u8,
    unique_id: [u8; 3],
}

impl RecordInfoEntry {
    fn new(bytes: &[u8]) -> RecordInfoEntry {
        RecordInfoEntry {
            offset: u32::from_be_bytes(bytes[0..4].try_into().unwrap()),
            attributes: bytes[4],
            unique_id: bytes[5..8].try_into().unwrap(),
        }
    }
}

/// Metadata specified by the Palm Database Format.
/// 
/// The Mobipocket file format is a standard Palm Database Format file with
/// MOBI-related metadata in the the first record (see `PalmDocHeader` and `MobiHeader`).
struct Metadata {
    name: String,
    attributes: u16,
    version: u16,
    creation_date: u32,
    modification_date: u32,
    last_backup_date: u32,
    modification_number: u32,
    app_info_id: u32,
    sort_info_id: u32,
    type_: u32,
    creator: u32,
    unique_seed_id: u32,
    next_record_list_id: u32,
    number_of_records: u16,
    record_info_list: Vec<RecordInfoEntry>,
}

impl Metadata {
    fn new(bytes: &[u8]) -> Metadata {
        let name = String::from_utf8(bytes[0..32].to_vec()).unwrap();
        let attributes = u16::from_be_bytes(bytes[32..34].try_into().unwrap());
        let version = u16::from_be_bytes(bytes[34..36].try_into().unwrap());
        let creation_date = u32::from_be_bytes(bytes[36..40].try_into().unwrap());
        let modification_date = u32::from_be_bytes(bytes[40..44].try_into().unwrap());
        let last_backup_date = u32::from_be_bytes(bytes[44..48].try_into().unwrap());
        let modification_number = u32::from_be_bytes(bytes[48..52].try_into().unwrap());
        let app_info_id = u32::from_be_bytes(bytes[52..56].try_into().unwrap());
        let sort_info_id = u32::from_be_bytes(bytes[56..60].try_into().unwrap());
        let type_ = u32::from_be_bytes(bytes[60..64].try_into().unwrap());
        let creator = u32::from_be_bytes(bytes[64..68].try_into().unwrap());
        let unique_seed_id = u32::from_be_bytes(bytes[68..72].try_into().unwrap());
        let next_record_list_id = u32::from_be_bytes(bytes[72..76].try_into().unwrap());
        let number_of_records = u16::from_be_bytes(bytes[76..78].try_into().unwrap());

        let mut record_info_list = Vec::with_capacity(number_of_records as usize);
        let mut n = number_of_records;
        let mut i = 78;
        while n > 0 {
            let entry = RecordInfoEntry::new(&bytes[i..(i+8)]);
            i += 8;
            n -= 1;
            record_info_list.push(entry);
        }

        Metadata {
            name, attributes, version, creation_date, modification_date, last_backup_date,
            modification_number, app_info_id, sort_info_id, type_, creator, unique_seed_id,
            next_record_list_id, number_of_records, record_info_list
        }
    }
}

/// A 16-byte header at the start of record 0.
/// Gives some basic information about the Mobipocket file.
#[derive(Debug)]
struct PalmDocHeader {
    /// 1 = no compression
    /// 
    /// 2 = PalmDOC compression
    /// 
    /// 17480 = HUFF/CDIC compression
    compression: u16,
    unused: u16,
    /// The length of the book's uncompressed text.
    text_length: u32,
    /// Number of PDB records used for the text of book.
    record_count: u16,
    /// Maximum size of each record containing text. Always 4096.
    record_size: u16,
    /// 0 == no encryption
    /// 
    /// 1 = Old Mobipocket Encryption
    /// 
    /// 2 = Mobipocket Encryption
    encryption_type: u16,
    unknown_14: u16,
}

impl PalmDocHeader {
    fn new(bytes: &[u8]) -> PalmDocHeader {
        PalmDocHeader {
            compression: u16::from_be_bytes(bytes[0..2].try_into().unwrap()),
            unused: u16::from_be_bytes(bytes[2..4].try_into().unwrap()),
            text_length: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
            record_count: u16::from_be_bytes(bytes[8..10].try_into().unwrap()),
            record_size: u16::from_be_bytes(bytes[10..12].try_into().unwrap()),
            encryption_type: u16::from_be_bytes(bytes[12..14].try_into().unwrap()),
            unknown_14: u16::from_be_bytes(bytes[14..16].try_into().unwrap()),
        }
    }
}

#[derive(Debug)]
/// A variable-length header giving most of the information about the Mobipocket file.
/// 
/// This header is not officially documented, so the purpose of some fields are unknown 
/// (named as `unknown_(offset)`). Most of this information is taken from the mobileread
/// wiki page at https://wiki.mobileread.com/wiki/MOBI.
struct MobiHeader {
    /// The characters M O B I.
    identifier: String,
    /// The length of the MOBI header, including the previous 4 bytes.
    length: u32,
    /// The kind of Mobipocket file this is.
    /// 
    /// 2 = Mobipocket Book,
    /// 
    /// 3 = PalmDoc Book,
    /// 
    /// 4 = Audio,
    /// 
    /// 232 = mobipocket? generated by kindlegen1.2,
    /// 
    /// 248 = KF8: generated by kindlegen2,
    /// 
    /// 257 = News,
    /// 
    /// 258 = News_Feed,
    /// 
    /// 259 = News_Magazine,
    /// 
    /// 513 = PICS,
    /// 
    /// 514 = WORD,
    /// 
    /// 515 = XLS,
    /// 
    /// 516 = PPT,
    /// 
    /// 517 = TEXT,
    /// 
    /// 518 = HTML
    mobi_type: u32,
    /// The encoding of the text in the text records.
    /// 1252 = CP1252 (WinLatin1); 65001 = UTF-8 
    text_encoding: u32,
    /// Some kind of unique ID number (random?).
    unique_id: u32,
    /// Version of the Mobipocket format used in this file.
    file_version: u32,
    /// First record number (starting with 0) that's not the book's text.
    /// 
    /// This seems to point to the start of special metadata records, such as INDX.
    /// Since text records come before these metadata records (with a record of a few null bytes in between),
    /// we currently use this to figure out where the text records end.
    first_non_book_record_number: u32,
    /// The offset (relative to the start of record 0, rather than the start of the file) of the book's full name.
    full_name_offset: u32,
    /// The length of the book's full name.
    full_name_length: u32,
    /// Book locale code.
    /// 
    /// Low byte is main language 09 = English, next byte is dialect, 08 = British, 04 = US. 
    /// Thus US English is 1033, UK English is 2057. 
    locale: u32,
    /// Input language for a dictionary.
    input_language: u32,
    /// Output language for a dictionary.
    output_language: u32,
    /// Minimum Mobipocket version support needed to read this file.
    min_version: u32,
    /// First record number (starting with 0) that contains an image. 
    /// Image records should be sequential.
    first_image_record_number: u32,
    /// The record number of the first huffman compression record.
    first_huffman_record_number: u32,
    /// The number of huffman compression records. 
    huffman_record_count: u32,
    /// If bit 6 (0x40) is set, then an EXTH header is present
    exth_flags: u32,
    /// Number of first text record. Normally 1.
    /// 
    /// In some Mobipocket files, this is 0 even when the text records actually start at 1.
    /// For this reason, we just assume the text records always start at 1.
    first_content_record_number: u16,
    /// Number of last image record, or last text record if it contains no images.
    /// This includes Image, DATP, HUFF, DRM records.
    last_content_record_number: u16,
    unknown_180: u32,
    /// The record number of the first FCIS record.
    fcis_record_number: u32,
    /// The number of FCIS records.
    fcis_record_count: u32,
    /// The record number of the first FLIS record. 
    flis_record_number: u32,
    /// The number of FLIS records.
    flis_record_count: u32,
    /// A set of binary flags, some of which indicate extra data at the end of each text block. 
    /// This only seems to be valid for Mobipocket format version 5 and 6 (and higher?), 
    /// when the header length is 228 (0xE4) or 232 (0xE8). 
    /// 
    /// bit 1 (0x1): <extra multibyte bytes><size>
    /// 
    /// bit 2 (0x2): <TBS indexing description of this HTML record><size>
    /// 
    /// bit 3 (0x4): <uncrossable breaks><size>
    extra_record_data_flags: u32,
    indx_record_number: u32,
}

impl MobiHeader {
    fn new(bytes: &[u8]) -> MobiHeader {
        MobiHeader {
            identifier: String::from_utf8(bytes[0..4].to_vec()).unwrap(),
            length: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
            mobi_type: u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
            text_encoding: u32::from_be_bytes(bytes[12..16].try_into().unwrap()),
            unique_id: u32::from_be_bytes(bytes[16..20].try_into().unwrap()),
            file_version: u32::from_be_bytes(bytes[20..24].try_into().unwrap()),

            first_non_book_record_number: u32::from_be_bytes(bytes[64..68].try_into().unwrap()),
            full_name_offset: u32::from_be_bytes(bytes[68..72].try_into().unwrap()),
            full_name_length: u32::from_be_bytes(bytes[72..76].try_into().unwrap()),
            locale: u32::from_be_bytes(bytes[76..80].try_into().unwrap()),
            input_language: u32::from_be_bytes(bytes[80..84].try_into().unwrap()),
            output_language: u32::from_be_bytes(bytes[84..88].try_into().unwrap()),
            min_version: u32::from_be_bytes(bytes[88..92].try_into().unwrap()),
            first_image_record_number: u32::from_be_bytes(bytes[92..96].try_into().unwrap()),
            first_huffman_record_number: u32::from_be_bytes(bytes[96..100].try_into().unwrap()),
            huffman_record_count: u32::from_be_bytes(bytes[100..104].try_into().unwrap()),

            exth_flags: u32::from_be_bytes(bytes[112..116].try_into().unwrap()),

            first_content_record_number: u16::from_be_bytes(bytes[176..178].try_into().unwrap()),
            last_content_record_number: u16::from_be_bytes(bytes[178..180].try_into().unwrap()),
            unknown_180: u32::from_be_bytes(bytes[180..184].try_into().unwrap()),
            fcis_record_number: u32::from_be_bytes(bytes[184..188].try_into().unwrap()),
            fcis_record_count: u32::from_be_bytes(bytes[188..192].try_into().unwrap()),
            flis_record_number: u32::from_be_bytes(bytes[192..196].try_into().unwrap()),
            flis_record_count: u32::from_be_bytes(bytes[196..200].try_into().unwrap()),

            extra_record_data_flags: u32::from_be_bytes(bytes[224..228].try_into().unwrap()),
            indx_record_number: u32::from_be_bytes(bytes[228..232].try_into().unwrap()),
        }
    }
}

#[derive(Debug)]
struct ExthRecord {
    type_: u32,
    length: u32,
    data: Vec<u8>,
}

impl ExthRecord {
    fn new(bytes: &[u8]) -> ExthRecord {
        let type_ = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        let length = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        let data = bytes[8..(length as usize + 8)].to_vec();

        ExthRecord {
            type_, length, data
        }
    }
}

#[derive(Debug)]
struct ExthHeader {
    identifier: String,
    header_length: u32,
    record_count: u32,
    record_list: Vec<ExthRecord>,
    padding: Vec<u8>,
}

impl ExthHeader {
    fn new(bytes: &[u8]) -> ExthHeader {
        let identifier = String::from_utf8(bytes[0..4].to_vec()).unwrap();
        let header_length = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        let record_count = u32::from_be_bytes(bytes[8..12].try_into().unwrap());

        let mut record_list = Vec::with_capacity(record_count as usize);
        let mut n = record_count;
        let mut i = 12;
        while n > 0 {
            let record = ExthRecord::new(&bytes[i..]);
            i += record.length as usize;
            n -= 1;
            record_list.push(record);
        }

        let mut padding = Vec::with_capacity(header_length as usize % 4);
        for _ in 0..padding.capacity() {
            padding.push(0);
        }

        ExthHeader {
            identifier, header_length, record_count, record_list, padding,
        }
    }
}

#[derive(Clone)]
#[derive(Debug)]
/// A PalmDoc Database Format record. 
/// The contents of records can be metadata, text, images, etc.
/// Records containing content like text and images are LZ77-encoded.
/// 
/// In addition, text records can optionally can trailing entries specifying things like
/// bytes needed to complete a multibyte character that crosses the record boundary 
/// (`extra_multibyte_bytes`).
struct Record {
    data: Vec<u8>,
    extra_multibyte_bytes: Vec<u8>,
    tbs_indexing_description: Vec<u8>,
    uncrossable_breaks: Vec<u8>,
}

impl Record {
    fn new(bytes: &[u8], flags: u32) -> Record {
        let mut extra_multibyte_bytes = vec!();
        let mut tbs_indexing_description = vec!();
        let mut uncrossable_breaks = vec!();

        let mut i = bytes.len();
        i -= 1;
        
        if flags & 0x4 != 0 {
            read_trailing_entry(&bytes, &mut i, &mut uncrossable_breaks);
        } 
        if flags & 0x2 != 0 {
            read_trailing_entry(&bytes, &mut i, &mut tbs_indexing_description);
        }
        if flags & 0x1 != 0 {
            // Trailing multibytes are handled a bit differently
            // Instead of a backwards-encoded VL integer, we just use the bottom 2
            // bits of the end byte to see how many trailing multibytes there are
            let n = bytes[i] & 0b0000_0011;
            i -= 1;
            for _ in 0..n {
                extra_multibyte_bytes.push(bytes[i]);
                i -= 1;
            }
        }

        let data = bytes[..i+1].to_vec();

        Record {
            data, extra_multibyte_bytes, tbs_indexing_description, uncrossable_breaks,
        }
    }
}

fn read_trailing_entry(bytes: &[u8], i: &mut usize, output: &mut Vec<u8>)  {
    let mut size = backwards_encoded_vl_integer(&bytes, i);
    size -= 1; // TODO for now assuming size itself is only 1 byte long
    while size > 0 {
        output.push(bytes[*i]);
        *i -= 1;
        size -= 1;
    }
}

/// Decode a Mobipocket backwards-encoded variable-length integer.
fn backwards_encoded_vl_integer(bytes: &[u8], i: &mut usize) -> u32 {
    let mut n = 0;
    let mut pos = 0;
    loop {
        // Add bottom 7 bits to n
        n |= ((bytes[*i] & 0b0111_1111) as u32) << pos;
        pos += 7;
        *i -= 1;
        // If msb was set or we've read 28 bits, we're done
        if bytes[*i + 1] & 0b1000_0000 != 0 || pos >= 28 {
            break;
        }
    }
    n
}

// I have no idea what this is used for.
#[derive(Debug)]
struct IndexMeta {
    identifier: String,
    length: u32,
    type_: u32,
    unknown_12: u32,
    unknown_16: u32,
    idxt_start: u32,
    index_count: u32,
    index_encoding: u32,
    total_index_count: u32,
    ordt_start: u32,
    ligt_start: u32,
    unknown_48: u32,
    unknown_52: u32,
}

impl IndexMeta {
    fn new(bytes: &[u8]) -> IndexMeta {
        IndexMeta {
            identifier: String::from_utf8(bytes[0..4].to_vec()).unwrap(),
            length: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
            type_: u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
            unknown_12: u32::from_be_bytes(bytes[12..16].try_into().unwrap()),
            unknown_16: u32::from_be_bytes(bytes[16..20].try_into().unwrap()),
            idxt_start: u32::from_be_bytes(bytes[20..24].try_into().unwrap()),
            index_count: u32::from_be_bytes(bytes[24..28].try_into().unwrap()),
            index_encoding: u32::from_be_bytes(bytes[28..32].try_into().unwrap()),
            total_index_count: u32::from_be_bytes(bytes[32..36].try_into().unwrap()),
            ordt_start: u32::from_be_bytes(bytes[36..40].try_into().unwrap()),
            ligt_start: u32::from_be_bytes(bytes[40..44].try_into().unwrap()),
            unknown_48: u32::from_be_bytes(bytes[48..52].try_into().unwrap()),
            unknown_52: u32::from_be_bytes(bytes[52..56].try_into().unwrap()),
        }
    }
}

#[derive(Debug)]
struct TagTableEntry {
    tag: u8,
    num_values: u8,
    bit_mask: u8,
    control_byte_end: u8,
    values: Vec<Vec<u8>>,
}

impl TagTableEntry {
    fn new(bytes: &[u8]) -> TagTableEntry {
        let tag = bytes[0];
        let num_values = bytes[1];
        let bit_mask = bytes[2];
        let control_byte_end = bytes[3];

        let mut values = vec!();
        let mut i = 4;
        while i < (4 + 4*(num_values as usize)) {
            values.push(bytes[i..i+4].to_vec());
            i += 4;
        }

        TagTableEntry {
            tag, num_values, bit_mask, control_byte_end, values,
        }
    }
}

#[derive(Debug)]
struct TagxSection {
    identifier: String,
    length: u32,
    control_byte_count: u32,
    tag_table: Vec<TagTableEntry>,
}

impl TagxSection {
    fn new(bytes: &[u8]) -> TagxSection {
        let identifier = String::from_utf8(bytes[0..4].to_vec()).unwrap();
        let length = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        let control_byte_count = u32::from_be_bytes(bytes[8..12].try_into().unwrap());

        let mut tag_table = vec!();
        let mut i = 12;
        while i < (length as usize) {
            let entry = TagTableEntry::new(&bytes[i..]);
            i += 4 + 4*(entry.num_values as usize);
            tag_table.push(entry);
        }

        TagxSection {
            identifier, length, control_byte_count, tag_table,
        }
    }
}

/// A Mobipocket format file.
pub struct Mobi {
    metadata: Metadata,
    record_list: Vec<Record>,
    /// Found in record 0
    palm_doc_header: PalmDocHeader,
    /// Found in record 0
    mobi_header: MobiHeader,
    /// Found in record 0
    exth_header: Option<ExthHeader>,
    /// Found in record 0
    full_name: String,
    index_meta_record: Option<IndexMeta>,
    tagx_section: Option<TagxSection>,
}

impl Mobi {
    /// Deserialize a MOBI file from a sequence of bytes. 
    pub fn from_file(path: &str) -> io::Result<Mobi> {
        let bytes = fs::read(path)?;
        let metadata = Metadata::new(&bytes);

        // Special record 0 data
        let record0_offset = metadata.record_info_list[0].offset as usize;
        let mut offset = record0_offset;
        let palm_doc_header = PalmDocHeader::new(&bytes[offset..offset+16]);
        offset += 16;
        let mobi_header = MobiHeader::new(&bytes[offset..]);
        offset += mobi_header.length as usize;
        let exth_header = 
            if mobi_header.exth_flags & 0x40 != 0 {
                let header = ExthHeader::new(&bytes[offset..]);
                Option::Some(header)
            } else {
                Option::None
            };
        let full_name_offset = record0_offset + mobi_header.full_name_offset as usize;
        let full_name_length = mobi_header.full_name_length as usize;
        let full_name = String::from_utf8(bytes[full_name_offset..full_name_offset + full_name_length].to_vec()).unwrap();

        // The actual full list of records
        let mut record_list = Vec::with_capacity(metadata.number_of_records as usize);
        let record_info_list = &metadata.record_info_list;
        record_list.push(Record::new(&bytes[record0_offset..], 0));
        for i in 1..(metadata.number_of_records as usize - 1) {
            let offset = record_info_list[i].offset as usize;
            let next_offset = record_info_list[i + 1].offset as usize;

            // Only text records can have trailing entries
            let flags = 
                if i < (mobi_header.first_non_book_record_number as usize - 1) {
                    mobi_header.extra_record_data_flags
                } else {
                    0 
                };
            
            record_list.push(Record::new(&bytes[offset..next_offset], flags));
        }
        let last_offset = record_info_list[record_info_list.len() - 1].offset as usize;
        record_list.push(Record::new(&bytes[last_offset..], 0));

        let (index_meta_record, tagx_section) = 
            if mobi_header.indx_record_number as usize != 0xffffffff {
                let index_record = &record_list[mobi_header.indx_record_number as usize].data;
                let index = IndexMeta::new(&index_record);
                let tagx = TagxSection::new(&index_record[index.length as usize..]);
                (Option::Some(index), Option::Some(tagx))
            } else {
                (Option::None, Option::None)
            };
        
        let mobi = Mobi {
            metadata, palm_doc_header, mobi_header, exth_header, record_list, full_name,
            index_meta_record, tagx_section,
        };
        Ok(mobi)
    }

    /// Serialize a MOBI struct back into a sequence of bytes.
    pub fn to_bytes(mobi: &Mobi) -> Vec<u8> {
        panic!("TODO implement")
    }

    pub fn dump_text_to_file(mobi: &Mobi, path: &str) -> Result<(), String> {
        let first_non_book_record_number = mobi.mobi_header.first_non_book_record_number as usize;
        let text_records = &mobi.record_list[1..first_non_book_record_number - 1];

        println!("Decompressing with 1 thread.");
        let decompression_start = Instant::now();
        let mut decompressed = vec!();
        for record in text_records.iter() {
            lz77::decompress(&record.data, &mut decompressed);
        }
        let decompression_end = Instant::now();

        let mut total_text_size = 0;
        for record in text_records {
            total_text_size += record.data.len();
        }

        println!("Decompressed {} KiB ({:.2} MiB) in {} ms.", 
            total_text_size / 1024, (total_text_size as f32) / 1024.0 / 1024.0, 
            decompression_end.duration_since(decompression_start).as_millis());

        let s = str::from_utf8(&decompressed).map_err(|x| format!("{}", x))?;
        let result = fs::write(path, s).map_err(|x| format!("{}", x));
        println!("Wrote text to \"{}\"", path);
        result
    }

    pub fn dump_text_to_file_concurrent(mobi: &Mobi, path: &str, num_threads: usize) -> Result<(), String> {
        let first_non_book_record_number = mobi.mobi_header.first_non_book_record_number as usize;
        let text_records = &mobi.record_list[1..first_non_book_record_number - 1];

        println!("Decompressing with {} threads.", num_threads);
        let decompression_start = Instant::now();
        let (tx, rx) = mpsc::channel();
        let chunk_size = text_records.len() / num_threads;
        for (i, chunk) in text_records.chunks(chunk_size).enumerate() {
            let tx_clone = mpsc::Sender::clone(&tx);
            let builder = thread::Builder::new();

            // We know that these threads won't outlive the current thread (the one owning `mobi`).
            // Rust doesn't, however, so we're not allowed to use `chunk` with thread::spawn.
            // `spawn_unchecked` lets us get around cloning the chunk.
            // It's a small speed boost. On my machine, it's around ~50ms faster for 65 MiB of compressed 
            // data.

            // TODO let's just create the vec here and pass a ref to the thread
            // Then the thread can just write into it, avoiding another copy

            unsafe {
                builder.spawn_unchecked(move || {
                    let mut decompressed = vec!();
                    for record in chunk {
                        lz77::decompress(&record.data, &mut decompressed);
                    }
                    tx_clone.send((i, decompressed)).unwrap();
                }).unwrap();
            }
        }

        let mut results = vec!();
        for _ in 0..num_threads {
            results.push(rx.recv().unwrap());
        }
        results.sort_by(|x, y| x.0.cmp(&y.0));

        let mut decompressed = vec!();
        for (_, bytes) in results.iter_mut() {
            decompressed.append(bytes);
        }
        let decompression_end = Instant::now();

        let mut total_text_size = 0;
        for record in text_records.iter() {
            total_text_size += record.data.len();
        }
        println!("Decompressed {} KiB ({:.2} MiB) in {} ms.", 
            total_text_size / 1024, (total_text_size as f32) / 1024.0 / 1024.0, 
            decompression_end.duration_since(decompression_start).as_millis());

        let s = str::from_utf8(&decompressed).map_err(|x| format!("{}", x))?;
        let result = fs::write(path, s).map_err(|x| format!("{}", x));
        println!("Wrote text to {}.", path);
        result
    }

    /// Display a rough summary useful for debugging.
    pub fn display_summary(mobi: &Mobi) {
        println!("number_of_records = {}", mobi.record_list.len());
        println!("{:#?}", mobi.palm_doc_header);
        println!("{:#?}", mobi.mobi_header);
        // println!("{:#?}", mobi.index_meta_record);
        // println!("{:#?}", mobi.tagx_section);
        println!("full name = {}", mobi.full_name);

        println!("\nRecords summary:");
        println!("\t0 - MOBI header and other metadata");
        println!("\t{}-{} - text", 
            1, mobi.mobi_header.first_non_book_record_number - 2);
        println!("\t{}-{} - other",
            mobi.mobi_header.first_non_book_record_number - 1, mobi.mobi_header.first_image_record_number - 1);
        println!("\t{}-{} - images(?)", 
            mobi.mobi_header.first_image_record_number, mobi.metadata.number_of_records);

        // mobi.exth_header.map(|header| {
        //     for record in &header.record_list {
        //         println!("type = {}, text = {}", 
        //             record.type_, str::from_utf8(&record.data).unwrap_or(""));
        //     }
        // });

        // for (i, entry) in mobi.metadata.record_info_list.iter().enumerate() {
        //     println!("record = {:2}, offset = {}, size = {}, mb = {:?}, tbs = {:?}", 
        //         i, entry.offset, mobi.record_list[i].data.len(), 
        //         &mobi.record_list[i].extra_multibyte_bytes,
        //         &mobi.record_list[i].tbs_indexing_description);

        //     if i >= mobi.mobi_header.first_non_book_record_number as usize {
        //         break;
        //     }
        // }
    }
}