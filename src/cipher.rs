extern crate base64;
extern crate hex;
extern crate openssl;

use base64::encode;
use openssl::symm::{decrypt, Cipher};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};

pub fn hex_to_b64(data_hex: &[u8]) -> String {
    encode(hex::decode(data_hex).expect("fuckery"))
}

pub fn fixed_xor(a: Vec<u8>, b: Vec<u8>) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(&x, &y)| x ^ y).collect()
}

pub fn read_bytes_no_whitespace(path: &str) -> Vec<u8> {
    let base64_s = fs::read_to_string(path)
        .and_then(|result| Ok(result.replace("\n", "")))
        .expect("Error reading file");
    base64::decode(base64_s).unwrap()
}

const LETTER_FREQ: [f64; 27] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, // A-G
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, // H-N
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, // O-U
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074, 0.19181, // V-Z & space char
];

pub fn calc_letter_freq_score(s: &str) -> f64 {
    let mut counts = vec![0_u32; 27];
    let mut score: f64 = 0_f64;

    s.chars().for_each(|c| match c {
        'a'..='z' => {
            counts[c as usize - 97] += 1;
        }
        'A'..='Z' => {
            counts[c as usize - 65] += 1;
        }
        ' ' => counts[26] += 1,
        _ => {}
    });

    for i in 0..27 {
        score += (counts[i] as f64) * LETTER_FREQ[i];
    }

    score
}

pub fn single_byte_xor(hex: &str) -> (String, f64) {
    let mut best_score = f64::MIN;
    let mut message = String::new();
    let bytes = hex::decode(hex).unwrap();
    for key in 0..=255 {
        let decoded: Vec<_> = bytes.iter().map(|x| x ^ key).collect();
        let decoded_string = String::from_utf8_lossy(&decoded);
        if decoded_string.is_ascii() {
            let string_score = calc_letter_freq_score(&decoded_string);
            if string_score > best_score {
                best_score = string_score;
                message = decoded_string.to_string();
            }
        }
    }
    //println!("score: {:?}, decoded: {:?}", best_score, message);
    (message, best_score)
}

pub fn single_character_xor_from_file(path: &str) -> (String, f64) {
    let file = File::open(path).expect("file failed to open");
    let lines = BufReader::new(file).lines();

    let mut line: String = String::new();
    let mut key = f64::MIN;
    let mut best_score: f64 = f64::MIN;

    for line_result in lines.enumerate() {
        let score = single_byte_xor(&line_result.1.unwrap());
        if score.1 > best_score {
            best_score = score.1;
            line = score.0;
            key = line_result.0 as f64;
        }
    }
    (line, key)
}

pub fn repeating_key_xor_impl(string: &str, key: &str) -> String {
    let key_seq: String = key.chars().cycle().take(string.len()).collect::<String>();
    let key_bytes = key_seq.as_bytes();
    let string_bytes = string.as_bytes();
    let content: Vec<u8> = string_bytes
        .iter()
        .zip(key_bytes.iter())
        .map(|(&b1, &b2)| b1 ^ b2)
        .collect();
    let raw = String::from_utf8_lossy(&content).to_string();
    hex::encode(raw)
}

pub fn single_char_xor(xor_bytes: &[u8]) -> u8 {
    let mut best_score = f64::MIN;
    let mut key: u8 = 0;
    for key_byte in 0..=255 {
        let msg_bytes: Vec<_> = xor_bytes.iter().map(|x| x ^ key_byte).collect();
        let message = String::from_utf8_lossy(&msg_bytes);
        let string_score = calc_letter_freq_score(&message);
        if string_score > best_score {
            best_score = string_score;
            key = key_byte
        }
    }
    //println!("score: {:?}, decoded: {:?}", best_score, message);
    key
}

pub fn hamming_distance(string_1: &[u8], string_2: &[u8]) -> u32 {
    if string_1.len() != string_2.len() {
        panic!("unequal string slices");
    }

    string_1
        .iter()
        .zip(string_2.iter())
        .fold(0_u32, |dist, (x1, x2)| {
            let bin1 = format!("{:08b}", x1);
            let bin2 = format!("{:08b}", x2);

            dist + bin1
                .chars()
                .zip(bin2.chars())
                .fold(0_u32, |d, (ch1, ch2)| if ch1 == ch2 { d } else { d + 1 })
        })
}

pub fn calc_avg_edit_dist(key_size: usize, txt_bytes: &[u8]) -> f64 {
    let len = txt_bytes.len();
    let mut i: usize = 0;
    let mut dist_sum = 0;
    let mut block1;
    let mut block2;

    loop {
        if i * 2 * key_size >= len {
            break;
        }

        block1 = &txt_bytes[i * key_size..(i + 1) * key_size];
        block2 = &txt_bytes[(i + 1) * key_size..(i + 2) * key_size];

        dist_sum += hamming_distance(block1, block2) / (key_size as u32);

        i += 1;
    }

    (dist_sum as f64) / (i as f64 + 1.0)
}

pub fn break_repeating_key_xor(path: &str) -> String {
    let text_bytes = read_bytes_no_whitespace(path);

    let mut edit_dist: Vec<(usize, f64)> = Vec::new();

    for key_sz in 2..40 {
        let dist = calc_avg_edit_dist(key_sz, &text_bytes);
        edit_dist.push((key_sz, dist));
    }

    edit_dist.sort_by(|x, y| y.1.partial_cmp(&x.1).unwrap());
    let key_sz = edit_dist.pop().and_then(|x| Some(x.0)).unwrap();

    let mut transposed: Vec<Vec<u8>> = vec![vec![]; key_sz];

    for slice in text_bytes.chunks(key_sz) {
        if slice.len() == key_sz {
            for i in 0..slice.len() {
                let item = slice[i];
                transposed[i].push(item);
            }
        }
    }

    let mut key_vector: Vec<u8> = Vec::new();

    for block in transposed {
        let key_i = single_char_xor(&block);
        key_vector.push(key_i);
    }

    let key: String = key_vector.iter().map(|&b| b as char).collect();
    key
}

pub fn decrypt_aes_ecb(path: &str, key: &str) -> String {
    let text_bytes = read_bytes_no_whitespace(path);
    let key = key.as_bytes();

    let decoded_cipher_text =
        decrypt(Cipher::aes_128_ecb(), key, Some(&text_bytes), &text_bytes).unwrap();
    String::from_utf8_lossy(&decoded_cipher_text).to_string()
}


