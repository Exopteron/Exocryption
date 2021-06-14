use std::io::Read;
#[derive(Debug)]
pub struct VarInt {
    number: u32
}
impl VarInt {
    #[allow(dead_code)]
    pub fn new(number: u32) -> VarInt {
        return VarInt {number: number};
    }
    #[allow(dead_code)]
    pub fn new_as_bytes(number: u32) -> Vec<u8> {
        let mut vint = VarInt {number: number};
        return vint.into_bytes();
    }
    #[allow(dead_code)]
    pub fn u32_from_bytes(mut input: &mut Vec<u8>) -> u32 {
        let vint = VarInt::from_bytes(&mut input);
        return vint.number;
    }
    pub fn into_bytes(&mut self) -> Vec<u8> {
        use integer_encoding::VarInt;
        let mut packetconstruct = vec![];
        let mut varint1 = vec![0; 32];
        self.number.encode_var(&mut varint1);
        for i in 0..varint1.len() {
            if varint1[i] != 0 {
                packetconstruct.push(varint1[i]);
            }
        }
        return packetconstruct;
    }
    pub fn from_bytes(inputvec: &mut Vec<u8>) -> VarInt {
        use std::convert::TryInto;
        let mut inputreader = std::io::Cursor::new(inputvec.clone());
        let mut input = vec![0; 1];
        inputreader.read_exact(&mut input).expect("Failed to read");
        let mut fullbyte: Vec<String> = vec![];
        let mut current = 0;
        let mut bytesstepped = 0;
        let mut largebytestepped = 0;
        for _ in 0..5 {
            bytesstepped += 1;
            let currentbyte = format!("{:b}", input[current]);
            let mut var = currentbyte.chars().rev().collect::<String>();
            for _g in 0..9 - var.chars().count() {
                if var.chars().count() < 8 {
                    var.push_str("0");
                }
            }
            let currentbyte = var.chars().rev().collect::<String>();
            //println!("current byte: {}",currentbyte);
            if currentbyte.chars().nth(0).unwrap() == '1' {
                if currentbyte.len() > 1 {
                    //println!("Pushing: {}",&currentbyte[1..currentbyte.len()]);
                    fullbyte.push(currentbyte[1..currentbyte.len()].to_string());
                    current += 1;
                } else {
                    fullbyte.push(currentbyte);
                    current += 1;
                }
                let mut buf = vec![0; 1];
                // Do appropriate error handling for your situation
                // Maybe it's OK if you didn't read enough bytes?
                inputreader.read_exact(&mut buf).expect("Didn't read enough");
                input.append(&mut buf.clone());
            } else {
                //println!("Pushing B: {}",&currentbyte[1..currentbyte.len()]);
                fullbyte.push(currentbyte[1..currentbyte.len()].to_string());
                break;
            }
        }
        fullbyte.reverse();
        let mut fullbyte2 = "".to_owned();
        //println!("Full byte: {:?}",fullbyte);
        for i in 0..fullbyte.len() {
            fullbyte2.push_str(&fullbyte[i]);
        }
    
        let finalen: u32 = isize::from_str_radix(&fullbyte2, 2)
            .unwrap()
            .try_into()
            .unwrap();
        largebytestepped+=bytesstepped;
        //largebytestepped+=finalen;
        for _ in 0..largebytestepped {
            inputvec.remove(0);
        }
        return VarInt {number: finalen};
    }
}