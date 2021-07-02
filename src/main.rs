
use std::io;
use std::io::Write;
use std::io::prelude::*;
use std::fs;
use std::fs::File;
use std::num::NonZeroU32;

use aes::Aes256;
use block_modes::{BlockMode,Cbc};
use block_modes::block_padding::Pkcs7;

use ring::error::Unspecified;
use ring::rand::SecureRandom;
use ring::{digest, pbkdf2, rand};

use data_encoding::HEXUPPER;


/**
 * Implements AES-256-CBC w/ PKDF2 for Key Derivation
 * provides CLI to recieve instructions. Code has not
 * been audited and may cointain bugs. Use at your own 
 * risk.
 */

 // TODO: swap the panics for re-directions,
 // fix up noted comments, should write unit tests. 


fn main() {

    let mut continue_with_program = true;
    
    println!("Welcome to Free Enc. \n");
    
    while continue_with_program { 
       
        begin_encrypt_or_decrypt();
        
        println!("\nThanks for using Free Enc!"); 
        println!("\nIf you would like to go back to encrypt or decrypt selection press enter, otherwise press any btn then enter to quit.");

        let user_input =  get_user_input();
       
        if user_input != "" {
            continue_with_program = false;
        }
    }
}

fn begin_encrypt_or_decrypt(){

    println!("\nWould you like to encrypt or decrypt?");
    let encrypt_or_decrypt =  get_user_input();     
    
    if encrypt_or_decrypt == "decrypt"{
        
        println!("\nWhat is the relative location of the file for decryption? ");
        let mut location_of_file = get_user_input();

        println!("\nLocation of File to be decrypted: {}", location_of_file);

        println!("\nPlease enter a password for decryption: ");
        let mut password =  get_user_input();

        println!("\nPlease enter your password one more time to confirm: ");
        let mut password_conformation =  get_user_input();

        if !verfiy_passwords_match(&mut password, &mut password_conformation)
        {
            panic!("Passwords for decryption do not match! Exiting program");
        }

        decrypt_document(&mut password, &mut location_of_file);
        println!("\nDecryption Successful!");
    }

    else if encrypt_or_decrypt == "encrypt" {

        println!("\nWhat is the relative location of the file for encryption?: ");
        let mut location_of_file = get_user_input();

        println!("\nLocation of File to be encrpyted: {}", location_of_file);

        println!("\nPlease enter a password for encrpytion: ");
        let mut password =  get_user_input();

        println!("\nPlease enter your password one more time to confirm: ");
        let mut password_conformation =  get_user_input();

        if !verfiy_passwords_match(&mut password, &mut password_conformation)
        {
            panic!("Passwords for encrpytion do not match! Exiting program");
        }

        encrypt_document(&mut password, &mut location_of_file);
        println!("\nEncryption Successful!");
    }

    else {
        panic!("\nBad Command! Exiting Program");
    }

}

fn encrypt_document(pwd: &mut String, location_of_file: &mut String){

    const SALT_LEN: usize = digest::SHA256_OUTPUT_LEN;
    const IV_LEN: usize = 16;

    let mut salt = [0u8; SALT_LEN];
    let mut iv = [0u8; IV_LEN];
    let n_iter = NonZeroU32::new(100_000).unwrap();
    let rng = rand::SystemRandom::new();
 
    rng.fill(&mut iv).expect("Error Filling IV");
    rng.fill(&mut salt).expect("Error Filling Salt");

    let mut pbkdf2_hash = [0u8; SALT_LEN];

    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256, 
        n_iter, 
        &salt, 
        pwd.as_bytes(), 
        &mut pbkdf2_hash,
    );

    // print_key_info(&salt, &iv, &pbkdf2_hash);
    
    let data = fs::read(&location_of_file).expect("Error Reading in File to Encrypt"); 
    
    type Aes256Cbc = Cbc<Aes256, Pkcs7>;
    let cipher = Aes256Cbc::new_var(&pbkdf2_hash, &iv).unwrap();
    
    let mut cipertext = cipher.encrypt_vec(&data); 
   
    let mut data_to_write : Vec<u8> = Vec::new();
    let spacer: u8 = b'=';

   
    for i in 0..IV_LEN {
        data_to_write.push(iv[i]);
    }

    data_to_write.push(spacer); 
    data_to_write.push(spacer);
    data_to_write.push(spacer);
    
    for i in 0..SALT_LEN {
        data_to_write.push(salt[i]);
    }

    data_to_write.push(spacer); 
    data_to_write.push(spacer);
    data_to_write.push(spacer);
    
    // append cipher 
    data_to_write.append(&mut cipertext);
    
    let mut buffer_to_write = File::create(location_of_file).expect("Error Creating New File");// create file at location of file to be encrypted.

    buffer_to_write.write_all(&data_to_write).expect("Error Writing Ciper Text"); 
}

fn decrypt_document(pwd: &mut String, location_of_file: &mut String){
    
    
    const SALT_LEN: usize = digest::SHA256_OUTPUT_LEN;
    const IV_LEN: usize = 16;

    let mut salt = [0u8; SALT_LEN];
    let mut iv = [0u8; IV_LEN];
    let n_iter = NonZeroU32::new(100_000).unwrap();

    let mut pbkdf2_hash = [0u8; SALT_LEN];


    let mut data = fs::read(&location_of_file).expect("Error Reading in File to Decrypt");

    //this can probably be initialized better..
    let mut space = [0u8; 3];
    space[0] = b'=';    
    space[1] = b'=';  
    space[2] = b'=';  

    let mut spacer_finder = data.windows(space.len()).position(|x| x == space);
    let mut inital_space: usize;

    match spacer_finder {
        Some(x) => inital_space = x,
        None => panic!("Error no spacers found when decrypted doc"),
    }
  
    for i in 0..inital_space{
        iv[i] = data[i];
    }

    let len_of_first_slice = inital_space + 3; //or spacer_finder.iter().len();

    data.drain(0..len_of_first_slice);

    spacer_finder = data.windows(space.len()).position(|x| x == space);

    match spacer_finder {
        Some(x) => inital_space = x,
        None => panic!("Error no spacers found when decrypted doc"),
    }

        for i in 0..inital_space{
            salt[i] = data[i];
    }
   
    let len_of_second_slice = inital_space + 3;

    data.drain(0..len_of_second_slice);

    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256, 
        n_iter, 
        &salt, 
        pwd.as_bytes(), 
        &mut pbkdf2_hash,
    );

    // print_key_info(&salt, &iv, &pbkdf2_hash);
    
    type Aes256Cbc = Cbc<Aes256, Pkcs7>;

    let dec_cipher = Aes256Cbc::new_var(&pbkdf2_hash, &iv).unwrap();
    let decrypted_ciphertext = dec_cipher.decrypt_vec(&data).expect("Error decrpyting doc");

    let mut buffer_to_write = File::create(location_of_file).expect("Error Creating New File");

    buffer_to_write.write_all(&decrypted_ciphertext).expect("Blah"); 
}


fn get_user_input() -> String {
   
   let mut return_string =  String::new();

    io::stdin()
    .read_line(&mut return_string)
    .expect("Read Line Failure");

    let new_string = return_string.trim_end();

    new_string.to_string()
}

fn verfiy_passwords_match(pwd_one: &mut String, pwd_two: &mut String) -> bool {

    if pwd_one == pwd_two
    {
        return true;
    }
    false
}

// For debugging
fn print_key_info(salt: &[u8],iv: &[u8],pbkdf2_hash: &[u8]){
     println!("Salt In Dec: {}", HEXUPPER.encode(&salt)); 
     println!("IV In Dec: {}", HEXUPPER.encode(&iv));
     println!("PDKDF2 hash In Dec: {}", HEXUPPER.encode(&pbkdf2_hash));

}