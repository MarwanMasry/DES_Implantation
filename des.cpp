//============================================================================
// Name        : des_24.cpp
// Author      : Group 24
// Version     : 1.0.0
// Copyright   : Your copyright notice
// Description : DES Encryption and Decryption
//============================================================================

/******************************************************************************
 *******************************************************************************
				 _____            _           _
				|_   _|          | |         | |
				  | |  _ __   ___| |_   _  __| | ___  ___
				  | | | '_ \ / __| | | | |/ _` |/ _ \/ __|
				 _| |_| | | | (__| | |_| | (_| |  __/\__ \
				|_____|_| |_|\___|_|\__,_|\__,_|\___||___/
 ********************************************************************************
 *******************************************************************************/
#include <iostream>
#include <string>
#include <fstream>
#include <iomanip>
#include <filesystem>
using namespace std;

/******************************************************************************
 *******************************************************************************
 _______                 _____        __ _       _ _   _
|__   __|               |  __ \      / _(_)     (_) | (_)
   | |_   _ _ __   ___  | |  | | ___| |_ _ _ __  _| |_ _  ___  _ __  ___
   | | | | | '_ \ / _ \ | |  | |/ _ \  _| | '_ \| | __| |/ _ \| '_ \/ __|
   | | |_| | |_) |  __/ | |__| |  __/ | | | | | | | |_| | (_) | | | \__ \
   |_|\__, | .__/ \___| |_____/ \___|_| |_|_| |_|_|\__|_|\___/|_| |_|___/
       __/ | |
      |___/|_|
 *******************************************************************************
 *******************************************************************************/
typedef unsigned long long DES_64;
/******************************************************************************
 *******************************************************************************
  _____                _              _
 / ____|              | |            | |       /\
| |     ___  _ __  ___| |_ __ _ _ __ | |_     /  \   _ __ _ __ __ _ _   _ ___
| |    / _ \| '_ \/ __| __/ _` | '_ \| __|   / /\ \ | '__| '__/ _` | | | / __|
| |___| (_) | | | \__ \ || (_| | | | | |_   / ____ \| |  | | | (_| | |_| \__ \
 \_____\___/|_| |_|___/\__\__,_|_| |_|\__| /_/    \_\_|  |_|  \__,_|\__, |___/
                                                                     __/ |
                                                                    |___/
 *******************************************************************************
 *******************************************************************************/
// Initial Permutation Table
long initial_permutation[64]=  {58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6,
		64, 56, 48, 40, 32, 24, 16, 8,
		57, 49, 41, 33, 25, 17, 9, 1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7};
/********************************************************************************/
// The inverse permutation table
long inverse_permutation[64]=   {40, 8, 48, 16, 56, 24, 64, 32,
		39, 7, 47, 15, 55, 23, 63, 31,
		38, 6, 46, 14, 54, 22, 62, 30,
		37, 5, 45, 13, 53, 21, 61, 29,
		36, 4, 44, 12, 52, 20, 60, 28,
		35, 3, 43, 11, 51, 19, 59, 27,
		34, 2, 42, 10, 50, 18, 58, 26,
		33, 1, 41, 9, 49, 17, 57, 25};
/********************************************************************************/
// Permutation Choice 1 For the Key
long permuted_choice_1[56] = {57, 49, 41, 33, 25, 17, 9,
		1, 58, 50, 42, 34, 26, 18,
		10, 2, 59, 51, 43, 35, 27,
		19, 11, 3, 60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15,
		7, 62, 54, 46, 38, 30, 22,
		14, 6, 61, 53, 45, 37, 29,
		21, 13, 5, 28, 20, 12, 4};
/*********************************************************************************/
// Permutation Choice 2 For the Key
long permuted_choice_2[48] = {14, 17, 11, 24, 1, 5,
		3, 28, 15, 6, 21, 10,
		23, 19, 12, 4, 26, 8,
		16, 7, 27, 20, 13, 2,
		41, 52, 31, 37, 47, 55,
		30, 40, 51, 45, 33, 48,
		44, 49, 39, 56, 34, 53,
		46, 42, 50, 36, 29, 32};
/**********************************************************************************/
//Expansion Permutation (E Table) for 32-bits of plain-Text
long expansion_permutation[48] = {  32, 1, 2, 3, 4, 5, 4, 5,
		6, 7, 8, 9, 8, 9, 10, 11,
		12, 13, 12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21, 20, 21,
		22, 23, 24, 25, 24, 25, 26, 27,
		28, 29, 28, 29, 30, 31, 32, 1};
/**********************************************************************************/
//Substitution Box (S-Box)
long sBoxes[8][4][16] = {
		/*S-Box 1*/
		{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
				0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
				4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
				15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
				/*S-Box 2*/
				{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
						3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
						0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
						13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
						/*S-Box 3*/
						{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
								13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
								13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
								1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
								/*S-Box 4*/
								{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
										13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
										10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
										3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
										/*S-Box 5*/
										{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
												14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
												4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
												11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
												/*S-Box 6*/
												{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
														10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
														9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
														4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
														/*S-Box 7*/
														{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
																13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
																1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
																6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
																/*S-Box 8*/
																{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
																		1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
																		7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
																		2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}};
/**********************************************************************************/
//The Permutation after S-Box Stage
long end_permutation[32] = { 16, 7, 20, 21, 29, 12, 28, 17,
		1, 15, 23, 26, 5, 18, 31, 10,
		2, 8, 24, 14, 32, 27, 3, 9,
		19, 13, 30, 6, 22, 11, 4, 25};
/**********************************************************************************/
//Shift Left Table
long shift_table[16] = {1, 1, 2, 2,
		2, 2, 2, 2,
		1, 2, 2, 2,
		2, 2, 2, 1};

/*********************************************************************************************
 **********************************************************************************************
 ______                _   _               _____           _        _
|  ____|              | | (_)             |  __ \         | |      | |
| |__ _   _ _ __   ___| |_ _  ___  _ __   | |__) | __ ___ | |_ ___ | |_ _   _ _ __   ___  ___
|  __| | | | '_ \ / __| __| |/ _ \| '_ \  |  ___/ '__/ _ \| __/ _ \| __| | | | '_ \ / _ \/ __|
| |  | |_| | | | | (__| |_| | (_) | | | | | |   | | | (_) | || (_) | |_| |_| | |_) |  __/\__ \
|_|   \__,_|_| |_|\___|\__|_|\___/|_| |_| |_|   |_|  \___/ \__\___/ \__|\__, | .__/ \___||___/
                                                                        __/ | |
                                                                       |___/|_|
 ************************************************************************************************
 ************************************************************************************************/
void shift_left(int shift_value, unsigned long* right_key, unsigned long* left_key);

DES_64 XOR_fn(DES_64 a, DES_64 b, long output_size);

DES_64 permutation_fn(DES_64 input, long *permutation_type, long output_size, long input_size);

unsigned long des_substitution_box(DES_64);

void mini_split(unsigned char len, unsigned long* temp, unsigned long long* num);

void split(unsigned char len, unsigned long long num, unsigned long* R, unsigned long* L);

unsigned long fiestel_function(unsigned long plaintext_32 , DES_64 key);

DES_64 encrypt_decrypt(DES_64 input,DES_64 key, string operation_type);

DES_64 _8ByteString_to_Ulonglong(string str);

string _UlongLong_to_8ByteString(DES_64 data);
/************************************************************************************************/

/*********************************************************************************************
 **********************************************************************************************
				 __  __       _          __                  _   _
				|  \/  |     (_)        / _|                | | (_)
				| \  / | __ _ _ _ __   | |_ _   _ _ __   ___| |_ _  ___  _ __
				| |\/| |/ _` | | '_ \  |  _| | | | '_ \ / __| __| |/ _ \| '_ \
				| |  | | (_| | | | | | | | | |_| | | | | (__| |_| | (_) | | | |
				|_|  |_|\__,_|_|_| |_| |_|  \__,_|_| |_|\___|\__|_|\___/|_| |_|

 ************************************************************************************************
 ************************************************************************************************/
int main(int argc, char** argv)
{
	/* needed Variables */
	string input_file_str = "";
	string key_str = "";
	string readLine = "";
	unsigned long numberOfPaddingChar = 0;
	DES_64 input_block;
	DES_64 output_block;
	size_t i = 0;
	char tempChar;

	/* Read input/key files paths and take the operation type[encrypt/decrypt] */
	string op_type = argv[1];
	string input_file_path = argv[2];
	string key_file_path = argv[3];
	string outputfileName = argv[4];

	/* needed streams */
	ifstream key_file_stream;
	ofstream output1_encrypt_file_stream;
	ofstream output2_decrypt_file_stream;

	/* make operation type string all to lower case */
	for(size_t i =0 ; i<op_type.length() ; i++)
	{
		if((op_type.at(i) >= 'A') && (op_type.at(i) <= 'Z'))
		{
			op_type.at(i) = char( ((unsigned char)op_type.at(i)) + 32 );
		}
	}

	/* Open the file that contain the key */
	key_file_stream.open(key_file_path);

	/*	If File didn't open Display Error MSG and exits main function */
	if(!(key_file_stream.is_open() ))
	{
		cerr<<"Error In Opening key File!!! \n";
		exit(1);
	}

	/* read key value in string and store in a long long variable */
	getline(key_file_stream, key_str);
	DES_64 key = stoull(key_str, nullptr, 16);

	/* Open the input file that contain either a plain-text or cypher-text */
	ifstream input_file_stream(input_file_path, ifstream::in|ifstream::binary);

	/*	If File didn't open Display Error MSG and exits main function */
	if(!(input_file_stream.is_open() ))
	{
		cerr<<"Error In Opening input File[either a plain-text or cypher-text] !!! \n";
		exit(1);
	}

	/* Get the size of file to be read in Bytes */
	size_t size_of_file = filesystem::file_size(input_file_path);

	while(i <= size_of_file)
	{
		input_file_stream.get(tempChar);

#ifdef _WIN64
		if((tempChar == '\n') && (!input_file_str.empty()) && (input_file_str.back() == char(13)))
		{
			input_file_str.pop_back();
		}
#endif
		input_file_str.push_back(char((unsigned char)tempChar));
		i++;
	}
	/* remove the added byte by the input stream */
	input_file_str.pop_back();

	/* Create files for output depends on the operation [encrypt/decrypt]*/
	if( "decrypt" == op_type)
	{
		cout<<"\n____________START DECRYPTING____________\n";

		output2_decrypt_file_stream.open(outputfileName);

	}else if ("encrypt" == op_type)
	{
		cout<<"\n____________START ENCRYPTING____________\n";

		output1_encrypt_file_stream.open(outputfileName);
	}

	/* If the input is not multiple of 64 bit then add padding */
	if( ( (input_file_str.length() % 8 )!= 0 )&& ("encrypt" == op_type))
	{
		numberOfPaddingChar = 8 - (input_file_str.length() % 8 );

		for(unsigned long i =0 ; i<numberOfPaddingChar ; i++)
		{
			input_file_str += char(0);
		}
	}

	/*
	 *  Divide the plain text into multiple of 8 characters then each loop
	 *  convert this 8 character to bits then encrypt/decrypt them then
	 *  add them to the output file.
	 *
	 */
	for(unsigned long i = 0; i < input_file_str.length(); i+=8)
	{
		input_block = _8ByteString_to_Ulonglong( string(input_file_str.begin()+i,input_file_str.begin()+i+8) );
		output_block = encrypt_decrypt(input_block, key, op_type);

		if ("encrypt" == op_type)
		{
			output1_encrypt_file_stream << _UlongLong_to_8ByteString(output_block);

		}else if( "decrypt" == op_type)
		{
			/* we need to remove the padding bytes with decryption so by converting the string
			 * class object to c style string and outputting a c style string won't print the
			 * padding bits [Zero Bits][which are null characters] to the file so we removed the
			 * padding bits by this conversion.
			 */
			output2_decrypt_file_stream << (_UlongLong_to_8ByteString(output_block)).c_str();
		}
	}

	if ("encrypt" == op_type)
	{
		cout<<"\n____________FINISHED ENCRYPTING____________\n";
		cout<<"You Can Open "<< outputfileName <<" Now.\n\n";
	}else if( "decrypt" == op_type)
	{
		cout<<"\n____________FINISHED DECRYPTING____________\n";
		cout<<"You Can Open "<< outputfileName <<" Now.\n\n";
	}


	input_file_stream.close();
	key_file_stream.close();
	output1_encrypt_file_stream.close();
	output2_decrypt_file_stream.close();

	return 0;
}


/**********************************************
 ______                _   _
|  ____|              | | (_)
| |__ _   _ _ __   ___| |_ _  ___  _ __  ___
|  __| | | | '_ \ / __| __| |/ _ \| '_ \/ __|
| |  | |_| | | | | (__| |_| | (_) | | | \__ \
|_|   \__,_|_| |_|\___|\__|_|\___/|_| |_|___/
 ***********************************************/

// right&left Key should be 28 bit
void shift_left(int shift_value, unsigned long* right_key, unsigned long* left_key)
{
	unsigned long temp=0;
	temp = *right_key;
	*right_key = (temp << shift_value) | (temp >> (28 - shift_value));
	*right_key = (*right_key & 0x0FFFFFFF);
	temp = *left_key;
	*left_key = (temp << shift_value) | (temp >> (28 - shift_value));
	*left_key = *left_key & 0x0FFFFFFF;
}
/*******************************************************************************************/
DES_64 permutation_fn(DES_64 input, long *permutation_type, long output_size, long input_size)
{
	DES_64 output=0;
	for (int i = 0; i < output_size; i++)
	{
		output |= (input >> (input_size - permutation_type[output_size - 1 - i]) & 1) << i;  //check this line
	}
	return output;
}
/*******************************************************************************************/
DES_64 XOR_fn (DES_64 a, DES_64 b, long output_size) {
	DES_64 output = (a ^ b);
	if (output_size==48){
		output = output & 0x0000FFFFFFFFFFFF;
	}else{
		output = output & 0x00000000FFFFFFFF;
	}
	return output;
}
/*******************************************************************************************/

unsigned long long encrypt_decrypt(DES_64 input, DES_64 key,string operation_type)
{
	// STEP1 - Permutation Choice 1 for the key
	DES_64 permutated_key_1 = permutation_fn(key, permuted_choice_1 , 56, 64);

	// STEP2 - Split the 56 bits key into 2 keys 28 bit each
	unsigned long right_key=0,left_key=0;
	split(56, permutated_key_1 , &right_key, &left_key);

	// STEP3 - Generate the 16 keys for the 16 round
	DES_64 round_keys[16];
	DES_64 merged_key;
	for(int i = 0 ; i < 16 ; i++){
		shift_left(shift_table[i], &right_key, &left_key);
		merged_key = ((DES_64)(left_key) << 28) | (DES_64)(right_key);
		merged_key = permutation_fn(merged_key, permuted_choice_2, 48, 56);
		round_keys[i]= merged_key;
	} // 16 keys generated.

	if (operation_type == "encrypt"){

		// ENCRYPTION PHASE

		//STEP4 - Initail Permutation for the plaintext input
		DES_64 plaintext_IP = permutation_fn(input, initial_permutation , 64, 64);

		//STEP5 - Split the 64 plaintext_ip into 2 plaintexts 32 bits each
		unsigned long right_plaintext=0,left_plaintext=0;
		split(64, plaintext_IP , &right_plaintext, &left_plaintext);

		unsigned long temp1, temp2;
		//STEP6- Start the 16 rounds
		for (int j = 0; j < 16; j++){

			//STEP 6.1 L(i) = R(i-1)
			temp1 = right_plaintext;
			temp2 = left_plaintext;
			left_plaintext = temp1;
			right_plaintext = (unsigned long) XOR_fn (temp2 , fiestel_function(temp1,round_keys[j]) , 32);
		}

		//STEP7 - Swap the plaintexts
		temp1 = right_plaintext;
		right_plaintext = left_plaintext;
		left_plaintext = temp1;


		//STEP8 - Merge the ciphers
		DES_64 cipher = ((DES_64)(left_plaintext) << 32) | (DES_64)(right_plaintext);

		//STEP9 - Inverse Permutation to the 64 bit ciphers
		cipher = permutation_fn(cipher, inverse_permutation, 64 , 64 );


		return cipher;
	}
	else if (operation_type == "decrypt"){

		// DECRYPTION PHASE

		//Step4 - Initial Permutation to cipher text input
		DES_64 ciphertext_IP = permutation_fn(input, initial_permutation , 64, 64);

		//Step5 - Split ciphertext
		unsigned long right_ciphertext=0,left_ciphertext=0;
		split(64, ciphertext_IP , &right_ciphertext, &left_ciphertext);


		unsigned long temp_1=0 , temp_2 =0;

		//Step6 - Swap the right and left
		temp_1 = right_ciphertext;
		temp_2 = left_ciphertext;
		right_ciphertext = temp_2;
		left_ciphertext = temp_1;

		//Step7 - Start the 16 round inversly
		for (int k=15 ; k >= 0 ; k--){

			temp_1 = right_ciphertext;
			temp_2 = left_ciphertext;
			right_ciphertext = temp_2;
			left_ciphertext = (unsigned long) XOR_fn(temp_1 ,fiestel_function(temp_2,round_keys[k]),32);
		}



		//Step8 - Merge the right and left
		DES_64 plain_text = ((DES_64)(left_ciphertext) << 32) | (DES_64)(right_ciphertext);

		//Step9 - Inverse Permutation to the cipher text
		plain_text = permutation_fn(plain_text, inverse_permutation , 64, 64);

		return plain_text;
	}
	else{

		return 0;
	}

}

/*******************************************************************************************/
unsigned long des_substitution_box(DES_64 sBox_Input)
{
	unsigned long result=0;
	unsigned int data = 0;
	unsigned int row =0,column=0;
	for (int Box_no = 0; Box_no < 8; Box_no++)
	{
		data = sBox_Input >> (7 - Box_no) * 6 & 0x3F;
		column = (data>> 1) & 15;
		row = (data & 1) | ((data & 0x20) >> 4);
		result |= sBoxes[Box_no][row][column] << ((7 - Box_no) * 4);



	}
	return result;
}
/*******************************************************************************************/
void mini_split(unsigned char len, unsigned long* temp, unsigned long long* num)
{
	*temp = 0;
	unsigned char max = (len / 2);
	for (unsigned char i = 0; i < max; i++)
	{
		(*temp) |= (((*num) >> i) & 1) << i;
	}

}


void split (unsigned char len, unsigned long long num, unsigned long* R, unsigned long* L)
{
	unsigned long temp;

	/* Right Part */
	mini_split(len, &temp, &num);
	*R = temp;

	/* Left Part */
	num >>= (len / 2); // Get Left Part & discard Right Part
	mini_split(len, &temp, &num);
	*L = temp;
}
/******************************************************************************************/
unsigned long fiestel_function(unsigned long plaintext_32 , DES_64 key){

	DES_64 plaintext_48=0;
	unsigned long result=0;
	plaintext_48 = permutation_fn(plaintext_32 , expansion_permutation , 48, 32);
	plaintext_48 = XOR_fn (plaintext_48,key,48);

	result = des_substitution_box(plaintext_48);

	result = permutation_fn(result, end_permutation, 32, 32);

	return result;
}
/******************************************************************************************/
DES_64 _8ByteString_to_Ulonglong(string str)
{
	DES_64 output = 0;

	for(int i =0; i < 8 ; i++)
	{
		output <<= 8;
		output |= (unsigned char)str[i];
	}

	return output;
}
/******************************************************************************************/
string _UlongLong_to_8ByteString(DES_64 data)
{
	string output = "";
	DES_64 MUX = 0xFF00000000000000;
	DES_64 temp ;

	for(int i =0 ; i < 8 ; i++)
	{
		temp = data & MUX;
		output += (char)(temp >> 56);
		data <<= 8;
	}

	return output;
}
/******************************************************************************************/



















