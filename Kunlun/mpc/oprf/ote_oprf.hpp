
/** @file
 *****************************************************************************
 This is an implementation of multi-point OPRF.

 References:
 \[CM20]: 
 "Private Set Intersection in the Internet Setting From Lightweight",
 Melissa Chase, Peihan Miao,
 CRYPTO 2020,
 <https://eprint.iacr.org/2020/729>

 Modified from the following project:
 <https://github.com/peihanmiao/OPRF-PSI>

 With modifications:
 1. Support multi-thread programming with OpenMP (improve computation efficiency);
 2. Substitute the unordered_map with bloom filter to do membership test (reduce communication cost).

 *****************************************************************************
 * @author     developed by Xiangling Zhang (slightly modified by Yu Chen)
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef KUNLUN_OTE_OPRF_HPP_
#define KUNLUN_OTE_OPRF_HPP_

#include "../ot/naor_pinkas_ot.hpp"
#include "../../crypto/prg.hpp"

namespace OTEOPRF{

using Serialization::operator<<; 
using Serialization::operator>>; 

struct PP
{
    size_t LEN; // the length of the client's input vector
    size_t matrix_height; // m (matrix_height = LEN)
    size_t log_matrix_height; // logm
    size_t matrix_width; // w
    size_t OUTPUT_LEN; // the output length \ell2 in bytes of hash function H2: {0,1}^w -> {0,1}^{\ell2}
    size_t BATCH_SIZE; // the batch size dealing with the LEN loops, LEN % BATCH_SIZE = 0
    
    // a common PRG seed, used to generate a number of AES keys, PRG(common_seed) -> k0 || k1 || ... || kt
    PRG::Seed common_seed; 

    NPOT::PP npot_part;
};
    
inline PP Setup(PP& pp,size_t LOG_LEN, size_t statistical_security_parameter = 40)
{
    pp.LEN = 1 << LOG_LEN; // LEN = 2^{LOG_LEN}
    pp.matrix_height = pp.LEN;
    pp.log_matrix_height = LOG_LEN;
    // the default statistical security parameter is 40
    pp.OUTPUT_LEN = ((statistical_security_parameter + 2*LOG_LEN) + 7) >> 3; 

    //customize BATCH_SIZE w.r.t. LOG_LEN
    if(LOG_LEN < 10) pp.BATCH_SIZE = 1 << (LOG_LEN/2); 
    else pp.BATCH_SIZE = 128;
    
    pp.npot_part = NPOT::Setup();
    // use the agreed PRF key to initiate a common PRG seed
    pp.common_seed = PRG::SetSeed(fixed_seed, 0); 

    // parameters of matrix width for input set size in page 16 table 1
    if (LOG_LEN <= 10) pp.matrix_width = 591;
    else if (LOG_LEN <= 12) pp.matrix_width = 597;
    else if (LOG_LEN <= 14) pp.matrix_width = 603;
    else if (LOG_LEN <= 16) pp.matrix_width = 609;
    else if (LOG_LEN <= 18) pp.matrix_width = 615;
    else if (LOG_LEN <= 20) pp.matrix_width = 621;
    else pp.matrix_width = 633;
        
	return pp; 
}

// serialize pp to stream
inline std::ofstream &operator<<(std::ofstream &fout, const PP &pp)
{
    fout << pp.LEN; 
    fout << pp.matrix_height; 
    fout << pp.log_matrix_height; 
    fout << pp.matrix_width; 
    fout << pp.OUTPUT_LEN; 
    fout << pp.BATCH_SIZE; 

    fout << pp.common_seed; 

    fout << pp.npot_part;

	return fout; 
}

// deserialize pp from stream
inline std::ifstream &operator>>(std::ifstream &fin, PP &pp)
{
    fin >> pp.LEN; 
    fin >> pp.matrix_height; 
    fin >> pp.log_matrix_height; 
    fin >> pp.matrix_width; 
    fin >> pp.OUTPUT_LEN; 
    fin >> pp.BATCH_SIZE; 

    fin >> pp.common_seed;

    fin >> pp.npot_part;

	return fin; 
}


// save pp to file
inline void SavePP(PP &pp, std::string pp_filename)
{
    std::ofstream fout; 
    fout.open(pp_filename, std::ios::binary); 
    if(!fout){
        std::cerr << pp_filename << " open error" << std::endl;
        exit(1); 
    }

    fout << pp; 

    fout.close(); 
}

// load pp from file
inline void FetchPP(PP &pp, std::string pp_filename)
{
    std::ifstream fin; 
    fin.open(pp_filename, std::ios::binary); 
    if(!fin){
        std::cerr << pp_filename << " open error" << std::endl;
        exit(1); 
    }

    fin >> pp;

    fin.close(); 
}

// print pp
inline void PrintPP(const PP &pp)
{
    PrintSplitLine('-'); 
    std::cout << "PP of OTE-based OPRF >>>" << std::endl;
    std::cout << "input vector length = " << pp.LEN << std::endl; 
    std::cout << "matrix height = " << pp.matrix_height << std::endl; 
    std::cout << "log matrix height = " << pp.log_matrix_height << std::endl; 
    std::cout << "matrix width = " << pp.matrix_width << std::endl; 
    std::cout << "OUTPUT_LEN = " << pp.OUTPUT_LEN << std::endl; 
    std::cout << "BATCH_SIZE = " << pp.BATCH_SIZE << std::endl; 

    PRG::PrintSeed(pp.common_seed); 

    NPOT::PrintPP(pp.npot_part);

    PrintSplitLine('-'); 
}

/* 
instantiate a small range PRF F: {0,1}^128 * {0,1}^* -> {0,1}^128 using AES
** H1: {0,1}^* -> {0,1}^256
** H1(x) = (z_0||z_1)
** F_k(x) = ECBEnc(k, z_0) xor z_1
*/
inline std::vector<block> Encode(std::vector<block> &vec_X, block& key)
{
    size_t LEN = vec_X.size(); 
    std::vector<std::vector<uint8_t>> vec_H1_X(LEN, std::vector<uint8_t>(HASH_OUTPUT_LEN));
    // std::vector<block> vec_Encode_X(LEN);

    std::vector<block> vec_Z0(LEN);
    std::vector<block> vec_Z1(LEN); 

    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for (auto i = 0; i < LEN; i++) {
        BasicHash((uint8_t*)(vec_X.data() + i), sizeof(block), vec_H1_X[i].data());
        // H1(x) = (x_left||x_right)
        memcpy(&vec_Z0[i], vec_H1_X[i].data(), sizeof(block)); 
        memcpy(&vec_Z1[i], vec_H1_X[i].data()+sizeof(block), sizeof(block)); 
    }
        
    AES::Key aes_enc_key = AES::GenEncKey(key);
    AES::FastECBEnc(aes_enc_key, vec_Z0.data(), LEN);

    // compute [ECBEnc(k, x_0) xor x_1]
    std::vector<block> vec_Encode_X(LEN); 
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
    for (auto i = 0; i < LEN; i++){
        vec_Encode_X[i] = vec_Z0[i]^vec_Z1[i];
    }

    return vec_Encode_X;
}

// hash each row in matrix_mapping_values to a OUTPUT_LEN string (H2:{0,1}^w -> {0,1}^{\ell2})
inline std::vector<std::vector<uint8_t>> Packing(PP &pp, std::vector<std::vector<uint8_t>> &matrix_mapping_values)
{
    size_t matrix_width_byte = (pp.matrix_width + 7) >> 3;

	std::vector<std::vector<uint8_t>> matrix_input(pp.matrix_height, std::vector<uint8_t>(matrix_width_byte, 0));

    // convert the matrix_mapping_values[matrix_width][matrix_height_byte] to matrix_input[matrix_height][matrix_width_byte]
    #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
	for (auto low_index = 0; low_index < pp.matrix_height; low_index += pp.BATCH_SIZE){
		for (auto i = 0; i < pp.matrix_width; i++){
			for (auto j = low_index; j < low_index + pp.BATCH_SIZE; j++){
				matrix_input[j][i >> 3] |= (uint8_t)((bool)(matrix_mapping_values[i][j >> 3] & (1 << (j & 7)))) << (i & 7);
			}
		}
	}

    uint8_t buffer[HASH_OUTPUT_LEN];
    //uint8_t split_hash_values[pp.OUTPUT_LEN]; 
    std::vector<std::vector<uint8_t>> result;

	for (auto i = 0; i < pp.matrix_height; i++){
        BasicHash(matrix_input[i].data(), matrix_width_byte, buffer);
        result.emplace_back(std::vector<uint8_t>(buffer, buffer + pp.OUTPUT_LEN)); 

        // // convert the H1_OUTPUT_LEN uint8_t array to a OUTPUT_LEN string 
        // memcpy(split_hash_values, vec_hash_values, pp.OUTPUT_LEN);
        // result[i] = std::string((char*)(split_hash_values), pp.OUTPUT_LEN);
	}

    return result;
}

// server obtains a matrix with dimension m*w as the OPRF key
inline std::vector<std::vector<uint8_t>> Server(NetIO &io, PP &pp)
{
    PrintSplitLine('-'); 
    auto start_time = std::chrono::steady_clock::now(); 

    /* step 1: base OT (page 10 figure 4 item1) */
    PRG::Seed seed = PRG::SetSeed(fixed_seed, 0);
	
    std::vector<uint8_t> vec_selection_bit = GenRandomBits(seed, pp.matrix_width); 

    std::vector<block> vec_K = NPOT::Receive(io, pp.npot_part, vec_selection_bit, pp.matrix_width);

    /* step 2: compute matrix_C[matrix_width][matrix_height] (page 10 figure 4 item3) */
    size_t log_height_byte = (pp.log_matrix_height + 7) >> 3; 
    size_t matrix_height_byte = pp.matrix_height >> 3;
    size_t split_bucket_size = sizeof(block) / log_height_byte; // the size of each splited part

    std::vector<std::vector<uint8_t>> matrix_C(pp.matrix_width, std::vector<uint8_t>(pp.matrix_height)); 
    std::vector<PRG::Seed> vec_seed(split_bucket_size);

    for (auto left_index = 0; left_index < pp.matrix_width; left_index += split_bucket_size){
        auto right_index = left_index + split_bucket_size < pp.matrix_width ? left_index + split_bucket_size : pp.matrix_width;
        // bucket_size = split_bucket_size at most time, except for the last splited part
        auto bucket_size = right_index - left_index; 
			
        std::vector<uint8_t> matrix_B(split_bucket_size * matrix_height_byte);
        io.ReceiveBytes(matrix_B.data(), bucket_size * matrix_height_byte);

        #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
		for (auto i = 0; i < bucket_size; i++){
            PRG::ReSeed(vec_seed[i], &vec_K[left_index + i], 0);
            matrix_C[left_index + i] = PRG::GenRandomBytes(vec_seed[i], matrix_height_byte);

			if (vec_selection_bit[left_index + i]){
                #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
				for (auto j = 0; j < matrix_height_byte; j++){
					matrix_C[left_index + i][j] ^= matrix_B[i * matrix_height_byte + j];
				}
			}
		}
    }
        

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "OTE-based OPRF: Server side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;        
    PrintSplitLine('-'); 

    return matrix_C;
}

// server evaluates OPRF values with input set use its own OPRF key
inline std::vector<std::vector<uint8_t>> Evaluate(PP &pp, std::vector<std::vector<uint8_t>> &oprf_key, 
                                  std::vector<block> &vec_X, size_t ITEM_NUM)
{
    /* step 1: compute F_k(x) (F: {0,1}^128 * {0,1}^* -> {0,1}^128) */
    size_t log_height_byte = (pp.log_matrix_height + 7) >> 3;
    size_t split_bucket_size = sizeof(block) / log_height_byte;

    // aes_key_num = t + 1 (t in page 17)
    size_t aes_key_num = (pp.matrix_width / split_bucket_size) + 2;
    std::vector<block> vec_salt = PRG::GenRandomBlocks(pp.common_seed, aes_key_num);

    std::vector<block> vec_Encode_X = Encode(vec_X, vec_salt[0]);

    /* 
    ** step 2: (computes v = F_k(H1(x)) in page 9 figure 3 item3-(b)) 
    ** extend the range of F from {0,1}^128 to {0,1}^{w*logm} by applying AES Enc t times
    ** t = matrix_width / split_bucket_size
    */
    size_t matrix_height_byte = pp.matrix_height >> 3;
    size_t max_location = (1 << pp.log_matrix_height) - 1;

    // the actual size is matrix_location[w][m*logm]
	std::vector<std::vector<uint8_t>> matrix_location(split_bucket_size, std::vector<uint8_t>(ITEM_NUM * log_height_byte + sizeof(uint32_t)));
    std::vector<std::vector<uint8_t>> matrix_mapping_values(pp.matrix_width, std::vector<uint8_t>(matrix_height_byte, 0));
    
    AES::Key aes_enc_key;

    // divides matrix_location into t parts from the matrix_width side
    for (auto left_index = 0; left_index < pp.matrix_width; left_index += split_bucket_size)
    {
        auto right_index = left_index + split_bucket_size < pp.matrix_width ? left_index + split_bucket_size : pp.matrix_width;
        auto bucket_size = right_index - left_index;

        aes_enc_key = AES::GenEncKey(vec_salt[left_index / split_bucket_size + 1]);

        #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
        for (auto low_index = 0; low_index < ITEM_NUM; low_index += pp.BATCH_SIZE){
            // encrypt vec_Fk_X t times, each time encrypt BATCH_SIZE blocks
            AES::FastECBEnc(aes_enc_key, vec_Encode_X.data() + low_index, pp.BATCH_SIZE);
                
			for (auto i = 0; i < bucket_size; i++){ 
                // i is the index of bucket_size (matrix_width)
				for (auto j = low_index; j < low_index + pp.BATCH_SIZE; j++){ 
                    // j is the index of LEN, but in the BATCH_SIZE way 
                    //when j = 0, the left log_height_byte columns of matrix_location is the result of F_k(H(x1)) 
					memcpy(matrix_location[i].data() + j * log_height_byte, (uint8_t*)(vec_Encode_X.data() + j) + i * log_height_byte, log_height_byte); 
                }
			}
		}

        // compute mapping values from the oprfkey (compute (C1[v[1]] || ... || Cw[v[w]]) in page 9 figure 3 item3-(b))
        #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
        for (auto i = 0; i < bucket_size; i++){
			for (auto j = 0; j < ITEM_NUM; j++){
                auto location = (*(uint32_t*)(matrix_location[i].data() + j * log_height_byte)) & max_location;
				matrix_mapping_values[left_index + i][j >> 3] |= (uint8_t)((bool)(oprf_key[left_index + i][location >> 3] & (1 << (location & 7)))) << (j & 7);
			}
		}
    }

    /* step3: compute \Psi = H2(C1[v[1]] || ... || Cw[v[w]]) */
    std::vector<std::vector<uint8_t>> vec_Fk_X = Packing(pp, matrix_mapping_values);

    return vec_Fk_X;
}

// client obtains OPRF values with input set
inline std::vector<std::vector<uint8_t>> Client(NetIO &io, PP &pp, std::vector<block> &vec_Y, size_t ITEM_NUM)
{
    PrintSplitLine('-'); 
    auto start_time = std::chrono::steady_clock::now(); 
    
    /* step 1: base OT (page 10 figure 4 item1) */
    PRG::Seed seed = PRG::SetSeed(fixed_seed, 0); 
    std::vector<block> vec_K0 = PRG::GenRandomBlocks(seed, pp.matrix_width);
    std::vector<block> vec_K1 = PRG::GenRandomBlocks(seed, pp.matrix_width);

	NPOT::Send(io, pp.npot_part, vec_K0, vec_K1, pp.matrix_width);

    /* step2: compute F_k(x) (F: {0,1}^128 * {0,1}^* -> {0,1}^128) */
    size_t log_height_byte = (pp.log_matrix_height + 7) >> 3; 
    size_t split_bucket_size = sizeof(block) / log_height_byte;

    // aes_key_num = t + 1 (t in page 17)
    size_t aes_key_num = (pp.matrix_width / split_bucket_size) + 2;
    std::vector<block> vec_keysalt = PRG::GenRandomBlocks(pp.common_seed, aes_key_num); // AES keys used

    std::vector<block> vec_Encode_Y = Encode(vec_Y, vec_keysalt[0]);

    /* 
    ** (page 10 figure 4 item2)
    ** step 3: compute matrix_location[w][m*logm] = {F_k(H(y_i))} and matrix A, B, D in parallel; 
    ** F: {0,1}^{128} * {0,1}^{128} -> {0,1}^{w*logm} is implemented by applying AES ENC t times, t = ceil(w*logm/128);
    ** F_k(y) = G_k1(G_k0(y0) xor y1) || ... || G_kt(G_k0(y0) xor y1), PRG(k) -> k0 || k1 || ... || kt
    ** matrix A, B, D, location are divided into t parts from the matrix_width side;
    */
    size_t matrix_height_byte = pp.matrix_height >> 3;
    size_t max_location = (1 << pp.log_matrix_height) - 1; 

    // the actual size is matrix_A[w][m]
    std::vector<std::vector<uint8_t>> matrix_A(split_bucket_size, std::vector<uint8_t>(matrix_height_byte));
	std::vector<std::vector<uint8_t>> matrix_D(split_bucket_size, std::vector<uint8_t>(matrix_height_byte));
    // the actual size is matrix_location[w][m*logm]
	std::vector<std::vector<uint8_t>> matrix_location(split_bucket_size, std::vector<uint8_t>(ITEM_NUM * log_height_byte + sizeof(uint32_t)));
    std::vector<std::vector<uint8_t>> matrix_mapping_values(pp.matrix_width, std::vector<uint8_t>(matrix_height_byte, 0));
    AES::Key aes_enc_key;

    // divides into t parts
    for (auto left_index = 0; left_index < pp.matrix_width; left_index += split_bucket_size){
        auto right_index = left_index + split_bucket_size < pp.matrix_width ? left_index + split_bucket_size : pp.matrix_width;
        auto bucket_size = right_index - left_index;

        aes_enc_key = AES::GenEncKey(vec_keysalt[left_index / split_bucket_size + 1]);

        /* step 3-1: compute matrix_location (computes v = F_k(H1(y)) in page 9 figure 3 item3-(c)) */
        #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
        for (auto low_index = 0; low_index < ITEM_NUM; low_index += pp.BATCH_SIZE){
            // encrypt vec_Fk_Y t times, each time encrypt BATCH_SIZE blocks
            AES::FastECBEnc(aes_enc_key, vec_Encode_Y.data() + low_index, pp.BATCH_SIZE);

			for (auto i = 0; i < bucket_size; i++){ 
                // i is the index of bucket_size (matrix_width)
				for (auto j = low_index; j < low_index + pp.BATCH_SIZE; j++){ 
                    // j is the index of LEN, , but in the BATCH_SIZE way 
                    //when j = 0, the left log_height_byte columns of matrix_location is the result of F_k(H(y1)) 
					memcpy(matrix_location[i].data() + j * log_height_byte, (uint8_t*)(vec_Encode_Y.data() + j) + i * log_height_byte, log_height_byte); 
                }
			}
		}
        
        // initialize a all one matrix_D
        #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
        for (auto i = 0; i < split_bucket_size; i++){
			memset(matrix_D[i].data(), 255, matrix_height_byte);
		}

        /* step3-2: compute matrix_D (page 9 figure 3 item1-(c)) */
        #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
		for (auto i = 0; i < bucket_size; i++){
			for (auto j = 0; j < ITEM_NUM; j++){
                // get a location from matrix_location, and set the value of that location in matrix_D to 0
				auto location_in_D = (*(uint32_t*)(matrix_location[i].data() + j * log_height_byte)) & max_location;
				matrix_D[i][location_in_D >> 3] &= ~(1 << (location_in_D & 7));
			}
		}

        /* step 3-3: compute matrix_B and send to sender (page 10 figure 4 item2) */
        std::vector<std::vector<uint8_t>> matrix_B(bucket_size, std::vector<uint8_t>(matrix_height_byte));
        std::vector<uint8_t> send_matrix_B(bucket_size * matrix_height_byte);
        std::vector<PRG::Seed> vec_seed(bucket_size);

        #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
		for (auto i = 0; i < bucket_size; i++){
            PRG::ReSeed(vec_seed[i], &vec_K0[left_index + i], 0);
            matrix_A[i] = PRG::GenRandomBytes(vec_seed[i], matrix_height_byte);

            PRG::ReSeed(vec_seed[i], &vec_K1[left_index + i], 0);
            matrix_B[i] = PRG::GenRandomBytes(vec_seed[i], matrix_height_byte);

            #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
			for (auto j = 0; j < matrix_height_byte; j++){
				matrix_B[i][j] ^= matrix_A[i][j] ^ matrix_D[i][j];
                send_matrix_B[i * matrix_height_byte + j] = matrix_B[i][j];
			}
		}

        io.SendBytes(send_matrix_B.data(), bucket_size * matrix_height_byte);
            
        /* step 3-4: compute mapping values from matrix A (compute (A1[v[1]] || ... || Aw[v[w]]) in page 9 figure 3 item3-(c)) */ 
        #pragma omp parallel for num_threads(NUMBER_OF_THREADS)
        for (auto i = 0; i < bucket_size; i++){
			for (auto j = 0; j < ITEM_NUM; j++){
                auto location_in_A = (*(uint32_t*)(matrix_location[i].data() + j * log_height_byte)) & max_location;
				matrix_mapping_values[left_index + i][j >> 3] |= (uint8_t)((bool)(matrix_A[i][location_in_A >> 3] & (1 << (location_in_A & 7)))) << (j & 7);
			}
		}
    }
    
    PrintSplitLine('-');
    std::cout << "OTE-based OPRF: Receiver ===> matrix_B ===> Sender [" 
              << (double)(pp.matrix_width * matrix_height_byte)/(1 << 20) << " MB]" << std::endl;


    /* step4: compute \Psi = H2(A1[v[1]] || ... || Aw[v[w]]) */
    std::vector<std::vector<uint8_t>> vec_Fk_Y = Packing(pp, matrix_mapping_values);
    
    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "OTE-based OPRF: Client side takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;        
    PrintSplitLine('-'); 

    return vec_Fk_Y;
}

}

#endif