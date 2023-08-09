#include "kunlun_ot.h"
#include <cryptoTools/Crypto/PRNG.h>
#include "Kunlun/crypto/prg.hpp"
#include "Kunlun/crypto/setup.hpp"
#include <future>
namespace apsu{
	namespace KunlunOT{
        void IKNP_KL_RandomSender(NetIO& chl,std::vector<std::array<osuCrypto::block, 2>>& sendMsg,size_t thread_num){
            
            
            size_t total_len = sendMsg.size();
            
            CRYPTO_Initialize(); 
            IKNPOTE::PP pp;
            pp = IKNPOTE::Setup(128);
            


            size_t exten_size = ((total_len >> 7) + 1) << 7;

            PRG::Seed seed = PRG::SetSeed(fixed_seed, 0); // initialize PRG
            std::vector<block> vec_0(exten_size);
            std::vector<block> vec_1(exten_size);

            IKNPOTE::RandomSend(chl,pp,vec_0,vec_1,exten_size);
            // Block::PrintBlocks(vec_0);
            // Block::PrintBlocks(vec_1);
            for(size_t idx = 0; idx < total_len; idx++){
                sendMsg[idx][0] = oc::toBlock((uint8_t*)&vec_0[idx]);
                sendMsg[idx][1] = oc::toBlock((uint8_t*)&vec_1[idx]);
            }
            

            // CRYPTO_Finalize();

        }

        void IKNP_KL_RandomReceiver(NetIO& chl,osuCrypto::BitVector& choices,
            std::vector<osuCrypto::block>& recvMsg,
            size_t thread_num){
            CRYPTO_Initialize(); 

            IKNPOTE::PP pp;

            pp = IKNPOTE::Setup(128);

            size_t total_len = recvMsg.size();
       
            size_t exten_size = ((total_len >> 7) + 1) << 7;

            std::vector<block> vec_k(exten_size);
            PRG::Seed seed = PRG::SetSeed(fixed_seed, 0); // initialize PRG
            std::vector<uint8_t> bitChoice(exten_size);
            for(size_t idx = 0 ; idx < total_len; idx ++){
                bitChoice[idx] = choices[idx];
            }
            
            IKNPOTE::RandomReceive(chl,pp,vec_k,bitChoice,exten_size);
            for(size_t idx = 0; idx < total_len; idx++){
                recvMsg[idx] = oc::toBlock((uint8_t*)&vec_k[idx]);
            }
                // for(auto x : bitChoice)
                //     printf("%02x\n",x);
                // Block::PrintBlocks(vec_k);
            


        }

        void IKNP_KL_ChosenSender(NetIO& chl,std::vector<std::array<oc::block, 2>> Messages){
            CRYPTO_Initialize(); 

            auto pp = IKNPOTE::Setup(128);


            size_t totalMessages = Messages.size();
            // The number of OT should be legal
            size_t paddingOT = ((totalMessages >> 7) + 1) << 7;
            // std::cout << item_len << std::endl;
            std::vector<block> vec_M(paddingOT,Block::zero_block);

            for(size_t idx =0 ;idx < totalMessages; idx++ ){
                auto cont = Messages.at(idx)[0];
                vec_M[idx] = cont;
            }
            IKNPOTE::OnesidedSend(chl,pp,vec_M,paddingOT);
            // Block::PrintBlocks(oneside_send);


            CRYPTO_Finalize();

        }

        void IKNP_KL_ChosenReceiver(NetIO& chl,std::vector<block>& DiffSet,size_t BlockNum,std::vector<size_t> choicesVec){
            CRYPTO_Initialize(); 

            auto pp = IKNPOTE::Setup(128);

            std::vector<uint8_t> choices(BlockNum,1);
            auto PaddintLen = ((BlockNum >> 7) + 1) << 7;

            size_t answeight = 0;
            for(auto i : choicesVec){
                choices[i] = 0;
                answeight++;
            }

            DiffSet = IKNPOTE::OnesidedReceive(chl,pp,choices,PaddintLen);

            CRYPTO_Finalize();

#ifdef OUTPUTTOFILE

            std::ofstream fout;
            fout.open("union.csv",std::ofstream::out);
            for(auto i:DiffSet){
                
                if(Block::Compare(i,Block::zero_block)) continue;
                fout<<i<<std::endl;
                // outcnt++;
            }
            fout.close();
#endif


        }

	}
}