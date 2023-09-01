
#include "utils.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Base/BaseOT.h"

#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"
#include "apsu/log.h"
#include <chrono>
using namespace std;
using milliseconds_ratio = std::ratio<1, 1000>;
using duration_millis = std::chrono::duration<double, milliseconds_ratio>;


namespace apsu{
    namespace sender{
        std::vector<kuku::item_type> oprf_receiver(std::vector<kuku::item_type> in,oc::Socket SenderKKRTSocket){
                APSU_LOG_INFO(__FILE__ << __LINE__);

            vector<oc::block> blocks;
            for(auto item: in){
                blocks.emplace_back(oc::toBlock(item.data()));       
            }
            //  std::vector<std::uint64_t> outputs;
            std::size_t numOTs = blocks.size();
            osuCrypto::PRNG prng(_mm_set_epi32(4253233465, 334565, 0, 235));

            osuCrypto::KkrtNcoOtReceiver recv;

            // get up the parameters and get some information back.
            //  1) false = semi-honest
            //  2) 40  =  statistical security param.
            //  3) numOTs = number of OTs that we will perform
            recv.configure(false, 40, 128);

            // set up networking



            const auto baseots_start_time = std::chrono::system_clock::now();
            // the number of base OT that need to be done
            osuCrypto::u64 baseCount = recv.getBaseOTCount();

            std::vector<osuCrypto::block> baseRecv(baseCount);

            std::vector<std::array<osuCrypto::block, 2>> baseSend(baseCount);

            osuCrypto::MasnyRindal baseOTs;
            coproto::sync_wait(baseOTs.send(baseSend, prng, SenderKKRTSocket));
            recv.setBaseOts(baseSend);
            const auto baseots_end_time = std::chrono::system_clock::now();
            const duration_millis baseOTs_duration = baseots_end_time - baseots_start_time;
            cout<<"baseOT time"<<baseOTs_duration.count()<<endl;

            const auto OPRF_start_time = std::chrono::system_clock::now();
            coproto::sync_wait(recv.init(numOTs, prng, SenderKKRTSocket));

            std::vector<osuCrypto::block>  receiver_encoding(numOTs);

            // for (auto i = 0ull; i < inputs.size(); ++i) {
            //     blocks.at(i) = osuCrypto::toBlock(inputs[i]);
            // }

            for (auto k = 0ull; k < numOTs && k < blocks.size(); ++k) {
                recv.encode(k, &blocks.at(k), reinterpret_cast<uint8_t *>(&receiver_encoding.at(k)),
                            sizeof(osuCrypto::block));
            }

            coproto::sync_wait(recv.sendCorrection(SenderKKRTSocket, numOTs));
            vector<kuku::item_type> outvec;
            for(size_t k = 0; k < numOTs; k++){
                outvec.emplace_back(receiver_encoding[k].get<uint8_t>());
            }
            // for (auto k = 0ull; k < numOTs; ++k) {
            //     // copy only part of the encoding
            //     outputs.push_back(reinterpret_cast<uint64_t *>(&receiver_encoding.at(k))[0] &= __61_bit_mask);
            // }
            const auto OPRF_end_time = std::chrono::system_clock::now();
            const duration_millis OPRF_duration = OPRF_end_time - OPRF_start_time;

            // cout <<"oprf time"<<OPRF_duration.count()<<endl;
            // cout<<"Receiver recv_com_size ps"<<chl.bytesReceived()/1024<<"KB"<<endl;
            // cout<<"Receiver send_com_size ps"<<chl.bytesSent()/1024<<"KB"<<endl;
            // chl.close();
      

            return outvec;
        }

        //  void ResponseOT(oc::Socket socket,std::vector<std::array<oc::block, 2>>&  shuffleMessages){
        //     APSU_LOG_INFO(__FILE__ << __LINE__);

        //     NetIO server("server","",60000);
        //     auto pp = IKNPOTE::Setup(128);
        //     Global_Initialize(); 
        //     ECGroup_Initialize(NID_X9_62_prime256v1);
        //     size_t item_len = shuffleMessages.size();
        //     std::vector<block> oneside_send(item_len);

        //     for(size_t idx =0 ;idx < item_len; idx++ ){
        //         auto cont = shuffleMessages[idx][0];
        //         oneside_send[idx] = Block::MakeBlock(cont.get<uint64_t>()[1],cont.get<uint64_t>()[0]);
        //     }
        //     IKNPOTE::OnesidedSend(server,pp,oneside_send,item_len);
        //     ECGroup_Finalize(); 
        //     Global_Finalize();  
        //     // oc::PRNG prng(_mm_set_epi32(4253465,3434565,23987025,234435));
        //     // oc::IknpOtExtSender IKNPsender;
        //     // oc::DefaultBaseOT base;
        //     // oc::BitVector bv(128);
        //     // std::array<oc::block, 128> baseMsg;
        //     // bv.randomize(prng);
        //     // APSU_LOG_INFO(__FILE__ << __LINE__);

        //     // coproto::sync_wait(base.receive(bv, baseMsg, prng, socket));
        //     // IKNPsender.setBaseOts(baseMsg, bv);
        //     // APSU_LOG_INFO(__FILE__ << __LINE__);

        //     // auto proto = IKNPsender.sendChosen(shuffleMessages, prng, socket);
        //     // coproto::sync_wait(proto);
        
        //     // int recv_num = socket.bytesReceived();
        //     // int send_num = socket.bytesSent();

    
        //     // APSU_LOG_INFO("OT send_com_size ps"<<send_num/1024<<"KB");
        //     // APSU_LOG_INFO("OT recv_com_size ps"<<recv_num/1024<<"KB");

   

        // }

    }
}

