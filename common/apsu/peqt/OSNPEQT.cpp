#include "OSNPEQT.h"
#include "libOTe/Tools/Coproto.h"
#include "coproto/Socket/AsioSocket.h"
namespace apsu{
    namespace peqt
    {
        std::vector<int> osn_peqt_sender(
            oc::Socket &SenderChl, 
            NetIO& net,
            std::vector<oc::block> decrypt_randoms_matrix,
            size_t alpha_max_cache_count, 
            size_t item_cnt){

                size_t shuffle_size = alpha_max_cache_count*item_cnt;
                OSNSender osn;
                osn.init(alpha_max_cache_count,item_cnt,OSNSender::OT_type::KunlunOT,NUMBER_OF_THREADS,"");
                auto permutation = osn.dest;
                auto col_permutation = osn.cols_premutation;
                auto sender_share = osn.run_osn(SenderChl,net);
                


            
                std::vector<oc::block> shuffle_decrypt_randoms_matrix(shuffle_size);

                std::vector<block> mpoprf_in;
                // template shuffle schream
                for(int i = 0;i<shuffle_size;i++){
                    shuffle_decrypt_randoms_matrix[i] = decrypt_randoms_matrix[permutation[i]];
                }
                for(int i = 0;i<shuffle_size;i++){
                    mpoprf_in.emplace_back(shuffle_decrypt_randoms_matrix[i]^sender_share[i]);
                }
                size_t padding = 128-mpoprf_in.size()%128;
                for(int i = 0;i<padding;i++)
                    mpoprf_in.emplace_back(Block::all_one_block);
                //APSU_LOG_INFO("padding size"<<mpoprf_in.size());
            
            
                CRYPTO_Initialize();
                // std::cout << generator << std::endl;

                // APSU_LOG_INFO("test");
                //APSU_LOG_INFO(decrypt_randoms_matrix.size()<<item_cnt<<alpha_max_cache_count);
                size_t set_size = mpoprf_in.size();
                size_t log_set_size=int(log2(set_size)+1);

                std::string pp_filename = "MPOPRF.pp"; 
                OTEOPRF::PP pp; 
                // pp.npot_part.g.point_ptr = EC_POINT_new(group);
                // cout<<set_size<<endl;
                OTEOPRF::Setup(pp,log_set_size);
                // if(!FileExist(pp_filename)){
                //     pp = MPOPRF::Setup(log_set_size); // 40 is the statistical parameter
                //     MPOPRF::SavePP(pp, pp_filename); 
                // }
                // else{
                //     MPOPRF::FetchPP(pp, pp_filename); 
                // }

                int test = 0;
                auto mpoprf_key = OTEOPRF::Server(net,pp);
                
                std::vector<std::vector<uint8_t>> mpoprf_out = OTEOPRF::Evaluate(pp,mpoprf_key,mpoprf_in,set_size);
                net.SendBytesArray(mpoprf_out);

                CRYPTO_Finalize();
                return col_permutation;

        }
        std::vector<size_t> osn_peqt_receiver(
            oc::Socket &ReceiverChl, 
            NetIO& net,
            std::vector<oc::block> random_matrix,


            size_t  alpha_max_cache_count,
            size_t item_cnt

            ){
                std::vector<block> mpoprf_in;
                

             
                size_t shuffle_size = random_matrix.size();

                OSNReceiver osn;
                osn.init(shuffle_size,OSNReceiver::OT_type::KunlunOT,NUMBER_OF_THREADS);

                

                auto receiver_share =osn.run_osn(random_matrix,ReceiverChl,net);
                
 
  
                
                for(auto x: receiver_share){
                    mpoprf_in.emplace_back(x);
                }
                size_t padding = 128-mpoprf_in.size()%128;
                for(int i = 0;i<padding;i++)
                    mpoprf_in.emplace_back(Block::zero_block);
            
                // mp-oprf 
                // Block::PrintBlocks(mpoprf_in);
                
     
                // group = EC_GROUP_new_by_curve_name(415);
                // generator = EC_GROUP_get0_generator(group);

                size_t set_size = mpoprf_in.size();
                size_t log_set_size=int(log2(set_size)+1);
                CRYPTO_Initialize();

                OTEOPRF::PP pp; 

                
                OTEOPRF::Setup(pp,log_set_size);
                std::cout << __FILE__ << __LINE__ << std::endl;
                auto mpoprf_out = OTEOPRF::Client(net,pp,mpoprf_in,set_size);
               
                std::vector<std::vector<uint8_t>> mpoprf_recv;
                net.ReceiveBytesArray(mpoprf_recv);
               
                // for(int i = 0;i<shuffle_size;i++){
                //     //  APSU_LOG_INFO(i);
                //     // std::cout << mpoprf_recv[i] << std::endl;
                //     for(size_t idx = 0; idx < pp.OUTPUT_LEN ; idx++){
                //         printf("%02x",(uint8_t)mpoprf_out[i][idx]);
                //     }
                //     printf("\n");
                //     for(size_t idx = 0; idx < pp.OUTPUT_LEN ; idx++){
                //         printf("%02x",(uint8_t)mpoprf_recv[i][idx]);
                //     }
                //     printf("\n");
                // }
                CRYPTO_Finalize();
                std::vector<size_t> ans; 

                for(size_t cache_idx = 0;cache_idx<alpha_max_cache_count;cache_idx++){
                    for(size_t item_idx = 0;item_idx<item_cnt;item_idx++){
                        auto& OTEOPRFValue  = mpoprf_out[cache_idx*item_cnt+item_idx];
                        auto& OTEOPRFRecv   = mpoprf_recv[cache_idx*item_cnt+item_idx];
                        
                        if(memcmp(OTEOPRFRecv.data(),OTEOPRFValue.data(),pp.OUTPUT_LEN)==0) ans.emplace_back(item_idx);
                    }
                }
           
                return ans;


        }


    } // namespace peqt
    

}