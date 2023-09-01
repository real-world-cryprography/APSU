#include "DDHPEQT.h"
namespace apsu{
    namespace peqt{
         std::vector<uint64_t> ddh_peqt_sender(NetIO& net,std::vector<block>& decrypt_randoms_matrix,size_t alpha_max_cache_count,size_t item_cnt){
            
            CRYPTO_Initialize();


            // Block::PrintBlocks(decrypt_randoms_matrix);

            auto permutation = DDHPEQT::Send(net, decrypt_randoms_matrix,  alpha_max_cache_count,item_cnt);
            decrypt_randoms_matrix.clear();
            decrypt_randoms_matrix.shrink_to_fit();
            CRYPTO_Finalize();  
            return permutation;

        }

        std::vector<size_t> ddh_peqt_receiver(NetIO& net,std::vector<block>& random_matrix,size_t max_bin_bundle_conut_alpha,size_t item_cnt){

                CRYPTO_Initialize();
                // Block::PrintBlocks(random_matrix);
                auto vec_result = DDHPEQT::Receive(net,random_matrix,max_bin_bundle_conut_alpha,item_cnt);

                std::vector<size_t> ans;
                for(size_t cache_idx = 0;cache_idx<max_bin_bundle_conut_alpha;cache_idx++){
                    for(size_t item_idx = 0;item_idx<item_cnt;item_idx++){
                        if(vec_result[cache_idx*item_cnt+item_idx]) ans.emplace_back(item_idx);
                    }
                }


                CRYPTO_Finalize();

                return ans;

        }


    }

}