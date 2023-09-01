#pragma once
#include "Kunlun/mpc/peqt/peqt_from_ddh.hpp"
#include "Kunlun/crypto/setup.hpp"
namespace apsu{
    namespace peqt{
         std::vector<uint64_t> ddh_peqt_sender
            (NetIO& net,
            std::vector<block>& decrypt_randoms_matrix,
            size_t alpha_max_cache_count,
            size_t item_cnt);

        std::vector<size_t> ddh_peqt_receiver(
            NetIO& net,
            std::vector<block>& random_matrix,
            size_t max_bin_bundle_conut_alpha,
            size_t item_cnt);

    }
}
