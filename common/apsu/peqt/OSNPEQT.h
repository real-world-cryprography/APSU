#pragma once
#include "apsu/ot/kunlun_ot.h"
#include "apsu/permute/apsu_OSNReceiver.h"
#include "apsu/permute/apsu_OSNSender.h"

#include "Kunlun/mpc/oprf/ote_oprf.hpp"
#include "Kunlun/crypto/setup.hpp"
namespace apsu{
    namespace peqt{
        std::vector<int> osn_peqt_sender(
            oc::Socket &SenderChl, 
            NetIO& net,
            std::vector<oc::block> decrypt_randoms_matrix,
            size_t alpha_max_cache_count, 
            size_t item_cnt);
        std::vector<size_t> osn_peqt_receiver(
            oc::Socket &ReceiverChl, 
            NetIO& net,
            std::vector<oc::block> random_matrix,
            size_t  alpha_max_cache_count,
            size_t item_cnt
            
            );

    }
}
