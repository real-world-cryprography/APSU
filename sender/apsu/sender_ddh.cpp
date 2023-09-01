// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <future>
#include <iostream>
#include <sstream>
#include <stdexcept>


// APSU
#include "apsu/log.h"
#include "apsu/network/channel.h"
#include "apsu/plaintext_powers.h"
#include "apsu/sender_ddh.h"
#include "apsu/thread_pool_mgr.h"
#include "apsu/util/db_encoding.h"
#include "apsu/util/label_encryptor.h"
#include "apsu/util/utils.h"

#include "apsu/utils.h"
#include "apsu/peqt/DDHPEQT.h"


// SEAL
#include "seal/ciphertext.h"
#include "seal/context.h"
#include "seal/encryptionparams.h"
#include "seal/keygenerator.h"
#include "seal/plaintext.h"
#include "seal/util/common.h"
#include "seal/util/defines.h"


#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
using milliseconds_ratio = std::ratio<1, 1000>;
using duration_millis = std::chrono::duration<double, milliseconds_ratio>;

using namespace std;
using namespace seal;
using namespace seal::util;
using namespace kuku;

namespace apsu {
    using namespace util;
    using namespace network;
    using namespace oprf;

    namespace {
        template <typename T>
        bool has_n_zeros(T *ptr, size_t count)
        {
            return all_of(ptr, ptr + count, [](auto a) { return a == T(0); });
        }
        inline oc::block vec_to_oc_block(const std::vector<uint64_t> &in,size_t felts_per_item,uint64_t plain_modulus){
            uint32_t plain_modulus_len = 1;
            while(((1<<plain_modulus_len)-1)<plain_modulus){
                plain_modulus_len++;
            }
            uint64_t plain_modulus_mask = (1<<plain_modulus_len)-1;
            uint64_t plain_modulus_mask_lower = (1<<(plain_modulus_len>>1))-1;
            uint64_t plain_modulus_mask_higher = plain_modulus_mask-plain_modulus_mask_lower;

            uint64_t lower=0,higher=0;
            if(felts_per_item&1){
                lower = (in[felts_per_item-1] & plain_modulus_mask_lower);
                higher = ((in[felts_per_item-1] & plain_modulus_mask_higher) >>((plain_modulus_len>>1)-1));
            }
            for(int pla = 0;pla < felts_per_item;pla+=2){
                lower = ((in[pla] & plain_modulus_mask) | (lower<<plain_modulus_len));
                higher = ((in[pla+1] & plain_modulus_mask) | (higher<<plain_modulus_len));
            }
            return oc::toBlock(higher,lower);
        }

        inline block vec_to_std_block(const std::vector<uint64_t> &in,size_t felts_per_item,uint64_t plain_modulus){
            uint32_t plain_modulus_len = 1;
            while(((1<<plain_modulus_len)-1)<plain_modulus){
                plain_modulus_len++;
            }
            uint64_t plain_modulus_mask = (1<<plain_modulus_len)-1;
            uint64_t plain_modulus_mask_lower = (1<<(plain_modulus_len>>1))-1;
            uint64_t plain_modulus_mask_higher = plain_modulus_mask-plain_modulus_mask_lower;
                //  cout<<"masks"<<endl;
                // cout<<hex<<plain_modulus<<endl;
                // cout<<hex<<plain_modulus_mask_lower<<endl;
                // cout<<hex<<plain_modulus_mask_higher<<endl;
            uint64_t lower=0,higher=0;
            if(felts_per_item&1){
                lower = (in[felts_per_item-1] & plain_modulus_mask_lower);
                higher = ((in[felts_per_item-1] & plain_modulus_mask_higher) >>((plain_modulus_len>>1)-1));
            }
            //cout<< lower<<' '<< higher<<endl;
            for(int pla = 0;pla < felts_per_item-1;pla+=2){
                lower = ((in[pla] & plain_modulus_mask) | (lower<<plain_modulus_len));
                higher = ((in[pla+1] & plain_modulus_mask) | (higher<<plain_modulus_len));
            }
            return Block::MakeBlock(higher,lower);
        }

        #define block_oc_to_std(a) (Block::MakeBlock((oc::block)a.as<uint64_t>()[1],(oc::block)a.as<uint64_t>()[0]))
        std::vector<block> decrypt_randoms_matrix;


        
    
    } // namespace

    namespace sender {
        size_t IndexTranslationTable::find_item_idx(size_t table_idx) const noexcept
        {
            auto item_idx = table_idx_to_item_idx_.find(table_idx);
            if (item_idx == table_idx_to_item_idx_.cend()) {
                return item_count();
            }

            return item_idx->second;
        }

        Sender::Sender(PSUParams params) : params_(move(params))
        {
            initialize();
            
        }

        void Sender::reset_keys()
        {
            // Generate new keys
            KeyGenerator generator(*get_seal_context());

            // Set the symmetric key, encryptor, and decryptor
            crypto_context_.set_secret(generator.secret_key());

            // Create Serializable<RelinKeys> and move to relin_keys_ for storage
            relin_keys_.clear();
            if (get_seal_context()->using_keyswitching()) {
                Serializable<RelinKeys> relin_keys(generator.create_relin_keys());
                relin_keys_.set(move(relin_keys));
            }
        }

        uint32_t Sender::reset_powers_dag(const set<uint32_t> &source_powers)
        {
            // First compute the target powers
            set<uint32_t> target_powers = create_powers_set(
                params_.query_params().ps_low_degree, params_.table_params().max_items_per_bin);

            // Configure the PowersDag
            pd_.configure(source_powers, target_powers);

            // Check that the PowersDag is valid
            if (!pd_.is_configured()) {
                APSU_LOG_ERROR(
                    "Failed to configure PowersDag ("
                    << "source_powers: " << to_string(source_powers) << ", "
                    << "target_powers: " << to_string(target_powers) << ")");
                throw logic_error("failed to configure PowersDag");
            }
            APSU_LOG_DEBUG("Configured PowersDag with depth " << pd_.depth());

            return pd_.depth();
        }

        void Sender::initialize()
        {
            APSU_LOG_DEBUG("PSU parameters set to: " << params_.to_string());
            APSU_LOG_DEBUG(
                "Derived parameters: "
                << "item_bit_count_per_felt: " << params_.item_bit_count_per_felt()
                << "; item_bit_count: " << params_.item_bit_count()
                << "; bins_per_bundle: " << params_.bins_per_bundle()
                << "; bundle_idx_count: " << params_.bundle_idx_count());

            STOPWATCH(sender_stopwatch, "Sender::initialize");

            // Initialize the CryptoContext with a new SEALContext
            crypto_context_ = CryptoContext(params_);

            // Set up the PowersDag
            reset_powers_dag(params_.query_params().query_powers);

            // Create new keys
            reset_keys();

            // init send Messages
            sendMessages.clear();

        
            
       

        }

        unique_ptr<ReceiverOperation> Sender::CreateParamsRequest()
        {
            auto rop = make_unique<ReceiverOperationParms>();
            APSU_LOG_INFO("Created parameter request");

            return rop;
        }

        PSUParams Sender::RequestParams(NetworkChannel &chl)
        {
            // Create parameter request and send to Sender
            chl.send(CreateParamsRequest());
            
            // Wait for a valid message of the right type

            
            ParamsResponse response;
            bool logged_waiting = false;
            while (!(response = to_params_response(chl.receive_response()))) {
                if (!logged_waiting) {
                    // We want to log 'Waiting' only once, even if we have to wait for several
                    // sleeps.
                    logged_waiting = true;
                    APSU_LOG_INFO("Waiting for response to parameter request");
                }

                this_thread::sleep_for(50ms);
            }

            return *response->params;
        }

// oprf has been removed

      



        pair<Request, IndexTranslationTable> Sender::create_query(
            const vector<HashedItem> &items,
            const std::vector<string> &origin_item,
            coproto::AsioSocket SenderKKRTSocket)
        {
            APSU_LOG_INFO("Creating encrypted query for " << items.size() << " items");
            STOPWATCH(sender_stopwatch, "Sender::create_query");
            all_timer.setTimePoint("create_query");
            IndexTranslationTable itt;
            itt.item_count_ = items.size();

            // Create the cuckoo table
            KukuTable cuckoo(
                params_.table_params().table_size,      // Size of the hash table
                0,                                      // Not using a stash
                params_.table_params().hash_func_count, // Number of hash functions
                { 0, 0 },                               // Hardcoded { 0, 0 } as the seed
                cuckoo_table_insert_attempts,           // The number of insertion attempts
                { 0, 0 });                              // The empty element can be set to anything

            // Hash the data into a cuckoo hash table
            // cuckoo_hashing
            {
                STOPWATCH(sender_stopwatch, "Sender::create_query::cuckoo_hashing");
                APSU_LOG_DEBUG(
                    "Inserting " << items.size() << " items into cuckoo table of size "
                                 << cuckoo.table_size() << " with " << cuckoo.loc_func_count()
                                 << " hash functions");
                for (size_t item_idx = 0; item_idx < items.size(); item_idx++) {
                    const auto &item = items[item_idx];
                    if (!cuckoo.insert(item.get_as<kuku::item_type>().front())) {
                        // Insertion can fail for two reasons:
                        //
                        //     (1) The item was already in the table, in which case the "leftover
                        //     item" is empty; (2) Cuckoo hashing failed due to too small table or
                        //     too few hash functions.
                        //
                        // In case (1) simply move on to the next item and log this issue. Case (2)
                        // is a critical issue so we throw and exception.
                        if (cuckoo.is_empty_item(cuckoo.leftover_item())) {
                            APSU_LOG_INFO(
                                "Skipping repeated insertion of items["
                                << item_idx << "]: " << item.to_string());
                        } else {
                            APSU_LOG_ERROR(
                                "Failed to insert items["
                                << item_idx << "]: " << item.to_string()
                                << "; cuckoo table fill-rate: " << cuckoo.fill_rate());
                            throw runtime_error("failed to insert item into cuckoo table");
                        }
                    }
                }
                APSU_LOG_DEBUG(
                    "Finished inserting items with "
                    << cuckoo.loc_func_count()
                    << " hash functions; cuckoo table fill-rate: " << cuckoo.fill_rate());
            }

#if CARDSUM == 1
            valueMessages.assign(cuckoo.table_size(),(uint64_t)0);
            shuffle_valueMessages.assign(cuckoo.table_size(),(uint64_t)0);

#endif
#if ARBITARY == 0 
            sendMessages.assign(cuckoo.table_size(),{oc::ZeroBlock,oc::ZeroBlock});

            shuffleMessages.assign(cuckoo.table_size(),{oc::ZeroBlock,oc::ZeroBlock});
            // Once the table is filled, fill the table_idx_to_item_idx map
            for (size_t item_idx = 0; item_idx < items.size(); item_idx++) {
                auto item_loc = cuckoo.query(items[item_idx].get_as<kuku::item_type>().front());
                auto temp_loc = item_loc.location();
                itt.table_idx_to_item_idx_[temp_loc] = item_idx;
               // sendMessages[temp_loc]={oc::ZeroBlock,oc::toBlock((uint8_t*)origin_item[item_idx].data())};
                sendMessages[temp_loc]={oc::toBlock((uint8_t*)origin_item[item_idx].data()),oc::ZeroBlock};
              //  APSU_LOG_INFO(sendMessages[temp_loc][0].as<char>().data());
               // cout<<(int)sendMessages[temp_loc][0].as<char>()[0]<<endl;

#if CARDSUM == 1
                valueMessages[temp_loc] = item_idx;
#endif
            }
#else

            item_len = (origin_item[0].size()+15)/16;
            sendMessages.resize(item_len);
            shuffleMessages.resize(item_len);
            for(size_t idx = 0;idx<item_len;idx++){
                sendMessages[idx].assign(cuckoo.table_size(),{oc::ZeroBlock,oc::ZeroBlock});

                shuffleMessages[idx].assign(cuckoo.table_size(),{oc::ZeroBlock,oc::ZeroBlock});
            }

            // Once the table is filled, fill the table_idx_to_item_idx map
            for (size_t item_idx = 0; item_idx < items.size(); item_idx++) {
                auto item_loc = cuckoo.query(items[item_idx].get_as<kuku::item_type>().front());
                auto temp_loc = item_loc.location();
                itt.table_idx_to_item_idx_[temp_loc] = item_idx;
               // sendMessages[temp_loc]={oc::ZeroBlock,oc::toBlock((uint8_t*)origin_item[item_idx].data())};

               // one block only contain 16 Bytes 
               // We need to truncate it into some substring
                for(size_t item_trunc_idx=0;item_trunc_idx<item_len;item_trunc_idx++){
                    sendMessages[item_trunc_idx][temp_loc]={oc::toBlock((uint8_t*)origin_item[item_idx].substr(16*item_trunc_idx,16).data()),oc::ZeroBlock};

                }
               // APSU_LOG_INFO(sendMessages[0][temp_loc][0].as<char>().data());
               // cout<<(int)sendMessages[temp_loc][0].as<char>()[0]<<endl;
            }

#endif
            // Set up unencrypted query data
            vector<PlaintextPowers> plain_powers;
            auto receiver_data = oprf_receiver(cuckoo.table(),SenderKKRTSocket);
            // prepare_data
            {
                STOPWATCH(sender_stopwatch, "Sender::create_query::prepare_data");
                for (uint32_t bundle_idx = 0; bundle_idx < params_.bundle_idx_count();
                     bundle_idx++) {
                    APSU_LOG_DEBUG("Preparing data for bundle index " << bundle_idx);

                    // First, find the items for this bundle index
                    gsl::span<const item_type> bundle_items(
                        receiver_data.data() + bundle_idx * params_.items_per_bundle(),
                        params_.items_per_bundle());

                    vector<uint64_t> alg_items;
                    for (auto &item : bundle_items) {
                        // Now set up a BitstringView to this item
                        gsl::span<const unsigned char> item_bytes(
                            reinterpret_cast<const unsigned char *>(item.data()), sizeof(item));
                        BitstringView<const unsigned char> item_bits(
                            item_bytes, params_.item_bit_count());

                        // Create an algebraic item by breaking up the item into modulo
                        // plain_modulus parts
                        vector<uint64_t> alg_item =
                            bits_to_field_elts(item_bits, params_.seal_params().plain_modulus());
                        copy(alg_item.cbegin(), alg_item.cend(), back_inserter(alg_items));
                    }

                    // Now that we have the algebraized items for this bundle index, we create a
                    // PlaintextPowers object that computes all necessary powers of the algebraized
                    // items.
                    plain_powers.emplace_back(move(alg_items), params_, pd_);
                }
                

            }

            // The very last thing to do is encrypt the plain_powers and consolidate the matching
            // powers for different bundle indices
            unordered_map<uint32_t, vector<SEALObject<Ciphertext>>> encrypted_powers;

            // encrypt_data
            {
                STOPWATCH(sender_stopwatch, "Sender::create_query::encrypt_data");
                for (uint32_t bundle_idx = 0; bundle_idx < params_.bundle_idx_count();
                     bundle_idx++) {
                    APSU_LOG_DEBUG("Encoding and encrypting data for bundle index " << bundle_idx);

                    // Encrypt the data for this power
                    auto encrypted_power(plain_powers[bundle_idx].encrypt(crypto_context_));

                    // Move the encrypted data to encrypted_powers
                    for (auto &e : encrypted_power) {
                        encrypted_powers[e.first].emplace_back(move(e.second));
                    }
                }
            }

            // Set up the return value
            auto rop_query = make_unique<ReceiverOperationQuery>();
            rop_query->compr_mode = seal::Serialization::compr_mode_default;
            rop_query->relin_keys = relin_keys_;
            rop_query->data = move(encrypted_powers);
            auto rop = to_request(move(rop_query));

            APSU_LOG_INFO("Finished creating encrypted query");
            all_timer.setTimePoint("create_query finish");
            return { move(rop), itt };
        }

        void Sender::request_query(
            const vector<HashedItem> &items,
            NetworkChannel &chl,
            const vector<string> &origin_item,
            coproto::AsioSocket SenderChl
            )
        {
            ThreadPoolMgr tpm;

            // Create query and send to Sender
            auto query = create_query(items,origin_item,SenderChl);
            chl.send(move(query.first));
            auto itt = move(query.second);
            all_timer.setTimePoint("with response start");

            // Wait for query response
            QueryResponse response;
            bool logged_waiting = false;
            while (!(response = to_query_response(chl.receive_response()))) {
                if (!logged_waiting) {
                    // We want to log 'Waiting' only once, even if we have to wait for several
                    // sleeps.
                    logged_waiting = true;
                    APSU_LOG_INFO("Waiting for response to query request");
                }

                this_thread::sleep_for(50ms);
            }
            all_timer.setTimePoint("with response finish");

            uint32_t bundle_idx_count = safe_cast<uint32_t>(params_.bundle_idx_count()); 
            uint32_t items_per_bundle = safe_cast<uint32_t>(params_.items_per_bundle());
            size_t felts_per_item = safe_cast<size_t>(params_.item_params().felts_per_item);
            uint32_t item_cnt = bundle_idx_count* items_per_bundle; 

        //       int block_num = ((felts_per_item+3)/4);


            // Get the number of ResultPackages we expect to receive
            atomic<uint32_t> package_count{ response->package_count };
            

            // prepare decrypt randoms matrix size for copy

            uint32_t alpha_max_cache_count = response->alpha_max_cache_count;
            decrypt_randoms_matrix.assign(alpha_max_cache_count * item_cnt,Block::zero_block);
            
            
            // Launch threads to receive ResultPackages and decrypt results
            size_t task_count = min<size_t>(ThreadPoolMgr::GetThreadCount(), package_count);
            vector<future<void>> futures(task_count);
            APSU_LOG_INFO(
                "Launching " << task_count << " result worker tasks to handle " << package_count
                             << " result parts");
            for (size_t t = 0; t < task_count; t++) {
                futures[t] = tpm.thread_pool().enqueue(
                    [&]() { process_result_worker(package_count, itt, chl); });
            }

            for (auto &f : futures) {
                f.get();
            }
            // pm-PEQT 
            NetIO client("client", "127.0.0.1", 59999);
            auto permutation = peqt::ddh_peqt_sender(client,decrypt_randoms_matrix,alpha_max_cache_count,item_cnt);
   
           
             
        
#if ARBITARY == 0 
          // memory overfit
            
            for(int i=0;i<item_cnt;i++)
                shuffleMessages[permutation[i]]=sendMessages[i];

            KunlunOT::ALSZ_KL_ChosenSender(client,shuffleMessages);
#else
            for(int item_trunc_idx=0;item_trunc_idx < item_len;item_trunc_idx++){
                for(int i=0;i<item_cnt;i++){
                    shuffleMessages[item_trunc_idx][permutation[i]]=sendMessages[item_trunc_idx][i];
                    // APSU_LOG_INFO(shuffleMessages[item_trunc_idx][permutation[i]][0].as<uint8_t>().data());
                    // APSU_LOG_INFO(sendMessages[item_trunc_idx][i][0].as<uint8_t>().data());
                }
           
            }
#endif

            all_timer.setTimePoint("decrypt and unpermute finish");
        }

        void Sender::process_result_part(
        
            const IndexTranslationTable &itt,
            const ResultPart &result_part,
            network::NetworkChannel &chl) const
        {
            STOPWATCH(sender_stopwatch, "Sender::process_result_part");

            if (!result_part) {
                APSU_LOG_ERROR("Failed to process result: result_part is null");
                return ;
            }

            // The number of items that were submitted in the query
            size_t item_count = itt.item_count();
            
            // Decrypt and decode the result; the result vector will have full batch size
            PlainResultPackage plain_rp = result_part->extract(crypto_context_);
            uint32_t items_per_bundle = safe_cast<uint32_t>(params_.items_per_bundle());
            size_t felts_per_item = safe_cast<size_t>(params_.item_params().felts_per_item);
            vector<block> decrypt_res(items_per_bundle);
            uint64_t plain_modulus=crypto_context_.seal_context()->last_context_data()->parms().plain_modulus().value();
            for(uint32_t item_idx=0;item_idx<items_per_bundle;item_idx++){
                vector<uint64_t> all_felts_one_item(felts_per_item,0);
                for(size_t felts_idx = 0;felts_idx<felts_per_item;felts_idx++){
                    all_felts_one_item[felts_idx] = plain_rp.psu_result[item_idx*felts_per_item+felts_idx];
                }
                decrypt_res[item_idx]= vec_to_std_block(all_felts_one_item,felts_per_item,plain_modulus);
            }
            uint32_t cache_idx = result_part->cache_idx;
            copy(
                decrypt_res.begin(),
                decrypt_res.end(),
                decrypt_randoms_matrix.begin()+(cache_idx*item_count+cache_idx*items_per_bundle)
            );
        
           
        }

        void Sender::process_result_worker(
            atomic<uint32_t> &package_count,
            const IndexTranslationTable &itt,
            NetworkChannel &chl)
        {
            stringstream sw_ss;
            sw_ss << "Sender::process_result_worker [" << this_thread::get_id() << "]";
            STOPWATCH(sender_stopwatch, sw_ss.str());

            APSU_LOG_INFO("Result worker [" << this_thread::get_id() << "]: starting");

            auto seal_context = get_seal_context();

            while (true) {
                // Return if all packages have been claimed
                uint32_t curr_package_count = package_count;
                if (curr_package_count == 0) {
                    APSU_LOG_DEBUG(
                        "Result worker [" << this_thread::get_id()
                                          << "]: all packages claimed; exiting");
                    return;
                }

                // If there has been no change to package_count, then decrement atomically
                if (!package_count.compare_exchange_strong(
                        curr_package_count, curr_package_count - 1)) {
                    continue;
                }

                // Wait for a valid ResultPart
                ResultPart result_part;
                while (!(result_part = chl.receive_result(seal_context)))
                    ;
                
            // Decrypt and decode the result; the result vector will have full batch size
                     
                    PlainResultPackage plain_rp = result_part->extract(crypto_context_);
                    uint32_t items_per_bundle = safe_cast<uint32_t>(params_.items_per_bundle());
                    uint32_t bundle_idx_count = safe_cast<uint32_t>(params_.bundle_idx_count());
                    size_t felts_per_item = safe_cast<size_t>(params_.item_params().felts_per_item);
                    vector<block> decrypt_res(items_per_bundle);
                    uint64_t plain_modulus=crypto_context_.seal_context()->last_context_data()->parms().plain_modulus().value();
                    // for(int i =0 ;i<plain_rp.psu_result.size();i++){
                    //     plain_rp.psu_result[i] = 124u;
                    // }
                  
                    for(uint32_t item_idx=0;item_idx<items_per_bundle;item_idx++){
                        vector<uint64_t> all_felts_one_item(felts_per_item,0);
                        for(size_t felts_idx = 0;felts_idx<felts_per_item;felts_idx++){
                            all_felts_one_item[felts_idx] = plain_rp.psu_result[item_idx*felts_per_item+felts_idx];
                        }
                        decrypt_res[item_idx]= vec_to_std_block(all_felts_one_item,felts_per_item,plain_modulus);
                    }
                    uint32_t cache_idx = result_part->cache_idx;
                    uint32_t bundle_idx = result_part->bundle_idx;
                    cout << decrypt_randoms_matrix.size() << std::endl;
                    cout << (cache_idx*items_per_bundle*bundle_idx_count+bundle_idx*items_per_bundle) << std::endl;
                    copy(
                        decrypt_res.begin(),
                        decrypt_res.end(),
                        decrypt_randoms_matrix.begin()+(cache_idx*items_per_bundle*bundle_idx_count+bundle_idx*items_per_bundle)
                    );
                   decrypt_res.clear();

            }
        }
#if ARBITARY == 0 

        // void Sender::ResponseOT(string conn_addr){


        //     all_timer.setTimePoint("response OT start");

        //     int numThreads = 1;
        //     prng.SetSeed(_mm_set_epi32(4253465,3434565,23987025,234435));
        //     oc::IOService ios;
        //     oc::Session send_session=oc::Session(ios,"localhost:50000",oc::SessionMode::Client);
        //     std::vector<oc::Channel> send_chls;
        
            

            

        //     for (int i = 0; i < numThreads; ++i)
        //         send_chls.emplace_back(send_session.addChannel());            
        //     std::vector<oc::IknpOtExtSender> senders(numThreads);
        //     APSU_LOG_INFO(sendMessages.size());
        //     senders[0].sendChosen(shuffleMessages, prng, send_chls[0]);

        //     int recv_num = send_chls[0].getTotalDataRecv();
        //     int send_num = send_chls[0].getTotalDataSent();

    
        //     APSU_LOG_INFO("OT send_com_size ps"<<send_num/1024<<"KB");
        //     APSU_LOG_INFO("OT recv_com_size ps"<<recv_num/1024<<"KB");
        //     all_timer.setTimePoint("response OT finish");

        //     cout<<all_timer<<endl;
        //     all_timer.reset();
        //     send_chls[0].close();
        //     send_session.stop();
        //     ios.stop();

        // }

#else
        void Sender::ResponseOT(string conn_addr){
            all_timer.setTimePoint("response OT start");

            int numThreads = 1;
      
            oc::IOService ios;
            oc::Session send_session=oc::Session(ios,"localhost:59999",oc::SessionMode::Client);
            std::vector<oc::Channel> send_chls(numThreads);
            APSU_LOG_INFO(item_len);
            oc::PRNG prng(oc::sysRandomSeed());            
            for (int i = 0; i < numThreads; ++i)
                send_chls[i]=send_session.addChannel();
            std::vector<oc::IknpOtExtSender> senders(numThreads);
           
            for(size_t item_trunc_idx=0;item_trunc_idx<item_len;item_trunc_idx++){
                APSU_LOG_INFO("send size"<<shuffleMessages[item_trunc_idx].size());
                senders[0].sendChosen(shuffleMessages[item_trunc_idx], prng, send_chls[0]);
            }

            int recv_num = send_chls[0].getTotalDataRecv();
            int send_num = send_chls[0].getTotalDataSent();


            APSU_LOG_INFO("OT send_com_size ps"<<send_num/1024<<"KB");
            APSU_LOG_INFO("OT recv_com_size ps"<<recv_num/1024<<"KB");
            all_timer.setTimePoint("response OT finish");

            cout<<all_timer<<endl;
            all_timer.reset();
        
            send_session.stop();
        }

#endif
#if CARDSUM == 1
    void Sender::Cardsum_Send(){
        all_timer.setTimePoint("cardsum_begin");
        
        Global_Initialize(); 
        ECGroup_Initialize(NID_X9_62_prime256v1); 
        APSU_LOG_INFO("line821");
        
            NetIO server("client","127.0.0.1",58888);

            
          
            auto pp = NPOT::Setup();
           
            APSU_LOG_INFO("line831");
    
   
            
            uint64_t sum_r = 0;
        

            prng_seed_type newseed;
            random_bytes(reinterpret_cast<seal_byte *>(newseed.data()), prng_seed_byte_count);
            UniformRandomGeneratorInfo myGEN(prng_type::blake2xb, newseed);
            std::shared_ptr<UniformRandomGenerator> myprng = myGEN.make_prng();
            std::vector<uint64_t> randomMessages;
            APSU_LOG_INFO("line837");
            for(auto v : shuffle_valueMessages){
                auto temp = (uint64_t)(myprng->generate()&0xFFFFFFFF);
                sum_r = ((sum_r + temp)&0xFFFFFFFF);
                randomMessages.emplace_back(temp);
            }
            size_t len = shuffle_valueMessages.size();
            std::vector<block> v;
            std::vector<block> r;

            for(size_t i = 0 ; i < len; i++){
                v.emplace_back(Block::MakeBlock(0,randomMessages[i]));
                r.emplace_back(Block::MakeBlock(0,randomMessages[i]+shuffle_valueMessages[i]));
            }
    
            APSU_LOG_INFO(len);
            NPOT::Send(server,pp,v,r,len);
            uint64_t S_prime = 0;
            uint64_t card = 0;
            server.ReceiveInteger(S_prime);
            S_prime -= sum_r;
            server.ReceiveInteger(card);
            APSU_LOG_INFO("Sum"<<S_prime);
            APSU_LOG_INFO("Card"<<card);

            ECGroup_Finalize(); 
            Global_Finalize();  
            all_timer.setTimePoint("cardsum Finish");
            cout<<all_timer<<endl;
            all_timer.reset();
    }

#endif



    } // namespace sender
} // namespace apsu
