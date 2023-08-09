// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <algorithm>
#include <future>
#include <iterator>
#include <memory>
#include <mutex>
#include <sstream>

// APSU
#include "apsu/psu_params.h"
#include "apsu/receiver_db.h"
#include "apsu/receiver_db_generated.h"
#include "apsu/thread_pool_mgr.h"
#include "apsu/util/db_encoding.h"
#include "apsu/util/label_encryptor.h"
#include "apsu/util/utils.h"

// Kuku
#include "kuku/locfunc.h"

// SEAL
#include "seal/util/common.h"
#include "seal/util/streambuf.h"

#include <cryptoTools/Network/Channel.h>
#include <cryptoTools/Network/Session.h>
#include <cryptoTools/Network/IOService.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Common/Defines.h>
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h"
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtSender.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtSender.h"
#include "libOTe/NChooseOne/Kkrt/KkrtNcoOtReceiver.h"
#include "coproto/Socket/AsioSocket.h"
#include "cryptoTools/Common/Matrix.h"

using milliseconds_ratio = std::ratio<1, 1000>;
using duration_millis = std::chrono::duration<double, milliseconds_ratio>;
using namespace std;
using namespace seal;
using namespace seal::util;
using namespace kuku;

namespace apsu {
    using namespace util;
    using namespace oprf;

    namespace receiver {
        namespace {
            /**
            Creates and returns the vector of hash functions similarly to how Kuku 2.x sets them
            internally.
            */
            vector<LocFunc> hash_functions(const PSUParams &params)
            {
                vector<LocFunc> result;
                for (uint32_t i = 0; i < params.table_params().hash_func_count; i++) {
                    result.emplace_back(params.table_params().table_size, make_item(i, 0));
                }

                return result;
            }

            /**
            Computes all cuckoo hash table locations for a given item.
            */
            unordered_set<location_type> all_locations(
                const vector<LocFunc> &hash_funcs, const HashedItem &item)
            {
                unordered_set<location_type> result;
                for (auto &hf : hash_funcs) {
                    result.emplace(hf(item.get_as<kuku::item_type>().front()));
                }

                return result;
            }

            /**
            Compute the label size in multiples of item-size chunks.
            */
            size_t compute_label_size(size_t label_byte_count, const PSUParams &params)
            {
                return (label_byte_count * 8 + params.item_bit_count() - 1) /
                       params.item_bit_count();
            }

            /**
            Unpacks a cuckoo idx into its bin and bundle indices
            */
            pair<size_t, size_t> unpack_cuckoo_idx(size_t cuckoo_idx, size_t bins_per_bundle)
            {
                // Recall that bin indices are relative to the bundle index. That is, the first bin
                // index of a bundle at bundle index 5 is 0. A cuckoo index is similar, except it is
                // not relative to the bundle index. It just keeps counting past bundle boundaries.
                // So in order to get the bin index from the cuckoo index, just compute cuckoo_idx
                // (mod bins_per_bundle).
                size_t bin_idx = cuckoo_idx % bins_per_bundle;

                // Compute which bundle index this cuckoo index belongs to
                size_t bundle_idx = (cuckoo_idx - bin_idx) / bins_per_bundle;

                return { bin_idx, bundle_idx };
            }

            /**
            Converts each given Item-Label pair in between the given iterators into its algebraic
            form, i.e., a sequence of felt-felt pairs. Also computes each Item's cuckoo index.
            */
            vector<pair<AlgItemLabel, size_t>> preprocess_labeled_data(
                const vector<pair<HashedItem, EncryptedLabel>>::const_iterator begin,
                const vector<pair<HashedItem, EncryptedLabel>>::const_iterator end,
                const PSUParams &params)
            {
                STOPWATCH(recv_stopwatch, "preprocess_labeled_data");
                APSU_LOG_DEBUG("Start preprocessing " << distance(begin, end) << " labeled items");

                // Some variables we'll need
                size_t bins_per_item = params.item_params().felts_per_item;
                size_t item_bit_count = params.item_bit_count();

                // Set up Kuku hash functions
                auto hash_funcs = hash_functions(params);

                // Calculate the cuckoo indices for each item. Store every pair of (item-label,
                // cuckoo_idx) in a vector. Later, we're gonna sort this vector by cuckoo_idx and
                // use the result to parallelize the work of inserting the items into BinBundles.
                vector<pair<AlgItemLabel, size_t>> data_with_indices;
                for (auto it = begin; it != end; it++) {
                    const pair<HashedItem, EncryptedLabel> &item_label_pair = *it;

                    // Serialize the data into field elements
                    const HashedItem &item = item_label_pair.first;
                    const EncryptedLabel &label = item_label_pair.second;
                    AlgItemLabel alg_item_label = algebraize_item_label(
                        item, label, item_bit_count, params.seal_params().plain_modulus());

                    // Get the cuckoo table locations for this item and add to data_with_indices
                    for (auto location : all_locations(hash_funcs, item)) {
                        // The current hash value is an index into a table of Items. In reality our
                        // BinBundles are tables of bins, which contain chunks of items. How many
                        // chunks? bins_per_item many chunks
                        size_t bin_idx = location * bins_per_item;

                        // Store the data along with its index
                        data_with_indices.push_back(make_pair(alg_item_label, bin_idx));
                    }
                }

                APSU_LOG_DEBUG(
                    "Finished preprocessing " << distance(begin, end) << " labeled items");

                return data_with_indices;
            }
            vector<vector<HashedItem> > oprf_sender(std::vector<std::vector<HashedItem> > inputs,coproto::AsioSocket chl){
                APSU_LOG_INFO(__FILE__ << __LINE__);
                
                
                osuCrypto::PRNG prng(_mm_set_epi32(4253465, 3434565, 234435, 23987025));
                
                osuCrypto::KkrtNcoOtSender sender;
                std::vector<std::vector<std::uint64_t>> outputs(inputs.size());
                
                const auto baseots_start_time = std::chrono::system_clock::now();


                size_t numOTs = inputs.size();

                sender.configure(false, 40, 128);

                
                // oc::IOService ios;

                // oc::Session  ep0(ios, "localhost:59999", oc::SessionMode::Server);

                // auto chls = ep0.addChannel();



                osuCrypto::u64 baseCount = sender.getBaseOTCount();
                osuCrypto::MasnyRindal baseOTs;
                osuCrypto::BitVector choices(baseCount);
                std::vector<osuCrypto::block> baseRecv(baseCount);
                choices.randomize(prng);
                APSU_LOG_INFO(__FILE__ << __LINE__);
                
                coproto::sync_wait(baseOTs.receive(choices, baseRecv, prng, chl, 1));
                APSU_LOG_INFO(__FILE__ << __LINE__);

                sender.setBaseOts(baseRecv, choices);

                const auto baseots_end_time = std::chrono::system_clock::now();
                const duration_millis baseOTs_duration = baseots_end_time - baseots_start_time;

                cout<<"baseOT time"<<baseOTs_duration.count()<<endl;

                const auto OPRF_start_time = std::chrono::system_clock::now();
                coproto::sync_wait(sender.init(numOTs, prng, chl));

                std::vector<std::vector<osuCrypto::block>> inputs_as_blocks(numOTs), outputs_as_blocks(numOTs);
                vector<vector<HashedItem> >outputs_as_items(numOTs);

                for (auto i = 0ull; i < numOTs; ++i) {
                    outputs_as_blocks.at(i).resize(inputs.at(i).size());
                    for (auto &var : inputs.at(i)) {
                        inputs_as_blocks.at(i).emplace_back(osuCrypto::toBlock(var.get_as<uint64_t>()[1],var.get_as<uint64_t>()[0]));
                    }
                }
                coproto::sync_wait(sender.recvCorrection(chl, numOTs));

                for (auto i = 0ull; i < numOTs; ++i) {
                    for (auto j = 0ull; j < inputs_as_blocks.at(i).size(); ++j) {
                        sender.encode(i, &inputs_as_blocks.at(i).at(j), &outputs_as_blocks.at(i).at(j),
                                        sizeof(osuCrypto::block));
                    }
                }
                for (size_t i = 0; i < numOTs; i+=1){
                    for(auto &encoding: outputs_as_blocks.at(i)){
                        outputs_as_items[i].emplace_back(HashedItem(encoding.get<uint64_t>()[0],encoding.get<uint64_t>()[1]));
                    }
                }
        
                // for (auto i = 0ull; i < numOTs; ++i) {
                //     for (auto &encoding : outputs_as_blocks.at(i)) {
                //         outputs.at(i).push_back(reinterpret_cast<uint64_t *>(&encoding)[0] &= __61_bit_mask);
                //     }
                // }

                const auto OPRF_end_time = std::chrono::system_clock::now();
                const duration_millis OPRF_duration = OPRF_end_time - OPRF_start_time;
                cout <<"oprf time"<<OPRF_duration.count()<<endl;
                // cout<<"Sender recv_com_size ps"<<chls.getTotalDataRecv()/1024<<"KB"<<endl;
                // cout<<"Sender send_com_size ps"<<chls.getTotalDataSent()/1024<<"KB"<<endl;
                // chls.close();
                // ep0.stop();
                // ios.stop();
                APSU_LOG_INFO("outputs_as_items"<<outputs_as_items[525].size());
                return outputs_as_items;
            }
            /**
            Converts each given Item into its algebraic form, i.e., a sequence of felt-monostate
            pairs. Also computes each Item's cuckoo index.
            */
            vector<pair<AlgItem, size_t>> preprocess_unlabeled_data(
                const vector<HashedItem>::const_iterator begin,
                const vector<HashedItem>::const_iterator end,
                const PSUParams &params,
                coproto::AsioSocket dbsocket
                )
            {
                
                STOPWATCH(recv_stopwatch, "preprocess_unlabeled_data");
                APSU_LOG_DEBUG(
                    "Start preprocessing " << distance(begin, end) << " unlabeled items");

                // Some variables we'll need
                size_t bins_per_item = params.item_params().felts_per_item;
                size_t item_bit_count = params.item_bit_count();

                // Set up Kuku hash functions
                auto hash_funcs = hash_functions(params);
                vector<vector<HashedItem>> oprf_in(params.table_params().table_size);
                
                // Calculate the cuckoo indices for each item. Store every pair of (item-label,
                // cuckoo_idx) in a vector. Later, we're gonna sort this vector by cuckoo_idx and
                // use the result to parallelize the work of inserting the items into BinBundles.
                vector<pair<AlgItem, size_t>> data_with_indices;
                for (auto it = begin; it != end; it++) {
                    const HashedItem &item = *it;

                    // Serialize the data into field elements

                    // AlgItem alg_item =
                    //     algebraize_item(item, item_bit_count, params.seal_params().plain_modulus());
                    // auto size_t max_idx = 0;

                    // Get the cuckoo table locations for this item and add to data_with_indices
                    for (auto location : all_locations(hash_funcs, item)) {
                        // The current hash value is an index into a table of Items. In reality our
                        // BinBundles are tables of bins, which contain chunks of items. How many
                        // chunks? bins_per_item many chunks
                        // size_t bin_idx = location * bins_per_item;
                        oprf_in[location].emplace_back(item);
                        // Store the data along with its index
                        // data_with_indices.emplace_back(make_pair(alg_item, bin_idx));
                    }
                }
                auto oprf_out = oprf_sender(oprf_in,dbsocket);
                size_t hash_table_size = oprf_in.size();
                for(size_t location = 0; location < hash_table_size; location++){
                    size_t bin_idx = location * bins_per_item;
                    // APSU_LOG_INFO(oprf_out[location].size());
                    for(auto item: oprf_out[location]){
                        AlgItem alg_item =
                            algebraize_item(item, item_bit_count, params.seal_params().plain_modulus());
                        data_with_indices.emplace_back(make_pair(alg_item, bin_idx));
                    }

                }

                APSU_LOG_DEBUG(
                    "Finished preprocessing " << distance(begin, end) << " unlabeled items");
                APSU_LOG_INFO("data_with_indices"<<data_with_indices.size());
                return data_with_indices;
            }

            /**
            Converts given Item into its algebraic form, i.e., a sequence of felt-monostate pairs.
            Also computes the Item's cuckoo index.
            */
            vector<pair<AlgItem, size_t>> preprocess_unlabeled_data(
                const HashedItem &item, const PSUParams &params, coproto::AsioSocket dbsocket)
            {
                vector<HashedItem> item_singleton{ item };
                return preprocess_unlabeled_data(
                    item_singleton.begin(), item_singleton.end(), params,dbsocket);
            }

            /**
            Inserts the given items and corresponding labels into bin_bundles at their respective
            cuckoo indices. It will only insert the data with bundle index in the half-open range
            range indicated by work_range. If inserting into a BinBundle would make the number of
            items in a bin larger than max_bin_size, this function will create and insert a new
            BinBundle. If overwrite is set, this will overwrite the labels if it finds an
            AlgItemLabel that matches the input perfectly.
            */
            template <typename T>
            void insert_or_assign_worker(
                const vector<pair<T, size_t>> &data_with_indices,
                vector<vector<BinBundle>> &bin_bundles,
                CryptoContext &crypto_context,
                uint32_t bundle_index,
                uint32_t bins_per_bundle,
                size_t label_size,
                size_t max_bin_size,
                size_t ps_low_degree,
                bool overwrite,
                bool compressed)
            {
                STOPWATCH(recv_stopwatch, "insert_or_assign_worker");
                APSU_LOG_DEBUG(
                    "Insert-or-Assign worker for bundle index "
                    << bundle_index << "; mode of operation: "
                    << (overwrite ? "overwriting existing" : "inserting new"));

                // Iteratively insert each item-label pair at the given cuckoo index
                for (auto &data_with_idx : data_with_indices) {
                    const T &data = data_with_idx.first;

                    // Get the bundle index
                    size_t cuckoo_idx = data_with_idx.second;
                    size_t bin_idx, bundle_idx;
                    tie(bin_idx, bundle_idx) = unpack_cuckoo_idx(cuckoo_idx, bins_per_bundle);

                    // If the bundle_idx isn't in the prescribed range, don't try to insert this
                    // data
                    if (bundle_idx != bundle_index) {
                        // Dealing with this bundle index is not our job
                        continue;
                    }

                    // Get the bundle set at the given bundle index
                    vector<BinBundle> &bundle_set = bin_bundles[bundle_idx];

                    // Try to insert or overwrite these field elements in an existing BinBundle at
                    // this bundle index. Keep track of whether or not we succeed.
                    bool written = false;
                    for (auto bundle_it = bundle_set.rbegin(); bundle_it != bundle_set.rend();
                         bundle_it++) {
                        // If we're supposed to overwrite, try to overwrite. One of these BinBundles
                        // has to have the data we're trying to overwrite.
                        if (overwrite) {
                            // If we successfully overwrote, we're done with this bundle
                            written = bundle_it->try_multi_overwrite(data, bin_idx);
                            if (written) {
                                break;
                            }
                        }

                        // Do a dry-run insertion and see if the new largest bin size in the range
                        // exceeds the limit
                        int32_t new_largest_bin_size =
                            bundle_it->multi_insert_dry_run(data, bin_idx);

                        // Check if inserting would violate the max bin size constraint
                        if (new_largest_bin_size > 0 &&
                            safe_cast<size_t>(new_largest_bin_size) < max_bin_size) {
                            // All good
                            bundle_it->multi_insert_for_real(data, bin_idx);
                            written = true;
                            break;
                        }
                    }

                    // We tried to overwrite an item that doesn't exist. This should never happen
                    if (overwrite && !written) {
                        APSU_LOG_ERROR(
                            "Insert-or-Assign worker: "
                            "failed to overwrite item at bundle index "
                            << bundle_idx
                            << " "
                               "because the item was not found");
                        throw logic_error("tried to overwrite non-existent item");
                    }

                    // If we had conflicts everywhere when trying to insert, then we need to make a
                    // new BinBundle and insert the data there
                    if (!written) {
                        // Make a fresh BinBundle and insert
                        BinBundle new_bin_bundle(
                            crypto_context,
                            label_size,
                            max_bin_size,
                            ps_low_degree,
                            bins_per_bundle,
                            compressed,
                            false);
                        int res = new_bin_bundle.multi_insert_for_real(data, bin_idx);

                        // If even that failed, I don't know what could've happened
                        if (res < 0) {
                            APSU_LOG_ERROR(
                                "Insert-or-Assign worker: "
                                "failed to insert item into a new BinBundle at bundle index "
                                << bundle_idx);
                            throw logic_error("failed to insert item into a new BinBundle");
                        }

                        // Push a new BinBundle to the set of BinBundles at this bundle index
                        bundle_set.push_back(move(new_bin_bundle));
                    }
                }

                APSU_LOG_DEBUG(
                    "Insert-or-Assign worker: finished processing bundle index " << bundle_index);
            }

            /**
            Takes algebraized data to be inserted, splits it up, and distributes it so that
            thread_count many threads can all insert in parallel. If overwrite is set, this will
            overwrite the labels if it finds an AlgItemLabel that matches the input perfectly.
            */
            template <typename T>
            void dispatch_insert_or_assign(
                vector<pair<T, size_t>> &data_with_indices,
                vector<vector<BinBundle>> &bin_bundles,
                CryptoContext &crypto_context,
                uint32_t bins_per_bundle,
                size_t label_size,
                uint32_t max_bin_size,
                uint32_t ps_low_degree,
                bool overwrite,
                bool compressed)
            {
                ThreadPoolMgr tpm;

                // Collect the bundle indices and partition them into thread_count many partitions.
                // By some uniformity assumption, the number of things to insert per partition
                // should be roughly the same. Note that the contents of bundle_indices is always
                // sorted (increasing order).
                set<size_t> bundle_indices_set;
                for (auto &data_with_idx : data_with_indices) {
                    size_t cuckoo_idx = data_with_idx.second;
                    size_t bin_idx, bundle_idx;
                    tie(bin_idx, bundle_idx) = unpack_cuckoo_idx(cuckoo_idx, bins_per_bundle);
                    bundle_indices_set.insert(bundle_idx);
                }

                // Copy the set of indices into a vector and sort so each thread processes a range
                // of indices
                vector<size_t> bundle_indices;
                bundle_indices.reserve(bundle_indices_set.size());
                copy(
                    bundle_indices_set.begin(),
                    bundle_indices_set.end(),
                    back_inserter(bundle_indices));
                sort(bundle_indices.begin(), bundle_indices.end());

                // Run the threads on the partitions
                vector<future<void>> futures(bundle_indices.size());
                APSU_LOG_INFO(
                    "Launching " << bundle_indices.size() << " insert-or-assign worker tasks");
                size_t future_idx = 0;
                for (auto &bundle_idx : bundle_indices) {
                    futures[future_idx++] = tpm.thread_pool().enqueue([&, bundle_idx]() {
                        insert_or_assign_worker(
                            data_with_indices,
                            bin_bundles,
                            crypto_context,
                            static_cast<uint32_t>(bundle_idx),
                            bins_per_bundle,
                            label_size,
                            max_bin_size,
                            ps_low_degree,
                            overwrite,
                            compressed);
                    });
                }

                // Wait for the tasks to finish
                for (auto &f : futures) {
                    f.get();
                }

                APSU_LOG_INFO("Finished insert-or-assign worker tasks");
            }

            /**
            Removes the given items and corresponding labels from bin_bundles at their respective
            cuckoo indices.
            */
            void remove_worker(
                const vector<pair<AlgItem, size_t>> &data_with_indices,
                vector<vector<BinBundle>> &bin_bundles,
                uint32_t bundle_index,
                uint32_t bins_per_bundle)
            {
                STOPWATCH(recv_stopwatch, "remove_worker");
                APSU_LOG_INFO("Remove worker [" << bundle_index << "]");

                // Iteratively remove each item-label pair at the given cuckoo index
                for (auto &data_with_idx : data_with_indices) {
                    // Get the bundle index
                    size_t cuckoo_idx = data_with_idx.second;
                    size_t bin_idx, bundle_idx;
                    tie(bin_idx, bundle_idx) = unpack_cuckoo_idx(cuckoo_idx, bins_per_bundle);

                    // If the bundle_idx isn't in the prescribed range, don't try to remove this
                    // data
                    if (bundle_idx != bundle_index) {
                        // Dealing with this bundle index is not our job
                        continue;
                    }

                    // Get the bundle set at the given bundle index
                    vector<BinBundle> &bundle_set = bin_bundles[bundle_idx];

                    // Try to remove these field elements from an existing BinBundle at this bundle
                    // index. Keep track of whether or not we succeed.
                    bool removed = false;
                    for (BinBundle &bundle : bundle_set) {
                        // If we successfully removed, we're done with this bundle
                        removed = bundle.try_multi_remove(data_with_idx.first, bin_idx);
                        if (removed) {
                            break;
                        }
                    }

                    // We may have produced some empty BinBundles so just remove them all
                    auto rem_it = remove_if(bundle_set.begin(), bundle_set.end(), [](auto &bundle) {
                        return bundle.empty();
                    });
                    bundle_set.erase(rem_it, bundle_set.end());

                    // We tried to remove an item that doesn't exist. This should never happen
                    if (!removed) {
                        APSU_LOG_ERROR(
                            "Remove worker: "
                            "failed to remove item at bundle index "
                            << bundle_idx
                            << " "
                               "because the item was not found");
                        throw logic_error("failed to remove item");
                    }
                }

                APSU_LOG_INFO("Remove worker: finished processing bundle index " << bundle_index);
            }

            /**
            Takes algebraized data to be removed, splits it up, and distributes it so that
            thread_count many threads can all remove in parallel.
            */
            void dispatch_remove(
                const vector<pair<AlgItem, size_t>> &data_with_indices,
                vector<vector<BinBundle>> &bin_bundles,
                uint32_t bins_per_bundle)
            {
                ThreadPoolMgr tpm;

                // Collect the bundle indices and partition them into thread_count many partitions.
                // By some uniformity assumption, the number of things to remove per partition
                // should be roughly the same. Note that the contents of bundle_indices is always
                // sorted (increasing order).
                set<size_t> bundle_indices_set;
                for (auto &data_with_idx : data_with_indices) {
                    size_t cuckoo_idx = data_with_idx.second;
                    size_t bin_idx, bundle_idx;
                    tie(bin_idx, bundle_idx) = unpack_cuckoo_idx(cuckoo_idx, bins_per_bundle);
                    bundle_indices_set.insert(bundle_idx);
                }

                // Copy the set of indices into a vector and sort so each thread processes a range
                // of indices
                vector<size_t> bundle_indices;
                bundle_indices.reserve(bundle_indices_set.size());
                copy(
                    bundle_indices_set.begin(),
                    bundle_indices_set.end(),
                    back_inserter(bundle_indices));
                sort(bundle_indices.begin(), bundle_indices.end());

                // Run the threads on the partitions
                vector<future<void>> futures(bundle_indices.size());
                APSU_LOG_INFO("Launching " << bundle_indices.size() << " remove worker tasks");
                size_t future_idx = 0;
                for (auto &bundle_idx : bundle_indices) {
                    futures[future_idx++] = tpm.thread_pool().enqueue([&]() {
                        remove_worker(
                            data_with_indices,
                            bin_bundles,
                            static_cast<uint32_t>(bundle_idx),
                            bins_per_bundle);
                    });
                }

                // Wait for the tasks to finish
                for (auto &f : futures) {
                    f.get();
                }
            }

            /**
            Returns a set of DB cache references corresponding to the bundles in the given set
            */
            vector<reference_wrapper<const BinBundleCache>> collect_caches(
                vector<BinBundle> &bin_bundles)
            {
                vector<reference_wrapper<const BinBundleCache>> result;
                for (const auto &bundle : bin_bundles) {
                    result.emplace_back(cref(bundle.get_cache()));
                }

                return result;
            }
        } // namespace

        ReceiverDB::ReceiverDB(
            PSUParams params, size_t label_byte_count, size_t nonce_byte_count, bool compressed)
            : params_(params), crypto_context_(params_), label_byte_count_(label_byte_count),
              nonce_byte_count_(label_byte_count_ ? nonce_byte_count : 0), item_count_(0),
              compressed_(compressed)
        {
            // The labels cannot be more than 1 KB.
            if (label_byte_count_ > 1024) {
                APSU_LOG_ERROR(
                    "Requested label byte count " << label_byte_count_
                                                  << " exceeds the maximum (1024)");
                throw invalid_argument("label_byte_count is too large");
            }

            if (nonce_byte_count_ > max_nonce_byte_count) {
                APSU_LOG_ERROR(
                    "Request nonce byte count " << nonce_byte_count_ << " exceeds the maximum ("
                                                << max_nonce_byte_count << ")");
                throw invalid_argument("nonce_byte_count is too large");
            }

            // If the nonce byte count is less than max_nonce_byte_count, print a warning; this is a
            // labeled ReceiverDB but may not be safe to use for arbitrary label changes.
            if (label_byte_count_ && nonce_byte_count_ < max_nonce_byte_count) {
                APSU_LOG_WARNING(
                    "You have instantiated a labeled ReceiverDB instance with a nonce byte count "
                    << nonce_byte_count_ << ", which is less than the safe default value "
                    << max_nonce_byte_count
                    << ". Updating labels for existing items in the ReceiverDB or removing and "
                       "reinserting items with "
                       "different labels may leak information about the labels.");
            }

            // Set the evaluator. This will be used for BatchedPlaintextPolyn::eval.
            crypto_context_.set_evaluator();

            // Reset the ReceiverDB data structures
            clear();
        }

        ReceiverDB::ReceiverDB(
            PSUParams params,
            OPRFKey oprf_key,
            size_t label_byte_count,
            size_t nonce_byte_count,
            bool compressed)
            : ReceiverDB(params, label_byte_count, nonce_byte_count, compressed)
        {
            // Initialize oprf key with the one given to this constructor
            oprf_key_ = move(oprf_key);
        }

        ReceiverDB::ReceiverDB(ReceiverDB &&source)
            : params_(source.params_), crypto_context_(source.crypto_context_),
              label_byte_count_(source.label_byte_count_),
              nonce_byte_count_(source.nonce_byte_count_), item_count_(source.item_count_),
              compressed_(source.compressed_), stripped_(source.stripped_)
        {
            // Lock the source before moving stuff over
            auto lock = source.get_writer_lock();

            hashed_items_ = move(source.hashed_items_);
            bin_bundles_ = move(source.bin_bundles_);
            oprf_key_ = move(source.oprf_key_);
            source.oprf_key_ = OPRFKey();

            // Reset the source data structures
            source.clear_internal();
        }

        ReceiverDB &ReceiverDB::operator=(ReceiverDB &&source)
        {
            // Do nothing if moving to self
            if (&source == this) {
                return *this;
            }

            // Lock the current ReceiverDB
            auto this_lock = get_writer_lock();

            params_ = source.params_;
            crypto_context_ = source.crypto_context_;
            label_byte_count_ = source.label_byte_count_;
            nonce_byte_count_ = source.nonce_byte_count_;
            item_count_ = source.item_count_;
            compressed_ = source.compressed_;
            stripped_ = source.stripped_;

            // Lock the source before moving stuff over
            auto source_lock = source.get_writer_lock();

            hashed_items_ = move(source.hashed_items_);
            bin_bundles_ = move(source.bin_bundles_);
            oprf_key_ = move(source.oprf_key_);
            source.oprf_key_ = OPRFKey();

            // Reset the source data structures
            source.clear_internal();

            return *this;
        }

        size_t ReceiverDB::get_bin_bundle_count(uint32_t bundle_idx) const
        {
            // Lock the database for reading
            auto lock = get_reader_lock();

            return bin_bundles_.at(safe_cast<size_t>(bundle_idx)).size();
        }

        size_t ReceiverDB::get_bin_bundle_count() const
        {
            // Lock the database for reading
            auto lock = get_reader_lock();

            // Compute the total number of BinBundles
            return accumulate(
                bin_bundles_.cbegin(), bin_bundles_.cend(), size_t(0), [&](auto &a, auto &b) {
                    return a + b.size();
                });
        }

        double ReceiverDB::get_packing_rate() const
        {
            // Lock the database for reading
            auto lock = get_reader_lock();

            uint64_t item_count = mul_safe(
                static_cast<uint64_t>(get_item_count()),
                static_cast<uint64_t>(params_.table_params().hash_func_count));
            uint64_t max_item_count = mul_safe(
                static_cast<uint64_t>(get_bin_bundle_count()),
                static_cast<uint64_t>(params_.items_per_bundle()),
                static_cast<uint64_t>(params_.table_params().max_items_per_bin));

            return max_item_count
                       ? static_cast<double>(item_count) / static_cast<double>(max_item_count)
                       : 0.0;
        }

        void ReceiverDB::clear_internal()
        {
            // Assume the ReceiverDB is already locked for writing

            // Clear the set of inserted items
            hashed_items_.clear();
            item_count_ = 0;

            // Clear the BinBundles
            bin_bundles_.clear();
            bin_bundles_.resize(params_.bundle_idx_count());

            // Reset the stripped_ flag
            stripped_ = false;
        }

        void ReceiverDB::clear()
        {
            if (hashed_items_.size()) {
                APSU_LOG_INFO("Removing " << hashed_items_.size() << " items pairs from ReceiverDB");
            }

            // Lock the database for writing
            auto lock = get_writer_lock();

            clear_internal();
        }

        void ReceiverDB::generate_caches()
        {
            STOPWATCH(recv_stopwatch, "ReceiverDB::generate_caches");
            APSU_LOG_INFO("Start generating bin bundle caches");

            for (auto &bundle_idx : bin_bundles_) {
                for (auto &bb : bundle_idx) {
                    bb.regen_cache();
                }
            }

            APSU_LOG_INFO("Finished generating bin bundle caches");
        }

        vector<reference_wrapper<const BinBundleCache>> ReceiverDB::get_cache_at(uint32_t bundle_idx)
        {
            return collect_caches(bin_bundles_.at(safe_cast<size_t>(bundle_idx)));
        }

        OPRFKey ReceiverDB::strip()
        {
            // Lock the database for writing
            auto lock = get_writer_lock();

            stripped_ = true;

            OPRFKey oprf_key_copy = move(oprf_key_);
            oprf_key_.clear();
            hashed_items_.clear();

            ThreadPoolMgr tpm;

            vector<future<void>> futures;
            for (auto &bundle_idx : bin_bundles_) {
                for (auto &bb : bundle_idx) {
                    futures.push_back(tpm.thread_pool().enqueue([&bb]() { bb.strip(); }));
                }
            }

            // Wait for the tasks to finish
            for (auto &f : futures) {
                f.get();
            }

            APSU_LOG_INFO("ReceiverDB has been stripped");

            return oprf_key_copy;
        }

        OPRFKey ReceiverDB::get_oprf_key() const
        {
            if (stripped_) {
                APSU_LOG_ERROR("Cannot return the OPRF key from a stripped ReceiverDB");
                throw logic_error("failed to return OPRF key");
            }
            return oprf_key_;
        }

        void ReceiverDB::insert_or_assign(const vector<pair<Item, Label>> &data)
        {
            if (stripped_) {
                APSU_LOG_ERROR("Cannot insert data to a stripped ReceiverDB");
                throw logic_error("failed to insert data");
            }
            if (!is_labeled()) {
                APSU_LOG_ERROR(
                    "Attempted to insert labeled data but this is an unlabeled ReceiverDB");
                throw logic_error("failed to insert data");
            }

            STOPWATCH(recv_stopwatch, "ReceiverDB::insert_or_assign (labeled)");
            APSU_LOG_INFO("Start inserting " << data.size() << " items in ReceiverDB");

            // First compute the hashes for the input data
            auto hashed_data =
                OPRFSender::ComputeHashes(data, oprf_key_, label_byte_count_, nonce_byte_count_);

            // Lock the database for writing
            auto lock = get_writer_lock();

            // We need to know which items are new and which are old, since we have to tell
            // dispatch_insert_or_assign when to have an overwrite-on-collision versus
            // add-binbundle-on-collision policy.
            auto new_data_end =
                remove_if(hashed_data.begin(), hashed_data.end(), [&](const auto &item_label_pair) {
                    bool found = hashed_items_.find(item_label_pair.first) != hashed_items_.end();
                    if (!found) {
                        // Add to hashed_items_ already at this point!
                        hashed_items_.insert(item_label_pair.first);
                        item_count_++;
                    }

                    // Remove those that were found
                    return found;
                });

            // Dispatch the insertion, first for the new data, then for the data we're gonna
            // overwrite
            uint32_t bins_per_bundle = params_.bins_per_bundle();
            uint32_t max_bin_size = params_.table_params().max_items_per_bin;
            uint32_t ps_low_degree = params_.query_params().ps_low_degree;

            // Compute the label size; this ceil(effective_label_bit_count / item_bit_count)
            size_t label_size = compute_label_size(nonce_byte_count_ + label_byte_count_, params_);

            auto new_item_count = distance(hashed_data.begin(), new_data_end);
            auto existing_item_count = distance(new_data_end, hashed_data.end());

            if (existing_item_count) {
                APSU_LOG_INFO(
                    "Found " << existing_item_count << " existing items to replace in ReceiverDB");

                // Break the data into field element representation. Also compute the items' cuckoo
                // indices.
                vector<pair<AlgItemLabel, size_t>> data_with_indices =
                    preprocess_labeled_data(new_data_end, hashed_data.end(), params_);

                dispatch_insert_or_assign(
                    data_with_indices,
                    bin_bundles_,
                    crypto_context_,
                    bins_per_bundle,
                    label_size,
                    max_bin_size,
                    ps_low_degree,
                    true, /* overwrite items */
                    compressed_);

                // Release memory that is no longer needed
                hashed_data.erase(new_data_end, hashed_data.end());
            }

            if (new_item_count) {
                APSU_LOG_INFO("Found " << new_item_count << " new items to insert in ReceiverDB");

                // Process and add the new data. Break the data into field element representation.
                // Also compute the items' cuckoo indices.
                vector<pair<AlgItemLabel, size_t>> data_with_indices =
                    preprocess_labeled_data(hashed_data.begin(), hashed_data.end(), params_);

                dispatch_insert_or_assign(
                    data_with_indices,
                    bin_bundles_,
                    crypto_context_,
                    bins_per_bundle,
                    label_size,
                    max_bin_size,
                    ps_low_degree,
                    false, /* don't overwrite items */
                    compressed_);
            }

            // Generate the BinBundle caches
            generate_caches();

            APSU_LOG_INFO("Finished inserting " << data.size() << " items in ReceiverDB");
        }

        void ReceiverDB::insert_or_assign(const vector<Item> &data)
        {
            if (stripped_) {
                APSU_LOG_ERROR("Cannot insert data to a stripped ReceiverDB");
                throw logic_error("failed to insert data");
            }
            if (is_labeled()) {
                APSU_LOG_ERROR("Attempted to insert unlabeled data but this is a labeled ReceiverDB");
                throw logic_error("failed to insert data");
            }

            STOPWATCH(recv_stopwatch, "ReceiverDB::insert_or_assign (unlabeled)");
            APSU_LOG_INFO("Start inserting " << data.size() << " items in ReceiverDB");

            // First compute the hashes for the input data
            //auto hashed_data = OPRFReceiver::ComputeHashes(data, oprf_key_);
// TO DO : 
            auto hashed_data = change_hashed_item(data);

            // Lock the database for writing
            auto lock = get_writer_lock();

            // We are not going to insert items that already appear in the database.
            auto new_data_end =
                remove_if(hashed_data.begin(), hashed_data.end(), [&](const auto &item) {
                    bool found = hashed_items_.find(item) != hashed_items_.end();
                    if (!found) {
                        // Add to hashed_items_ already at this point!
                        hashed_items_.insert(item);
                        item_count_++;
                    }

                    // Remove those that were found
                    return found;
                });

            // Erase the previously existing items from hashed_data; in unlabeled case there is
            // nothing to do
            hashed_data.erase(new_data_end, hashed_data.end());

            APSU_LOG_INFO("Found " << hashed_data.size() << " new items to insert in ReceiverDB");

            // Break the new data down into its field element representation. Also compute the
            // items' cuckoo indices.
            if(!hasSocket){
                APSU_LOG_ERROR("SOCKET DOESNT INIT");
            }
            vector<pair<AlgItem, size_t>> data_with_indices =
                preprocess_unlabeled_data(hashed_data.begin(), hashed_data.end(), params_,DBSocket);

            // Dispatch the insertion
            uint32_t bins_per_bundle = params_.bins_per_bundle();
            uint32_t max_bin_size = params_.table_params().max_items_per_bin;
            uint32_t ps_low_degree = params_.query_params().ps_low_degree;

            dispatch_insert_or_assign(
                data_with_indices,
                bin_bundles_,
                crypto_context_,
                bins_per_bundle,
                0, /* label size */
                max_bin_size,
                ps_low_degree,
                false, /* don't overwrite items */
                compressed_);

            // Generate the BinBundle caches
            generate_caches();

            APSU_LOG_INFO("Finished inserting " << data.size() << " items in ReceiverDB");
        }

        void ReceiverDB::remove(const vector<Item> &data)
        {
            if (stripped_) {
                APSU_LOG_ERROR("Cannot remove data from a stripped ReceiverDB");
                throw logic_error("failed to remove data");
            }

            STOPWATCH(recv_stopwatch, "ReceiverDB::remove");
            APSU_LOG_INFO("Start removing " << data.size() << " items from ReceiverDB");

            // First compute the hashes for the input data
           // auto hashed_data = OPRFReceiver::ComputeHashes(data, oprf_key_);
// TO DO : 
            auto hashed_data = change_hashed_item(data);
            // Lock the database for writing
            auto lock = get_writer_lock();

            // Remove items that do not exist in the database.
            auto existing_data_end =
                remove_if(hashed_data.begin(), hashed_data.end(), [&](const auto &item) {
                    bool found = hashed_items_.find(item) != hashed_items_.end();
                    if (found) {
                        // Remove from hashed_items_ already at this point!
                        hashed_items_.erase(item);
                        item_count_--;
                    }

                    // Remove those that were not found
                    return !found;
                });

            // This distance is always non-negative
            size_t existing_item_count =
                static_cast<size_t>(distance(existing_data_end, hashed_data.end()));
            if (existing_item_count) {
                APSU_LOG_WARNING(
                    "Ignoring " << existing_item_count
                                << " items that are not present in the ReceiverDB");
            }

            // Break the data down into its field element representation. Also compute the items'
            // cuckoo indices.
            vector<pair<AlgItem, size_t>> data_with_indices =
                preprocess_unlabeled_data(hashed_data.begin(), hashed_data.end(), params_,DBSocket);

            // Dispatch the removal
            uint32_t bins_per_bundle = params_.bins_per_bundle();
            dispatch_remove(data_with_indices, bin_bundles_, bins_per_bundle);

            // Generate the BinBundle caches
            generate_caches();

            APSU_LOG_INFO("Finished removing " << data.size() << " items from ReceiverDB");
        }

        bool ReceiverDB::has_item(const Item &item) const
        {
            if (stripped_) {
                APSU_LOG_ERROR("Cannot retrieve the presence of an item from a stripped ReceiverDB");
                throw logic_error("failed to retrieve the presence of item");
            }

            // First compute the hash for the input item
           // auto hashed_item = OPRFReceiver::ComputeHashes({ &item, 1 }, oprf_key_)[0];
// TO DO : 
            
            auto hashed_item = change_hashed_item({ &item, 1 })[0];
            // Lock the database for reading
            auto lock = get_reader_lock();

            return hashed_items_.find(hashed_item) != hashed_items_.end();
        }

        Label ReceiverDB::get_label(const Item &item) const
        {
            if (stripped_) {
                APSU_LOG_ERROR("Cannot retrieve a label from a stripped ReceiverDB");
                throw logic_error("failed to retrieve label");
            }
            if (!is_labeled()) {
                APSU_LOG_ERROR("Attempted to retrieve a label but this is an unlabeled ReceiverDB");
                throw logic_error("failed to retrieve label");
            }

            // First compute the hash for the input item
            HashedItem hashed_item;
            LabelKey key;
            tie(hashed_item, key) = OPRFSender::GetItemHash(item, oprf_key_);

            // Lock the database for reading
            auto lock = get_reader_lock();

            // Check if this item is in the DB. If not, throw an exception
            if (hashed_items_.find(hashed_item) == hashed_items_.end()) {
                APSU_LOG_ERROR("Cannot retrieve label for an item that is not in the ReceiverDB");
                throw invalid_argument("failed to retrieve label");
            }

            uint32_t bins_per_bundle = params_.bins_per_bundle();

            // Preprocess a single element. This algebraizes the item and gives back its field
            // element representation as well as its cuckoo hash. We only read one of the locations
            // because the labels are the same in each location.
            AlgItem alg_item;
            size_t cuckoo_idx;
            tie(alg_item, cuckoo_idx) = preprocess_unlabeled_data(hashed_item, params_,DBSocket)[0];

            // Now figure out where to look to get the label
            size_t bin_idx, bundle_idx;
            tie(bin_idx, bundle_idx) = unpack_cuckoo_idx(cuckoo_idx, bins_per_bundle);

            // Retrieve the algebraic labels from one of the BinBundles at this index
            const vector<BinBundle> &bundle_set = bin_bundles_[bundle_idx];
            vector<felt_t> alg_label;
            bool got_labels = false;
            for (const BinBundle &bundle : bundle_set) {
                // Try to retrieve the contiguous labels from this BinBundle
                if (bundle.try_get_multi_label(alg_item, bin_idx, alg_label)) {
                    got_labels = true;
                    break;
                }
            }

            // It shouldn't be possible to have items in your set but be unable to retrieve the
            // associated label. Throw an exception because something is terribly wrong.
            if (!got_labels) {
                APSU_LOG_ERROR(
                    "Failed to retrieve label for an item that was supposed to be in the ReceiverDB");
                throw logic_error("failed to retrieve label");
            }

            // All good. Now just reconstruct the big label from its split-up parts
            EncryptedLabel encrypted_label = dealgebraize_label(
                alg_label,
                alg_label.size() * static_cast<size_t>(params_.item_bit_count_per_felt()),
                params_.seal_params().plain_modulus());

            // Resize down to the effective byte count
            encrypted_label.resize(nonce_byte_count_ + label_byte_count_);

            // Decrypt the label
            return decrypt_label(encrypted_label, key, nonce_byte_count_);
        }

        size_t ReceiverDB::save(ostream &out) const
        {
            // Lock the database for reading
            auto lock = get_reader_lock();

            STOPWATCH(recv_stopwatch, "ReceiverDB::save");
            APSU_LOG_DEBUG("Start saving ReceiverDB");

            // First save the PSUParam
            stringstream ss;
            params_.save(ss);
            string params_str = ss.str();

            flatbuffers::FlatBufferBuilder fbs_builder(1024);

            auto params = fbs_builder.CreateVector(
                reinterpret_cast<const uint8_t *>(&params_str[0]), params_str.size());
            fbs::ReceiverDBInfo info(
                safe_cast<uint32_t>(label_byte_count_),
                safe_cast<uint32_t>(nonce_byte_count_),
                safe_cast<uint32_t>(item_count_),
                compressed_,
                stripped_);
            auto oprf_key_span = oprf_key_.key_span();
            auto oprf_key = fbs_builder.CreateVector(oprf_key_span.data(), oprf_key_span.size());
            auto hashed_items = fbs_builder.CreateVectorOfStructs([&]() {
                // The HashedItems vector is populated with an immediately-invoked lambda
                vector<fbs::HashedItem> ret;
                ret.reserve(get_hashed_items().size());
                for (const auto &it : get_hashed_items()) {
                    // Then create the vector of bytes for this hashed item
                    auto item_data = it.get_as<uint64_t>();
                    ret.emplace_back(item_data[0], item_data[1]);
                }
                return ret;
            }());

            auto bin_bundle_count = get_bin_bundle_count();

            fbs::ReceiverDBBuilder receiver_db_builder(fbs_builder);
            receiver_db_builder.add_params(params);
            receiver_db_builder.add_info(&info);
            receiver_db_builder.add_oprf_key(oprf_key);
            receiver_db_builder.add_hashed_items(hashed_items);
            receiver_db_builder.add_bin_bundle_count(safe_cast<uint32_t>(bin_bundle_count));
            auto sdb = receiver_db_builder.Finish();
            fbs_builder.FinishSizePrefixed(sdb);

            out.write(
                reinterpret_cast<const char *>(fbs_builder.GetBufferPointer()),
                safe_cast<streamsize>(fbs_builder.GetSize()));
            size_t total_size = fbs_builder.GetSize();

            // Finally write the BinBundles
            size_t bin_bundle_data_size = 0;
            for (size_t bundle_idx = 0; bundle_idx < bin_bundles_.size(); bundle_idx++) {
                for (auto &bb : bin_bundles_[bundle_idx]) {
                    auto size = bb.save(out, static_cast<uint32_t>(bundle_idx));
                    APSU_LOG_DEBUG(
                        "Saved BinBundle at bundle index " << bundle_idx << " (" << size
                                                           << " bytes)");
                    bin_bundle_data_size += size;
                }
            }

            total_size += bin_bundle_data_size;
            APSU_LOG_DEBUG(
                "Saved ReceiverDB with " << get_item_count() << " items (" << total_size
                                       << " bytes)");

            APSU_LOG_DEBUG("Finished saving ReceiverDB");

            return total_size;
        }

        pair<ReceiverDB, size_t> ReceiverDB::Load(istream &in)
        {
            STOPWATCH(recv_stopwatch, "ReceiverDB::Load");
            APSU_LOG_DEBUG("Start loading ReceiverDB");

            vector<unsigned char> in_data(apsu::util::read_from_stream(in));

            auto verifier = flatbuffers::Verifier(
                reinterpret_cast<const uint8_t *>(in_data.data()), in_data.size());
            bool safe = fbs::VerifySizePrefixedReceiverDBBuffer(verifier);
            if (!safe) {
                APSU_LOG_ERROR("Failed to load ReceiverDB: the buffer is invalid");
                throw runtime_error("failed to load ReceiverDB");
            }

            auto sdb = fbs::GetSizePrefixedReceiverDB(in_data.data());

            // Load the PSUParams; this will automatically check version compatibility
            unique_ptr<PSUParams> params;
            try {
                ArrayGetBuffer agbuf(
                    reinterpret_cast<const char *>(sdb->params()->data()),
                    static_cast<streamsize>(sdb->params()->size()));
                istream params_stream(&agbuf);
                params = make_unique<PSUParams>(PSUParams::Load(params_stream).first);
            } catch (const runtime_error &ex) {
                APSU_LOG_ERROR("APSU threw an exception creating PSUParams: " << ex.what());
                throw runtime_error("failed to load ReceiverDB");
            }

            // Load the info so we know what kind of ReceiverDB to create
            size_t item_count = static_cast<size_t>(sdb->info()->item_count());
            size_t label_byte_count = static_cast<size_t>(sdb->info()->label_byte_count());
            size_t nonce_byte_count = static_cast<size_t>(sdb->info()->nonce_byte_count());

            bool compressed = sdb->info()->compressed();
            bool stripped = sdb->info()->stripped();

            APSU_LOG_DEBUG(
                "Loaded ReceiverDB properties: "
                "item_count: "
                << item_count
                << "; "
                   "label_byte_count: "
                << label_byte_count
                << "; "
                   "nonce_byte_count: "
                << nonce_byte_count
                << "; "
                   "compressed: "
                << boolalpha << compressed
                << "; "
                   "stripped: "
                << boolalpha << stripped);

            // Create the correct kind of ReceiverDB
            unique_ptr<ReceiverDB> receiver_db;
            try {
                receiver_db =
                    make_unique<ReceiverDB>(*params, label_byte_count, nonce_byte_count, compressed);
                receiver_db->stripped_ = stripped;
                receiver_db->item_count_ = item_count;
            } catch (const invalid_argument &ex) {
                APSU_LOG_ERROR("APSU threw an exception creating ReceiverDB: " << ex.what());
                throw runtime_error("failed to load ReceiverDB");
            }

            // Check that the OPRF key size is correct
            size_t oprf_key_size = sdb->oprf_key()->size();
            if (oprf_key_size != oprf_key_size) {
                APSU_LOG_ERROR(
                    "The loaded OPRF key has invalid size (" << oprf_key_size << " bytes; expected "
                                                             << oprf_key_size << " bytes)");
                throw runtime_error("failed to load ReceiverDB");
            }

            // Copy over the OPRF key
            receiver_db->oprf_key_.load(oprf_key_span_const_type(
                reinterpret_cast<const unsigned char *>(sdb->oprf_key()->data()), oprf_key_size));

            // Load the hashed items if this ReceiverDB is not stripped
            if (!stripped) {
                const auto &hashed_items = *sdb->hashed_items();
                receiver_db->hashed_items_.reserve(hashed_items.size());
                for (const auto &it : hashed_items) {
                    receiver_db->hashed_items_.insert({ it->low_word(), it->high_word() });
                }

                // Check that item_count matches the number of hashed items
                if (item_count != hashed_items.size()) {
                    APSU_LOG_ERROR(
                        "The item count indicated in the loaded ReceiverDB ("
                        << item_count << ") does not match the size of the loaded data ("
                        << hashed_items.size() << ")");
                    throw runtime_error("failed to load ReceiverDB");
                }
            }

            uint32_t bin_bundle_count = sdb->bin_bundle_count();
            size_t bin_bundle_data_size = 0;
            uint32_t max_bin_size = params->table_params().max_items_per_bin;
            uint32_t ps_low_degree = params->query_params().ps_low_degree;
            uint32_t bins_per_bundle = params->bins_per_bundle();
            size_t label_size = compute_label_size(nonce_byte_count + label_byte_count, *params);

            // Load all BinBundle data
            vector<vector<unsigned char>> bin_bundle_data;
            bin_bundle_data.reserve(bin_bundle_count);
            while (bin_bundle_count--) {
                bin_bundle_data.push_back(read_from_stream(in));
            }

            // Use multiple threads to recreate the BinBundles
            ThreadPoolMgr tpm;

            vector<mutex> bundle_idx_mtxs(receiver_db->bin_bundles_.size());
            mutex bin_bundle_data_size_mtx;
            vector<future<void>> futures;
            for (size_t i = 0; i < bin_bundle_data.size(); i++) {
                futures.push_back(tpm.thread_pool().enqueue([&, i]() {
                    BinBundle bb(
                        receiver_db->crypto_context_,
                        label_size,
                        max_bin_size,
                        ps_low_degree,
                        bins_per_bundle,
                        compressed,
                        stripped);
                    auto bb_data = bb.load(bin_bundle_data[i]);

                    // Clear the data buffer since we have now loaded the BinBundle
                    bin_bundle_data[i].clear();

                    // Check that the loaded bundle index is not out of range
                    if (bb_data.first >= receiver_db->bin_bundles_.size()) {
                        APSU_LOG_ERROR(
                            "The bundle index of the loaded BinBundle ("
                            << bb_data.first << ") exceeds the maximum ("
                            << params->bundle_idx_count() - 1 << ")");
                        throw runtime_error("failed to load ReceiverDB");
                    }

                    // Add the loaded BinBundle to the correct location in bin_bundles_
                    bundle_idx_mtxs[bb_data.first].lock();
                    receiver_db->bin_bundles_[bb_data.first].push_back(move(bb));
                    bundle_idx_mtxs[bb_data.first].unlock();

                    APSU_LOG_DEBUG(
                        "Loaded BinBundle at bundle index " << bb_data.first << " ("
                                                            << bb_data.second << " bytes)");

                    lock_guard<mutex> bin_bundle_data_size_lock(bin_bundle_data_size_mtx);
                    bin_bundle_data_size += bb_data.second;
                }));
            }

            // Wait for the tasks to finish
            for (auto &f : futures) {
                f.get();
            }

            size_t total_size = in_data.size() + bin_bundle_data_size;
            APSU_LOG_DEBUG(
                "Loaded ReceiverDB with " << receiver_db->get_item_count() << " items (" << total_size
                                        << " bytes)");

            // Make sure the BinBundle caches are valid
            receiver_db->generate_caches();

            APSU_LOG_DEBUG("Finished loading ReceiverDB");

            return { move(*receiver_db), total_size };
        }

        vector<HashedItem> ReceiverDB::change_hashed_item(const gsl::span<const Item> &origin_item) const {
            STOPWATCH(recv_stopwatch, "Receiverdb::ComputeHashes (unlabeled)");
            APSU_LOG_DEBUG("Start computing OPRF hashes for " << origin_item.size() << " items");

            ThreadPoolMgr tpm;
            vector<HashedItem> hashes(origin_item.size());
            size_t task_count = min<size_t>(ThreadPoolMgr::GetThreadCount(), origin_item.size());
            vector<future<void>> futures(task_count);

            auto ComputeHashesLambda = [&](size_t start_idx, size_t step) {
                for (size_t idx = start_idx; idx < origin_item.size(); idx += step) {
                    hashes[idx] = HashedItem{origin_item[idx].get_as<uint64_t>()[0],origin_item[idx].get_as<uint64_t>()[1]};
                }
            };
            for (size_t thread_idx = 0; thread_idx < task_count; thread_idx++) {
                futures[thread_idx] =
                    tpm.thread_pool().enqueue(ComputeHashesLambda, thread_idx, task_count);
            }
            for (auto &f : futures) {
                f.get();
            }
            APSU_LOG_DEBUG("Finished computing OPRF hashes for " << origin_item.size() << " items");
            return hashes;
        }



    } // namespace receiver
} // namespace apsu
