// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

// STD
#include <csignal>
#include <fstream>
#include <functional>
#include <iostream>
#include <string>
#if defined(__GNUC__) && (__GNUC__ < 8) && !defined(__clang__)
#include <experimental/filesystem>
#else
#include <filesystem>
#endif

// APSU
#include "apsu/log.h"
#include "apsu/oprf/oprf_sender.h"
#include "apsu/thread_pool_mgr.h"
#include "apsu/version.h"
#include "common/common_utils.h"
#include "common/csv_reader.h"
#include "receiver/clp.h"
#include "receiver/receiver_utils.h"
#include "Kunlun/crypto/setup.hpp"

#ifdef __OSN__
#include "apsu/zmq/receiver_dispatcher_osn.h"
#else
#include "apsu/zmq/receiver_dispatcher_ddh.h"
#endif

using namespace std;
#if defined(__GNUC__) && (__GNUC__ < 8) && !defined(__clang__)
namespace fs = std::experimental::filesystem;
#else
namespace fs = std::filesystem;
#endif
using namespace apsu;
using namespace apsu::receiver;
using namespace apsu::network;
using namespace apsu::oprf;


int start_receiver(const CLP &cmd);

unique_ptr<CSVReader::DBData> load_db(const string &db_file);

shared_ptr<ReceiverDB> create_receiver_db(
    const CSVReader::DBData &db_data,
    unique_ptr<PSUParams> psu_params,
    size_t nonce_byte_count,
    bool compress,
    coproto::AsioSocket ReceiverSocket
    );

int main(int argc, char *argv[])
{

    prepare_console();
    CLP cmd("Example of a Receiver implementation", APSU_VERSION);
    if (!cmd.parse_args(argc, argv)) {
        APSU_LOG_ERROR("Failed parsing command line arguments");
        return -1;
    }

    return start_receiver(cmd);
}

void sigint_handler(int param [[maybe_unused]])
{
    APSU_LOG_WARNING("Receiver interrupted");
    exit(0);
}

shared_ptr<ReceiverDB> try_load_receiver_db(const CLP &cmd)
{
    shared_ptr<ReceiverDB> result = nullptr;

    ifstream fs(cmd.db_file(), ios::binary);
    fs.exceptions(ios_base::badbit | ios_base::failbit);
    try {
        auto [data, size] = ReceiverDB::Load(fs);
        APSU_LOG_INFO("Loaded ReceiverDB (" << size << " bytes) from " << cmd.db_file());
        if (!cmd.params_file().empty()) {
            APSU_LOG_WARNING(
                "PSU parameters were loaded with the ReceiverDB; ignoring given PSU parameters");
        }
        result = make_shared<ReceiverDB>(move(data));

        // Load also the OPRF key
        //oprf_key.load(fs);
        //APSU_LOG_INFO("Loaded OPRF key (" << oprf_key_size << " bytes) from " << cmd.db_file());
    } catch (const exception &e) {
        // Failed to load ReceiverDB
        APSU_LOG_DEBUG("Failed to load ReceiverDB: " << e.what());
    }

    return result;
}

shared_ptr<ReceiverDB> try_load_csv_db(const CLP &cmd,coproto::AsioSocket receiversocket)
{
    unique_ptr<PSUParams> params = build_psu_params(cmd);
    if (!params) {
        // We must have valid parameters given
        APSU_LOG_ERROR("Failed to set PSU parameters");
        return nullptr;
    }

    unique_ptr<CSVReader::DBData> db_data;
    if (cmd.db_file().empty() || !(db_data = load_db(cmd.db_file()))) {
        // Failed to read db file
        APSU_LOG_DEBUG("Failed to load data from a CSV file");
        return nullptr;
    }

    return create_receiver_db( *db_data, move(params), cmd.nonce_byte_count(), cmd.compress(),receiversocket);
}

bool try_save_receiver_db(const CLP &cmd, shared_ptr<ReceiverDB> receiver_db)
{
    if (!receiver_db) {
        return false;
    }

    ofstream fs(cmd.sdb_out_file(), ios::binary);
    fs.exceptions(ios_base::badbit | ios_base::failbit);
    try {
        size_t size = receiver_db->save(fs);
        APSU_LOG_INFO("Saved ReceiverDB (" << size << " bytes) to " << cmd.sdb_out_file());

        // Save also the OPRF key (fixed size: oprf_key_size bytes)
    
        APSU_LOG_INFO("Saved OPRF key (" << oprf_key_size << " bytes) to " << cmd.sdb_out_file());

    } catch (const exception &e) {
        APSU_LOG_WARNING("Failed to save ReceiverDB: " << e.what());
        return false;
    }



    return true;
}

int start_receiver(const CLP &cmd)
{
    auto start_time = std::chrono::steady_clock::now();
    APSU_LOG_INFO(__FILE__ << __LINE__);
    auto ReceiverKKRTSocket = coproto::asioConnect("localhost:1212",true);



    ThreadPoolMgr::SetThreadCount(cmd.threads());
    APSU_LOG_INFO("Setting thread count to " << ThreadPoolMgr::GetThreadCount());
    signal(SIGINT, sigint_handler);

    // Check that the database file is valid
    throw_if_file_invalid(cmd.db_file());

    // Try loading first as a ReceiverDB, then as a CSV file
    shared_ptr<ReceiverDB> receiver_db;
    // receiver_db->setSocket(ReceiverSocket);
    //  OPRFKey oprf_key;
    if (!(receiver_db = try_load_csv_db(cmd,ReceiverKKRTSocket))) {
        APSU_LOG_ERROR("Failed to create ReceiverDB: terminating");
        return -1;
    }

    // Print the total number of bin bundles and the largest number of bin bundles for any bundle
    // index
    uint32_t max_bin_bundles_per_bundle_idx = 0;
    for (uint32_t bundle_idx = 0; bundle_idx < receiver_db->get_params().bundle_idx_count();
         bundle_idx++) {
        max_bin_bundles_per_bundle_idx =
            max(max_bin_bundles_per_bundle_idx,
                static_cast<uint32_t>(receiver_db->get_bin_bundle_count(bundle_idx)));
    }
    APSU_LOG_INFO(
        "ReceiverDB holds a total of " << receiver_db->get_bin_bundle_count() << " bin bundles across "
                                     << receiver_db->get_params().bundle_idx_count()
                                     << " bundle indices");
    APSU_LOG_INFO(
        "The largest bundle index holds " << max_bin_bundles_per_bundle_idx << " bin bundles");



    // Run the dispatcher
    atomic<bool> stop = false;
    Receiver receiver;
    receiver.setSocket(ReceiverKKRTSocket);
#if ARBITARY == 0 
#else
    receiver.set_item_len(cmd.item_byte_count());
#endif
    ZMQReceiverDispatcher dispatcher(receiver_db, receiver);


    // The dispatcher will run until stopped.
    dispatcher.run(stop, cmd.net_port());

    auto end_time = std::chrono::steady_clock::now();
    auto running_time = end_time-start_time;
    std::cout<<"\n\n\n\n receiver all time"<<std::chrono::duration<double,std::milli> (running_time).count()<<std::endl<<std::endl<<std::endl;
    print_timing_report(recv_stopwatch);
    ReceiverKKRTSocket.close();
    APSU_LOG_INFO(__LINE__);
    return 0;
}

unique_ptr<CSVReader::DBData> load_db(const string &db_file)
{
    CSVReader::DBData db_data;
    try {
        CSVReader reader(db_file);
        tie(db_data, ignore) = reader.read();
    } catch (const exception &ex) {
        APSU_LOG_WARNING("Could not open or read file `" << db_file << "`: " << ex.what());
        return nullptr;
    }

    return make_unique<CSVReader::DBData>(move(db_data));
}

shared_ptr<ReceiverDB> create_receiver_db(
    const CSVReader::DBData &db_data,
    unique_ptr<PSUParams> psu_params,
    size_t nonce_byte_count,
    bool compress,
    coproto::AsioSocket ReceiverSocket
    )
{
    if (!psu_params) {
        APSU_LOG_ERROR("No PSU parameters were given");
        return nullptr;
    }

    shared_ptr<ReceiverDB> receiver_db;
    if (holds_alternative<CSVReader::UnlabeledData>(db_data)) {
        try {
            receiver_db = make_shared<ReceiverDB>(*psu_params, 0, 0, compress);
            receiver_db->setSocket(ReceiverSocket);
            receiver_db->set_data(get<CSVReader::UnlabeledData>(db_data));

            APSU_LOG_INFO(
                "Created unlabeled ReceiverDB with " << receiver_db->get_item_count() << " items");
        } catch (const exception &ex) {
            APSU_LOG_ERROR("Failed to create ReceiverDB: " << ex.what());
            return nullptr;
        }
    }  else {
        // Should never reach this point
        APSU_LOG_ERROR("Loaded database is in an invalid state");
        return nullptr;
    }

    if (compress) {
        APSU_LOG_INFO("Using in-memory compression to reduce memory footprint");
    }

    // Read the OPRFKey and strip the ReceiverDB to reduce memory use
    receiver_db->strip();

    APSU_LOG_INFO("ReceiverDB packing rate: " << receiver_db->get_packing_rate());

    return receiver_db;
}
