#include "apsu_OSNSender.h"
#include "libOTe/Base/BaseOT.h"
#include "cryptoTools/Common/BitVector.h"
#include <cryptoTools/Crypto/AES.h>
#include <libOTe/TwoChooseOne/Silent/SilentOtExtReceiver.h>
#include "libOTe/TwoChooseOne/Iknp/IknpOtExtReceiver.h"
#include "apsu_benes.h"
#include <iterator>

using namespace std;
using namespace osuCrypto;

std::vector<std::array<osuCrypto::block, 2>> OSNSender::gen_benes_server_osn(int values,oc::Socket chl,NetIO& SendChl)
{
	osuCrypto::BitVector switches = benes.return_gen_benes_switches(values);

	std::vector<std::array<osuCrypto::block, 2>> recvMsg(switches.size());
	std::vector<std::array<osuCrypto::block, 2>> recvCorr(switches.size());
	if (ot_type == OT_type::Silent_OT)
	{
		std::vector<osuCrypto::block> tmpMsg(switches.size());
		osuCrypto::BitVector choices(switches.size());

		silent_ot_recv(choices, tmpMsg, chl);
		oc::AES aes(ZeroBlock);

		for (auto i = 0; i < recvMsg.size(); i++)
		{
			recvMsg[i] = { tmpMsg[i], aes.ecbEncBlock(tmpMsg[i]) };
		}
		osuCrypto::BitVector bit_correction = switches ^ choices;
		chl.send(bit_correction);
	}
	if(OT_type::RandOT == ot_type)
	{
		std::vector<osuCrypto::block> tmpMsg(switches.size());
		rand_ot_recv(switches, tmpMsg, chl);
		oc::AES aes(ZeroBlock);
		for (auto i = 0; i < recvMsg.size(); i++)
			recvMsg[i] = { tmpMsg[i], aes.ecbEncBlock(tmpMsg[i]) };
	}
	if(OT_type::KunlunOT == ot_type){
		std::vector<osuCrypto::block> tmpMsg(switches.size());
		apsu::KunlunOT::IKNP_KL_RandomReceiver(SendChl,switches,tmpMsg,thread_num);
		oc::AES aes(ZeroBlock);
		for (auto i = 0; i < recvMsg.size(); i++)
			recvMsg[i] = { tmpMsg[i], aes.ecbEncBlock(tmpMsg[i]) };

	}
	
	// cp::sync_wait(chl.recv(recvCorr));
	SendChl.ReceiveBits((uint8_t*)recvCorr.data(),recvCorr.size()*2*sizeof(oc::block));
	// for(auto ar : recvCorr){
	// 	std::cout << hex << ar[0].get<uint64_t>()[0] << ' ' <<ar[0].get<uint64_t>()[1] << std::endl;
	// 	std::cout << hex << ar[1].get<uint64_t>()[0] << ' ' <<ar[1].get<uint64_t>()[1] << std::endl;

	// }
	oc::block temp_msg[2], temp_corr[2];
	for (int i = 0; i < recvMsg.size(); i++)
	{
		if (switches[i] == 1)
		{
			temp_msg[0] = recvCorr[i][0] ^ recvMsg[i][0];
			temp_msg[1] = recvCorr[i][1] ^ recvMsg[i][1];
			recvMsg[i] = { temp_msg[0], temp_msg[1] };
		}
	}
	return recvMsg;
}

std::vector<oc::block> OSNSender::run_osn(oc::Socket chl,NetIO& SendChl)
{
	int values = size;
	int N = int(ceil(log2(values)));
	int levels = 2 * N - 1;

	std::vector<std::array<osuCrypto::block, 2>> ot_output = gen_benes_server_osn(values, chl,SendChl);

	std::vector<oc::block> input_vec(values);
	// chl.recv(input_vec);

	SendChl.ReceiveBits((uint8_t*)input_vec.data(),values*sizeof(oc::block));
	// for(auto x : input_vec){
	// 	std::cout << hex << x.get<uint64_t>().data()[0] << ' ' << x.get<uint64_t>().data()[1] << std::endl;
	// }
	std::cout <<__FILE__ << __LINE__ << std::endl;
	std::vector<std::vector<std::array<osuCrypto::block, 2>>> matrix_ot_output(
		levels, std::vector<std::array<osuCrypto::block, 2>>(values));
	int ctr = 0;
	for (int i = 0; i < levels; ++i)
	{
		for (int j = 0; j < values / 2; ++j)
			matrix_ot_output[i][j] = ot_output[ctr++];
	}

	benes.gen_benes_masked_evaluate(N, 0, 0, input_vec, matrix_ot_output);
	return input_vec; //share
}

void OSNSender::setTimer(Timer& timer)
{
	this->timer = &timer;
}

void OSNSender::silent_ot_recv(osuCrypto::BitVector& choices,
	std::vector<osuCrypto::block>& recvMsg,
	oc::Socket chl)
{
	//std::cout << "\n Silent OT receiver!!\n";

	size_t total_len = choices.size();
	vector<BitVector> tmpChoices(thread_num);
	auto routine = [&](size_t tid)
	{
		size_t start_idx = total_len * tid / thread_num;
		size_t end_idx = total_len * (tid + 1) / thread_num;
		end_idx = ((end_idx <= total_len) ? end_idx : total_len);
		size_t size = end_idx - start_idx;

		osuCrypto::PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
		osuCrypto::u64 numOTs = size;

		osuCrypto::SilentOtExtReceiver recv;
		recv.configure(numOTs);

		tmpChoices[tid].copy(choices, start_idx, size);
		std::vector<oc::block> tmpMsg(size);
		recv.silentReceive(tmpChoices[tid], tmpMsg, prng0, chl);

		std::copy_n(tmpMsg.begin(), size, recvMsg.begin() + start_idx);
	};
	vector<thread> thrds(thread_num);
	for (size_t t = 0; t < thread_num; t++)
		thrds[t] = std::thread(routine, t);
	for (size_t t = 0; t < thread_num; t++)
		thrds[t].join();
	choices.resize(0);
	for (size_t t = 0; t < thread_num; t++)
		choices.append(tmpChoices[t]);

	/*osuCrypto::PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
	osuCrypto::u64 numOTs = choices.size();

	osuCrypto::SilentOtExtReceiver recv;
	recv.configure(numOTs, 2, num_threads);

	recv.silentReceive(choices, recvMsg, prng0, chls[0]);*/
}

void OSNSender::rand_ot_recv(osuCrypto::BitVector& choices,
	std::vector<osuCrypto::block>& recvMsg,
	oc::Socket chl)
{
	//std::cout << "\n Ot receiver!!\n";

	size_t total_len = choices.size();
	vector<BitVector> tmpChoices(thread_num);

	auto routine = [&](size_t tid)
	{

		size_t start_idx = total_len * tid / thread_num;
		size_t end_idx = total_len * (tid + 1) / thread_num;
		end_idx = ((end_idx <= total_len) ? end_idx : total_len);
		size_t size = end_idx - start_idx;

		osuCrypto::PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
		osuCrypto::u64 numOTs = size; // input.length();
		std::vector<osuCrypto::block> baseRecv(128);
		std::vector<std::array<osuCrypto::block, 2>> baseSend(128);
		osuCrypto::BitVector baseChoice(128);

		prng0.get((osuCrypto::u8*)baseSend.data()->data(), sizeof(osuCrypto::block) * 2 * baseSend.size());

		osuCrypto::DefaultBaseOT baseOTs;
		cp::sync_wait(baseOTs.send(baseSend, prng0, chl));

		osuCrypto::IknpOtExtReceiver recv;
		recv.setBaseOts(baseSend);

		tmpChoices[tid].copy(choices, start_idx, size);
		std::vector<oc::block> tmpMsg(size);

		cp::sync_wait(recv.receive(tmpChoices[tid], tmpMsg, prng0, chl));
		std::copy_n(tmpMsg.begin(), size, recvMsg.begin() + start_idx);
	};
	vector<thread> thrds(thread_num);
	for (size_t t = 0; t < thread_num; t++)
		thrds[t] = std::thread(routine, t);
	for (size_t t = 0; t < thread_num; t++)
		thrds[t].join();
	choices.resize(0);
	for (size_t t = 0; t < thread_num; t++)
		choices.append(tmpChoices[t]);

	/*osuCrypto::PRNG prng0(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
	osuCrypto::u64 numOTs = choices.size(); // input.length();
	std::vector<osuCrypto::block> baseRecv(128);
	std::vector<std::array<osuCrypto::block, 2>> baseSend(128);
	osuCrypto::BitVector baseChoice(128);

	prng0.get((osuCrypto::u8*)baseSend.data()->data(), sizeof(osuCrypto::block) * 2 * baseSend.size());

	osuCrypto::DefaultBaseOT baseOTs;
	baseOTs.send(baseSend, prng0, chls[0], num_threads);

	osuCrypto::IknpOtExtReceiver recv;
	recv.setBaseOts(baseSend);

	recv.receive(choices, recvMsg, prng0, chls[0]);*/
}

OSNSender::OSNSender(size_t size, OT_type ot_type) : size(size), ot_type(ot_type)
{

}

void OSNSender::init(size_t Row_num, size_t Col_num, OT_type ot_type,size_t threads ,const string& osn_cache)
{
	this->size = Row_num * Col_num ;
	this->ot_type = ot_type;

	int values = size;
	
	int N = int(ceil(log2(values)));
	int levels = 2 * N - 1;

	dest.resize(size);
	cols_premutation.resize(Col_num);
	rows_permutation.resize(Row_num);
	thread_num = threads;
	benes.initialize(values, levels);

	std::vector<int> src(values);
	


	for(int i = 0;i<Col_num;i++){
		cols_premutation[i] = i;
	}
	for(int j = 0;j<Row_num;j++){
		rows_permutation[j] = j;
	}
	// random seed
	//std::srand(std::time(NULL));
	//random()
	std::random_shuffle(cols_premutation.begin(),cols_premutation.end());
	std::random_shuffle(rows_permutation.begin(),rows_permutation.end());

	for (int i = 0; i < Row_num; ++i){
		for(int j = 0;j < Col_num;j++){
			src[i*Col_num+j]  = i*Col_num+j;
			dest[i*Col_num+j] = rows_permutation[i]*Col_num + cols_premutation[j];
		}
	}
		
	if (osn_cache != "")
	{
		string file = osn_cache + "_" + to_string(size);
		if (!benes.load(file))
		{
			cout << "OSNSender is generating osn cache!" << endl;
			benes.gen_benes_route(N, 0, 0, src, dest);
			benes.dump(file);
		}
		else 
		{
			cout << "OSNSender is using osn cache!" << endl;
		}
	}
	else 
	{
		benes.gen_benes_route(N, 0, 0, src, dest);
	}
	

}
