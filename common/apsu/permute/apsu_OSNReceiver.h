#pragma once

#include <vector>
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Network/Channel.h"
#include "libOTe/Tools/Coproto.h"
#include <atomic>
#include "apsu/ot/kunlun_ot.h"

class OSNReceiver
{
public:
	enum OT_type{
		Silent_OT,
		RandOT,
		KunlunOT
	};
private:
	size_t size;
	size_t thread_num;
	OT_type ot_type;
	oc::Timer* timer;
	std::atomic<int> cpus;

	void rand_ot_send(std::vector<std::array<osuCrypto::block, 2>>& sendMsg, oc::Socket chl);
	void silent_ot_send(std::vector<std::array<osuCrypto::block, 2>>& sendMsg, oc::Socket chl);
	void Kunlun_ot_send(std::vector<std::array<oc::block, 2>>& sendMsg);
	std::vector<std::vector<oc::block>> gen_benes_client_osn(int values, oc::Socket chls, NetIO& RecvChl);
	void prepare_correction(int n, int Val, int lvl_p, int perm_idx, std::vector<oc::block>& src,
		std::vector<std::array<std::array<osuCrypto::block, 2>, 2>>& ot_output,
		std::vector<std::array<osuCrypto::block, 2>>& correction_blocks);
 public:


	OSNReceiver(size_t size = 0, OT_type ot_type = Silent_OT);
	void init(size_t size, OT_type ot_type = Silent_OT, size_t threads = 1);
	std::vector<oc::block> run_osn(std::vector<oc::block> inputs,oc::Socket chl, NetIO& RecvChl);
	void setTimer(oc::Timer& timer);
};

