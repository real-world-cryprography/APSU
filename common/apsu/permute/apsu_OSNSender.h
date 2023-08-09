#pragma once

#include <vector>
#include <string>
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Network/Channel.h"
#include "libOTe/Tools/Coproto.h"
#include "apsu_benes.h"
#include "apsu/ot/kunlun_ot.h"
class OSNSender
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

	Benes benes;
	void silent_ot_recv(osuCrypto::BitVector& choices,
		std::vector<osuCrypto::block>& recvMsg,
		oc::Socket chl);
	void rand_ot_recv(osuCrypto::BitVector& choices,
		std::vector<osuCrypto::block>& recvMsg,
		oc::Socket chl);
	std::vector<std::array<osuCrypto::block, 2>> gen_benes_server_osn(int values,oc::Socket chl,NetIO& SendChl);
 public:
	std::vector<int> dest;
	std::vector<int> rows_permutation;
	std::vector<int> cols_premutation;
	OSNSender(size_t size = 0, OT_type ot_type = Silent_OT);
	void init(size_t Row_num,size_t Col_num, OT_type ot_type = Silent_OT, size_t threads=1, const std::string& osn_cache = "");
	std::vector<oc::block> run_osn(oc::Socket chl,NetIO& SendChl);
	void setTimer(oc::Timer& timer);
};

