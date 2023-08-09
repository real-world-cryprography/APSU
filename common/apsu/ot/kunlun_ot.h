#pragma once
#include "Kunlun/mpc/ot/iknp_ote.hpp"
#include <vector>
#include <array>
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Common/BitVector.h"
namespace apsu{
#define OUTPUTTOFILE

	namespace KunlunOT{
		void IKNP_KL_RandomSender(NetIO& chl,std::vector<std::array<osuCrypto::block, 2>>& sendMsg,size_t thread_num = 1);
		void IKNP_KL_RandomReceiver(NetIO& chl,osuCrypto::BitVector& choices,
			std::vector<osuCrypto::block>& recvMsg,size_t thread_num = 1);
		void IKNP_KL_ChosenSender(NetIO& chl,std::vector<std::array<oc::block, 2>> Messages);
		void IKNP_KL_ChosenReceiver(NetIO& chl,std::vector<block>& DiffSet,size_t BlockNum,std::vector<size_t> choicesVec);
	}
}