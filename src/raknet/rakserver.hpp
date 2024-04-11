#pragma once

#include "../main.hpp"

#ifdef _WIN32
	#define SEND_FUNC_IDX 7
	#define RPC_FUNC_IDX 32
	#define PLAYERID_FROM_IDX_FUNC_IDX 58
	#define DEALLOCATE_PKT_FUNC_IDX 12
	#define RECEIVE_FUNC_IDX 10
#else
	#define SEND_FUNC_IDX 9
	#define RPC_FUNC_IDX 35
	#define PLAYERID_FROM_IDX_FUNC_IDX 59
	#define DEALLOCATE_PKT_FUNC_IDX 13
	#define RECEIVE_FUNC_IDX 11
#endif

class rakserver
{
	urmem::address_t _rakserver{};
	urmem::address_t _Send_fun;
	urmem::address_t _RPC_fun;
	urmem::address_t _GetPlayerIdFromIndex_fun;
	urmem::address_t _DeallocatePacket_fun;
	urmem::address_t _Receive_fun;
	inline static urmem::address_t _GetPacketId_fun{0};

	static Packet* FASTCALL RakServer__Receive(void* _this);
public:
	rakserver() = default;

	bool initialize(void** plugin_data);
	PlayerID get_playerid_from_index(int index) const;
	static std::uint8_t get_packet_id(Packet* packet);

	bool send_packet(BitStream* bs, int index = -1, PacketPriority priority = LOW_PRIORITY, PacketReliability reliability = RELIABLE) const;
	bool send_packet(BitStream* bs, PlayerID playerid = UNASSIGNED_PLAYER_ID, PacketPriority priority = LOW_PRIORITY, PacketReliability reliability = RELIABLE) const;
	bool send_rpc(BitStream* bs, unsigned char rpcid, int index, PacketPriority priority = HIGH_PRIORITY, PacketReliability reliability = RELIABLE, unsigned ordering_channel = 0, bool broadcast = false);
	bool send_rpc(BitStream* bs, unsigned char rpcid, PlayerID playerid, PacketPriority priority = HIGH_PRIORITY, PacketReliability reliability = RELIABLE, unsigned ordering_channel = 0, bool broadcast = false);
	void deallocate_packet(Packet* packet);
	Packet* receive();
};

inline std::unique_ptr<rakserver> rakserver_instance{ nullptr };