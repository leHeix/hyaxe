#include "../main.hpp"

bool rakserver::initialize(void** plugin_data)
{
	using GetRakServer_t = uintptr_t(*)();
	_rakserver = reinterpret_cast<GetRakServer_t>(plugin_data[PLUGIN_DATA_RAKSERVER])();
	const auto vmt = urmem::pointer(_rakserver).field<urmem::address_t*>(0);

	_Send_fun = vmt[SEND_FUNC_IDX];
	_RPC_fun = vmt[RPC_FUNC_IDX];
	_GetPlayerIdFromIndex_fun = vmt[PLAYERID_FROM_IDX_FUNC_IDX];
	_DeallocatePacket_fun = vmt[DEALLOCATE_PKT_FUNC_IDX];
	_Receive_fun = vmt[RECEIVE_FUNC_IDX];

	{
		urmem::unprotect_scope lk(reinterpret_cast<urmem::address_t>(&vmt[RECEIVE_FUNC_IDX]), sizeof(urmem::address_t));
		vmt[RECEIVE_FUNC_IDX] = reinterpret_cast<urmem::address_t>(&RakServer__Receive);
	}

#ifdef _WIN32
	urmem::sig_scanner scanner;

	if (!scanner.init(reinterpret_cast<urmem::address_t>(*plugin_data)))
	{
		console::print("failed to initialize rakserver: couldn't init address scanner");
		return false;
	}

	if (!scanner.find("\x8B\x44\x24\x04\x85\xC0\x75\x03\x0C\xFF\xC3\x8B\x48\x10\x8A\x01\x3C\xFF\x75\x03\x8A\x41\x05\xC3", "?????xxxxxxxxxxxx?xxxxxx", _GetPacketId_fun))
	{
		console::print("failed to initialize rakserver: couldn't find GetPacketId address");
		return false;
	}
#else
	if ((_GetPacketId_fun = find_pattern("\x53\x8B\x5D\x00\x0F\xB6\x0B\x84\xC9\x74\x00\x66\x90", "xxx?xxxxxx?xx")) == 0)
	{
		console::print("failed to initialize rakserver: couldn't find GetPacketId address");
		return false;
	}
#endif

	return true;
}

std::uint8_t rakserver::get_packet_id(Packet* packet)
{
	return urmem::call_function<urmem::calling_convention::cdeclcall, std::uint8_t>(_GetPacketId_fun, packet);
}

PlayerID rakserver::get_playerid_from_index(int index) const
{
	return urmem::call_function<urmem::calling_convention::thiscall, PlayerID>(_GetPlayerIdFromIndex_fun, _rakserver, index);
}

bool rakserver::send_packet(BitStream* bs, int index, PacketPriority priority, PacketReliability reliability) const
{
	if (index == -1)
	{
		return urmem::call_function<urmem::calling_convention::thiscall, bool>(_Send_fun, _rakserver, bs, priority, reliability, 0, UNASSIGNED_PLAYER_ID, true);
	}
	return urmem::call_function<urmem::calling_convention::thiscall, bool>(_Send_fun, _rakserver, bs, priority, reliability, 0, get_playerid_from_index(index), 0);
}

bool rakserver::send_packet(BitStream* bs, PlayerID playerid, PacketPriority priority, PacketReliability reliability) const
{
	return urmem::call_function<urmem::calling_convention::thiscall, bool>(_Send_fun, _rakserver, bs, priority, reliability, 0, playerid, (playerid == UNASSIGNED_PLAYER_ID));
}

bool rakserver::send_rpc(BitStream* bs, unsigned char rpcid, int index, PacketPriority priority, PacketReliability reliability, unsigned ordering_channel, bool broadcast)
{
	return urmem::call_function<urmem::calling_convention::thiscall, bool>(_RPC_fun, _rakserver, &rpcid, bs, priority, reliability, ordering_channel, get_playerid_from_index(index), broadcast, false);
}

bool rakserver::send_rpc(BitStream* bs, unsigned char rpcid, PlayerID playerid, PacketPriority priority, PacketReliability reliability, unsigned ordering_channel, bool broadcast)
{
	return urmem::call_function<urmem::calling_convention::thiscall, bool>(_RPC_fun, _rakserver, &rpcid, bs, priority, reliability, ordering_channel, playerid, broadcast, false);
}

void rakserver::deallocate_packet(Packet* packet)
{
	return urmem::call_function<urmem::calling_convention::thiscall, void>(_DeallocatePacket_fun, _rakserver, packet);
}

Packet* rakserver::receive()
{
	return urmem::call_function<urmem::calling_convention::thiscall, Packet*>(_Receive_fun, _rakserver);
}

Packet* FASTCALL rakserver::RakServer__Receive(void* _this)
{
	Packet* p = rakserver_instance->receive();
	auto packetid = rakserver::get_packet_id(p);
	if (packetid == 0xFF)
		return p;

	return p;
}
