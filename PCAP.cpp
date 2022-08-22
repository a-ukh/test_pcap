#include "PCAP.h"
#include <fstream>
#include <iostream>

namespace
{
	struct pcap_hdr_t
	{
		uint32_t magic_number;
		uint16_t version_major;
		uint16_t version_minor;
		int32_t  thiszone;
		uint32_t sigfigs;
		uint32_t snaplen;
		uint32_t network;
	};

	struct pcaprec_hdr_t
	{
		uint32_t ts_sec;
		uint32_t ts_usec;
		uint32_t incl_len;
		uint32_t orig_len;
	};
}

PCAPReader::PCAPReader(const std::string& fileName) : _fileName(fileName), _packetsCount(0), _payloadSize(0) 
{
	std::ifstream pcap_file(_fileName, std::ios::binary);
	if (pcap_file.is_open())
	{
		//read global header
		pcap_hdr_t global_header{};
		pcap_file.read(reinterpret_cast<char*>(&global_header), sizeof(pcap_hdr_t));
		
		while (!pcap_file.eof())
		{
			//read packet header
			pcaprec_hdr_t packet_header{};
			pcap_file.read(reinterpret_cast<char*>(&packet_header), sizeof(pcaprec_hdr_t));

			//if SWAPPED then swap bytes
			if (global_header.magic_number == 0xd4c3b2a1)
				packet_header.incl_len = ((packet_header.incl_len >> 24) & 0xFFul) |
										 ((packet_header.incl_len >> 8) & 0xFF00ul) |
										 ((packet_header.incl_len << 8) & 0xFF0000ul) |
										 ((packet_header.incl_len << 24) & 0xFF000000ul);

			//read packet
			pcap_file.ignore(packet_header.incl_len);

			if (packet_header.incl_len > 0)
			{
				++_packetsCount;
				_payloadSize += packet_header.incl_len;
			}			
		}
	}
};

uint64_t PCAPReader::packetsCount() const noexcept
{
	return _packetsCount;
}

uint64_t PCAPReader::payloadSize() const noexcept
{
	return _payloadSize;
}
