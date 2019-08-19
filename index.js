const pcap = require('pcap');
const hexToBinary = require('hex-to-binary');

pcap_session = pcap.createSession('wlp58s0', 'src 63.34.101.111' );

pcap_session.on('packet', raw_packet => {
	const packet = pcap.decode.packet(raw_packet);
	const payload = packet.payload.payload;

	if (!payload || !payload.payload || !payload.payload.dataLength)
		return;

	const parsedPacket = parsePacket(payload.payload.data);
	if (parsedPacket.header.packetId === 951)
		return;
	console.log(`Package from ${payload.saddr.addr.join('.')} to ${payload.daddr.addr.join('.')} :`);
	console.log('packet id : ', parsedPacket.header.packetId, 'contentLength : ', payload.payload.data.length);
	// payload.payload.data.map((byte) => console.log(byte.toString('binary')));
	// console.log(hexToBinary(payload.payload.data.join('')));
		// ${payload.payload.data.toString()}
	// console.log(packet.payload.payload);
	// 
	// 00000101 00000011 01100110 01100110 00100100 00010111 100100000010000100010000000000000110000000011000000000000
	// 00000110 00000011 01100110 01100110 00010100 00010001 010001110000001000010001000000000000011000000001000100101
});

const parsePacket = (buffer) => {
	const hiheader = buffer.readInt16BE();
	const packetId = hiheader >> 2;
	const lenType = hiheader & 3;
	// buffer = buffer.slice(16);

	if (packetId === 226) {
		console.log(hexToBinary(buffer.join('')))
		const subAreaId = buffer.readInt8(16);
		// buffer = buffer.slice(8);
		const mapId = buffer.readInt16BE(24);
		console.log('subAreaId : ', subAreaId, 'mapId :', mapId);
	}

	return {
		header: {
			packetId
		},
		content: {

		}
	}
}