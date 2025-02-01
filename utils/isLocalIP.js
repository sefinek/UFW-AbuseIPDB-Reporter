const ipaddr = require('ipaddr.js');

module.exports = ip => {
	const range = ipaddr.parse(ip).range();
	return [
		'unspecified', 'multicast', 'linkLocal', 'loopback', 'reserved', 'benchmarking',
		'amt', 'broadcast', 'carrierGradeNat', 'private', 'as112', 'uniqueLocal',
		'ipv4Mapped', 'rfc6145', '6to4', 'teredo', 'as112v6', 'orchid2', 'droneRemoteIdProtocolEntityTags',
	].includes(range);
};