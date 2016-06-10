import codecs

class KeepassDatabase(object):
	header = {}

	def __init__(self, filename):
		with open(filename, 'rb') as file:
			buffer = file.read()

			self.decode(buffer)

	def decode(self, buf):
		self.header['signature1'] = codecs.encode(buf[:4], 'hex_codec')
		self.header['signature2'] = codecs.encode(buf[4:8], 'hex_codec')
		self.header['version_major'] = codecs.encode(buf[8:10], 'hex_codec')
		self.header['version_minor'] = codecs.encode(buf[10:12], 'hex_codec')

		header = buf[12:]

		header_entries = {
				2: 'cipher_id',
				3: 'compression_flags',
				4: 'master_seed',
				5: 'transform_seed',
				6: 'transform_rounds',
				7: 'encryption_iv',
				8: 'protected_stream_key',
				9: 'stream_start_bytes',
				10: 'inner_random_stream_id',
		}

		while True:
			field_id = int.from_bytes(header[:1], 'little')                  # 1 byte
			field_size = int.from_bytes(header[1:3],'little')                # 1 WORD
			field_value = header[3: field_size+3]                            # field_size

			header = header[field_size+3:]

			if field_id == 0:
				break

			self.header[ header_entries[ field_id ] ] = codecs.encode(field_value, 'hex_codec')
			if field_id == 6:
				self.header[ header_entries[ field_id ] ] = int.from_bytes(field_value, 'little')
			if field_id == 10:
				self.header[ header_entries[ field_id ] ] = int.from_bytes(field_value, 'little')
			if field_id == 7:
				self.header[ header_entries[ field_id ] ] = field_value
			if field_id == 5:
				self.header[ header_entries[ field_id ] ] = field_value
			if field_id == 9:
				self.header[ header_entries[ field_id ] ] = field_value
			if field_id == 4:
				self.header[ header_entries[ field_id ] ] = field_value
			if field_id == 8:
				self.header[ header_entries[ field_id ] ] = field_value

		self.payload = header
