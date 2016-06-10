import hashlib
import base64
import codecs
import zlib

from Crypto.Cipher import AES
from os import urandom
from pureSalsa20 import Salsa20

import xml.etree.ElementTree as ET

from KeepassDatabase import KeepassDatabase


class KeepassReader(object):
	entries = []

	status = {'error': 0}

	# Open the filename and password
	# ----------------------------------------------------------------------------
	def open(self, filename, password):
		try:
			self.database = KeepassDatabase(filename)
			return self.decrypt(self.database, password)
		except:
			self.status['error'] = 2
			return None


	# Pretty self explanatory
	# ----------------------------------------------------------------------------
	def decrypt(self, database, password):
		# 1) SHA256 all key composites
		hash_key = hashlib.sha256(bytearray(password.encode())).digest()

		# 2) SHA256 all key composites together
		composite_key = hashlib.sha256(hash_key).digest()

		# 3) Establish an AES 128-ECB context, IV: 16x \0, key: transform_seed
		transform_seed = database.header['transform_seed']
		cipher = AES.new(bytes(transform_seed), AES.MODE_ECB, bytes(16))

		# 4) Encrypt transform_rounds time the composite_key
		transformed_key = composite_key
		rounds = database.header['transform_rounds']
		while rounds:
			transformed_key = cipher.encrypt(transformed_key)
			rounds -= 1

		# 5) SHA256 the transformed key
		transformed_key = hashlib.sha256(transformed_key).digest()

		# 6) Obtain the master key
		master_key = hashlib.sha256(database.header['master_seed'] + transformed_key).digest()

		# 7) Establish an AES 128-CBC contact, IV: header, key: master_key
		iv = database.header['encryption_iv']
		cipher = AES.new(master_key, AES.MODE_CBC, bytes(iv))
		payload = database.payload
		content = cipher.decrypt(payload)

		# 8) Split the payload by blocks
		if content[:32] != database.header['stream_start_bytes']:
			# Database corrupted or master key not valid!
			self.status['error'] = 1
			return None

		# Remove the validation block
		content = content[32:]
		xml = bytes(0)

		while len(content) > 0:
			block_id = content[:4]
			block_hash = content[4:36]
			data_size = int.from_bytes(content[36:40], 'little')
			block_data = content[40:40 + data_size]

			if data_size > 0 and hashlib.sha256(block_data).digest() == block_hash:
				xml += block_data

			content = content[40 + data_size:]

		# If compressed, ungzip
		if int.from_bytes(database.header['compression_flags'], 'big') > 0x0:
			xml = zlib.decompress(xml, 15 + 32)

		return xml

	# Parse the Keepass xml and fetch the entries
	# ----------------------------------------------------------------------------
	def parse(self, xml):
		if xml == None:
			self.status['error'] = 3
			return None

		xml_root = ET.fromstring(xml)

		salsa_buffer = bytearray()
		iv = bytes( [0xE8,0x30,0x09,0x4B,0x97,0x20,0x5D,0x2A] )

		key = hashlib.sha256(self.database.header['protected_stream_key']).digest()

		salsa = Salsa20( key, iv)
		salsa.setCounter(0)

		for xml_entry in xml_root.iter('Entry'):
			need_decryption = False
			entry = {}
			entry['uid'] = xml_entry[0].text
			data = {}
			for child in xml_entry:
				if child.tag == "String" and child[1].text != None:
					data[ child[0].text ] = child[1].text

					if len(child[1].attrib) > 0 and child[1].attrib['Protected'] != None:
						# Salsa20
						if self.database.header['inner_random_stream_id'] == 2:

							encoded = base64.b64decode( child[1].text )
							length = len(encoded)

							# Assure we have an enought buffer for the value
							while length > len(salsa_buffer):
								new_salsa = salsa.encryptBytes(bytes(bytearray(64)))
								salsa_buffer.extend(new_salsa)

							# xor the encoded value with
							result = bytearray()
							for a, b in zip(bytearray(encoded), bytearray(salsa_buffer[:length])):
								result.append(a ^ b)

							# Replace the existing value with the decoded one
							data[ child[0].text ] = result.decode('utf-8')

							del salsa_buffer[:length]

			entry['data'] = data

			self.entries.append( entry )
		
		return self.entries


if __name__ == "__main__":
	reader = KeepassReader()

	xml = reader.open("database.kdbx", "keepass")

	entries = reader.parse(xml)

	print( entries )
