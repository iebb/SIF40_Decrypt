#!/usr/bin/python
# -*- coding: utf-8 -*-
from Crypto.Cipher import AES
import base64
import sqlite3
import json, re, sys
print '====== SIF4 Decrypt Tool by ieb ======'
if len(sys.argv) == 1:
	print 'Command-Line usage:', sys.argv[0], '[filename.db_]'
	filename = raw_input('Filename to decrypt: ')
else:
	filename = sys.argv[1]
def decrypt(key, content):
	key = base64.b64decode(key)
	IV = 16 * '\x00'
	mode = AES.MODE_CBC
	encryptor = AES.new(key, mode, IV=IV)
	text = base64.b64decode(content)
	ciphertext = encryptor.decrypt(text)
	data = re.findall('({".*})', ciphertext)[0]
	load = json.loads(data)
	return load

try:
	conn = sqlite3.connect(filename)
	conn.row_factory = sqlite3.Row
	cur = conn.cursor()
	upd = conn.cursor()
	keys = json.loads(open("conf.json").read())
	keypairs = {}
	for i in keys: keypairs[i['id']] = i['key']
	cur.execute("SELECT * FROM sqlite_master WHERE type='table'")
	tables = cur.fetchall()
	notfound = []
	count = 0
	for i in tables:
		if 'release_tag' in i['sql']:
			print 'Found Encrypted Table', i['tbl_name']
			cur.execute("SELECT _rowid_ as __rowid, * FROM " + i['tbl_name'] + " WHERE release_tag IS NOT NULL", )
			data = cur.fetchall()
			for item in data:
				keyid = item['_encryption_release_id']
				content = item['release_tag']
				__rowid = item['__rowid']
				if keyid in keypairs:
					dec = decrypt(keypairs[keyid], content)
					for col in dec:
						val = dec[col] if dec[col] != False else None
						if type(dec[col]) != bool:
							val = dec[col]
						count += 1
						upd.execute("UPDATE " + i['tbl_name'] + " SET " + col + " = ? WHERE _rowid_ = ?", (val, __rowid))
						upd.execute("UPDATE " + i['tbl_name'] + " SET release_tag = ?, _encryption_release_id = ? WHERE _rowid_ = ?", (None, None, __rowid))
						
				else:
					if keyid not in notfound:
						notfound.append(keyid)
	conn.commit()
	if len(notfound):
		print 'Failed to decrypt key', notfound
	print 'Successfully Decypted %d Records' % (count)
except Exception, e:
	print 'Err:', e
raw_input('Press Enter To Exit')