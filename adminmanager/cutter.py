# -*- coding: utf-8 -*-
from django.contrib.auth.models import User
from adminmanager.models import *
from Crypto.Cipher import AES
import base64
import os
import sqlite3 as lite
import sys
import time
import datetime

# Получение userid из сессии
def get_userid(_session_str):
	j = 0
	str_userid = ''
	user_id = 0
	while(_session_str[j] != '|'):
		str_userid = str_userid + _session_str[j]
		j = j + 1
	user_id = int(str_userid)
	return user_id
	
	
def cutter_base(my_userid):
	p0 = User.objects.get(pk=my_userid)
	p1 = CSVBox_site.objects.filter(users=p0)
	p1_count = CSVBox_site.objects.filter(users=p0).count()
	p2 = CSVBox_bank.objects.filter(users=p0)
	p2_count = CSVBox_bank.objects.filter(users=p0).count()
	
	rec_counts = str(p1_count) + ',' + str(p2_count)
	string_full_base = ''
	
	for i in p1:
		string_full_base = string_full_base+i.title+','+i.login_base+','+i.password+','+i.url+','+i.pass_type+'\n'
		
	for j in p2:
		string_full_base = string_full_base+j.bank_name+','+j.type_card+','+j.pin_code+'\n'
	
	#--------------------------AES-CRYPT-----------------------------
	# the block size for the cipher object; must be 16, 24, or 32 for AES
	BLOCK_SIZE = 32
	
	# the character used for padding--with a block cipher such as AES, the value
	# you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
	# used to ensure that your value is always a multiple of BLOCK_SIZE
	PADDING = '{'
	
	# one-liner to sufficiently pad the text to be encrypted
	pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
	
	# one-liners to encrypt/encode and decrypt/decode a string
	# encrypt with AES, encode with base64
	EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
	DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
	
	# generate a random secret key
	#secret = os.urandom(BLOCK_SIZE)
	#Вытащить хэш пароля из базы
	x_pass = ''
	j = 0
	for i in p0.password:
		if (j<32):
			x_pass = x_pass + i
		j = j + 1
	secret = x_pass
	
	# create a cipher object using the random secret
	cipher = AES.new(secret)
	#-------------------------------------------------------------------
	# encode a string
	encoded = EncodeAES(cipher, string_full_base)
	#-----------------------cut out base--------------------------------
	full_len = len(encoded)
	p0len_tmp = round((full_len*2/3), 0)
	p0_len = int(p0len_tmp)
	enc_str0 = ''
	enc_str1 = ''
	j = 0
	for i in encoded:
		if (j<=p0_len):
			enc_str0 = enc_str0 + i
		else:
			enc_str1 = enc_str1 + i
		j = j + 1
		
	p0.record_counts = rec_counts
	p0.bd_part_z = enc_str0
	p0.save()
	#Подумать где лучше применять очистку базы - возможно это будет при закрытии сессии
	p1.delete()
	p2.delete()
	return enc_str1
	