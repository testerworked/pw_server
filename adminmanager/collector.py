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
from django.core.servers.basehttp import FileWrapper

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
	
	
def collector_base(my_userid, path):
	p0 = User.objects.get(pk=my_userid)
	
	#читаем password hash	
	j = 0
	x_pass = ''
	for i in p0.password:
		if (j<32):
			x_pass = x_pass + i
		j = j + 1
		
	#Узнаем размерность сайтовых и банковских строк
	j = 0
	row_count = ''
	for i in p0.record_counts:
		row_count = row_count + i
		j = j + 1
		
	to_decode0 = ''
	to_decode0 = p0.bd_part_z
	row_count_sum = row_count.split(',')

	handle = ''
	time.sleep(3)
	handle = open(path,'r+')
	to_decode1 = handle.read()
	handle.close()
	
	if ((to_decode0 != None) and (p0.flag_bd == True)):
		
		sum_decode = ''
		sum_decode = to_decode0 + to_decode1
		#--------------------------------AES-----------------------------------
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
		#secret = "ellectroenergiyaellectroenergiya"
		secret = x_pass

		# create a cipher object using the random secret
		cipher = AES.new(secret)
		#----------------------------------------------------------------------
		#------------------------------расшифрока------------------------------
		# decode the encoded string
		decoded = DecodeAES(cipher, sum_decode)

		#------------------------Извлечь данные из decoded---------------------
		forstr_len = ['']
		forstr_len = decoded.split('\n')
		x_count_site = int(row_count_sum[0])
		x_count_bank = int(row_count_sum[1])
		print x_count_site, forstr_len
		
		
		str = ['']*x_count_site
		title = ['']*x_count_site
		login_base = ['']*x_count_site
		rec_pass = ['']*x_count_site
		url = ['']*x_count_site
		pass_type = ['']*x_count_site
		
		bank_name = ['']*x_count_bank
		type_card = ['']*x_count_bank
		pin_code = ['']*x_count_bank
		
		max_count = x_count_site + x_count_bank
		j=0
		x=0
		for i in range(max_count):
			if (j < x_count_site):
				title[i] = forstr_len[i].split(',')[0]
				login_base[i] = forstr_len[i].split(',')[1]
				rec_pass[i] = forstr_len[i].split(',')[2]
				url[i] = forstr_len[i].split(',')[3]
				pass_type[i] = forstr_len[i].split(',')[4]
			else:
				bank_name[x] = forstr_len[i].split(',')[0]
				type_card[x] = forstr_len[i].split(',')[1]
				pin_code[x] = forstr_len[i].split(',')[2]
				x = x + 1
			j = j + 1
		print title[0], login_base[0], url, pin_code
		
		my_string = ['']*x_count_site
		for i in range(x_count_site):
			save_services = CSVBox_site(title=title[i],login_base=login_base[i],password=rec_pass[i],url=url[i],pass_type=pass_type[i],users_id=my_userid)
			save_services.save()
			
		my_string_bank = ['']*x_count_bank
		for i in range(x_count_bank):
			save_banks = CSVBox_bank(bank_name=bank_name[i],type_card=type_card[i],pin_code=pin_code[i],users_id=my_userid)
			save_banks.save()
	#---------------------------------------------------------------
	#Удалить файл
	p0.bd_part_f.delete(True)
	#Обновить таблицу User
	p0.bd_part_z = ''
	#p0.bd_part_f = ''
	p0.record_counts = ''
	p0.flag_bd = 'False'
	p0.save()
	
	var_result = "success!"
	return var_result
	