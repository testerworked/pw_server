#--*-- coding: utf-8 --
from django.db import models
from primate.models import UserBase, UserMeta

class User(UserBase):
	__metaclass__ = UserMeta
	session_hash = models.CharField(max_length=50)
	user_ip = models.CharField(max_length=30)
	user_agent = models.CharField(max_length=512)
	bd_part_z = models.TextField()
	bd_part_f = models.FileField(upload_to='APCenter/static/hashing/first')
	record_counts = models.CharField(max_length=30)
	flag_bd = models.BooleanField()
	
	
class CSVBox_site(models.Model):
	title = models.CharField(max_length=30)
	login_base = models.CharField(max_length=30)
	password = models.CharField(max_length=32)
	url = models.CharField(max_length=120)
	pass_type = models.CharField(max_length=30)
	users = models.ForeignKey(User, related_name='site box')
	
	def __unicode__(self):
		return self.title
		
class CSVBox_bank(models.Model):
	bank_name = models.CharField(max_length=30)
	type_card = models.CharField(max_length=30)
	pin_code = models.CharField(max_length=32)
	users = models.ForeignKey(User, related_name='bank box')
	
	def __unicode__(self):
		return self.bank_name
	
class PasswordType(models.Model):
	email = models.CharField(max_length=60)
	for_date = models.DateField()
	url_site = models.CharField(max_length=120)
	users = models.ForeignKey(User, related_name='password type')

	def __unicode__(self):
		return self.email
		
class DirectoryInfo(models.Model):
	directory_list = models.TextField()
	users = models.ForeignKey(User, related_name='directory info')

	def __unicode__(self):
		return self.directory_list
		
