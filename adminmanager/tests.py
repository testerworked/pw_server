"""
This file demonstrates writing tests using the unittest module. These will pass
when you run "manage.py test".

Replace this with more appropriate tests for your application.
"""

from django.test import TestCase
from adminmanager.views import *


class SimpleTest(TestCase):
    def test_basic_addition(self):
        """
        Tests that 1 + 1 always equals 2.
        """
        self.assertEqual(1 + 1, 2)


def checkPass(password):
	'''
	>>> a = checkPass('sdfas876876KJHKJh')
	>>> a
	True
	>>> b = checkPass('^%&GJHGJVGHJ786')
	>>> b
	False
	'''
	return password
	
	
def checkURL(url_message):
	'''
	>>> a = checkURL('http://asdfsadfas.ru')
	>>> a
	True
	>>> a1 = checkURL('https://asdfsadfas.ru')
	>>> a1
	True
	>>> a2 = checkURL('www.www.www')
	>>> a2
	False
	>>> a3 = checkURL('567^&*^8wwasdfwww')
	>>> a3
	False
	'''
	return url_message

def login(result):
	'''
	>>> from django.test.client import Client
	>>> from adminmanager.views import *
	>>> c = Client()
	>>> c.login(username='gipnoz', password='p123456')
	C:\Python27\lib\site-packages\django\db\models\fields\__init__.py:808: RuntimeWa
	rning: DateTimeField received a naive datetime (2013-03-23 15:49:19.286000) whil
	e time zone support is active.
	  RuntimeWarning)
	True
	'''
	return result
	
'''
from django import test
from django.core.urlresolvers import reverse

__test__ = {"urls": """
>>> c = test.Client()
>>> c.get(reverse('reg_set')).status_code
200
>>> c.get(reverse('login')).status_code
200
>>> c.get(reverse('logout')).status_code
302
"""}'''