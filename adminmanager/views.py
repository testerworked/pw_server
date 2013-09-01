# -*- coding: utf-8 -*-
from django.contrib import auth
from django.contrib.auth.models import User
from django.shortcuts import render_to_response
from django.http import HttpResponse,HttpResponseRedirect
from adminmanager.models import *
from django.template.loader import get_template
from django.template import Context
import md5
import base64, hmac, hashlib
import datetime
import StringIO
from cutter import *
from collector import *
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
import re

#------------Вспомогательные функции-----------------------------------------
#-------------Создание хеша django пароля-------------------------------------
def get_random_string(length=12, allowed_chars='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'):
	    import random
	    try:
	        random = random.SystemRandom()
	    except NotImplementedError:
	        pass
	    return ''.join([random.choice(allowed_chars) for i in range(length)])

class Promise(object):
	    pass

def smart_str(s, encoding='utf-8', strings_only=False, errors='strict'):
	    if strings_only and isinstance(s, (types.NoneType, int)):
	        return s
	    if isinstance(s, Promise):
	        return unicode(s).encode(encoding, errors)
	    elif not isinstance(s, basestring):
	        try:
	            return str(s)
	        except UnicodeEncodeError:
	            if isinstance(s, Exception):
	                return ' '.join([smart_str(arg, encoding, strings_only,
	                        errors) for arg in s])
	            return unicode(s).encode(encoding, errors)
	    elif isinstance(s, unicode):
	        return s.encode(encoding, errors)
	    elif s and encoding != 'utf-8':
	        return s.decode('utf-8', errors).encode(encoding, errors)
	    else:
		return s		

def get_hexdigest(algorithm, salt, raw_password):
	    raw_password, salt = smart_str(raw_password), smart_str(salt)
	    if algorithm == 'crypt':
	        try:
	            import crypt
	        except ImportError:
	            raise ValueError('"crypt" password algorithm not supported in this environment')
	        return crypt.crypt(raw_password, salt)

	    if algorithm == 'md5':
	        return hashlib.md5(salt + raw_password).hexdigest()
	    elif algorithm == 'sha1':
	        return hashlib.sha1(salt + raw_password).hexdigest()
	    raise ValueError("Got unknown password algorithm type in password.")
#--------------------------------------------------------------------------------------------

#Получить хеш django пароля
def get_sha_hesh(password_string):
	algorithm='sha1'
	salt=get_random_string()
	raw_password=password_string
	raw_password, salt = smart_str(raw_password), smart_str(salt)
	hsh = get_hexdigest(algorithm, salt, raw_password)
	return '%s$%s$%s' % (algorithm, salt, hsh)

# Автоматизация проверки сессии
def if_user_session(session_key):
	# Вытащить userid из сессии
	userid = get_userid(session_key)
	p0 = User.objects.get(pk=userid)
	# Сравнение сессии юзера со значением в его куках
	if (session_key == p0.session_hash):
		return True
	else:
		return False

#Вычисление даты отправки письма рекомендации о смене пароля
def date_for_pass(pass_type_str):
	result_day = datetime.date.today()
	today = datetime.date.today()
	if(pass_type_str == 'cold'):
		one_month = datetime.timedelta(days=30)
		result_day = today + one_month
		return result_day
	if(pass_type_str == 'warm'):
		two_week = datetime.timedelta(days=14)
		result_day = today + two_week
		return result_day
	else:
		one_week = datetime.timedelta(days=7)
		result_day = today + one_week
		return result_day
		
# Проверка пароля
def checkPass(password):
	pass_len = len(password)
	score = 0
	for i in password:
		if re.search('\d+',i) or re.search('[a-z]',i) or re.search('[A-Z]',i)  or re.search('.[!,@,#,$,%,^,&,*,?,_,~,-,(,)]',i):
			score = score + 1
	if (score == pass_len):
		return True
	else:
		return False
		
# Проверка email без EmailField
def email(value):
        try:
            validate_email(value)
            return True

        except (ValidationError), e:
            return (False, e.messages[0])
		
# Проверка URL		
def checkURL(url_message):
	url_re = re.compile(
		r'^https?://'
		r'(?:(?:[A-Z0-9-]+\.)+[A-Z]{2,6}|'
		r'localhost|'
		r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
		r'(?::\d+)?'
		r'(?:/?|/\S+)$', 
	re.IGNORECASE)
	m_test = re.search(url_re, url_message)
	try:
		m_test.group(0)
		return True
	except Exception, e:
		#print e
		return False
#-------------------------------------------------------------------------------------
	
def index(request):
	return render_to_response("index.html")

# Авторизация
def login(request):
	username = request.POST['username'].lower()
	password = request.POST['password']
	user = auth.authenticate(username=username, password=password)
	if user is not None and user.is_active:
		# Правильный пароль и пользователь "активен"
		auth.login(request, user)
		# Cоздаем и сохраняем hash сессии
		tester = User.objects.filter(username=username).values('id')
		userid = tester[0]['id']
		p0 = User.objects.get(pk=userid)
		session_hashgen = str(userid) + '|' + md5.new(str(userid)+request.META['REMOTE_ADDR']).hexdigest()+md5.new(request.META['HTTP_USER_AGENT']+'random_secret').hexdigest()
		p0.session_hash = session_hashgen
		p0.save()
		request.session['SESSION_EXPIRE_AT_BROWSER_CLOSE'] = True
		request.session['you_session'] = session_hashgen
		# Перенаправление на "правильную" страницу
		return HttpResponseRedirect("/account/loggedin/")
	else:
		# Отображение страницы с ошибкой
		return HttpResponseRedirect("/account/invalid/")
		

# Закрытие сессии
def logout(request):
	try:
		auth.logout(request)
		del request.session['you_session']
	except KeyError:
		pass
	return HttpResponseRedirect("/")

def reg_set(request):
	if ('username' in request.POST) and ('name' in request.POST) and ('email' in request.POST) and ('password' in request.POST):
		if(request.POST['username'].isalnum() and request.POST['name'].isalpha() and checkPass(request.POST['password']) and email(request.POST['email'])):
			username_low = request.POST['username'].lower()
			unic_username = User.objects.filter(username=request.POST['username']).count()
			unic_email = User.objects.filter(email=request.POST['email']).count()
			if(unic_username == 0):
				if(unic_email == 0):
					reg_pass = get_sha_hesh(request.POST['password'])
					savebase = User(username=username_low,name=request.POST['name'],email=request.POST['email'],password=reg_pass,user_ip=request.META['REMOTE_ADDR'],user_agent=request.META['HTTP_USER_AGENT'])
					savebase.save()
					user_name = request.POST['username']
					t = get_template('registration_response.html')
					message = t.render(Context({'success': user_name}))
					return HttpResponse(message)
				else:
					user_name = request.POST['username']
					return render_to_response('registration_response.html', {'fail_email': user_name})
			else:
				user_name = request.POST['username']
				return render_to_response('registration_response.html', {'fail_name': user_name})	
		
#--------------------------------------------------------------------------------------------------------------

#user administration module
def usermodule(request):
	if (if_user_session(request.session['you_session'])):
		user_session = 'Success!'
		t = get_template('usermodule.html')
		message = t.render(Context({'my_session': user_session}))
		return HttpResponse(message)
	else:
		return render_to_response("usermodule.html")
		
# Вывод значений из базы по сайтам
def work_services(request):
	# Сравнение сессии юзера со значением в его куках
	if (if_user_session(request.session['you_session'])):
		userid = get_userid(request.session['you_session'])
		if 'add_services' in request.POST:
			# Добавление строк в CSVBox_site
			#Добавить проверки на уникальность значений, на sql-инъекцию
			if (('title' in request.POST) and ('login1' in request.POST) and ('pass1' in request.POST) and ('url' in request.POST)):
				if (request.POST['title'].isalpha() and request.POST['login1'].isalnum() and checkPass(request.POST['pass1']) and checkURL(request.POST['url'])):
					save_services = CSVBox_site(title=request.POST['title'],login_base=request.POST['login1'],password=request.POST['pass1'],url=request.POST['url'],pass_type=request.POST['type_pass'],users_id=userid)
					save_services.save()
					if(request.POST['type_pass'] == 'cold'):
						p0 = User.objects.get(pk=userid)
						save_pass_type = PasswordType(email=p0.email,for_date=date_for_pass('cold'),url_site=request.POST['url'],users_id=userid)
						save_pass_type.save()
					if(request.POST['type_pass'] == 'warm'):
						p0 = User.objects.get(pk=userid)
						save_pass_type = PasswordType(email=p0.email,for_date=date_for_pass('warm'),url_site=request.POST['url'],users_id=userid)
						save_pass_type.save()
					if(request.POST['type_pass'] == 'hot'):
						p0 = User.objects.get(pk=userid)
						save_pass_type = PasswordType(email=p0.email,for_date=date_for_pass('hot'),url_site=request.POST['url'],users_id=userid)
						save_pass_type.save()
			else:
				err_csvbox_site = 'Ошибка при добавлении строки'
				return render_to_response("usermodule.html", {'err_csvbox_site':err_csvbox_site})
		if 'editor_index' in request.POST:
			edit_row = CSVBox_site.objects.get(pk=request.POST['editor_index'])
			t = get_template('usermodule.html')
			message = t.render(Context({'edit_this_row_service': edit_row}))
			return HttpResponse(message)
		if 'update_please' in request.POST:
			if (request.POST['title'].isalpha() and request.POST['login_base'].isalnum() and request.POST['type_pass'].isalpha() and checkPass(request.POST['pass']) and checkURL(request.POST['url'])):
				update_row = CSVBox_site.objects.get(pk=request.POST['update_please'])
				update_row.title=request.POST['title']
				update_row.login_base=request.POST['login_base']
				update_row.password=request.POST['pass']
				update_row.pass_type=request.POST['type_pass']
				update_row.url=request.POST['url']
				update_row.save()
		if 'del_index' in request.POST:
			CSVBox_site.objects.filter(pk=request.POST['del_index']).delete()
		p0 = User.objects.get(pk=userid)
		list_services = CSVBox_site.objects.filter(users=p0)
		paginator = Paginator(list_services, 10) # Show 10 service_output per page

		page = request.GET.get('page')
		try:
			out_services = paginator.page(page)
		except PageNotAnInteger:
			# If page is not an integer, deliver first page.
			out_services = paginator.page(1)
		except EmptyPage:
			# If page is out of range (e.g. 9999), deliver last page of results.
			out_services = paginator.page(paginator.num_pages)

		t = get_template('usermodule.html')
		message = t.render(Context({'service_output': out_services}))
		return HttpResponse(message)
	else:
		error_session = 'Ошибка в сессии, переавторизуйтесь пожалуйста.'
		return render_to_response("usermodule.html", {'error_session':error_session})


#Вывод значений из базы по сайтам
def work_bank(request):
	#Сравнение сессии юзера со значением в его куках
	if (if_user_session(request.session['you_session'])):
		userid = get_userid(request.session['you_session'])
		if 'add_bank' in request.POST:
			# Добавление строк в CSVBox_site
			#Добавить проверки на уникальность значений, на sql-инъекцию
			if (('bank_name' in request.POST) and ('type_card' in request.POST) and ('pin_code' in request.POST)):
				if (request.POST['bank_name'].isalpha() and request.POST['type_card'].isalnum() and request.POST['pin_code'].isdigit()):
					save_banks = CSVBox_bank(bank_name=request.POST['bank_name'],type_card=request.POST['type_card'],pin_code=request.POST['pin_code'],users_id=userid)
					save_banks.save()
			else:
				err_csvbox_bank = 'Ошибка при добавлении строки'
				return render_to_response("usermodule.html", {'err_csvbox_site':err_csvbox_bank})
		if 'editor_index' in request.POST:
			edit_row = CSVBox_bank.objects.get(pk=request.POST['editor_index'])
			t = get_template('usermodule.html')
			message = t.render(Context({'edit_this_row_bank': edit_row}))
			return HttpResponse(message)
		if 'update_please' in request.POST:
			if (request.POST['bank_name'].isalpha() and request.POST['type_card'].isalnum() and request.POST['pin_code'].isdigit()):
				update_row = CSVBox_bank.objects.get(pk=request.POST['update_please'])
				update_row.bank_name=request.POST['bank_name']
				update_row.type_card=request.POST['type_card']
				update_row.pin_code=request.POST['pin_code']
				update_row.save()
		if 'del_index' in request.POST:
			CSVBox_bank.objects.filter(pk=request.POST['del_index']).delete()
		p0 = User.objects.get(pk=userid)
		list_banks = CSVBox_bank.objects.filter(users=p0)
		paginator = Paginator(list_banks, 10) # Show 10 service_output per page
		page = request.GET.get('page')
		try:
			out_banks = paginator.page(page)
		except PageNotAnInteger:
			# If page is not an integer, deliver first page.
			out_banks = paginator.page(1)
		except EmptyPage:
			# If page is out of range (e.g. 9999), deliver last page of results.
			out_banks = paginator.page(paginator.num_pages)
		t = get_template('usermodule.html')
		message = t.render(Context({'bank_output': out_banks}))
		return HttpResponse(message)
	else:
		error_session = 'Ошибка в сессии, переавторизуйтесь пожалуйста.'
		return render_to_response("usermodule.html", {'error_session':error_session})

#-----------------------------------------------------------------------------------------
def documentation(request):
	if (if_user_session(request.session['you_session'])):
		doc_in_session = 'FAQ'
		t = get_template('usermodule.html')
		message = t.render(Context({ 'doc_in_session': doc_in_session }))
		return HttpResponse(message)
	else:
		return render_to_response("usermodule.html")

#-----------------------Cutter-Collector------------------------------------------------------
def base_cutter(request):
	if (if_user_session(request.session['you_session'])):
		cutter_session = 'Cutter opened!'
		t = get_template('usermodule.html')
		message = t.render(Context({'cutter_session': cutter_session}))
		return HttpResponse(message)
	else:
		return render_to_response("usermodule.html")
		

def cut_download(request):
	if (if_user_session(request.session['you_session'])):
		if 'flag_cutter' in request.POST:
			userid = get_userid(request.session['you_session'])
			p0 = User.objects.get(pk=userid)
			x_message = ''
			output = StringIO.StringIO()
			x_message = cutter_base(userid)
			output.write(x_message)
			output.seek(0)
			responce = HttpResponse(output.read(), mimetype='text/plain')
			responce['Content-Disposition'] = 'attachment; filename=base_part2_'+p0.username+'.txt'
			return responce
		flag_download = "*Рекомендация - Пересохраните файл в безопасное файловое хранилище"
		t = get_template('usermodule.html')
		message = t.render(Context({'flag_download': flag_download}))
		return HttpResponse(message)
	else:
		error_session = 'Ошибка в сессии, переавторизуйтесь пожалуйста.'
		return render_to_response("usermodule.html", {'error_session':error_session})

from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.conf import settings
def base_collector(request):
	if (if_user_session(request.session['you_session'])):
		if 'flag_upload' in request.POST:
			userid = get_userid(request.session['you_session'])
			p0 = User.objects.get(pk=userid)
			p0.bd_part_f = request.FILES['part_file']
			p0.flag_bd = True
			p0.save()
			# Извлекаем данные собирая и расшифровывая базу
			file_path = ''
			file_path = str(p0.bd_part_f)
			x_message = collector_base(userid, file_path)
			t = get_template('usermodule.html')
			message = t.render(Context({'x_message': x_message}))
			return HttpResponse(message)
		collector_session = "Собери меня!"
		t = get_template('usermodule.html')
		message = t.render(Context({'collector_session': collector_session}))
		return HttpResponse(message)
	else:
		collector_session = "Собери меня!"
		t = get_template('usermodule.html')
		message = t.render(Context({'collector_session': collector_session}))
		return HttpResponse(message)
#-------------------------------------------------------------------------------------------------
def generate(request):
	if (if_user_session(request.session['you_session'])):
		if 'secret' in request.POST:
			gen_pas = base64.b64encode(hmac.new(str(request.POST['secret']),str(request.POST['gen_url']), hashlib.sha1).digest())
			new_pas = ''
			i = int(request.POST['max_len'])
			new_pas = gen_pas[:i]
			t = get_template('usermodule.html')
			message = t.render(Context({'generated_pas': new_pas }))
			return HttpResponse(message)
		generate_session = 'Generator opened!'
		t = get_template('usermodule.html')
		message = t.render(Context({'password_gen': generate_session}))
		return HttpResponse(message)
	else:
		generate_session = 'Generator opened!'
		t = get_template('usermodule.html')
		message = t.render(Context({'password_gen': generate_session}))
		return HttpResponse(message)
#---------------------------------------------------------------------------------------
def device_data(request):
	if (if_user_session(request.session['you_session'])):
		userid = get_userid(request.session['you_session'])
		if 'flag_list_upload' in request.POST:
			userid = get_userid(request.session['you_session'])
			p0 = User.objects.get(pk=userid)
			if 'directory_list' in request.POST:
				save_directory = DirectoryInfo(directory_list=request.POST['directory_list'],users_id=userid)
				save_directory.save()
				x_message = 'Загружено...1'
				t = get_template('usermodule.html')
				message = t.render(Context({'x_message': x_message}))
				return HttpResponse(message)
			else:
				err_csvbox_bank = 'Ошибка при добавлении строки'
				return render_to_response("usermodule.html", {'err_csvbox_site':err_csvbox_bank})
		
		p0 = User.objects.get(pk=userid)
		list_services = DirectoryInfo.objects.filter(users=p0)
		paginator = Paginator(list_services, 10) # Show 10 service_output per page

		page = request.GET.get('page')
		try:
			out_directory = paginator.page(page)
		except PageNotAnInteger:
			# If page is not an integer, deliver first page.
			out_directory = paginator.page(1)
		except EmptyPage:
			# If page is out of range (e.g. 9999), deliver last page of results.
			out_directory = paginator.page(paginator.num_pages)
		
		data_session = "Загружено...2"
		t = get_template('usermodule.html')
		message = t.render(Context({'directory_output': out_directory, 'data_session': data_session}))
		return HttpResponse(message)
	else:
		data_session = "Ошибка в сессии!"
		t = get_template('usermodule.html')
		message = t.render(Context({'data_session': data_session}))
		return HttpResponse(message)

#-----------------------------------------------------------------------------------
def clients(request):
	if (if_user_session(request.session['you_session'])):
		clients_output = 'Clients'
		t = get_template('usermodule.html')
		message = t.render(Context({'clients_output': clients_output}))
		return HttpResponse(message)
	else:
		return render_to_response("usermodule.html")