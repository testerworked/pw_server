$(document).ready(function(){

    $("#register_form").validate({
        
       rules:{ 
        
            username:{
                required: true,
                minlength: 4,
                maxlength: 16,
            },
			
			name:{
                required: true,
                minlength: 4,
                maxlength: 16,
            },
            
			email:{
                required: true,
				email: true,
                minlength: 6,
                maxlength: 16,
            },
			
            password:{
                required: true,
                minlength: 6,
                maxlength: 16,
            },
			
			password2:{ 
                required: true,
				equalTo: "#password",
				minlength: 6,
				maxlength: 16,
          }, 
       },
       
       messages:{
        
            username:{
                required: "Это поле обязательно для заполнения",
                minlength: "Логин должен быть минимум 4 символа",
                maxlength: "Максимальное число символо - 16",
            },
            
            password:{
                required: true,
                minlength: "Пароль должен быть минимум 6 символа",
                maxlength: 16,
            },
			
			password2:{
                required: true,
				equalTo: "Пароли не совпадают",
                minlength: "Пароль должен быть минимум 6 символа",
                maxlength: 16,
            },
        
       }
        
    });


}); //end of ready