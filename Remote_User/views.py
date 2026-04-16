import os
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib import messages

from Remote_User.models import (
    ClientRegister_Model,
    cyber_attack_detection,
    ChatMessage
)

from Service_Provider.security import check_bruteforce, log_attack, detect_ddos


# --------------------------------------------------------------------
# SIMPLE USER PAGES
# --------------------------------------------------------------------
def login(request):
    ip = request.META.get('REMOTE_ADDR')

    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')

        # Check Brute Force before attempting login
        if check_bruteforce(ip, request=request):
            messages.error(request, "Too many login attempts from this IP. Please try again after 10 minutes.")
            return render(request, 'RUser/login.html')


        try:
            user = ClientRegister_Model.objects.get(username=username)
            if user.is_blocked:
                messages.error(request, "Your account is blocked due to 4 wrong password entries. Please contact admin.")
                log_attack(ip, f"Blocked User Login Attempt: {username}", "Intrusion", "Blocked", request=request)
                return render(request, 'RUser/login.html')

            if user.password == password:
                user.failed_login_attempts = 0
                user.save()
                request.session["userid"] = user.id
                messages.success(request, 'Login Successful!')
                return render(request, 'RUser/login.html', {'login_success': True})
            else:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 4:
                    user.is_blocked = True
                    log_attack(ip, f"User Blocked: {username} (4 wrong attempts)", "Brute Force", "Blocked", is_alert=True, request=request)
                    messages.error(request, "Your account has been blocked due to 4 wrong password entries.")
                else:
                    log_attack(ip, f"Login Failure: {username}", "Suspicious", "Warning", request=request)
                    messages.error(request, f"Invalid Password. Attempt {user.failed_login_attempts} of 4.")
                user.save()
        except ClientRegister_Model.DoesNotExist:
            log_attack(ip, f"Login Failure (Invalid User): {username}", "Suspicious", "Warning", request=request)
            messages.error(request, "User Not Found")


    return render(request, 'RUser/login.html')

def forgot_password(request):
    if request.method == "POST":
        username = request.POST.get('username')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if new_password != confirm_password:
            messages.error(request, "Passwords do not match!")
            return render(request, 'RUser/forgot_password.html')

        try:
            user = ClientRegister_Model.objects.get(username=username)
            user.password = new_password
            user.failed_login_attempts = 0
            user.is_blocked = False
            user.save()

            messages.success(request, "Password updated successfully!")
            return render(request, 'RUser/forgot_password.html', {'reset_success': True})
        except ClientRegister_Model.DoesNotExist:
            messages.error(request, "Invalid username! User not found.")
            return render(request, 'RUser/forgot_password.html')

    return render(request, 'RUser/forgot_password.html')


def index(request):
    ip = request.META.get('REMOTE_ADDR')
    if detect_ddos(ip, request=request):
        return HttpResponse("⚠️ Too many requests. Please slow down.", status=429)
    return render(request, 'RUser/index.html')


def Add_DataSet_Details(request):
    return render(request, 'RUser/Add_DataSet_Details.html', {"excel_data": ''})


def Register1(request):
    if request.method == "POST":
        username = request.POST.get('username')
        
        # Check if username already exists
        if ClientRegister_Model.objects.filter(username=username).exists():
            messages.error(request, 'invalid user name')
            return render(request, 'RUser/Register1.html')

        # Check if email already exists
        email = request.POST.get('email')
        if ClientRegister_Model.objects.filter(email=email).exists():
            messages.error(request, 'invalid email id')
            return render(request, 'RUser/Register1.html')

        # Check if phoneno already exists or is invalid
        phoneno = request.POST.get('phoneno')
        if not phoneno.isdigit() or len(phoneno) != 10:
            messages.error(request, 'invalid mobile number')
            return render(request, 'RUser/Register1.html')
            
        if ClientRegister_Model.objects.filter(phoneno=phoneno).exists():
            messages.error(request, 'invalid mobile number')
            return render(request, 'RUser/Register1.html')

        try:
            ClientRegister_Model.objects.create(
                username=username,
                email=email,
                password=request.POST.get('password'),
                phoneno=phoneno,
                country=request.POST.get('country'),
                state=request.POST.get('state'),
                city=request.POST.get('city'),
                address=request.POST.get('address'),
                gender=request.POST.get('gender'),
            )
            messages.success(request, 'Registered Successfully!')
            return render(request, 'RUser/Register1.html', {'redirect_to_login': True})
        except Exception as e:
            messages.error(request, f'Registration failed: {str(e)}')
            return render(request, 'RUser/Register1.html')

    return render(request, 'RUser/Register1.html')


def ViewYourProfile(request):
    user = ClientRegister_Model.objects.get(id=request.session['userid'])
    return render(request, 'RUser/ViewYourProfile.html', {'object': user})


# --------------------------------------------------------------------
# FULL FIXED PREDICTION VIEW
# --------------------------------------------------------------------
def Predict_Cyber_Attack_Type(request):

    if request.method == "POST":

        # extract all fields from form (but manually)
        Fid = request.POST.get('Fid')
        Timestamp = request.POST.get('Timestamp')
        Source_IP_Address = request.POST.get('Source_IP_Address')
        Destination_IP_Address = request.POST.get('Destination_IP_Address')
        Source_Port = request.POST.get('Source_Port')
        Destination_Port = request.POST.get('Destination_Port')
        Protocol = request.POST.get('Protocol')
        Packet_Length = request.POST.get('Packet_Length')
        Packet_Type = request.POST.get('Packet_Type')
        Traffic_Type = request.POST.get('Traffic_Type')
        Payload_Data = request.POST.get('Payload_Data')
        Malware_Indicators = request.POST.get('Malware_Indicators')
        Anomaly_Scores = request.POST.get('Anomaly_Scores')
        Alerts_Warnings = request.POST.get('Alerts_Warnings')
        Attack_Signature = request.POST.get('Attack_Signature')
        Action_Taken = request.POST.get('Action_Taken')
        Severity_Level = request.POST.get('Severity_Level')
        Device_Information = request.POST.get('Device_Information')
        Network_Segment = request.POST.get('Network_Segment')
        Geo_City_location_Data = request.POST.get('Geo_City_location_Data')
        Proxy_Information = request.POST.get('Proxy_Information')
        Firewall_Logs = request.POST.get('Firewall_Logs')
        IDS_IPS_Alerts = request.POST.get('IDS_IPS_Alerts')
        Log_Source = request.POST.get('Log_Source')

        # Advanced imports inside for speed/environment isolation
        import pandas as pd
        import numpy as np
        from sklearn.model_selection import train_test_split
        from sklearn.preprocessing import StandardScaler, OneHotEncoder
        from sklearn.compose import ColumnTransformer
        from sklearn.pipeline import Pipeline
        from sklearn.impute import SimpleImputer
        from sklearn.ensemble import RandomForestClassifier
        import joblib
        from django.conf import settings

        # 6. Load Model if exists, else fallback to quick training
        model_path = os.path.join(settings.BASE_DIR, 'trained_model.joblib')
        model_loaded = False
        if os.path.exists(model_path):
            try:
                clf = joblib.load(model_path)
                model_loaded = True
            except:
                pass
        
        if not model_loaded:
            # Fallback logic: Load data and train a quick model
            try:
                df = pd.read_csv(os.path.join(settings.BASE_DIR, 'Datasets.csv'))
                mapping = {"Malware": 0, "DDoS": 1, "Intrusion": 2, "Normal": 3}
                df["results"] = df["Attack_Type"].map(mapping)
                df = df.dropna(subset=['results'])

                num_features = ['Source_Port', 'Destination_Port', 'Packet_Length', 'Anomaly_Scores']
                cat_features = ['Protocol', 'Packet_Type', 'Traffic_Type', 'Severity_Level', 'Action_Taken', 'Network_Segment']
                
                for col in num_features:
                    df[col] = pd.to_numeric(df[col], errors='coerce')
                
                df = df.dropna(subset=num_features + cat_features)
                X = df[num_features + cat_features]
                y = df["results"]

                numeric_transformer = Pipeline(steps=[
                    ('imputer', SimpleImputer(strategy='median')),
                    ('scaler', StandardScaler())
                ])
                categorical_transformer = Pipeline(steps=[
                    ('imputer', SimpleImputer(strategy='constant', fill_value='missing')),
                    ('onehot', OneHotEncoder(handle_unknown='ignore'))
                ])
                preprocessor = ColumnTransformer(
                    transformers=[
                        ('num', numeric_transformer, num_features),
                        ('cat', categorical_transformer, cat_features)
                    ])

                clf = Pipeline(steps=[('preprocessor', preprocessor),
                                      ('classifier', RandomForestClassifier(n_estimators=10, random_state=42))])
                clf.fit(X, y)
            except Exception as e:
                messages.error(request, f"Model not trained and fallback failed: {str(e)}")
                return render(request, 'RUser/Predict_Cyber_Attack_Type.html')

        # 7. Predict on input data
        try:
            input_df = pd.DataFrame([{
                'Source_Port': pd.to_numeric(Source_Port, errors='coerce'),
                'Destination_Port': pd.to_numeric(Destination_Port, errors='coerce'),
                'Packet_Length': pd.to_numeric(Packet_Length, errors='coerce'),
                'Anomaly_Scores': pd.to_numeric(Anomaly_Scores, errors='coerce'),
                'Protocol': Protocol,
                'Packet_Type': Packet_Type,
                'Traffic_Type': Traffic_Type,
                'Severity_Level': Severity_Level,
                'Action_Taken': Action_Taken,
                'Network_Segment': Network_Segment,
                'Payload_Data': Payload_Data if Payload_Data else ""
            }])

            result = clf.predict(input_df)[0]
            
            # Label mapping back
            attack_type = {0: 'Malware', 1: 'DDoS', 2: 'Intrusion', 3: 'Normal'}.get(result)
            
            # Use specific attack labels as requested
            if attack_type == 'Normal':
                val = "No Cyber Attack Detected (Normal Traffic)"
            else:
                val = f"Cyber Attack Detected: {attack_type} Attack"
            
            # Logging if attack
            ip = request.META.get('REMOTE_ADDR')
            if attack_type in ['Intrusion', 'Malware', 'DDoS']:
                log_attack(ip, f"Detected {attack_type} via Persistent Model", attack_type, "Detected", request=request)
                if not model_loaded:
                    messages.warning(request, "Model was not pre-trained by admin. Result based on quick fallback model.")

            # Store in DB
            cyber_attack_detection.objects.create(
                Fid=Fid,
                Timestamp=Timestamp,
                Source_IP_Address=Source_IP_Address,
                Destination_IP_Address=Destination_IP_Address,
                Source_Port=Source_Port,
                Destination_Port=Destination_Port,
                Protocol=Protocol,
                Packet_Length=Packet_Length,
                Packet_Type=Packet_Type,
                Traffic_Type=Traffic_Type,
                Payload_Data=Payload_Data,
                Malware_Indicators=Malware_Indicators,
                Anomaly_Scores=Anomaly_Scores,
                Alerts_Warnings=Alerts_Warnings,
                Attack_Signature=Attack_Signature,
                Action_Taken=Action_Taken,
                Severity_Level=Severity_Level,
                Device_Information=Device_Information,
                Network_Segment=Network_Segment,
                Geo_City_location_Data=Geo_City_location_Data,
                Proxy_Information=Proxy_Information,
                Firewall_Logs=Firewall_Logs,
                IDS_IPS_Alerts=IDS_IPS_Alerts,
                Log_Source=Log_Source,
                Prediction=val
            )

            return render(request, 'RUser/Predict_Cyber_Attack_Type.html', {'objs': val})

        except Exception as e:
            messages.error(request, f"Error during prediction: {str(e)}")
            return render(request, 'RUser/Predict_Cyber_Attack_Type.html')

    return render(request, 'RUser/Predict_Cyber_Attack_Type.html')


def user_chatbot(request):
    if 'userid' not in request.session:
        return redirect('login')
    
    user = ClientRegister_Model.objects.get(id=request.session['userid'])
    chats = ChatMessage.objects.filter(user=user).order_by('timestamp')

    if request.method == "POST":
        message = request.POST.get('message')
        # Simplified AI logic
        ai_response = f"Hello {user.username}, I have received your query: '{message}'. An administrator will review it and get back to you shortly."
        
        ChatMessage.objects.create(
            user=user,
            message=message,
            response=ai_response
        )
        return redirect('user_chatbot')

    return render(request, 'RUser/chatbot.html', {'chats': chats})

def home_chatbot(request):
    """Stateless chatbot for the public home page support."""
    response = ""
    message = ""
    if request.method == "POST":
        message = request.POST.get('message', '').lower()
        if "login" in message or "sign in" in message:
            response = "To login, click the 'Login' link in the top navigation bar. You'll need your username and password. If you are an admin, use the 'Admin' link."
        elif "register" in message or "account" in message or "signup" in message:
            response = "New users can create an account by clicking 'Register' on the Login page. Account creation is required to use the AI prediction tools."
        elif "cyber" in message or "attack" in message or "predict" in message:
            response = "This system uses Machine Learning models like Random Forest and SVM to predict cyber attacks (e.g., DoS, Probe, R2L, U2R) in real-time based on network traffic data."
        elif "admin" in message:
            response = "Administrators can monitor all system activity, view security logs, unblock users, and train the AI models with new datasets."
        elif "governance" in message or "e-gov" in message:
            response = "Our portal supports e-Governance by providing a secure, transparent platform for public services, protected by real-time AI security monitoring."
        elif "real-time" in message or "monitoring" in message or "graph" in message:
            response = "The system features real-time security graphs and instant alerts for brute-force attacks and other suspicious activities."
        elif "help" in message or "how" in message:
            response = "I can help with: Login/Registration info, AI Attack Prediction details, Admin features, and E-Governance context. What specifically would you like to know?"
        elif "profile" in message:
            response = "Once logged in, you can view and edit your profile, and see your personal security history."
        elif "contact" in message or "support" in message:
            response = "For direct support, please log in and use the persistent AI Chatbot, which allows for direct communication with system administrators."
        else:
            response = "I'm the Home Support AI. I can tell you about our AI Attack Detection, E-Governance security, Registration, and Admin features. What would you like to know more about?"
            
    return render(request, "RUser/home_chatbot.html", {'response': response, 'message': message})

