import os
import json
from django.db.models import Avg
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.conf import settings
from django.contrib import messages

from Remote_User.models import (
    ClientRegister_Model,
    cyber_attack_detection,
    detection_ratio,
    detection_accuracy,
    ChatMessage
)

from Service_Provider.models import AttackLog
from Service_Provider.security import detect_ddos, log_attack

# ---------------------------------------------
# ADMIN LOGIN CREDENTIALS HELPER
# ---------------------------------------------
ADMIN_CREDENTIALS_FILE = os.path.join(settings.BASE_DIR, 'admin_credentials.json')

def get_admin_credentials():
    if os.path.exists(ADMIN_CREDENTIALS_FILE):
        try:
            with open(ADMIN_CREDENTIALS_FILE, 'r') as f:
                data = json.load(f)
                if isinstance(data, dict):
                    # Migration from old format
                    return [data]
                return data
        except json.JSONDecodeError:
            pass
    return [{"username": "admin", "password": "admin"}]

def set_admin_credentials(creds_list):
    with open(ADMIN_CREDENTIALS_FILE, 'w') as f:
        json.dump(creds_list, f)

def get_admin_user(username):
    for user in get_admin_credentials():
        if user["username"] == username:
            return user
    return None


# ---------------------------------------------
# ADMIN LOGIN & REGISTER
# ---------------------------------------------
def serviceproviderlogin(request):
    ip = request.META.get('REMOTE_ADDR')
    if detect_ddos(ip, request=request):
        return HttpResponse("⚠️ Too many requests. DDoS protection active.", status=429)

    if request.method == "POST":
        admin = request.POST.get("username")
        password = request.POST.get("password")
        
        # Check Brute Force before attempting login (Added for Admin too)
        from Service_Provider.security import check_bruteforce
        if check_bruteforce(ip, request=request):
            messages.error(request, "Too many login attempts from this IP. Please try again after 10 minutes.")
            return render(request, "SProvider/serviceproviderlogin.html")

        creds_list = get_admin_credentials()

        admin_found = False
        
        for user in creds_list:
            if user["username"] == admin:
                admin_found = True
                if user.get("is_blocked"):
                    messages.error(request, "Your admin account is blocked due to 4 wrong password entries. Please contact primary admin.")
                    log_attack(ip, f"Blocked Admin Login Attempt: {admin}", "Intrusion", "Blocked", request=request)
                    return render(request, "SProvider/serviceproviderlogin.html")

                if user["password"] == password:
                    user["failed_attempts"] = 0
                    set_admin_credentials(creds_list)
                    request.session['admin_id'] = admin # Set admin session
                    detection_accuracy.objects.all().delete()
                    messages.success(request, 'Login Successful!')
                    return render(request, "SProvider/serviceproviderlogin.html", {'login_success': True})
                else:
                    user["failed_attempts"] = user.get("failed_attempts", 0) + 1
                    if user["failed_attempts"] >= 4:
                        user["is_blocked"] = True
                        log_attack(ip, f"Admin Blocked: {admin} (4 wrong attempts)", "Brute Force", "Blocked", is_alert=True, request=request)
                        messages.error(request, "Your admin account has been blocked due to 4 wrong password entries.")
                    else:
                        log_attack(ip, f"Admin Login Failure: {admin}", "Suspicious", "Warning", request=request)
                        messages.error(request, f"Invalid Admin Password. Attempt {user['failed_attempts']} of 4.")
                    set_admin_credentials(creds_list)
                    break
        
        if not admin_found:
            log_attack(ip, f"Admin Login Failure (Invalid Admin): {admin}", "Suspicious", "Warning", request=request)
            messages.error(request, 'Admin Not Found')

    return render(request, "SProvider/serviceproviderlogin.html")


def view_admins(request):
    admins = get_admin_credentials()
    return render(request, "SProvider/view_admins.html", {"admins": admins})


def delete_admin(request, username):
    if username == "lava":
        messages.error(request, "Cannot delete the Master Admin!")
        return redirect('view_admins')
        
    creds_list = get_admin_credentials()
    new_creds = [u for u in creds_list if u["username"] != username]
    
    if len(new_creds) < len(creds_list):
        set_admin_credentials(new_creds)
        messages.success(request, f"Admin '{username}' deleted successfully!")
    else:
        messages.error(request, f"Admin '{username}' not found!")
        
    return redirect('view_admins')


def register_admin(request):
    if request.method == "POST":
        auth_username = request.POST.get("auth_username")
        auth_password = request.POST.get("auth_password")
        username = request.POST.get("username")
        password = request.POST.get("password")
        
        # Authenticate the creator
        auth_user = get_admin_user(auth_username)
        if not auth_user or auth_user["password"] != auth_password:
            messages.error(request, 'Authorization Failed: Invalid Main Admin Credentials!')
            return render(request, "SProvider/register_admin.html")
        
        if get_admin_user(username):
            messages.error(request, 'Username already exists!')
            return render(request, "SProvider/register_admin.html")
            
        creds_list = get_admin_credentials()
        creds_list.append({"username": username, "password": password})
        set_admin_credentials(creds_list)
        
        messages.success(request, 'Admin Registered Successfully!')
        return render(request, "SProvider/register_admin.html", {'register_success': True})
        
    return render(request, "SProvider/register_admin.html")


def forgot_password_admin(request):
    if request.method == "POST":
        username = request.POST.get('username')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if new_password != confirm_password:
            messages.error(request, "Passwords do not match!")
            return render(request, 'SProvider/forgot_password_admin.html')

        creds_list = get_admin_credentials()
        updated = False
        for user in creds_list:
            if user["username"] == username:
                user["password"] = new_password
                user["failed_attempts"] = 0
                user["is_blocked"] = False
                updated = True
                break

                
        if updated:
            set_admin_credentials(creds_list)
            messages.success(request, "Admin Password updated successfully!")
            return render(request, 'SProvider/forgot_password_admin.html', {'reset_success': True})
        else:
            messages.error(request, "Admin Not Found!")
            return render(request, 'SProvider/forgot_password_admin.html')

    return render(request, 'SProvider/forgot_password_admin.html')


# ---------------------------------------------
# USER LIST
# ---------------------------------------------
def View_Remote_Users(request):
    if 'admin_id' not in request.session:
        log_attack(request.META.get('REMOTE_ADDR'), "Unauthorized Access Attempt to Users List", "Intrusion", "Blocked", request=request)
        return HttpResponse("Unauthorized Access", status=403)
    return render(
        request,
        "SProvider/View_Remote_Users.html",
        {"objects": ClientRegister_Model.objects.all()}
    )


# ---------------------------------------------
# DELETE USER
# ---------------------------------------------
def delete_user(request, pk):
    ClientRegister_Model.objects.filter(id=pk).delete()
    return redirect("View_Remote_Users")


# ---------------------------------------------
# PREDICTION RATIO
# ---------------------------------------------
def View_Prediction_Of_Cyber_Attack_Type_Ratio(request):

    detection_ratio.objects.all().delete()

    def calc_ratio(keyword):
        total = cyber_attack_detection.objects.count()
        if total == 0:
            return
        count = cyber_attack_detection.objects.filter(Prediction=keyword).count()
        ratio = (count / total) * 100
        if ratio > 0:
            detection_ratio.objects.create(names=keyword, ratio=ratio)

    for key in ["DDoS", "Intrusion", "Malware", "Normal"]:
        calc_ratio(key)

    return render(
        request,
        "SProvider/View_Prediction_Of_Cyber_Attack_Type_Ratio.html",
        {"objs": detection_ratio.objects.all()}
    )


# ---------------------------------------------
# CHARTS
# ---------------------------------------------
def charts(request, chart_type):
    chart = detection_ratio.objects.values("names").annotate(dcount=Avg("ratio"))
    return render(request, "SProvider/charts.html", {"form": chart, "chart_type": chart_type})


def charts1(request, chart_type):
    chart = detection_accuracy.objects.values("names").annotate(dcount=Avg("ratio"))
    return render(request, "SProvider/charts1.html", {"form": chart, "chart_type": chart_type})


def likeschart(request, like_chart):
    chart = detection_accuracy.objects.values("names").annotate(dcount=Avg("ratio"))
    return render(request, "SProvider/likeschart.html", {"form": chart, "like_chart": like_chart})


# ---------------------------------------------
# VIEW PREDICTIONS
# ---------------------------------------------
def View_Prediction_Of_Cyber_Attack_Type(request):
    return render(
        request,
        "SProvider/View_Prediction_Of_Cyber_Attack_Type.html",
        {"list_objects": cyber_attack_detection.objects.all()}
    )


# ---------------------------------------------
# DOWNLOAD PREDICTED DATA
# ---------------------------------------------
def Download_Predicted_DataSets(request):

    from openpyxl import Workbook  # safe here

    response = HttpResponse(
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
    response["Content-Disposition"] = 'attachment; filename="Predicted_Datasets.xlsx"'

    wb = Workbook()
    ws = wb.active
    ws.title = "Predicted"

    headers = [
        field.name for field in cyber_attack_detection._meta.fields
    ]
    ws.append(headers)

    for obj in cyber_attack_detection.objects.all():
        ws.append([getattr(obj, field) for field in headers])

    wb.save(response)
    return response


# ---------------------------------------------
# DOWNLOAD USER DATA
# ---------------------------------------------
def Download_User_Data(request):
    from openpyxl import Workbook
    response = HttpResponse(content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    response["Content-Disposition"] = 'attachment; filename="Remote_Users_Data.xlsx"'
    wb = Workbook()
    ws = wb.active
    ws.title = "Users"
    headers = [field.name for field in ClientRegister_Model._meta.fields]
    ws.append(headers)
    for obj in ClientRegister_Model.objects.all():
        ws.append([getattr(obj, field) for field in headers])
    wb.save(response)
    return response


# ---------------------------------------------
# TRAIN MODEL (FAST after first run)
# ---------------------------------------------
def train_model(request):

    # Clear previous results to avoid duplicates as requested
    detection_accuracy.objects.all().delete()

    # Advanced imports
    import pandas as pd
    import numpy as np
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler, OneHotEncoder
    from sklearn.compose import ColumnTransformer
    from sklearn.pipeline import Pipeline
    from sklearn.impute import SimpleImputer
    from sklearn.metrics import accuracy_score, classification_report
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.neural_network import MLPClassifier
    from sklearn.tree import DecisionTreeClassifier
    from xgboost import XGBClassifier
    from imblearn.over_sampling import SMOTE
    from imblearn.pipeline import Pipeline as ImbPipeline
    from sklearn.feature_extraction.text import TfidfVectorizer
    import joblib

    # Load dataset
    df = pd.read_csv(os.path.join(settings.BASE_DIR, "Datasets.csv"))

    # 1. Data Cleaning
    df = df.drop_duplicates()
    
    # 2. Map target
    mapping = {"Malware": 0, "DDoS": 1, "Intrusion": 2, "Normal": 3}
    df["results"] = df["Attack_Type"].map(mapping)
    
    # 3. Feature Selection
    num_features = ['Source_Port', 'Destination_Port', 'Packet_Length', 'Anomaly_Scores']
    cat_features = ['Protocol', 'Packet_Type', 'Traffic_Type', 'Severity_Level', 'Action_Taken', 'Network_Segment']
    text_feature = 'Payload_Data'
    
    for col in num_features:
        df[col] = pd.to_numeric(df[col], errors='coerce')

    # Drop rows with NaN in results or key features if any
    df = df.dropna(subset=['results'] + num_features + cat_features + [text_feature])

    X = df[num_features + cat_features + [text_feature]]
    y = df["results"]

    # 4. Preprocessing Pipeline
    numeric_transformer = Pipeline(steps=[
        ('imputer', SimpleImputer(strategy='median')),
        ('scaler', StandardScaler())
    ])

    categorical_transformer = Pipeline(steps=[
        ('imputer', SimpleImputer(strategy='constant', fill_value='missing')),
        ('onehot', OneHotEncoder(handle_unknown='ignore'))
    ])

    # For text, we'll use Tfidf
    text_transformer = Pipeline(steps=[
        ('tfidf', TfidfVectorizer(max_features=100))
    ])

    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numeric_transformer, num_features),
            ('cat', categorical_transformer, cat_features),
            ('text', text_transformer, text_feature)
        ])

    # 5. Split data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # 6. Define Models - FAST VERSION (PRE-TUNED)
    models_to_run = [
        ("XGBoost Classifier", XGBClassifier(n_estimators=100, max_depth=6, random_state=42, use_label_encoder=False, eval_metric='mlogloss')),
        ("Random Forest Classifier", RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42)),
        ("Artificial Neural Network (ANN)", MLPClassifier(max_iter=300, hidden_layer_sizes=(50,), random_state=42)),
        ("Gradient Boosting Classifier", GradientBoostingClassifier(n_estimators=100, random_state=42)),
        ("Decision Tree Classifier", DecisionTreeClassifier(max_depth=10, random_state=42))
    ]

    objs = []
    
    for name, model in models_to_run:
        pipeline = ImbPipeline(steps=[
            ('preprocessor', preprocessor),
            ('smote', SMOTE(random_state=42)),
            ('model', model)
        ])
        
        # Fast fit without RandomizedSearchCV
        pipeline.fit(X_train, y_train)
        y_pred = pipeline.predict(X_test)
        acc = accuracy_score(y_test, y_pred) * 100
        
        objs.append(detection_accuracy(names=name, ratio=acc))

    detection_accuracy.objects.bulk_create(objs)

    # Save the best model for real-time prediction (using the first one as a default best for now)
    # or iterate to find the max accuracy.
    best_acc = 0
    best_pipeline = None
    for name, model in models_to_run:
        # Re-run a simple pipeline for accuracy comparison if needed, 
        # but here we can just pick the last trained one if we want.
        # Let's pick Random Forest as a reliable default if XGBoost is not first.
        if "Random Forest" in name:
            best_pipeline = ImbPipeline(steps=[
                ('preprocessor', preprocessor),
                ('model', model)
            ])
            best_pipeline.fit(X_train, y_train) # Fit without SMOTE for prediction speed if possible? 
                                                # Actually SMOTE is only during fit anyway.
            break
    
    if best_pipeline:
        model_path = os.path.join(settings.BASE_DIR, 'trained_model.joblib')
        joblib.dump(best_pipeline, model_path)

    return render(
        request,
        "SProvider/train_model.html",
        {"objs": detection_accuracy.objects.all()}
    )

def view_attack_logs(request):
    if 'admin_id' not in request.session:
        log_attack(request.META.get('REMOTE_ADDR'), "Unauthorized Access Attempt to Attack Logs", "Intrusion", "Blocked", request=request)
        return HttpResponse("Unauthorized Access", status=403)
    
    logs = AttackLog.objects.all().order_by('-timestamp')
    return render(request, "SProvider/attack_logs.html", {"logs": logs})

def delete_attack_log(request, pk):
    if 'admin_id' not in request.session:
        return HttpResponse("Unauthorized", status=403)
    AttackLog.objects.filter(id=pk).delete()
    return redirect('attack_logs')

def Attack_Ratio_Graph(request):
    if 'admin_id' not in request.session:
        return HttpResponse("Unauthorized Access", status=403)
    
    # Calculate counts
    ddos_count = AttackLog.objects.filter(attack_type='DDoS').count()
    brute_count = AttackLog.objects.filter(attack_type='Brute Force').count()
    intrusion_count = AttackLog.objects.filter(attack_type='Intrusion').count()
    suspicious_count = AttackLog.objects.filter(attack_type='Suspicious').count()
    
    context = {
        'ddos': ddos_count,
        'brute': brute_count,
        'intrusion': intrusion_count,
        'suspicious': suspicious_count,
    }
    return render(request, 'SProvider/Attack_Ratio_Graph.html', context)

from django.http import JsonResponse
def get_attack_counts(request):
    data = {
        "ddos": AttackLog.objects.filter(attack_type='DDoS').count(),
        "brute": AttackLog.objects.filter(attack_type='Brute Force').count(),
        "intrusion": AttackLog.objects.filter(attack_type='Intrusion').count(),
        "suspicious": AttackLog.objects.filter(attack_type='Suspicious').count(),
    }
    return JsonResponse(data)

def unblock_user(request, pk):
    if 'admin_id' not in request.session:
        return HttpResponse("Unauthorized", status=403)
    user = ClientRegister_Model.objects.get(id=pk)
    user.is_blocked = False
    user.failed_login_attempts = 0
    user.save()
    messages.success(request, f"User {user.username} unblocked successfully.")
    return redirect('View_Remote_Users')

def unblock_admin(request, username):
    if 'admin_id' not in request.session:
        return HttpResponse("Unauthorized", status=403)
    
    creds_list = get_admin_credentials()
    updated = False
    for user in creds_list:
        if user["username"] == username:
            user["is_blocked"] = False
            user["failed_attempts"] = 0
            updated = True
            break
    
    if updated:
        set_admin_credentials(creds_list)
        messages.success(request, f"Admin {username} unblocked successfully.")
    return redirect('view_admins')

def view_user_queries(request):
    if 'admin_id' not in request.session:
        return HttpResponse("Unauthorized", status=403)
    queries = ChatMessage.objects.all().order_by('-timestamp')
    return render(request, 'SProvider/user_queries.html', {'queries': queries})

def admin_reply(request, pk):
    if 'admin_id' not in request.session:
        return HttpResponse("Unauthorized", status=403)
    
    query = ChatMessage.objects.get(id=pk)
    if request.method == "POST":
        reply = request.POST.get('reply')
        query.response = reply
        query.save()
        messages.success(request, "Reply sent successfully.")
        return redirect('view_user_queries')
    
    return render(request, 'SProvider/admin_reply.html', {'query': query})


