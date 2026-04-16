from django.contrib import admin
from django.urls import path, re_path
from django.conf import settings
from django.conf.urls.static import static

from Remote_User import views as remoteuser
from Service_Provider import views as serviceprovider

urlpatterns = [
    # Remote User
    path('admin/', admin.site.urls),
    path('', remoteuser.index, name="index"),
    path('login/', remoteuser.login, name="login"),
    path('forgot_password/', remoteuser.forgot_password, name="forgot_password"),
    path('Register1/', remoteuser.Register1, name="Register1"),
    path('Predict_Cyber_Attack_Type/', remoteuser.Predict_Cyber_Attack_Type, name="Predict_Cyber_Attack_Type"),
    path('ViewYourProfile/', remoteuser.ViewYourProfile, name="ViewYourProfile"),

    # Service Provider
    path('serviceproviderlogin/', serviceprovider.serviceproviderlogin, name="serviceproviderlogin"),
    path('register_admin/', serviceprovider.register_admin, name="register_admin"),
    path('view_admins/', serviceprovider.view_admins, name="view_admins"),
    path('delete_admin/<str:username>/', serviceprovider.delete_admin, name="delete_admin"),
    path('forgot_password_admin/', serviceprovider.forgot_password_admin, name="forgot_password_admin"),
    path('View_Remote_Users/', serviceprovider.View_Remote_Users, name="View_Remote_Users"),
    path('delete_user/<int:pk>/', serviceprovider.delete_user, name="delete_user"),
    path('View_Prediction_Of_Cyber_Attack_Type/', serviceprovider.View_Prediction_Of_Cyber_Attack_Type, name="View_Prediction_Of_Cyber_Attack_Type"),
    path('View_Prediction_Of_Cyber_Attack_Type_Ratio/', serviceprovider.View_Prediction_Of_Cyber_Attack_Type_Ratio, name="View_Prediction_Of_Cyber_Attack_Type_Ratio"),

    path('charts/<str:chart_type>/', serviceprovider.charts, name="charts"),
    path('charts1/<str:chart_type>/', serviceprovider.charts1, name="charts1"),
    path('likeschart/<str:like_chart>/', serviceprovider.likeschart, name="likeschart"),

    path('train_model/', serviceprovider.train_model, name="train_model"),
    path('Download_Predicted_DataSets/', serviceprovider.Download_Predicted_DataSets, name="Download_Predicted_DataSets"),
    path('Download_User_Data/', serviceprovider.Download_User_Data, name="Download_User_Data"),
    path('attack_logs/', serviceprovider.view_attack_logs, name="attack_logs"),
    path('attack_ratio_graph/', serviceprovider.Attack_Ratio_Graph, name="attack_ratio_graph"),
    path('get_attack_counts/', serviceprovider.get_attack_counts, name="get_attack_counts"),
    path('delete_attack_log/<int:pk>/', serviceprovider.delete_attack_log, name="delete_attack_log"),
    path('unblock_user/<int:pk>/', serviceprovider.unblock_user, name="unblock_user"),
    path('unblock_admin/<str:username>/', serviceprovider.unblock_admin, name="unblock_admin"),
    path('user_chatbot/', remoteuser.user_chatbot, name="user_chatbot"),
    path('view_user_queries/', serviceprovider.view_user_queries, name="view_user_queries"),
    path('admin_reply/<int:pk>/', serviceprovider.admin_reply, name="admin_reply"),
    path('home_chatbot/', remoteuser.home_chatbot, name="home_chatbot"),
]




if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
