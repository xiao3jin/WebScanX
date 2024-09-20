from os import path

from django.conf.urls import url,static

from webscan import settings
from . import views
from django.views.decorators.csrf import csrf_exempt


urlpatterns = [

    url(r'^myinfo/', csrf_exempt(views.MyInfo.as_view())),
    url(r'^userman/', csrf_exempt(views.UserManager.as_view())),
    url(r'^deluser/', csrf_exempt(views.del_user)),
    url(r'^fingertype/', csrf_exempt(views.finger_type)),
    url(r'^delfingertype/', csrf_exempt(views.del_finger_type)),
    url(r'^addfingertype/', csrf_exempt(views.AddFingerType.as_view())),
    url(r'^delfinger/', csrf_exempt(views.del_finger)),
    url(r'^run_nuclei_scan/$', csrf_exempt(views.run_nuclei_scan), name='run_nuclei_scan'),
    url(r'^port_scan/$', csrf_exempt(views.masscan_scan), name='port_scan'),
    url(r'^stop_port_scan/$', csrf_exempt(views.stop_portscan), name='stop_port_scan'),
    url(r'^scan_form/$', csrf_exempt(views.scan_form), name='scan_form'),
    url(r'^upload-fingers/$', csrf_exempt(views.upload_fingers), name='upload_fingers'),
    url(r'^finger_list/$', csrf_exempt(views.finger_list), name='finger_list'),

    url(r'^run_nuclei_scan/$', csrf_exempt(views.run_nuclei_scan), name='run_nuclei_scan'),
    url(r'^download_results/$', views.download_results, name='download_results'),  # 下载结果文件
    url(r'^stop_scan/$', csrf_exempt(views.stop_scan), name='scan_form'),
    url(r'^check_scan_status/$', csrf_exempt(views.check_scan_status), name='check_scan_status'),
    url(r'^get_poc_templates/$', views.get_poc_templates, name='get_poc_templates'),  # 添加新路由
    url(r'^pocmanage/$', csrf_exempt(views.poc_manage), name='manage_poc'),  # 添加新路由
    url(r'^upload_poc/$', csrf_exempt(views.upload_poc), name='upload_poc'),  # 添加新路由
    url(r'^get_poc_folders/$', csrf_exempt(views.get_poc_folders), name='get_poc_folders'),  # 添加新路由
    url(r'^create_folder/$', csrf_exempt(views.create_folder), name='create_folder'),  # 添加新路由
    url(r'^port_scan_form/$', csrf_exempt(views.port_scan_form), name='port_scan'),  # 添加新路由

    url(r'^finger_scan_form/$', csrf_exempt(views.finger_scan_form), name='finger_scan_form'),  # 添加新路由
    url(r'^finger_scan/$', csrf_exempt(views.finger_scan), name='finger_scan'),  # 添加新路由
    url(r'^stop_finger_scan/$', csrf_exempt(views.stop_fingerscan), name='stop_finger_scan'),  # 添加新路由

    url(r'^fingerman/', csrf_exempt(views.all_finger)),
    url(r'^addfinger/', csrf_exempt(views.add_fingers)),
    url(r'^adduser/', csrf_exempt(views.AddUser.as_view())),

    url(r'^get_ehole_config/$', csrf_exempt(views.get_ehole_config), name='get_ehole_config'),
    url(r'^update_ehole_config/$', csrf_exempt(views.update_ehole_config), name='update_ehole_config'),

    url(r'^', csrf_exempt(views.Index.as_view())),

]

# urlpatterns += static.static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

