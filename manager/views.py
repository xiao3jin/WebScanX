import configparser
import os
import re
import subprocess
import threading
import time
import json
import datetime
import pandas as pd
from django.core.files.storage import FileSystemStorage
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
import subprocess
from django.views.decorators.csrf import csrf_exempt
# from .scan_functions import SubdomainExplosion, DirScan, PortScanner, nuclei_scan, FoundationInfo, Fofa_Api
from django.core.paginator import Paginator
from django.http import JsonResponse, FileResponse
from django.shortcuts import render, redirect
from django.views import View
import settings
from .models import ManUser, Users, Fingers, Finger_type


# Create your views here.
def user_required(view_func):
    def wrapped_view(request, *args, **kwargs):
        if request.session.get('uid', '') == '':
            return redirect('/manager/')  # 重定向到登录页面
        return view_func(request, *args, **kwargs)

    return wrapped_view


class Index(View):
    def get(self, request):
        return render(request, 'man/manlogin.html')

    def post(self, request):
        name = request.POST.get('name', '')
        pwd = request.POST.get('pwd', '')
        try:
            us = ManUser.objects.get(uname=name, upwd=pwd)
            request.session['uid'] = us.id
            return redirect('/manager/myinfo/')
        except:
            msg = '账号或密码错误!'
            return render(request, 'man/manlogin.html', {'msg': msg})


# 我的信息
class MyInfo(View):
    def get(self, request):
        if request.session.get('uid', '') == '':
            return redirect('/manager/')
        us = ManUser.objects.get(id=request.session.get('uid'))
        return render(request, 'man/maninfo.html', context={'us': us})

    def post(self, request):
        if request.session.get('uid', '') == '':
            return redirect('/manager/')  # 防止未授权
        name = request.POST.get('name', '')
        pwd = request.POST.get('pwd', '')
        us = ManUser.objects.get(id=1)
        us.uname = name
        us.upwd = pwd
        us.save()
        return redirect('/manager/myinfo/')


class UserManager(View):
    def get(self, request):
        if request.session.get('uid', '') == '':
            return redirect('/manager/')
        all_user = Users.objects.all()
        items_per_page = request.GET.get('items_per_page', 10)  # 获取自定义的每页数据量，默认为10
        paginator = Paginator(all_user, items_per_page)  # 分页器
        page_number = request.GET.get('page')  # 获取当前页码
        page_obj = paginator.get_page(page_number or 1)  # 默认显示第一页

        return render(request, 'man/userman.html', context={'all_user': all_user, 'items_per_page': items_per_page})


class AddUser(View):
    def get(self, request):
        if request.session.get('uid', '') == '':
            return redirect('/manager/')
        return render(request, 'man/adduser.html')

    def post(self, request):
        if request.session.get('uid', '') == '':
            return redirect('/manager/')  # 防止未授权
        name = request.POST.get('name', '')
        pwd = request.POST.get('pwd', '')
        Users.objects.create(
            uname=name,
            upwd=pwd,
            create_time=time.strftime('%Y-%m-%d %H:%M:', time.localtime())

        )
        return redirect('/manager/userman/')


def del_user(request):
    if request.session.get('uid', '') == '':
        return redirect('/manager/')
    id = request.GET.get('id')
    type = request.GET.get('type')
    if type == '1':
        Users.objects.get(id=id).delete()
    elif type == '2':
        u = Users.objects.get(id=id)
        u.status = 0
        u.save()
    else:
        u = Users.objects.get(id=id)
        u.status = 1
        u.save()
    return redirect('/manager/userman/')


def all_finger(request):
    # all_fingers = Fingers.objects.all()
    # return render(request, 'man/allfinger.html', context={'all_fingers': all_fingers})
    all_fingers = Fingers.objects.all()  # 获取所有指纹数据
    items_per_page = request.GET.get('items_per_page', 5)  # 获取自定义的每页数据量，默认为10
    paginator = Paginator(all_fingers, items_per_page)  # 分页器
    page_number = request.GET.get('page')  # 获取当前页码
    page_obj = paginator.get_page(page_number or 1)  # 默认显示第一页

    return render(request, 'man/allfinger.html', {'page_obj': page_obj, 'items_per_page': items_per_page})


def add_fingers(request):
    if request.method == 'POST':
        cmsname = request.POST.get('cmsname', '')
        keyword = request.POST.get('keyword', '')
        location = request.POST.get('location', '')
        method = request.POST.get('method', '')
        Fingers.objects.create(
            cmsname=cmsname,
            keyword=keyword,
            location=location,
            method=method,
        )
        return redirect('/manager/fingerman/')
    else:
        return render(request, 'man/addfinger.html')


def del_finger(request):
    id = request.GET.get('id', '')
    Fingers.objects.get(id=id).delete()
    return redirect('/manager/fingerman/')


# 所有指纹分类
def finger_type(request):
    all_finger_type = Finger_type.objects.all()
    return render(request, 'man/finger_type.html', {"all_finger_type": all_finger_type})


# 添加指纹分类
class AddFingerType(View):
    def get(self, request):
        return render(request, 'man/addfingertype.html')

    def post(self, request):
        name = request.POST.get('name', '')
        Finger_type.objects.create(name=name)
        return redirect('/manager/fingertype/')


# 删除指纹分类
def del_finger_type(request):
    id = request.GET.get('id')
    Finger_type.objects.get(id=id).delete()
    return redirect('/manager/fingertype/')


def upload_fingers(request):
    if request.method == 'POST':
        file = request.FILES.get('fingerfile')
        if file:
            # 获取当前目录并构建保存路径
            sava_finger_directory = os.path.join(original_directory, 'tools', 'ehole_windows')
            os.makedirs(sava_finger_directory, exist_ok=True)  # 确保目录存在

            # 保存文件
            finger_file_path = os.path.join(sava_finger_directory, 'finger.json')
            with open(finger_file_path, 'wb') as f:
                for chunk in file.chunks():
                    f.write(chunk)

            # 读取并处理 JSON 数据
            try:
                with open(finger_file_path, 'r', encoding='utf-8') as f:
                    data = f.read()
                    fingerprints = json.loads(data)
                    for item in fingerprints.get('fingerprint', []):
                        Fingers.objects.create(
                            cmsname=item['cms'],
                            keyword=','.join(item['keyword']),
                            location=item['location'],
                            method=item['method']
                        )
                return JsonResponse({'status': 'success', 'message': '指纹导入成功。'})
            except json.JSONDecodeError:
                return JsonResponse({'status': 'error', 'message': '无效的JSON格式'})
        else:
            return JsonResponse({'status': 'error', 'message': '未提供文件'})
    return JsonResponse({'status': 'error', 'message': '无效的请求'})


def finger_list(request):
    all_fingers = Fingers.objects.all()  # 获取所有指纹数据
    paginator = Paginator(all_fingers, 10)  # 每页显示10个数据
    page_number = request.GET.get('page')  # 获取当前页码
    page_obj = paginator.get_page(page_number)  # 获取当前页的数据

    return render(request, '/manager/fingerman/', {'page_obj': page_obj})


def scan_form(request):
    if request.method == 'POST':
        target_urls = request.POST.get('target_url')
        if target_urls:
            return run_nuclei_scan(request)
    return render(request, 'man/scan_form.html')


# def nuclei_scan
# 后台执行 Nuclei 扫描的函数
# def nuclei_scan(target_urls, scan_type, template_paths, author='', tags='', severity='', tc=''):
#     try:
#         # 目标可以是单个 URL 或者文件路径
#         if scan_type == 'batch':
#             command = [
#                 'F:\\PyProject\\DYAQ\\day17\\webscan\\tools\\nuclei.exe',
#                 '-l',
#                 target_urls
#             ]
#         else:
#             command = [
#                 'F:\\PyProject\\DYAQ\\day17\\webscan\\tools\\nuclei.exe',
#                 '-u',
#                 target_urls
#             ]
#
#         # 如果有多个模板路径，则逐个添加 '-t' 参数
#         if template_paths:
#             print(template_paths)
#             template_paths = [item.strip() for item in template_paths.split(',')]
#             for tpl in template_paths:
#                 command.extend(['-t', os.path.join('nuc_poc\\http', tpl)])
#         # else:
#         #     command = [
#         #         'F:\\PyProject\\DYAQ\\day17\\webscan\\tools\\nuclei.exe',
#         #         '-u',
#         #         target_urls
#         #     ]
#         # 添加其他过滤器参数
#         if author:
#             command.extend(['-author', author])
#         if tags:
#             command.extend(['-tags', tags])
#         if severity:
#             command.extend(['-severity', severity])
#         if tc:
#             command.extend(['-tc', tc])
#
#         # 输出文件根据目标名称命名
#         if scan_type == 'single':
#             target_name = target_urls.replace('http://', '').replace('https://', '').replace('/', '_')
#             current_time = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')  # 格式化为 YYYYMMDD_HHMMSS
#             output_file = f'results_{current_time}.txt'  # 每次运行生成不同的文件名
#         else:
#             output_file = 'scan_output.txt'
#
#         command.extend(['-o', output_file])
#
#         # 执行扫描命令
#         print("执行命令:", ' '.join(command))
#         result = subprocess.run(command, capture_output=True, text=True)
#
#         # 将扫描结果保存到文件中
#         with open(output_file, 'w', encoding='utf-8') as f:
#             if result.returncode == 0:
#                 f.write(f"Scan succeeded:\n{result.stdout}")
#             else:
#                 f.write(f"Error during scan:\n{result.stderr}")
#
#     except Exception as e:
#         with open('scan_output.txt', 'w', encoding='utf-8') as f:
#             f.write(f"Exception during scan: {str(e)}")

# Django 视图函数
# 用于控制扫描是否停止的全局变量
# 用于保存扫描状态
scan_status = {
    'running': False,
    'finished': False,
    'status_message': ''
}

file_path = ''


def nuclei_scan(target_urls, scan_type, template_paths, author='', tags='', severity='', tc=''):
    nuclei_directory = os.path.join(original_directory, 'tools')
    os.chdir(nuclei_directory)
    global scan_status
    global file_path
    try:
        # 目标可以是单个 URL 或者文件路径
        if scan_type == 'batch':
            command = [
                '.\\nuclei.exe',
                '-l',
                target_urls
            ]
        else:
            command = [
                '.\\nuclei.exe',
                '-u',
                target_urls
            ]

        # 如果有多个模板路径，则逐个添加 '-t' 参数
        if template_paths:
            # print(template_paths)
            template_paths = [item.strip() for item in template_paths.split(',')]
            for tpl in template_paths:
                command.extend(['-t', os.path.join('nuc_poc\\http', tpl)])

        # 添加其他过滤器参数
        if author:
            command.extend(['-author', author])
        if tags:
            command.extend(['-tags', tags])
        if severity:
            command.extend(['-severity', severity])
        if tc:
            command.extend(['-tc', tc])

        # 输出文件根据目标名称命名
        if scan_type == 'single':
            target_name = target_urls.replace('http://', '').replace('https://', '').replace('/', '_')
            current_time = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f'results_{current_time}.txt'
        else:
            output_file = 'scan_output.txt'

        command.extend(['-o', output_file])

        # 执行扫描命令，并允许在运行时检查停止标志
        print("执行命令:", ' '.join(command))
        result = subprocess.run(command, capture_output=True, text=True)
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # 实时读取输出，检查停止标志
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(output.strip())
                # 在这里可以添加对输出的进一步处理，比如实时更新状态等

            # 检查是否需要停止扫描
            scan_status['status_message'] = "扫描完成！"
            scan_status['finished'] = True

        # 等待进程结束并获取结果
        stdout, stderr = process.communicate()

        # 将扫描结果保存到文件中
        with open(output_file, 'w', encoding='utf-8') as f:
            if result.returncode == 0:
                f.write(f"Scan succeeded:\n{result.stdout}")
            else:
                f.write(f"Error during scan:\n{result.stderr}")

        print("生成的输出文件路径: " + nuclei_directory + "\\" + output_file)

        file_path = nuclei_directory + "\\" + output_file
        os.chdir(original_directory)
        return nuclei_directory + "\\" + output_file  # 返回生成的输出文件路径

    except Exception as e:
        output_file = 'scan_output.txt'
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"Exception during scan: {str(e)}")
            os.chdir(original_directory)
        return nuclei_directory + "\\" + output_file  # 返回错误文件路径


# def run_nuclei_scan(request):
#     if request.method == 'POST':
#         target_urls = request.POST.get('target_url', '')
#         scan_type = request.POST.get('scan_type', 'all')
#         template_path = request.POST.get('template_path', '')
#         author = request.POST.get('author', '')
#         tags = request.POST.get('tags', '')
#         severity = request.POST.get('severity', '')
#         tc = request.POST.get('tc', '')
#
#         # 处理选中的 POC 模板
#         selected_pocs = request.POST.getlist('poc_templates')  # 这需要在表单中加个对复选框的定义
#
#         # 构建 Nuclei 命令
#         # 将选中的模板路径拼接为命令
#         templates_command = ','.join(selected_pocs) if selected_pocs else ''
#
#         # 启动 Nuclei 扫描
#         scan_thread = threading.Thread(
#             target=nuclei_scan,
#             args=(target_urls, scan_type, templates_command, author, tags, severity, tc)
#         )
#         scan_thread.start()
#         current_time = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')  # 格式化为 YYYYMMDD_HHMMSS
#         result_file_name = f'results_{current_time}.txt'
#         return HttpResponse(f"开始扫描目标: {target_urls}. 扫描结果将在稍后可用。", status=200)
#
#     return HttpResponse("无效的请求方法", status=400)
def run_nuclei_scan(request):
    global scan_status
    if request.method == 'POST':
        target_urls = request.POST.get('target_url', '')
        scan_type = request.POST.get('scan_type', 'all')
        template_path = request.POST.get('template_path', '')
        author = request.POST.get('author', '')
        tags = request.POST.get('tags', '')
        severity = request.POST.get('severity', '')
        tc = request.POST.get('tc', '')

        # 启动扫描线程
        scan_status['running'] = True
        scan_status['finished'] = False
        scan_status['status_message'] = f"开始扫描目标: {target_urls}..."

        # 处理选中的 POC 模板
        selected_pocs = request.POST.getlist('poc_templates')  # 这需要在表单中加个对复选框的定义
        #
        #         # 构建 Nuclei 命令
        #         # 将选中的模板路径拼接为命令
        templates_command = ','.join(selected_pocs) if selected_pocs else ''
        #
        #         # 启动 Nuclei 扫描
        scan_thread = threading.Thread(
            target=nuclei_scan,
            args=(target_urls, scan_type, templates_command, author, tags, severity, tc)
        )
        scan_thread.start()
        return render(request, 'man/poc_scanning.html')

    return HttpResponse("无效的请求方法", status=400)


def check_scan_status(request):
    return JsonResponse({
        'status': scan_status['status_message'],
        'finished': scan_status['finished']
    })


def stop_scan(request):
    global scan_status
    scan_status['running'] = False
    scan_status['finished'] = True
    scan_status['status_message'] = "扫描已被停止。"
    return JsonResponse({'status': '停止成功'})


@csrf_exempt
def get_poc_templates(request):
    template_dir = 'nuc_poc/http/'  # 确保这个路径是存在的

    def find_yaml_files(base_dir):
        files_structure = {}
        for root, dirs, files in os.walk(base_dir):
            # 确保目录在结构中
            relative_path = os.path.relpath(root, base_dir)
            path_parts = relative_path.split(os.sep) if relative_path != '.' else []
            current_level = files_structure

            # 创建目录结构
            for part in path_parts:
                current_level = current_level.setdefault(part, {})

            # 添加 YAML 文件
            for file in files:
                if file.endswith('.yaml'):
                    current_level[file] = os.path.join(relative_path, file)

        return files_structure

    yaml_files_structure = find_yaml_files(template_dir)
    return JsonResponse({'templates': yaml_files_structure})


@csrf_exempt
def download_results(request):
    global file_path
    # current_time = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    # result_file_name = f'results_{current_time}.txt'
    # file_path = os.path.join('path/to/results', result_file_name)  # 更新为实际路径

    if os.path.exists(file_path):
        return FileResponse(open(file_path, 'rb'), as_attachment=True)
    return HttpResponse("文件不存在", status=404)


# def scan_dashboard(request):
#     return render(request, 'man/scan_dashboard.html')
#
#
# @csrf_exempt
# def run_scan(request):
#     if request.method == 'POST':
#         data = json.loads(request.body)
#         task = ScanTask.objects.create(
#             target=data['target'],
#             port_scan_ports=data.get('port_scan_ports'),
#             nuclei_option=data.get('nuclei_option'),
#             nuclei_custom_pocs=data.get('nuclei_custom_pocs'),
#             status='running'
#         )
#         task.set_selected_scans(data['selected_scans'])
#         task.save()
#
#         # 启动后台线程执行扫描
#         thread = threading.Thread(target=execute_scans, args=(task.id,))
#         thread.start()
#
#         return JsonResponse({'task_id': task.id})
#     return JsonResponse({'error': 'Invalid request'}, status=400)
# return render(request, 'man/scan_dashboard.html')


# def get_scan_status(request, task_id):
#     try:
#         task = ScanTask.objects.get(id=task_id)
#         return JsonResponse({
#             'status': task.status,
#             'results': task.get_results()
#         })
#     except ScanTask.DoesNotExist:
#         return JsonResponse({'error': 'Task not found'}, status=404)


# def execute_scans(task_id, target, selected_scans, port_scan_ports, nuclei_option, nuclei_custom_pocs):
#     task = ScanTask.objects.get(id=task_id)
#     results = {}
#
#     try:
#         if 'subdomain' in selected_scans:
#             subdomain_scanner = SubdomainExplosion()
#             results['subdomain'] = subdomain_scanner.sub_domain(target)
#
#         if 'port' in selected_scans:
#             port_scanner = PortScanner()
#             results['port'] = port_scanner.portscan(target, port_scan_ports)
#
#         if 'dir' in selected_scans:
#             dir_scanner = DirScan()
#             results['dir'] = dir_scanner.run(target, 'path/to/dir_dict.txt')
#
#         if 'nuclei' in selected_scans:
#             if nuclei_option == 'all':
#                 results['nuclei'] = nuclei_scan(target)
#             else:
#                 results['nuclei'] = nuclei_scan(target, nuclei_custom_pocs)
#
#         task.results = json.dumps(results)
#         task.status = 'Completed'
#     except Exception as e:
#         task.status = 'Failed'
#         task.results = str(e)
#
#     task.save()
#
#
# def get_scan_status(request, task_id):
#     try:
#         task = ScanTask.objects.get(id=task_id)
#         return JsonResponse({
#             'status': task.status,
#             'results': json.loads(task.results) if task.results else None
#         })
#     except ScanTask.DoesNotExist:
#         return JsonResponse({'error': 'Task not found'}, status=404)
#
# def execute_scans(task_id, target, selected_scans, port_scan_ports, nuclei_option, nuclei_custom_pocs):
#     task = ScanTask.objects.get(id=task_id)
#     results = {}
#
#     try:
#         if 'subdomain' in selected_scans:
#             subdomain_scanner = SubdomainExplosion()
#             results['subdomain'] = subdomain_scanner.sub_domain(target)
#
#         if 'port' in selected_scans:
#             port_scanner = PortScanner()
#             results['port'] = port_scanner.portscan(target)  # 注意：这里可能需要调整参数
#
#         if 'dir' in selected_scans:
#             dir_scanner = DirScan()
#             results['dir'] = dir_scanner.run(target, 'path/to/dir_dict.txt')
#
#         if 'nuclei' in selected_scans:
#             results['nuclei'] = nuclei_scan(target)  # 可能需要根据 nuclei_option 和 nuclei_custom_pocs 调整
#
#         if 'cdn' in selected_scans:
#             foundation_info = FoundationInfo()
#             results['cdn'] = foundation_info.get_cdn(target)
#
#         if 'whois' in selected_scans:
#             foundation_info = FoundationInfo()
#             results['whois'] = foundation_info.get_whois(target)
#
#         if 'fofa' in selected_scans:
#             fofa_api = Fofa_Api()
#             results['fofa'] = fofa_api.get_data(target)
#
#         task.results = json.dumps(results)
#         task.status = 'Completed'
#     except Exception as e:
#         task.status = 'Failed'
#         task.results = str(e)
#
#     task.save()


def poc_manage(request):
    return render(request, 'man/manage_poc.html')


def upload_poc(request):
    if request.method == 'POST' and request.FILES.get('poc_file'):
        poc_file = request.FILES['poc_file']
        # 获取用户选择的文件夹，默认到 mypoc
        upload_folder = request.POST.get('upload_folder')

        # 构建目标路径
        target_path = os.path.join(settings.UPLOAD_POC_ROOT, upload_folder)

        # 确保目标路径存在
        os.makedirs(target_path, exist_ok=True)

        fs = FileSystemStorage(location=target_path)
        print('POC文件上传路径: ' + target_path)

        # 保存文件
        filename = fs.save(poc_file.name, poc_file)

        # 返回成功响应
        return JsonResponse({'message': 'POC uploaded successfully', 'file_name': filename})

    return JsonResponse({'error': 'Invalid request'}, status=400)


poc_path = ''


def download_selected_pocs(request):
    pass
    # current_time = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    # result_file_name = f'results_{current_time}.txt'
    # file_path = os.path.join('path/to/results', result_file_name)  # 更新为实际路径

    # if os.path.exists(file_path):
    #     return FileResponse(open(file_path, 'rb'), as_attachment=True)
    # return HttpResponse("文件不存在", status=404)


def get_poc_folders(request):
    base_dir = os.path.join(original_directory, 'nuc_poc', 'http')
    # base_dir = 'F:\\PyProject\\DYAQ\\day17\\webscan\\nuc_poc\\http\\'  # 基础目录
    page_size = int(request.GET.get('page_size', 10))  # 每页文件夹数量
    page_number = int(request.GET.get('page', 1))  # 当前页码

    def list_folders(base_dir):
        folders = []
        for entry in os.listdir(base_dir):
            entry_path = os.path.join(base_dir, entry)
            if os.path.isdir(entry_path):
                folders.append(entry)
        return folders

    all_folders = list_folders(base_dir)
    start_index = (page_number - 1) * page_size
    end_index = start_index + page_size
    paginated_folders = all_folders[start_index:end_index]

    return JsonResponse({
        'folders': paginated_folders,
        'total': len(all_folders),
        'page_size': page_size,
        'page_number': page_number
    })


def create_folder(request):
    if request.method == 'POST':
        folder_name = request.POST.get('folder_name')
        current_path = request.POST.get('current_path')
        print(folder_name)
        # 构建新文件夹的完整路径
        new_folder_path = os.path.join(settings.CREATE_POC_FOLDER, folder_name)
        print(new_folder_path)
        try:
            os.makedirs(new_folder_path)
            return JsonResponse({'message': '文件夹创建成功'}, status=201)
        except FileExistsError:
            return JsonResponse({'error': '文件夹已存在'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': '无效请求'}, status=400)


def port_scan_form(request):
    if request.method == 'POST':
        # target_urls = request.POST.get('target_url')
        # if target_urls:
        return masscan_scan(request)
    return render(request, 'man/port_scan_form.html')


# 全局变量来保存扫描进程
masscan_process = None


@csrf_exempt
def masscan_scan(request):
    global masscan_process
    if request.method == 'POST':
        masscan_directory = os.path.join(original_directory, 'tools')
        os.chdir(masscan_directory)

        ip_range = request.POST.get('ip_range').strip().splitlines()
        ports = request.POST.get('ports')
        options = []

        # 检查 IP 地址和端口
        if not ip_range or not ports:
            return JsonResponse({'result': 'IP 地址或端口不能为空'}, status=400)

        # 收集根据用户选择的参数
        if request.POST.get('sS'):
            options.append('-sS')
        if request.POST.get('Pn'):
            options.append('-Pn')
        if request.POST.get('randomize_hosts'):
            options.append('--randomize-hosts')
        if request.POST.get('banners'):
            options.append('--banners')

        # 新增参数处理
        if request.POST.get('rate'):
            rate = request.POST.get('rate')
            options.extend(['--rate', rate])
        if request.POST.get('http_user_agent'):
            http_user_agent = request.POST.get('http_user_agent')
            options.extend(['--http-user-agent', f'"{http_user_agent}"'])
        if request.POST.get('conf_file'):
            conf_file = request.POST.get('conf_file')
            options.extend(['-c', f'"{conf_file}"'])
        if request.POST.get('adapter'):
            adapter = request.POST.get('adapter')
            options.extend(['-e', f'"{adapter}"'])
        if request.POST.get('adapter_ip'):
            adapter_ip = request.POST.get('adapter_ip')
            options.extend(['--adapter-ip', f'"{adapter_ip}"'])
        if request.POST.get('adapter_mac'):
            adapter_mac = request.POST.get('adapter_mac')
            options.extend(['--adapter-mac', f'"{adapter_mac}"'])
        if request.POST.get('router_mac'):
            router_mac = request.POST.get('router_mac')
            options.extend(['--router-mac', f'"{router_mac}"'])
        if request.POST.get('exclude'):
            exclude = request.POST.get('exclude')
            options.extend(['--exclude', f'"{exclude}"'])
        if request.POST.get('excludefile'):
            excludefile = request.POST.get('excludefile')
            options.extend(['--excludefile', f'"{excludefile}"'])
        if request.POST.get('includefile'):
            includefile = request.POST.get('includefile')
            options.extend(['--includefile', f'"{includefile}"'])
        if request.POST.get('ping'):
            options.append('--ping')
        if request.POST.get('retries'):
            retries = request.POST.get('retries')
            options.extend(['--retries', retries])
        if request.POST.get('ttl'):
            ttl = request.POST.get('ttl')
            options.extend(['--ttl', ttl])
        if request.POST.get('wait'):
            wait = request.POST.get('wait')
            options.extend(['--wait', wait])

        # 确保 IP 地址格式正确
        ip_range = ' '.join(ip_range).strip()
        command = ['.\\masscan.exe', ip_range, '-p', ports] + options
        print("执行端口扫描命令:", ' '.join(command))

        try:
            masscan_process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                               universal_newlines=True)
            output_lines = []
            last_rate_line = ""

            # 处理输出
            for line in masscan_process.stdout:
                if re.search(r'rate:\s+\d+(\.\d+)?-kpps', line):
                    last_rate_line = line.strip()
                else:
                    output_lines.append(line.strip())

            masscan_process.wait()  # 等待进程完成

            # 合并结果

            result = "\n".join(output_lines) + "\n" + last_rate_line
            os.chdir(original_directory)
            return JsonResponse({'result': result})

        except subprocess.CalledProcessError as e:
            os.chdir(original_directory)
            return JsonResponse({'result': e.output}, status=400)

    os.chdir(original_directory)
    return JsonResponse({'result': 'Invalid request'}, status=400)


@csrf_exempt
def stop_portscan(request):
    global masscan_process
    if masscan_process:
        masscan_process.terminate()  # 停止进程
        masscan_process.wait()  # 等待进程完全结束
        masscan_process = None  # 清空进程引用
        return JsonResponse({'result': 'Scanning process stopped.'})
    return JsonResponse({'result': 'No scanning process to stop.'}, status=400)


def finger_scan_form(request):
    if request.method == 'POST':
        # target_urls = request.POST.get('target_url')
        # if target_urls:
        return finger_scan(request)
    return render(request, 'man/fingerscanner.html')


# 全局变量来保存扫描进程
fingerscan_process = None
# F:\PyProject\DYAQ\day17\webscan\
original_directory = os.getcwd()


@csrf_exempt
def finger_scan(request):
    temp_file_path = ''
    global fingerscan_process
    if request.method == 'POST':
        ehole_directory = os.path.join(original_directory, 'tools', 'ehole_windows')
        os.chdir(ehole_directory)
        # ip_range = request.POST.get('ip_range').strip().splitlines()
        # ports = request.POST.get('ports')
        options = []

        # 检查 IP 地址和端口
        # if not ip_range or not ports:
        #     return JsonResponse({'result': 'IP 地址不能为空'}, status=400)

        # 收集根据用户选择的参数
        if request.POST.get('finger'):
            options.append('finger')
        if request.POST.get('fofaext'):
            options.append('fofaext')

        # 新增参数处理
        if request.POST.get('thread'):
            thread = request.POST.get('thread')
            options.extend(['--thread', thread])
        if request.POST.get('url'):
            url = request.POST.get('url')
            options.extend(['--url', f'"{url}"'])
        if request.POST.get('fofa'):
            fofa = request.POST.get('fofa')
            options.extend(['--fofa', fofa])
        if request.POST.get('hunter'):
            hunter = request.POST.get('hunter')
            options.extend(['--hunter', hunter])
        if request.POST.get('proxy'):
            proxy = request.POST.get('proxy')
            options.extend(['--proxy', proxy])
        if request.POST.get('local'):
            local_input = request.POST.get('local').strip().splitlines()
            # 创建临时文件路径
            temp_file_path = os.path.join(os.getcwd(), 'temp_urls.txt')
            # 将用户输入写入临时文件
            with open(temp_file_path, 'w', encoding='utf-8') as f:
                for url in local_input:
                    f.write(url.strip() + '\n')  # 写入每行并去除空格

            print(f"临时文件已创建: {temp_file_path}")

            # 扩展 options，指向临时文件
            options.extend(['--local', temp_file_path])
            # 继续后续处理...
            print(options)

        # ehole_directory = "F:\\PyProject\\DYAQ\\day17\\webscan\\tools\\ehole_windows"
        # os.chdir(ehole_directory)
        command = ['.\\ehole_windows.exe'] + options
        command_str = '.\\ehole_windows.exe ' + ' '.join(
            options)
        print("执行指纹识别命令:", ' '.join(command))
        print(command_str)
        print("当前工作目录:", os.getcwd())
        # 创建临时文件来存储输出
        output_file = 'output.txt'

        try:

            if 'fofaext' in options:
                # 执行命令
                os.system(f'{command_str} > {output_file} 2>&1')

                # 读取结果文件
                results_file = 'results.xlsx'  # 假设结果文件名为 results.xlsx
                if os.path.exists(results_file):
                    df = pd.read_excel(results_file)
                    result_data = df.to_dict(orient='records')  # 将数据转换为字典
                    print(result_data)

                    # 将结果写入 output.txt
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(json.dumps(result_data, ensure_ascii=False, indent=4))
                        # 读取输出文件内容
                    with open(output_file, 'r', encoding='utf-8') as f:
                        result = f.read()
                    # 清理临时文件
                    print(result)
                    os.remove('.\output.txt')
                    os.remove('.\\results.xlsx')
                    os.chdir(original_directory)
                    return JsonResponse({'result': result})

                else:
                    return JsonResponse({'result': '未生成结果文件'}, status=500)
            else:
                # 启动指纹识别进程，读取输出，不去除ANSI控制字符
                fingerscan_process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                                      universal_newlines=True, encoding='utf-8')
                output_lines = []
                # os.system(f'{command_str} > {output_file} 2>&1')

                # 处理输出，保留ANSI控制字符
                for line in fingerscan_process.stdout:
                    print(line)
                    output_lines.append(line.strip())  # 保留原始输出
                #
                fingerscan_process.wait()  # 等待进程结束

                # 读取输出文件
                # with open(output_file, 'r', encoding='utf-8') as f:
                #     result = f.read()
                #
                # print(result)
                result = "\n".join(output_lines)
                if os.path.exists(temp_file_path):
                    os.remove(temp_file_path)
                # os.remove('.\output.txt')
                os.chdir(original_directory)
                return JsonResponse({'result': result})

        except Exception as ex:
            print(f"意外错误: {str(ex)}")
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)
            os.remove('.\output.txt')
            os.chdir(original_directory)
            return JsonResponse({'result': '发生意外错误', 'error': str(ex)}, status=500)

    #     except subprocess.CalledProcessError as e:
    #         # 如果进程调用失败，返回错误输出
    #         return JsonResponse({'result': e.output}, status=400)
    #
    #     # 处理无效请求的情况
    # return JsonResponse({'result': 'Invalid request'}, status=400)
    # 确保 IP 地址格式正确
    # ip_range = ' '.join(ip_range).strip()
    # command = ['F:\\PyProject\\DYAQ\\day17\\webscan\\tools\\ehole_windows\\ehole_windows.exe','finger','-u', ip_range] + options
    # command_str = 'F:\\PyProject\\DYAQ\\day17\\webscan\\tools\\EHole_windows_amd64\\EHole_windows_amd64.exe ' + ' '.join(
    #     options)
    # print("执行指纹识别命令:", command_str)
    # print("当前工作目录:", os.getcwd())
    #
    # # 创建临时文件来存储输出
    # output_file = 'output.txt'
    #
    # try:
    #     # 使用 os.system 执行命令，并将输出重定向到文件
    #     os.system(f'{command_str} > {output_file} 2>&1')

    # 读取输出文件
    #     with open(output_file, 'r', encoding='utf-8') as f:
    #         result = f.read()
    #
    #     print(result)
    #     return JsonResponse({'result': result})
    #
    # except Exception as ex:
    #     print(f"意外错误: {str(ex)}")
    #     return JsonResponse({'result': '发生意外错误', 'error': str(ex)}, status=500)


@csrf_exempt
def stop_fingerscan(request):
    global fingerscan_process
    if fingerscan_process:
        fingerscan_process.terminate()  # 停止进程
        fingerscan_process.wait()  # 等待进程完全结束
        fingerscan_process = None  # 清空进程引用
        return JsonResponse({'result': 'Scanning process stopped.'})
    return JsonResponse({'result': 'No scanning process to stop.'}, status=400)


def write_config(file_path, config):
    with open(file_path, 'w') as f:
        for key, value in config.items():
            f.write(f"{key}={value}\n")


def read_config(file_path):
    config = {}
    with open(file_path, 'r') as f:
        for line in f:
            if '=' in line:
                key, value = line.strip().split('=', 1)
                config[key] = value
    return config


@csrf_exempt
def get_ehole_config(request):
    ehole_directory = os.path.join(original_directory, 'tools', 'ehole_windows')
    os.chdir(ehole_directory)
    config = read_config('config.ini')
    os.chdir(original_directory)
    # print('get_ehole_config' + os.getcwd())
    return JsonResponse(config)


@csrf_exempt
def update_ehole_config(request):
    if request.method == 'POST':
        ehole_directory = os.path.join(original_directory, 'tools', 'ehole_windows')
        os.chdir(ehole_directory)
        config = {
            'Email': request.POST.get('Email', ''),
            'Fofa_token': request.POST.get('Fofa_token', ''),
            'Fofa_timeout': request.POST.get('Fofa_timeout', ''),
            'Hunter_key': request.POST.get('Hunter_key', ''),
        }
        write_config('config.ini', config)
        os.chdir(original_directory)
        # print('update_ehole_config' + os.getcwd())
        return JsonResponse({'status': 'success'})
    os.chdir(original_directory)
    # print('update_ehole_config'+os.getcwd())
    return JsonResponse({'status': 'fail'}, status=400)
