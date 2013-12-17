#!/usr/bin/env python3


import csv
import os
import os.path
import queue
import re
import sys
import time
import threading
import urllib.request


class Table_row(): 
    def __init__(self, sigid, signame=" ", enabled=" ", retired=" ", url=" ",
                 description=" ", cve=" ", appling=" ",
                 script=" ", ggl_trnslt_dscr=" ", ggl_trnslt_cvn=" "):
        self.sigid = sigid
        self.signame = signame
        self.enabled = enabled
        self.retired = retired
        self.url = url
        self.description = description
        self.cve = cve
        self.russ_description = ("Данная сигнатура срабатывает при обнаружении "
                                 "<краткий критерий срабатывания сигнатуры>, "
                                 "с помощью которого(ых)(ой) злоумышленник может "
                                 "<краткое описание предотвращаемой атаки> "
                                 "через уязвимость в <описание уязвимого продукта>.")
        self.appling = appling
        self.script = script
        self.ggl_trnslt_dscr = ggl_trnslt_dscr # если реализовать колонку перевода гугла
        self.ggl_trnslt_cvn = ggl_trnslt_cvn # см. выше


    def attr_list(self):
        return [self.sigid, self.signame, self.enabled, self.retired,
                self.url, self.description, self.cve,
                self.russ_description, self.appling, self.script,
                self.ggl_trnslt_dscr, self.ggl_trnslt_cvn] 



class Connect():
    """Класс отвечает за соединение с сайтами, аутентификацию, прокси и прочее."""
    def __init__(self):
        self.username = input("Введите ваш acs-логин ... : ")
        self.password = input("... и пароль: ")
        self.proxys = 'http://proxy.acs.ru:8080'
        self.proxy = urllib.request.ProxyHandler({'http': self.proxys})
        self.proxy_auth_handler = urllib.request.ProxyBasicAuthHandler()        
        self.proxy_auth_handler.add_password('realm', 'uri', self.username, self.password)


    def cisco_connect(self):        
        try:
            username='smartnetstp'
            password = 'Radisheva12'
            auth = urllib.request.HTTPBasicAuthHandler()
            auth.add_password('User', "https://www.cisco.com",
                              username, password)

            opener = urllib.request.build_opener(auth, self.proxy, self.proxy_auth_handler)
            return opener
        except urllib.request.HTTPError as err:
            print(err.read())


    def cve_connect(self):
        try:
            open_cve = urllib.request.HTTPHandler()
            opener = urllib.request.build_opener(open_cve, self.proxy, self.proxy_auth_handler)
        except urllib.request.HTTPError as err:
            print(err.read())
            opener = None
        return opener


class Worker(threading.Thread):
    """Класс-работник для каждого потока.

    Получает номер сигнатуры и имя сигнатуры из очереди о по нему составляет url, парсит страницу. Парсинг находит значения: Enabled, Retired, Description, CVE Description.
    Данные закидываются в рабочую очередь.
    """

    lock = threading.Lock()

    def __init__(self, work_queue, result_queue):
        super().__init__()
        self.work_queue = work_queue
        self.result_queue = result_queue

    def run(self):
        while True:
            try:
                sigid, signame = self.work_queue.get()
                self.process(sigid, signame)
            finally:
                self.work_queue.task_done()

    def process(self, sigid, signame):
        """Метод, который совершает всю работу класса.

        Метод состоит из четырех процедур: первая создает url ссылку из sigid, вторая парсит страницу в поиске значений,
        третья ищет данные в description, по которым будет создана новая ссылка, четвёртая парсит страницу по новой ссылке.
        """

        def cisco_intellishield_url(sigid):
            one, two = sigid.split(".")
            url = ("https://intellishield.cisco.com/security/alertmanager/ipsSignature?signatureId="
                   + one + "&signatureSubId=" + two)
            return url

        def parser(cisco_url):
            """Функция получает в качестве аргумента экземпляр класса Connect"""

            opener = connect.cisco_connect()
            resp = opener.open(cisco_url)

            lines = resp.read().decode('utf8', 'ignore')
            enabled_pattern = re.compile('>Default Enabled:\s*</SPAN>.*?<SPAN\s+[^>]*?>(.*?)</SPAN>', re.DOTALL)
            enabled = enabled_pattern.findall(lines)
            enabled = enabled[0] if enabled else " "

            retired_pattern = re.compile('>Default Retired:\s*</SPAN>.*?<SPAN\s+[^>]*?>(.*?)</SPAN>', re.DOTALL)
            retired = retired_pattern.findall(lines)
            retired = retired[0] if retired else " "
            
            desc_pattern = re.compile('<SPAN class=label[0-9]{1,2}>Description</SPAN>.*?<SPAN\s+[^>]*?>(.*?)</SPAN>', re.DOTALL)
            description = desc_pattern.findall(lines)
            description = description[0] if description else " "

            for attribute in [enabled, retired, description]:
                if attribute == " ,":
                    print("{0} is not find".format(attribute))
            
            return enabled, retired, description


        def get_cve_description(cve_url):

            opener = connect.cve_connect()
            resp = opener.open(cve_url)
            lines = resp.read().decode('utf8', 'ignore')
            description_pattern = re.compile('>Description<.*?<[tTdD]{2}\s+[^>]*?>(.*?)</[tTdD]{2}>', re.DOTALL)
            cve_description = description_pattern.findall(lines)          
            return cve_description[0].replace("\n", " ").strip() if cve_description else " "


        def get_cve_url(description):
            cve_pattern = re.compile(r'CVE-[\w\d]+-[\w\d]+')
            cve_number = re.findall(cve_pattern, description)
            return ('https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + cve_number[0]) if cve_number else None



 
        opener = connect.cisco_connect()
        cisco_url = cisco_intellishield_url(sigid) # заполняется колонка url-адресов intellishield.cisco.com
        enabled, retired, description = parser(cisco_url)

        cve_url = get_cve_url(description)
        if cve_url:
            cve_description = get_cve_description(cve_url)
        else:
            cve_description = " "
        
        
        table_row = Table_row(sigid, signame, enabled, retired, url=cisco_url, description=description, cve=cve_description)       
        self.result_queue.put(table_row)


class Fill_and_WriteRow(threading.Thread):
    def __init__(self, result_queue):
        super().__init__()
        self.result_queue = result_queue
        self.data_table = {}

    def run(self):
        while True:
            try:
                table_row = self.result_queue.get()
                self.process(table_row)
            finally:
                self.result_queue.task_done()
                
    def process(self, table_row):
        sigid = table_row.sigid
        self.data_table[sigid] = table_row

    def write_csv(self, path):
        with open(path, 'w')as fh:
            first_row = "S5xx SIGNATURE UPDATE DETAILS",
            second_row = "NEW SIGNATURES",
            header = "SIGID", "SIGNAME", "ENABLED", "RETIRED", "URL", "DESCRIPTION", "Уязвимость (CVE)", "Описание", "Используется в СВК", "Скрипт"
            w = csv.writer(fh, dialect='excel')
            w.writerow(first_row)
            w.writerow(second_row)
            w.writerow(header)
            for key, table_row in sorted(self.data_table.items()):
                w.writerow(table_row.attr_list())


class DownloadReadMe():
    def __init__(self):
        path_folder = os.path.join(os.path.dirname(sys.argv[0]), 'Temp')
        while os.path.exists(path_folder):
            path_folder = path_folder + '1'
        os.mkdir(path_folder)
            
        self.path_folder = path_folder

    def download(self):
        
        def download_sensor_readme(download_software_url, opener):
            def get_readme_url(url):
                auth = urllib.request.HTTPBasicAuthHandler()
                opener = urllib.request.build_opener(auth)
                resp = opener.open(url)
                page = resp.read().decode('utf8', 'ignore')
                pattern = re.compile('<a\s+[^>]*?title=[\'\"]?Signature\s+Update\s+.*?Readme[^>]*?(?P<readme_url>[\"\']?http://www.cisco.com/[^>]*?[.]txt[\"\']?)[^>]*?>')
                readme_url = pattern.findall(page)
                if readme_url:
                    return readme_url[0].strip('\'\"')
                else:
                    print("Не удалось найти ссылку на скачивание Sensor Readme")
                    sys.exit()

            readme_url = get_readme_url(download_software_url)
            filename = readme_url.rsplit('/', 1)[1]
            path = os.path.dirname(sys.argv[0])
            fullname, headers = urllib.request.urlretrieve(readme_url, filename=(self.path_folder + '/' + filename))
            return os.path.abspath(fullname)
            
            
        def get_download_software_url(opener):
            url_search_page = "https://software.cisco.com/download/type.html?mdfid=278810718&catid=268438162"
            resp = opener.open(url_search_page)
            search_page = resp.read().decode('utf8', 'ignore')
            pattern = re.compile('<a[^>]*?href=(?P<url_half>[^>]*?)>Intrusion\s+Prevention\s+System\s+\(IPS\)\s+Signature\s+Updates</a>')
            url_half = pattern.findall(search_page)
            if url_half:
                download_software_page = "http://software.cisco.com" + url_half[0].strip('"\'')
                print("Страница скачивания новой сигнатуры: ", download_software_page)
            else:
                print('Не удалось найти страницу скачивания новой сигнатуры')
            return download_software_page


        opener = connect.cisco_connect()
        download_software_page = get_download_software_url(opener)
        with open(os.path.join(self.path_folder, "Скачать Файл по этой ссылке"), 'wt')as fh:
            fh.write(download_software_page)
        read_me_path = download_sensor_readme(download_software_page, opener)
        read_me_filename = os.path.basename(read_me_path)
        new_folder_name = os.path.join(os.path.dirname(self.path_folder), os.path.basename(read_me_path).split('.')[0])
        n = 1
        while os.path.exists(new_folder_name):
            if n > 1:
                new_folder_name = new_folder_name.replace('({0})'.format(n-1), '({0})'.format(n))
            else:
                new_folder_name += '({0})'.format(n)
            n += 1
        os.rename(self.path_folder, os.path.basename(new_folder_name))

        return os.path.abspath(os.path.join(new_folder_name, read_me_filename))


class Extract():
    def __init__(self, path):
        self.path = path
        self.data = {}

    def extract(self):
        filename = os.path.basename(self.path)
        number_pattern = re.compile('.+-S(\d+).+')
        signature_number = number_pattern.findall(filename)[0]
        with open(self.path) as fh:
            text = fh.read()
        table_pattern = re.compile('S{0}\s+SIGNATURE\s+UPDATE\s+DETAILS\n\n.*?[=]+'.format(signature_number), re.DOTALL)
        table = table_pattern.findall(text)[0]
        if not table:
            print('Не удалось найти таблицу по определенному патерну регулярного выражения')
            sys.exit()

        for border in (('NEW SIGNATURES', 'TUNED SIGNATURES'), ('TUNED SIGNATURES', 'CAVEATS'), ('CAVEATS', 'Modified signature\(s\) detail:')):
            section_pattern = re.compile('{0}\n+(.*?)\n+{1}'.format(*[x.replace(' ', '\s+') for x in border]), re.DOTALL)
            section = section_pattern.findall(table)
            if not section or not section[0][0:5] == 'SIGID':
                continue
            
            section = section[0].split('\n')
            column_names = {}
            for line in section:
                if line[0:5] == "SIGID":
                    while line:
                        column_name = ""
                        alnum = True
                        for char in line:
                            if char.isalnum() and alnum:
                                column_name += char
                                continue
                            if char.isspace():
                                alnum = False
                                column_name += char
                                continue
                            break 
                        column_width = len(column_name)
                        column_names[column_name.strip()] = column_width
                        line = line[column_width:len(line)]
                        continue
                if line.strip():
                    if line[0:column_names["SIGID"]].strip():
                        sigid = line[0:column_names["SIGID"]].strip()
                        signame = line[column_names["SIGID"]:(column_names["SIGNAME"] + column_names["SIGID"])].strip()
                        self.data[sigid] = signame
                    else:
                        signame = signame + " " + line[column_names["SIGID"]:(column_names["SIGNAME"] + column_names["SIGID"])].strip()
                        self.data[sigid] = signame
        return self.data

                    
        

connect = Connect()

def main():
    path = DownloadReadMe().download()
    data = Extract(path).extract()
    work_queue = queue.Queue()
    result_queue = queue.Queue()
    for i in range(8):
        worker = Worker(work_queue, result_queue)
        worker.deamon = True
        worker.start()
    
    result_thread = Fill_and_WriteRow(result_queue)
    result_thread.daemon = True
    result_thread.start()
    

    for sigid, signame in data.items():
        work_queue.put((str(sigid), str(signame)))

    work_queue.join()
    result_queue.join()
    result_thread.write_csv(os.path.join(os.path.dirname(path), 'Table.csv'))
    print("Готово. Папка с необходимой информацией должна появиться в той же директории, что и скрипт.")

    
if __name__ == '__main__':
    sys.exit(main())


























