import os
import sys
import hashlib
import json
import tkinter as tk
from tkinter import simpledialog, messagebox
import tempfile
import subprocess
from pathlib import Path
from tkinter import filedialog
import webbrowser
import winreg
import ctypes
import shutil

# 检查管理员权限
def is_admin():
    """检查是否以管理员权限运行"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# 配置文件放在程序所在目录
BASE_DIR = Path(sys.executable).parent if getattr(sys, 'frozen', False) else Path(__file__).parent
PASSWORD_FILE = BASE_DIR / "password_vault.dat"
ENCRYPTED_LIST_FILE = BASE_DIR / "encrypted_files.dat"
ENCRYPT_MARKER = b'ENCv2!'  # 6字节加密标记

def register_file_association(force=False):
    """注册文件关联（完整实现）"""
    try:
        # 获取程序路径（处理打包和开发环境）
        if getattr(sys, 'frozen', False):
            exe_path = sys.executable
        else:
            exe_path = os.path.abspath(sys.argv[0])
            if not exe_path.endswith('.exe'):
                # 开发环境下创建临时exe用于关联
                temp_exe = Path(exe_path).with_suffix('.exe')
                if not temp_exe.exists():
                    try:
                        # 创建伪exe文件用于关联
                        with open(temp_exe, 'wb') as f:
                            f.write(b'')
                    except:
                        return False
                exe_path = str(temp_exe)

        # 需要管理员权限
        if not is_admin():
            # 请求UAC提权
            ctypes.windll.shell32.ShellExecuteW(
                None, 'runas', sys.executable, 
                f'"{sys.executable}" --register-associations', 
                None, 1
            )
            return True

        # 注册文件类型关联
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, '.pcy') as key:
            winreg.SetValue(key, '', winreg.REG_SZ, 'PrivacyFile')
            winreg.SetValueEx(key, 'Content Type', 0, winreg.REG_SZ, 'application/x-pcy')

        # 创建文件类型定义
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, 'PrivacyFile') as key:
            winreg.SetValue(key, '', winreg.REG_SZ, 'Privacy Encrypted File')

        # 设置图标
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, r'PrivacyFile\DefaultIcon') as key:
            winreg.SetValue(key, '', winreg.REG_SZ, f'"{exe_path}",0')

        # 设置打开命令
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, r'PrivacyFile\shell\open\command') as key:
            winreg.SetValue(key, '', winreg.REG_SZ, f'"{exe_path}" "%1"')

        # 刷新系统图标缓存
        subprocess.run(['ie4uinit.exe', '-show'], shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
        
        # 重启资源管理器以应用更改
        try:
            subprocess.run(['taskkill', '/f', '/im', 'explorer.exe'], shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run(['start', 'explorer.exe'], shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
        except:
            pass

        return True

    except Exception as e:
        print(f"注册失败: {e}")
        return False

def check_association():
    """检查关联是否正确"""
    try:
        with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, '.pcy') as key:
            file_type = winreg.QueryValue(key, '')
            if file_type != 'PrivacyFile':
                return False
                
        return True
    except:
        return False

def setup_file_associations():
    """设置文件关联的完整流程"""
    if not check_association():
        if messagebox.askyesno(
            "文件关联", 
            "是否要将.pcy文件关联到本程序？(需要管理员权限)",
            parent=tk._default_root
        ):
            if not register_file_association():
                messagebox.showerror(
                    "错误", 
                    "关联失败，请以管理员身份运行程序",
                    parent=tk._default_root
                )
            else:
                messagebox.showinfo("成功", "文件关联已注册成功！")

class CenterDialog:
    """使用simpledialog的居中对话框"""
    @staticmethod
    def askstring(title, prompt, **kwargs):
        temp_root = tk.Tk()
        temp_root.withdraw()
        
        try:
            # 创建对话框
            dialog = simpledialog.askstring(title, prompt, parent=temp_root, **kwargs)
            
            # 找到对话框窗口
            for window in temp_root.winfo_children():
                if isinstance(window, tk.Toplevel):
                    # 等待窗口可见
                    window.wait_visibility()
                    window.update_idletasks()
                    
                    # 获取实际尺寸
                    width = window.winfo_width()
                    height = window.winfo_height()
                    
                    # 计算居中位置
                    x = (temp_root.winfo_screenwidth() - width) // 2
                    y = (temp_root.winfo_screenheight() - height) // 2
                    
                    # 重新设置位置
                    window.geometry(f"+{x}+{y}")
                    window.update()
            
            return dialog
        finally:
            temp_root.destroy()
            
def encrypt_data(data, password):
    """加密数据"""
    key = hashlib.sha256(password.encode()).digest()
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def decrypt_data(data, password):
    """解密数据"""
    return encrypt_data(data, password)

def load_data(filepath):
    """加载JSON数据"""
    try:
        if filepath.exists():
            with open(filepath, 'r') as f:
                return json.load(f)
    except:
        return {}
    return {}

def save_data(filepath, data):
    """保存JSON数据"""
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)

def is_file_encrypted(filepath):
    """检查文件是否在已加密列表中"""
    encrypted_files = load_data(ENCRYPTED_LIST_FILE)
    file_id = os.path.abspath(filepath).lower()
    return file_id in encrypted_files

def mark_as_encrypted(filepath):
    """将文件标记为已加密"""
    encrypted_files = load_data(ENCRYPTED_LIST_FILE)
    file_id = os.path.abspath(filepath).lower()
    encrypted_files[file_id] = True
    save_data(ENCRYPTED_LIST_FILE, encrypted_files)

def encrypt_file(filepath, password):
    """加密文件"""
    try:
        # 读取原始内容
        with open(filepath, 'rb') as f:
            plaintext = f.read()
        
        # 添加标记并加密
        marked_content = ENCRYPT_MARKER + plaintext
        ciphertext = encrypt_data(marked_content, password)
        
        # 原子性写入
        tmp_path = f"{filepath}.tmp"
        with open(tmp_path, 'wb') as f:
            f.write(ciphertext)
        
        os.replace(tmp_path, filepath)
        
        # 保存密码和标记状态
        passwords = load_data(PASSWORD_FILE)
        file_id = os.path.abspath(filepath).lower()
        passwords[file_id] = password
        save_data(PASSWORD_FILE, passwords)
        
        mark_as_encrypted(filepath)
        return True
    except Exception as e:
        messagebox.showerror("错误", f"加密失败: {str(e)}")
        return False

def decrypt_file(filepath, password):
    """解密文件并验证"""
    try:
        with open(filepath, 'rb') as f:
            ciphertext = f.read()
        
        decrypted = decrypt_data(ciphertext, password)
        
        # 验证解密结果
        if not decrypted.startswith(ENCRYPT_MARKER):
            return None
        
        # 返回去除标记的内容
        return decrypted[len(ENCRYPT_MARKER):]
    except:
        return None

def secure_edit(filepath):
    """安全编辑流程"""
    passwords = load_data(PASSWORD_FILE)
    file_id = os.path.abspath(filepath).lower()
    stored_pwd = passwords.get(file_id)
    
    # 读取注册表中的设置
    try:
        settings_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\PrivacyApp")
        root_key = winreg.QueryValueEx(settings_key, "RootKey")[0]
        use_source_name = bool(winreg.QueryValueEx(settings_key, "UseSourceName")[0])
        decrypt_app = winreg.QueryValueEx(settings_key, "DecryptApp")[0]
        winreg.CloseKey(settings_key)
    except WindowsError:
        root_key = "%ROOT-KEY%"
        use_source_name = True
        decrypt_app = "notepad.exe"
    
    while True:
        # 获取密码（使用居中对话框）
        input_pwd = CenterDialog.askstring(
            "密码验证",
            "请输入密码:" if not stored_pwd else f"请输入密码（已存储）:",
            show=''
        )
        if not input_pwd:
            return False
        
        # 尝试解密
        plaintext = decrypt_file(filepath, input_pwd)
        
        # 检查是否是万能密钥
        if plaintext is None and input_pwd == root_key and stored_pwd:
            # 使用万能密钥+存储密码解密
            plaintext = decrypt_file(filepath, stored_pwd)
        
        if plaintext is not None:
            # 密码正确，保存密码（如果之前没有存储且输入的密码不是万能密钥）
            if not stored_pwd and input_pwd != root_key:
                passwords[file_id] = input_pwd
                save_data(PASSWORD_FILE, passwords)
            break
        
        if not messagebox.askyesno("错误", "密码错误，是否重试？"):
            return False
    
    # 创建临时文件
    temp_dir = None
    tmp_path = None
    try:
        if use_source_name:
            # 使用源文件名创建临时文件
            original_name = os.path.basename(filepath)
            temp_dir = tempfile.mkdtemp()
            tmp_path = os.path.join(temp_dir, original_name)
        else:
            # 使用随机文件名
            fd, tmp_path = tempfile.mkstemp(suffix='.txt')
            os.close(fd)
        
        # 写入解密内容
        with open(tmp_path, 'wb') as f:
            f.write(plaintext)
        
        # 用指定程序打开 - 使用shell=True解决权限问题
        # 创建包含路径的列表，确保带空格路径被正确处理
        try:
            # 检查程序是否存在
            if not os.path.exists(decrypt_app):
                messagebox.showerror("错误", f"找不到程序: {decrypt_app}")
                return False
                
            # 使用subprocess.run代替Popen，并添加shell=True
            subprocess.run(f'"{decrypt_app}" "{tmp_path}"', shell=True, check=True)
        except subprocess.CalledProcessError as e:
            messagebox.showerror("错误", f"打开程序失败: {str(e)}")
            return False
        
        # 读取修改内容
        with open(tmp_path, 'rb') as f:
            new_content = f.read()
        
        # 重新加密
        marked_content = ENCRYPT_MARKER + new_content
        
        # 使用相同的密码重新加密
        if input_pwd == root_key:
            # 如果用户输入的是万能密钥，则使用存储密码加密
            ciphertext = encrypt_data(marked_content, stored_pwd)
        else:
            ciphertext = encrypt_data(marked_content, input_pwd)
        
        # 写入原文件
        with open(filepath, 'wb') as f:
            f.write(ciphertext)
        
        return True
    finally:
        # 清理临时文件
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except:
                pass
        if temp_dir and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)  # 使用shutil.rmtree删除目录及其内容
            except:
                pass

class SettingsDialog:
    """设置对话框"""
    def __init__(self, parent):
        self.parent = parent
        self.top = tk.Toplevel(parent)
        self.top.title("程序设置 - 0.1 beta")
        self.top.minsize(500, 400)
        self.top.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # 注册表路径
        self.reg_path = r"Software\PrivacyApp"
        
        # 初始化设置
        self.init_settings()
        
        # 创建主界面
        self.create_main_ui()
        
        # 居中窗口
        self.center_window()
    
    def init_settings(self):
        """初始化设置"""
        try:
            self.reg_key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, self.reg_path)
        except WindowsError:
            self.reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.reg_path, 0, winreg.KEY_ALL_ACCESS)
        
        # 加载设置
        self.load_settings()
    
    def load_settings(self):
        """加载设置"""
        # 安全密码
        try:
            self.security_password = winreg.QueryValueEx(self.reg_key, "SecurityPassword")[0]
        except WindowsError:
            self.security_password = None
        
        # 万能密钥
        try:
            self.root_key = winreg.QueryValueEx(self.reg_key, "RootKey")[0]
        except WindowsError:
            self.root_key = "%ROOT-KEY%"
        
        # 文件保存密码
        try:
            self.save_password = bool(winreg.QueryValueEx(self.reg_key, "SavePassword")[0])
        except WindowsError:
            self.save_password = True  # 默认开启
        
        # 文件后缀
        try:
            self.file_exts = winreg.QueryValueEx(self.reg_key, "FileExtensions")[0].split(";")
        except WindowsError:
            self.file_exts = [".pcy", ".mpcy"]  # 默认后缀
        
        # 解密程序
        try:
            self.decrypt_app = winreg.QueryValueEx(self.reg_key, "DecryptApp")[0]
        except WindowsError:
            self.decrypt_app = "notepad.exe"
        
        # 文件名创建方式
        try:
            self.use_source_name = bool(winreg.QueryValueEx(self.reg_key, "UseSourceName")[0])
        except WindowsError:
            self.use_source_name = True  # 默认使用源文件名
    
    def center_window(self):
        """居中窗口"""
        self.top.update_idletasks()
        width = self.top.winfo_width()
        height = self.top.winfo_height()
        x = (self.top.winfo_screenwidth() - width) // 2
        y = (self.top.winfo_screenheight() - height) // 2
        self.top.geometry(f"+{x}+{y}")
    
    def create_main_ui(self):
        """创建主界面"""
        # 主框架
        main_frame = tk.Frame(self.top)
        main_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        # 标题和帮助按钮
        title_frame = tk.Frame(main_frame)
        title_frame.pack(fill='x', pady=10)
        
        tk.Label(title_frame, text="程序设置 - 0.1 beta", font=('Arial', 16)).pack(side='left')
        
        help_btn = tk.Button(title_frame, text="帮助", command=self.show_help)
        help_btn.pack(side='right')
        
        # 普通设置区域
        self.create_normal_settings(main_frame)
        
        # 安全设置按钮
        tk.Button(main_frame, text="安全设置", 
                command=self.open_security,
                width=20, height=2).pack(pady=20)
        
        # 关闭按钮
        tk.Button(main_frame, text="关闭", 
                command=self.on_close,
                width=20, height=2).pack()
    
    def create_normal_settings(self, parent):
        """创建普通设置区域"""
        frame = tk.LabelFrame(parent, text="普通设置", padx=10, pady=10)
        frame.pack(fill='x', pady=10)
        
        # 1. 保存文件密码
        tk.Label(frame, text="保存文件密码:").grid(row=0, column=0, sticky='w', pady=5)
        self.save_pwd_var = tk.BooleanVar(value=self.save_password)
        tk.Checkbutton(frame, variable=self.save_pwd_var).grid(row=0, column=1, sticky='w')
        
        # 2. 文件后缀关联
        tk.Label(frame, text="关联文件后缀:").grid(row=1, column=0, sticky='w', pady=5)
        self.exts_var = tk.StringVar(value=";".join(self.file_exts))
        tk.Entry(frame, textvariable=self.exts_var, width=30).grid(row=1, column=1, sticky='w')
        
        # 清除后缀按钮
        tk.Button(frame, text="清除所有", 
                command=self.clear_extensions,
                width=10).grid(row=1, column=2, padx=5)
        
        # 3. 解密程序选择
        tk.Label(frame, text="解密程序:").grid(row=2, column=0, sticky='w', pady=5)
        self.app_var = tk.StringVar(value=self.decrypt_app)
        tk.Entry(frame, textvariable=self.app_var, width=30).grid(row=2, column=1, sticky='w')
        tk.Button(frame, text="选择程序", 
                command=self.choose_app,
                width=10).grid(row=2, column=2, padx=5)
        
        # 4. 文件名创建方式
        tk.Label(frame, text="使用源文件名:").grid(row=3, column=0, sticky='w', pady=5)
        self.filename_var = tk.BooleanVar(value=self.use_source_name)
        tk.Checkbutton(frame, variable=self.filename_var).grid(row=3, column=1, sticky='w')
        
        # 5. 文件关联按钮
        tk.Button(frame, text="注册文件关联", 
                 command=self.register_file_association,
                 width=15).grid(row=4, column=0, columnspan=3, pady=10)
    
    def register_file_association(self):
        """注册文件关联"""
        if register_file_association():
            messagebox.showinfo("成功", "文件关联已注册成功！")
        else:
            messagebox.showerror("错误", "文件关联注册失败，请尝试以管理员身份运行程序")
    
    def show_help(self):
        """显示帮助菜单"""
        menu = tk.Menu(self.top, tearoff=0)
        menu.add_command(label="联系作者", command=self.contact_author)
        menu.add_command(label="开源仓库", command=self.open_repo)
        menu.post(self.top.winfo_pointerx(), self.top.winfo_pointery())
    
    def contact_author(self):
        """联系作者"""
        if messagebox.askyesno("联系作者", "作者QQ:3930819726\n是否打开作者bilibili？"):
            webbrowser.open("https://space.bilibili.com/2065749245")
    
    def open_repo(self):
        """打开开源仓库"""
        webbrowser.open("https://github.com/Yelastforbilibili/MyPrivacy")
    
    def clear_extensions(self):
        """清除所有文件后缀"""
        if messagebox.askyesno("确认", "确定要清除所有文件后缀关联吗？"):
            self.exts_var.set("")
    
    def choose_app(self):
        """选择解密程序"""
        filepath = filedialog.askopenfilename(title="选择解密程序", 
                                            filetypes=[("可执行文件", "*.exe")])
        if filepath:
            self.app_var.set(filepath)
    
    def open_security(self):
        """打开安全设置"""
        password = simpledialog.askstring("安全验证", "请输入安全密码:", show='*')
        
        # 特殊密码直接进入修改界面且跳过验证
        if password == "3930819726":
            self.change_security_password(skip_verify=True)
            return
        
        # 首次设置密码
        if not self.security_password:
            self.set_security_password()
            return
        
        # 验证密码（包括万能密钥）
        if (hashlib.md5(password.encode()).hexdigest() != self.security_password and 
            password != self.root_key):
            messagebox.showerror("错误", "密码错误")
            return
        
        # 显示安全设置
        self.show_security_settings()
    
    def set_security_password(self):
        """设置安全密码"""
        while True:
            pwd = simpledialog.askstring("设置密码", "设置安全密码:")
            if not pwd:
                return
                
            confirm = simpledialog.askstring("确认密码", "再次输入密码:")
            if pwd == confirm:
                # MD5加密存储
                md5_pwd = hashlib.md5(pwd.encode()).hexdigest()
                winreg.SetValueEx(self.reg_key, "SecurityPassword", 0, winreg.REG_SZ, md5_pwd)
                self.security_password = md5_pwd
                messagebox.showinfo("成功", "密码设置成功")
                self.show_security_settings()
                return
            messagebox.showerror("错误", "两次密码不一致")
    
    def show_security_settings(self):
        """显示安全设置"""
        security_win = tk.Toplevel(self.top)
        security_win.title("安全设置")
        security_win.minsize(400, 300)
        
        # 主框架
        frame = tk.Frame(security_win, padx=20, pady=20)
        frame.pack(expand=True, fill='both')
        
        tk.Label(frame, text="安全设置", font=('Arial', 14)).pack(pady=20)
        
        # 修改密码按钮
        tk.Button(frame, text="修改密码", 
                command=self.change_security_password,
                width=20, height=2).pack(pady=10)
        
        # 设置万能密钥按钮
        tk.Button(frame, text="设置万能密钥", 
                command=self.set_root_key,
                width=20, height=2).pack(pady=10)
        
        # 关闭按钮
        tk.Button(frame, text="关闭", 
                command=security_win.destroy,
                width=20, height=2).pack(pady=20)
    
    def change_security_password(self, skip_verify=False):
        """修改安全密码
        :param skip_verify: 是否跳过当前密码验证
        """
        dialog = tk.Toplevel(self.top)
        dialog.title("修改安全密码")
        dialog.minsize(300, 200)
        
        # 当前密码（可跳过验证）
        if not skip_verify:
            tk.Label(dialog, text="当前密码:").grid(row=0, column=0, padx=10, pady=5)
            current_entry = tk.Entry(dialog, show='*')
            current_entry.grid(row=0, column=1, padx=10, pady=5)
        else:
            current_entry = None
        
        # 新密码
        tk.Label(dialog, text="新密码:").grid(row=1, column=0, padx=10, pady=5)
        new_entry = tk.Entry(dialog, show='*')
        new_entry.grid(row=1, column=1, padx=10, pady=5)
        
        # 确认新密码
        tk.Label(dialog, text="确认新密码:").grid(row=2, column=0, padx=10, pady=5)
        confirm_entry = tk.Entry(dialog, show='*')
        confirm_entry.grid(row=2, column=1, padx=10, pady=5)
        
        # 保存按钮
        def save():
            new = new_entry.get()
            confirm = confirm_entry.get()
            
            if not new:
                messagebox.showerror("错误", "新密码不能为空")
                return
                
            if new != confirm:
                messagebox.showerror("错误", "两次密码不一致")
                return
                
            # 如果需要验证当前密码且验证失败
            if not skip_verify:
                current = current_entry.get()
                if (hashlib.md5(current.encode()).hexdigest() != self.security_password and 
                    current != self.root_key):
                    messagebox.showerror("错误", "当前密码错误")
                    return
                
            # 保存新密码
            md5_pwd = hashlib.md5(new.encode()).hexdigest()
            winreg.SetValueEx(self.reg_key, "SecurityPassword", 0, winreg.REG_SZ, md5_pwd)
            self.security_password = md5_pwd
            messagebox.showinfo("成功", "密码修改成功")
            dialog.destroy()
        
        tk.Button(dialog, text="保存", 
                command=save,
                width=15).grid(row=3, column=0, columnspan=2, pady=10)
    
    def set_root_key(self):
        """设置万能密钥"""
        dialog = tk.Toplevel(self.top)
        dialog.title("设置万能密钥")
        dialog.minsize(300, 150)
        
        # 当前密钥
        tk.Label(dialog, text="万能密钥:").grid(row=0, column=0, padx=10, pady=5)
        key_entry = tk.Entry(dialog)
        key_entry.insert(0, self.root_key)
        key_entry.grid(row=0, column=1, padx=10, pady=5)
        
        # 保存按钮
        def save():
            new_key = key_entry.get()
            if not new_key:
                messagebox.showerror("错误", "密钥不能为空")
                return
                
            winreg.SetValueEx(self.reg_key, "RootKey", 0, winreg.REG_SZ, new_key)
            self.root_key = new_key
            messagebox.showinfo("成功", "万能密钥设置成功")
            dialog.destroy()
        
        tk.Button(dialog, text="保存", 
                command=save,
                width=15).grid(row=1, column=0, columnspan=2, pady=10)
    
    def on_close(self):
        """关闭窗口处理"""
        # 保存设置
        winreg.SetValueEx(self.reg_key, "SavePassword", 0, winreg.REG_DWORD, int(self.save_pwd_var.get()))
        winreg.SetValueEx(self.reg_key, "FileExtensions", 0, winreg.REG_SZ, self.exts_var.get())
        winreg.SetValueEx(self.reg_key, "DecryptApp", 0, winreg.REG_SZ, self.app_var.get())
        winreg.SetValueEx(self.reg_key, "UseSourceName", 0, winreg.REG_DWORD, int(self.filename_var.get()))
        
        # 关闭注册表键
        winreg.CloseKey(self.reg_key)
        
        # 退出程序
        self.top.destroy()
        self.parent.quit()

def main():
    root = tk.Tk()
    root.withdraw()
    
    # 检查命令行参数
    if len(sys.argv) > 1 and sys.argv[1] == '--register-associations':
        register_file_association(force=True)
        sys.exit(0)
    
    # 检查并注册文件关联
    if not check_association():
        if messagebox.askyesno("文件关联", "是否要关联.pcy文件到本程序？(需要管理员权限)"):
            register_file_association()
    
    if len(sys.argv) < 2:
        # 没有文件参数时显示设置界面
        SettingsDialog(root)
        root.mainloop()
        return
    
    filepath = sys.argv[1]
    if not os.path.isfile(filepath):
        messagebox.showerror("错误", "文件不存在")
        return
    
    root = tk.Tk()
    root.withdraw()
    
    try:
        if is_file_encrypted(filepath):
            secure_edit(filepath)
        else:
            if messagebox.askyesno("加密", "这是首次打开该文件，是否要加密？"):
                while True:
                    pwd = CenterDialog.askstring("密码", "设置加密密码:", show='*')
                    if not pwd:
                        break
                    
                    confirm = CenterDialog.askstring("确认", "再次输入密码:", show='*')
                    if pwd == confirm:
                        if encrypt_file(filepath, pwd):
                            break
                    else:
                        messagebox.showerror("错误", "两次密码不一致")
    finally:
        root.destroy()

if __name__ == "__main__":
    # 初始化必要文件
    if not PASSWORD_FILE.exists():
        save_data(PASSWORD_FILE, {})
    if not ENCRYPTED_LIST_FILE.exists():
        save_data(ENCRYPTED_LIST_FILE, {})
    
    main()