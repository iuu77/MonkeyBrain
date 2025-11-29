import subprocess
import re
import time
from datetime import datetime
import os
import argparse
import json
import sys

class AndroidMemoryMonitor:
    def __init__(self, config):
        self.device_id = config.get('device_id')
        self.monkey_events = config.get('monkey_events', 600)
        self.monitor_duration = config.get('monitor_duration', 10)
        self.interval = config.get('interval', 30)
        self.threshold = config.get('threshold', 50)
        self.target_package = config.get('target_package', 'com.android.chrome')
        
        # 新增：完整的Monkey参数配置
        self.monkey_params = config.get('monkey_params', {
            'throttle': 100,
            'ignore_crashes': True,
            'ignore_timeouts': True,
            'monitor_native_crashes': True,
            'verbose': 3  # -v -v -v
        })
        
        # 使用时间戳创建目录
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        self.monkeylog_dir = f"monkey_logs_{timestamp}"
        self.logcat_dir = f"logcat_logs_{timestamp}"
        
        # 创建目录
        #os.makedirs(self.monkeylog_dir, exist_ok=True)
        #os.makedirs(self.logcat_dir, exist_ok=True)
        #print(f"📁 创建输出目录:")
        #print(f"   ├── {self.monkeylog_dir}/  (Monkey日志)")
        #print(f"   └── {self.logcat_dir}/  (Logcat日志)")
        
        self.log_file = os.path.join(self.monkeylog_dir, f"monkey_log_{timestamp}.log")
        self.baseline_memory = {}
    
    def run_adb_command(self, command):
        cmd = ['adb']
        if self.device_id:
            cmd.extend(['-s', self.device_id])
        cmd.extend(command.split())
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"ADB命令执行失败: {e}")
            return None
    
    def capture_logcat(self, issue_type):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        logcat_filename = f"logcat_{issue_type}_{timestamp}.log"
        local_logcat_file = os.path.join(self.logcat_dir, logcat_filename)
        
        print(f"Capturing logcat for {issue_type}...")
        try:
            logcat_cmd = ['adb']
            if self.device_id:
                logcat_cmd.extend(['-s', self.device_id])
            logcat_cmd.extend(['logcat', '-d', '-v', 'threadtime'])
            
            with open(local_logcat_file, 'w', encoding='utf-8') as f:
                result = subprocess.run(logcat_cmd, stdout=f, stderr=subprocess.PIPE, text=True)
            
            if result.returncode == 0:
                print(f"Logcat captured successfully: {local_logcat_file}")
                return local_logcat_file
            else:
                print(f"Failed to capture logcat: {result.stderr}")
                return None
        except Exception as e:
            print(f"Error capturing logcat: {e}")
            return None
    
    def get_process_memory(self):
        output = self.run_adb_command('shell top -n 1 -o RES')
        if not output:
            return {}
        
        process_memory = {}
        lines = output.split('\n')
        for line in lines[5:]:
            parts = re.split(r'\s+', line.strip())
            if len(parts) >= 10:
                pid = parts[0]
                name = parts[-1]
                mem = int(parts[5])  # RES列
                process_memory[f"{name}({pid})"] = mem
        return process_memory
    
    def print_memory_summary(self, memory_dict, check_number, elapsed_time):
        if not memory_dict:
            print("No memory data available")
            return
        
        total_memory_kb = sum(memory_dict.values())
        total_memory_mb = total_memory_kb // 1024
        
        sorted_memory = sorted(memory_dict.items(), key=lambda x: x[1], reverse=True)[:5]
        
        print(f"\n=== Memory Check #{check_number} at {elapsed_time}s ===")
        print(f"Total processes monitored: {len(memory_dict)}")
        print(f"Total memory usage: {total_memory_mb} MB ({total_memory_kb} KB)")
        print("Top 5 memory consumers:")
        
        for process, mem_kb in sorted_memory:
            mem_mb = mem_kb // 1024
            if self.target_package in process:
                print(f"  🎯 {process}: {mem_mb} MB ({mem_kb} KB)")
            else:
                print(f"     {process}: {mem_mb} MB ({mem_kb} KB)")
    
    def check_memory_leak(self, current_memory):
        leaks = []
        has_leaks = False
        
        for process, mem in current_memory.items():
            if process in self.baseline_memory:
                baseline = self.baseline_memory[process]
                if baseline > 0:
                    increase = ((mem - baseline) / baseline) * 100
                    if increase > self.threshold:
                        leak = f"{process}: memory increased {increase:.2f}% (from {baseline}KB to {mem}KB)"
                        leaks.append(leak)
                        has_leaks = True
                        self.capture_logcat("MEMORY_LEAK")
        
        return leaks, has_leaks
    
    def analyze_monkey_log(self):
        if not os.path.exists(self.log_file):
            print(f"Monkey log file not found: {self.log_file}")
            return []
        
        issues = []
        with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    if 'ANR' in line.upper():
                        match = re.search(r'ANR in (\S+)', line, re.IGNORECASE)
                        if match:
                            issue = f"ANR detected in process: {match.group(1)} (line {line_num})"
                            issues.append(issue)
                            self.capture_logcat("ANR")
                    
                    elif 'CRASH' in line.upper():
                        match = re.search(r'CRASH:?\s*(\S+)', line, re.IGNORECASE)
                        if match:
                            issue = f"Crash detected in process: {match.group(1)} (line {line_num})"
                            issues.append(issue)
                            self.capture_logcat("CRASH")
                    
                    elif 'exception' in line.lower():
                        match = re.search(r'(\S+).*exception', line, re.IGNORECASE)
                        if match:
                            issue = f"Exception detected in process: {match.group(1)} (line {line_num})"
                            issues.append(issue)
                            self.capture_logcat("EXCEPTION")
                except Exception as e:
                    print(f"Error processing line {line_num}: {e}")
                    continue
        
        return issues
    
    def start_monkey_test(self):
        print(f"Starting Monkey test for {self.monkey_events} events on package {self.target_package}...")
        
        # 构建Monkey命令参数
        monkey_cmd = f'shell monkey -p {self.target_package}'
        
        # 添加所有可配置参数
        if 'throttle' in self.monkey_params:
            monkey_cmd += f" --throttle {self.monkey_params['throttle']}"
        if self.monkey_params.get('ignore_crashes', True):
            monkey_cmd += " --ignore-crashes"
        if self.monkey_params.get('ignore_timeouts', True):
            monkey_cmd += " --ignore-timeouts"
        if self.monkey_params.get('monitor_native_crashes', True):
            monkey_cmd += " --monitor-native-crashes"
        
        # 处理verbose级别
        verbose_level = self.monkey_params.get('verbose', 3)
        monkey_cmd += ' -v' * min(verbose_level, 3)
        
        # 添加其他自定义参数
        if 'extra_args' in self.monkey_params:
            monkey_cmd += f" {self.monkey_params['extra_args']}"
        
        # 添加事件数
        monkey_cmd += f" {self.monkey_events}"
        
        print(f"Generated Monkey command: {monkey_cmd}")
        
        try:
            with open(self.log_file, 'w', encoding='utf-8') as log:
                full_cmd = ['adb'] + (['-s', self.device_id] if self.device_id else []) + monkey_cmd.split()
                subprocess.run(full_cmd, stdout=log, stderr=subprocess.STDOUT)
            print(f"Monkey test started, logging to: {self.log_file}")
        except Exception as e:
            print(f"Failed to start Monkey test: {e}")
    
    def call_analyze_tool(self):
        """调用 analyze.py 工具分析 Monkey 日志"""
        try:
            # 检查 analyze.py 是否存在
            script_dir = os.path.dirname(os.path.abspath(__file__))
            analyze_script = os.path.join(script_dir, 'analyze.py')
            
            if not os.path.exists(analyze_script):
                # 尝试当前工作目录
                analyze_script = 'analyze.py'
                if not os.path.exists(analyze_script):
                    print(f"\n⚠️  未找到 analyze.py，跳过日志分析")
                    return None
            
            # 检查日志文件是否存在
            if not os.path.exists(self.log_file):
                print(f"\n⚠️  日志文件不存在: {self.log_file}")
                return None
            
            print(f"\n" + "="*60)
            print(f"🔍 正在调用 analyze.py 进行深度日志分析...")
            print(f"   日志文件: {os.path.basename(self.log_file)}")
            print("="*60)
            
            # 构建命令
            log_abs_path = os.path.abspath(self.log_file)
            cmd = ['python', analyze_script, log_abs_path]
            
            # 如果指定了包名，添加 --package 参数
            if self.target_package:
                cmd.extend(['--package', self.target_package])
            
            # 执行 analyze.py
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5分钟超时
            )
            
            # 打印输出
            if result.stdout:
                print(result.stdout)
            
            if result.returncode == 0:
                print(f"\n✅ analyze.py 执行成功")
                return True
            else:
                print(f"\n❌ analyze.py 执行失败 (退出码: {result.returncode})")
                if result.stderr:
                    print(f"错误信息: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"\n⏱️  analyze.py 执行超时（>5分钟）")
            return False
        except FileNotFoundError:
            print(f"\n⚠️  未找到 Python 解释器或 analyze.py")
            return False
        except Exception as e:
            print(f"\n⚠️  调用 analyze.py 时出错: {e}")
            return False
    def monitor(self):
        check_count = 0
        start_time = time.time()

        try:
            while True:
                timestamp2 = datetime.now().strftime('%Y%m%d_%H%M%S')
                self.logcat_dir = f"logcat_logs_{timestamp2}"
                self.monkeylog_dir = f"monkey_logs_{timestamp2}"
                self.log_file = os.path.join(self.monkeylog_dir, f"monkey_log_{timestamp2}.log")
                os.makedirs(self.monkeylog_dir, exist_ok=True)
                os.makedirs(self.logcat_dir, exist_ok=True)
                print(f"📁 创建输出目录:")
                print(f"   ├── {self.monkeylog_dir}/  (Monkey日志)")
                print(f"   └── {self.logcat_dir}/  (Logcat日志)")
                check_count += 1
                print(f"Starting monitoring...count: {check_count}")
                self.start_monkey_test()

                self.capture_logcat("monkey")
                print("monkey completed successfully!")

                if time.time() - start_time > self.monitor_duration:
                    print(f"total test completed, test count: {check_count}")
                    break
            
            # 调用 analyze.py 进行深度日志分析
            self.call_analyze_tool()
        
        except KeyboardInterrupt:
            print("\nMonitoring interrupted by user")
            # 即使被中断也尝试分析已有日志
            self.call_analyze_tool()
        except Exception as e:
            print(f"Monitoring error: {e}")
            # 即使出错也尝试分析已有日志
            self.call_analyze_tool()

def load_config_from_file(config_file):
    if not os.path.exists(config_file):
        return None
    with open(config_file, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON format in {config_file}")
            return None

def generate_default_config(config_file='default_config.json'):
    default_config = {
        'device_id': None,
        'monkey_events': 600,
        'monitor_duration': 10,
        'interval': 30,
        'threshold': 50,
        'target_package': 'com.android.chrome',
        # 新增：默认Monkey参数配置
        'monkey_params': {
            'throttle': 100,
            'ignore_crashes': True,
            'ignore_timeouts': True,
            'monitor_native_crashes': True,
            'verbose': 3,
            # 可以添加更多参数如：
            # 'pct_touch': 70,
            # 'pct_motion': 20,
            # 'extra_args': '--pct-nav 10'
        }
    }
    with open(config_file, 'w') as f:
        json.dump(default_config, f, indent=4)
    print(f"Default config generated: {config_file}")
    return default_config

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Android Memory Monitor Tool',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
示例用法:
  基本用法: python android_memory_monitor.py
  指定设备: python android_memory_monitor.py --device emulator-5554
  自定义配置: python android_memory_monitor.py --config custom_config.json
  动态参数: python android_memory_monitor.py --set target_package com.example.app interval 20
  生成默认配置: python android_memory_monitor.py --generate-config

参数说明:
  --events: 指定Monkey测试的事件数量（默认 600）
  --duration: 内存监控持续时间（秒，默认 300）
  --interval: 内存检查间隔（秒，默认 30）
  --threshold: 内存增长百分比阈值（默认 50%）
  --monkey-params: JSON格式的Monkey参数（可选）
""")
    parser.add_argument('--config', type=str, help='JSON配置文件路径')
    parser.add_argument('--generate-config', action='store_true', help='生成默认配置文件(default_config.json)')

    monitor_group = parser.add_argument_group('监控参数')
    monitor_group.add_argument('--device', type=str, help='设备ID，例如 emulator-5554')
    monitor_group.add_argument('--package', type=str, help='目标应用包名，例如 com.example.app')
    monitor_group.add_argument('--events', type=int, help='Monkey测试事件数量（默认 600）')
    monitor_group.add_argument('--duration', type=int, help='内存监控持续时间（秒，默认 300）')
    monitor_group.add_argument('--interval', type=int, help='内存检查间隔（秒，默认 30）')
    monitor_group.add_argument('--threshold', type=int, help='内存增长百分比阈值（默认 50）')
    monitor_group.add_argument('--monkey-params', type=str, help='JSON格式的Monkey参数配置')

    dynamic_group = parser.add_argument_group('动态参数')
    dynamic_group.add_argument('--set', action='append', nargs='+', 
                              help='设置任意配置键值对，例如 --set target_package com.test interval 60 monkey_params.verbose 2')

    
    return parser.parse_args()

def process_custom_args(args, config):
    if args.set:
        for i in range(0, len(args.set[0]), 2):
            if i+1 < len(args.set[0]):
                key = args.set[0][i]
                value = args.set[0][i+1]
                try:
                    # 处理嵌套参数（如 monkey_params.throttle）
                    if '.' in key:
                        parts = key.split('.')
                        current = config
                        for part in parts[:-1]:
                            if part not in current:
                                current[part] = {}
                            current = current[part]
                        current[parts[-1]] = parse_value(value)
                    else:
                        config[key] = parse_value(value)
                except Exception as e:
                    print(f"Error processing argument {key}={value}: {e}")
    
    # 处理单独的monkey_params参数
    if args.monkey_params:
        try:
            monkey_params = json.loads(args.monkey_params)
            if isinstance(monkey_params, dict):
                config['monkey_params'] = monkey_params
        except json.JSONDecodeError:
            print("Warning: Invalid JSON format for --monkey-params")
    
    return config

def parse_value(value):
    """智能转换参数值的类型"""
    if value.lower() == 'true':
        return True
    elif value.lower() == 'false':
        return False
    elif value.isdigit():
        return int(value)
    elif value.replace('.', '', 1).isdigit():
        return float(value)
    else:
        return value

def get_configuration():
    args = parse_arguments()
    if args.generate_config:
        return generate_default_config()
    
    config = {
        'device_id': None,
        'monkey_events': 600,
        'monitor_duration': 10,
        'interval': 30,
        'threshold': 50,
        'target_package': 'com.android.chrome',
        'monkey_params': {
            'throttle': 100,
            'ignore_crashes': True,
            'ignore_timeouts': True,
            'monitor_native_crashes': True,
            'verbose': 3
        }
    }
    
    if args.config:
        file_config = load_config_from_file(args.config)
        if file_config:
            config.update(file_config)
    else:
        args.config = "default_config.json"
        file_config = load_config_from_file(args.config)
        if file_config:
            config.update(file_config)
        else:
            generate_default_config()

    
    if args.device:
        config['device_id'] = args.device
    if args.package:
        config['target_package'] = args.package
    if args.events:
        config['monkey_events'] = args.events
    if args.duration:
        config['monitor_duration'] = args.duration
    if args.interval:
        config['interval'] = args.interval
    if args.threshold:
        config['threshold'] = args.threshold
    
    config = process_custom_args(args, config)
    
    return config

if __name__ == "__main__":
    try:
        config = get_configuration()
        monitor = AndroidMemoryMonitor(config)
        monitor.monitor()
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)
