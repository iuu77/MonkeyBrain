#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
精细化Monkey日志根因分析工具 - 列表式报告输出
功能：提供代码级定位和具体问题分类，以清晰列表形式呈现
"""

import re
import os
import sys
import json
import hashlib
import subprocess
from datetime import datetime
from collections import defaultdict, Counter
import argparse

# ========================================
# Windows GBK编码兼容处理
# ========================================

def safe_print(text, **kwargs):
    """安全打印函数，处理Windows GBK编码问题"""
    try:
        print(text, **kwargs)
    except UnicodeEncodeError:
        # 移除emoji和特殊字符
        safe_text = text.encode('gbk', errors='ignore').decode('gbk')
        print(safe_text, **kwargs)

def get_emoji(emoji_char, fallback=''):
    """获取emoji字符，Windows GBK环境返回fallback"""
    try:
        # 测试是否能编码
        emoji_char.encode(sys.stdout.encoding or 'utf-8')
        return emoji_char
    except (UnicodeEncodeError, AttributeError):
        return fallback

# Emoji映射（Windows兼容）
EMOJI = {
    'check': get_emoji('✅', '[OK]'),
    'cross': get_emoji('❌', '[X]'),
    'warning': get_emoji('⚠️', '[!]'),
    'folder': get_emoji('📁', '[DIR]'),
    'file': get_emoji('📂', '[FILE]'),
    'search': get_emoji('🔍', '[SEARCH]'),
    'save': get_emoji('💾', '[SAVE]'),
    'process': get_emoji('🔄', '[PROC]'),
    'clock': get_emoji('⏱️', '[TIME]'),
    'target': get_emoji('🎯', '[TARGET]'),
    'note': get_emoji('📝', '[NOTE]'),
    'chart': get_emoji('📊', '[CHART]'),
    'red_circle': get_emoji('🔴', '[CRASH]'),
    'yellow_circle': get_emoji('🟡', '[ANR]'),
    'orange_circle': get_emoji('🟠', '[EXCEPTION]'),
    'clipboard': get_emoji('📋', '[REPORT]'),
    'phone': get_emoji('📱', '[DEVICE]'),
    'blue_circle': get_emoji('🔵', '[MEDIUM]'),
    'green_circle': get_emoji('🟢', '[LOW]'),
    'star': get_emoji('🌟', '[EXCELLENT]'),
    'thumbs_up': get_emoji('👍', '[GOOD]'),
    'bulb': get_emoji('💡', '[TIP]'),
}

class ListStyleMonkeyAnalyzer:
    def __init__(self, target_package=None):
        self.target_package = target_package
        self.monkey_log = []
        self.log_file_path = None  # 保存Monkey日志文件路径
        self.logcat_dir_path = None  # 保存对应的Logcat目录路径
        self.analysis_results = {
            'crashes': [],
            'anrs': [],
            'exceptions': [],
            'performance_issues': [],
            'test_summary': {},
            'code_level_issues': defaultdict(list),
            'component_issues': defaultdict(list)
        }
        # Monkey自身相关的包名/进程名，需要过滤
        self.monkey_internal_patterns = [
            'flipjava.io',
            'com.android.commands.monkey',
            'android.app.Instrumentation',
            '/system/bin/monkey',
            'MonkeySourceNetwork',
            'MonkeySourceRandom'
        ]

    def load_monkey_log(self, file_path):
        """加载Monkey日志文件"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                self.monkey_log = f.readlines()
            
            # 保存日志文件路径（绝对路径）
            self.log_file_path = os.path.abspath(file_path)
            
            # 尝试找到对应的 logcat_logs 目录
            # 如果日志文件在 monkey_logs_xxx 目录中，查找对应的 logcat_logs_xxx 目录
            file_dir = os.path.dirname(self.log_file_path)
            dir_name = os.path.basename(file_dir)
            
            if dir_name.startswith('monkey_logs_'):
                # 提取时间戳
                timestamp = dir_name.replace('monkey_logs_', '')
                # 构建对应的 logcat_logs 目录路径
                parent_dir = os.path.dirname(file_dir)
                logcat_dir = os.path.join(parent_dir, f'logcat_logs_{timestamp}')
                
                # 检查目录是否存在
                if os.path.exists(logcat_dir) and os.path.isdir(logcat_dir):
                    self.logcat_dir_path = logcat_dir
                    safe_print(f"{EMOJI['check']} 找到对应的 Logcat 目录: {logcat_dir}")
                else:
                    self.logcat_dir_path = None
            else:
                self.logcat_dir_path = None
            
            safe_print(f"{EMOJI['check']} 已加载Monkey日志: {file_path} ({len(self.monkey_log)} 行)")
            return True
        except Exception as e:
            safe_print(f"{EMOJI['cross']} 加载Monkey日志失败: {e}")
            return False
    
    def _is_monkey_internal_error(self, process_name, context=""):
        """判断是否是Monkey工具自身的错误
        
        Args:
            process_name: 进程名
            context: 上下文信息（堆栈、错误详情等）
            
        Returns:
            bool: True表示是Monkey自身错误，应该过滤掉
        """
        # 检查进程名
        if process_name:
            for pattern in self.monkey_internal_patterns:
                if pattern in process_name:
                    return True
        
        # 检查上下文
        if context:
            for pattern in self.monkey_internal_patterns:
                if pattern in context:
                    return True
        
        return False
    
    # ==================== 增强功能：智能错误去重 ====================
    
    def _calculate_stack_signature(self, error):
        """计算错误的堆栈签名，用于去重
        
        签名组成：异常类型 + 关键调用方法（前3个）+ 进程名
        """
        context = ' '.join(error.get('context', []))
        
        # 提取异常类型
        exception_pattern = r'(\w+Exception|\w+Error)'
        exceptions = re.findall(exception_pattern, context)
        exception_type = exceptions[0] if exceptions else 'Unknown'
        
        # 提取调用栈中的关键方法（前3个）
        method_pattern = r'at ([\w\.$]+\.[\w]+)\('
        methods = re.findall(method_pattern, context)
        key_methods = methods[:3] if methods else []
        
        # 组合签名
        signature_parts = [
            exception_type,
            error.get('processName', ''),
            *key_methods
        ]
        
        signature = '|'.join(signature_parts)
        return hashlib.md5(signature.encode()).hexdigest()[:16]
    
    def deduplicate_errors(self, errors):
        """对错误进行去重并统计"""
        error_groups = defaultdict(lambda: {
            'error': None,
            'count': 0,
            'timestamps': [],
            'first_seen': None,
            'last_seen': None
        })
        
        for error in errors:
            signature = self._calculate_stack_signature(error)
            group = error_groups[signature]
            
            if group['error'] is None:
                group['error'] = error
                group['first_seen'] = error.get('timestamp')
            
            group['count'] += 1
            group['timestamps'].append(error.get('timestamp'))
            group['last_seen'] = error.get('timestamp')
        
        # 构建去重后的结果
        deduplicated = []
        for signature, group in error_groups.items():
            error = group['error'].copy()
            error['deduplication'] = {
                'signature': signature,
                'occurrences': group['count'],
                'first_seen': group['first_seen'],
                'last_seen': group['last_seen'],
                'frequency': self._calculate_frequency(group['timestamps'])
            }
            deduplicated.append(error)
        
        # 按出现次数降序排序
        deduplicated.sort(key=lambda x: x['deduplication']['occurrences'], reverse=True)
        
        return deduplicated
    
    def _calculate_frequency(self, timestamps):
        """计算错误频率（次/分钟）"""
        if len(timestamps) < 2:
            return 0
        
        try:
            first = datetime.fromisoformat(timestamps[0].replace('Z', '+00:00'))
            last = datetime.fromisoformat(timestamps[-1].replace('Z', '+00:00'))
            duration_minutes = (last - first).total_seconds() / 60
            
            if duration_minutes == 0:
                return len(timestamps)
            
            return round(len(timestamps) / duration_minutes, 2)
        except:
            return 0
    
    # ==================== 增强功能：错误严重性评分 ====================
    
    def calculate_severity_score(self, error):
        """计算错误严重性得分（0-100分）"""
        score = 0
        details = {}
        
        # 1. 错误类型权重 (0-40分)
        category_scores = {
            'crash': 40,
            'anr': 30,
            'exception': 15
        }
        type_score = category_scores.get(error['category'], 10)
        score += type_score
        details['type_score'] = type_score
        
        # 2. 影响范围 (0-20分)
        impact_score = self._calculate_impact_score(error)
        score += impact_score
        details['impact_score'] = impact_score
        
        # 3. 复现频率 (0-20分)
        frequency_score = self._calculate_frequency_score(error)
        score += frequency_score
        details['frequency_score'] = frequency_score
        
        # 4. 用户影响程度 (0-20分)
        user_impact_score = self._calculate_user_impact_score(error)
        score += user_impact_score
        details['user_impact_score'] = user_impact_score
        
        # 确定优先级
        priority = self._get_priority_level(score)
        
        return {
            'total_score': min(score, 100),
            'priority': priority,
            'details': details
        }
    
    def _calculate_impact_score(self, error):
        """计算影响范围得分"""
        score = 0
        process_name = error.get('processName', '').lower()
        context = ' '.join(error.get('context', [])).lower()
        
        # 主进程崩溃
        if ':' not in process_name:
            score += 10
        
        # 关键模块识别
        critical_modules = [
            'activity', 'mainactivity', 'launcher',
            'payment', 'login', 'auth',
            'application', 'service'
        ]
        if any(module in process_name or module in context for module in critical_modules):
            score += 10
        
        return min(score, 20)
    
    def _calculate_frequency_score(self, error):
        """计算复现频率得分"""
        if 'deduplication' not in error:
            return 0
        
        occurrences = error['deduplication']['occurrences']
        
        if occurrences >= 10:
            return 20
        elif occurrences >= 5:
            return 15
        elif occurrences >= 3:
            return 10
        else:
            return 5
    
    def _calculate_user_impact_score(self, error):
        """计算用户影响程度得分"""
        context = ' '.join(error.get('context', [])).lower()
        
        # 阻塞型错误
        blocking_patterns = [
            'fatal', 'unable to start', 'cannot create',
            'force close', 'application not responding'
        ]
        if any(pattern in context for pattern in blocking_patterns):
            return 20
        
        # 降级型错误
        degraded_patterns = [
            'slow', 'timeout', 'retry',
            'null', 'not found', 'invalid'
        ]
        if any(pattern in context for pattern in degraded_patterns):
            return 10
        
        return 5
    
    def _get_priority_level(self, score):
        """根据得分确定优先级"""
        if score >= 80:
            return 'CRITICAL'
        elif score >= 60:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def prioritize_errors(self, errors):
        """对所有错误进行评分和排序"""
        for error in errors:
            severity_info = self.calculate_severity_score(error)
            error['severity'] = severity_info
        
        # 按严重性得分降序排序
        errors.sort(key=lambda x: x['severity']['total_score'], reverse=True)
        
        return errors
    
    # ==================== 增强功能：智能根因定位 ====================
    
    def analyze_root_cause(self, error):
        """智能根因分析"""
        context = ' '.join(error.get('context', []))
        
        # 1. 识别代码归属
        code_attribution = self._identify_code_attribution(context)
        
        # 2. 定位最可能的出错点
        error_location = self._locate_error_point(context, code_attribution)
        
        # 3. 识别错误模式
        error_pattern = self._identify_error_pattern(context)
        
        # 4. 生成修复建议
        fix_suggestions = self._generate_fix_suggestions(error_pattern, error_location)
        
        return {
            'code_attribution': code_attribution,
            'error_location': error_location,
            'error_pattern': error_pattern,
            'fix_suggestions': fix_suggestions,
            'confidence': self._calculate_confidence(error_location, error_pattern)
        }
    
    def _identify_code_attribution(self, context):
        """识别代码归属"""
        stack_pattern = r'at ([\w\.$]+)\.(\w+)\(([\w\.]+):(\d+)\)'
        matches = re.findall(stack_pattern, context)
        
        attributions = []
        for class_path, method, file, line in matches:
            attribution = {
                'class': class_path,
                'method': method,
                'file': file,
                'line': int(line),
                'type': self._classify_code_type(class_path)
            }
            attributions.append(attribution)
        
        return attributions
    
    def _classify_code_type(self, class_path):
        """分类代码类型"""
        if class_path.startswith('android.') or class_path.startswith('java.'):
            return 'SYSTEM'
        elif any(lib in class_path for lib in ['okhttp', 'retrofit', 'glide', 'gson', 'kotlinx']):
            return 'THIRD_PARTY'
        else:
            return 'APPLICATION'
    
    def _locate_error_point(self, context, attributions):
        """定位最可能的出错点"""
        # 优先查找应用代码
        app_code = [attr for attr in attributions if attr['type'] == 'APPLICATION']
        
        if app_code:
            location = app_code[0]
        elif attributions:
            location = attributions[0]
        else:
            return None
        
        # 提取代码片段
        location['code_snippet'] = self._extract_code_snippet(context, location)
        
        return location
    
    def _extract_code_snippet(self, context, location):
        """提取代码片段提示"""
        snippets = []
        
        # 从Long Msg中提取
        long_msg_pattern = r'Long Msg: (.+?)(?://|$)'
        long_msgs = re.findall(long_msg_pattern, context)
        if long_msgs:
            snippets.extend(long_msgs)
        
        # 从错误描述中提取
        desc_pattern = r'property (\w+)|variable (\w+)|method (\w+)'
        descs = re.findall(desc_pattern, context)
        snippets.extend([d for group in descs for d in group if d])
        
        return ' '.join(snippets[:3]) if snippets else None
    
    def _identify_error_pattern(self, context):
        """识别错误模式"""
        patterns = {
            'UNINITIALIZED_LATEINIT': {
                'keywords': ['UninitializedPropertyAccessException', 'lateinit property'],
                'name': '未初始化的lateinit属性',
                'description': 'Kotlin的lateinit属性在初始化前被访问'
            },
            'NULL_POINTER': {
                'keywords': ['NullPointerException', 'null object reference'],
                'name': '空指针异常',
                'description': '尝试访问null对象的方法或属性'
            },
            'OUT_OF_MEMORY': {
                'keywords': ['OutOfMemoryError', 'Failed to allocate'],
                'name': '内存溢出',
                'description': '应用内存不足，无法分配新对象'
            },
            'RESOURCE_NOT_FOUND': {
                'keywords': ['Resources$NotFoundException', 'Resource ID'],
                'name': '资源未找到',
                'description': '尝试访问不存在的资源文件'
            },
            'CONCURRENT_MODIFICATION': {
                'keywords': ['ConcurrentModificationException'],
                'name': '并发修改异常',
                'description': '在迭代过程中修改了集合'
            },
            'LIFECYCLE_ERROR': {
                'keywords': ['IllegalStateException', 'Can not perform this action after onSaveInstanceState'],
                'name': '生命周期错误',
                'description': 'Activity/Fragment生命周期使用不当'
            }
        }
        
        context_lower = context.lower()
        for pattern_id, pattern_info in patterns.items():
            if any(keyword.lower() in context_lower for keyword in pattern_info['keywords']):
                return {
                    'id': pattern_id,
                    **pattern_info
                }
        
        return {
            'id': 'UNKNOWN',
            'name': '未知错误模式',
            'description': '需要人工分析'
        }
    
    def _generate_fix_suggestions(self, error_pattern, error_location):
        """生成修复建议"""
        suggestions_map = {
            'UNINITIALIZED_LATEINIT': [
                '在访问前使用 ::property.isInitialized 检查',
                '在构造函数或init块中初始化属性',
                '考虑改用可空类型代替lateinit'
            ],
            'NULL_POINTER': [
                '使用安全调用操作符 ?.',
                '在访问前进行null检查',
                '使用Elvis操作符提供默认值'
            ],
            'OUT_OF_MEMORY': [
                '检查是否存在内存泄漏',
                '优化图片加载，使用inSampleSize压缩',
                '及时释放不再使用的资源'
            ],
            'RESOURCE_NOT_FOUND': [
                '检查资源ID是否正确',
                '确认资源在所有配置中都存在'
            ],
            'LIFECYCLE_ERROR': [
                '使用commitAllowingStateLoss()代替commit()',
                '在合适的生命周期方法中执行Fragment事务'
            ]
        }
        
        pattern_id = error_pattern.get('id', 'UNKNOWN')
        suggestions = suggestions_map.get(pattern_id, ['查看完整堆栈信息，定位具体问题代码'])
        
        return suggestions[:3]  # 最多返回3条建议
    
    def _calculate_confidence(self, error_location, error_pattern):
        """计算根因定位的置信度"""
        confidence = 0
        
        if error_location:
            if error_location['type'] == 'APPLICATION':
                confidence += 50
            elif error_location['type'] == 'THIRD_PARTY':
                confidence += 30
            else:
                confidence += 10
        
        if error_pattern['id'] != 'UNKNOWN':
            confidence += 40
        
        if error_location and error_location.get('code_snippet'):
            confidence += 10
        
        return min(confidence, 100)
    
    # ==================== 增强功能：错误上下文增强 ====================
    
    def extract_environment_context(self, log_text):
        """提取环境上下文信息"""
        context = {
            'device': self._extract_device_info(log_text),
            'application': self._extract_app_info(log_text),
            'memory': self._extract_memory_info(log_text),
            'test_config': self._extract_test_config(log_text)
        }
        return context
    
    def _extract_device_info(self, log_text):
        """提取设备信息"""
        device_info = {}
        
        # 提取Build Label
        build_pattern = r'Build Label: (.+?)(?:\n|//|$)'
        build_match = re.search(build_pattern, log_text)
        if build_match:
            device_info['build_label'] = build_match.group(1).strip()
        
        # 提取Build Time
        time_pattern = r'Build Time: (\d+)'
        time_match = re.search(time_pattern, log_text)
        if time_match:
            timestamp = int(time_match.group(1)) / 1000
            device_info['build_time'] = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        
        # 提取Changelist
        change_pattern = r'Build Changelist: (\d+)'
        change_match = re.search(change_pattern, log_text)
        if change_match:
            device_info['changelist'] = change_match.group(1)
        
        return device_info
    
    def _extract_app_info(self, log_text):
        """提取应用信息"""
        app_info = {}
        
        # 从崩溃日志中提取包名
        package_pattern = r'Process: ([\w\.]+)|CRASH: ([\w\.]+)'
        package_matches = re.findall(package_pattern, log_text)
        packages = set()
        for match in package_matches:
            pkg = match[0] or match[1]
            if pkg:
                packages.add(pkg)
        
        if packages:
            app_info['packages'] = list(packages)
        
        return app_info
    
    def _extract_memory_info(self, log_text):
        """提取内存信息"""
        memory_info = {}
        
        # 查找OOM相关信息
        if 'OutOfMemoryError' in log_text:
            memory_info['oom_detected'] = True
            
            # 提取内存分配失败信息
            alloc_pattern = r'Failed to allocate (\d+) bytes'
            alloc_match = re.search(alloc_pattern, log_text)
            if alloc_match:
                bytes_failed = int(alloc_match.group(1))
                memory_info['failed_allocation_bytes'] = bytes_failed
                memory_info['failed_allocation_mb'] = round(bytes_failed / 1024 / 1024, 2)
        
        return memory_info
    
    def _extract_test_config(self, log_text):
        """提取测试配置信息"""
        config = {}
        
        # 提取事件数
        events_pattern = r'Events injected: (\d+)'
        events_match = re.search(events_pattern, log_text)
        if events_match:
            config['events_injected'] = int(events_match.group(1))
        
        # 检测测试是否完成
        if 'Monkey finished' in log_text:
            config['status'] = 'COMPLETED'
        elif 'Monkey aborted' in log_text:
            config['status'] = 'ABORTED'
        else:
            config['status'] = 'UNKNOWN'
        
        return config
    
    # ==================== 增强功能：智能总结生成 ====================
    
    def generate_executive_summary(self, errors, environment_context=None):
        """生成执行摘要"""
        summary = []
        
        # 标题
        summary.append("\n" + "=" * 80)
        summary.append(f"{EMOJI['clipboard']} Monkey测试执行摘要")
        summary.append("=" * 80)
        summary.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        summary.append(f"分析错误数: {len(errors)}个")
        summary.append("")
        
        # 环境信息
        if environment_context:
            summary.append(f"{EMOJI['phone']} 测试环境")
            if environment_context.get('device'):
                device = environment_context['device']
                if device.get('build_label'):
                    summary.append(f"   设备: {device['build_label']}")
                if device.get('build_time'):
                    summary.append(f"   构建时间: {device['build_time']}")
            
            if environment_context.get('test_config'):
                config = environment_context['test_config']
                if config.get('events_injected'):
                    summary.append(f"   注入事件: {config['events_injected']}个")
                if config.get('status'):
                    summary.append(f"   测试状态: {config['status']}")
            summary.append("")
        
        # 严重性分析
        priority_counts = self._count_by_priority(errors)
        summary.append(f"{EMOJI['target']} 严重性分析")
        
        critical_count = priority_counts.get('CRITICAL', 0)
        high_count = priority_counts.get('HIGH', 0)
        medium_count = priority_counts.get('MEDIUM', 0)
        low_count = priority_counts.get('LOW', 0)
        
        if critical_count > 0:
            summary.append(f"   {EMOJI['red_circle']} 致命错误: {critical_count}个 (需立即修复)")
            # 列出致命错误
            critical_errors = [e for e in errors if e.get('severity', {}).get('priority') == 'CRITICAL']
            for i, error in enumerate(critical_errors[:3], 1):
                process = error.get('processName', 'Unknown')
                pattern = error.get('rootCause', {}).get('error_pattern', {}).get('name', 'Unknown')
                summary.append(f"      {i}. [{error['category'].upper()}] {process}")
                summary.append(f"         错误: {pattern}")
                if 'deduplication' in error:
                    occurrences = error['deduplication']['occurrences']
                    summary.append(f"         复现: {occurrences}次")
        
        if high_count > 0:
            summary.append(f"   {EMOJI['yellow_circle']} 严重问题: {high_count}个 (建议本周修复)")
        
        summary.append(f"   {EMOJI['blue_circle']} 中等问题: {medium_count}个")
        summary.append(f"   {EMOJI['green_circle']} 较低问题: {low_count}个")
        summary.append("")
        
        # 稳定性评分
        stability_score = self._calculate_stability_score(errors)
        summary.append(f"{EMOJI['check']} 稳定性评分: {stability_score}/100")
        
        if stability_score >= 90:
            level, emoji = "优秀", EMOJI['star']
        elif stability_score >= 75:
            level, emoji = "良好", EMOJI['thumbs_up']
        elif stability_score >= 60:
            level, emoji = "一般", EMOJI['warning']
        else:
            level, emoji = "较差", EMOJI['cross']
        
        summary.append(f"   {emoji} 评级: {level}")
        summary.append("")
        
        # 关键建议
        summary.append(f"{EMOJI['bulb']} 关键建议")
        recommendations = self._generate_key_recommendations(errors, priority_counts)
        for i, rec in enumerate(recommendations, 1):
            summary.append(f"   {i}. {rec}")
        summary.append("")
        
        summary.append("=" * 80)
        
        return '\n'.join(summary)
    
    def _count_by_priority(self, errors):
        """按优先级统计"""
        counts = defaultdict(int)
        for error in errors:
            priority = error.get('severity', {}).get('priority', 'UNKNOWN')
            counts[priority] += 1
        return dict(counts)
    
    def _calculate_stability_score(self, errors):
        """计算稳定性评分（0-100）"""
        score = 100
        
        # 根据错误数量扣分
        total_errors = len(errors)
        if total_errors > 0:
            score -= min(total_errors * 2, 40)
        
        # 根据严重性扣分
        for error in errors:
            priority = error.get('severity', {}).get('priority', 'LOW')
            deduction = {
                'CRITICAL': 10,
                'HIGH': 5,
                'MEDIUM': 2,
                'LOW': 1
            }
            score -= deduction.get(priority, 0)
        
        # 根据复现频率扣分
        for error in errors:
            if 'deduplication' in error:
                occurrences = error['deduplication']['occurrences']
                if occurrences > 10:
                    score -= 5
                elif occurrences > 5:
                    score -= 3
        
        return max(score, 0)
    
    def _generate_key_recommendations(self, errors, priority_counts):
        """生成关键修复建议"""
        recommendations = []
        
        critical_count = priority_counts.get('CRITICAL', 0)
        high_count = priority_counts.get('HIGH', 0)
        
        if critical_count > 0:
            recommendations.append(f"立即修复{critical_count}个致命错误，这些错误严重影响应用可用性")
        
        if high_count > 0:
            recommendations.append(f"本周内修复{high_count}个严重问题，避免影响用户体验")
        
        # 分析高频错误
        high_freq_errors = [
            e for e in errors 
            if e.get('deduplication', {}).get('occurrences', 1) > 5
        ]
        if high_freq_errors:
            recommendations.append(f"优先处理{len(high_freq_errors)}个高频错误，这些问题容易被用户触发")
        
        # 内存问题
        oom_errors = [e for e in errors if 'OutOfMemoryError' in str(e.get('context', []))]
        if oom_errors:
            recommendations.append("使用LeakCanary或Profiler工具排查内存泄漏问题")
        
        # ANR问题
        anr_errors = [e for e in errors if e['category'] == 'anr']
        if anr_errors:
            recommendations.append("优化主线程操作，将耗时任务移至后台线程")
        
        # 如果没有其他建议
        if not recommendations:
            recommendations.append("继续保持测试覆盖，监控应用稳定性")
        
        return recommendations[:5]

    def analyze_monkey_log(self, output_format='list', enable_correlation=False):
        """执行综合分析
        
        Args:
            output_format: 输出格式，'list'为列表式，'json'为JSON格式
            enable_correlation: 是否启用关联分析，过滤衍生错误（仅JSON格式有效）
        """
        if not self.monkey_log:
            safe_print(f"{EMOJI['cross']} 没有可分析的Monkey日志")
            return
        
        print("\n" + "="*80)
        print("Monkey日志根因分析")
        print("="*80)
        
        log_text = "".join(self.monkey_log)
        
        # 执行各项分析
        self._analyze_crashes(log_text)
        self._analyze_anrs(log_text)
        self._analyze_exceptions(log_text)
        self._analyze_test_summary(log_text)
        
        # 根据格式生成对应报告
        if output_format == 'json':
            self.print_json_report(enable_correlation)
        else:
            self.generate_list_style_report()

    def _analyze_crashes(self, log_text):
        """分析崩溃信息"""
        crash_pattern = r'// CRASH: (.+?) \(pid (\d+)\)'
        crash_matches = re.findall(crash_pattern, log_text)
        
        for process_name, pid in crash_matches:
            error_section = self._extract_error_section(log_text, f"CRASH: {process_name}")
            stack_trace = self._extract_stack_trace(log_text, process_name)
            context_lines = self._extract_context_lines(log_text, f"CRASH: {process_name}")
            
            # 过滤掉Monkey自身的错误
            if self._is_monkey_internal_error(process_name, error_section + stack_trace):
                continue
            
            crash_info = {
                'process': process_name,
                'pid': pid,
                'type': '应用崩溃',
                'severity': 'CRITICAL',
                'timestamp': self._extract_timestamp(error_section if error_section else "\n".join(context_lines)),
                'error_details': error_section[:500] if error_section else "无详细错误信息",
                'stack_trace': stack_trace[:1000] if stack_trace else "无堆栈信息",
                'exception_type': self._extract_exception_type(stack_trace),
                'root_cause': self._analyze_root_cause(stack_trace, error_section),
                'context': context_lines  # 新增：完整上下文行
            }
            
            self.analysis_results['crashes'].append(crash_info)

    def _analyze_anrs(self, log_text):
        """分析ANR信息"""
        anr_pattern = r'// NOT RESPONDING: (.+?) \(pid (\d+)\)'
        anr_matches = re.findall(anr_pattern, log_text)
        
        for process_name, pid in anr_matches:
            context_lines = self._extract_context_lines(log_text, f"NOT RESPONDING: {process_name}")
            
            # 过滤掉Monkey自身的错误
            context_str = "\n".join(context_lines) if context_lines else ""
            if self._is_monkey_internal_error(process_name, context_str):
                continue
            
            anr_info = {
                'process': process_name,
                'pid': pid,
                'type': '应用无响应',
                'severity': 'HIGH',
                'timestamp': self._extract_timestamp(context_str),
                'root_cause': self._analyze_anr_cause(log_text, process_name),
                'suggestions': [
                    "检查主线程中的耗时操作",
                    "优化数据库查询和文件IO",
                    "减少网络请求阻塞",
                    "使用异步任务处理后台工作"
                ],
                'context': context_lines  # 新增：完整上下文行
            }
            
            self.analysis_results['anrs'].append(anr_info)

    def _analyze_exceptions(self, log_text):
        """分析异常信息"""
        exception_keywords = ['Exception', 'Error', 'Fatal', 'FAILED']
        
        for i, line in enumerate(self.monkey_log):
            if any(keyword in line for keyword in exception_keywords):
                # 获取上下文信息
                context_start = max(0, i-2)
                context_end = min(len(self.monkey_log), i+5)
                context = "".join(self.monkey_log[context_start:context_end])
                
                # 过滤掉Monkey自身的错误
                process_name = self._extract_process_from_context(context)
                if self._is_monkey_internal_error(process_name, context + line):
                    continue
                
                exception_info = {
                    'process': process_name,
                    'type': '运行时异常',
                    'severity': 'MEDIUM',
                    'timestamp': self._extract_timestamp(context + line),
                    'details': line.strip(),
                    'context': context[:300],
                    'root_cause': self._classify_exception(line)
                }
                
                self.analysis_results['exceptions'].append(exception_info)

    def _analyze_test_summary(self, log_text):
        """分析测试摘要"""
        summary = {}
        
        if 'Monkey finished' in log_text:
            summary['status'] = '完成'
            finished_match = re.search(r'Events injected: (\d+)', log_text)
            if finished_match:
                summary['events_injected'] = finished_match.group(1)
        else:
            summary['status'] = '未完成或中止'
        
        if 'Monkey aborted due to error' in log_text:
            summary['abort_reason'] = '因错误中止'
        
        summary['total_crashes'] = len(self.analysis_results['crashes'])
        summary['total_anrs'] = len(self.analysis_results['anrs'])
        summary['total_exceptions'] = len(self.analysis_results['exceptions'])
        
        self.analysis_results['test_summary'] = summary

    def _extract_error_section(self, log_text, crash_keyword):
        """提取错误详情部分"""
        lines = log_text.split('\n')
        error_section = []
        capture = False
        
        for line in lines:
            if crash_keyword in line:
                capture = True
            if capture:
                error_section.append(line)
                if not line.strip().startswith('//') and line.strip():
                    break
        
        return "\n".join(error_section)

    def _extract_stack_trace(self, log_text, process_name):
        """提取堆栈轨迹"""
        lines = log_text.split('\n')
        stack_trace = []
        capture = False
        
        for line in lines:
            if process_name in line and ('Exception' in line or 'Error' in line):
                capture = True
            if capture:
                stack_trace.append(line)
                if not line.strip() and len(stack_trace) > 5:
                    break
        
        return "\n".join(stack_trace)

    def _extract_process_from_context(self, context):
        """从上下文中提取进程信息"""
        process_match = re.search(r'Process: ([^,]+), PID: (\d+)', context)
        if process_match:
            return f"{process_match.group(1)} (PID: {process_match.group(2)})"
        
        package_match = re.search(r'([a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+)', context)
        if package_match:
            return package_match.group(1)
        
        return "未知进程"

    def _extract_exception_type(self, stack_trace):
        """提取异常类型"""
        exception_pattern = r'([a-zA-Z0-9_.]+(?:Exception|Error))'
        matches = re.findall(exception_pattern, stack_trace)
        return matches[0] if matches else "Unknown"

    def _extract_timestamp(self, text):
        """从文本中提取时间戳
        
        支持格式：
        1. Build Time: 1762325307000 (Monkey 日志中的 Unix 时间戳，毫秒)
        2. YYYY-MM-DD HH:MM:SS (标准格式)
        3. 找不到时返回当前时间
        """
        # 1. 优先提取 Build Time (Monkey 日志格式: Unix 时间戳毫秒)
        build_time_match = re.search(r'Build Time:\s*(\d{13})', text)
        if build_time_match:
            try:
                unix_ms = int(build_time_match.group(1))
                dt = datetime.fromtimestamp(unix_ms / 1000.0)
                return dt.strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, OSError):
                pass  # 时间戳无效，继续尝试其他格式
        
        # 2. 尝试标准格式 (兼容其他日志)
        timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', text)
        if timestamp_match:
            return timestamp_match.group(1)
        
        # 3. 找不到时返回当前时间
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def _extract_context_lines(self, log_text, keyword):
        """提取错误的完整上下文行（用于JSON输出）"""
        lines = log_text.split('\n')
        context = []
        capture = False
        line_count = 0
        max_lines = 20  # 最多提取20行上下文
        
        for line in lines:
            if keyword in line:
                capture = True
            
            if capture:
                # 提取以//开头的注释行和堆栈信息
                if line.strip().startswith('//') or line.strip().startswith('at '):
                    context.append(line.strip())
                    line_count += 1
                elif line.strip() and not line.strip().startswith('**'):
                    # 包含异常信息行
                    if 'Exception' in line or 'Error' in line:
                        context.append(line.strip())
                        line_count += 1
                
                # 达到最大行数或遇到空行则停止
                if line_count >= max_lines or (not line.strip() and len(context) > 5):
                    break
        
        return context

    def _analyze_root_cause(self, stack_trace, error_details):
        """分析崩溃根本原因"""
        causes = []
        
        # 空指针异常
        if 'NullPointerException' in stack_trace:
            causes.append({
                'type': '空指针异常',
                'description': '尝试访问空对象的方法或字段',
                'solution': '检查对象初始化，添加非空验证',
                'confidence': '高'
            })
        
        # 内存溢出
        if 'OutOfMemoryError' in stack_trace:
            causes.append({
                'type': '内存溢出',
                'description': '堆内存或Native内存不足',
                'solution': '检查Bitmap加载，优化内存使用',
                'confidence': '高'
            })
        
        # 权限问题
        if 'Permission Denial' in stack_trace or 'SecurityException' in stack_trace:
            causes.append({
                'type': '权限拒绝',
                'description': '缺少必要的权限或签名不匹配',
                'solution': '检查权限声明和运行时请求',
                'confidence': '中'
            })
        
        # 网络问题
        if 'NetworkOnMainThreadException' in stack_trace:
            causes.append({
                'type': '主线程网络请求',
                'description': '在主线程执行网络操作',
                'solution': '将网络请求移至后台线程',
                'confidence': '高'
            })
        
        # 数据库问题
        if 'SQLiteException' in stack_trace:
            causes.append({
                'type': '数据库异常',
                'description': '数据库操作失败',
                'solution': '检查数据库版本和表结构',
                'confidence': '中'
            })
        
        # 资源问题
        if 'Resources$NotFoundException' in stack_trace:
            causes.append({
                'type': '资源未找到',
                'description': '引用的资源文件不存在',
                'solution': '检查资源ID和文件存在性',
                'confidence': '中'
            })
        
        return causes if causes else [{
            'type': '未知原因',
            'description': '需要进一步分析堆栈信息',
            'solution': '查看完整日志堆栈',
            'confidence': '低'
        }]

    def _analyze_anr_cause(self, log_text, process_name):
        """分析ANR原因"""
        causes = []
        
        # 检查ANR上下文
        anr_context = self._extract_anr_context(log_text, process_name)
        
        if 'Input dispatching timed out' in anr_context:
            causes.append({
                'type': '输入事件超时',
                'description': '主线程处理输入事件超时',
                'solution': '检查主线程耗时操作',
                'confidence': '高'
            })
        
        if 'executing service' in anr_context:
            causes.append({
                'type': '服务执行超时',
                'description': 'Service执行时间过长',
                'solution': '优化Service逻辑，使用IntentService',
                'confidence': '中'
            })
        
        if 'Broadcast of Intent' in anr_context:
            causes.append({
                'type': '广播处理超时',
                'description': 'BroadcastReceiver执行超时',
                'solution': '将广播处理移至后台线程',
                'confidence': '中'
            })
        
        if 'CPU usage' in anr_context and '100%' in anr_context:
            causes.append({
                'type': '系统资源耗尽',
                'description': 'CPU使用率达到100%',
                'solution': '检查性能瓶颈，优化资源使用',
                'confidence': '高'
            })
        
        return causes if causes else [{
            'type': '未知ANR原因',
            'description': '需要查看系统ANR日志',
            'solution': '检查/data/anr/traces.txt文件',
            'confidence': '低'
        }]

    def _extract_anr_context(self, log_text, process_name):
        """提取ANR上下文"""
        lines = log_text.split('\n')
        anr_context = []
        capture = False
        
        for line in lines:
            if 'NOT RESPONDING' in line and process_name in line:
                capture = True
            if capture:
                anr_context.append(line)
                if 'CPU usage' in line or 'Load:' in line:
                    break
        
        return "\n".join(anr_context)

    def _classify_exception(self, exception_line):
        """分类异常类型"""
        if 'NullPointerException' in exception_line:
            return '空指针异常'
        elif 'OutOfMemoryError' in exception_line:
            return '内存溢出'
        elif 'NetworkOnMainThreadException' in exception_line:
            return '主线程网络请求'
        elif 'SQLiteException' in exception_line:
            return '数据库异常'
        elif 'Resources$NotFoundException' in exception_line:
            return '资源未找到'
        elif 'SecurityException' in exception_line:
            return '权限异常'
        else:
            return '其他异常'

    def generate_list_style_report(self):
        """生成列表式报告"""
        print("\n" + "="*80)
        print("MONKEY测试分析报告 - 列表式")
        print("="*80)
        
        # 测试概览
        self._print_test_overview()
        
        # 崩溃问题列表
        self._print_crash_list()
        
        # ANR问题列表
        self._print_anr_list()
        
        # 异常问题列表
        self._print_exception_list()
        
        # 修复建议总结
        self._print_recommendations_summary()
    
    def generate_json_report(self, enable_correlation=False):
        """生成JSON格式报告（增强版）
        
        Args:
            enable_correlation: 是否启用关联分析，过滤衍生错误
        
        增强功能：
        1. 智能错误去重
        2. 错误严重性评分
        3. 智能根因定位
        4. 环境上下文提取
        """
        json_errors = []
        
        # 处理崩溃信息
        for crash in self.analysis_results['crashes']:
            error_obj = {
                "category": "crash",
                "processName": crash['process'],
                "pid": crash.get('pid', ''),
                "timestamp": self._format_iso_timestamp(crash.get('timestamp', '')),
                "context": crash.get('context', [])
            }
            json_errors.append(error_obj)
        
        # 处理ANR信息
        for anr in self.analysis_results['anrs']:
            error_obj = {
                "category": "anr",
                "processName": anr['process'],
                "pid": anr.get('pid', ''),
                "timestamp": self._format_iso_timestamp(anr.get('timestamp', '')),
                "context": anr.get('context', [])
            }
            json_errors.append(error_obj)
        
        # 处理异常信息
        for exception in self.analysis_results['exceptions']:
            error_obj = {
                "category": "exception",
                "processName": exception['process'],
                "timestamp": self._format_iso_timestamp(exception.get('timestamp', '')),
                "context": [exception.get('details', '')] + [exception.get('context', '')]
            }
            json_errors.append(error_obj)
        
        # === 应用增强功能 ===
        
        # 1. 智能错误去重
        safe_print(f"   {EMOJI['process']} 正在进行智能去重...")
        original_count = len(json_errors)
        json_errors = self.deduplicate_errors(json_errors)
        safe_print(f"   {EMOJI['check']} 去重完成: {original_count}个错误 -> {len(json_errors)}个独特错误")
        
        # 2. 错误严重性评分
        safe_print(f"   {EMOJI['chart']} 正在计算严重性评分...")
        json_errors = self.prioritize_errors(json_errors)
        critical_count = sum(1 for e in json_errors if e.get('severity', {}).get('priority') == 'CRITICAL')
        safe_print(f"   {EMOJI['check']} 评分完成: 发现{critical_count}个致命错误")
        
        # 3. 智能根因定位
        safe_print(f"   {EMOJI['search']} 正在进行根因定位...")
        for error in json_errors:
            error['rootCause'] = self.analyze_root_cause(error)
        high_confidence = sum(1 for e in json_errors if e.get('rootCause', {}).get('confidence', 0) >= 80)
        safe_print(f"   {EMOJI['check']} 根因定位完成: {high_confidence}个错误定位置信度≥80%")
        
        # 4. 启用关联分析时，过滤衍生错误
        if enable_correlation:
            safe_print(f"   {EMOJI['search']} 正在进行关联分析...")
            original_count = len(json_errors)
            json_errors = self._filter_derived_errors(json_errors)
            safe_print(f"   {EMOJI['check']} 关联分析完成: 过滤了{original_count - len(json_errors)}个衍生错误")
        
        return json_errors
    
    def _filter_derived_errors(self, errors):
        """多异常链根因分析：识别并过滤衍生错误，仅保留根本原因
        
        分析策略：
        1. 时间顺序分析 - 第一个发生的异常通常是根本原因
        2. 调用链分析 - 分析堆栈的调用关系，寻找最深层的原始错误点
        3. 因果关系识别 - 识别异常之间的直接因果关系
        4. 上下文关联 - 结合日志上下文判断异常相关性
        """
        if not errors:
            return errors
        
        # 1. 时间顺序分析：按时间排序，最早的错误优先
        errors.sort(key=lambda x: x.get('timestamp', ''))
        
        # 构建异常链分组
        error_chains = self._build_error_chains(errors)
        
        # 2. 从每个异常链中识别根因
        root_causes = []
        for chain in error_chains:
            root_error = self._identify_root_cause(chain)
            if root_error:
                root_causes.append(root_error)
        
        return root_causes
    
    def _build_error_chains(self, errors):
        """构建异常链分组：将相关的异常归为一组
        
        基于：
        - 时间窗口（5秒内）
        - 进程关联
        - 错误特征相似度
        """
        if not errors:
            return []
        
        chains = []
        used_indices = set()
        
        for i, error in enumerate(errors):
            if i in used_indices:
                continue
            
            # 开始新的异常链
            chain = [error]
            used_indices.add(i)
            
            # 查找与当前错误相关的后续错误
            for j in range(i + 1, len(errors)):
                if j in used_indices:
                    continue
                
                if self._is_related_error(error, errors[j], chain):
                    chain.append(errors[j])
                    used_indices.add(j)
            
            chains.append(chain)
        
        return chains
    
    def _is_related_error(self, error1, error2, chain):
        """判断两个错误是否相关（属于同一异常链）
        
        判断维度：
        1. 时间窗口（5秒内）
        2. 进程关联
        3. 错误特征匹配
        4. 调用链关联
        """
        # 1. 时间窗口检查（5秒内）
        try:
            time1 = datetime.fromisoformat(error1['timestamp'].replace('Z', '+00:00'))
            time2 = datetime.fromisoformat(error2['timestamp'].replace('Z', '+00:00'))
            time_diff = abs((time2 - time1).total_seconds())
            
            if time_diff > 5:
                return False
        except:
            pass
        
        # 2. 进程关联检查
        process1 = error1.get('processName', '')
        process2 = error2.get('processName', '')
        
        # 进程不相关则不属于同一异常链
        if not self._is_process_related(process1, process2):
            return False
        
        # 3. 错误特征匹配（检查是否包含相同的异常类型或错误信息）
        context1 = ' '.join(error1.get('context', []))
        context2 = ' '.join(error2.get('context', []))
        
        # 提取异常特征
        features1 = self._extract_error_features(context1)
        features2 = self._extract_error_features(context2)
        
        # 检查特征重叠度
        if self._has_feature_overlap(features1, features2):
            return True
        
        # 4. 调用链关联检查
        if self._has_call_stack_relation(context1, context2):
            return True
        
        return False
    
    def _is_process_related(self, process1, process2):
        """判断两个进程是否相关"""
        if not process1 or not process2:
            return False
        
        # 完全相同
        if process1 == process2:
            return True
        
        # 一个是另一个的子模块
        if process1 in process2 or process2 in process1:
            return True
        
        # 同一个应用的不同组件
        parts1 = process1.split('.')
        parts2 = process2.split('.')
        if len(parts1) >= 3 and len(parts2) >= 3:
            # 前三段相同则认为是同一应用
            if parts1[:3] == parts2[:3]:
                return True
        
        return False
    
    def _extract_error_features(self, context):
        """提取错误特征用于关联分析"""
        features = {
            'exception_types': [],
            'error_messages': [],
            'key_methods': [],
            'error_codes': []
        }
        
        # 提取异常类型
        exception_pattern = r'(\w+Exception|\w+Error)'
        features['exception_types'] = re.findall(exception_pattern, context)
        
        # 提取错误消息
        msg_patterns = [
            r'Short Msg: (.+?)(?://|$)',
            r'Long Msg: (.+?)(?://|$)',
            r'lateinit property (\w+)',
        ]
        for pattern in msg_patterns:
            matches = re.findall(pattern, context)
            features['error_messages'].extend(matches)
        
        # 提取关键方法（调用链顶部）
        method_pattern = r'at ([\w\.$]+\.[\w]+)\('
        methods = re.findall(method_pattern, context)
        if methods:
            features['key_methods'] = methods[:3]  # 只取前3个方法
        
        return features
    
    def _has_feature_overlap(self, features1, features2):
        """检查两个错误特征是否有重叠"""
        # 检查异常类型重叠
        exception_overlap = set(features1['exception_types']) & set(features2['exception_types'])
        if exception_overlap:
            return True
        
        # 检查错误消息重叠
        for msg1 in features1['error_messages']:
            for msg2 in features2['error_messages']:
                if msg1 and msg2 and (msg1 in msg2 or msg2 in msg1):
                    return True
        
        # 检查关键方法重叠
        method_overlap = set(features1['key_methods']) & set(features2['key_methods'])
        if method_overlap:
            return True
        
        return False
    
    def _has_call_stack_relation(self, context1, context2):
        """检查两个错误的调用栈是否有关联"""
        # 提取调用栈中的类和方法
        stack_pattern = r'at ([\w\.$]+)\.'
        
        stack1 = re.findall(stack_pattern, context1)
        stack2 = re.findall(stack_pattern, context2)
        
        if not stack1 or not stack2:
            return False
        
        # 检查是否有共同的调用路径
        common_classes = set(stack1) & set(stack2)
        if len(common_classes) >= 2:  # 至少2个共同类
            return True
        
        return False
    
    def _identify_root_cause(self, error_chain):
        """从异常链中识别根本原因
        
        策略：
        1. 优先选择Crash/ANR（通常是最终表现）
        2. 如果没有Crash/ANR，选择调用栈最深的错误
        3. 如果调用栈深度相同，选择时间最早的
        """
        if not error_chain:
            return None
        
        if len(error_chain) == 1:
            return error_chain[0]
        
        # 策略1：优先选择Crash/ANR（因为它们信息最完整）
        crash_anr = [e for e in error_chain if e['category'] in ['crash', 'anr']]
        if crash_anr:
            # 如果有多个crash/anr，选择第一个（时间最早）
            return crash_anr[0]
        
        # 策略2：选择调用栈最深的错误（信息最完整）
        def get_stack_depth(error):
            context = ' '.join(error.get('context', []))
            # 统计"at "出现次数作为堆栈深度
            return context.count(' at ')
        
        error_chain.sort(key=get_stack_depth, reverse=True)
        max_depth = get_stack_depth(error_chain[0])
        
        # 找出所有最大深度的错误
        deepest_errors = [e for e in error_chain if get_stack_depth(e) == max_depth]
        
        # 策略3：在最深的错误中选择时间最早的
        return deepest_errors[0]
    
    def _format_iso_timestamp(self, timestamp_str):
        """将时间戳格式化为ISO 8601格式"""
        if not timestamp_str:
            return datetime.now().strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
        try:
            # 尝试解析现有格式
            dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        except:
            return timestamp_str

    def _print_test_overview(self):
        """打印测试概览"""
        summary = self.analysis_results['test_summary']
        
        safe_print(f"\n{EMOJI['chart']} 测试概览:")
        print("  • 测试状态: {}".format(summary.get('status', '未知')))
        if 'events_injected' in summary:
            print("  • 注入事件数: {}".format(summary['events_injected']))
        if 'abort_reason' in summary:
            print("  • 中止原因: {}".format(summary['abort_reason']))
        print("  • 发现崩溃: {} 个".format(summary.get('total_crashes', 0)))
        print("  • 发现ANR: {} 个".format(summary.get('total_anrs', 0)))
        print("  • 发现异常: {} 个".format(summary.get('total_exceptions', 0)))

    def _print_crash_list(self):
        """打印崩溃问题列表"""
        if not self.analysis_results['crashes']:
            safe_print(f"\n{EMOJI['check']} 未发现崩溃问题")
            return
        
        safe_print("\n{} 崩溃问题列表 ({}个):".format(EMOJI['red_circle'], len(self.analysis_results['crashes'])))
        print("-" * 80)
        
        for i, crash in enumerate(self.analysis_results['crashes'], 1):
            print("{}. 进程: {} (PID: {})".format(i, crash['process'], crash['pid']))
            print("   • 异常类型: {}".format(crash['exception_type']))
            print("   • 发生时间: {}".format(crash['timestamp']))
            print("   • 严重程度: {}".format(crash['severity']))
            
            # 根因分析
            if crash.get('root_cause'):
                print("   • 根本原因分析:")
                for cause in crash['root_cause']:
                    print("     - {} (置信度: {})".format(cause['type'], cause['confidence']))
                    print("       描述: {}".format(cause['description']))
                    print("       解决方案: {}".format(cause['solution']))
            
            # 错误详情摘要
            if crash.get('error_details'):
                error_preview = crash['error_details'][:100] + "..." if len(crash['error_details']) > 100 else crash['error_details']
                print("   • 错误摘要: {}".format(error_preview))
            
            print()

    def _print_anr_list(self):
        """打印ANR问题列表"""
        if not self.analysis_results['anrs']:
            safe_print(f"\n{EMOJI['check']} 未发现ANR问题")
            return
        
        safe_print("\n{} ANR问题列表 ({}个):".format(EMOJI['yellow_circle'], len(self.analysis_results['anrs'])))
        print("-" * 80)
        
        for i, anr in enumerate(self.analysis_results['anrs'], 1):
            print("{}. 进程: {} (PID: {})".format(i, anr['process'], anr['pid']))
            print("   • 发生时间: {}".format(anr['timestamp']))
            print("   • 严重程度: {}".format(anr['severity']))
            
            # 根因分析
            if anr.get('root_cause'):
                print("   • 根本原因分析:")
                for cause in anr['root_cause']:
                    print("     - {} (置信度: {})".format(cause['type'], cause['confidence']))
                    print("       描述: {}".format(cause['description']))
                    print("       解决方案: {}".format(cause['solution']))
            
            # 修复建议
            if anr.get('suggestions'):
                print("   • 修复建议:")
                for suggestion in anr['suggestions']:
                    print("     - {}".format(suggestion))
            
            print()

    def _print_exception_list(self):
        """打印异常问题列表"""
        if not self.analysis_results['exceptions']:
            safe_print(f"\n{EMOJI['check']} 未发现异常问题")
            return
        
        safe_print("\n{} 异常问题列表 ({}个):".format(EMOJI['orange_circle'], len(self.analysis_results['exceptions'])))
        print("-" * 80)
        
        for i, exception in enumerate(self.analysis_results['exceptions'], 1):
            print("{}. 进程: {}".format(i, exception['process']))
            print("   • 异常类型: {}".format(exception['root_cause']))
            print("   • 发生时间: {}".format(exception['timestamp']))
            print("   • 严重程度: {}".format(exception['severity']))
            print("   • 异常详情: {}".format(exception['details']))
            
            # 上下文信息
            if exception.get('context'):
                context_preview = exception['context'][:150] + "..." if len(exception['context']) > 150 else exception['context']
                print("   • 上下文: {}".format(context_preview))
            
            print()

    def _print_recommendations_summary(self):
        """打印修复建议总结"""
        safe_print(f"\n{EMOJI['target']} 修复建议总结:")
        safe_print("-" * 80)
        
        # 崩溃相关建议
        if self.analysis_results['crashes']:
            safe_print(f"{EMOJI['red_circle']} 针对崩溃问题的建议:")
            print("  • 检查空指针异常和对象初始化")
            print("  • 优化内存使用，避免内存泄漏")
            print("  • 验证权限声明和运行时请求")
            print("  • 检查数据库操作和事务管理")
            print("  • 查看完整堆栈轨迹定位问题代码")
        
        # ANR相关建议
        if self.analysis_results['anrs']:
            safe_print(f"\n{EMOJI['yellow_circle']} 针对ANR问题的建议:")
            print("  • 检查主线程中的耗时操作")
            print("  • 优化数据库查询和文件IO操作")
            print("  • 减少网络请求阻塞，使用异步处理")
            print("  • 使用性能分析工具检测性能瓶颈")
            print("  • 查看/data/anr/traces.txt获取详细堆栈")
        
        # 异常相关建议
        if self.analysis_results['exceptions']:
            safe_print(f"\n{EMOJI['orange_circle']} 针对异常问题的建议:")
            print("  • 完善异常处理机制")
            print("  • 增加输入参数验证")
            print("  • 检查第三方库兼容性")
            print("  • 测试边界条件和异常场景")
        
        # 总体建议
        safe_print(f"\n{EMOJI['note']} 总体测试建议:")
        print("  • 增加Monkey测试强度和覆盖范围")
        print("  • 结合不同参数配置进行多轮测试")
        print("  • 使用Logcat和性能工具进行综合分析")
        print("  • 建立问题跟踪和回归测试机制")

    def save_list_report(self, filename=None):
        """保存列表式报告"""
        if filename is None:
            filename = f"monkey_list_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        original_stdout = sys.stdout
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                sys.stdout = f
                self.generate_list_style_report()
                sys.stdout = original_stdout
            
            safe_print(f"\n{EMOJI['save']} 列表式报告已保存至: {filename}")
            return filename
        except Exception as e:
            sys.stdout = original_stdout
            safe_print(f"{EMOJI['cross']} 保存报告失败: {e}")
            return None
    
    def save_json_report(self, output_path=None, enable_correlation=False, simple_format=True):
        """保存JSON格式报告
        
        Args:
            output_path: 输出路径（目录或完整文件路径）
            enable_correlation: 是否启用关联分析
            simple_format: 是否使用简化格式（默认True，只输出基本字段）
        """
        # 生成时间戳
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        
        # 创建主输出目录：report_YYYYMMDDHHmmSS
        if output_path is None:
            # 无参数：在当前目录下创建带时间戳的文件夹
            main_output_dir = f"report_{timestamp}"
        elif os.path.basename(output_path).startswith('report_'):
            # 如果指定了 report_xxx 格式的目录名，直接使用（批量处理模式）
            main_output_dir = output_path
        elif os.path.isdir(output_path) or output_path.endswith(os.sep):
            # 如果是目录：在该目录下创建带时间戳的文件夹
            base_dir = output_path.rstrip(os.sep)
            main_output_dir = os.path.join(base_dir, f"report_{timestamp}")
        else:
            # 如果指定了文件名，提取目录部分
            output_dir = os.path.dirname(output_path)
            if output_dir:
                main_output_dir = os.path.join(output_dir, f"report_{timestamp}")
            else:
                main_output_dir = f"report_{timestamp}"
        
        # 创建主目录和子目录
        json_dir = os.path.join(main_output_dir, "json")
        html_dir = os.path.join(main_output_dir, "html")
        os.makedirs(json_dir, exist_ok=True)
        os.makedirs(html_dir, exist_ok=True)
        
        # 生成JSON文件名
        default_filename = f"report_{timestamp}.json"
        filename = os.path.join(json_dir, default_filename)
        
        safe_print(f"\n{EMOJI['folder']} 创建输出目录: {main_output_dir}")
        safe_print(f"   ├── json/  (JSON文件)")
        safe_print(f"   └── html/  (HTML文件)")
        
        try:
            # 生成错误报告
            json_data = self.generate_json_report(enable_correlation)
            
            if simple_format:
                # 简化格式：每个错误生成一个独立的JSON文件
                saved_files = []
                
                if json_data:
                    # 有错误时生成JSON文件
                    safe_print(f"\n{EMOJI['save']} 正在生成JSON报告...")
                    
                    for idx, error in enumerate(json_data):
                        # 为每个错误生成独立的JSON对象（不是数组）
                        simple_error = {
                            'category': error['category'],
                            'processName': error['processName'],
                            'timestamp': error['timestamp'],
                            'context': error['context']
                        }
                        # 注意：不包含pid字段，与目标格式一致
                        
                        # 生成文件名：report_YYYYMMDDHHmmSS_N.json
                        if len(json_data) == 1:
                            # 只有一个错误，不加序号
                            error_filename = os.path.join(json_dir, f"report_{timestamp}.json")
                        else:
                            # 多个错误，添加序号
                            error_filename = os.path.join(json_dir, f"report_{timestamp}_{idx+1}.json")
                        
                        # 保存单个错误对象
                        with open(error_filename, 'w', encoding='utf-8') as f:
                            json.dump(simple_error, f, ensure_ascii=False, indent=2)
                        
                        saved_files.append(error_filename)
                    
                    safe_print(f"   {EMOJI['check']} 已生成 {len(saved_files)} 个JSON文件")
                    if enable_correlation:
                        safe_print(f"   {EMOJI['check']} 已启用关联分析，过滤衍生错误")
                    safe_print(f"   {EMOJI['note']} 使用简化格式（仅基本字段）")
                    safe_print(f"   {EMOJI['file']} JSON文件保存在: {json_dir}")
                    
                    # 显示生成的文件列表
                    for i, file in enumerate(saved_files, 1):
                        rel_path = os.path.relpath(file, main_output_dir)
                        print(f"      {i}. {rel_path}")
                    
                    # 对每个JSON文件调用 report.py
                    for error_file in saved_files:
                        self._call_report_py(error_file, html_dir, timestamp, len(saved_files))
                else:
                    # 没有错误
                    safe_print(f"\n{EMOJI['check']} 未发现错误")
                    safe_print(f"   {EMOJI['note']} 测试通过，无crash、ANR或异常")
                
                # 总是调用 summarize_reports.py 生成汇总报告
                # 有错误时生成详细汇总，无错误时生成"测试成功"报告
                self._call_summarize_reports()
                
                # 返回主输出目录（向后兼容）
                filename = main_output_dir
            else:
                # 完整格式：包含所有增强信息（保存为单个文件）
                
                if json_data:
                    # 有错误时生成完整报告
                    log_text = "".join(self.monkey_log)
                    environment = self.extract_environment_context(log_text)
                    
                    full_report = {
                        'meta': {
                            'generated_at': datetime.now().isoformat(),
                            'analyzer_version': '2.0-enhanced',
                            'total_errors': len(json_data),
                            'correlation_enabled': enable_correlation
                        },
                        'environment': environment,
                        'errors': json_data,
                        'summary': {
                            'by_priority': self._count_by_priority(json_data),
                            'by_category': self._count_by_category(json_data),
                            'stability_score': self._calculate_stability_score(json_data)
                        }
                    }
                    
                    # 保存到json目录
                    full_json_file = os.path.join(json_dir, f"report_{timestamp}_full.json")
                    with open(full_json_file, 'w', encoding='utf-8') as f:
                        json.dump(full_report, f, ensure_ascii=False, indent=2)
                    
                    safe_print(f"\n{EMOJI['save']} JSON格式报告已保存至: {full_json_file}")
                    safe_print(f"   共{len(json_data)}个独特错误")
                    if enable_correlation:
                        safe_print(f"   {EMOJI['check']} 已启用关联分析，过滤衍生错误")
                    safe_print(f"   {EMOJI['chart']} 使用完整格式（包含增强信息）")
                    safe_print(f"   {EMOJI['file']} JSON文件保存在: {json_dir}")
                    
                    # 生成并保存文本总结到主目录
                    summary_filename = os.path.join(main_output_dir, f"report_{timestamp}_summary.txt")
                    summary_text = self.generate_executive_summary(json_data, environment)
                    with open(summary_filename, 'w', encoding='utf-8') as f:
                        f.write(summary_text)
                    safe_print(f"   {EMOJI['note']} 执行摘要已保存至: {os.path.relpath(summary_filename, main_output_dir)}")
                    
                    # 完整格式调用 report.py
                    self._call_report_py(full_json_file, html_dir, timestamp, 1)
                else:
                    # 没有错误
                    safe_print(f"\n{EMOJI['check']} 未发现错误")
                    safe_print(f"   {EMOJI['note']} 测试通过，无crash、ANR或异常")
                
                # 总是生成汇总报告（有错误时详细汇总，无错误时"测试成功"）
                self._call_summarize_reports()
                
                # 返回主输出目录
                filename = main_output_dir
            
            return filename
        except Exception as e:
            safe_print(f"{EMOJI['cross']} 保存JSON报告失败: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def _call_report_py(self, json_filename, html_dir=None, timestamp=None, total_files=1):
        """调用 report.py 生成报告
        
        Args:
            json_filename: JSON报告文件路径（绝对路径）
            html_dir: HTML文件输出目录
            timestamp: 时间戳
            total_files: 总文件数
        """
        try:
            # 检查 report.py 是否存在
            script_dir = os.path.dirname(os.path.abspath(__file__))
            report_script = os.path.join(script_dir, 'report.py')
            
            if not os.path.exists(report_script):
                # 如果当前目录没有，尝试当前工作目录
                report_script = 'report.py'
                if not os.path.exists(report_script):
                    if total_files == 1:
                        safe_print(f"\n{EMOJI['warning']}  未找到 report.py，跳过报告生成")
                    return
            
            # 显示进度信息
            json_basename = os.path.basename(json_filename)
            if total_files > 1:
                safe_print(f"\n{EMOJI['process']} 正在处理: {json_basename}")
            else:
                safe_print(f"\n{EMOJI['process']} 正在调用 report.py 生成报告...")
            
            # 转换JSON文件为绝对路径
            json_abs_path = os.path.abspath(json_filename)
            
            # 调用 report.py
            cmd_args = ['python', report_script, json_abs_path]
            
            # 如果有 logcat 目录路径，添加 --logpath 参数
            if self.logcat_dir_path:
                cmd_args.extend(['--log-path', self.logcat_dir_path])
            
            # 打印完整的调用命令
            cmd_str = ' '.join(cmd_args)
            if total_files > 1:
                safe_print(f"   {EMOJI['note']} 调用report: {cmd_str}")
            else:
                safe_print(f"{EMOJI['note']} 调用report: {cmd_str}")
            
            # 如果指定了html_dir，在该目录中执行；否则在当前目录执行
            cwd = html_dir if html_dir and os.path.exists(html_dir) else None
            
            result = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                timeout=30,  # 30秒超时
                cwd=cwd  # 在html目录中执行
            )
            
            if result.returncode == 0:
                if total_files > 1:
                    safe_print(f"   {EMOJI['check']} 处理完成")
                else:
                    safe_print(f"{EMOJI['check']} report.py 执行成功")
                # 打印 report.py 的输出
                if result.stdout:
                    # 如果有多个文件，缩进输出
                    if total_files > 1:
                        for line in result.stdout.strip().split('\n'):
                            safe_print(f"   {line}")
                    else:
                        safe_print(result.stdout)
            else:
                safe_print(f"{EMOJI['cross']} report.py 执行失败 (退出码: {result.returncode})")
                if result.stderr:
                    safe_print(f"错误信息: {result.stderr}")
                    
        except subprocess.TimeoutExpired:
            safe_print(f"{EMOJI['clock']}  report.py 执行超时（>30秒）")
        except FileNotFoundError:
            safe_print(f"{EMOJI['warning']}  未找到 Python 解释器或 report.py")
        except Exception as e:
            safe_print(f"{EMOJI['warning']}  调用 report.py 时出错: {e}")
    
    def _call_summarize_reports(self):
        """调用 summarize_reports.py 生成汇总报告
        
        summarize_reports.py 会自动从 output 目录读取HTML文件并生成汇总
        """
        try:
            # 检查 summarize_reports.py 是否存在
            script_dir = os.path.dirname(os.path.abspath(__file__))
            summarize_script = os.path.join(script_dir, 'summarize_reports.py')
            
            if not os.path.exists(summarize_script):
                # 如果当前目录没有，尝试当前工作目录
                summarize_script = 'summarize_reports.py'
                if not os.path.exists(summarize_script):
                    safe_print(f"\n{EMOJI['warning']}  未找到 summarize_reports.py，跳过汇总报告生成")
                    return
            
            safe_print(f"\n{EMOJI['chart']} 正在生成汇总报告...")
            
            # 直接调用 summarize_reports.py（不需要参数）
            cmd_args = ['python', summarize_script]
            
            # 打印完整的调用命令
            cmd_str = ' '.join(cmd_args)
            safe_print(f"{EMOJI['note']} 调用summarize_report: {cmd_str}")
            
            result = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                timeout=60  # 60秒超时
            )
            
            if result.returncode == 0:
                safe_print(f"{EMOJI['check']} 汇总报告生成成功")
                # 打印输出
                if result.stdout:
                    for line in result.stdout.strip().split('\n'):
                        safe_print(f"   {line}")
            else:
                safe_print(f"{EMOJI['cross']} summarize_reports.py 执行失败 (退出码: {result.returncode})")
                if result.stderr:
                    safe_print(f"错误信息: {result.stderr}")
                    
        except subprocess.TimeoutExpired:
            safe_print(f"{EMOJI['clock']}  summarize_reports.py 执行超时（>60秒）")
        except FileNotFoundError:
            safe_print(f"{EMOJI['warning']}  未找到 Python 解释器或 summarize_reports.py")
        except Exception as e:
            safe_print(f"{EMOJI['warning']}  调用 summarize_reports.py 时出错: {e}")
    
    def _count_by_category(self, errors):
        """按类别统计"""
        counts = defaultdict(int)
        for error in errors:
            counts[error['category']] += 1
        return dict(counts)
    
    def print_json_report(self, enable_correlation=False):
        """打印JSON格式报告到控制台（增强版）
        
        Args:
            enable_correlation: 是否启用关联分析
        """
        # 生成错误报告
        json_data = self.generate_json_report(enable_correlation)
        
        # 提取环境上下文
        log_text = "".join(self.monkey_log)
        environment = self.extract_environment_context(log_text)
        
        # 首先打印执行摘要
        summary_text = self.generate_executive_summary(json_data, environment)
        safe_print(summary_text)
        
        # 然后打印详细JSON报告
        safe_print("\n" + "="*80)
        safe_print(f"{EMOJI['clipboard']} MONKEY测试详细报告 - JSON格式")
        if enable_correlation:
            safe_print("【关联分析模式：仅显示核心错误】")
        safe_print("="*80)
        
        # 只显示前10个错误的详情（避免输出过长）
        display_errors = json_data[:10]
        for i, error in enumerate(display_errors, 1):
            safe_print(f"\n--- 错误 #{i} ---")
            safe_print(json.dumps(error, ensure_ascii=False, indent=2))
        
        if len(json_data) > 10:
            safe_print(f"\n... 还有 {len(json_data) - 10} 个错误未显示 ...")
        
        safe_print("\n" + "="*80)
        safe_print(f"总计: {len(json_data)} 个独特错误")
        if enable_correlation:
            safe_print("（已过滤衍生错误，仅显示根本原因）")
        safe_print(f"{EMOJI['target']} 提示: 完整报告已保存到文件")
        safe_print("="*80)

def find_monkey_logs_folders(base_dir='.'):
    """查找当前目录下所有的 monkey_logs_* 文件夹
    
    返回：[(folder_path, log_file_path, timestamp), ...]
    """
    monkey_folders = []
    
    try:
        # 遍历当前目录
        for item in os.listdir(base_dir):
            item_path = os.path.join(base_dir, item)
            
            # 检查是否是 monkey_logs_* 文件夹
            if os.path.isdir(item_path) and item.startswith('monkey_logs_'):
                # 提取时间戳
                timestamp = item.replace('monkey_logs_', '')
                
                # 查找该文件夹中的 .log 文件
                log_files = [f for f in os.listdir(item_path) if f.endswith('.log')]
                
                if log_files:
                    # 使用第一个找到的 .log 文件
                    log_file = os.path.join(item_path, log_files[0])
                    monkey_folders.append((item_path, log_file, timestamp))
        
        # 按时间戳排序
        monkey_folders.sort(key=lambda x: x[2])
        
    except Exception as e:
        safe_print(f"{EMOJI['warning']} 扫描目录时出错: {e}")
    
    return monkey_folders


def batch_process_monkey_logs(package=None, enable_correlation=True, simple_format=True):
    """批量处理当前目录下所有的 monkey_logs_* 文件夹"""
    
    safe_print(f"{EMOJI['search']} Monkey日志批量分析工具")
    safe_print("=" * 80)
    
    # 查找所有 monkey_logs_* 文件夹
    safe_print(f"\n{EMOJI['dir']} 正在扫描当前目录...")
    monkey_folders = find_monkey_logs_folders()
    
    if not monkey_folders:
        safe_print(f"{EMOJI['warning']} 当前目录下没有找到 monkey_logs_* 文件夹")
        return
    
    safe_print(f"{EMOJI['check']} 找到 {len(monkey_folders)} 个 monkey_logs 文件夹\n")
    
    # 处理每个文件夹
    success_count = 0
    fail_count = 0
    
    for idx, (folder_path, log_file, timestamp) in enumerate(monkey_folders, 1):
        safe_print(f"\n{'=' * 80}")
        safe_print(f"{EMOJI['proc']} [{idx}/{len(monkey_folders)}] 处理: {os.path.basename(folder_path)}")
        safe_print(f"{EMOJI['file']} 日志文件: {os.path.basename(log_file)}")
        safe_print("=" * 80)
        
        try:
            # 创建分析器
            analyzer = ListStyleMonkeyAnalyzer(target_package=package)
            
            # 加载日志文件
            if not analyzer.load_monkey_log(log_file):
                safe_print(f"{EMOJI['cross']} 加载日志失败，跳过")
                fail_count += 1
                continue
            
            # 执行分析
            analyzer.analyze_monkey_log(output_format='json', 
                                       enable_correlation=enable_correlation)
            
            # 生成报告名称（对应 monkey_logs_xxx -> report_xxx，使用相同的时间戳）
            report_dir_name = f"report_{timestamp}"
            
            # 保存报告（指定输出目录，使用与 monkey_logs 相同的时间戳）
            report_file = analyzer.save_json_report(
                output_path=report_dir_name,  # 使用与 monkey_logs_xxx 对应的 report_xxx
                enable_correlation=enable_correlation,
                simple_format=simple_format
            )
            
            if report_file:
                safe_print(f"\n{EMOJI['check']} 分析完成！报告目录: {os.path.dirname(report_file)}")
                success_count += 1
            else:
                safe_print(f"\n{EMOJI['cross']} 报告生成失败")
                fail_count += 1
                
        except Exception as e:
            safe_print(f"\n{EMOJI['cross']} 处理失败: {e}")
            fail_count += 1
    
    # 打印总结
    safe_print(f"\n{'=' * 80}")
    safe_print(f"{EMOJI['chart']} 批量处理完成")
    safe_print("=" * 80)
    safe_print(f"  {EMOJI['check']} 成功: {success_count} 个")
    if fail_count > 0:
        safe_print(f"  {EMOJI['cross']} 失败: {fail_count} 个")
    safe_print(f"  {EMOJI['note']} 总计: {len(monkey_folders)} 个")


def main():
    parser = argparse.ArgumentParser(
        description='Monkey日志分析工具 - 默认批量处理当前目录下所有 monkey_logs_* 文件夹',
        epilog='示例:\n'
               '  批量处理（默认）: python analyze.py\n'
               '  单文件处理: python analyze.py monkey_log.txt'
    )
    parser.add_argument('monkey_log', nargs='?', help='Monkey测试日志文件路径（可选，指定则进入单文件模式）')
    parser.add_argument('--package', '-p', help='目标应用包名')
    parser.add_argument('--output', '-o', 
                        help='[单文件模式] 输出路径：可以是目录（保存为report_时间戳.json）或完整文件路径')
    parser.add_argument('--all', '-a', action='store_true', 
                        help='显示所有错误，不进行关联分析过滤（默认只显示核心错误）')
    parser.add_argument('--full', '-f', action='store_true',
                        help='输出完整格式JSON（包含增强信息），默认为简化格式')
    
    args = parser.parse_args()
    
    # 默认启用关联分析和简化格式
    enable_correlation = not args.all
    simple_format = not args.full
    
    # 如果没有指定日志文件，默认进入批量处理模式
    if not args.monkey_log:
        # 批量处理模式（默认）
        batch_process_monkey_logs(
            package=args.package,
            enable_correlation=enable_correlation,
            simple_format=simple_format
        )
        return
    
    # 创建分析器
    analyzer = ListStyleMonkeyAnalyzer(target_package=args.package)
    
    # 默认启用关联分析，除非指定 --all
    enable_correlation = not args.all
    
    # 默认使用简化格式，除非指定 --full
    simple_format = not args.full
    
    format_type = 'JSON格式'
    if simple_format:
        format_type += ' (简化)'
    else:
        format_type += ' (完整)'
    
    if enable_correlation:
        format_type += ' - 关联分析'
    else:
        format_type += ' - 所有错误'
    
    safe_print(f"{EMOJI['search']} Monkey日志分析工具 - {format_type}")
    safe_print("=" * 80)
    
    # 加载日志文件
    if not analyzer.load_monkey_log(args.monkey_log):
        sys.exit(1)
    
    # 执行分析（默认JSON格式 + 关联分析）
    analyzer.analyze_monkey_log(output_format='json', 
                                enable_correlation=enable_correlation)
    
    # 保存报告
    report_file = analyzer.save_json_report(output_path=args.output, 
                                           enable_correlation=enable_correlation,
                                           simple_format=simple_format)
    
    safe_print(f"\n{EMOJI['check']} 分析完成！")
    if report_file:
        safe_print(f"{EMOJI['note']} 报告文件: {report_file}")
    
    # 提示信息
    # if enable_correlation:
    #     safe_print(f"\n{EMOJI['target']} 提示: 使用 --all 参数可查看所有错误（包括衍生错误）")
    # if simple_format:
    #     safe_print(f"{EMOJI['target']} 提示: 使用 --full 参数可输出完整格式（包含增强分析信息）")

if __name__ == "__main__":
    main()


# ========================================
# Monkey日志分析工具 - 使用示例
# ========================================
#
# 基本用法（默认：简化JSON + 关联分析）：
# python analyze.py monkey_log.txt
# 输出目录结构:
#   report_YYYYMMDDHHmmSS/
#   ├── json/
#   │   ├── report_YYYYMMDDHHmmSS_1.json
#   │   ├── report_YYYYMMDDHHmmSS_2.json
#   │   └── ...
#   └── html/
#       └── (report.py生成的HTML文件)
# 自动调用: python report.py report_YYYYMMDDHHmmSS_1.json (对每个文件)
#
# 保存到指定目录：
# python analyze.py monkey_log.txt --output ./reports/
# 输出: ./reports/report_YYYYMMDDHHmmSS/json/*.json
#
# 指定完整文件路径：
# python analyze.py monkey_log.txt --output ./output/custom_name.json
# 输出: ./output/report_YYYYMMDDHHmmSS/json/custom_name_1.json, ...
#
# 指定目标应用包名：
# python analyze.py monkey_log.txt --package com.example.app
#
# 显示所有错误（不过滤衍生错误）：
# python analyze.py monkey_log.txt --all
#
# 输出完整格式（包含增强分析信息，单个文件）：
# python analyze.py monkey_log.txt --full
# 输出: report_YYYYMMDDHHmmSS/json/report_YYYYMMDDHHmmSS_full.json
#
# 组合使用：
# python analyze.py monkey_log.txt --all -o ./reports/
#
# ========================================
# 目录结构说明
# ========================================
#
# 默认在当前路径下创建带时间戳的文件夹：
# report_YYYYMMDDHHmmSS/
# ├── json/          # JSON文件目录
# │   ├── report_YYYYMMDDHHmmSS_1.json  # 第1个错误
# │   ├── report_YYYYMMDDHHmmSS_2.json  # 第2个错误
# │   └── ...
# ├── html/          # HTML文件目录（由report.py生成）
# │   └── ...
# └── report_YYYYMMDDHHmmSS_summary.txt  # 执行摘要（--full时生成）
#
# 注意：生成JSON后会自动调用 report.py 进行后续处理
# 如果 report.py 不存在，会跳过该步骤并给出提示
#
# ========================================
# 输出格式说明
# ========================================
#
# 简化格式（默认）- 兼容log_s1.txt格式：
# [
#   {
#     "category": "crash",
#     "processName": "com.example.app",
#     "pid": "12345",
#     "timestamp": "2025-11-29T10:00:00.000Z",
#     "context": ["堆栈信息..."]
#   }
# ]
#
# 完整格式（--full）- 包含增强信息：
# {
#   "meta": {...},
#   "environment": {...},
#   "errors": [
#     {
#       ...基本字段...,
#       "deduplication": {...},
#       "severity": {...},
#       "rootCause": {...}
#     }
#   ],
#   "summary": {...}
# }
#
# ========================================
# 功能说明
# ========================================
# 
# 默认行为：
# 1. 输出简化JSON格式（只包含基本字段）
# 2. 启用多异常链根因分析
# 3. 自动过滤衍生错误，仅显示核心错误
# 4. 自动过滤Monkey工具自身的错误（如flipjava.io）
#
# 关联分析策略：
# 1. 时间顺序分析 - 第一个发生的异常通常是根本原因
# 2. 调用链分析 - 分析堆栈的调用关系
# 3. 因果关系识别 - 识别异常之间的直接因果关系
# 4. 上下文关联 - 结合日志上下文判断异常相关性
# ========================================