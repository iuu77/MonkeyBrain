🚀 快速开始 (Quick Start)
MonkeyBrain 开箱即用。确保手机已连接并开启 USB 调试模式，即可通过以下命令启动诊断：
code
Bash
# 1. 默认模式（自动加载 default_config.json）
python monkey.py

# 2. 指定配置文件模式default_config.json
python monkey.py --config default_config.json

# 3. 查看帮助文档
python monkey.py -h
⚙️ 配置文件说明 (Configuration)
项目根目录下的 default_config.json 控制着测试的核心逻辑。你可以根据测试场景灵活调整。
配置示例模板
code
JSON
{
  "device_id": null,
  "monkey_events": 600,
  "monitor_duration": 300,
  "target_package": "com.android.chrome",
  "monkey_params": {
    "throttle": 100,
    "ignore_crashes": true,
    "ignore_timeouts": true,
    "monitor_native_crashes": true,
    "verbose": 3
  }
}
📝 参数详解
参数字段	类型	说明	推荐值/备注
device_id	String	指定设备序列号。设为 null 时自动连接首台设备。	null (自动检测)
monkey_events	Int	单次 Monkey 执行的事件总数。	600 - 2000
monitor_duration	Int	最小监控时长 (秒)。在此期间 Monkey 会循环执行，确保覆盖足够的时间跨度。	300 (5分钟)
target_package	String	被测应用的包名。	如 com.tencent.mm
monkey_params	Object	传递给 adb shell monkey 的原生参数字典。	见下表
🔧 Monkey Params 高级选项
该对象内的字段将直接映射为 ADB 命令参数，支持自定义扩展：
参数 Key	对应 ADB 参数	作用
throttle	--throttle	事件间的延迟 (毫秒)，防止操作过快导致系统无响应。
ignore_crashes	--ignore-crashes	遇到 Crash 继续发送事件，不中断测试。
ignore_timeouts	--ignore-timeouts	遇到 ANR 继续发送事件。
monitor_native_crashes	--monitor-native-crashes	捕获底层 C/C++ 代码崩溃。
verbose	-v -v ...	日志详细等级 (1-3)。