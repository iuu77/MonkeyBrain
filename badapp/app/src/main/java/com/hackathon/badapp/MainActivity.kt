package com.hackathon.badapp

import android.os.Bundle
import android.util.Log
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import java.io.File
import java.io.FileInputStream
import java.util.ArrayList

class MainActivity : AppCompatActivity() {

    companion object {
        val leakContainer = ArrayList<ByteArray>()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val scrollView = ScrollView(this)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(50, 50, 50, 50)
            gravity = Gravity.CENTER_HORIZONTAL
        }
        scrollView.addView(layout)

        val title = TextView(this).apply {
            text = "🐵 MonkeyBrain 靶场\n(光速崩溃版)"
            textSize = 24f
            textAlignment = TextView.TEXT_ALIGNMENT_CENTER
            setPadding(0, 0, 0, 50)
        }
        layout.addView(title)

        // ==========================================
        // 按钮 1: Crash
        // ==========================================
        layout.addView(createButton("1. 触发 Crash (立即)") {
            throw RuntimeException("MonkeyBrain Test Crash: 这是一个故意抛出的异常！")
        })

        // ==========================================
        // 按钮 2: 内存泄露
        // ==========================================
        layout.addView(createButton("2. 触发 内存泄露 (极速)") {
            Toast.makeText(this, "正在极速吞噬内存...", Toast.LENGTH_SHORT).show()
            Thread {
                try {
                    Log.i("BadApp", "Memory Leak Started...")
                    while (true) {
                        leakContainer.add(ByteArray(1024 * 1024 * 30))
                        Thread.sleep(50)
                    }
                } catch (e: OutOfMemoryError) {
                    Log.e("BadApp", "OOM Triggered! Memory is full.")
                }
            }.start()
        })

        // ==========================================
        // 按钮 3: 线程泄露 (光速版)
        // ==========================================
        layout.addView(createButton("3. 触发 线程泄露 (光速)") {
            Toast.makeText(this, "正在光速创建线程...", Toast.LENGTH_SHORT).show()
            Thread {
                val targetCount = 20000
                Log.i("BadApp", "Thread Leak Started... Goal: $targetCount threads")

                for (i in 1..targetCount) {
                    try {
                        // 每 2000 个打一次日志，减少 IO 耗时
                        if (i % 2000 == 0) {
                            Log.w("BadApp", "Thread Leaking... Current Count: $i")
                        }

                        Thread {
                            try { Thread.sleep(Long.MAX_VALUE) } catch (e: Exception) {}
                        }.start()

                        // 【关键修改】去掉了 Thread.sleep(2)
                        // 现在是 CPU 全速运行，毫秒级撑爆系统

                    } catch (e: OutOfMemoryError) {
                        Log.e("BadApp", "Thread Limit Reached: ${e.message}")
                        // 主动崩
                        throw RuntimeException("Thread Leak Crash triggered at $i threads!")
                    }
                }
            }.start()
        })

        // ==========================================
        // 按钮 4: FD 泄露
        // ==========================================
        layout.addView(createButton("4. 触发 FD 泄露 (瞬间)") {
            Toast.makeText(this, "正在耗尽文件句柄...", Toast.LENGTH_SHORT).show()
            Thread {
                val file = File(cacheDir, "test_fd_leak.txt")
                if (!file.exists()) file.createNewFile()

                val openedStreams = ArrayList<FileInputStream>()
                Log.i("BadApp", "FD Leak Started...")

                while (true) {
                    try {
                        val fis = FileInputStream(file)
                        openedStreams.add(fis)
                    } catch (e: Exception) {
                        Log.e("BadApp", "FD Limit Reached: ${e.message}")
                        break
                    }
                }
            }.start()
        })

        // ==========================================
        // 按钮 5: ANR
        // ==========================================
        layout.addView(createButton("5. 触发 ANR (卡死)") {
            Toast.makeText(this, "主线程已卡死...", Toast.LENGTH_SHORT).show()
            try {
                Thread.sleep(20000)
            } catch (e: InterruptedException) {}
        })

        setContentView(scrollView)
    }

    private fun createButton(text: String, onClick: () -> Unit): Button {
        return Button(this).apply {
            this.text = text
            this.textSize = 18f
            setOnClickListener { onClick() }
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                setMargins(0, 20, 0, 20)
            }
            minHeight = 180
        }
    }
}