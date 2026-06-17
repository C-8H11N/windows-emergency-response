"""启动画面 - 可选"""
import sys
import time
import threading


def show_splash():
    """显示简单启动画面（仅 Windows）"""
    try:
        import tkinter as tk
        from tkinter import ttk

        root = tk.Tk()
        root.title("Windows 应急响应助手")
        root.geometry("400x200")
        root.overrideredirect(True)
        root.configure(bg="#0f172a")

        # 居中显示
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        x = (screen_width - 400) // 2
        y = (screen_height - 200) // 2
        root.geometry(f"400x200+{x}+{y}")

        # 内容
        ttk.Label(root, text="🛡️", font=("Segoe UI", 48),
                  background="#0f172a", foreground="#22d3ee").pack(pady=20)
        ttk.Label(root, text="Windows 应急响应助手", font=("Segoe UI", 16, "bold"),
                  background="#0f172a", foreground="#e2e8f0").pack()
        ttk.Label(root, text="正在启动...", font=("Segoe UI", 10),
                  background="#0f172a", foreground="#94a3b8").pack(pady=10)

        # 进度条
        progress = ttk.Progressbar(root, mode="indeterminate", length=300)
        progress.pack(pady=10)
        progress.start(10)

        # 3秒后自动关闭
        def close():
            time.sleep(3)
            root.destroy()

        threading.Thread(target=close, daemon=True).start()
        root.mainloop()

    except Exception:
        # Tk 不可用时静默失败
        pass


if __name__ == "__main__":
    show_splash()
