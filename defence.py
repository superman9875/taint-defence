import time
import re
print(">>> 标准攻击测试 - Toxic Agent Flow 污点追踪防御原型")
print(">>> 虚拟值声明：所有 SECRET_* 均为随机生成，非真实凭证\n")

# =====================================================================
# 1. 定义安全异常类
# =====================================================================
class SecurityPolicyViolation(Exception):
    """当数据违规跨越安全边界时抛出的异常"""
    pass

# =====================================================================
# 2. 核心防御中间件：上下文污点管理器 (Context Taint Manager)
# =====================================================================
class ContextTaintManager:
    def __init__(self):
        self.is_tainted = False             # 当前上下文是否已被污染
        self.sensitive_artifacts = set()    # 捕获到的高密级数据片段
        self.sensitive_patterns = [         # 敏感词/格式匹配正则
            r"SECRET_[a-zA-Z0-9_]+",
            r"sk-[a-zA-Z0-9]{16,}"
        ]

    def post_execution_hook(self, tool_name: str, output: str):
        """【后置钩子】：在 Source 工具执行后，自动打上污点标记 (Taint Source)"""
        is_source = "private" in tool_name or "secret" in tool_name
        matched_secrets = [p for p in self.sensitive_patterns if re.search(p, str(output))]

        if is_source or matched_secrets:
            self.is_tainted = True
            self.sensitive_artifacts.add(str(output))
            print(f"  [Taint Hook] 🚨 检测到高密级数据读取 (<{tool_name}>)")
            print(f"  [Taint Hook] 🏷️ 上下文状态更新: [TAINTED = True]")

    def pre_execution_hook(self, tool_name: str, kwargs: dict):
        """【前置钩子】：在 Sink 工具执行前，进行越权审计与阻断 (Taint Sink)"""
        is_sink = "public" in tool_name or "external" in tool_name or "send" in tool_name

        if is_sink and self.is_tainted:
            # 校验参数中是否混入了被标记的敏感内容
            for artifact in self.sensitive_artifacts:
                if artifact in str(kwargs):
                    print(f"  [Taint Hook] 🛡️ 触发防线：阻断敏感数据流向低信任域工具 <{tool_name}>！")
                    raise SecurityPolicyViolation(
                        f"【安全拦截】禁止将高密级数据 ({artifact[:12]}...) 提交至公域工具 <{tool_name}>"
                    )

# =====================================================================
# 3. 模拟 Agent 工具与执行管道
# =====================================================================
def read_private_resource(resource_id: str) -> str:
    """[Taint Source 工具] 读取私密凭据"""
    return "SECRET_API_KEY_998877665544332211"

def write_public_resource(destination: str, content: str) -> str:
    """[Taint Sink 工具] 提交内容至公域/写出文件"""
    return f"Success: Content published to {destination}"

class AgentExecutionEngine:
    def __init__(self, taint_manager: ContextTaintManager = None):
        self.taint_manager = taint_manager

    def execute_tool_call(self, tool_name: str, tool_func, **kwargs):
        print(f"\n[Agent Pipeline] 尝试执行工具: <{tool_name}> | 入参: {kwargs}")
        
        # 1. 触发前置审计 (Pre-Hook)
        if self.taint_manager:
            self.taint_manager.pre_execution_hook(tool_name, kwargs)

        # 2. 执行真实工具
        result = tool_func(**kwargs)

        # 3. 触发后置标记 (Post-Hook)
        if self.taint_manager:
            self.taint_manager.post_execution_hook(tool_name, result)

        return result

# =====================================================================
# 4. 对照实验组运行
# =====================================================================
def run_experiment(enable_defense: bool):
    manager = ContextTaintManager() if enable_defense else None
    agent = AgentExecutionEngine(taint_manager=manager)
    
    mode_name = "【实验组：开启 Context Taint 防御】" if enable_defense else "【基线组：无防御 (Bare Agent)】"
    print("\n" + "="*70)
    print(f" 运行模式: {mode_name}")
    print("="*70)

    try:
        # Phase 1: 分段诱导读取
        print("--> [Step 1 / Phase 1] 诱导 Agent 提取私密数据...")
        payload_secret = agent.execute_tool_call(
            tool_name="read_private_resource", 
            tool_func=read_private_resource, 
            resource_id="secrets.json"
        )
        print(f"    Agent 获取内容: {payload_secret}")

        # Phase 2: 分段诱导泄露
        print("\n--> [Step 2 / Phase 2] 诱导 Agent 将内容提交至公域工具...")
        res = agent.execute_tool_call(
            tool_name="write_public_resource", 
            tool_func=write_public_resource, 
            destination="public_log.txt", 
            content=f"Summary: {payload_secret}"
        )
        print(f"    Agent 执行结果: {res}")
        print("\n❌ [实验结论] 攻击成功 (ASR = 100%)：敏感凭据跨越信任域泄露！")

    except SecurityPolicyViolation as e:
        print(f"\n✅ [实验结论] 防御成功 (Mitigation Rate = 100%)：{e}")

if __name__ == "__main__":
    # 运行基线组（证明漏洞）
    run_experiment(enable_defense=False)
    
    time.sleep(1)
    
    # 运行实验组（证明防御闭环）
    run_experiment(enable_defense=True)