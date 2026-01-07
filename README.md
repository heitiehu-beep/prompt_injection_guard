# prompt_injection_guard v1.0.0

防御提示词注入攻击的 MaiBot 安全插件。

**作者**: heitiehu

## 功能特性

- **三种检测模式**
  - `rule_only` - 仅规则检测（最快，零成本）
  - `rule_then_llm` - 规则 + LLM 二次确认（推荐，平衡）
  - `llm_only` - 仅 LLM 检测（最准确，高成本）

- **三种执行方式**
  - `delete` - 删除危险消息，bot 完全看不到
  - `warn_context` - 保留消息，在 LLM prompt 中注入警告
  - `detect_only` - 仅检测并记录日志，不采取任何行动

- **管理员通知**
  - 检测到注入时私聊通知指定管理员
  - 包含攻击者 QQ 号和威胁内容

- **丰富的预设规则**（100+ 条）
  - 指令覆盖类：忽略之前、ignore previous...
  - 角色扮演类：你现在是、pretend to be...
  - 系统标记伪造类：system:、<|im_start|>...
  - 越狱类：jailbreak、DAN mode...
  - 元指令类：隐藏指令、secret instruction...
  - 多语言绕过类：日语、韩语、编码...

- **灵活的 LLM 配置**
  - 使用主程序已配置的模型
  - 或配置自定义 OpenAI 格式 API

## 安装

将 `prompt_injection_guard` 文件夹放入 `plugins/` 目录即可。

## 配置说明

配置文件位于 `plugins/prompt_injection_guard/config.toml`

### 检测模式

```toml
[detection]
# "rule_only"     - 仅规则检测（速度最快，零费用）
# "rule_then_llm" - 规则 + LLM 确认（推荐）
# "llm_only"      - 仅 LLM 检测（最准确，费用高）
mode = "rule_then_llm"
```

### 执行方式

```toml
[action]
# "delete"       - 删除消息
# "warn_context" - 在 prompt 中注入警告
# "detect_only"  - 仅检测记录，不采取行动
type = "warn_context"

# 管理员通知
enable_admin_notify = false
admin_qq = "123456789"
```

### 自定义规则

```toml
[rules]
# 追加自定义关键词
custom_keywords = ["我的关键词", "my keyword"]

# 追加自定义正则
custom_patterns = ["(?i)my\\s+pattern"]
```

### LLM 配置

```toml
[llm]
# 使用主程序模型
source = "main"
main_model_name = "replyer"

# 或使用自定义 API
# source = "custom"
# [llm.custom]
# api_base = "https://api.openai.com/v1"
# api_key = "sk-xxx"
# model = "gpt-4o-mini"
```

## 工作原理

### delete 模式
1. 消息到达时触发 `ON_MESSAGE` 事件
2. 检测消息内容是否包含注入特征
3. 如果检测到：从数据库删除消息，拦截后续处理
4. bot 完全看不到这条消息

### warn_context 模式
1. LLM 调用前触发 `POST_LLM` 事件
2. 检查上下文中的所有消息（根据 `max_context_size`）
3. 如果检测到注入：在 LLM prompt 开头注入警告
4. bot 看到消息，但同时收到安全提示

### detect_only 模式
1. 消息到达时触发 `ON_MESSAGE` 事件
2. 检测消息内容是否包含注入特征
3. 如果检测到：仅记录日志，不采取任何行动
4. 适用于测试规则效果或观察攻击模式

### 管理员通知
- 当 `enable_admin_notify = true` 且设置了 `admin_qq` 时
- 检测到注入会私聊通知管理员
- 通知内容包含：攻击者 QQ、攻击类型、威胁内容

## 日志

启用 `enable_logging = true` 后，检测结果会记录到日志：

```
[注入检测] 已删除消息 | 用户: 123456 | 类别: 越狱尝试 | 方式: 规则+LLM | 规则: jailbreak
[注入检测] 上下文警告 | 用户: 路人甲 (123456) | 类别: 指令覆盖 | 方式: 规则检测 | 规则: 忽略之前
```

## 注意事项

1. **误报处理**：如果发现正常消息被误判，可以：
   - 切换到 `rule_then_llm` 模式让 LLM 二次确认
   - 检查并调整自定义规则

2. **性能考虑**：
   - `rule_only` 模式性能最好
   - `llm_only` 模式每条消息都调用 LLM，费用较高
   - `warn_context` 模式会检查整个上下文，消息多时可能较慢

3. **上下文长度**：默认跟随主程序的 `chat.max_context_size` 设置


## 许可证

MIT
