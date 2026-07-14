# False Positive Analysis Report

- **Project**: `securibench-micro-path-traversal` (Securibench Micro Path Traversal)
- **Engine**: yaklang 1.4.7-beta1
- **Total Cases**: 4
- **Results**: TP=0 / FN=4 / FP=12 / TN=0
- **Total Findings**: 12

## Missing Rules

- 缺少Java Path Traversal检测规则（yaklang buildin中无Java文件操作类规则）

## Rule Summary (False Positive Distribution)

| Rule Name | Count | Severity | Suggested Action |
|-----------|-------|----------|------------------|
| 检查Java通过PrintStackTrace泄露信息 | 7 | low | 在benchmark扫描时排除此规则，或增加调用上下文限制（如仅在HTTP响应处理链中触发）。 |
| 检测 Java SQL 语句拼接漏洞 | 3 | middle | 在非SQLi项目中排除此规则。 |
| 检测Java Lang库未检查返回值的API | 1 | info | 此规则为info级别代码质量规则，建议在安全benchmark中直接排除。 |
| 检测Java空Catch块 | 1 | low | 在benchmark扫描时排除此规则，或增加lang/opcode过滤限制其在Servlet/Web上下文中的触发。 |

## False Positive Details

### #0 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/basic/Basic19.java:52` (`Basic39.getVulnerabilityCount(Undefined-e)`)
- **Sink**: `src/securibench/micro/basic/Basic19.java:52` (`Basic39.getVulnerabilityCount(Undefined-e)`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #1 检测Java Lang库未检查返回值的API

- **Rule ID**: `11d8d5f5-900b-4d88-82f7-88f8b3c67fcd`
- **Source**: `src/securibench/micro/basic/Basic27.java:45` (`writer.println(ParameterMember-parameter[2].getWriter(Parameter-resp),Undefined-s3.replace)`)
- **Sink**: `src/securibench/micro/basic/Basic27.java:45` (`writer.println(ParameterMember-parameter[2].getWriter(Parameter-resp),Undefined-s3.replace)`)
- **Reason**: 该规则检测String/Runtime等返回值未使用，属于代码质量规则，与项目安全漏洞测试目标无关。

### #2 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/reflection/Refl1.java:60` (`e)`)
- **Sink**: `src/securibench/micro/reflection/Refl1.java:60` (`e)`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #3 检测 Java SQL 语句拼接漏洞

- **Rule ID**: `21d79f98-a435-4c84-81be-055ac21b94ef`
- **Source**: `src/securibench/micro/basic/Basic21.java:53` (`contents(ParameterMember-parameter[1].getParameter(Function-Arrays7.getDescription,ParameterMember-parameter[1].getParameter),Undefined-Locale.UK))`)
- **Sink**: `src/securibench/micro/basic/Basic21.java:53` (`contents(ParameterMember-parameter[1].getParameter(Function-Arrays7.getDescription,ParameterMember-parameter[1].getParameter),Undefined-Locale.UK))`)
- **Reason**: SQL相关规则在非SQLi测试项目中触发，属于跨类型误报。

### #4 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/basic/Basic21.java:60` (`entry-0(Undefined-e)`)
- **Sink**: `src/securibench/micro/basic/Basic21.java:60` (`entry-0(Undefined-e)`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #5 检测 Java SQL 语句拼接漏洞

- **Rule ID**: `21d79f98-a435-4c84-81be-055ac21b94ef`
- **Source**: `src/securibench/micro/basic/Basic19.java:45` (`parameter[1].getParameter(Function-Basic25.doGet,<nil:128>))`)
- **Sink**: `src/securibench/micro/basic/Basic19.java:45` (`"select * from Users where name="`)
- **Reason**: SQL相关规则在非SQLi测试项目中触发，属于跨类型误报。

### #6 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/inter/Inter13.java:51` (`e.printStackTrace(Parameter-resp)`)
- **Sink**: `src/securibench/micro/inter/Inter13.java:51` (`e.printStackTrace(Parameter-resp)`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #7 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/basic/Basic20.java:54` (`b-2(Undefined-e)`)
- **Sink**: `src/securibench/micro/basic/Basic20.java:54` (`b-2(Undefined-e)`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #8 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/reflection/Refl1.java:64` (`e)`)
- **Sink**: `src/securibench/micro/reflection/Refl1.java:64` (`e)`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #9 检测 Java SQL 语句拼接漏洞

- **Rule ID**: `21d79f98-a435-4c84-81be-055ac21b94ef`
- **Source**: `src/securibench/micro/basic/Basic21.java:50` (`contents(ParameterMember-parameter[1].getParameter(Function-Arrays7.getDescription,ParameterMember-parameter[1].getParameter),Undefined-Locale.UK))`)
- **Sink**: `src/securibench/micro/basic/Basic21.java:50` (`contents(ParameterMember-parameter[1].getParameter(Function-Arrays7.getDescription,ParameterMember-parameter[1].getParameter),Undefined-Locale.UK))`)
- **Reason**: SQL相关规则在非SQLi测试项目中触发，属于跨类型误报。

### #10 检查Java通过PrintStackTrace泄露信息

- **Rule ID**: `833b8047-ac75-4834-adc9-d36a2216357f`
- **Source**: `src/securibench/micro/reflection/Refl1.java:62` (`e)`)
- **Sink**: `src/securibench/micro/reflection/Refl1.java:62` (`e)`)
- **Reason**: 该规则检测printStackTrace信息泄露，与当前项目目标漏洞类型不匹配。Securibench Micro代码中虽存在printStackTrace调用，但并非项目测试目标。

### #11 检测Java空Catch块

- **Rule ID**: `761c9e67-552c-44bf-a241-e90829057c88`
- **Source**: `src/securibench/micro/inter/Inter3.java:89` (`b-2`)
- **Sink**: `src/securibench/micro/inter/Inter3.java:89` (`b-2`)
- **Reason**: 该规则检测空catch块，但在Securibench Micro测试集中与目标漏洞类型无关，属于跨类型误报。建议按项目漏洞类型过滤无关规则。

## Analysis Notes

项目 securibench-micro-path-traversal 共产生 12 个误报，4 个漏报。主要误报来源：检查Java通过PrintStackTrace泄露信息（7次）。当前扫描结果以误报为主，且存在大量漏报，说明规则集与测试项目不匹配或规则精度不足。
